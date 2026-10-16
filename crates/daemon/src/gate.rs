//! One approval window at a time per vault, shared where that is honest.
//!
//! Without this, N requests that each need the person (N `vahta run` started
//! at once by a harness, say N MCP servers) open N windows at the same time.
//! Here the first request for a vault opens the window; the others wait for
//! it, and what they get when it closes depends on what it was:
//!
//! * **A session was opened** (`vahta unlock`): the waiters look for a session
//!   again, with the ordinary lookup of `session.rs` (the caller's process
//!   tree and the secrets it covers). A waiter that the new session covers is
//!   served by it with no window of its own. One that it does not cover (a
//!   different process tree, a secret outside its scope, an each-use secret)
//!   gains nothing and takes its own turn, after the others.
//! * **A one-use approval was given** (`vahta run`, `vahta http`): it covers
//!   what the person saw. A waiter whose window would have said exactly the
//!   same (same vault, same secrets, same command text and labels, same agent
//!   anchor) is served by that approval, because for the person it is the
//!   same question asked twice. Any other waiter takes its own turn: another
//!   command is another question.
//! * **The person refused or closed the window**: the waiters whose secrets
//!   are all among the ones just refused get the same refusal, so one "no"
//!   does not bring up the window N times more. Waiters asking for other
//!   secrets take their own turn.
//! * **The request fell through** (its client went away, or an error): nobody
//!   was answered; the next waiter takes the turn.
//!
//! A waiter whose own client goes away stops waiting.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use vahta_auth::Cancel;
use vahta_vault::SecretValue;

use crate::protocol::ClientReply;

/// What a one-use approval was for: only a request with an equal key shares
/// it. `None` where the request cannot be pinned down (no agent anchor).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct UseKey(pub String);

/// How a turn ended, for the ones who waited on it.
enum Outcome {
    /// A session now exists; look for it.
    Session,
    /// A one-use approval for `key`, and the values it unlocked.
    Granted {
        key: UseKey,
        values: Vec<(String, SecretValue)>,
    },
    /// The person said no to a window about `names`.
    Refused {
        names: Vec<String>,
        reply: ClientReply,
    },
    /// Nothing was decided.
    Fell,
}

#[derive(Default)]
struct State {
    /// Someone holds the turn.
    busy: bool,
    /// Counts turns, so a waiter knows which one it waited on.
    round: u64,
    /// The last turn's outcome, kept only while someone may still read it.
    outcome: Option<(u64, Arc<Outcome>)>,
    waiting: usize,
}

#[derive(Default)]
struct Gate {
    state: Mutex<State>,
    cv: Condvar,
}

/// The gates of the daemon, one per vault.
#[derive(Default)]
pub(crate) struct Gates {
    map: Mutex<HashMap<[u8; 16], Arc<Gate>>>,
}

/// What [`Gates::enter`] came to.
pub(crate) enum Admission {
    /// The turn is yours: open the window, then [`Turn::finish`].
    Turn(Turn),
    /// A one-use approval that covers this request was given meanwhile.
    Granted(Vec<(String, SecretValue)>),
    /// The person refused something that includes this request.
    Refused(ClientReply),
    /// A session may exist now: look again, then [`Gates::enter`] again if
    /// none covers the request.
    Look,
    /// The client is gone.
    Gone,
}

/// The turn on a vault's window. Dropped without [`Turn::finish`], it ends as
/// a turn that decided nothing.
pub(crate) struct Turn {
    gate: Arc<Gate>,
    done: bool,
}

/// How long a waiter waits at most; a window gives up long before.
const MAX_WAIT: Duration = Duration::from_secs(8 * 60);
/// How often a waiter looks at its client.
const TICK: Duration = Duration::from_millis(100);

impl Gates {
    fn gate(&self, vault_id: &[u8; 16]) -> Option<Arc<Gate>> {
        let mut map = self.map.lock().ok()?;
        Some(map.entry(*vault_id).or_default().clone())
    }

    /// Ask for the turn on `vault_id` for a request about `names`. `key` says
    /// what a one-use approval for this request would be an approval of.
    pub(crate) fn enter(
        &self,
        vault_id: &[u8; 16],
        names: &[String],
        key: Option<&UseKey>,
        gone: &Cancel,
    ) -> Admission {
        let Some(gate) = self.gate(vault_id) else {
            // Cannot coordinate: behave as before, a window of one's own.
            return Admission::Turn(Turn::detached());
        };
        let Ok(mut st) = gate.state.lock() else {
            return Admission::Turn(Turn::detached());
        };
        if !st.busy {
            st.busy = true;
            st.round += 1;
            // Values of an earlier turn are not kept for the next one.
            st.outcome = None;
            return Admission::Turn(Turn {
                gate: gate.clone(),
                done: false,
            });
        }
        let round = st.round;
        st.waiting += 1;
        let until = Instant::now() + MAX_WAIT;
        let timed_out = loop {
            if gone.is_cancelled() {
                break false;
            }
            if !st.busy || st.round != round {
                break false;
            }
            if Instant::now() >= until {
                break true;
            }
            st = match gate.cv.wait_timeout(st, TICK) {
                Ok((st, _)) => st,
                Err(_) => return Admission::Look,
            };
        };
        st.waiting -= 1;
        let answer = if gone.is_cancelled() {
            Admission::Gone
        } else if timed_out {
            Admission::Look
        } else {
            match &st.outcome {
                Some((r, outcome)) if *r == round => match &**outcome {
                    Outcome::Granted { key: k, values } if key == Some(k) => {
                        Admission::Granted(values.clone())
                    }
                    Outcome::Refused { names: n, reply } if names.iter().all(|x| n.contains(x)) => {
                        Admission::Refused(reply.clone())
                    }
                    _ => Admission::Look,
                },
                _ => Admission::Look,
            }
        };
        if st.waiting == 0 && !st.busy {
            // The last reader has read: nothing of the turn stays.
            st.outcome = None;
        }
        answer
    }
}

impl Turn {
    /// A turn nobody else knows about.
    fn detached() -> Turn {
        Turn {
            gate: Arc::new(Gate::default()),
            done: false,
        }
    }

    /// A session now exists; the waiters look for one.
    pub(crate) fn session_opened(self) {
        self.end(Outcome::Session);
    }

    /// The person approved one use; waiters with the same `key` share it.
    pub(crate) fn granted(self, key: Option<UseKey>, values: &[(String, SecretValue)]) {
        match key {
            Some(key) => self.end(Outcome::Granted {
                key,
                values: values.to_vec(),
            }),
            None => self.end(Outcome::Fell),
        }
    }

    /// The person said no.
    pub(crate) fn refused(self, names: &[String], reply: &ClientReply) {
        self.end(Outcome::Refused {
            names: names.to_vec(),
            reply: reply.clone(),
        });
    }

    /// Nothing was decided (the client went away, or an error).
    pub(crate) fn fell(self) {
        self.end(Outcome::Fell);
    }

    fn end(mut self, outcome: Outcome) {
        self.done = true;
        self.release(outcome);
    }

    fn release(&self, outcome: Outcome) {
        if let Ok(mut st) = self.gate.state.lock() {
            st.busy = false;
            // Kept only for those who are waiting for it.
            st.outcome = (st.waiting > 0).then(|| (st.round, Arc::new(outcome)));
            self.gate.cv.notify_all();
        }
    }
}

impl Drop for Turn {
    fn drop(&mut self) {
        if !self.done {
            self.release(Outcome::Fell);
        }
    }
}
