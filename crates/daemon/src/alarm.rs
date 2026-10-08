//! The injection alarm: does this agent look prompt-injected?
//!
//! Hooks tell the daemon what an agent tried (`report.rs`): a secret-shaped
//! value in a command, a touch of Vahta's own files, a command meant for the
//! person, a held value written in some encoding. One of those can be an
//! honest mistake. Several in a few minutes, and above all an agent that keeps
//! rewriting the same value to get it past the hook, are what a hijacked
//! agent looks like. The alarm scores them per **subject** and goes off past
//! a threshold.
//!
//! **Subject.** The harness's own session id when its payload had one, else
//! the agent process the report came from (the same anchor `unlock` chooses).
//! Reports from the spool, written while no daemon ran, count too, at the
//! time they were written.
//!
//! **Weights.** Each signal is worth:
//!
//! | Signal                          | Weight |
//! |---------------------------------|--------|
//! | `Blocked`                       | 1      |
//! | `Observed`                      | 0.5    |
//! | `Blocked`, value hidden         | 4      |
//! | `KnownValue`                    | 6      |
//! | `VahtaFileTouch`                | 3      |
//! | `AgentGuard` (reveal, copy)     | 2      |
//! | `HookTamper`                    | 4      |
//!
//! The score is the sum over the last [`WINDOW`]; at [`THRESHOLD`] or more the
//! alarm goes off, at most once per subject per [`THROTTLE`]. A held value in
//! a command (6) is enough alone; so are two disguised secrets (4 + 4) or a
//! disguised secret and a touch of Vahta's files (4 + 3).
//!
//! **Action** (config `alarm`). `warn`, the default, opens a window titled
//! "Suspicious agent behaviour" with what was seen (kinds, never values) and
//! two choices: lock every session, or ignore this agent session from now on.
//! No answer does nothing, and the alarm is journalled. `lock`, or no window
//! to ask in (headless, cloud), ends every session at once and, if a window
//! can be opened, tells the person what happened.
//!
//! Nothing here sees a value: signals carry categories, rule ids and paths,
//! and the text of this module's windows and journal entries is built from
//! the kinds below.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vahta_ipc::config::AlarmAction;

use crate::journal::Entry;
use crate::protocol::{Panel, Signal};
use crate::server::Shared;
use crate::surface::SurfaceError;

/// How far back signals count.
pub const WINDOW: Duration = Duration::from_secs(10 * 60);
/// The score at which the alarm goes off.
pub const THRESHOLD: f64 = 6.0;
/// The least time between two alarms for one subject.
pub const THROTTLE: Duration = Duration::from_secs(10 * 60);
/// How long the question stays up.
const ANSWER_WITHIN: Duration = Duration::from_secs(10 * 60);
/// How many subjects are tracked at once; the quietest is dropped first.
const MAX_SUBJECTS: usize = 256;

/// What a signal is worth, and how the window names it.
fn weigh(signal: &Signal) -> (f64, String) {
    match signal {
        Signal::Blocked {
            evasion: Some(e), ..
        } => (4.0, format!("a secret hidden as {}", e.as_str())),
        Signal::Blocked { evasion: None, .. } => (1.0, "a secret-shaped value".to_string()),
        Signal::Observed { .. } => (0.5, "a secret-shaped value (let through)".to_string()),
        Signal::KnownValue { form } => (6.0, format!("a value Vahta holds, written as {form}")),
        Signal::VahtaFileTouch { .. } => (3.0, "a touch of Vahta's own files".to_string()),
        Signal::AgentGuard { .. } => (2.0, "a command meant for the person".to_string()),
        Signal::HookTamper { .. } => (4.0, "a change to the hook settings".to_string()),
    }
}

/// Who the signals are about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// What signals are grouped by.
    pub key: String,
    /// How the person reads it: the harness and the agent session or process.
    pub shown: String,
}

struct Seen {
    at: Instant,
    weight: f64,
    what: String,
}

#[derive(Default)]
struct Track {
    seen: VecDeque<Seen>,
    last_alarm: Option<Instant>,
}

/// Why the alarm went off.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub score: f64,
    /// The kinds in the window with their counts, for the person.
    pub summary: String,
}

#[derive(Default)]
struct State {
    tracks: HashMap<String, Track>,
    ignored: HashSet<String>,
    /// When the alarm last went off (Unix seconds), until the next unlock.
    raised_at: Option<u64>,
}

#[derive(Default)]
pub struct Alarm {
    state: Mutex<State>,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Alarm {
    /// Score `signal` for `subject`, seen at `at`. `Some` when this is the
    /// signal that takes the subject past the threshold, and it has not been
    /// raised (or ignored) already.
    pub fn record(&self, subject: &Subject, signal: &Signal, at: Instant) -> Option<Verdict> {
        let mut state = self.state.lock().ok()?;
        let (weight, what) = weigh(signal);
        if state.tracks.len() >= MAX_SUBJECTS && !state.tracks.contains_key(&subject.key) {
            // Forget the subject whose newest signal is oldest.
            let oldest = state
                .tracks
                .iter()
                .min_by_key(|(_, t)| t.seen.back().map(|s| s.at))
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                state.tracks.remove(&k);
            }
        }
        let ignored = state.ignored.contains(&subject.key);
        let now = Instant::now();
        // A spooled signal may be older than the window already.
        if now.saturating_duration_since(at) >= WINDOW {
            return None;
        }
        let track = state.tracks.entry(subject.key.clone()).or_default();
        track
            .seen
            .retain(|s| now.saturating_duration_since(s.at) < WINDOW);
        track.seen.push_back(Seen { at, weight, what });
        let score: f64 = track.seen.iter().map(|s| s.weight).sum();
        if ignored || score < THRESHOLD {
            return None;
        }
        if track
            .last_alarm
            .is_some_and(|t| now.saturating_duration_since(t) < THROTTLE)
        {
            return None;
        }
        track.last_alarm = Some(now);
        let mut counts: Vec<(&str, usize)> = Vec::new();
        for s in &track.seen {
            match counts.iter_mut().find(|(w, _)| *w == s.what) {
                Some((_, n)) => *n += 1,
                None => counts.push((&s.what, 1)),
            }
        }
        let summary = counts
            .iter()
            .map(|(w, n)| {
                if *n > 1 {
                    format!("{w} x{n}")
                } else {
                    (*w).to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        Some(Verdict { score, summary })
    }

    /// The person chose to ignore this subject: no more alarms for it.
    pub fn ignore(&self, subject: &Subject) {
        if let Ok(mut s) = self.state.lock() {
            s.ignored.insert(subject.key.clone());
        }
    }

    pub fn mark_raised(&self) {
        if let Ok(mut s) = self.state.lock() {
            s.raised_at = Some(unix_now());
        }
    }

    /// Sessions were unlocked again: the alarm is over.
    pub fn clear_raised(&self) {
        if let Ok(mut s) = self.state.lock() {
            s.raised_at = None;
        }
    }

    /// When the alarm last went off, if sessions have not been unlocked since.
    pub fn raised_at(&self) -> Option<u64> {
        self.state.lock().ok().and_then(|s| s.raised_at)
    }
}

/// The alarm has gone off for `subject`: act on it. Never blocks the caller
/// on a window.
pub(crate) fn raise(shared: &Arc<Shared>, subject: Subject, verdict: Verdict) {
    shared.alarm.mark_raised();
    let action = shared.options.config.alarm;
    let detail = format!(
        "{}; score {}; {}",
        subject.shown, verdict.score, verdict.summary
    );
    shared.journal.record(Entry::new("alarm").result(
        match action {
            AlarmAction::Warn => "warn",
            AlarmAction::Lock => "lock",
        },
        Some(&detail),
    ));
    let shared = shared.clone();
    match action {
        AlarmAction::Lock => {
            let n = lock_everything(&shared, "the alarm is set to lock");
            let _ = std::thread::Builder::new()
                .name("vahta-alarm".to_string())
                .spawn(move || inform(&shared, &subject, &verdict, n));
        }
        AlarmAction::Warn => {
            let _ = std::thread::Builder::new()
                .name("vahta-alarm".to_string())
                .spawn(move || warn(&shared, subject, verdict));
        }
    }
}

fn lock_everything(shared: &Arc<Shared>, why: &str) -> usize {
    let n = shared.end_all_sessions("alarm");
    shared.journal.record(
        Entry::new("alarm").result("locked", Some(&format!("{n} session(s) ended; {why}"))),
    );
    n
}

fn panel(subject: &Subject, verdict: &Verdict, lead: &str, ending: &str) -> Panel {
    Panel {
        title: "Suspicious agent behaviour".to_string(),
        lines: vec![
            format!("{lead}: {}.", verdict.summary),
            ending.to_string(),
            format!("Agent: {}", subject.shown),
        ],
        warning: None,
        agent_note: None,
    }
}

const LEAD: &str = "This looks like prompt injection or an agent far outside its task";

/// Tell the person what the lock did, if a window can be had.
fn inform(shared: &Arc<Shared>, subject: &Subject, verdict: &Verdict, ended: usize) {
    let Ok(window) = shared.surface.open("Suspicious agent behaviour") else {
        return;
    };
    window.close(Some(&format!(
        "{LEAD}: {}. Vahta locked {ended} session(s) ({}). Stop or restart the agent, then \
         unlock again.",
        verdict.summary, subject.shown
    )));
}

fn warn(shared: &Arc<Shared>, subject: Subject, verdict: Verdict) {
    let mut window = match shared.surface.open("Suspicious agent behaviour") {
        Ok(w) => w,
        Err(_) => {
            // Nobody to ask (headless, cloud): fail closed.
            lock_everything(shared, "no window could be opened to ask");
            return;
        }
    };
    let p = panel(
        &subject,
        &verdict,
        LEAD,
        "Lock Vahta sessions now, then stop or restart the agent.",
    );
    let options = [
        "Lock all sessions".to_string(),
        "Ignore for this agent session".to_string(),
    ];
    match window.choose_within(&p, "What now?", &options, ANSWER_WITHIN) {
        Ok(Some(0)) => {
            let n = lock_everything(shared, "the person chose to lock");
            window.close(Some(&format!("Locked {n} session(s).")));
        }
        Ok(Some(_)) => {
            shared.alarm.ignore(&subject);
            shared.journal.record(Entry::new("alarm_ignored").result(
                "ignored",
                Some(&format!("{}; the person chose to ignore", subject.shown)),
            ));
            window.close(None);
        }
        Ok(None) | Err(SurfaceError::Timeout) | Err(SurfaceError::Closed) => {
            shared.journal.record(
                Entry::new("alarm")
                    .result("no_answer", Some("nothing was done; sessions stay open")),
            );
        }
        Err(_) => {
            // The window broke while asking: not an answer, and not safe.
            lock_everything(shared, "the question could not be asked");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Evasion;

    fn who(n: &str) -> Subject {
        Subject {
            key: format!("session:{n}"),
            shown: format!("claude session {n}"),
        }
    }

    fn evaded() -> Signal {
        Signal::Blocked {
            category: "an API token".into(),
            rule: "r".into(),
            evasion: Some(Evasion::Base64),
        }
    }

    fn plain() -> Signal {
        Signal::Blocked {
            category: "an API token".into(),
            rule: "r".into(),
            evasion: None,
        }
    }

    #[test]
    fn weights_add_up_to_the_threshold() {
        let a = Alarm::default();
        let s = who("a");
        let now = Instant::now();
        assert!(a.record(&s, &evaded(), now).is_none());
        let v = a.record(&s, &evaded(), now).expect("4 + 4 is enough");
        assert_eq!(v.score, 8.0);
        assert_eq!(v.summary, "a secret hidden as base64 x2");

        // A held value is enough alone; plain blocks need six of them.
        let b = Alarm::default();
        let k = Signal::KnownValue {
            form: "base64".into(),
        };
        assert!(b.record(&s, &k, now).is_some());
        let c = Alarm::default();
        for _ in 0..5 {
            assert!(c.record(&s, &plain(), now).is_none());
        }
        assert!(c.record(&s, &plain(), now).is_some());
        // Observed counts half.
        let d = Alarm::default();
        let o = Signal::Observed {
            category: "x".into(),
            rule: "r".into(),
            evasion: None,
        };
        for _ in 0..11 {
            assert!(d.record(&s, &o, now).is_none());
        }
        assert!(d.record(&s, &o, now).is_some());
    }

    #[test]
    fn the_other_signals_weigh_what_the_table_says() {
        let now = Instant::now();
        let touch = Signal::VahtaFileTouch { path: "p".into() };
        let guard = Signal::AgentGuard {
            command: "c".into(),
        };
        let tamper = Signal::HookTamper {
            file: "f".into(),
            what: "w".into(),
        };
        let score = |signals: &[Signal]| {
            let a = Alarm::default();
            let s = who("x");
            let mut last = None;
            for sig in signals {
                last = a.record(&s, sig, now).or(last);
            }
            last.map(|v| v.score)
        };
        assert_eq!(score(&[touch.clone(), touch.clone()]), Some(6.0));
        assert_eq!(score(&[touch.clone(), guard.clone()]), None);
        assert_eq!(
            score(&[touch.clone(), guard.clone(), guard.clone()]),
            Some(7.0)
        );
        assert_eq!(score(&[tamper.clone(), guard.clone()]), Some(6.0));
    }

    #[test]
    fn signals_decay_after_the_window() {
        let a = Alarm::default();
        let s = who("a");
        let now = Instant::now();
        let Some(long_ago) = now.checked_sub(WINDOW + Duration::from_secs(5)) else {
            return;
        };
        // One disguised secret, long ago, does not add to one now.
        assert!(a.record(&s, &evaded(), long_ago).is_none());
        assert!(a.record(&s, &evaded(), now).is_none());
        // Two within the window do.
        let recent = now - Duration::from_secs(60);
        assert!(a.record(&s, &evaded(), recent).is_some());
    }

    #[test]
    fn one_alarm_per_subject_per_throttle_and_subjects_are_apart() {
        let a = Alarm::default();
        let (x, y) = (who("x"), who("y"));
        let now = Instant::now();
        let k = Signal::KnownValue { form: "hex".into() };
        assert!(a.record(&x, &k, now).is_some());
        assert!(a.record(&x, &k, now).is_none(), "throttled");
        assert!(a.record(&x, &k, now).is_none());
        // Another agent session has its own score.
        assert!(a.record(&y, &plain(), now).is_none());
        assert!(a.record(&y, &k, now).is_some());
    }

    #[test]
    fn an_ignored_subject_is_not_raised_again() {
        let a = Alarm::default();
        let s = who("a");
        let k = Signal::KnownValue { form: "hex".into() };
        assert!(a.record(&s, &k, Instant::now()).is_some());
        a.ignore(&s);
        assert!(a.record(&s, &k, Instant::now()).is_none());
    }

    #[test]
    fn raised_until_cleared() {
        let a = Alarm::default();
        assert!(a.raised_at().is_none());
        a.mark_raised();
        assert!(a.raised_at().is_some());
        a.clear_raised();
        assert!(a.raised_at().is_none());
    }
}
