//! Asking for a yes: the [`Approver`] trait and [`decide_any`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::AuthError;
use crate::factor::{Factor, Need};
use crate::request::Request;

/// Tells the approvers that lost the race to stop. An approver that waits on
/// something it can close (a window) registers a function with
/// [`Cancel::on_cancel`]; one that polls reads [`Cancel::is_cancelled`].
#[derive(Clone, Default)]
pub struct Cancel {
    flag: Arc<AtomicBool>,
    hooks: Arc<Mutex<Vec<Box<dyn FnOnce() + Send>>>>,
}

impl Cancel {
    pub fn new() -> Cancel {
        Cancel::default()
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Run `f` when cancelled (at once, if it already is).
    pub fn on_cancel(&self, f: impl FnOnce() + Send + 'static) {
        if self.is_cancelled() {
            f();
            return;
        }
        if let Ok(mut hooks) = self.hooks.lock() {
            hooks.push(Box::new(f));
            // Cancelled between the check and the push.
            if self.is_cancelled() {
                for h in hooks.drain(..) {
                    h();
                }
            }
        }
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
        let hooks: Vec<_> = self
            .hooks
            .lock()
            .map(|mut h| h.drain(..).collect())
            .unwrap_or_default();
        for h in hooks {
            h();
        }
    }
}

/// One way to get a person's yes.
pub trait Approver: Send + Sync {
    fn factor(&self) -> Factor;
    /// For the journal and the person: "window", the phone's name.
    fn label(&self) -> String;
    /// The device behind it, when it is one.
    fn device_id(&self) -> Option<[u8; 16]> {
        None
    }
    /// Whether it can be asked now (a phone in reach, a window that can open).
    fn available(&self) -> bool;
    /// Ask. The answer is an index into `options`; `None` is no answer (the
    /// person closed it, the time ran out, or it was cancelled). Stop early
    /// when `cancel` fires.
    fn decide(
        &self,
        req: &Request,
        options: &[String],
        timeout: Duration,
        cancel: &Cancel,
    ) -> Result<Option<usize>, AuthError>;
}

/// Who answered, and what.
#[derive(Debug, Clone)]
pub struct Decided {
    pub choice: usize,
    pub factor: Factor,
    pub by: String,
    pub device_id: Option<[u8; 16]>,
}

/// Ask every available approver good enough for `need`, all at once; the first
/// answer wins and the others are cancelled. A window that is among them stays
/// a way through: the password is never made to wait for a phone.
///
/// `Ok(None)` is no one answering; an error only when every approver failed
/// and none answered.
pub fn decide_any(
    approvers: &[&dyn Approver],
    req: &Request,
    options: &[String],
    need: Need,
    timeout: Duration,
) -> Result<Option<Decided>, AuthError> {
    let chosen: Vec<&&dyn Approver> = approvers
        .iter()
        .filter(|a| need.satisfied_by(a.factor()) && a.available())
        .collect();
    if chosen.is_empty() {
        return Err(AuthError::Unavailable(
            "nobody can be asked for this right now".into(),
        ));
    }
    let cancel = Cancel::new();
    let (tx, rx) = mpsc::channel();
    let total = chosen.len();
    let mut winner: Option<Decided> = None;
    let mut first_err: Option<AuthError> = None;
    std::thread::scope(|scope| {
        for (i, a) in chosen.iter().enumerate() {
            let (tx, cancel) = (tx.clone(), cancel.clone());
            let a: &dyn Approver = **a;
            scope.spawn(move || {
                let _ = tx.send((i, a.decide(req, options, timeout, &cancel)));
            });
        }
        drop(tx);
        for _ in 0..total {
            let Ok((i, answer)) = rx.recv() else { break };
            match answer {
                Ok(Some(choice)) if choice < options.len().max(1) => {
                    let a = chosen[i];
                    winner = Some(Decided {
                        choice,
                        factor: a.factor(),
                        by: a.label(),
                        device_id: a.device_id(),
                    });
                    cancel.cancel();
                    break;
                }
                Ok(_) => {}
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        cancel.cancel();
    });
    match (winner, first_err) {
        (Some(w), _) => Ok(Some(w)),
        (None, Some(e)) if total == 1 => Err(e),
        (None, _) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    struct Fake {
        factor: Factor,
        after: Duration,
        answer: Result<Option<usize>, &'static str>,
        up: bool,
        cancelled: Arc<AtomicBool>,
    }

    impl Fake {
        fn new(factor: Factor, after_ms: u64, answer: Option<usize>) -> Fake {
            Fake {
                factor,
                after: Duration::from_millis(after_ms),
                answer: Ok(answer),
                up: true,
                cancelled: Arc::default(),
            }
        }
    }

    impl Approver for Fake {
        fn factor(&self) -> Factor {
            self.factor
        }
        fn label(&self) -> String {
            format!("{:?}", self.factor)
        }
        fn available(&self) -> bool {
            self.up
        }
        fn decide(
            &self,
            _: &Request,
            _: &[String],
            _: Duration,
            cancel: &Cancel,
        ) -> Result<Option<usize>, AuthError> {
            let end = Instant::now() + self.after;
            while Instant::now() < end {
                if cancel.is_cancelled() {
                    self.cancelled.store(true, Ordering::SeqCst);
                    return Ok(None);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            self.answer
                .clone()
                .map_err(|e| AuthError::Unavailable(e.into()))
        }
    }

    fn req() -> Request {
        Request::new(
            crate::Action::AlarmLock,
            "/p",
            [0; 16],
            Duration::from_secs(60),
        )
        .unwrap()
    }

    fn opts() -> Vec<String> {
        vec!["yes".into(), "no".into()]
    }

    #[test]
    fn the_first_answer_wins_and_the_slow_one_is_cancelled() {
        let window = Fake::new(Factor::Knowledge, 5000, Some(1));
        let phone = Fake::new(Factor::PossessionBiometric, 20, Some(0));
        let start = Instant::now();
        let got = decide_any(
            &[&window, &phone],
            &req(),
            &opts(),
            Need::Knowledge,
            Duration::from_secs(30),
        )
        .unwrap()
        .unwrap();
        assert_eq!(got.choice, 0);
        assert_eq!(got.factor, Factor::PossessionBiometric);
        assert!(start.elapsed() < Duration::from_secs(3));
        assert!(window.cancelled.load(Ordering::SeqCst));
    }

    #[test]
    fn the_window_answers_when_the_phone_is_away() {
        let window = Fake::new(Factor::Knowledge, 10, Some(0));
        let mut phone = Fake::new(Factor::PossessionBiometric, 10, Some(1));
        phone.up = false;
        let got = decide_any(
            &[&phone, &window],
            &req(),
            &opts(),
            Need::PasswordOnly,
            Duration::from_secs(5),
        )
        .unwrap()
        .unwrap();
        assert_eq!(got.factor, Factor::Knowledge);
    }

    #[test]
    fn only_approvers_good_enough_are_asked() {
        let presence = Fake::new(Factor::Presence, 1, Some(0));
        let err = decide_any(
            &[&presence],
            &req(),
            &opts(),
            Need::Knowledge,
            Duration::from_secs(1),
        );
        assert!(matches!(err, Err(AuthError::Unavailable(_))));
        // The password answers for a presence-level action too.
        let pw = Fake::new(Factor::Knowledge, 1, Some(1));
        let got = decide_any(
            &[&pw],
            &req(),
            &opts(),
            Need::Presence,
            Duration::from_secs(1),
        )
        .unwrap()
        .unwrap();
        assert_eq!(got.choice, 1);
    }

    #[test]
    fn no_answer_and_errors_do_not_stop_the_others() {
        let silent = Fake::new(Factor::PossessionBiometric, 1, None);
        let mut broken = Fake::new(Factor::PossessionBiometric, 1, None);
        broken.answer = Err("link down");
        let window = Fake::new(Factor::Knowledge, 60, Some(0));
        let got = decide_any(
            &[&silent, &broken, &window],
            &req(),
            &opts(),
            Need::Knowledge,
            Duration::from_secs(5),
        )
        .unwrap()
        .unwrap();
        assert_eq!(got.factor, Factor::Knowledge);
        // Everyone silent: no answer, not an error.
        let none = decide_any(
            &[&silent],
            &req(),
            &opts(),
            Need::Knowledge,
            Duration::from_secs(1),
        );
        assert!(matches!(none, Ok(None)));
        // A choice outside the options is not an answer.
        let wild = Fake::new(Factor::Knowledge, 1, Some(7));
        assert!(matches!(
            decide_any(
                &[&wild],
                &req(),
                &opts(),
                Need::Knowledge,
                Duration::from_secs(1)
            ),
            Ok(None)
        ));
    }
}
