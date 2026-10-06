//! Ending sessions when the machine sleeps or the screen locks
//! (`lock_on_sleep` in config.toml, on by default).
//!
//! A person who closes the laptop lid has left; a session that outlives that is
//! a window of time for whatever else runs as them. What tells the daemon so
//! differs by system: logind's signals, a compositor's own socket, a desktop's
//! lock service. This file knows none of them. It defines what a trigger is
//! ([`LockSource`]), what a trigger may do ([`LockSink`]), and starts the ones
//! that apply. Each trigger lives in its own file in this directory.
//!
//! To add one: write `lock/<name>.rs` with a type that implements
//! [`LockSource`], and add one line to [`sources`]. The core does not change.
//!
//! Sources in this version:
//!
//! * `logind` (Linux): `PrepareForSleep`, `Lock` and `LockedHint` over the
//!   local system bus.
//! * `hyprland` (Linux, cargo feature `lock-hyprland`): lockers on Hyprland
//!   (hyprlock, Omarchy's shell) tell logind nothing, so the compositor is
//!   asked directly while a session is open.
//!
//! Other screen lockers that tell neither are not heard by a source, but any of
//! them can run `vahta lock --all` (it needs no password) as a custom trigger.
//!
//! macOS and Windows: not in this version. The daemon says so in its journal
//! rather than leaving the person to assume.

#[cfg(all(target_os = "linux", feature = "lock-hyprland"))]
mod hyprland;
#[cfg(target_os = "linux")]
mod logind;

use std::sync::Arc;

use crate::journal::{Entry, Journal};
use crate::server::Shared;

/// One way of finding out that the person has left.
pub trait LockSource: Send {
    /// Short stable name, used in the journal and in `lock_sources` in
    /// config.toml: "logind", "hyprland".
    fn name(&self) -> &'static str;

    /// Run in its own thread until `sink.stopping()`. Returns at once if it does
    /// not apply here (no system bus, not inside Hyprland, ...), after saying so
    /// through [`LockSink::note`].
    fn run(self: Box<Self>, sink: LockSink);
}

/// What the daemon's core offers a source. Behind a trait, and not `Shared`
/// itself, so a source cannot reach sessions, keys or the surface, and so the
/// core can be tested without a whole daemon.
pub(crate) trait Core: Send + Sync {
    fn journal(&self) -> &Journal;
    fn end_all_sessions(&self, reason: &'static str) -> usize;
    // Only polling sources ask; a build with none has no caller.
    #[allow(dead_code)]
    fn live_sessions(&self) -> usize;
    fn stopping(&self) -> bool;
}

impl Core for Shared {
    fn journal(&self) -> &Journal {
        &self.journal
    }
    fn end_all_sessions(&self, reason: &'static str) -> usize {
        Shared::end_all_sessions(self, reason)
    }
    fn live_sessions(&self) -> usize {
        Shared::live_sessions(self)
    }
    fn stopping(&self) -> bool {
        Shared::stopping(self)
    }
}

/// The narrow handle a source gets: it can end sessions, ask whether there are
/// any and whether the daemon is stopping, and write to the journal. Cheap to
/// clone, for a source that watches from several threads.
#[derive(Clone)]
pub struct LockSink {
    core: Arc<dyn Core>,
}

// Not every build has a caller of each method (no source on Windows or macOS).
#[cfg_attr(
    not(any(target_os = "linux", feature = "test-surface")),
    allow(dead_code)
)]
impl LockSink {
    pub(crate) fn new(core: Arc<dyn Core>) -> LockSink {
        LockSink { core }
    }

    /// End every session because the machine slept or locked, and journal why.
    pub fn lock(&self, why: &str) {
        let n = self.core.end_all_sessions("sleep");
        self.core.journal().record(
            Entry::new("sleep_lock")
                .result("ok", Some(why))
                .uses(n as u64),
        );
    }

    /// Whether any session is open. A source that has to poll can skip the
    /// poll while there is nothing to end.
    #[allow(dead_code)]
    pub fn sessions_open(&self) -> bool {
        self.core.live_sessions() > 0
    }

    /// Whether the daemon is shutting down.
    pub fn stopping(&self) -> bool {
        self.core.stopping()
    }

    /// Journal the state of `lock_on_sleep`: "listening", "unavailable",
    /// "disabled" or the like, with the reason.
    pub fn note(&self, result: &str, reason: &str) {
        self.core
            .journal()
            .record(Entry::new("lock_on_sleep").result(result, Some(reason)));
    }
}

/// Every source compiled into this build that could apply on this platform.
/// The only place in the core with a `cfg` on the system or a feature.
#[allow(clippy::vec_init_then_push)]
fn sources() -> Vec<Box<dyn LockSource>> {
    #[allow(unused_mut)]
    let mut all: Vec<Box<dyn LockSource>> = Vec::new();
    #[cfg(target_os = "linux")]
    all.push(Box::new(logind::Logind));
    #[cfg(all(target_os = "linux", feature = "lock-hyprland"))]
    all.push(Box::new(hyprland::Hyprland));
    all
}

/// Start listening, if `lock_on_sleep` is on and this platform can.
pub(crate) fn start(shared: &Arc<Shared>) {
    let sink = LockSink::new(shared.clone());
    if !shared.options.config.lock_on_sleep {
        sink.note("disabled", "config.toml");
        return;
    }
    start_sources(
        &sink,
        sources(),
        shared.options.config.lock_sources.as_deref(),
    );
    crate::testing::start_sleep_trigger(&sink);
}

/// Start `available` on a thread each, those named in `enabled` (all of them
/// when it is `None`). Returns the names it started. A name nothing answers to
/// is journalled and ignored.
fn start_sources(
    sink: &LockSink,
    available: Vec<Box<dyn LockSource>>,
    enabled: Option<&[String]>,
) -> Vec<&'static str> {
    if available.is_empty() {
        sink.note("unavailable", "not implemented on this platform");
        return Vec::new();
    }
    if let Some(wanted) = enabled {
        for name in wanted {
            if !available.iter().any(|s| s.name() == name) {
                sink.note("ignored", &format!("unknown lock source {name:?}"));
            }
        }
    }
    let mut started = Vec::new();
    for source in available {
        let name = source.name();
        if enabled.is_some_and(|wanted| !wanted.iter().any(|w| w == name)) {
            continue;
        }
        let thread_sink = sink.clone();
        let spawned = std::thread::Builder::new()
            .name(format!("vahta-lock-{name}"))
            .spawn(move || source.run(thread_sink));
        match spawned {
            Ok(_) => started.push(name),
            Err(_) => sink.note("unavailable", &format!("{name}: no thread")),
        }
    }
    if started.is_empty() {
        sink.note("disabled", "lock_sources in config.toml");
    }
    started
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    /// A core with a real journal in a temp dir and a counter for sessions.
    struct FakeCore {
        journal: Journal,
        ended: AtomicUsize,
        open: usize,
    }

    impl Core for FakeCore {
        fn journal(&self) -> &Journal {
            &self.journal
        }
        fn end_all_sessions(&self, _reason: &'static str) -> usize {
            self.ended.fetch_add(1, Ordering::SeqCst);
            self.open
        }
        fn live_sessions(&self) -> usize {
            self.open
        }
        fn stopping(&self) -> bool {
            false
        }
    }

    fn fake(dir: &tempfile::TempDir, open: usize) -> (Arc<FakeCore>, LockSink) {
        let core = Arc::new(FakeCore {
            journal: Journal::open(&dir.path().join("journal.jsonl")),
            ended: AtomicUsize::new(0),
            open,
        });
        (core.clone(), LockSink::new(core))
    }

    fn journal_text(dir: &tempfile::TempDir) -> String {
        std::fs::read_to_string(dir.path().join("journal.jsonl")).unwrap_or_default()
    }

    /// A source that reports it ran, then locks.
    struct Fake {
        name: &'static str,
        ran: Mutex<mpsc::Sender<&'static str>>,
    }

    impl LockSource for Fake {
        fn name(&self) -> &'static str {
            self.name
        }
        fn run(self: Box<Self>, sink: LockSink) {
            sink.lock("x");
            if let Ok(tx) = self.ran.lock() {
                let _ = tx.send(self.name);
            }
        }
    }

    fn fakes(names: &[&'static str]) -> (Vec<Box<dyn LockSource>>, mpsc::Receiver<&'static str>) {
        let (tx, rx) = mpsc::channel();
        let list = names
            .iter()
            .map(|&name| {
                Box::new(Fake {
                    name,
                    ran: Mutex::new(tx.clone()),
                }) as Box<dyn LockSource>
            })
            .collect();
        (list, rx)
    }

    #[test]
    fn a_source_that_locks_ends_the_sessions_and_journals_why() {
        let dir = tempfile::tempdir().unwrap();
        let (core, sink) = fake(&dir, 2);
        let (list, rx) = fakes(&["fake"]);
        assert_eq!(start_sources(&sink, list, None), ["fake"]);
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(5)),
            Ok("fake")
        );
        assert_eq!(core.ended.load(Ordering::SeqCst), 1);
        let journal = journal_text(&dir);
        assert!(journal.contains("sleep_lock"), "{journal}");
        assert!(journal.contains("\"reason\":\"x\""), "{journal}");
        assert!(sink.sessions_open());
    }

    #[test]
    fn lock_sources_filters_which_sources_start() {
        let dir = tempfile::tempdir().unwrap();
        let (core, sink) = fake(&dir, 0);

        // Not set: all of them.
        let (list, rx) = fakes(&["a", "b"]);
        assert_eq!(start_sources(&sink, list, None), ["a", "b"]);
        for _ in 0..2 {
            rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        }

        // Named: only those, and a name nothing answers to is journalled.
        let (list, rx) = fakes(&["a", "b"]);
        let wanted = ["b".to_string(), "nope".to_string()];
        assert_eq!(start_sources(&sink, list, Some(&wanted)), ["b"]);
        assert_eq!(rx.recv_timeout(std::time::Duration::from_secs(5)), Ok("b"));
        assert!(journal_text(&dir).contains("unknown lock source \\\"nope\\\""));

        // Empty: none, and it says so.
        let before = core.ended.load(Ordering::SeqCst);
        let (list, rx) = fakes(&["a", "b"]);
        assert!(start_sources(&sink, list, Some(&[])).is_empty());
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(200))
                .is_err()
        );
        assert_eq!(core.ended.load(Ordering::SeqCst), before);
        assert!(journal_text(&dir).contains("lock_sources in config.toml"));
    }

    #[test]
    fn no_source_on_a_platform_is_said_so() {
        let dir = tempfile::tempdir().unwrap();
        let (_core, sink) = fake(&dir, 0);
        assert!(start_sources(&sink, Vec::new(), None).is_empty());
        assert!(journal_text(&dir).contains("not implemented on this platform"));
    }
}
