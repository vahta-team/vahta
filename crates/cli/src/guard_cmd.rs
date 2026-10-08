//! `vahta _guard`: the hook watchdog.
//!
//! A small process, separate from the daemon and outliving it, that watches the
//! hook settings of Claude Code, Codex and Cursor. If an agent or a tool removes
//! Vahta's hooks, or sets `disableAllHooks`, it asks the person (through the
//! daemon's window) before putting them back; with no answer in two minutes it
//! puts them back on its own.
//!
//! What it is **not**: it holds no vault key (it never opens a vault), opens no
//! network socket (the only socket it connects to is the daemon's, in the
//! user's runtime directory), and reads only the files it watches. Those are
//! each harness's hook config, Claude Code settings files of the projects the
//! daemon has seen, and Codex's `config.toml`.
//!
//! One runs per user: it holds `guard.lock` in the runtime directory. It looks
//! at the files' modification times every two seconds (polling, no watcher
//! library) and re-reads them when one changed. It ends when `guard.stop` is
//! created (`vahta setup --uninstall` does that), when the config no longer
//! says `guard = "on"`, or when its runtime directory is gone.

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use vahta_harness::Manifest;
use vahta_ipc::client::Connector;
use vahta_ipc::config::{Config, Guard};
use vahta_ipc::paths::Paths;
use vahta_ipc::protocol::{ClientReply, ClientRequest, GuardChoice, GuardEvent, Signal};
use vahta_ipc::spool::{self, SpoolLine};
use vahta_setup::guard::{self, Tamper};

use crate::autostart::{self, SystemRunner};
use crate::daemon_cmd;
use crate::{EXIT_CLEAN, EXIT_DAEMON, Env};

fn manifests() -> Vec<Manifest> {
    vahta_harness::HARNESSES
        .iter()
        .filter_map(|h| vahta_harness::manifest(h).and_then(Result::ok))
        .collect()
}

fn unix_now() -> u64 {
    vahta_ipc::state::now()
}

/// A cheap fingerprint of the watched files: when each was last changed, and
/// how long it is. Equal fingerprints mean nothing needs re-reading.
fn fingerprint(files: &[PathBuf], extra: &[PathBuf]) -> Vec<Option<(SystemTime, u64)>> {
    files
        .iter()
        .chain(extra)
        .map(|f| {
            std::fs::metadata(f)
                .ok()
                .map(|m| (m.modified().unwrap_or(SystemTime::UNIX_EPOCH), m.len()))
        })
        .collect()
}

/// Ask the daemon (starting it if need be) what to do about `t`.
fn ask(env: &Env, t: &Tamper) -> Option<GuardChoice> {
    let connector = daemon_cmd::connector(env, true).ok()?;
    let mut conn = connector.connect().ok()?;
    let reply = conn
        .request(&ClientRequest::GuardAsk {
            harness: t.harness.clone(),
            file: t.file.display().to_string(),
            what: t.what.clone(),
        })
        .ok()?;
    match reply {
        ClientReply::GuardChoice { choice } => Some(choice),
        _ => None,
    }
}

/// Tell the daemon what the watchdog did. Never starts a daemon for it: the
/// note is only for the journal, and a daemon that is not there is told
/// nothing.
fn note(connector: &Connector, harness: &str, file: &str, event: GuardEvent) {
    if let Ok(Some(mut conn)) = connector.connect_running() {
        let _ = conn.request(&ClientRequest::GuardNote {
            harness: harness.to_string(),
            file: file.to_string(),
            event,
        });
    }
}

/// With no daemon to ask or tell, leave the report where the next daemon
/// finds it.
fn spool_tamper(paths: &Paths, t: &Tamper) {
    let _ = spool::append(
        paths,
        &SpoolLine {
            time: unix_now(),
            session: None,
            harness: t.harness.clone(),
            cwd: String::new(),
            signal: Signal::HookTamper {
                file: t.file.display().to_string(),
                what: t.what.clone(),
            },
        },
    );
}

/// How often the files are looked at.
fn poll() -> Duration {
    vahta_daemon::testing::guard_poll().unwrap_or(Duration::from_secs(2))
}

pub fn run(env: &Env, stderr: &mut dyn Write) -> i32 {
    let Ok(paths) = daemon_cmd::paths(env) else {
        let _ = writeln!(
            stderr,
            "vahta _guard: error: cannot tell where Vahta keeps its files"
        );
        return EXIT_DAEMON;
    };
    if paths.ensure_runtime_dir().is_err() {
        return EXIT_DAEMON;
    }
    let lock = match OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(paths.guard_lock_file())
    {
        Ok(f) => f,
        Err(_) => return EXIT_DAEMON,
    };
    match lock.try_lock() {
        Ok(()) => {}
        // Another one is watching: nothing to do.
        Err(std::fs::TryLockError::WouldBlock) => return EXIT_CLEAN,
        Err(_) => return EXIT_DAEMON,
    }
    let _ = lock.set_len(0);
    let _ = (&lock).write_all(std::process::id().to_string().as_bytes());
    // A stop request from before this process started is not for it.
    let _ = std::fs::remove_file(paths.guard_stop_file());

    let Some(setup) = env.setup.clone() else {
        return EXIT_DAEMON;
    };
    let ms = manifests();
    let connector = match daemon_cmd::connector(env, false) {
        Ok(c) => c,
        Err(_) => return EXIT_DAEMON,
    };
    let mut expected: BTreeSet<String> = guard::read_expected(&paths.data);
    let mut last = Vec::new();
    let mut first = true;
    let slice = Duration::from_millis(100).min(poll());
    let mut next_look = Instant::now();
    loop {
        if paths.guard_stop_file().exists() {
            let _ = std::fs::remove_file(paths.guard_stop_file());
            break;
        }
        // Its own directory gone (a removed sandbox, a logout): nothing to watch for.
        if !paths.guard_lock_file().exists() {
            break;
        }
        if Instant::now() < next_look {
            std::thread::sleep(slice);
            continue;
        }
        next_look = Instant::now() + poll();
        match Config::load(&paths.config_file()) {
            Ok(c) if c.guard != Some(Guard::On) => break,
            _ => {}
        }
        let now = unix_now();
        // A pause that has run out: the hooks come back.
        let mut pauses = guard::read_pauses(&paths.data);
        let (over, still): (Vec<_>, Vec<_>) = pauses.drain(..).partition(|p| p.until <= now);
        if !over.is_empty() {
            for p in &over {
                if let Some(m) = ms.iter().find(|m| m.name == p.harness) {
                    let file = vahta_setup::config_path(m, &setup)
                        .map(|f| f.display().to_string())
                        .unwrap_or_default();
                    let event = match guard::add_entries(m, &setup) {
                        Ok(_) => GuardEvent::RestoredAfterPause,
                        Err(_) => GuardEvent::RestoreFailed,
                    };
                    note(&connector, &p.harness, &file, event);
                }
            }
            let _ = guard::write_pauses(&paths.data, &still);
            pauses = still;
        } else {
            pauses = still;
        }
        let projects = guard::read_projects(&paths.data);
        let files = guard::watched_files(&ms, &setup, &projects);
        let extra = [guard::pause_file(&paths.data)];
        let now_fp = fingerprint(&files, &extra);
        if !first && now_fp == last && over.is_empty() {
            continue;
        }
        first = false;
        let before = expected.clone();
        let found = guard::check(&ms, &setup, &projects, &mut expected, &pauses, now);
        if expected != before {
            let _ = guard::write_expected(&paths.data, &expected);
        }
        let mut turned_off = false;
        for t in &found {
            let choice = ask(env, t);
            let file = t.file.display().to_string();
            match choice {
                Some(GuardChoice::KeepOff { .. }) => {}
                Some(GuardChoice::TurnOff) => {
                    autostart::disable(&setup, &SystemRunner);
                    note(&connector, &t.harness, &file, GuardEvent::TurnedOff);
                    turned_off = true;
                    break;
                }
                // Restore, or nobody to ask: put it back.
                other => {
                    if other.is_none() {
                        spool_tamper(&paths, t);
                    }
                    let event = match guard::restore(&ms, &setup, t) {
                        Ok(()) if other.is_none() => GuardEvent::Unasked,
                        Ok(()) => GuardEvent::Restored,
                        Err(_) => GuardEvent::RestoreFailed,
                    };
                    note(&connector, &t.harness, &file, event);
                }
            }
        }
        if turned_off {
            break;
        }
        // What we changed ourselves is not news next time.
        last = fingerprint(&files, &extra);
    }
    drop(lock);
    EXIT_CLEAN
}

/// One line on how the watchdog stands, for `vahta setup` and `vahta check`.
pub fn status_line(env: &Env) -> String {
    let Ok(paths) = daemon_cmd::paths(env) else {
        return "hook watchdog: unknown (no data directory)".to_string();
    };
    let guard = Config::load(&paths.config_file())
        .ok()
        .and_then(|c| c.guard);
    match guard {
        Some(Guard::On) => {
            let running = if paths.guard_running() {
                "running"
            } else {
                "not running right now (the daemon starts it)"
            };
            let login = match (&env.setup, std::env::current_exe()) {
                (Some(s), Ok(exe)) => match guard::autostart_present(&guard::autostart(s, &exe)) {
                    Some(true) => ", starts at login",
                    Some(false) => ", does not start at login",
                    None => "",
                },
                _ => "",
            };
            format!("hook watchdog: on, {running}{login}")
        }
        Some(Guard::Off) => "hook watchdog: off: if an agent removes Vahta's hooks, nothing \
             notices. Turn it on with `vahta setup --guard on`"
            .to_string(),
        None => "hook watchdog: not decided yet. It watches the hook settings and asks before \
             putting them back; `vahta setup --guard on` (or `off`) answers"
            .to_string(),
    }
}

/// `vahta check` always says how the watchdog stands, on stderr and only in
/// text mode, so its stdout and its JSON stay as CI reads them.
pub fn note_check(args: &[String], env: &Env, stderr: &mut dyn Write) {
    if args
        .iter()
        .any(|a| a == "--json" || a == "-h" || a == "--help")
    {
        return;
    }
    let line = status_line(env);
    let _ = writeln!(stderr, "vahta: {line}");
}

/// Start the watchdog now, detached, if none runs. It is a plain
/// `vahta _guard` with the directories this command resolved.
pub fn spawn(env: &Env) -> Result<(), String> {
    let paths = daemon_cmd::paths(env)?;
    if paths.guard_running() {
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    vahta_os::spawn_detached(
        std::process::Command::new(exe)
            .arg("_guard")
            .env("VAHTA_RUNTIME_DIR", &paths.runtime)
            .env("VAHTA_DATA_DIR", &paths.data)
            .env("VAHTA_CONFIG_DIR", &paths.config),
    )
    .map_err(|e| e.to_string())
}

/// Wait up to `secs` seconds for a watchdog to be running (one an autostart
/// service manager just started). `true` once one runs.
pub fn wait_running(env: &Env, secs: u64) -> bool {
    let Ok(paths) = daemon_cmd::paths(env) else {
        return false;
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        if paths.guard_running() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Ask a running watchdog to end, and wait (up to five seconds) until it has.
/// `true` when none runs afterwards.
pub fn stop(env: &Env) -> bool {
    let Ok(paths) = daemon_cmd::paths(env) else {
        return true;
    };
    if !paths.guard_running() {
        return true;
    }
    if paths.ensure_runtime_dir().is_err() || std::fs::write(paths.guard_stop_file(), b"").is_err()
    {
        return false;
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if !paths.guard_running() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_file(paths.guard_stop_file());
    !paths.guard_running()
}
