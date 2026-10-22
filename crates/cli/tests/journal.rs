//! `vahta journal`: a journal written by hand in a temp data directory, read by
//! the real binary with no daemon.

#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::{Value, json};

static NEXT: AtomicU32 = AtomicU32::new(0);

struct Box_ {
    root: PathBuf,
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Never written whole in the repository.
fn value() -> String {
    format!("{}-{}-{}", "fake", "journal", "value")
}

impl Box_ {
    fn new(lines: &[Value]) -> Box_ {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("vahta-jr-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for d in ["home", "run", "data", "config"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        let body: String = lines.iter().map(|l| format!("{l}\n")).collect();
        fs::write(root.join("data/journal.jsonl"), body).unwrap();
        Box_ { root }
    }

    fn vahta(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vahta"))
            .current_dir(&self.root)
            .args(args)
            .env("HOME", self.root.join("home"))
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env_remove("XDG_RUNTIME_DIR")
            .env("VAHTA_DATA_DIR", self.root.join("data"))
            .env("VAHTA_RUNTIME_DIR", self.root.join("run"))
            .env("VAHTA_CONFIG_DIR", self.root.join("config"))
            .env_remove("NO_COLOR")
            .output()
            .expect("run vahta")
    }
}

impl Drop for Box_ {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sample() -> Vec<Value> {
    let t = now();
    vec![
        json!({"time": t - 7200, "event": "daemon_start", "result": "ok"}),
        json!({"time": t - 3000, "event": "session_start", "session": "s1", "names": ["PYPI_TOKEN"],
               "peer_exe": "claude", "peer_pid": 42, "result": "ok", "reason": "anchor claude pid 42; 1 hour(s)"}),
        json!({"time": t - 2900, "event": "run", "names": ["PYPI_TOKEN"], "peer_exe": "cargo", "peer_pid": 43,
               "result": "started", "reason": "via session s1", "secret_value": value()}),
        json!({"time": t - 2800, "event": "run_refused", "names": ["GITHUB_TOKEN"], "peer_exe": "bash", "peer_pid": 50,
               "result": "refused", "reason": "suspicious: not_from_harness; bound to claude"}),
        json!({"time": t - 2700, "event": "session_start", "names": ["GITHUB_TOKEN"], "result": "ok",
               "reason": "connectors; claude pid 77; until that process exits", "vault": "c0ffee"}),
        json!({"time": t - 2600, "event": "session_end", "names": ["GITHUB_TOKEN"], "result": "ended",
               "reason": "anchor_exited; connectors; claude pid 77"}),
        json!({"time": t - 2500, "event": "notified", "names": ["GITHUB_TOKEN"], "result": "ok", "reason": "not_from_harness"}),
        json!({"time": t - 2400, "event": "alarm", "result": "warn", "reason": "claude (pid 42); score 6"}),
        json!({"time": t - 2300, "event": "bind", "names": ["PYPI_TOKEN"], "result": "ok"}),
        json!({"time": t - 2200, "event": "future_event", "result": "weird", "reason": value(), "names": ["PYPI_TOKEN"]}),
        json!({"time": t - 2100, "event": "run", "names": ["PYPI_TOKEN"], "result": "cancelled",
               "reason": "the client went away before the command started; nothing was run"}),
    ]
}

#[test]
fn every_kind_reads_in_plain_words_and_suspicious_ones_are_marked() {
    let b = Box_::new(&sample());
    let out = b.vahta(&["journal", "--last", "100"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let shown = text(&out.stdout);
    let has = |s: &str| assert!(shown.contains(s), "missing {s:?} in\n{shown}");
    has("the daemon started");
    has("session opened with PYPI_TOKEN by claude (pid 42)");
    has("run with PYPI_TOKEN by cargo (pid 43): started");
    has(
        "refused: not started by the harness the connector with GITHUB_TOKEN is bound to by bash (pid 50)",
    );
    has("connectors session opened for Claude Code pid 77");
    has("connectors session for Claude Code pid 77 ended (anchor_exited)");
    has(
        "desktop notification sent: a process that is not the harness tried to start a server with GITHUB_TOKEN",
    );
    has("ALARM warn");
    has("bind with PYPI_TOKEN: ok");
    has("cancelled, the client went away; nothing ran");
    has(" UTC");
    // The marker, on the suspicious lines only.
    let marked: Vec<&str> = shown.lines().filter(|l| l.contains(" ! ")).collect();
    assert_eq!(marked.len(), 3, "{shown}");
    assert!(marked.iter().any(|l| l.contains("refused: not started")));
    assert!(marked.iter().any(|l| l.contains("ALARM")));
    assert!(
        !shown.contains('\u{1b}'),
        "no colour when not on a terminal"
    );
    // An event this version does not know: its name and result only; and no
    // value, from a field that is not shown or from a free text that is not
    // known.
    has("future_event: weird");
    assert!(!shown.contains(&value()), "{shown}");
}

#[test]
fn the_filters_narrow_the_list() {
    let b = Box_::new(&sample());
    let lines = |args: &[&str]| -> Vec<String> {
        let mut a = vec!["journal"];
        a.extend_from_slice(args);
        let out = b.vahta(&a);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        text(&out.stdout).lines().map(str::to_string).collect()
    };
    // --last takes the newest, oldest first.
    let last = lines(&["--last", "2"]);
    assert_eq!(last.len(), 2, "{last:?}");
    assert!(last[1].contains("cancelled"), "{last:?}");
    // --since drops the old.
    let recent = lines(&["--since", "1h", "--last", "100"]);
    assert!(!recent.iter().any(|l| l.contains("the daemon started")));
    assert!(recent.iter().any(|l| l.contains("run with PYPI_TOKEN")));
    assert!(lines(&["--since", "10s"])[0].contains("no matching events"));
    // --secret
    let github = lines(&["--secret", "GITHUB_TOKEN", "--last", "100"]);
    assert!(
        github.len() == 4 && github.iter().all(|l| !l.contains("PYPI_TOKEN")),
        "{github:?}"
    );
    // --kind, alone and repeated
    let sus = lines(&["--kind", "suspicious", "--last", "100"]);
    assert_eq!(sus.len(), 3, "{sus:?}");
    assert_eq!(lines(&["--kind", "notified"]).len(), 1);
    let conn = lines(&["--kind", "connector", "--last", "100"]);
    assert!(
        conn.iter().any(|l| l.contains("connectors session opened")),
        "{conn:?}"
    );
    let session = lines(&["--kind", "session", "--last", "100"]);
    assert_eq!(session.len(), 3, "{session:?}");
    let both = lines(&["--kind", "session", "--kind", "daemon", "--last", "100"]);
    assert_eq!(both.len(), 4, "{both:?}");
    let refused = lines(&["--kind", "refused", "--last", "100"]);
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(lines(&["--kind", "run", "--last", "100"]).len(), 3);
    assert_eq!(lines(&["--kind", "vault", "--last", "100"]).len(), 1);
    // A bad value is a usage error that lists the kinds.
    let out = b.vahta(&["journal", "--kind", "nonsense"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("suspicious"));
    let out = b.vahta(&["journal", "--since", "soon"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn json_gives_the_matching_lines_as_they_are() {
    let b = Box_::new(&sample());
    let out = b.vahta(&["journal", "--json", "--kind", "run", "--last", "100"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let parsed: Vec<Value> = text(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let expected: Vec<Value> = sample()
        .into_iter()
        .filter(|l| l["event"] == "run" || l["event"] == "run_refused")
        .collect();
    assert_eq!(parsed, expected);
}

#[test]
fn no_journal_is_said_and_a_hostile_line_does_no_harm() {
    let b = Box_::new(&[]);
    fs::remove_file(b.root.join("data/journal.jsonl")).unwrap();
    let out = b.vahta(&["journal"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stdout).contains("no journal yet"));
    // Escape sequences in a field are not passed to the terminal; a broken line
    // is skipped.
    let t = now();
    let body = format!(
        "not json\n{}\n",
        json!({"time": t, "event": "run", "names": ["A\u{1b}[31mB"], "result": "started\u{7}"})
    );
    fs::write(b.root.join("data/journal.jsonl"), body).unwrap();
    let out = b.vahta(&["journal"]);
    let shown = text(&out.stdout);
    assert!(
        !shown.contains('\u{1b}') && !shown.contains('\u{7}'),
        "{shown:?}"
    );
    assert!(shown.contains("run with A [31mB"), "{shown:?}");
}
