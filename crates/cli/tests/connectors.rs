//! The connectors vault (`--connector`), against a real daemon in a sandbox with
//! a scripted prompt window and a temp HOME, like `remote.rs`.
//!
//! The harness is stood in for by the test process itself: a test build of the
//! daemon takes `VAHTA_TEST_CONNECTOR_PARENT` as the name of a parent process
//! that counts as every harness. A sandbox made without it has the test process
//! for what it is, a parent that is no harness. A second harness process is a
//! copy of a shell under that same name (`HarnessCopy`).
//!
//! A connectors session belongs to the harness process that asked: the first
//! launch from a process opens a password window, the rest of that process's
//! launches use its session.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;

static NEXT: AtomicU32 = AtomicU32::new(0);
const PW_ANSWER: &str = r#"{"secret":"correct horse"}"#;
const KEY: &str = "CONN_API_KEY";

struct Sandbox {
    root: PathBuf,
    proj: PathBuf,
    as_harness: bool,
    /// The daemon's idle time in seconds, when a test wants it short.
    idle: Option<u32>,
    /// Refusals count for the injection alarm (a test of the burst notice).
    alarm_on: bool,
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// The value is put together here so no file of the repository holds one.
fn value_of(tag: &str) -> String {
    format!("{}-{}-{tag}", "fake", "value")
}

fn typed(value: &str) -> String {
    format!(r#"{{"secret":"{value}"}}"#)
}

impl Sandbox {
    fn new(as_harness: bool) -> Sandbox {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("vahta-c-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for d in ["proj", "home", "run", "data", "config"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        let root = fs::canonicalize(root).unwrap();
        Sandbox {
            proj: root.join("proj"),
            root,
            as_harness,
            idle: None,
            alarm_on: false,
        }
    }

    fn command(&self, cwd: &Path) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vahta"));
        cmd.current_dir(cwd)
            .env("HOME", self.root.join("home"))
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env_remove("XDG_RUNTIME_DIR")
            .env("VAHTA_DATA_DIR", self.root.join("data"))
            .env("VAHTA_RUNTIME_DIR", self.root.join("run"))
            .env("VAHTA_CONFIG_DIR", self.root.join("config"))
            .env_remove("VAHTA_TEST_DAEMON_VERSION")
            .env("VAHTA_TEST_NOTIFY_LOG", self.root.join("notify.log"))
            .env("VAHTA_TEST_SURFACE", self.root.join("script.jsonl"))
            .env("VAHTA_TEST_SURFACE_LOG", self.root.join("surface.log"))
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .env("VAHTA_TEST_RELAY_CONNECT", "127.0.0.1");
        if self.alarm_on {
            cmd.env_remove("VAHTA_TEST_MUTE_REFUSAL_ALARM");
        } else {
            cmd.env("VAHTA_TEST_MUTE_REFUSAL_ALARM", "1");
        }
        match self.idle {
            Some(n) => cmd.env("VAHTA_TEST_IDLE_SECONDS", n.to_string()),
            None => cmd.env_remove("VAHTA_TEST_IDLE_SECONDS"),
        };
        if self.as_harness {
            let me = std::env::current_exe().unwrap();
            cmd.env("VAHTA_TEST_CONNECTOR_PARENT", me.file_name().unwrap());
        } else {
            cmd.env_remove("VAHTA_TEST_CONNECTOR_PARENT");
        }
        cmd
    }

    fn vahta(&self, cwd: &Path, args: &[&str]) -> Output {
        self.command(cwd).args(args).output().expect("run vahta")
    }

    fn script(&self, answers: &[&str]) {
        let path = self.root.join("script.jsonl");
        let mut text = fs::read_to_string(&path).unwrap_or_default();
        for a in answers {
            text.push_str(a);
            text.push('\n');
        }
        fs::write(path, text).unwrap();
    }

    fn window_log(&self) -> Vec<Value> {
        fs::read_to_string(self.root.join("surface.log"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    fn windows(&self) -> usize {
        self.window_log().len()
    }

    fn passwords(&self) -> usize {
        self.window_log()
            .iter()
            .filter(|e| e["ask"] == "password")
            .count()
    }

    fn journal(&self) -> String {
        fs::read_to_string(self.root.join("data/journal.jsonl")).unwrap_or_default()
    }

    /// The connectors vault with one connector, `KEY`, for claude, whose
    /// server is `printenv`.
    fn with_connector(as_harness: bool) -> Sandbox {
        Sandbox::with_connector_idle(as_harness, None)
    }

    fn with_connector_idle(as_harness: bool, idle: Option<u32>) -> Sandbox {
        let mut s = Sandbox::new(as_harness);
        s.idle = idle;
        s.script(&[PW_ANSWER, r#"{"ack":true}"#]);
        let out = s.vahta(&s.root, &["init", "--connector"]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert!(s.root.join("data/connectors/vault.vht").is_file());
        s.script(&[PW_ANSWER, &typed(&value_of("a")), r#"{"choose":0}"#]);
        let out = s.vahta(
            &s.root,
            &[
                "add",
                "--connector",
                KEY,
                "--harness",
                "claude",
                "--allow",
                "printenv",
            ],
        );
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        s
    }

    /// The desktop notifications the daemon sent, one per line.
    fn notifications(&self) -> Vec<String> {
        fs::read_to_string(self.root.join("notify.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// The first launch from this harness process: it opens the password
    /// window, and its session then serves the rest.
    fn unlock(&self) {
        self.script(&[PW_ANSWER]);
        let out = self.run_connector(KEY, &["printenv", KEY]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    }

    /// A launch with `args` as a command in its own process, to run beside
    /// others.
    fn spawn_launch(&self, command: &[&str]) -> std::process::Child {
        let mut args = vec!["run", "--connector", "--secret", KEY, "--"];
        args.extend_from_slice(command);
        self.command(&self.root)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn vahta")
    }

    /// The open sessions, as `vahta sessions --json` says.
    fn sessions(&self) -> Vec<Value> {
        let out = self.vahta(&self.root, &["sessions", "--json"]);
        let doc: Value = serde_json::from_str(&text(&out.stdout)).unwrap_or(Value::Null);
        doc["sessions"].as_array().cloned().unwrap_or_default()
    }

    /// The real hook, given a tool's output as Claude would, from this process.
    fn hook_after_tool(&self, stdout: &str) -> Option<Value> {
        use std::io::Write;
        let payload = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "cat notes.txt"},
            "tool_response": {"stdout": stdout, "stderr": ""},
            "cwd": self.proj,
        });
        let mut child = Command::new(hook_bin())
            .args(["--harness", "claude", "--event", "after_tool"])
            .current_dir(&self.proj)
            .env("HOME", self.root.join("home"))
            .env_remove("XDG_RUNTIME_DIR")
            .env_remove("VAHTA_HOOK_DISABLE")
            .env("VAHTA_DATA_DIR", self.root.join("data"))
            .env("VAHTA_RUNTIME_DIR", self.root.join("run"))
            .env("VAHTA_CONFIG_DIR", self.root.join("config"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run vahta-hook");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(0));
        let t = text(&out.stdout);
        (!t.trim().is_empty()).then(|| serde_json::from_str(&t).unwrap())
    }

    fn run_connector(&self, name: &str, command: &[&str]) -> Output {
        let mut args = vec!["run", "--connector", "--secret", name, "--"];
        args.extend_from_slice(command);
        self.vahta(&self.root, &args)
    }
}

/// The real `vahta-hook`, built once per test run next to `vahta`.
fn hook_bin() -> PathBuf {
    static BUILT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            let dir = Path::new(env!("CARGO_BIN_EXE_vahta")).parent().unwrap();
            let mut cmd = Command::new(env!("CARGO"));
            cmd.args(["build", "--quiet", "-p", "vahta-hook"]);
            if dir.file_name().is_some_and(|n| n == "release") {
                cmd.arg("--release");
            }
            let status = cmd.status().expect("run cargo build");
            assert!(status.success(), "cargo build -p vahta-hook failed");
            dir.join(format!("vahta-hook{}", std::env::consts::EXE_SUFFIX))
        })
        .clone()
}

/// The text the hook put in place of a tool's stdout.
fn cut_stdout(reply: &Value) -> String {
    reply["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn wait_until(what: &str, secs: u64, mut done: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        if done() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = self
            .command(&self.root)
            .args(["daemon", "stop"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn with_a_session_a_connector_starts_with_no_window_and_gets_its_value() {
    let s = Sandbox::with_connector(true);
    s.unlock();
    let passwords = s.passwords();
    let windows = s.windows();
    for _ in 0..2 {
        let out = s.run_connector(KEY, &["printenv", KEY]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert_eq!(text(&out.stdout), format!("***REDACTED({KEY})***\n"));
    }
    assert_eq!(s.passwords(), passwords, "no password for a run");
    assert_eq!(s.windows(), windows, "no window of any kind for a run");
    assert!(s.journal().contains("\"started\""));
    // The list shows the connector and its rules, and no value.
    let out = s.vahta(&s.root, &["list", "--connector"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let listed = text(&out.stdout);
    assert!(listed.contains(KEY) && listed.contains("claude") && listed.contains("printenv"));
    assert!(!listed.contains(&value_of("a")));
    let out = s.vahta(&s.root, &["check", "--connector"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
}

#[test]
fn the_first_launch_of_a_harness_process_opens_one_window_and_the_next_none() {
    let s = Sandbox::with_connector(true);
    let passwords = s.passwords();
    s.script(&[PW_ANSWER]);
    let out = s.run_connector(KEY, &["printenv", KEY]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), format!("***REDACTED({KEY})***\n"));
    assert_eq!(
        s.passwords(),
        passwords + 1,
        "one window for the first launch"
    );
    // The window says whose servers they are and what to enter.
    let shown = s
        .window_log()
        .iter()
        .rfind(|e| e["ask"] == "password")
        .unwrap()
        .to_string();
    assert!(
        shown.contains("Claude Code (pid") && shown.contains("wants its MCP servers"),
        "{shown}"
    );
    assert!(
        shown.contains(KEY) && !shown.contains(&value_of("a")),
        "{shown}"
    );
    // The session is this process's, and the journal names the harness and pid.
    let sessions = s.sessions();
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    assert_eq!(sessions[0]["anchor_exe"], "claude");
    assert_eq!(sessions[0]["anchor_pid"], std::process::id());
    assert!(sessions[0]["remaining_secs"].is_null());
    let journal = s.journal();
    assert!(
        journal.contains(&format!("connectors; claude pid {}", std::process::id())),
        "{journal}"
    );
    // The second launch from the same process asks nothing.
    let windows = s.windows();
    let out = s.run_connector(KEY, &["printenv", KEY]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.windows(), windows, "no window for the second launch");
    assert!(!journal.contains(&value_of("a")));
    // The daemon status tells a connectors session is open.
    let status = text(&s.vahta(&s.root, &["daemon", "status"]).stdout);
    assert!(status.contains("connectors session: open"), "{status}");
}

#[test]
fn launches_at_once_from_one_harness_process_share_one_window() {
    let s = Sandbox::with_connector(true);
    let windows = s.passwords();
    // The person takes a moment: all three launches are waiting by then.
    s.script(&[r#"{"secret":"correct horse","after_ms":800}"#]);
    let kids: Vec<_> = (0..3).map(|_| s.spawn_launch(&["printenv", KEY])).collect();
    for kid in kids {
        let out = kid.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert_eq!(text(&out.stdout), format!("***REDACTED({KEY})***\n"));
    }
    assert_eq!(s.passwords(), windows + 1, "one window for all three");
    assert_eq!(s.sessions().len(), 1);
    assert_eq!(s.journal().matches("\"session_start\"").count(), 1);
}

#[test]
fn a_no_for_launches_at_once_fails_them_all_with_the_hint_after_one_window() {
    let s = Sandbox::with_connector(true);
    let windows = s.passwords();
    s.script(&[r#"{"cancel":true,"after_ms":800}"#]);
    let started = std::time::Instant::now();
    let kids: Vec<_> = (0..2).map(|_| s.spawn_launch(&["printenv", KEY])).collect();
    for kid in kids {
        let out = kid.wait_with_output().unwrap();
        assert_ne!(out.status.code(), Some(0));
        assert!(!text(&out.stdout).contains(&value_of("a")));
        let err = text(&out.stderr);
        assert!(
            err.contains("reconnect the server in Claude Code (`/mcp`)"),
            "{err}"
        );
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert_eq!(s.passwords(), windows + 1, "one window, one no");
    assert!(s.sessions().is_empty());
    // Reconnecting asks again.
    s.unlock();
    assert_eq!(s.sessions().len(), 1);
}

#[test]
fn a_wrong_password_ends_the_launch_fast_with_the_hint() {
    let s = Sandbox::with_connector(true);
    s.script(&[
        r#"{"secret":"wrong one"}"#,
        r#"{"secret":"wrong two"}"#,
        r#"{"secret":"wrong three"}"#,
    ]);
    let started = std::time::Instant::now();
    let out = s.run_connector(KEY, &["printenv", KEY]);
    assert_ne!(out.status.code(), Some(0));
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    let err = text(&out.stderr);
    assert!(
        err.contains("reconnect the server in Claude Code (`/mcp`)"),
        "{err}"
    );
    assert!(!text(&out.stdout).contains(&value_of("a")));
    assert!(s.sessions().is_empty());
}

#[test]
fn a_cancelled_window_ends_the_launch_fast_and_the_next_launch_asks_again() {
    let s = Sandbox::with_connector(true);
    s.script(&[r#"{"cancel":true}"#]);
    let started = std::time::Instant::now();
    let out = s.run_connector(KEY, &["printenv", KEY]);
    assert_ne!(out.status.code(), Some(0));
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    let err = text(&out.stderr);
    assert!(
        err.contains("not unlocked") && err.contains("/mcp"),
        "{err}"
    );
    assert!(s.sessions().is_empty());
    let windows = s.passwords();
    s.unlock();
    assert_eq!(s.passwords(), windows + 1, "asked again");
}

// The harness gave up on the server and killed `vahta run`: the window goes
// with it and nothing runs.
#[cfg(target_os = "linux")]
#[test]
fn a_client_that_goes_away_takes_the_window_with_it_and_nothing_runs() {
    let s = Sandbox::with_connector(true);
    s.script(&[r#"{"hang":true}"#]);
    let mut client = s.spawn_launch(&["printenv", KEY]);
    let asked = s.passwords();
    wait_until("the password window", 10, || s.passwords() == asked + 1);
    client.kill().unwrap();
    let _ = client.wait();
    wait_until("the window to be withdrawn", 5, || {
        s.window_log().iter().any(|e| e["close"] == "withdrawn")
    });
    wait_until("the journal to say so", 5, || {
        s.journal().contains("went away before the command started")
    });
    let journal = s.journal();
    assert!(journal.contains("\"result\":\"cancelled\""), "{journal}");
    assert!(!journal.contains("\"result\":\"started\""), "{journal}");
    assert!(s.sessions().is_empty());
    // Nothing keeps the vault's turn: the next launch gets its window.
    s.unlock();
}

/// A shell under the harness stand-in's name: another harness process.
#[cfg(target_os = "linux")]
fn harness_copy(s: &Sandbox) -> PathBuf {
    let sh = fs::canonicalize("/bin/sh").unwrap();
    let me = std::env::current_exe().unwrap();
    let dir = s.root.join("harness-b");
    fs::create_dir_all(&dir).unwrap();
    let copy = dir.join(me.file_name().unwrap());
    fs::copy(sh, &copy).unwrap();
    copy
}

/// `vahta run --connector` started by `harness` (a copy of a shell), which then
/// stays `then` before it exits.
#[cfg(target_os = "linux")]
fn launch_under(s: &Sandbox, harness: &Path, then: &str) -> std::process::Child {
    let script = format!(
        "'{}' run --connector --secret {KEY} -- printenv {KEY}; echo \"code=$?\"; {then}; exit 0",
        env!("CARGO_BIN_EXE_vahta")
    );
    let mut cmd = Command::new(harness);
    let base = s.command(&s.root);
    for (k, v) in base.get_envs() {
        match v {
            Some(v) => cmd.env(k, v),
            None => cmd.env_remove(k),
        };
    }
    cmd.current_dir(&s.root)
        .args(["-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the harness copy")
}

#[cfg(target_os = "linux")]
#[test]
fn another_harness_process_gets_its_own_window_and_a_session_never_passes_between() {
    let s = Sandbox::with_connector(true);
    let b = harness_copy(&s);
    s.unlock();
    let windows = s.passwords();
    // A second process has no session: its own window.
    s.script(&[PW_ANSWER]);
    let kid = launch_under(&s, &b, "sleep 4");
    wait_until("the second process's session", 10, || {
        s.sessions().len() == 2
    });
    assert_eq!(
        s.passwords(),
        windows + 1,
        "the second process asked for itself"
    );
    // The first process still needs none, and the two sessions are two
    // processes'.
    let windows = s.passwords();
    let out = s.run_connector(KEY, &["printenv", KEY]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.passwords(), windows);
    let mut pids: Vec<u64> = s
        .sessions()
        .iter()
        .filter_map(|x| x["anchor_pid"].as_u64())
        .collect();
    pids.sort();
    pids.dedup();
    assert_eq!(pids.len(), 2, "{pids:?}");
    assert!(pids.contains(&u64::from(std::process::id())), "{pids:?}");
    let out = kid.wait_with_output().unwrap();
    assert!(
        text(&out.stdout).contains("code=0"),
        "{}",
        text(&out.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn the_session_ends_with_its_harness_process() {
    let s = Sandbox::with_connector(true);
    let b = harness_copy(&s);
    s.script(&[PW_ANSWER]);
    let kid = launch_under(&s, &b, "sleep 3");
    wait_until("the session of the second process", 10, || {
        !s.sessions().is_empty()
    });
    let session = s.sessions().remove(0);
    let pid = session["anchor_pid"].as_u64().unwrap();
    assert_ne!(pid, u64::from(std::process::id()));
    let out = kid.wait_with_output().unwrap();
    assert!(
        text(&out.stdout).contains("code=0"),
        "{}",
        text(&out.stderr)
    );
    wait_until("the session to end with its process", 10, || {
        s.sessions().is_empty()
    });
    wait_until("the journal to say why", 10, || {
        s.journal()
            .contains(&format!("anchor_exited; connectors; claude pid {pid}"))
    });
}

#[test]
fn unlock_connector_is_gone_and_says_how_it_works_now() {
    let s = Sandbox::with_connector(true);
    let windows = s.windows();
    for args in [
        &["unlock", "--connector"][..],
        &["unlock", "--connector", "--for", "8h"],
    ] {
        let out = s.vahta(&s.root, args);
        assert!(!out.status.success());
        let err = text(&out.stderr);
        assert!(
            err.contains("no such step") && err.contains("/mcp"),
            "{err}"
        );
    }
    assert_eq!(s.windows(), windows);
    assert!(s.sessions().is_empty());
}

#[test]
fn a_parent_that_is_no_harness_is_refused_and_marked_suspicious() {
    let s = Sandbox::with_connector(false);
    let windows = s.windows();
    let out = s.run_connector(KEY, &["printenv", KEY]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    let err = text(&out.stderr);
    assert!(err.contains("bound to claude"), "{err}");
    assert!(!text(&out.stdout).contains(&value_of("a")));
    assert_eq!(s.windows(), windows);
    let journal = s.journal();
    assert!(
        journal.contains("suspicious: not_from_harness"),
        "{journal}"
    );
    let status = s.vahta(&s.root, &["daemon", "status"]);
    assert!(text(&status.stdout).contains(&format!("connector {KEY} was refused at")));
}

#[test]
fn a_command_outside_the_allow_rule_is_refused_even_with_a_session() {
    let s = Sandbox::with_connector(true);
    s.unlock();
    let out = s.run_connector(KEY, &["sh", "-c", "echo hi"]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(!text(&out.stdout).contains("hi"));
    let err = text(&out.stderr);
    assert!(err.contains("outside its allow rules"), "{err}");
    assert!(!err.contains("--ask"), "{err}");
}

#[test]
fn a_connector_needs_harnesses_and_an_allow_rule() {
    let s = Sandbox::new(true);
    s.script(&[PW_ANSWER, r#"{"ack":true}"#]);
    assert_eq!(
        s.vahta(&s.root, &["init", "--connector"]).status.code(),
        Some(0)
    );
    let windows = s.windows();
    // Refused before any window: no harness, no allow rule, a bad harness.
    for args in [
        vec!["add", "--connector", KEY, "--allow", "printenv"],
        vec!["add", "--connector", KEY, "--harness", "claude"],
        vec![
            "add",
            "--connector",
            KEY,
            "--harness",
            "vim",
            "--allow",
            "printenv",
        ],
    ] {
        let out = s.vahta(&s.root, &args);
        assert_ne!(out.status.code(), Some(0), "{args:?}");
        assert_eq!(s.windows(), windows, "{args:?}");
    }
    // `remote` and `from` do not apply.
    let out = s.vahta(&s.root, &["bind", "--connector", KEY, "--from", "/tmp"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    let out = s.vahta(&s.root, &["remote", "on", "--connector"]);
    assert_ne!(out.status.code(), Some(0));
}

#[test]
fn a_connector_whose_rules_were_cleared_is_refused_as_having_no_rules() {
    let s = Sandbox::with_connector(true);
    // The person clears the rules: Approve, then the password.
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&s.root, &["bind", "--connector", KEY, "--clear"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let windows = s.windows();
    let out = s.run_connector(KEY, &["printenv", KEY]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("no harnesses or no allow rule"));
    assert_eq!(
        s.windows(),
        windows,
        "no window for a connector with no rules"
    );
    let out = s.vahta(&s.root, &["check", "--connector"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn rebinding_changes_the_harnesses_and_is_shown() {
    let s = Sandbox::with_connector(true);
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(
        &s.root,
        &["bind", "--connector", KEY, "--harness", "codex,cursor"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let out = s.vahta(&s.root, &["list", "--connector"]);
    let listed = text(&out.stdout);
    assert!(
        listed.contains("codex,cursor") && !listed.contains("claude"),
        "{listed}"
    );
    // The stand-in harness counts as every harness, so the bound set is shown
    // by the list and by the refusal of a parent that is none.
    let rules = fs::read_to_string(s.root.join("data/connectors/vahta.toml")).unwrap();
    assert!(
        rules.contains("harnesses") && rules.contains("codex"),
        "{rules}"
    );
}

#[test]
fn a_project_vault_is_never_used_by_connector_and_the_connectors_vault_never_by_a_project() {
    let s = Sandbox::with_connector(true);
    s.unlock();
    // A project with a vault of its own and a secret.
    s.script(&[PW_ANSWER, r#"{"ack":true}"#]);
    let out = s.vahta(&s.proj, &["init"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    s.script(&[PW_ANSWER, &typed(&value_of("p")), r#"{"choose":0}"#]);
    let out = s.vahta(&s.proj, &["add", "PROJ_ONLY_KEY", "--allow", "printenv"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let windows = s.windows();

    // `--connector` from inside the project does not see the project's secret.
    let out = s.vahta(
        &s.proj,
        &[
            "run",
            "--connector",
            "--secret",
            "PROJ_ONLY_KEY",
            "--",
            "printenv",
            "PROJ_ONLY_KEY",
        ],
    );
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(!text(&out.stdout).contains(&value_of("p")));
    let list = s.vahta(&s.proj, &["list", "--connector"]);
    // Only as a launch that was refused, never as one of its connectors.
    let listed = text(&list.stdout);
    assert!(
        listed
            .lines()
            .filter(|l| !l.contains("was refused at"))
            .all(|l| !l.contains("PROJ_ONLY_KEY")),
        "{listed}"
    );
    assert!(listed.contains(KEY));

    // A project run does not see the connector, from the project or anywhere.
    for cwd in [&s.proj, &s.root, &s.root.join("data/connectors")] {
        let out = s.vahta(cwd, &["run", "--secret", KEY, "--", "printenv", KEY]);
        assert_eq!(out.status.code(), Some(3), "{cwd:?}: {}", text(&out.stderr));
        assert!(!text(&out.stdout).contains(&value_of("a")));
    }
    let out = s.vahta(&s.proj, &["list"]);
    assert!(!text(&out.stdout).contains(KEY));
    // Not through `--vault`, which names a project folder.
    let dir = s.root.join("data/connectors");
    let out = s.vahta(
        &s.proj,
        &[
            "run",
            "--vault",
            &dir.to_string_lossy(),
            "--secret",
            KEY,
            "--",
            "printenv",
            KEY,
        ],
    );
    assert_ne!(out.status.code(), Some(0));
    assert!(!text(&out.stdout).contains(&value_of("a")));

    // Not even when the connectors vault's file is copied into a project.
    let other = s.root.join("copy");
    fs::create_dir_all(other.join(".vahta")).unwrap();
    fs::copy(
        s.root.join("data/connectors/vault.vht"),
        other.join(".vahta/vault.vht"),
    )
    .unwrap();
    let out = s.vahta(&other, &["run", "--secret", KEY, "--", "printenv", KEY]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("no vault"),
        "{}",
        text(&out.stderr)
    );
    assert!(!text(&out.stdout).contains(&value_of("a")));
    assert_eq!(s.windows(), windows, "none of it opened a window");
}

#[test]
fn the_project_session_does_not_start_a_connector_and_the_connector_session_does_not_run_a_project()
{
    let s = Sandbox::with_connector(true);
    // A project session open, but no connectors session.
    s.script(&[PW_ANSWER, r#"{"ack":true}"#]);
    assert_eq!(s.vahta(&s.proj, &["init"]).status.code(), Some(0));
    s.script(&[PW_ANSWER, &typed(&value_of("p")), r#"{"choose":0}"#]);
    assert_eq!(
        s.vahta(&s.proj, &["add", "PROJ_ONLY_KEY", "--allow", "printenv"])
            .status
            .code(),
        Some(0)
    );
    s.script(&[PW_ANSWER]);
    assert_eq!(s.vahta(&s.proj, &["unlock"]).status.code(), Some(0));
    // The project's session opens nothing for a connector: it asks for its own.
    let windows = s.passwords();
    s.unlock();
    assert_eq!(s.passwords(), windows + 1);
    // And the connectors session covers no project secret.
    let out = s.vahta(
        &s.proj,
        &[
            "run",
            "--secret",
            "PROJ_ONLY_KEY",
            "--",
            "printenv",
            "PROJ_ONLY_KEY",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "***REDACTED(PROJ_ONLY_KEY)***\n");
}

#[test]
fn a_connector_is_removed_by_the_person_in_a_window() {
    let s = Sandbox::with_connector(true);
    s.script(&[PW_ANSWER]);
    let out = s.vahta(&s.root, &["remove", "--connector", KEY]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let out = s.vahta(&s.root, &["list", "--connector"]);
    assert!(text(&out.stdout).contains("No connectors"));
}

// A connector bound with `--net hosts:...` reaches its host through the relay
// (Linux only: needs a network namespace for the server).
#[cfg(target_os = "linux")]
#[test]
fn a_connector_with_hosts_reaches_only_its_host() {
    use vahta_net::test_server::{Reply, TestServer};
    if !vahta_os::network_isolation_available() {
        eprintln!("skipped: no unprivileged network namespaces here");
        return;
    }
    let server = TestServer::start(|_| Reply::ok(b"connector-ok"));
    let s = Sandbox::new(true);
    fs::write(s.root.join("ca.pem"), vahta_net::test_server::CA_PEM).unwrap();
    s.script(&[PW_ANSWER, r#"{"ack":true}"#]);
    let out = s.vahta(&s.root, &["init", "--connector"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let python = ["python3", "python"]
        .into_iter()
        .find(|p| Command::new(p).arg("-V").output().is_ok());
    let Some(python) = python else {
        eprintln!("skipped: no python");
        return;
    };
    let net = format!("hosts:private:other.localhost:{}", server.port);
    s.script(&[PW_ANSWER, &typed(&value_of("a")), r#"{"choose":0}"#]);
    let out = s.vahta(
        &s.root,
        &[
            "add",
            "--connector",
            KEY,
            "--harness",
            "claude",
            "--allow",
            python,
            "--net",
            &net,
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    s.script(&[PW_ANSWER]);
    let code = format!(
        "import socket,ssl\nctx=ssl.create_default_context(cafile='{}')\ns=ctx.wrap_socket(socket.create_connection(('other.localhost',{}),timeout=5),server_hostname='other.localhost')\ns.sendall(b'GET / HTTP/1.1\\r\\n\\r\\n')\nprint(b'connector-ok' in s.recv(4096))\ntry:\n    socket.getaddrinfo('example.com',443)\n    print('resolved')\nexcept OSError:\n    print('noresolve')",
        s.root.join("ca.pem").display(),
        server.port
    );
    let out = s.run_connector(KEY, &[python, "-c", &code]);
    assert_eq!(
        text(&out.stdout),
        "True\nnoresolve\n",
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn the_daemon_stays_while_a_connectors_session_is_open_and_lock_ends_it() {
    let s = Sandbox::with_connector_idle(true, Some(1));
    s.unlock();
    let pid_of = |s: &Sandbox| -> Value {
        let out = s.vahta(&s.root, &["daemon", "status", "--json"]);
        serde_json::from_str(&text(&out.stdout)).unwrap_or(Value::Null)
    };
    let before = pid_of(&s)["pid"].clone();
    assert!(before.is_u64());
    // Well past the idle time, with no connection in between.
    std::thread::sleep(std::time::Duration::from_secs(4));
    let after = pid_of(&s);
    assert_eq!(after["pid"], before, "the daemon exited and came back");
    assert_eq!(after["connectors_session"], true);
    assert!(!s.journal().contains("daemon_idle_exit"));
    let windows = s.windows();
    let out = s.run_connector(KEY, &["printenv", KEY]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.windows(), windows);
    // `lock --all` ends it, and then the daemon may go idle.
    assert_eq!(s.vahta(&s.root, &["lock", "--all"]).status.code(), Some(0));
    assert!(s.sessions().is_empty());
    assert!(s.journal().contains("locked; connectors; claude pid"));
    wait_until("the idle exit", 15, || {
        s.journal().contains("daemon_idle_exit")
    });
    // After a lock the same process is asked again.
    s.unlock();
}

#[test]
fn lock_connector_ends_every_connectors_session_and_plain_lock_leaves_them() {
    let s = Sandbox::with_connector_idle(true, None);
    s.unlock();
    // A plain lock is the project's, whatever it holds (a project with no
    // vault still has sessions to end).
    fs::create_dir_all(s.proj.join(".vahta")).unwrap();
    assert_eq!(s.vahta(&s.proj, &["lock"]).status.code(), Some(0));
    let windows = s.passwords();
    let out = s.run_connector(KEY, &["printenv", KEY]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        s.passwords(),
        windows,
        "the session survived the plain lock"
    );
    // `--connector` ends it, says so, and a second one has nothing to end.
    let out = s.vahta(&s.proj, &["lock", "--connector"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("ended the connectors session"));
    assert!(s.sessions().is_empty());
    let out = s.vahta(&s.proj, &["lock", "--connector"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("no connectors session"));
    assert!(s.journal().contains("(connectors)"));
    // The same process is asked again.
    s.unlock();
}

#[test]
fn the_hook_redacts_a_connectors_value_in_any_agents_output() {
    let s = Sandbox::with_connector(true);
    let value = value_of("a");
    // Nothing is known of it while locked and never run, bar the detector.
    s.unlock();
    let reply = s
        .hook_after_tool(&format!("the key is {value} ok"))
        .expect("the value is cut");
    assert_eq!(
        cut_stdout(&reply),
        format!("the key is ***REDACTED({KEY})*** ok")
    );
    // Run once, then lock: the recent run's value is still looked for.
    let out = s.run_connector(KEY, &["printenv", KEY]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.vahta(&s.root, &["lock", "--all"]).status.code(), Some(0));
    let reply = s
        .hook_after_tool(&format!("again {value}"))
        .expect("the value is still cut");
    assert_eq!(cut_stdout(&reply), format!("again ***REDACTED({KEY})***"));
    assert!(!s.journal().contains(&value));
}

#[test]
fn as_puts_a_connectors_value_in_another_variable() {
    let s = Sandbox::with_connector(true);
    s.unlock();
    let out = s.vahta(
        &s.root,
        &[
            "run",
            "--connector",
            "--secret",
            KEY,
            "--as",
            &format!("{KEY}=OTHER_VAR"),
            "--",
            "printenv",
            "OTHER_VAR",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), format!("***REDACTED({KEY})***\n"));
    // The original name is not set.
    let out = s.vahta(
        &s.root,
        &[
            "run",
            "--connector",
            "--secret",
            KEY,
            "--as",
            &format!("{KEY}=OTHER_VAR"),
            "--",
            "printenv",
            KEY,
        ],
    );
    assert_ne!(out.status.code(), Some(0));
    assert!(!text(&out.stdout).contains("REDACTED"));
    // A bad form, another secret's name and a reserved variable are refused.
    for bad in ["OTHER_VAR", "NOT_THE_SECRET=X", &format!("{KEY}=PATH")] {
        let out = s.vahta(
            &s.root,
            &[
                "run",
                "--connector",
                "--secret",
                KEY,
                "--as",
                bad,
                "--",
                "printenv",
                "X",
            ],
        );
        assert!(
            matches!(out.status.code(), Some(1..=3)),
            "{bad}: {:?} {}",
            out.status.code(),
            text(&out.stderr)
        );
    }
}

// Silent when all is well: opening a session and launching never notify.
#[test]
fn a_normal_launch_never_notifies() {
    let s = Sandbox::with_connector(true);
    s.script(&[PW_ANSWER]);
    for _ in 0..2 {
        let out = s.run_connector(KEY, &["printenv", "HOME"]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    }
    assert!(s.notifications().is_empty(), "{:?}", s.notifications());
    assert!(!s.journal().contains("\"notified\""));
}

#[test]
fn a_launch_by_a_process_that_is_not_the_harness_notifies_once_per_while() {
    let s = Sandbox::with_connector(false);
    for _ in 0..3 {
        let out = s.run_connector(KEY, &["printenv", "HOME"]);
        assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    }
    let notes = s.notifications();
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(notes[0].contains(&format!(
        "not Claude Code tried to start the MCP server for {KEY}"
    )));
    assert!(notes[0].contains("Nothing ran"), "{notes:?}");
    assert!(!notes[0].contains(&value_of("a")));
    let journal = s.journal();
    assert_eq!(journal.matches("\"notified\"").count(), 1, "{journal}");
    assert!(journal.contains("not_from_harness"));
}

#[test]
fn a_command_outside_the_rules_notifies_once() {
    let s = Sandbox::with_connector(true);
    s.script(&[PW_ANSWER]);
    let out = s.run_connector(KEY, &["printenv", "HOME"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    for _ in 0..2 {
        let out = s.run_connector(KEY, &["npx", "-p", "evil", "@pkg/server"]);
        assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    }
    let notes = s.notifications();
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].contains(KEY) && notes[0].contains("npx -p evil"),
        "{notes:?}"
    );
    assert!(notes[0].contains("rules do not allow") && notes[0].contains("Nothing ran"));
    assert!(s.journal().contains("command_not_allowed"));
}

#[test]
fn a_server_that_prints_its_own_key_notifies() {
    let s = Sandbox::with_connector(true);
    s.unlock();
    let notes = s.notifications();
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(notes[0].contains(&format!("MCP server for {KEY} printed its own key")));
    assert!(!notes[0].contains(&value_of("a")));
    // Again within the while: said once.
    let out = s.run_connector(KEY, &["printenv", KEY]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.notifications().len(), 1);
    let journal = s.journal();
    assert!(journal.contains("value_in_output") && !journal.contains(&value_of("a")));
}

#[test]
fn a_burst_of_refused_launches_notifies_through_the_alarms_score() {
    let mut s = Sandbox::with_connector(true);
    s.alarm_on = true;
    // The daemon that made the vault runs with the alarm muted: start afresh.
    s.vahta(&s.root, &["daemon", "stop"]);
    s.script(&[PW_ANSWER]);
    let out = s.run_connector(KEY, &["printenv", "HOME"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(s.notifications().is_empty());
    for _ in 0..2 {
        let out = s.run_connector(KEY, &["true"]);
        assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    }
    let notes = s.notifications();
    assert!(
        notes
            .iter()
            .any(|n| n.contains("Many launches of MCP servers")),
        "{notes:?}"
    );
    assert!(s.journal().contains("refusal_burst"));
}
