//! The hook starts the daemon when none answers (`crates/hook/src/autostart.rs`),
//! with the real `vahta-hook` and `vahta` in a temp directory, a temp runtime
//! directory and a temp HOME.
//!
//! The call used is a prompt with a long key-like string: with a daemon behind
//! it the prompt passes (no output), without one the hook is strict and blocks.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT: AtomicU32 = AtomicU32::new(0);

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
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
            assert!(cmd.status().expect("run cargo build").success());
            dir.join(format!("vahta-hook{}", std::env::consts::EXE_SUFFIX))
        })
        .clone()
}

struct Rig {
    root: PathBuf,
    bin: PathBuf,
    planted: PathBuf,
}

impl Rig {
    fn new() -> Rig {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("vahta-hs-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for d in ["home", "run", "data", "config", "bin", "planted"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        let root = fs::canonicalize(root).unwrap();
        let rig = Rig {
            bin: root.join("bin"),
            planted: root.join("planted"),
            root,
        };
        fs::copy(hook_bin(), rig.bin.join("vahta-hook")).unwrap();
        rig
    }

    /// The real `vahta` beside the hook.
    fn with_real_vahta(self) -> Rig {
        fs::copy(env!("CARGO_BIN_EXE_vahta"), self.bin.join("vahta")).unwrap();
        self
    }

    /// A `vahta` beside the hook that is a script: it notes each start in
    /// `starts` and exits.
    fn with_failing_vahta(self) -> Rig {
        self.script(
            &self.bin.join("vahta"),
            &format!("echo x >> '{}'\nexit 1", self.root.join("starts").display()),
        );
        self
    }

    fn script(&self, at: &Path, body: &str) {
        fs::write(at, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(at, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn starts(&self) -> usize {
        fs::read_to_string(self.root.join("starts")).map_or(0, |t| t.lines().count())
    }

    fn envs(&self, cmd: &mut Command) {
        cmd.env("HOME", self.root.join("home"))
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env_remove("XDG_RUNTIME_DIR")
            .env("VAHTA_DATA_DIR", self.root.join("data"))
            .env("VAHTA_RUNTIME_DIR", self.root.join("run"))
            .env("VAHTA_CONFIG_DIR", self.root.join("config"))
            .env_remove("VAHTA_HOOK_DISABLE")
            .env_remove("VAHTA_STARTED_BY");
    }

    /// The hook, given a prompt with a key-like string. The working directory
    /// and the PATH both hold a planted `vahta`.
    fn prompt(&self) -> Output {
        let key = format!("{}{}{}", "Zq8Lm2Xv9R", "t4Bn7Kc3Hd5", "Wp6Ys1Jf");
        let payload = serde_json::json!({
            "hook_event_name": "UserPromptSubmit",
            "prompt": format!("please deploy with {key} now"),
            "cwd": self.planted,
        })
        .to_string();
        let mut cmd = Command::new(self.bin.join("vahta-hook"));
        cmd.args(["--harness", "claude", "--event", "prompt"])
            .current_dir(&self.planted)
            .env("PATH", format!("{}:/usr/bin:/bin", self.planted.display()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        self.envs(&mut cmd);
        let mut child = cmd.spawn().expect("spawn the hook");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn vahta(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vahta"));
        cmd.args(args).current_dir(&self.root);
        self.envs(&mut cmd);
        cmd.output().expect("run vahta")
    }

    fn running(&self) -> bool {
        text(&self.vahta(&["daemon", "status"]).stdout).contains("running:")
    }

    fn journal(&self) -> String {
        fs::read_to_string(self.root.join("data/journal.jsonl")).unwrap_or_default()
    }

    fn count_file(&self) -> PathBuf {
        self.root.join("run/hook-starts")
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = self.vahta(&["daemon", "stop"]);
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn blocked(out: &Output) -> bool {
    text(&out.stdout).contains("\"block\"")
}

#[test]
fn a_hook_with_no_daemon_starts_one_and_the_call_is_served() {
    let rig = Rig::new().with_real_vahta();
    assert!(!rig.running());
    let out = rig.prompt();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        !blocked(&out),
        "served by the daemon it started: {}",
        text(&out.stdout)
    );
    assert!(rig.running());
    let journal = rig.journal();
    assert_eq!(journal.matches("\"daemon_start\"").count(), 1, "{journal}");
    assert!(journal.contains("started by hook"), "{journal}");
    assert!(
        !rig.count_file().exists(),
        "the count is cleared once it is up"
    );
}

#[test]
fn a_daemon_that_is_up_is_not_started_again() {
    let rig = Rig::new().with_real_vahta();
    assert_eq!(rig.vahta(&["daemon", "restart"]).status.code(), Some(0));
    assert!(rig.running());
    for _ in 0..2 {
        let out = rig.prompt();
        assert!(!blocked(&out), "{}", text(&out.stdout));
    }
    let journal = rig.journal();
    assert_eq!(journal.matches("\"daemon_start\"").count(), 1, "{journal}");
    assert!(!journal.contains("started by hook"));
}

#[test]
fn three_failed_starts_in_a_row_end_the_trying_until_a_daemon_is_seen() {
    let rig = Rig::new().with_failing_vahta();
    for n in 1..=4 {
        let out = rig.prompt();
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert!(blocked(&out), "call {n} is strict: {}", text(&out.stdout));
    }
    assert_eq!(rig.starts(), 3, "the fourth call did not try");
    assert_eq!(fs::read_to_string(rig.count_file()).unwrap().trim(), "3");
    // A daemon comes up by other means and answers: the count is cleared, and
    // when it is gone again the hook may start one.
    fs::copy(env!("CARGO_BIN_EXE_vahta"), rig.bin.join("vahta")).unwrap();
    assert_eq!(rig.vahta(&["daemon", "restart"]).status.code(), Some(0));
    let out = rig.prompt();
    assert!(!blocked(&out), "{}", text(&out.stdout));
    assert!(!rig.count_file().exists());
    assert_eq!(rig.vahta(&["daemon", "stop"]).status.code(), Some(0));
    assert!(!rig.running());
    let out = rig.prompt();
    assert!(!blocked(&out), "started again: {}", text(&out.stdout));
    assert!(rig.running());
}

#[test]
fn a_vahta_in_path_or_the_working_directory_is_never_run() {
    // No `vahta` beside the hook; one in the PATH and in the cwd.
    let rig = Rig::new();
    let mark = rig.root.join("planted-ran");
    rig.script(
        &rig.planted.join("vahta"),
        &format!("echo x > '{}'", mark.display()),
    );
    let out = rig.prompt();
    assert!(blocked(&out), "{}", text(&out.stdout));
    assert!(!mark.exists(), "the planted program was run");
    assert!(!rig.count_file().exists());
    assert!(!rig.running());
}

#[test]
fn a_corrupt_count_means_no_start() {
    let rig = Rig::new().with_real_vahta();
    fs::write(rig.count_file(), "not a number").unwrap();
    let out = rig.prompt();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(blocked(&out), "{}", text(&out.stdout));
    assert!(!rig.running(), "nothing was started");
    // An unreadable one (a directory) is the same.
    fs::remove_file(rig.count_file()).unwrap();
    fs::create_dir(rig.count_file()).unwrap();
    assert!(blocked(&rig.prompt()));
    assert!(!rig.running());
}
