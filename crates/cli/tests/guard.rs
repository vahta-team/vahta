//! The hook watchdog end to end: `vahta hooks pause|resume`, `vahta _guard`
//! and the consent, autostart and administrator-policy parts of `vahta setup`.
//!
//! Every run is in a sandbox: `HOME`, the Vahta directories and a copy of the
//! `vahta` binary (with a stand-in `vahta-hook` beside it) are all inside one
//! temp directory. The daemon and the watchdog it starts are the sandbox's own
//! and are stopped when the test ends. The daemon is a test build: its windows
//! answer from a script, the watchdog polls every 100 ms, and the commands of
//! the login autostart (`systemctl --user ...`) are written to a log and never
//! run. The administrator-policy paths are re-rooted inside the sandbox.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;

static NEXT: AtomicU32 = AtomicU32::new(0);
const EXE: &str = std::env::consts::EXE_SUFFIX;
const PW: &str = "correct horse";

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Sandbox {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        // Beside the test binaries (so the `vahta` below can be a hard link, not a
        // copy that another thread's fork could hold open) and short (a socket
        // path has a length limit).
        let root =
            PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("g{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for d in [
            "bin",
            "home/.claude",
            "project",
            "run",
            "data",
            "config",
            "path",
        ] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        let exe = root.join(format!("bin/vahta{EXE}"));
        if fs::hard_link(env!("CARGO_BIN_EXE_vahta"), &exe).is_err() {
            fs::copy(env!("CARGO_BIN_EXE_vahta"), &exe).unwrap();
        }
        fs::write(root.join(format!("bin/vahta-hook{EXE}")), "#!/bin/sh\n").unwrap();
        Sandbox { root }
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn settings(&self) -> PathBuf {
        self.home().join(".claude/settings.json")
    }

    fn command(&self, cwd: &Path) -> Command {
        let mut cmd = Command::new(self.root.join(format!("bin/vahta{EXE}")));
        cmd.current_dir(cwd)
            .env_clear()
            .env("HOME", self.home())
            .env("USERPROFILE", self.home())
            .env("PATH", self.root.join("path"))
            .env("VAHTA_DATA_DIR", self.root.join("data"))
            .env("VAHTA_RUNTIME_DIR", self.root.join("run"))
            .env("VAHTA_CONFIG_DIR", self.root.join("config"))
            .env("VAHTA_TEST_SURFACE", self.root.join("script.jsonl"))
            .env("VAHTA_TEST_SURFACE_LOG", self.root.join("surface.log"))
            .env("VAHTA_TEST_SERVICE_LOG", self.root.join("service.log"))
            .env("VAHTA_TEST_MANAGED_ROOT", self.root.join("managed"))
            .env("VAHTA_TEST_GUARD_POLL_MS", "100");
        cmd
    }

    fn vahta(&self, args: &[&str]) -> Output {
        // A copy of the binary can be "busy" for a moment if another test
        // thread forked while it was being written; try again.
        for _ in 0..40 {
            match self.command(&self.root.join("project")).args(args).output() {
                Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                other => return other.expect("run vahta"),
            }
        }
        panic!("vahta stayed busy");
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

    fn journal(&self) -> String {
        fs::read_to_string(self.root.join("data/journal.jsonl")).unwrap_or_default()
    }

    fn service_log(&self) -> String {
        fs::read_to_string(self.root.join("service.log")).unwrap_or_default()
    }

    fn guard_running(&self) -> bool {
        vahta_ipc::paths::Paths {
            runtime: self.root.join("run"),
            data: self.root.join("data"),
            config: self.root.join("config"),
        }
        .guard_running()
    }

    /// `vahta setup --claude`, which writes the hooks into the sandbox's settings.
    fn install(&self) {
        let out = self.vahta(&["setup", "--claude"]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert!(self.settings_text().contains("vahta-hook"));
    }

    fn settings_text(&self) -> String {
        fs::read_to_string(self.settings()).unwrap_or_default()
    }

    /// A vault in the project, so that windows ask for its password.
    fn with_vault(&self) {
        self.script(&[&format!(r#"{{"secret":"{PW}"}}"#), r#"{"ack":true}"#]);
        let out = self.vahta(&["init"]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        // The watchdog first, so it cannot put anything back or ask anyone
        // while the daemon goes; then the daemon.
        let _ = fs::write(self.root.join("run/guard.stop"), b"");
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.guard_running() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self
            .command(&self.root)
            .args(["daemon", "stop"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[cfg(unix)]
fn wait_until(what: &str, secs: u64, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

// --- pause and resume ----------------------------------------------------------------------------------

#[test]
fn pause_takes_the_hooks_out_and_resume_puts_them_back() {
    let s = Sandbox::new();
    s.install();
    s.with_vault();
    s.script(&[&format!(r#"{{"secret":"{PW}"}}"#)]);
    let out = s.vahta(&[
        "hooks",
        "pause",
        "--for",
        "30m",
        "--reason",
        "edit my settings",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("off in Claude Code for 30m"),
        "{}",
        text(&out.stdout)
    );
    assert!(!s.settings_text().contains("vahta-hook"));
    assert!(s.root.join("data/pause.json").is_file());

    // What the person saw: the reason (unverified), the harness and the time.
    let log = s.window_log();
    let ask = log
        .iter()
        .rfind(|e| e["ask"] == "password")
        .expect("a password window");
    let panel = ask["panel"].to_string();
    assert!(
        panel.contains("Claude Code") && panel.contains("30m"),
        "{panel}"
    );
    assert!(panel.contains("edit my settings"), "{panel}");
    assert!(
        panel.contains("does not see what the agent does"),
        "{panel}"
    );

    let status = text(&s.vahta(&["hooks", "status"]).stdout);
    assert!(status.contains("claude: paused"), "{status}");

    let out = s.vahta(&["hooks", "resume"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(s.settings_text().contains("vahta-hook"));
    assert!(!s.root.join("data/pause.json").exists());
    assert!(text(&s.vahta(&["hooks", "status"]).stdout).contains("no hooks are paused"));
    let journal = s.journal();
    assert!(
        journal.contains("hooks_paused") && journal.contains("hooks_resumed"),
        "{journal}"
    );
}

#[test]
fn pause_needs_the_password_when_a_vault_is_known_and_a_cancel_changes_nothing() {
    let s = Sandbox::new();
    s.install();
    s.with_vault();
    s.script(&[r#"{"cancel":true}"#]);
    let out = s.vahta(&["hooks", "pause", "--for", "10m"]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
    assert!(s.settings_text().contains("vahta-hook"));
    assert!(!s.root.join("data/pause.json").exists());

    // A wrong password, then the right one.
    s.script(&[r#"{"secret":"nope"}"#, &format!(r#"{{"secret":"{PW}"}}"#)]);
    let out = s.vahta(&["hooks", "pause", "--for", "10m"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!s.settings_text().contains("vahta-hook"));
    assert!(s.window_log().iter().any(|e| e["ask"] == "password"));
}

#[test]
fn pause_with_no_vault_known_is_refused_and_points_to_the_terminal() {
    let s = Sandbox::new();
    s.install();
    let out = s.vahta(&["hooks", "pause", "--for", "10m"]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    let e = text(&out.stderr);
    assert!(
        e.contains("vahta setup --uninstall") && e.contains("vahta setup --guard off"),
        "{e}"
    );
    assert!(s.settings_text().contains("vahta-hook"));
    assert!(s.window_log().is_empty(), "no plain yes is offered");
}

#[test]
fn a_pause_over_eight_hours_is_refused_before_any_window() {
    let s = Sandbox::new();
    s.install();
    let out = s.vahta(&["hooks", "pause", "--for", "9h"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("at most 8h"),
        "{}",
        text(&out.stderr)
    );
    assert!(s.settings_text().contains("vahta-hook"));
    assert!(s.window_log().is_empty());
}

// --- consent and autostart ------------------------------------------------------------------------------

#[test]
fn nothing_is_installed_at_login_without_consent() {
    let s = Sandbox::new();
    s.install();
    // Not a terminal, no flag: told how to answer, nothing written.
    let out = s.vahta(&["setup", "--claude"]);
    let o = text(&out.stdout);
    assert!(
        o.contains("watches the hook settings") || o.contains("hook watchdog"),
        "{o}"
    );
    assert!(o.contains("--guard on"), "{o}");
    assert!(s.service_log().is_empty());
    assert!(!s.root.join("config/config.toml").exists());
    assert!(!s.guard_running());

    // "off" writes the answer, counts a decline, and installs nothing.
    let out = s.vahta(&["setup", "--guard", "off"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        fs::read_to_string(s.root.join("config/config.toml"))
            .unwrap()
            .contains("guard = \"off\"")
    );
    let state = fs::read_to_string(s.root.join("data/state.json")).unwrap();
    assert!(state.contains("\"guard_declines\": 1"), "{state}");
    assert!(!s.guard_running());
    assert!(!s.service_log().contains("enable"));
}

#[cfg(unix)]
#[test]
fn consent_writes_the_autostart_and_starts_the_watchdog() {
    let s = Sandbox::new();
    s.install();
    let out = s.vahta(&["setup", "--guard", "on", "--dry-run"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(!s.root.join("config/config.toml").exists());
    assert!(s.service_log().is_empty());

    let out = s.vahta(&["setup", "--guard", "on"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        fs::read_to_string(s.root.join("config/config.toml"))
            .unwrap()
            .contains("guard = \"on\"")
    );
    let log = s.service_log();
    if cfg!(target_os = "macos") {
        assert!(log.contains("launchctl load"), "{log}");
        assert!(
            s.home()
                .join("Library/LaunchAgents/dev.vahta.guard.plist")
                .is_file()
        );
    } else {
        assert!(
            log.contains("systemctl --user enable --now vahta-guard.service"),
            "{log}"
        );
        let unit =
            fs::read_to_string(s.home().join(".config/systemd/user/vahta-guard.service")).unwrap();
        assert!(unit.contains("_guard"), "{unit}");
        assert!(unit.contains("bin/vahta"), "{unit}");
    }
    wait_until("the watchdog", 10, || s.guard_running());
    // It holds no vault and listens on nothing of the network: its one
    // single-instance lock is a file in the runtime directory.
    assert!(s.root.join("run/guard.lock").is_file());

    // A second one finds the lock taken and leaves quietly.
    let out = s.vahta(&["_guard"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(s.guard_running());
}

#[cfg(unix)]
#[test]
fn uninstall_stops_the_watchdog_and_removes_the_autostart_first() {
    let s = Sandbox::new();
    s.install();
    assert_eq!(s.vahta(&["setup", "--guard", "on"]).status.code(), Some(0));
    wait_until("the watchdog", 10, || s.guard_running());

    let out = s.vahta(&["setup", "--claude", "--uninstall"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!s.guard_running());
    assert!(!s.settings_text().contains("vahta-hook"));
    let log = s.service_log();
    assert!(log.contains("disable") || log.contains("unload"), "{log}");
    assert!(
        !s.home()
            .join(".config/systemd/user/vahta-guard.service")
            .exists()
    );
    assert!(
        !s.home()
            .join("Library/LaunchAgents/dev.vahta.guard.plist")
            .exists()
    );
    // The answer is forgotten, so the next install asks again.
    assert!(
        !fs::read_to_string(s.root.join("config/config.toml"))
            .unwrap_or_default()
            .contains("guard")
    );
    // And nothing puts the hooks back.
    std::thread::sleep(Duration::from_millis(600));
    assert!(!s.settings_text().contains("vahta-hook"));
}

// --- the watchdog at work ---------------------------------------------------------------------------------

#[cfg(unix)]
fn with_watchdog(s: &Sandbox) {
    s.install();
    assert_eq!(s.vahta(&["setup", "--guard", "on"]).status.code(), Some(0));
    wait_until("the watchdog", 10, || s.guard_running());
    // Let it see the hooks once, so it knows what to keep.
    wait_until("the watchdog to learn the hooks", 10, || {
        fs::read_to_string(s.root.join("data/guard-state.json")).is_ok_and(|t| t.contains("claude"))
    });
}

#[cfg(unix)]
#[test]
fn removed_hooks_are_put_back_when_nobody_answers() {
    let s = Sandbox::new();
    with_watchdog(&s);
    // What an agent would do: take the hooks out.
    fs::write(s.settings(), "{\"model\": \"opus\"}\n").unwrap();
    s.script(&[r#"{"noanswer":true}"#]);
    wait_until("the hooks to come back", 20, || {
        s.settings_text().contains("vahta-hook")
    });
    assert!(
        s.settings_text().contains("opus"),
        "the person's own setting stays"
    );
    wait_until("the journal", 5, || s.journal().contains("hook_restored"));
    let journal = s.journal();
    assert!(journal.contains("hook_tamper"), "{journal}");
    // The window said what happened and what the choices are.
    let log = s.window_log();
    let ask = log.iter().find(|e| e["ask"] == "choose").expect("a choice");
    // No vault is known here, so the only choice is Restore, and the window
    // says where to go to keep the hooks off.
    assert_eq!(ask["options"].as_array().map(Vec::len), Some(1), "{ask}");
    assert!(
        ask["panel"].to_string().contains("vahta setup --guard off"),
        "{ask}"
    );
    assert!(
        ask["panel"]
            .to_string()
            .contains("Vahta does not see what agents do")
    );
}

#[cfg(unix)]
#[test]
fn restore_is_chosen_and_disable_all_hooks_is_cleared() {
    let s = Sandbox::new();
    with_watchdog(&s);
    let with_switch = s
        .settings_text()
        .replacen('{', "{\n  \"disableAllHooks\": true,", 1);
    fs::write(s.settings(), with_switch).unwrap();
    s.script(&[r#"{"choose":0}"#]);
    wait_until("disableAllHooks to go", 20, || {
        !s.settings_text().contains("disableAllHooks")
    });
    assert!(s.settings_text().contains("vahta-hook"));
    wait_until("the journal", 5, || s.journal().contains("hook_restored"));
}

#[cfg(unix)]
#[test]
fn keep_off_with_the_password_keeps_the_change_and_the_pause_ends_it() {
    let s = Sandbox::new();
    s.with_vault();
    // The daemon learns the project when it sees a command for it.
    fs::write(
        s.root.join("data/projects.json"),
        format!("[{:?}]", s.root.join("project").to_string_lossy()),
    )
    .unwrap();
    with_watchdog(&s);
    fs::write(s.settings(), "{}\n").unwrap();
    s.script(&["{\"choose\":1}", &format!(r#"{{"secret":"{PW}"}}"#)]);
    wait_until("the keep-off", 20, || {
        s.journal().contains("hook_tamper_kept")
    });
    // Kept: still no hooks a moment later, and a pause is on record.
    std::thread::sleep(Duration::from_millis(600));
    assert!(!s.settings_text().contains("vahta-hook"));
    assert!(s.root.join("data/pause.json").is_file());
    assert!(s.window_log().iter().any(|e| e["ask"] == "password"));

    // The hour is up (made so by rewriting the pause): the hooks return.
    fs::write(
        s.root.join("data/pause.json"),
        r#"{"pauses":[{"harness":"claude","until":1,"reason":"test"}]}"#,
    )
    .unwrap();
    wait_until("the hooks to return", 20, || {
        s.settings_text().contains("vahta-hook")
    });
    wait_until("the journal", 5, || s.journal().contains("hooks_restored"));
    assert!(!s.root.join("data/pause.json").exists());
}

#[cfg(unix)]
#[test]
fn turn_off_protection_with_the_password_stops_the_watchdog_for_good() {
    let s = Sandbox::new();
    s.with_vault();
    fs::write(
        s.root.join("data/projects.json"),
        format!("[{:?}]", s.root.join("project").to_string_lossy()),
    )
    .unwrap();
    with_watchdog(&s);
    fs::write(s.settings(), "{}\n").unwrap();
    s.script(&["{\"choose\":2}", &format!(r#"{{"secret":"{PW}"}}"#)]);
    wait_until("the watchdog to end", 20, || !s.guard_running());
    assert!(!s.settings_text().contains("vahta-hook"));
    assert!(
        fs::read_to_string(s.root.join("config/config.toml"))
            .unwrap()
            .contains("guard = \"off\"")
    );
    assert!(s.service_log().contains("disable") || s.service_log().contains("unload"));
    assert!(s.journal().contains("guard_off"));
}

// --- administrator policy -----------------------------------------------------------------------------------

#[test]
fn managed_dry_run_prints_the_policy_and_writes_nothing() {
    let s = Sandbox::new();
    let out = s.vahta(&["setup", "--claude", "--force", "--managed", "--dry-run"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let o = text(&out.stdout);
    assert!(o.contains("would write the administrator policy"), "{o}");
    assert!(o.contains("managed-settings.json"), "{o}");
    assert!(
        o.contains("vahta-hook") && o.contains("--harness claude --event before_tool"),
        "{o}"
    );
    assert!(!s.root.join("managed").exists());
}

#[test]
fn managed_writes_where_it_can_and_prints_the_command_where_it_cannot() {
    let s = Sandbox::new();
    let out = s.vahta(&["setup", "--claude", "--force", "--managed"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let file = s.root.join("managed").join(if cfg!(target_os = "macos") {
        "Library/Application Support/ClaudeCode/managed-settings.json"
    } else if cfg!(windows) {
        "Program Files/ClaudeCode/managed-settings.json"
    } else {
        "etc/claude-code/managed-settings.json"
    });
    let written = fs::read_to_string(&file).unwrap();
    assert!(written.contains("vahta-hook"), "{written}");
    // Again: already current.
    assert!(
        text(
            &s.vahta(&["setup", "--claude", "--force", "--managed"])
                .stdout
        )
        .contains("already current")
    );

    // A place that cannot be written (a file where a directory should be):
    // the command is printed, nothing escalates, and the exit code says so.
    let blocked = Sandbox::new();
    fs::write(blocked.root.join("managed"), "in the way").unwrap();
    let out = blocked.vahta(&["setup", "--claude", "--force", "--managed"]);
    assert_eq!(out.status.code(), Some(1));
    let o = text(&out.stdout);
    assert!(o.contains("nothing was written"), "{o}");
    if !cfg!(windows) {
        assert!(
            o.contains("sudo") && o.contains("VAHTA_EOF") && o.contains("vahta-hook"),
            "{o}"
        );
    }
}

#[test]
fn managed_for_cursor_and_codex_use_their_own_files() {
    let s = Sandbox::new();
    let out = s.vahta(&["setup", "--cursor", "--codex", "--force", "--managed"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    if cfg!(target_os = "linux") {
        let cursor = fs::read_to_string(s.root.join("managed/etc/cursor/hooks.json")).unwrap();
        assert!(
            cursor.contains("\"version\": 1") && cursor.contains("vahta-hook"),
            "{cursor}"
        );
        let codex = fs::read_to_string(s.root.join("managed/etc/codex/requirements.toml")).unwrap();
        assert!(
            codex.contains("[features]") && codex.contains("hooks = true"),
            "{codex}"
        );
        assert!(
            codex.contains("[[hooks.PreToolUse]]") && codex.contains("vahta-hook"),
            "{codex}"
        );
    }
}

#[test]
fn managed_is_refused_with_uninstall_and_without_a_harness() {
    let s = Sandbox::new();
    assert_eq!(s.vahta(&["setup", "--managed"]).status.code(), Some(2));
    assert_eq!(
        s.vahta(&["setup", "--claude", "--managed", "--uninstall"])
            .status
            .code(),
        Some(2)
    );
}

// --- the reminders in setup and check ---------------------------------------------------------------------------------

#[test]
fn setup_and_check_say_where_the_watchdog_stands() {
    let s = Sandbox::new();
    let o = text(&s.vahta(&["setup"]).stdout);
    assert!(o.contains("hook watchdog: not decided yet"), "{o}");
    assert_eq!(s.vahta(&["setup", "--guard", "off"]).status.code(), Some(0));
    let o = text(&s.vahta(&["setup"]).stdout);
    assert!(o.contains("hook watchdog: off"), "{o}");
    // `check` says so on stderr, in text mode only.
    fs::write(s.root.join("project/vahta.toml"), "[secrets.A]\n").unwrap();
    let out = s.vahta(&["check"]);
    assert!(
        text(&out.stderr).contains("hook watchdog: off"),
        "{}",
        text(&out.stderr)
    );
    let out = s.vahta(&["check", "--json"]);
    assert!(!text(&out.stderr).contains("watchdog"));
}
