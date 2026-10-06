//! Drives the real `vahta` binary against a real daemon.
//!
//! Every run happens in a sandbox: a temp directory with `HOME`,
//! `XDG_DATA_HOME`, `VAHTA_DATA_DIR`, `VAHTA_RUNTIME_DIR` and `VAHTA_CONFIG_DIR`
//! all pointed inside it, so nothing reads or writes the real home, data,
//! config or runtime directory, and the daemon the sandbox starts is its own.
//! The daemon is a test build (the `test-surface` feature, switched on for
//! this test target only): it answers its prompts from a script and no
//! terminal window is ever opened. Values and passwords are made up.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;
use vahta_daemon::client::{ClientError, Connector};
use vahta_daemon::paths::Paths;
use vahta_vault::store::LocalStore;
use vahta_vault::{Tier, Vault};

use vahta_daemon::protocol::{
    ClientReply, ClientRequest, Hello, HelloKind, HelloReply, PROTOCOL, read_frame, write_frame,
};

static NEXT: AtomicU32 = AtomicU32::new(0);
const PW: &[u8] = b"correct horse";

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Sandbox {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("vahta-d-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for d in ["project", "home", "run", "data", "config"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        Sandbox { root }
    }

    fn project(&self) -> PathBuf {
        self.root.join("project")
    }

    fn paths(&self) -> Paths {
        Paths {
            runtime: self.root.join("run"),
            data: self.root.join("data"),
            config: self.root.join("config"),
        }
    }

    /// The command with the sandbox's environment and nothing of the real one
    /// that points at a user directory.
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
            .env_remove("VAHTA_TEST_IDLE_SECONDS")
            // The daemon answers its prompts from the script, and if it ever
            // tried a real terminal there is no display to open one on.
            .env("VAHTA_TEST_SURFACE", self.root.join("script.jsonl"))
            .env("VAHTA_TEST_SURFACE_LOG", self.root.join("surface.log"))
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY");
        cmd
    }

    /// Queue the window's answers for the next questions: each is one JSON
    /// line (see the scripted surface).
    fn script(&self, answers: &[&str]) {
        let path = self.root.join("script.jsonl");
        let mut text = fs::read_to_string(&path).unwrap_or_default();
        for a in answers {
            text.push_str(a);
            text.push('\n');
        }
        fs::write(path, text).unwrap();
    }

    /// What the window was asked and shown, in order.
    fn window_log(&self) -> Vec<Value> {
        fs::read_to_string(self.root.join("surface.log"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn asks(&self) -> usize {
        self.window_log()
            .iter()
            .filter(|e| e.get("ask").is_some())
            .count()
    }

    fn vault_path(&self) -> PathBuf {
        self.project().join(".vahta/vault.vht")
    }

    /// Open the project's vault directly, as a check that the daemon wrote what
    /// it said.
    fn open_vault(&self) -> Vault {
        Vault::unlock_password(
            &self.vault_path(),
            PW,
            &LocalStore::new(self.root.join("data")),
        )
        .unwrap()
    }

    /// `vahta init` and `vahta set` for each of `items`, through the window.
    fn with_vault(&self, items: &[(&str, &str, &str)]) {
        self.script(&[r#"{"secret":"correct horse"}"#, r#"{"ack":true}"#]);
        let out = self.vahta(&["init"]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        for (name, value, tier) in items {
            self.script(&[
                r#"{"secret":"correct horse"}"#,
                &format!(r#"{{"secret":"{value}"}}"#),
            ]);
            let out = self.vahta(&["set", name, "--tier", tier]);
            assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        }
    }

    fn vahta(&self, args: &[&str]) -> Output {
        self.command(&self.project())
            .args(args)
            .output()
            .expect("run vahta")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        // Stop the sandbox's daemon, so none outlives its test.
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

#[test]
fn status_with_no_daemon_says_so_and_exits_5() {
    let s = Sandbox::new();
    let out = s.vahta(&["daemon", "status"]);
    assert_eq!(out.status.code(), Some(5));
    assert_eq!(text(&out.stdout).trim(), "not running");
    let out = s.vahta(&["daemon", "status", "--json"]);
    assert_eq!(out.status.code(), Some(5));
    assert!(text(&out.stdout).contains("\"running\":false"));
    // Asking never starts one.
    assert_eq!(s.vahta(&["daemon", "status"]).status.code(), Some(5));
}

#[test]
fn restart_starts_one_and_status_and_stop_work() {
    let s = Sandbox::new();
    let out = s.vahta(&["daemon", "restart"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("restarted (0 session(s) ended)"));

    let out = s.vahta(&["daemon", "status", "--json"]);
    assert_eq!(out.status.code(), Some(0));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["running"], true);
    assert_eq!(doc["version"], vahta_daemon::VERSION);
    assert_eq!(doc["sessions"], 0);
    assert!(doc["runtime_dir"].as_str().unwrap().ends_with("run"));

    // The runtime directory is private and holds the socket.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(s.root.join("run"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
        let sock = fs::metadata(s.root.join("run/daemon.sock")).unwrap();
        assert_eq!(sock.permissions().mode() & 0o077, 0);
    }

    let out = s.vahta(&["daemon", "stop"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stdout).contains("stopped"));
    assert_eq!(s.vahta(&["daemon", "status"]).status.code(), Some(5));
    // Stopping again is not an error.
    assert_eq!(s.vahta(&["daemon", "stop"]).status.code(), Some(0));

    // It journalled its own life, with no value in it.
    let journal = fs::read_to_string(s.root.join("data/journal.jsonl")).unwrap();
    assert!(journal.contains("daemon_start") && journal.contains("daemon_stop"));
}

#[test]
fn a_second_daemon_does_not_run_beside_the_first() {
    let s = Sandbox::new();
    assert_eq!(s.vahta(&["daemon", "restart"]).status.code(), Some(0));
    // `daemon run` finds the lock taken and leaves quietly.
    let out = s.vahta(&["daemon", "run"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(s.vahta(&["daemon", "status"]).status.code(), Some(0));
}

#[test]
fn the_daemon_exits_when_it_has_been_idle() {
    let s = Sandbox::new();
    let out = s
        .command(&s.project())
        .env("VAHTA_TEST_IDLE_SECONDS", "1")
        .args(["daemon", "restart"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    // Not polled with `status`: every connection would count as activity.
    let journal = s.root.join("data/journal.jsonl");
    wait_until("the idle daemon to exit", 15, || {
        fs::read_to_string(&journal).is_ok_and(|j| j.contains("daemon_stop"))
    });
    assert!(
        fs::read_to_string(&journal)
            .unwrap()
            .contains("daemon_idle_exit")
    );
    wait_until("the socket to go", 5, || {
        !s.root.join("run/daemon.sock").exists()
    });
    assert_eq!(s.vahta(&["daemon", "status"]).status.code(), Some(5));
}

fn connector(s: &Sandbox, start: bool) -> Connector {
    // A connector that may start a daemon must never be able to reach outside
    // the sandbox.
    assert!(s.paths().runtime.starts_with(std::env::temp_dir()));
    Connector {
        paths: s.paths(),
        version: vahta_daemon::VERSION.to_string(),
        start: start.then(|| {
            vec![
                env!("CARGO_BIN_EXE_vahta").into(),
                "daemon".into(),
                "run".into(),
            ]
        }),
    }
}

/// Start a daemon that reports `version`, as an old daemon would, and keep its
/// process so a test can see it go.
fn start_old_daemon(s: &Sandbox, version: &str) -> std::process::Child {
    let child = s
        .command(&s.project())
        .env("VAHTA_TEST_DAEMON_VERSION", version)
        .args(["daemon", "run"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let c = connector(s, false);
    wait_until("the old daemon", 10, || {
        c.connect_running().ok().flatten().is_some()
    });
    child
}

#[test]
fn an_old_daemon_with_no_sessions_is_replaced() {
    let s = Sandbox::new();
    let mut old = start_old_daemon(&s, "0.0.0-old");
    let c = connector(&s, true);
    let conn = c.connect().expect("connect and replace");
    assert_eq!(conn.daemon.version, vahta_daemon::VERSION);
    // The old process has gone.
    wait_until("the old daemon to exit", 10, || {
        old.try_wait().unwrap().is_some()
    });
}

#[test]
fn an_old_daemon_is_not_replaced_when_the_caller_may_not_start_one() {
    let s = Sandbox::new();
    let mut old = start_old_daemon(&s, "0.0.0-old");
    let err = connector(&s, false).connect().unwrap_err();
    assert!(matches!(err, ClientError::Unavailable(_)), "{err}");
    // Still running.
    assert!(old.try_wait().unwrap().is_none());
    let _ = old.kill();
    let _ = old.wait();
}

#[test]
fn a_hostile_peer_gets_an_error_and_the_daemon_carries_on() {
    let s = Sandbox::new();
    assert_eq!(s.vahta(&["daemon", "restart"]).status.code(), Some(0));
    let address = s.paths().address().unwrap();

    // A hello of the wrong protocol is refused.
    let mut stream = vahta_os::ipc::Stream::connect(&address).unwrap();
    write_frame(
        &mut stream,
        &Hello {
            protocol: PROTOCOL + 1,
            version: "x".into(),
            kind: HelloKind::Client,
        },
    )
    .unwrap();
    let reply: HelloReply = read_frame(&mut stream).unwrap().unwrap();
    assert!(!reply.ok);

    // Garbage after a good hello is answered with an error and a close.
    let mut stream = vahta_os::ipc::Stream::connect(&address).unwrap();
    write_frame(
        &mut stream,
        &Hello {
            protocol: PROTOCOL,
            version: "x".into(),
            kind: HelloKind::Client,
        },
    )
    .unwrap();
    let reply: HelloReply = read_frame(&mut stream).unwrap().unwrap();
    assert!(reply.ok);
    let junk = b"{\"op\":\"status\",\"value\":\"fake-one\"}";
    stream
        .write_all(&(junk.len() as u32).to_le_bytes())
        .unwrap();
    stream.write_all(junk).unwrap();
    let answer: ClientReply = read_frame(&mut stream).unwrap().unwrap();
    let ClientReply::Error { message } = answer else {
        panic!("expected an error reply")
    };
    assert!(!message.contains("fake-one"));

    // A window with a token nobody issued is turned away.
    let mut stream = vahta_os::ipc::Stream::connect(&address).unwrap();
    write_frame(
        &mut stream,
        &Hello {
            protocol: PROTOCOL,
            version: "x".into(),
            kind: HelloKind::Surface {
                token: "0".repeat(64),
            },
        },
    )
    .unwrap();
    let reply: HelloReply = read_frame(&mut stream).unwrap().unwrap();
    assert!(!reply.ok);

    // An oversized length is refused too.
    let mut stream = vahta_os::ipc::Stream::connect(&address).unwrap();
    write_frame(
        &mut stream,
        &Hello {
            protocol: PROTOCOL,
            version: "x".into(),
            kind: HelloKind::Client,
        },
    )
    .unwrap();
    let _: HelloReply = read_frame(&mut stream).unwrap().unwrap();
    stream.write_all(&u32::MAX.to_le_bytes()).unwrap();
    let answer: ClientReply = read_frame(&mut stream).unwrap().unwrap();
    assert!(matches!(answer, ClientReply::Error { .. }));

    // And the daemon is still fine.
    let mut conn = connector(&s, false).connect().unwrap();
    assert!(matches!(
        conn.request(&ClientRequest::Status {}).unwrap(),
        ClientReply::Status(_)
    ));
}

// --- init, set, remove, import, reveal, copy -----------------------------------------

#[test]
fn init_and_set_go_through_the_window_and_nothing_secret_comes_back() {
    let s = Sandbox::new();
    s.script(&[r#"{"secret":"correct horse"}"#, r#"{"ack":true}"#]);
    let out = s.vahta(&["init"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(s.vault_path().is_file());
    assert_eq!(
        fs::read_to_string(s.project().join(".vahta/.gitignore")).unwrap(),
        "*\n"
    );
    // The window was shown the recovery key; this process was not.
    let log = s.window_log();
    let recovery = log
        .iter()
        .find(|e| e["ask"] == "recovery")
        .expect("the recovery key was shown");
    let key = recovery["shown"].as_str().unwrap().to_string();
    assert_eq!(key.matches('-').count(), 7);
    assert!(!text(&out.stdout).contains(&key) && !text(&out.stderr).contains(&key));
    // What the person approves is rendered by Vahta: project, vault, requester.
    let lines = recovery["panel"]["lines"].to_string();
    assert!(lines.contains("Project:") && lines.contains("Requested by:"));

    // A second init is refused, with no window.
    let before = s.asks();
    let out = s.vahta(&["init"]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(s.asks(), before);

    s.script(&[r#"{"secret":"correct horse"}"#, r#"{"secret":"fake-one"}"#]);
    let out = s.vahta(&["set", "ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout).trim(), "saved ZETA");
    s.script(&[r#"{"secret":"correct horse"}"#, r#"{"secret":"fake-two"}"#]);
    let out = s.vahta(&["set", "ALPHA", "--tier", "each-use", "--file", "alpha.pem"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));

    // The index shows names, kinds and tiers without any password...
    let list = s.vahta(&["list"]);
    let listed = text(&list.stdout);
    assert!(listed.contains("ZETA") && listed.contains("session"));
    assert!(
        listed.contains("ALPHA")
            && listed.contains("file:alpha.pem")
            && listed.contains("each_use")
    );
    assert!(!listed.contains("fake-"));
    // ...and the vault really holds what was typed.
    let vault = s.open_vault();
    assert_eq!(vault.get("ZETA").unwrap().expose(), b"fake-one");
    assert_eq!(vault.get("ALPHA").unwrap().expose(), b"fake-two");
    let tiers: Vec<_> = vault
        .entries()
        .iter()
        .map(|e| (e.name.as_str(), e.tier))
        .collect();
    assert!(tiers.contains(&("ALPHA", Tier::EachUse)) && tiers.contains(&("ZETA", Tier::Session)));

    // The window was told what it was approving.
    let set_ask = s
        .window_log()
        .into_iter()
        .rev()
        .find(|e| e["ask"] == "value")
        .unwrap();
    let lines = set_ask["panel"]["lines"].to_string();
    assert!(lines.contains("Name: ALPHA (tier each-use)"), "{lines}");

    // The journal names what happened and holds no value.
    let journal = fs::read_to_string(s.root.join("data/journal.jsonl")).unwrap();
    assert!(journal.contains("\"event\":\"set\"") && journal.contains("ALPHA"));
    for leak in ["fake-one", "fake-two", "correct horse", &key] {
        assert!(!journal.contains(leak), "the journal holds {leak}");
    }
}

#[test]
fn a_wrong_password_is_asked_again_and_cancelling_changes_nothing() {
    let s = Sandbox::new();
    s.with_vault(&[("ZETA", "fake-one", "session")]);
    let before = fs::read(s.vault_path()).unwrap();

    // Wrong, then right: one window, a warning on the second ask.
    s.script(&[
        r#"{"secret":"wrong"}"#,
        r#"{"secret":"correct horse"}"#,
        r#"{"secret":"fake-new"}"#,
    ]);
    let out = s.vahta(&["set", "ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let log = s.window_log();
    let any_warning = log.iter().any(|e| {
        e["panel"]["warning"]
            .as_str()
            .is_some_and(|w| w.contains("Wrong password"))
    });
    assert!(any_warning);
    assert_eq!(s.open_vault().get("ZETA").unwrap().expose(), b"fake-new");
    let after_set = fs::read(s.vault_path()).unwrap();
    assert_ne!(before, after_set);

    // Cancelled at the password: exit 4, the file untouched.
    s.script(&[r#"{"cancel":true}"#]);
    let out = s.vahta(&["set", "ZETA"]);
    assert_eq!(out.status.code(), Some(4));
    assert!(text(&out.stderr).contains("cancelled"));
    // Cancelled at the value, after the password: still untouched.
    s.script(&[r#"{"secret":"correct horse"}"#, r#"{"cancel":true}"#]);
    assert_eq!(s.vahta(&["set", "ZETA"]).status.code(), Some(4));
    assert_eq!(fs::read(s.vault_path()).unwrap(), after_set);

    // Three wrong passwords end the request.
    s.script(&[
        r#"{"secret":"no"}"#,
        r#"{"secret":"nope"}"#,
        r#"{"secret":"nein"}"#,
    ]);
    let out = s.vahta(&["set", "ZETA"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("too many wrong passwords"));
    assert_eq!(fs::read(s.vault_path()).unwrap(), after_set);
}

#[test]
fn what_can_be_refused_is_refused_before_any_window() {
    let s = Sandbox::new();
    // No vault yet.
    let out = s.vahta(&["set", "ZETA"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(text(&out.stderr).contains("vahta init"));
    s.with_vault(&[("ZETA", "fake-one", "session")]);
    let asks = s.asks();

    let out = s.vahta(&["set", "1bad"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("letters, digits and underscores"));
    // An unknown name, in the structured form an agent can read.
    let out = s.vahta(&["remove", "NOPE", "--json"]);
    assert_eq!(out.status.code(), Some(3));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["ok"], false);
    assert_eq!(doc["refused"]["kind"], "unknown_name");
    assert_eq!(doc["refused"]["names"][0]["name"], "NOPE");
    let out = s.vahta(&["reveal", "NOPE"]);
    assert_eq!(out.status.code(), Some(3));
    // Usage errors.
    assert_eq!(s.vahta(&["set"]).status.code(), Some(2));
    assert_eq!(s.vahta(&["set", "A", "B"]).status.code(), Some(2));
    assert_eq!(
        s.vahta(&["set", "A", "--tier", "weekly"]).status.code(),
        Some(2)
    );
    assert_eq!(s.vahta(&["import"]).status.code(), Some(2));
    assert_eq!(
        s.vahta(&["import", "--ka", "a", "--dotenv", "b"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        s.vahta(&["set", "A", "--value", "fake-one"]).status.code(),
        Some(2)
    );
    assert_eq!(s.asks(), asks, "a window opened for a refusal");
}

#[test]
fn remove_and_import_a_dotenv_file() {
    let s = Sandbox::new();
    s.with_vault(&[("ZETA", "fake-one", "session")]);
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&["remove", "ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(s.open_vault().entries().is_empty());

    fs::write(
        s.project().join("app.env"),
        "# comment\nexport ALPHA=fake-a\nBETA=\"fake b\"\nEMPTY=\n",
    )
    .unwrap();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&["import", "--dotenv", "app.env"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let vault = s.open_vault();
    assert_eq!(vault.get("ALPHA").unwrap().expose(), b"fake-a");
    assert_eq!(vault.get("BETA").unwrap().expose(), b"fake b");
    assert!(vault.get("EMPTY").is_err());
    // The window was shown the names, not the values.
    let ask = s
        .window_log()
        .into_iter()
        .rev()
        .find(|e| e["ask"] == "password")
        .unwrap();
    let lines = ask["panel"]["lines"].to_string();
    assert!(lines.contains("ALPHA, BETA") && !lines.contains("fake-a"));

    // A name already there refuses the whole file, before any window.
    let asks = s.asks();
    let out = s.vahta(&["import", "--dotenv", "app.env", "--json"]);
    assert_eq!(out.status.code(), Some(3));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["refused"]["kind"], "exists");
    assert_eq!(s.asks(), asks);
    // A file that is not a dotenv file is an error that quotes no content.
    fs::write(s.project().join("bad.env"), "not an assignment fake-leak\n").unwrap();
    let out = s.vahta(&["import", "--dotenv", "bad.env"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!text(&out.stderr).contains("fake-leak"));
    assert!(text(&out.stderr).contains("line 1"));
    assert_eq!(s.asks(), asks);
    // A missing file too.
    assert_eq!(
        s.vahta(&["import", "--dotenv", "gone.env"]).status.code(),
        Some(1)
    );
    assert_eq!(
        s.vahta(&["import", "--ka", "gone.ka"]).status.code(),
        Some(1)
    );
}

#[test]
fn reveal_shows_the_value_only_in_the_window() {
    let s = Sandbox::new();
    s.with_vault(&[("ZETA", "fake-one", "each-use")]);
    s.script(&[r#"{"secret":"correct horse"}"#, r#"{"ack":true}"#]);
    let out = s.vahta(&["reveal", "ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let shown = s
        .window_log()
        .into_iter()
        .rev()
        .find(|e| e["ask"] == "show")
        .expect("the window was shown the value");
    assert_eq!(shown["shown"], "fake-one");
    assert!(!text(&out.stdout).contains("fake-one") && !text(&out.stderr).contains("fake-one"));
    let journal = fs::read_to_string(s.root.join("data/journal.jsonl")).unwrap();
    assert!(journal.contains("\"event\":\"reveal\"") && !journal.contains("fake-one"));
}

#[cfg(target_os = "linux")]
#[test]
fn copy_puts_the_value_on_the_clipboard_and_takes_it_back() {
    use std::os::unix::fs::PermissionsExt;
    let s = Sandbox::new();
    s.with_vault(&[("ZETA", "fake-one", "session")]);
    // A fake Wayland clipboard in a directory that is the whole PATH.
    let bin = s.root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    for (name, body) in [
        (
            "wl-copy",
            "if [ \"$1\" = \"--clear\" ]; then : > \"$(dirname \"$0\")/clip\"; else cat > \"$(dirname \"$0\")/clip\"; fi",
        ),
        ("wl-paste", "cat \"$(dirname \"$0\")/clip\""),
    ] {
        let p = bin.join(name);
        fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    }
    // The daemon takes its environment from the command that starts it.
    assert_eq!(s.vahta(&["daemon", "stop"]).status.code(), Some(0));
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s
        .command(&s.project())
        // The fakes first; the system's `cat` and `dirname` after them.
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("WAYLAND_DISPLAY", "wayland-fake")
        .env("VAHTA_TEST_CLIPBOARD_SECONDS", "1")
        .args(["copy", "ZETA"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(fs::read(bin.join("clip")).unwrap(), b"fake-one");
    assert!(!text(&out.stdout).contains("fake-one"));
    wait_until("the clipboard to be cleared", 10, || {
        fs::read(bin.join("clip")).is_ok_and(|c| c.is_empty())
    });
    let journal = fs::read_to_string(s.root.join("data/journal.jsonl")).unwrap();
    assert!(journal.contains("copy_cleared") && !journal.contains("fake-one"));
}

#[test]
fn with_no_display_the_real_surface_fails_closed() {
    // A daemon with the real terminal surface, and nowhere to open a window.
    let s = Sandbox::new();
    let mut cmd = s.command(&s.project());
    cmd.env_remove("VAHTA_TEST_SURFACE")
        .env("VAHTA_TEST_KDF", "1");
    let out = cmd.args(["init"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    assert!(
        err.contains("no interactive display") && err.contains("nothing was done"),
        "{err}"
    );
    assert!(!s.vault_path().exists());
}

#[cfg(unix)]
#[test]
fn the_real_window_process_connects_back_with_its_token_and_carries_the_answers() {
    use std::os::unix::fs::PermissionsExt;
    let s = Sandbox::new();
    // A "terminal" that is kitty-shaped (`kitty CMD ARGS`), records its command
    // line, and runs the command with the test's keystrokes on its stdin. It is
    // the only thing on PATH, so no real terminal can be found.
    let bin = s.root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let term = bin.join("kitty");
    fs::write(
        &term,
        format!(
            "#!/bin/sh\necho \"$@\" > {}\nexec \"$@\" < \"$VAHTA_FAKE_TERMINAL_INPUT\"\n",
            s.root.join("terminal-args").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&term, fs::Permissions::from_mode(0o755)).unwrap();
    let keys = s.root.join("keys");
    fs::write(&keys, "correct horse\ncorrect horse\n\n").unwrap();
    let mut cmd = s.command(&s.project());
    cmd.env_remove("VAHTA_TEST_SURFACE")
        .env("VAHTA_TEST_KDF", "1")
        .env("VAHTA_TEST_SURFACE_PLAIN", "1")
        .env("VAHTA_FAKE_TERMINAL_INPUT", &keys)
        .env("PATH", &bin)
        .env("DISPLAY", ":fake");
    let out = cmd.args(["init"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.open_vault().entries().len(), 0);

    // The token and the address went in the environment, not on the command line.
    let args = fs::read_to_string(s.root.join("terminal-args")).unwrap();
    assert!(args.contains("_surface"));
    let longest_hex_run = args
        .split(|c: char| !c.is_ascii_hexdigit())
        .map(str::len)
        .max()
        .unwrap_or(0);
    assert!(
        longest_hex_run < 32,
        "something token-like is on argv: {args}"
    );
    assert!(!args.contains("daemon.sock"));
}
