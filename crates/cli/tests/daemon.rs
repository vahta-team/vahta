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
use vahta_ipc::client::{ClientError, Connector};
use vahta_ipc::paths::Paths;
use vahta_vault::store::LocalStore;
use vahta_vault::{Tier, Vault};

use vahta_ipc::protocol::{
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

    /// What the window was asked and shown, in order. The daemon may be in the
    /// middle of writing a line; a line that does not parse yet is left for the
    /// next look.
    fn window_log(&self) -> Vec<Value> {
        fs::read_to_string(self.root.join("surface.log"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
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

    /// `vahta init` and `vahta add` for each of `items`, through the window.
    fn with_vault(&self, items: &[(&str, &str, &str)]) {
        self.script(&[r#"{"secret":"correct horse"}"#, r#"{"ack":true}"#]);
        let out = self.vahta(&["init"]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        for (name, value, tier) in items {
            self.script(&[
                r#"{"secret":"correct horse"}"#,
                &format!(r#"{{"secret":"{value}"}}"#),
            ]);
            let out = self.vahta(&["add", name, "--tier", tier]);
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

// --- init, add, reset, remove, import, reveal, copy ---------------------------------

#[test]
fn init_and_add_go_through_the_window_and_nothing_secret_comes_back() {
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
    let out = s.vahta(&["add", "ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout).trim(), "saved ZETA");
    s.script(&[r#"{"secret":"correct horse"}"#, r#"{"secret":"fake-two"}"#]);
    let out = s.vahta(&["add", "ALPHA", "--tier", "each-use", "--file", "alpha.pem"]);
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
    assert!(journal.contains("\"event\":\"add\"") && journal.contains("ALPHA"));
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
    let out = s.vahta(&["reset", "ZETA"]);
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
    let out = s.vahta(&["reset", "ZETA"]);
    assert_eq!(out.status.code(), Some(4));
    assert!(text(&out.stderr).contains("cancelled"));
    // Cancelled at the value, after the password: still untouched.
    s.script(&[r#"{"secret":"correct horse"}"#, r#"{"cancel":true}"#]);
    assert_eq!(s.vahta(&["reset", "ZETA"]).status.code(), Some(4));
    assert_eq!(fs::read(s.vault_path()).unwrap(), after_set);

    // Three wrong passwords end the request.
    s.script(&[
        r#"{"secret":"no"}"#,
        r#"{"secret":"nope"}"#,
        r#"{"secret":"nein"}"#,
    ]);
    let out = s.vahta(&["reset", "ZETA"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("too many wrong passwords"));
    assert_eq!(fs::read(s.vault_path()).unwrap(), after_set);
}

#[test]
fn what_can_be_refused_is_refused_before_any_window() {
    let s = Sandbox::new();
    // No vault yet.
    let out = s.vahta(&["add", "ZETA"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(text(&out.stderr).contains("vahta init"));
    s.with_vault(&[("ZETA", "fake-one", "session")]);
    let asks = s.asks();

    let out = s.vahta(&["add", "1bad"]);
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
    assert_eq!(s.vahta(&["add"]).status.code(), Some(2));
    assert_eq!(s.vahta(&["add", "A", "B"]).status.code(), Some(2));
    assert_eq!(
        s.vahta(&["add", "A", "--tier", "weekly"]).status.code(),
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
        s.vahta(&["add", "A", "--value", "fake-one"]).status.code(),
        Some(2)
    );
    assert_eq!(s.asks(), asks, "a window opened for a refusal");
}

#[test]
fn add_refuses_a_name_there_is_and_reset_one_there_is_not() {
    let s = Sandbox::new();
    s.with_vault(&[("ZETA", "fake-one", "each-use")]);
    let asks = s.asks();
    // Both refusals come from the plain index, before any window.
    let out = s.vahta(&["add", "ZETA", "--json"]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["refused"]["kind"], "exists");
    assert_eq!(doc["refused"]["names"][0]["name"], "ZETA");
    assert!(
        doc["refused"]["message"]
            .as_str()
            .unwrap()
            .contains("vahta reset ZETA")
    );
    let out = s.vahta(&["reset", "NOPE"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(
        text(&out.stderr).contains("vahta add NOPE"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(s.asks(), asks, "a window opened for a refusal");

    // A reset replaces the value and keeps the tier it had.
    s.script(&[r#"{"secret":"correct horse"}"#, r#"{"secret":"fake-new"}"#]);
    let out = s.vahta(&["reset", "ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout).trim(), "replaced ZETA");
    let vault = s.open_vault();
    assert_eq!(vault.get("ZETA").unwrap().expose(), b"fake-new");
    assert_eq!(vault.entries()[0].tier, Tier::EachUse);
    let journal = fs::read_to_string(s.root.join("data/journal.jsonl")).unwrap();
    assert!(journal.contains("\"event\":\"reset\""));
    assert!(!journal.contains("fake-new") && !journal.contains("fake-one"));

    // The old command says which of the two to use, and does nothing.
    let asks = s.asks();
    let out = s.vahta(&["set", "ZETA"]);
    assert_eq!(out.status.code(), Some(2));
    let err = text(&out.stderr);
    assert!(
        err.contains("unknown command: set")
            && err.contains("vahta add")
            && err.contains("vahta reset"),
        "{err}"
    );
    assert_eq!(s.asks(), asks);
}

#[test]
fn vh_is_the_same_program() {
    // `--version` and `--help` touch no directory and no daemon.
    let out = Command::new(env!("CARGO_BIN_EXE_vh"))
        .arg("--version")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        text(&out.stdout).trim(),
        format!("vahta {}", env!("CARGO_PKG_VERSION"))
    );
    let out = Command::new(env!("CARGO_BIN_EXE_vh"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(text(&out.stdout).contains("`vh` is the short name"));
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

// Only Linux and the BSDs can lack a display: Windows and macOS always have a
// console or Terminal.app to open, which on CI nobody answers.
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
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

// macOS opens Terminal.app, not a terminal found on PATH, so the fake terminal
// below is only reachable on Linux and the BSDs.
#[cfg(all(unix, not(target_os = "macos")))]
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

// The daemon gives up on a window when its time to answer runs out, but the
// window may be sitting in a read that only returns on Enter. It must notice the
// hang-up and close itself, not take a password and do nothing with it.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn the_real_window_closes_itself_when_the_daemon_hangs_up_mid_question() {
    use std::os::unix::fs::PermissionsExt;
    let s = Sandbox::new();
    // A kitty-shaped "terminal" whose stdin never answers: a FIFO held open by
    // a writer that writes nothing. It records the window's exit code.
    let bin = s.root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let fifo = s.root.join("silent");
    let status = s.root.join("window-status");
    let screen = s.root.join("window-screen");
    let term = bin.join("kitty");
    fs::write(
        &term,
        format!(
            "#!/bin/sh\nmkfifo {fifo}\nsleep 60 > {fifo} &\n\"$@\" < {fifo} > {screen} 2>&1\necho $? > {status}\nkill $! 2>/dev/null\n",
            fifo = fifo.display(),
            screen = screen.display(),
            status = status.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&term, fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let mut cmd = s.command(&s.project());
    cmd.env_remove("VAHTA_TEST_SURFACE")
        .env("VAHTA_TEST_KDF", "1")
        .env("VAHTA_TEST_SURFACE_PLAIN", "1")
        .env("PATH", &path)
        .env("DISPLAY", ":fake");
    let mut init = cmd
        .args(["init"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    // The window is up and asking.
    wait_until("the window to ask", 20, || {
        fs::read_to_string(&screen).is_ok_and(|t| !t.is_empty())
    });

    let out = s.vahta(&["daemon", "stop"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    // Well before the silent writer's 60 seconds.
    wait_until("the window to close itself", 15, || status.exists());
    assert_eq!(fs::read_to_string(&status).unwrap().trim(), "5");
    assert!(
        fs::read_to_string(&screen)
            .unwrap()
            .contains("nothing was done"),
    );
    let _ = init.wait();
    assert!(!s.vault_path().exists());
}

// --- sessions ---------------------------------------------------------------------------

impl Sandbox {
    /// `vahta sessions --json`, as the sessions array.
    fn sessions(&self) -> Vec<Value> {
        let out = self.vahta(&["sessions", "--json"]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
        doc["sessions"].as_array().unwrap().clone()
    }

    fn journal(&self) -> String {
        fs::read_to_string(self.root.join("data/journal.jsonl")).unwrap_or_default()
    }
}

/// A vault with a session-tier ZETA and BETA and an each-use ALPHA.
fn sandbox_with_secrets() -> Sandbox {
    let s = Sandbox::new();
    s.with_vault(&[
        ("ZETA", "fake-one", "session"),
        ("BETA", "fake-two", "session"),
        ("ALPHA", "fake-three", "each-use"),
    ]);
    s
}

#[test]
fn unlock_opens_a_session_for_the_session_tier_secrets_and_names_its_anchor() {
    let s = sandbox_with_secrets();
    let asks = s.asks();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&["unlock", "--json", "--label", "deploy the site"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    let info = &doc["session"];
    // Every session-tier secret and not the each-use one.
    assert_eq!(info["names"], serde_json::json!(["BETA", "ZETA"]));
    assert_eq!(info["role"], "runner");
    assert_eq!(
        info["remaining_secs"].as_u64().map(|s| s > 1700),
        Some(true)
    );
    // The anchor is the process that called us: this test.
    assert_eq!(info["anchor_pid"], std::process::id());
    assert_eq!(s.asks(), asks + 1, "one window, one password");
    assert!(!text(&out.stdout).contains("fake-") && !text(&out.stdout).contains("correct horse"));

    // What the person approved: project, vault, names, duration, anchor, and
    // the agent's description marked as such.
    let ask = s
        .window_log()
        .into_iter()
        .rev()
        .find(|e| e["ask"] == "password")
        .unwrap();
    let lines = ask["panel"]["lines"].to_string();
    for needle in [
        "Project:",
        "Vault:",
        "Secrets: BETA, ZETA",
        "Lasts: 30 minute(s)",
        "Belongs to:",
    ] {
        assert!(lines.contains(needle), "{needle} missing from {lines}");
    }
    assert!(lines.contains(&format!("(pid {})", std::process::id())));
    assert_eq!(ask["panel"]["agent_note"], "deploy the site");

    let list = s.sessions();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], info["id"]);
    assert_eq!(list[0]["uses"], 0);
    // The daemon reports it, and the text form lists it too.
    let status: Value =
        serde_json::from_slice(&s.vahta(&["daemon", "status", "--json"]).stdout).unwrap();
    assert_eq!(status["sessions"], 1);
    let text_list = text(&s.vahta(&["sessions"]).stdout);
    assert!(text_list.contains("BETA,ZETA") && text_list.contains(info["id"].as_str().unwrap()));

    let journal = s.journal();
    assert!(journal.contains("session_start") && journal.contains("BETA"));
    assert!(!journal.contains("fake-") && !journal.contains("correct horse"));
}

#[test]
fn an_each_use_or_unknown_name_refuses_the_whole_unlock_before_any_window() {
    let s = sandbox_with_secrets();
    let asks = s.asks();
    let out = s.vahta(&[
        "unlock", "--secret", "ZETA", "--secret", "ALPHA", "--secret", "NOPE", "--json",
    ]);
    assert_eq!(out.status.code(), Some(3));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["ok"], false);
    assert_eq!(doc["refused"]["kind"], "each_use");
    let names = doc["refused"]["names"].as_array().unwrap();
    assert!(
        names
            .iter()
            .any(|n| n["name"] == "ALPHA" && n["why"] == "each_use")
    );
    assert!(
        names
            .iter()
            .any(|n| n["name"] == "NOPE" && n["why"] == "unknown_name")
    );
    // ZETA was fine, so it is not in the list of problems.
    assert!(!names.iter().any(|n| n["name"] == "ZETA"));
    assert!(
        doc["refused"]["message"]
            .as_str()
            .unwrap()
            .contains("nothing was opened")
    );
    assert_eq!(s.asks(), asks, "no window for a refusal");
    assert!(s.sessions().is_empty());
    // In text form the names and reasons are lines the caller can read.
    let out = s.vahta(&["unlock", "--secret", "ALPHA"]);
    assert_eq!(out.status.code(), Some(3));
    let err = text(&out.stderr);
    assert!(err.contains("ALPHA") && err.contains("each-use"), "{err}");
    // Only the causes present are explained.
    assert!(!err.contains("not in this vault"), "{err}");
    let out = s.vahta(&["unlock", "--secret", "NOPE"]);
    assert_eq!(out.status.code(), Some(3));
    let err = text(&out.stderr);
    assert!(
        err.contains("not in this vault") && !err.contains("each-use"),
        "{err}"
    );
    // A vault with only each-use secrets has nothing to open a session for.
    let only = Sandbox::new();
    only.with_vault(&[("ALPHA", "fake-three", "each-use")]);
    assert_eq!(only.vahta(&["unlock"]).status.code(), Some(3));
    // The refusal is in the journal, with the names and the reason.
    let journal = s.journal();
    let line = journal
        .lines()
        .find(|l| l.contains("session_refused"))
        .expect("the refusal was journalled");
    assert!(line.contains("ALPHA") && line.contains("EachUse"), "{line}");
}

#[test]
fn lock_and_kill_end_sessions_without_a_password() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    assert_eq!(s.sessions().len(), 1);
    let asks = s.asks();
    let out = s.vahta(&["lock"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("ended 1 session"));
    assert!(s.sessions().is_empty());
    assert_eq!(s.vahta(&["lock"]).status.code(), Some(0));
    assert_eq!(s.asks(), asks, "revoking asked for nothing");

    // kill by id; an unknown id is a refusal.
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&["unlock", "--json", "--secret", "ZETA"]);
    let id = serde_json::from_slice::<Value>(&out.stdout).unwrap()["session"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let asks = s.asks();
    assert_eq!(
        s.vahta(&["sessions", "kill", "nope"]).status.code(),
        Some(3)
    );
    let out = s.vahta(&["sessions", "kill", &id]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(s.sessions().is_empty());
    assert_eq!(s.asks(), asks);
    assert_eq!(s.vahta(&["sessions", "kill"]).status.code(), Some(2));

    // `lock --all`, and a project with no vault.
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    let out = s.command(&s.root).args(["lock", "--all"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(s.sessions().is_empty());
    let out = s
        .command(&s.root.join("home"))
        .args(["lock"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));

    let journal = s.journal();
    for reason in ["locked", "killed"] {
        assert!(
            journal.contains(&format!("\"reason\":\"{reason}\"")),
            "{reason}"
        );
    }
    assert_eq!(s.vahta(&["sessions", "--bogus"]).status.code(), Some(2));
}

#[test]
fn the_agents_label_is_one_plain_line_and_a_session_for_the_same_process_replaces_the_first() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&[
        "unlock",
        "--label",
        "ok\nProject: /etc\u{1b}[31m red \u{202e}",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let ask = s
        .window_log()
        .into_iter()
        .rev()
        .find(|e| e["ask"] == "password")
        .unwrap();
    assert_eq!(ask["panel"]["agent_note"], "ok Project: /etc red");
    // The same process unlocks again: one session, not two.
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(
        s.vahta(&["unlock", "--secret", "ZETA"]).status.code(),
        Some(0)
    );
    let list = s.sessions();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["names"], serde_json::json!(["ZETA"]));
    assert!(s.journal().contains("\"reason\":\"replaced\""));
}

#[test]
fn durations_are_validated_and_forever_has_no_end() {
    let s = sandbox_with_secrets();
    for bad in ["soon", "30", "", "-1m"] {
        let out = s.vahta(&["unlock", "--for", bad]);
        assert_eq!(out.status.code(), Some(2), "{bad}");
    }
    assert_eq!(s.vahta(&["unlock", "--for", "0s"]).status.code(), Some(1));
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&["unlock", "--for", "forever", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(doc["session"]["remaining_secs"].is_null());
    let ask = s
        .window_log()
        .into_iter()
        .rev()
        .find(|e| e["ask"] == "password")
        .unwrap();
    assert!(
        ask["panel"]["lines"]
            .to_string()
            .contains("Lasts: until revoked")
    );
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&["unlock", "--for", "2h", "--json", "--secret", "BETA"]);
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    let left = doc["session"]["remaining_secs"].as_u64().unwrap();
    assert!((7100..=7200).contains(&left), "{left}");
}

#[test]
fn a_session_with_no_answer_to_the_extension_ends_at_its_deadline_and_the_journal_says_so() {
    let s = sandbox_with_secrets();
    // Four seconds: the question comes at two, and nobody answers.
    let passwords = |s: &Sandbox| {
        s.window_log()
            .iter()
            .filter(|e| e["ask"] == "password")
            .count()
    };
    let before = passwords(&s);
    s.script(&[r#"{"secret":"correct horse"}"#, r#"{"noanswer":true}"#]);
    let out = s.vahta(&["unlock", "--for", "4s"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    wait_until("the question", 10, || {
        s.window_log().iter().any(|e| e["ask"] == "confirm")
    });
    let q = s
        .window_log()
        .into_iter()
        .find(|e| e["ask"] == "confirm")
        .unwrap();
    assert_eq!(q["prompt"], "Extend by 30 minutes?");
    // No password in an extension question.
    assert_eq!(passwords(&s), before + 1);
    wait_until("the session to end", 10, || s.sessions().is_empty());
    let journal = s.journal();
    assert!(journal.contains("\"reason\":\"expired\""));
    assert!(journal.contains("session_extension") && journal.contains("no_answer"));
}

#[test]
fn saying_yes_to_the_extension_keeps_the_session_alive_past_its_deadline() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#, r#"{"yes":true}"#]);
    assert_eq!(s.vahta(&["unlock", "--for", "4s"]).status.code(), Some(0));
    wait_until("the extension", 10, || {
        s.journal().contains("\"result\":\"extended\"")
    });
    // Past the original end it is still there, with about half an hour left.
    std::thread::sleep(Duration::from_secs(4));
    let list = s.sessions();
    assert_eq!(list.len(), 1);
    assert!(list[0]["remaining_secs"].as_u64().unwrap() > 1700);
}

#[cfg(target_os = "linux")]
#[test]
fn a_session_ends_when_its_anchor_process_is_gone() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    // `find` runs vahta and exits: it is the nearest process that is neither a
    // shell nor a wrapper, so it is the anchor, and it is gone at once.
    let mut find = Command::new("find");
    find.current_dir(s.project());
    let base = s.command(&s.project());
    for (k, v) in base.get_envs() {
        match v {
            Some(v) => find.env(k, v),
            None => find.env_remove(k),
        };
    }
    let out = find
        .args([".", "-maxdepth", "0", "-exec"])
        .arg(env!("CARGO_BIN_EXE_vahta"))
        .args(["unlock", "--json", ";"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["session"]["anchor_exe"], "find");
    wait_until("the session to end with its anchor", 10, || {
        s.sessions().is_empty()
    });
    assert!(s.journal().contains("anchor_exited"));
}

#[test]
fn a_daemon_of_another_version_holding_sessions_is_not_replaced() {
    let s = sandbox_with_secrets();
    assert_eq!(s.vahta(&["daemon", "stop"]).status.code(), Some(0));
    let mut old = start_old_daemon(&s, "0.0.0-old");
    // A session on the old daemon, opened over a connection that does not
    // replace it.
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let mut conn = connector(&s, false).connect_running().unwrap().unwrap();
    let reply = conn
        .request(&ClientRequest::Unlock {
            cwd: s.project().to_string_lossy().into_owned(),
            names: None,
            duration: vahta_ipc::protocol::DurationSpec::Default {},
            label: None,
        })
        .unwrap();
    assert!(matches!(reply, ClientReply::Session(_)), "{reply:?}");
    drop(conn);

    // A command that needs the daemon is told, and pointed at the way out.
    let out = s.vahta(&["add", "ZETA"]);
    assert_eq!(out.status.code(), Some(5));
    let err = text(&out.stderr);
    assert!(
        err.contains("holds 1 live session") && err.contains("vahta daemon restart"),
        "{err}"
    );
    assert!(old.try_wait().unwrap().is_none());
    assert!(matches!(
        connector(&s, true).connect(),
        Err(ClientError::LiveSessions { sessions: 1, .. })
    ));
    // The explicit restart ends them.
    let out = s.vahta(&["daemon", "restart"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("1 session(s) ended"));
    wait_until("the old daemon to exit", 10, || {
        old.try_wait().unwrap().is_some()
    });
    assert!(s.sessions().is_empty());
}

// --- run and delegate -----------------------------------------------------------------------

#[cfg(unix)]
const VAHTA: &str = env!("CARGO_BIN_EXE_vahta");

#[cfg(unix)]
impl Sandbox {
    fn passwords_asked(&self) -> usize {
        self.window_log()
            .iter()
            .filter(|e| e["ask"] == "password")
            .count()
    }
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn run_with_the_password_injects_the_value_and_scrubs_it_from_the_output() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "printenv", "ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "***REDACTED(ZETA)***\n");
    // The window said what it was approving: names, the command, one run only.
    let ask = s
        .window_log()
        .into_iter()
        .rev()
        .find(|e| e["ask"] == "password")
        .unwrap();
    let lines = ask["panel"]["lines"].to_string();
    assert!(
        lines.contains("Secrets: ZETA") && lines.contains("Command: printenv ZETA"),
        "{lines}"
    );
    assert!(lines.contains("no session is opened"));
    // No session came of it.
    assert!(s.sessions().is_empty());
    // The next run asks again.
    let before = s.passwords_asked();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(
        s.vahta(&["run", "--secret", "ZETA", "--", "true"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(s.passwords_asked(), before + 1);
    let journal = s.journal();
    assert!(journal.contains("\"event\":\"run\"") && journal.contains("\"reason\":\"password\""));
    assert!(journal.contains("run_end") && !journal.contains("fake-"));
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn names_and_variables_come_from_the_flags_and_vahta_toml() {
    let s = sandbox_with_secrets();
    // No names and no manifest: nothing to run with.
    let out = s.vahta(&["run", "--", "true"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(text(&out.stderr).contains("vahta.toml"));
    fs::write(
        s.project().join("vahta.toml"),
        "[secrets.ZETA]\nenv = \"MY_ZETA\"\n[secrets.BETA]\n[secrets.GONE]\nrequired = false\n",
    )
    .unwrap();
    // Every manifest name the vault holds, each in its variable.
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&[
        "run",
        "--",
        "sh",
        "-c",
        "echo \"[$MY_ZETA] [$BETA] [$ZETA] [$GONE]\"",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "[***REDACTED(ZETA)***] [***REDACTED(BETA)***] [] []\n"
    );
    // --as overrides the variable; --secret narrows the names.
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&[
        "run",
        "--secret",
        "BETA",
        "--as",
        "BETA=OTHER",
        "--",
        "sh",
        "-c",
        "echo \"[$OTHER] [$BETA] [$MY_ZETA]\"",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "[***REDACTED(BETA)***] [] []\n");
    // What is refused, with no window.
    let asks = s.asks();
    for (args, code) in [
        (vec!["run", "--secret", "NOPE", "--", "true"], 3),
        (
            vec!["run", "--secret", "BETA", "--as", "ZETA=X", "--", "true"],
            1,
        ),
        (
            vec![
                "run",
                "--secret",
                "BETA",
                "--as",
                "BETA=LD_PRELOAD",
                "--",
                "true",
            ],
            1,
        ),
        (
            vec!["run", "--secret", "BETA", "--as", "BETA=1bad", "--", "true"],
            1,
        ),
        (
            vec![
                "run", "--secret", "BETA", "--secret", "ZETA", "--as", "BETA=X", "--as", "ZETA=X",
                "--", "true",
            ],
            1,
        ),
        (vec!["run", "--secret", "BETA"], 2),
        (vec!["run", "--as", "NOEQUALS", "--", "true"], 2),
        (vec!["run", "--bogus", "--", "true"], 2),
    ] {
        let out = s.vahta(&args);
        assert_eq!(
            out.status.code(),
            Some(code),
            "{args:?}: {}",
            text(&out.stderr)
        );
    }
    assert_eq!(s.asks(), asks, "a window opened for a refusal");
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn exit_codes_streams_stdin_cwd_and_the_environment_pass_through() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    let run = |args: &[&str]| s.vahta(&[&["run", "--secret", "ZETA", "--"][..], args].concat());
    assert_eq!(run(&["sh", "-c", "exit 7"]).status.code(), Some(7));
    assert_eq!(run(&["sh", "-c", "kill -9 $$"]).status.code(), Some(137));
    // stdout and stderr stay separate, and a value on either is scrubbed.
    let out = run(&["sh", "-c", "echo out $ZETA; echo err $ZETA >&2"]);
    assert_eq!(text(&out.stdout), "out ***REDACTED(ZETA)***\n");
    assert_eq!(text(&out.stderr), "err ***REDACTED(ZETA)***\n");
    // A program that does not exist is a failure with a reason.
    let out = run(&["definitely-not-a-program"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("cannot start definitely-not-a-program"));

    // The directory and the environment are the caller's, less what must not
    // be passed on.
    let sub = s.project().join("sub");
    fs::create_dir_all(&sub).unwrap();
    let out = s
        .command(&sub)
        .env("FOO", "bar baz")
        .env("LD_PRELOAD", "/nonexistent.so")
        .env("LD_LIBRARY_PATH", "/nonexistent")
        // Not DYLD_INSERT_LIBRARIES: on macOS that would stop the vahta
        // client itself, which dyld refuses to start with a missing library.
        .env("DYLD_FAKE_ONE", "/nonexistent")
        .args(["run", "--secret", "ZETA", "--", "sh", "-c"])
        .arg("pwd; echo \"$FOO\"; env | grep -c -E '^(LD_PRELOAD|LD_LIBRARY_PATH|DYLD_|VAHTA_)' || true")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let lines: Vec<String> = text(&out.stdout).lines().map(str::to_string).collect();
    assert!(lines[0].ends_with("/project/sub"), "{lines:?}");
    assert_eq!(lines[1], "bar baz");
    assert_eq!(lines[2], "0");

    // stdin is relayed, and what comes back is scrubbed.
    let mut child = s
        .command(&s.project())
        .args(["run", "--secret", "ZETA", "--", "cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"hello fake-one and fake-on")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(text(&out.stdout), "hello ***REDACTED(ZETA)*** and fake-on");
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn a_session_serves_runs_with_no_window_and_each_use_secrets_always_ask() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    let asked = s.asks();
    for _ in 0..2 {
        let out = s.vahta(&[
            "run",
            "--secret",
            "ZETA",
            "--secret",
            "BETA",
            "--",
            "sh",
            "-c",
            "echo $ZETA $BETA",
        ]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert_eq!(
            text(&out.stdout),
            "***REDACTED(ZETA)*** ***REDACTED(BETA)***\n"
        );
    }
    assert_eq!(s.asks(), asked, "the session answered both runs");
    assert_eq!(s.sessions()[0]["uses"], 2);
    let journal = s.journal();
    assert!(journal.matches("\"reason\":\"session ").count() >= 2);

    // An each-use secret asks every time, in a session or not; so does a run
    // that mixes it with covered ones.
    for args in [
        vec!["run", "--secret", "ALPHA", "--", "printenv", "ALPHA"],
        vec!["run", "--secret", "ALPHA", "--secret", "ZETA", "--", "true"],
    ] {
        s.script(&[r#"{"secret":"correct horse"}"#]);
        let before = s.asks();
        let out = s.vahta(&args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{args:?}: {}",
            text(&out.stderr)
        );
        assert_eq!(s.asks(), before + 1, "{args:?}");
    }
    // A name the session does not cover (it covers all session-tier ones, so
    // narrow it first) asks for this one run and opens no session.
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(
        s.vahta(&["unlock", "--secret", "ZETA"]).status.code(),
        Some(0)
    );
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let before = s.asks();
    let out = s.vahta(&["run", "--secret", "BETA", "--", "printenv", "BETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.asks(), before + 1);
    assert_eq!(s.sessions().len(), 1);
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn lock_ends_the_session_and_the_next_run_asks_again() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    assert_eq!(
        s.vahta(&["run", "--secret", "ZETA", "--", "true"])
            .status
            .code(),
        Some(0)
    );
    let asks = s.asks();
    assert_eq!(s.vahta(&["lock"]).status.code(), Some(0));
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(
        s.vahta(&["run", "--secret", "ZETA", "--", "true"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(s.asks(), asks + 1);
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn a_changed_secret_fails_the_session_closed_with_a_message_to_unlock_again() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(
        s.vahta(&["unlock", "--secret", "ZETA"]).status.code(),
        Some(0)
    );
    assert_eq!(
        s.vahta(&["run", "--secret", "ZETA", "--", "true"])
            .status
            .code(),
        Some(0)
    );
    // The value is replaced (through the window, as it must be).
    s.script(&[r#"{"secret":"correct horse"}"#, r#"{"secret":"fake-new"}"#]);
    assert_eq!(s.vahta(&["reset", "ZETA"]).status.code(), Some(0));
    let asks = s.asks();
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "true"]);
    // Refused, not run, and not silently re-prompted.
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("unlock again"));
    assert_eq!(s.asks(), asks);
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn a_command_started_by_the_daemon_inherits_the_session() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    let asks = s.asks();
    // The inner `vahta run` is a descendant of a process the daemon launched,
    // not of the unlock's anchor, and names the sandbox explicitly because the
    // daemon strips VAHTA_* from what it launches.
    let script = format!(
        "VAHTA_RUNTIME_DIR='{r}' VAHTA_DATA_DIR='{d}' VAHTA_CONFIG_DIR='{c}' \
         VAHTA_TEST_SURFACE='{sc}' VAHTA_TEST_SURFACE_LOG='{l}' HOME='{h}' \
         '{v}' run --secret BETA -- sh -c 'echo $BETA'",
        r = s.root.join("run").display(),
        d = s.root.join("data").display(),
        c = s.root.join("config").display(),
        sc = s.root.join("script.jsonl").display(),
        l = s.root.join("surface.log").display(),
        h = s.root.join("home").display(),
        v = VAHTA,
    );
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "sh", "-c", &script]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "***REDACTED(BETA)***\n");
    assert_eq!(s.asks(), asks, "the inner run used the session too");
    // Outer and inner both counted.
    assert_eq!(s.sessions()[0]["uses"], 2);
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn delegation_narrows_the_session_and_refuses_anything_wider_with_no_window() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&["unlock", "--json"]);
    let root_id = serde_json::from_slice::<Value>(&out.stdout).unwrap()["session"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let asks = s.asks();

    // Inside a delegation for ZETA alone: ZETA runs, with no window...
    let out = s.vahta(&[
        "delegate", "--secret", "ZETA", "--for", "10m", "--", VAHTA, "run", "--secret", "ZETA",
        "--", "printenv", "ZETA",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "***REDACTED(ZETA)***\n");
    // ...and BETA, which the parent has but the child does not, is refused with
    // no window, and the refusal is the sub-agent's exit code.
    let out = s.vahta(&[
        "delegate", "--secret", "ZETA", "--", VAHTA, "run", "--secret", "BETA", "--", "true",
    ]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    let err = text(&out.stderr);
    assert!(
        err.contains("BETA") && err.contains("not covered by this session"),
        "{err}"
    );
    assert_eq!(s.asks(), asks, "no window for a delegated session");

    // While it runs, the child is below the parent and belongs to the
    // delegating process.
    let out = s.vahta(&[
        "delegate", "--secret", "ZETA", "--", VAHTA, "sessions", "--json",
    ]);
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    let list = doc["sessions"].as_array().unwrap();
    assert_eq!(list.len(), 2);
    let child = list.iter().find(|x| x["parent"] == root_id).unwrap();
    assert_eq!(child["names"], serde_json::json!(["ZETA"]));
    assert_eq!(child["anchor_exe"], "vahta");
    // Once the command is gone so is the child session; the parent remains.
    let list = s.sessions();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], root_id);

    // Wider than the parent: refused, no window.
    for (args, kind) in [
        (
            vec!["delegate", "--secret", "ALPHA", "--", "true"],
            "not_a_subset",
        ),
        (
            vec![
                "delegate", "--secret", "ZETA", "--secret", "NOPE", "--", "true",
            ],
            "not_a_subset",
        ),
        (
            vec!["delegate", "--secret", "ZETA", "--for", "2h", "--", "true"],
            "later_deadline",
        ),
        (
            vec![
                "delegate", "--secret", "ZETA", "--for", "forever", "--", "true",
            ],
            "later_deadline",
        ),
    ] {
        let mut full = args.clone();
        full.insert(1, "--label");
        full.insert(2, "x");
        let out = s.vahta(&full);
        assert_eq!(
            out.status.code(),
            Some(3),
            "{args:?}: {}",
            text(&out.stderr)
        );
        let _ = kind;
    }
    assert_eq!(s.asks(), asks);
    assert!(s.journal().contains("delegate_refused"));
    // Usage errors, and a program that cannot start (the session still ends).
    assert_eq!(s.vahta(&["delegate", "--", "true"]).status.code(), Some(3));
    assert_eq!(
        s.vahta(&["delegate", "--secret", "ZETA"]).status.code(),
        Some(2)
    );
    assert_eq!(
        s.vahta(&[
            "delegate",
            "--secret",
            "ZETA",
            "--",
            "definitely-not-a-program"
        ])
        .status
        .code(),
        Some(127)
    );
    assert_eq!(s.sessions().len(), 1);
    // With no session at all there is nothing to narrow.
    assert_eq!(s.vahta(&["lock"]).status.code(), Some(0));
    let out = s.vahta(&["delegate", "--secret", "ZETA", "--", "true"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(text(&out.stderr).contains("vahta unlock"));
}

#[cfg(target_os = "linux")]
#[test]
fn a_command_is_ended_when_its_client_goes_away() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    let pidfile = s.root.join("child.pid");
    let mut client = s
        .command(&s.project())
        .args(["run", "--secret", "ZETA", "--", "sh", "-c"])
        .arg(format!("echo $$ > '{}'; exec sleep 60", pidfile.display()))
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    wait_until("the command to start", 10, || {
        fs::read_to_string(&pidfile).is_ok_and(|p| !p.trim().is_empty())
    });
    let pid: u32 = fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let alive = |pid: u32| {
        fs::read_to_string(format!("/proc/{pid}/stat"))
            .map(|t| !t.contains(") Z"))
            .unwrap_or(false)
    };
    assert!(alive(pid));
    client.kill().unwrap();
    let _ = client.wait();
    wait_until("the command to be ended", 10, || !alive(pid));
}

#[cfg(target_os = "linux")]
#[test]
fn ctrl_c_reaches_the_command_and_its_exit_code_comes_back() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    let mut client = s
        .command(&s.project())
        .args(["run", "--secret", "ZETA", "--", "sh", "-c"])
        .arg("trap 'echo got-int; exit 3' INT; echo ready; while :; do sleep 0.05; done")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = client.stdout.take().unwrap();
    let mut seen = Vec::new();
    wait_until("the command to be ready", 10, || {
        use std::io::Read;
        let mut b = [0u8; 64];
        // Blocking read, but the command prints its first line at once.
        let n = stdout.read(&mut b).unwrap_or(0);
        seen.extend_from_slice(&b[..n]);
        String::from_utf8_lossy(&seen).contains("ready")
    });
    let status = Command::new("kill")
        .args(["-INT", &client.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let mut rest = String::new();
    {
        use std::io::Read;
        let _ = stdout.read_to_string(&mut rest);
    }
    let status = client.wait().unwrap();
    assert_eq!(status.code(), Some(3));
    assert!(rest.contains("got-int"), "{rest:?}");
}

// --- the invariant ------------------------------------------------------------------------

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn nothing_secret_is_in_the_journal_the_daemons_stderr_or_any_clients_output() {
    let s = Sandbox::new();
    // A daemon whose stderr is kept, so it can be searched.
    let stderr_path = s.root.join("daemon.stderr");
    let mut daemon = s
        .command(&s.project())
        .args(["daemon", "run"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(fs::File::create(&stderr_path).unwrap())
        .spawn()
        .unwrap();
    let c = connector(&s, false);
    wait_until("the daemon", 10, || {
        c.connect_running().ok().flatten().is_some()
    });

    let mut seen: Vec<String> = Vec::new();
    let mut run = |args: &[&str]| -> Output {
        let out = s.vahta(args);
        seen.push(text(&out.stdout));
        seen.push(text(&out.stderr));
        out
    };
    let pw = r#"{"secret":"correct horse"}"#;
    s.script(&[pw, r#"{"ack":true}"#]);
    run(&["init"]);
    for (name, value, tier) in [
        ("ZETA", "fake-one", "session"),
        ("BETA", "fake-two", "session"),
        ("ALPHA", "fake-three", "each-use"),
    ] {
        s.script(&[pw, &format!(r#"{{"secret":"{value}"}}"#)]);
        assert_eq!(run(&["add", name, "--tier", tier]).status.code(), Some(0));
    }
    // A wrong password, a cancel, and a refusal.
    s.script(&[r#"{"secret":"wrong"}"#, pw, r#"{"secret":"fake-new"}"#]);
    run(&["reset", "ZETA"]);
    s.script(&[r#"{"cancel":true}"#]);
    run(&["reset", "ZETA"]);
    run(&["unlock", "--secret", "ALPHA", "--json"]);
    // A session, runs that print the values on both streams, a reveal, a run
    // with the password, a delegation, a failure, the list and a lock.
    s.script(&[pw]);
    run(&["unlock", "--json"]);
    run(&[
        "run",
        "--secret",
        "ZETA",
        "--secret",
        "BETA",
        "--",
        "sh",
        "-c",
        "echo $ZETA $BETA; echo $ZETA $BETA >&2; printenv",
    ]);
    s.script(&[pw]);
    run(&[
        "run",
        "--secret",
        "ALPHA",
        "--",
        "sh",
        "-c",
        "echo $ALPHA >&2; echo $ALPHA",
    ]);
    s.script(&[pw, r#"{"ack":true}"#]);
    run(&["reveal", "ZETA"]);
    run(&[
        "delegate",
        "--secret",
        "ZETA",
        "--",
        VAHTA,
        "run",
        "--secret",
        "ZETA",
        "--",
        "sh",
        "-c",
        "echo $ZETA",
    ]);
    run(&[
        "delegate", "--secret", "ZETA", "--", VAHTA, "run", "--secret", "BETA", "--", "true",
    ]);
    run(&["run", "--secret", "ZETA", "--", "sh", "-c", "exit 4"]);
    run(&["sessions", "--json"]);
    run(&["daemon", "status", "--json"]);
    run(&["lock"]);
    run(&["list", "--json"]);
    run(&["check", "--json"]);

    // Everything the person typed or was shown, in the window's own channel.
    let window = fs::read_to_string(s.root.join("surface.log")).unwrap();
    assert!(window.contains("fake-new"), "the window was shown a value");
    let key = s
        .window_log()
        .iter()
        .find(|e| e["ask"] == "recovery")
        .map(|e| e["shown"].as_str().unwrap().to_string())
        .unwrap();

    let _ = daemon.kill();
    let _ = daemon.wait();
    let journal = s.journal();
    let daemon_stderr = fs::read_to_string(&stderr_path).unwrap_or_default();
    assert!(
        journal.lines().count() > 20,
        "the journal should have recorded all of this"
    );
    let mut everywhere = vec![
        ("the journal".to_string(), journal),
        ("the daemon's stderr".to_string(), daemon_stderr),
    ];
    for (i, text) in seen.iter().enumerate() {
        everywhere.push((format!("client output {i}"), text.clone()));
    }
    for secret in [
        "fake-one",
        "fake-two",
        "fake-three",
        "fake-new",
        "correct horse",
        "wrong",
        key.as_str(),
    ] {
        for (place, content) in &everywhere {
            assert!(!content.contains(secret), "{place} holds {secret:?}");
        }
    }
    // The scrubbed values did come back, as markers.
    assert!(seen.iter().any(|t| t.contains("***REDACTED(ZETA)***")));
    assert!(seen.iter().any(|t| t.contains("***REDACTED(ALPHA)***")));
}

// --- lock on sleep ---------------------------------------------------------------------------

#[test]
fn sessions_end_when_the_machine_sleeps_unless_the_config_says_not_to() {
    let s = sandbox_with_secrets();
    assert_eq!(s.vahta(&["daemon", "stop"]).status.code(), Some(0));
    let trigger = s.root.join("sleep-now");
    let start = |s: &Sandbox| {
        s.script(&[r#"{"secret":"correct horse"}"#]);
        let out = s
            .command(&s.project())
            .env("VAHTA_TEST_SLEEP_TRIGGER", &trigger)
            .args(["unlock"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    };
    // On by default: the machine sleeps, the session ends, the journal says why.
    start(&s);
    assert_eq!(s.sessions().len(), 1);
    fs::write(&trigger, "").unwrap();
    wait_until("the session to end on sleep", 10, || {
        s.sessions().is_empty()
    });
    let journal = s.journal();
    assert!(journal.contains("\"reason\":\"sleep\"") && journal.contains("sleep_lock"));

    // lock_on_sleep = false in config.toml: the same event ends nothing.
    assert_eq!(s.vahta(&["daemon", "stop"]).status.code(), Some(0));
    fs::write(s.root.join("config/config.toml"), "lock_on_sleep = false\n").unwrap();
    start(&s);
    fs::write(&trigger, "").unwrap();
    std::thread::sleep(Duration::from_millis(800));
    assert_eq!(s.sessions().len(), 1);
    assert!(s.journal().contains("disabled"));
    // A misspelt key is an error, not a silent default.
    assert_eq!(s.vahta(&["daemon", "stop"]).status.code(), Some(0));
    fs::write(s.root.join("config/config.toml"), "lock_on_slepe = false\n").unwrap();
    let out = s.vahta(&["daemon", "restart"]);
    assert_eq!(out.status.code(), Some(5));
}

// --- the hook and a tool's output ----------------------------------------------------

/// The real `vahta-hook`, built once per test run next to `vahta`. It is
/// another package's binary, so cargo does not hand it to this test; building
/// it here (a no-op when it is fresh) means the test never runs a stale one.
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

impl Sandbox {
    /// Feed the hook a Claude PostToolUse event whose Bash output is `stdout`,
    /// as Claude would, from this test process (so the hook's anchor is the
    /// anchor `vahta unlock` and `vahta run` get from here). Returns its reply.
    fn hook_after_bash(&self, stdout: &str) -> Option<Value> {
        self.hook_after_bash_in(stdout, &self.project())
    }

    /// As `hook_after_bash`, with the agent's working directory the harness
    /// reports.
    fn hook_after_bash_in(&self, stdout: &str, cwd: &Path) -> Option<Value> {
        let payload = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "cat notes.txt"},
            "tool_response": {"stdout": stdout, "stderr": ""},
            "cwd": cwd,
        });
        let mut child = Command::new(hook_bin())
            .args(["--harness", "claude", "--event", "after_tool"])
            .current_dir(self.project())
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
        let text = text(&out.stdout);
        (!text.trim().is_empty()).then(|| serde_json::from_str(&text).unwrap())
    }
}

/// The rewritten Bash stdout and the message for the model, from a reply.
fn redacted(reply: &Value) -> (String, String) {
    let hso = &reply["hookSpecificOutput"];
    (
        hso["updatedToolOutput"]["stdout"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        hso["additionalContext"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
}

/// The `vahta output allow <ref>` reference in a message for the model.
fn reference_in(message: &str) -> String {
    let after = message
        .split("vahta output allow ")
        .nth(1)
        .expect("a reference in the message");
    after.split_whitespace().next().unwrap().to_string()
}

#[test]
fn the_hook_cuts_a_session_value_by_name_and_keeps_the_original() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "printenv", "ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));

    // The value, as a later tool (a file read, say) would show it. Plain text:
    // the detector sees nothing here, so a cut can only be the daemon's.
    let reply = s
        .hook_after_bash("the notes say fake-one and more")
        .expect("the hook answered");
    let (stdout, message) = redacted(&reply);
    assert_eq!(stdout, "the notes say ***REDACTED(ZETA)*** and more");
    assert!(message.contains("vahta output allow "), "{message}");
    // There is a reference, so the person is not bothered.
    assert!(reply.get("systemMessage").is_none(), "{reply}");
    assert!(!reply.to_string().contains("fake-one"));

    // Clean output gets no answer at all.
    assert!(s.hook_after_bash("nothing to see").is_none());

    // The journal names what was cut and keeps no value.
    let journal = s.journal();
    assert!(journal.contains("output_redacted") && journal.contains("ZETA"));
    assert!(journal.contains(&reference_in(&message)));
    assert!(!journal.contains("fake-one"));
}

#[test]
fn the_hook_cuts_the_values_of_a_run_that_had_no_session() {
    let s = sandbox_with_secrets();
    // Each-use: a run with the password, no session anywhere.
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&["run", "--secret", "ALPHA", "--", "printenv", "ALPHA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(s.sessions().is_empty());
    let reply = s.hook_after_bash("x fake-three y").unwrap();
    assert_eq!(redacted(&reply).0, "x ***REDACTED(ALPHA)*** y");
}

#[test]
fn without_a_daemon_the_hook_cuts_what_the_detector_finds_and_says_so() {
    let s = Sandbox::new();
    let key = ["sk-", "ant-", &"a".repeat(25)].concat();
    let reply = s.hook_after_bash(&format!("found {key}")).unwrap();
    let (stdout, message) = redacted(&reply);
    assert_eq!(stdout, "found ***REDACTED(Anthropic-style key)***");
    assert!(message.contains("not kept"), "{message}");
    assert!(
        reply["systemMessage"]
            .as_str()
            .unwrap()
            .contains("redacted")
    );
    // And no daemon was started for it.
    assert_eq!(s.vahta(&["daemon", "status"]).status.code(), Some(5));
}

/// The person is asked with a choice: show, no, or save. Inside a session of
/// this agent there is no password; "show" prints the output, and the hook
/// lets those values through from then on.
#[test]
fn output_allow_inside_a_session_is_a_choice_and_releases_the_values() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    let original = "line one\nthe notes say fake-one and fake-two\nend";
    let reply = s.hook_after_bash(original).unwrap();
    let (cut, message) = redacted(&reply);
    assert_eq!(
        cut,
        "line one\nthe notes say ***REDACTED(ZETA)*** and ***REDACTED(BETA)***\nend"
    );
    let reference = reference_in(&message);

    let asks = s.asks();
    s.script(&[r#"{"choose":0}"#]);
    let out = s.vahta(&[
        "output",
        "allow",
        &reference,
        "--reason",
        "need to compare\nApprove: yes",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    // The output as the tool gave it (its strings, joined).
    assert_eq!(text(&out.stdout), format!("{original}\n"));
    // One question, a choice, and no password.
    let log = s.window_log();
    let new: Vec<&Value> = log
        .iter()
        .filter(|e| e.get("ask").is_some())
        .skip(asks)
        .collect();
    assert_eq!(new.len(), 1, "{new:?}");
    assert_eq!(new[0]["ask"], "choose");
    assert_eq!(new[0]["options"][0], "Show to the agent");
    assert_eq!(new[0]["options"][2], "Save as a secret");
    // The window names what was cut, masked, and the agent's reason as such;
    // never a value.
    let panel = new[0]["panel"].to_string();
    assert!(panel.contains("ZETA") && panel.contains("BETA") && panel.contains("Bash"));
    assert!(panel.contains("the notes say *** and ***"), "{panel}");
    assert!(!panel.contains("fake-one") && !panel.contains("fake-two"));
    assert_eq!(
        new[0]["panel"]["agent_note"],
        "need to compare Approve: yes"
    );

    // The released values pass the next hook untouched: the agent's printout
    // of the output is not cut again.
    assert!(s.hook_after_bash(original).is_none());
    // Another value still is.
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&["run", "--secret", "ALPHA", "--", "true"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let again = s.hook_after_bash("x fake-three fake-one").unwrap();
    assert_eq!(redacted(&again).0, "x ***REDACTED(ALPHA)*** fake-one");

    let journal = s.journal();
    assert!(journal.contains("output_allow") && journal.contains("\"result\":\"shown\""));
    for leak in ["fake-one", "fake-two", "fake-three"] {
        assert!(!journal.contains(leak), "the journal holds {leak}");
    }
}

#[test]
fn output_allow_without_a_session_asks_for_the_password() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&["run", "--secret", "ALPHA", "--", "true"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let reply = s.hook_after_bash("value fake-three").unwrap();
    let reference = reference_in(&redacted(&reply).1);

    // A wrong password does not release it.
    s.script(&[
        r#"{"choose":0}"#,
        r#"{"secret":"no"}"#,
        r#"{"secret":"nope"}"#,
        r#"{"secret":"nein"}"#,
    ]);
    let out = s.vahta(&["output", "allow", &reference]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!text(&out.stdout).contains("fake-three"));
    assert!(s.hook_after_bash("value fake-three").is_some());

    s.script(&[r#"{"choose":0}"#, r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&["output", "allow", &reference]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "value fake-three\n");
    let last_asks: Vec<String> = s
        .window_log()
        .iter()
        .filter_map(|e| e["ask"].as_str().map(str::to_string))
        .collect();
    assert_eq!(
        last_asks[last_asks.len() - 2..],
        ["choose".to_string(), "password".to_string()]
    );
}

#[test]
fn output_allow_can_save_a_value_as_a_secret_and_the_output_stays_cut() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    let key = ["sk-", "ant-", &"b".repeat(25)].concat();
    let output = format!("config has {key} and fake-one");
    let reply = s.hook_after_bash(&output).unwrap();
    let reference = reference_in(&redacted(&reply).1);

    // Two values: which one, a name (a taken one first), a tier, the password.
    s.script(&[
        r#"{"choose":2}"#,
        r#"{"choose":0}"#,
        r#"{"text":"ZETA"}"#,
        r#"{"text":"VENDOR_KEY"}"#,
        r#"{"choose":1}"#,
        r#"{"secret":"correct horse"}"#,
    ]);
    let out = s.vahta(&["output", "allow", &reference]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let said = text(&out.stdout);
    assert!(said.contains("saved as VENDOR_KEY") && said.contains("vahta run --secret VENDOR_KEY"));
    assert!(!said.contains(&key) && !said.contains("fake-one"));
    let listed = text(&s.vahta(&["list"]).stdout);
    assert!(listed.contains("VENDOR_KEY"), "{listed}");
    let vault = s.open_vault();
    assert_eq!(vault.get("VENDOR_KEY").unwrap().expose(), key.as_bytes());
    let tier = vault
        .entries()
        .iter()
        .find(|e| e.name == "VENDOR_KEY")
        .unwrap()
        .tier;
    assert_eq!(tier, Tier::EachUse);
    // The taken name was refused in the window, with a reason.
    assert!(s.window_log().iter().any(|e| {
        e["panel"]["warning"]
            .as_str()
            .is_some_and(|w| w.contains("already has ZETA"))
    }));
    // Saving lets nothing through.
    assert!(s.hook_after_bash(&output).is_some());
    assert!(!s.journal().contains(&key));
}

/// Claude Code reports the agent's working directory, not the one a command
/// `cd`-ed into. With a session open, the session's vault is the one to save
/// into, even when that directory has no vault.
#[test]
fn output_allow_offers_saving_into_the_sessions_vault_from_a_directory_without_one() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    let elsewhere = s.root.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    let reply = s.hook_after_bash_in("a fake-one b", &elsewhere).unwrap();
    let reference = reference_in(&redacted(&reply).1);

    let asks = s.asks();
    s.script(&[r#"{"choose":1}"#]);
    let out = s.vahta(&["output", "allow", &reference]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
    let log = s.window_log();
    let ask = log
        .iter()
        .filter(|e| e.get("ask").is_some())
        .nth(asks)
        .unwrap();
    assert_eq!(ask["options"][2], "Save as a secret", "{ask}");
    // Compared as lines, not as JSON, where a Windows path's backslashes are
    // escaped.
    let vault_line = format!("Vault: {}", s.vault_path().display());
    assert!(
        ask["panel"]["lines"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l.as_str() == Some(vault_line.as_str())),
        "{}",
        ask["panel"]
    );
}

#[test]
fn output_allow_cancelled_unknown_or_another_agents_is_refused() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    let reply = s.hook_after_bash("a fake-one b").unwrap();
    let reference = reference_in(&redacted(&reply).1);

    // The person says no, or closes the window: exit 4, nothing printed.
    for answer in [r#"{"choose":1}"#, r#"{"cancel":true}"#] {
        s.script(&[answer]);
        let out = s.vahta(&["output", "allow", &reference]);
        assert_eq!(out.status.code(), Some(4), "{answer}");
        assert!(!text(&out.stdout).contains("fake-one"));
    }
    assert!(s.hook_after_bash("a fake-one b").is_some());

    // A reference nobody made: refused before any window.
    let asks = s.asks();
    let out = s.vahta(&["output", "allow", "0123456789ab", "--json"]);
    assert_eq!(out.status.code(), Some(3));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["refused"]["kind"], "unknown_output");

    // Another agent: the same command under another anchor (xargs, which is
    // neither a shell nor a wrapper, stands in for a second agent).
    #[cfg(unix)]
    {
        let mut xargs = Command::new("xargs");
        xargs
            .args(["-I{}", env!("CARGO_BIN_EXE_vahta"), "output", "allow", "{}"])
            .current_dir(s.project())
            .env("HOME", s.root.join("home"))
            .env_remove("XDG_RUNTIME_DIR")
            .env("VAHTA_DATA_DIR", s.root.join("data"))
            .env("VAHTA_RUNTIME_DIR", s.root.join("run"))
            .env("VAHTA_CONFIG_DIR", s.root.join("config"))
            .env("VAHTA_TEST_SURFACE", s.root.join("script.jsonl"))
            .env("VAHTA_TEST_SURFACE_LOG", s.root.join("surface.log"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut running = xargs.spawn().expect("run xargs");
        running
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{reference}\n").as_bytes())
            .unwrap();
        let out = running.wait_with_output().unwrap();
        assert!(
            text(&out.stderr).contains("refused"),
            "{}",
            text(&out.stderr)
        );
        assert!(!text(&out.stdout).contains("fake-one"));
    }
    assert_eq!(s.asks(), asks, "a window opened for a refusal");

    // Usage.
    assert_eq!(s.vahta(&["output"]).status.code(), Some(2));
    assert_eq!(s.vahta(&["output", "allow"]).status.code(), Some(2));
    assert_eq!(s.vahta(&["output", "show", "x"]).status.code(), Some(2));
}

/// `hook_output = "observe"`: nothing is rewritten. The person and the model
/// are told, as before redaction, and the daemon journals what was seen.
#[test]
fn observe_mode_changes_nothing_and_the_daemon_journals_it() {
    let s = sandbox_with_secrets();
    fs::write(
        s.root.join("config/config.toml"),
        "hook_output = \"observe\"\n",
    )
    .unwrap();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    let key = ["sk-", "ant-", &"c".repeat(25)].concat();
    let reply = s.hook_after_bash(&format!("found {key}")).unwrap();
    let hso = &reply["hookSpecificOutput"];
    assert!(hso.get("updatedToolOutput").is_none(), "{reply}");
    assert!(
        hso["additionalContext"]
            .as_str()
            .unwrap()
            .contains("reached the transcript")
    );
    assert!(
        reply["systemMessage"]
            .as_str()
            .unwrap()
            .contains("rotate it")
    );
    let journal = s.journal();
    assert!(journal.contains("output_observed") && journal.contains("Anthropic-style key"));
    assert!(!journal.contains("output_redacted"));
    assert!(!journal.contains(&key));
}

/// Through every path of output redaction (cut, refused, declined, saved,
/// shown), no value reaches the journal, the window, or any stdout or stderr
/// except the one printout the person agreed to.
#[test]
fn no_value_leaks_through_output_redaction() {
    let s = sandbox_with_secrets();
    let key = ["sk-", "ant-", &"d".repeat(25)].concat();
    let values = ["fake-one", "fake-two", "fake-three", key.as_str()];
    let mut seen: Vec<String> = Vec::new();
    let vahta = |seen: &mut Vec<String>, args: &[&str]| {
        let out = s.vahta(args);
        seen.push(text(&out.stdout));
        seen.push(text(&out.stderr));
        out
    };
    s.script(&[r#"{"secret":"correct horse"}"#]);
    vahta(&mut seen, &["unlock"]);
    s.script(&[r#"{"secret":"correct horse"}"#]);
    vahta(
        &mut seen,
        &["run", "--secret", "ALPHA", "--", "printenv", "ALPHA"],
    );
    let output = format!("fake-one {key} fake-three");
    let reply = s.hook_after_bash(&output).unwrap();
    seen.push(reply.to_string());
    let reference = reference_in(&redacted(&reply).1);
    vahta(&mut seen, &["output", "allow", "000000000000"]);
    s.script(&[r#"{"choose":1}"#]);
    vahta(&mut seen, &["output", "allow", &reference]);
    s.script(&[
        r#"{"choose":2}"#,
        r#"{"choose":1}"#,
        r#"{"text":"SAVED_KEY"}"#,
        r#"{"choose":0}"#,
        r#"{"secret":"correct horse"}"#,
    ]);
    vahta(&mut seen, &["output", "allow", &reference, "--json"]);
    // The one release: its stdout is the output, by the person's choice; its
    // stderr is still checked.
    s.script(&[r#"{"choose":0}"#]);
    let shown = s.vahta(&["output", "allow", &reference]);
    assert_eq!(text(&shown.stdout), format!("{output}\n"));
    seen.push(text(&shown.stderr));

    let window = fs::read_to_string(s.root.join("surface.log")).unwrap();
    for v in values {
        for (i, t) in seen.iter().enumerate() {
            assert!(!t.contains(v), "output {i} holds a value: {t}");
        }
        assert!(!s.journal().contains(v), "the journal holds a value");
        assert!(!window.contains(v), "the window was shown a value");
    }
}
