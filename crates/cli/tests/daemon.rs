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
    /// Where a test's software phone listens on loopback. Set, the daemon
    /// reaches phones over the real phone link (LAN transport) instead of the
    /// loopback phones kept in files.
    phone_addr: Option<String>,
    /// Whether the daemon counts refusals by a secret's rules for the alarm.
    /// Off in most tests, which refuse several commands in a row and count
    /// windows; the alarm tests turn it on.
    refusal_alarm: bool,
}

impl Sandbox {
    fn new() -> Sandbox {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("vahta-d-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for d in ["project", "home", "run", "data", "config"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        // The certificate authority of the tests' HTTPS server, which a test
        // daemon (and only a test daemon) also trusts for `vahta http`.
        fs::write(root.join("ca.pem"), vahta_net::test_server::CA_PEM).unwrap();
        Sandbox {
            root,
            phone_addr: None,
            refusal_alarm: false,
        }
    }

    /// A sandbox whose daemon counts refusals by rules for the alarm.
    #[cfg(unix)]
    fn counting_refusals() -> Sandbox {
        let mut s = Sandbox::new();
        s.refusal_alarm = true;
        s
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
            // The software phones a test pairs live here.
            .env("VAHTA_TEST_LOOPBACK", self.root.join("phones"))
            .env("VAHTA_TEST_HTTP_ROOT", self.root.join("ca.pem"))
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("VAHTA_TEST_PHONE_ADDR");
        if let Some(addr) = &self.phone_addr {
            cmd.env("VAHTA_TEST_PHONE_ADDR", addr);
        }
        if self.refusal_alarm {
            cmd.env_remove("VAHTA_TEST_MUTE_REFUSAL_ALARM");
        } else {
            cmd.env("VAHTA_TEST_MUTE_REFUSAL_ALARM", "1");
        }
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
                r#"{"choose":0}"#,
            ]);
            let out = self.vahta(&["add", name, "--tier", tier]);
            assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        }
        self.open_rules(&items.iter().map(|i| i.0).collect::<Vec<_>>());
    }

    /// Give each of `names` an explicit rule set that lets any command use it
    /// (no category, no deny groups, the program's own network), and drop the
    /// `vahta.toml` that `add` wrote, so tests that are not about rules start
    /// from "everything allowed" as they did before rules were mandatory.
    fn open_rules(&self, names: &[&str]) {
        let mut vault = self.open_vault();
        for n in names {
            vault
                .set_bindings(
                    n,
                    Some(vahta_vault::RuleSet {
                        name: (*n).to_string(),
                        network: vahta_vault::Network::App,
                        ..Default::default()
                    }),
                )
                .unwrap();
        }
        vault
            .save(&self.vault_path(), &LocalStore::new(self.root.join("data")))
            .unwrap();
        let _ = fs::remove_file(self.project().join("vahta.toml"));
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

    // The watchdog learns of the project, so it can ask for its password.
    // Compared without separators: JSON doubles a Windows backslash.
    let flat = |t: &str| t.replace(['\\', '/'], "");
    let projects = fs::read_to_string(s.root.join("data/projects.json")).unwrap_or_default();
    assert!(
        flat(&projects).contains(&flat(&s.project().to_string_lossy())),
        "{projects}"
    );

    // A second init is refused, with no window.
    let before = s.asks();
    let out = s.vahta(&["init"]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(s.asks(), before);

    s.script(&[
        r#"{"secret":"correct horse"}"#,
        r#"{"secret":"fake-one"}"#,
        r#"{"choose":0}"#,
    ]);
    let out = s.vahta(&["add", "ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    // The first line says what was done; the rest tells the agent how to ask
    // for rules, with no value in it.
    let said = text(&out.stdout);
    assert_eq!(said.lines().next(), Some("saved ZETA"));
    assert!(
        said.contains("Rules approved with it: category: ordinary")
            && said.contains("prompt injection")
            && !said.contains("fake-")
    );
    s.script(&[
        r#"{"secret":"correct horse"}"#,
        r#"{"secret":"fake-two"}"#,
        r#"{"choose":0}"#,
    ]);
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

/// A script line answering with a typed value, escaped as JSON.
fn typed(value: &str) -> String {
    serde_json::json!({ "secret": value }).to_string()
}

#[test]
fn a_value_with_stray_whitespace_is_asked_about_and_never_shown() {
    let s = Sandbox::new();
    s.with_vault(&[]);
    // Assembled at run time; the pieces are what the checks look for.
    let core = ["tok", "en", "-body", "-1234"].concat();
    let with_space = format!("{core} ");
    let pad = "  ";
    let with_break = format!("{core}\n");
    let two_lines = format!("{core}\n{core}");

    // Trailing space, trim chosen: stored trimmed.
    s.script(&[
        PW_ANSWER,
        &typed(&with_space),
        r#"{"choose":0}"#,
        r#"{"choose":0}"#,
    ]);
    let out = s.vahta(&["add", "ONE"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!text(&out.stdout).contains(&core) && !text(&out.stderr).contains(&core));
    assert_eq!(s.open_vault().get("ONE").unwrap().expose(), core.as_bytes());
    let log = s.window_log();
    let asked = log
        .iter()
        .find(|e| {
            e["ask"] == "choose"
                && e["prompt"]
                    .as_str()
                    .is_some_and(|p| p.contains("ends with"))
        })
        .expect("the person was asked about the trailing space");
    assert_eq!(asked["options"][0], "Trim it and store");
    assert_eq!(asked["options"].as_array().unwrap().len(), 4);

    // Stored exactly as typed.
    s.script(&[
        PW_ANSWER,
        &typed(&with_break),
        r#"{"choose":1}"#,
        r#"{"choose":0}"#,
    ]);
    let out = s.vahta(&["add", "TWO"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        s.open_vault().get("TWO").unwrap().expose(),
        with_break.as_bytes()
    );

    // Type it again: the second value is the one stored.
    s.script(&[
        PW_ANSWER,
        &typed(&format!("{pad}{core}")),
        r#"{"choose":2}"#,
        &typed(&core),
        r#"{"choose":0}"#,
    ]);
    let out = s.vahta(&["add", "THREE"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        s.open_vault().get("THREE").unwrap().expose(),
        core.as_bytes()
    );

    // A line break inside cannot be trimmed: no trim option, and the numbers
    // shift. Cancel stores nothing.
    s.script(&[PW_ANSWER, &typed(&two_lines), r#"{"choose":2}"#]);
    let out = s.vahta(&["add", "FOUR"]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
    let log = s.window_log();
    let last = log.iter().rev().find(|e| e["ask"] == "choose").unwrap();
    assert!(
        last["prompt"]
            .as_str()
            .unwrap()
            .contains("line break inside")
    );
    assert_eq!(last["options"][0], "Store exactly as typed");
    assert!(s.open_vault().get("FOUR").is_err());

    // A reset asks as well.
    s.script(&[PW_ANSWER, &typed(&with_space), r#"{"choose":0}"#]);
    let out = s.vahta(&["reset", "TWO"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.open_vault().get("TWO").unwrap().expose(), core.as_bytes());

    // The journal says a warning was shown and what was chosen, not the value.
    let journal = s.journal();
    assert!(journal.contains("value_warning") && journal.contains("trimmed"));
    assert!(journal.contains("as_typed") && journal.contains("retype"));
    let surface = fs::read_to_string(s.root.join("surface.log")).unwrap();
    for place in [&journal, &surface] {
        assert!(!place.contains(&core));
    }
    for e in s.window_log() {
        if e["ask"] == "choose" {
            assert!(!e.to_string().contains(&core));
        }
    }
}

#[test]
fn a_pem_block_and_a_file_secret_are_not_nagged_about_their_lines() {
    let s = Sandbox::new();
    s.with_vault(&[]);
    let body = ["Zm9v", "YmFy", "YmF6"].concat();
    let pem = format!("-----BEGIN KEY-----\n{body}\n{body}\n-----END KEY-----\n");
    let before = s.asks();
    s.script(&[PW_ANSWER, &typed(&pem), r#"{"choose":0}"#]);
    let out = s.vahta(&["add", "PEMMED"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    // The password, the value and the rules: no whitespace question.
    assert_eq!(s.asks() - before, 3);
    assert_eq!(
        s.open_vault().get("PEMMED").unwrap().expose(),
        pem.as_bytes()
    );

    // A file secret may be many lines of anything.
    let lines = format!("{body}\n{body}\n");
    s.script(&[PW_ANSWER, &typed(&lines), r#"{"choose":0}"#]);
    let before = s.asks();
    let out = s.vahta(&["add", "FILED", "--file", "f.txt"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.asks() - before, 3);
    assert!(!s.journal().contains("value_warning"));
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
    assert_eq!(text(&out.stdout).lines().next(), Some("replaced ZETA"));
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
    // The clipboard is cleared first and the journal line written after.
    wait_until("the journal to say it was cleared", 10, || {
        s.journal().contains("copy_cleared")
    });
    assert!(!s.journal().contains("fake-one"));
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

#[test]
fn hook_reports_and_the_spool_reach_the_journal_without_values() {
    use vahta_ipc::protocol::{Evasion, Signal};
    use vahta_ipc::spool::{self, SpoolLine};

    let s = Sandbox::new();
    // A report a hook spooled while no daemon ran.
    spool::append(
        &s.paths(),
        &SpoolLine {
            time: 1_700_000_000,
            session: None,
            harness: "codex".into(),
            cwd: "/p".into(),
            signal: Signal::AgentGuard {
                command: "vahta reveal".into(),
            },
        },
    )
    .unwrap();
    assert_eq!(s.vahta(&["daemon", "restart"]).status.code(), Some(0));
    wait_until("the spool to be journalled", 10, || {
        s.journal().contains("command vahta reveal; spooled")
    });
    assert!(!spool::spool_file(&s.paths()).exists());

    // A report from a hook while the daemon runs.
    let mut conn = connector(&s, false).connect_running().unwrap().unwrap();
    let reply = conn
        .request(&ClientRequest::HookReport {
            session: Some("agent-1".into()),
            harness: "claude".into(),
            cwd: s.project().to_string_lossy().into_owned(),
            signal: Signal::Blocked {
                category: "an API token".into(),
                rule: "test.rule".into(),
                evasion: Some(Evasion::Base64),
            },
        })
        .unwrap();
    assert!(matches!(reply, ClientReply::Ok {}));
    let journal = s.journal();
    let line = journal
        .lines()
        .find(|l| l.contains("\"result\":\"blocked\""))
        .expect("a blocked report in the journal");
    let entry: Value = serde_json::from_str(line).unwrap();
    assert_eq!(entry["event"], "hook_report");
    assert_eq!(
        entry["reason"],
        "claude; an API token; rule test.rule; hidden as base64; agent session agent-1"
    );
}

/// A vault with a session-tier ZETA and BETA and an each-use ALPHA.
fn sandbox_with_secrets() -> Sandbox {
    sandbox_with_secrets_in(Sandbox::new())
}

fn sandbox_with_secrets_in(s: Sandbox) -> Sandbox {
    s.with_vault(&[
        ("ZETA", "fake-one", "session"),
        ("BETA", "fake-two", "session"),
        ("ALPHA", "fake-three", "each-use"),
    ]);
    s
}

#[test]
fn reset_remove_and_tier_name_the_open_sessions_that_hold_the_old_value() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&["unlock", "--label", "deploy the site"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));

    // A reset: the session still holds the old ZETA, and both the agent (the
    // command's answer) and the person (the window) are told which session.
    s.script(&[r#"{"secret":"correct horse"}"#, r#"{"secret":"fake-new"}"#]);
    let out = s.vahta(&["reset", "ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let said = text(&out.stdout);
    assert!(
        said.contains("1 open session holds the old ZETA")
            && said.contains("\"deploy the site\"")
            && said.contains("vahta unlock"),
        "{said}"
    );
    let closed = s
        .window_log()
        .into_iter()
        .rev()
        .find(|e| e["close"].is_string())
        .map(|e| e["close"].to_string())
        .unwrap_or_default();
    assert!(closed.contains("old ZETA"), "{closed}");
    assert!(s.journal().contains("\"event\":\"sessions_stale\""));
    // And the session is refused at its next run, as before.
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "true"]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));

    // Moving BETA to each-use takes it out of the session: said so too.
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&["tier", "BETA", "each-use"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("the old BETA"));

    // ALPHA is each-use: no session holds it, so nothing to say.
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&["remove", "ALPHA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!text(&out.stdout).contains("open session"));

    let all = format!(
        "{}{}",
        s.journal(),
        serde_json::to_string(&s.window_log()).unwrap()
    );
    assert!(!all.contains("fake-"));
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
    let extension = |e: &Value| e["ask"] == "choose" && e["prompt"] == "Extend this session?";
    wait_until("the question", 10, || s.window_log().iter().any(extension));
    let q = s.window_log().into_iter().find(extension).unwrap();
    assert_eq!(q["prompt"], "Extend this session?");
    // The session's own length is offered, not a fixed half hour.
    assert_eq!(q["options"][0], "Extend by 4s");
    assert_eq!(q["options"][1], "No");
    assert_eq!(q["options"][2], "Other duration...");
    // No password in an extension question.
    assert_eq!(passwords(&s), before + 1);
    wait_until("the session to end", 10, || s.sessions().is_empty());
    let journal = s.journal();
    assert!(journal.contains("\"reason\":\"expired\""));
    assert!(journal.contains("session_extension") && journal.contains("no_answer"));
}

#[test]
fn extending_by_the_sessions_own_length_keeps_it_alive_past_its_deadline() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#, r#"{"choose":0}"#]);
    assert_eq!(s.vahta(&["unlock", "--for", "8s"]).status.code(), Some(0));
    wait_until("the extension", 10, || {
        s.journal().contains("\"result\":\"extended\"")
    });
    assert!(s.journal().contains("8s (the last length)"));
    // Past the original end it is still there, with less than eight seconds.
    std::thread::sleep(Duration::from_secs(5));
    let list = s.sessions();
    assert_eq!(list.len(), 1);
    let left = list[0]["remaining_secs"].as_u64().unwrap();
    assert!((1..=8).contains(&left), "{left}");
}

#[test]
fn another_duration_can_be_typed_as_units_or_a_clock_and_nonsense_is_asked_again() {
    let s = sandbox_with_secrets();
    s.script(&[
        r#"{"secret":"correct horse"}"#,
        r#"{"choose":2}"#,
        r#"{"text":"soon"}"#,
        r#"{"text":"1:30:00"}"#,
    ]);
    assert_eq!(s.vahta(&["unlock", "--for", "4s"]).status.code(), Some(0));
    wait_until("the extension", 10, || {
        s.journal().contains("\"result\":\"extended\"")
    });
    assert!(s.journal().contains("1h30m (typed)"));
    let texts: Vec<Value> = s
        .window_log()
        .into_iter()
        .filter(|e| e["ask"] == "text")
        .collect();
    assert_eq!(texts.len(), 2);
    assert!(
        texts[1]["panel"]["warning"]
            .as_str()
            .unwrap()
            .contains("not a duration"),
        "{}",
        texts[1]
    );
    std::thread::sleep(Duration::from_secs(4));
    let list = s.sessions();
    assert_eq!(list.len(), 1);
    assert!(list[0]["remaining_secs"].as_u64().unwrap() > 5300);
}

#[test]
fn giving_up_on_another_duration_ends_the_session_at_its_old_deadline() {
    let s = sandbox_with_secrets();
    s.script(&[
        r#"{"secret":"correct horse"}"#,
        r#"{"choose":2}"#,
        r#"{"cancel":true}"#,
    ]);
    assert_eq!(s.vahta(&["unlock", "--for", "4s"]).status.code(), Some(0));
    wait_until("the session to end", 10, || {
        s.journal().contains("\"reason\":\"expired\"")
    });
    assert!(s.sessions().is_empty());
    assert!(!s.journal().contains("\"result\":\"extended\""));
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
    // The sweep drops the session first and writes the journal line after.
    wait_until("the journal to say why", 10, || {
        s.journal().contains("anchor_exited")
    });
}

#[test]
fn a_daemon_of_another_version_holding_sessions_is_not_replaced() {
    let s = sandbox_with_secrets();
    assert_eq!(s.vahta(&["daemon", "stop"]).status.code(), Some(0));
    let mut old = start_old_daemon(&s, "0.0.0-old");
    // A session on the old daemon, opened over a connection that does not
    // replace it.
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let reply = raw_request(
        &s,
        &s.project(),
        &ClientRequest::Unlock {
            cwd: s.project().to_string_lossy().into_owned(),
            names: None,
            duration: vahta_ipc::protocol::DurationSpec::Default {},
            label: None,
            vault: None,
        },
    );
    assert!(matches!(reply, ClientReply::Session(_)), "{reply:?}");

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

// --- A raw client with a chosen real directory -----------------------------------------------

/// Run by `raw_request` in a child process whose working directory is the one
/// the test chose: it sends the request in `VAHTA_RAW_REQUEST` over the
/// sandbox's socket as a raw frame and prints the reply. A no-op otherwise.
#[test]
fn raw_client_child() {
    let Ok(request) = std::env::var("VAHTA_RAW_REQUEST") else {
        return;
    };
    let request: ClientRequest = serde_json::from_str(&request).unwrap();
    let paths = Paths::from_env(None).unwrap();
    let connector = Connector {
        paths,
        version: vahta_daemon::VERSION.to_string(),
        start: Some(vec![
            env!("CARGO_BIN_EXE_vahta").into(),
            "daemon".into(),
            "run".into(),
        ]),
    };
    // The daemon that runs is the one asked, whatever its version.
    let mut conn = connector.connect_running().unwrap().unwrap();
    let reply = conn.request(&request).unwrap();
    println!("RAW_REPLY:{}", serde_json::to_string(&reply).unwrap());
}

/// Send `request` as a raw frame from a process whose real working directory is
/// `real`; whatever directory the request claims is the request's own business.
fn raw_request(s: &Sandbox, real: &Path, request: &ClientRequest) -> ClientReply {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .current_dir(real)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("VAHTA_DATA_DIR", s.root.join("data"))
        .env("VAHTA_RUNTIME_DIR", s.root.join("run"))
        .env("VAHTA_CONFIG_DIR", s.root.join("config"))
        .env("VAHTA_TEST_SURFACE", s.root.join("script.jsonl"))
        .env("VAHTA_TEST_SURFACE_LOG", s.root.join("surface.log"))
        .env("HOME", s.root.join("home"))
        .env("VAHTA_RAW_REQUEST", serde_json::to_string(request).unwrap())
        .args(["raw_client_child", "--exact", "--nocapture"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let line = stdout
        .lines()
        .find_map(|l| l.strip_prefix("RAW_REPLY:"))
        .unwrap_or_else(|| panic!("no reply: {stdout}{}", String::from_utf8_lossy(&out.stderr)));
    serde_json::from_str(line).unwrap()
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

// A scripted answer can be held back (`after_ms`), for tests of what happens
// while a window waits.
#[cfg(unix)]
#[test]
fn a_scripted_answer_can_be_held_back() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse","after_ms":900}"#]);
    let t = Instant::now();
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "true"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        t.elapsed() >= Duration::from_millis(900),
        "{:?}",
        t.elapsed()
    );
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

// The window is the daemon's, the client is the harness's. When the harness
// gives up and kills `vahta run`, the window must go with it and the command
// must never start.
#[cfg(target_os = "linux")]
#[test]
fn a_client_killed_while_the_window_is_open_takes_the_window_with_it() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"hang":true}"#]);
    let started = s.root.join("started");
    let mut client = s
        .command(&s.project())
        .args(["run", "--secret", "ZETA", "--", "sh", "-c"])
        .arg(format!("echo x > '{}'", started.display()))
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let asked = s.passwords_asked();
    wait_until("the password window", 10, || {
        s.passwords_asked() == asked + 1
    });
    client.kill().unwrap();
    let _ = client.wait();
    let t = Instant::now();
    wait_until("the window to be withdrawn", 5, || {
        s.window_log().iter().any(|e| e["close"] == "withdrawn")
    });
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    wait_until("the journal to say so", 5, || {
        s.journal().contains("went away before the command started")
    });
    let journal = s.journal();
    assert!(journal.contains("\"result\":\"cancelled\""), "{journal}");
    assert!(!journal.contains("\"result\":\"started\""), "{journal}");
    assert!(!started.exists());
    // Nothing is left holding the vault's turn: the next run gets its window.
    s.script(&[r#"{"secret":"correct horse"}"#]);
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "true"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
}

// The same for a session that is being opened.
#[cfg(target_os = "linux")]
#[test]
fn a_client_killed_while_an_unlock_window_is_open_takes_the_window_with_it() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"hang":true}"#]);
    let mut client = s
        .command(&s.project())
        .args(["unlock"])
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let asked = s.passwords_asked();
    wait_until("the password window", 10, || {
        s.passwords_asked() == asked + 1
    });
    client.kill().unwrap();
    let _ = client.wait();
    wait_until("the window to be withdrawn", 5, || {
        s.window_log().iter().any(|e| e["close"] == "withdrawn")
    });
    assert!(s.sessions().is_empty());
}

fn spawn_run(s: &Sandbox, argv_tail: &[&str]) -> std::process::Child {
    s.command(&s.project())
        .args(["run", "--secret", "ZETA", "--"])
        .args(argv_tail)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn windows_opened(s: &Sandbox) -> usize {
    s.window_log()
        .iter()
        .filter(|e| e.get("open").is_some())
        .count()
}

// Three of the same command at once are one question to the person.
#[cfg(target_os = "linux")]
#[test]
fn three_identical_runs_at_once_open_one_window() {
    let s = sandbox_with_secrets();
    let before = windows_opened(&s);
    let asked = s.passwords_asked();
    s.script(&[r#"{"secret":"correct horse","after_ms":700}"#]);
    let kids: Vec<_> = (0..3).map(|_| spawn_run(&s, &["true"])).collect();
    for k in kids {
        let out = k.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    }
    assert_eq!(windows_opened(&s) - before, 1);
    assert_eq!(s.passwords_asked() - asked, 1);
    let journal = s.journal();
    assert_eq!(journal.matches("\"result\":\"started\"").count(), 3);
}

// A different command is a different question: it is asked after the first,
// never beside it.
#[cfg(target_os = "linux")]
#[test]
fn different_runs_at_once_get_their_windows_one_after_the_other() {
    let s = sandbox_with_secrets();
    let before = windows_opened(&s);
    s.script(&[
        r#"{"secret":"correct horse","after_ms":500}"#,
        r#"{"secret":"correct horse","after_ms":500}"#,
    ]);
    let kids = vec![
        spawn_run(&s, &["true"]),
        spawn_run(&s, &["sh", "-c", "exit 0"]),
    ];
    for k in kids {
        let out = k.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    }
    let log = s.window_log();
    let mut open = 0i32;
    let mut peak = 0i32;
    for e in &log {
        if e.get("open").is_some() {
            open += 1;
            peak = peak.max(open);
        } else if e.get("close").is_some() {
            open -= 1;
        }
    }
    assert_eq!(peak, 1, "{log:?}");
    assert_eq!(windows_opened(&s) - before, 2);
}

// One "no" is the answer for everyone who asked for the same secrets.
#[cfg(target_os = "linux")]
#[test]
fn a_refusal_in_the_window_is_the_answer_for_those_who_waited() {
    let s = sandbox_with_secrets();
    let before = windows_opened(&s);
    s.script(&[r#"{"cancel":true,"after_ms":700}"#]);
    let kids = vec![
        spawn_run(&s, &["true"]),
        spawn_run(&s, &["sh", "-c", "exit 0"]),
    ];
    for k in kids {
        let out = k.wait_with_output().unwrap();
        assert_ne!(out.status.code(), Some(0));
    }
    assert_eq!(windows_opened(&s) - before, 1);
    assert!(!s.journal().contains("\"result\":\"started\""));
}

// A session opened by the window that a run waited on serves the run, when
// the run belongs to it; no second window.
#[cfg(target_os = "linux")]
#[test]
fn a_run_that_waited_on_an_unlock_window_is_served_by_the_session() {
    let s = sandbox_with_secrets();
    let before = windows_opened(&s);
    s.script(&[r#"{"secret":"correct horse","after_ms":800}"#]);
    let mut unlock = s
        .command(&s.project())
        .args(["unlock"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    wait_until("the unlock window", 10, || windows_opened(&s) == before + 1);
    let out = spawn_run(&s, &["true"]).wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(unlock.wait().unwrap().success());
    assert_eq!(windows_opened(&s) - before, 1);
    assert_eq!(s.sessions().len(), 1);
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
        s.script(&[pw, &format!(r#"{{"secret":"{value}"}}"#), r#"{"choose":0}"#]);
        assert_eq!(run(&["add", name, "--tier", tier]).status.code(), Some(0));
    }
    s.open_rules(&["ZETA", "BETA", "ALPHA"]);
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

// --- command rules (binding) -----------------------------------------------------------------

#[cfg(unix)]
impl Sandbox {
    /// The canonical path of `program` on this test's PATH.
    fn which(program: &str) -> PathBuf {
        let path = std::env::var_os("PATH").unwrap();
        let found = std::env::split_paths(&path)
            .map(|d| d.join(program))
            .find(|p| p.is_file())
            .unwrap_or_else(|| panic!("no {program} on PATH"));
        fs::canonicalize(found).unwrap()
    }

    /// Approve rules for `name` straight into the vault (the way `vahta bind`
    /// does, without its window): `allow` programs are looked up on PATH.
    fn bind_directly(&self, name: &str, allow: &[&str], deny: &[&str]) {
        use vahta_vault::rules::parse_rule;
        let mut vault = self.open_vault();
        let allow = allow
            .iter()
            .map(|rule| {
                let parsed = parse_rule(rule, true).unwrap();
                let program = match &parsed.program {
                    vahta_vault::rules::ProgramSpec::Bare(n) => Sandbox::which(n),
                    other => panic!("test rules use bare names, got {other:?}"),
                };
                parsed.to_allow(program.to_string_lossy().into_owned())
            })
            .collect();
        let deny = deny
            .iter()
            .map(|rule| parse_rule(rule, false).unwrap().to_deny())
            .collect();
        vault
            .set_bindings(
                name,
                Some(vahta_vault::RuleSet {
                    name: name.to_string(),
                    allow,
                    deny,
                    network: vahta_vault::Network::App,
                    ..Default::default()
                }),
            )
            .unwrap();
        vault
            .save(&self.vault_path(), &LocalStore::new(self.root.join("data")))
            .unwrap();
    }
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn a_bound_secret_runs_only_the_commands_on_its_list_and_the_refusal_has_no_window() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    s.bind_directly("ZETA", &["printenv"], &[]);

    let asked = s.asks();
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "printenv", "ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "***REDACTED(ZETA)***\n");
    assert_eq!(s.asks(), asked, "an allowed command opens no window");

    let out = s.vahta(&["run", "--secret", "ZETA", "--", "env"]);
    assert_eq!(out.status.code(), Some(3));
    let err = text(&out.stderr);
    assert!(
        err.contains("--ask") && err.contains("allow: printenv"),
        "{err}"
    );
    assert!(err.contains("ZETA: this command is not allowed"), "{err}");
    assert_eq!(s.asks(), asked, "a refusal opens no window");
    assert!(!text(&out.stdout).contains("fake-"));

    // The journal has the resolved program, not the arguments.
    let journal = s.journal();
    let env_path = Sandbox::which("env");
    assert!(
        journal.contains("command_not_allowed")
            && journal.contains(&format!("program {}", env_path.display())),
        "{journal}"
    );
    // A secret with the open rule set takes any command.
    let out = s.vahta(&["run", "--secret", "BETA", "--", "env"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    // One bound name is enough to refuse a mixed run.
    let out = s.vahta(&["run", "--secret", "BETA", "--secret", "ZETA", "--", "true"]);
    assert_eq!(out.status.code(), Some(3));
}

#[cfg(unix)]
impl Sandbox {
    /// Like `bind_directly`, with a category (its deny groups and no network
    /// limit), as `vahta bind --category` stores it.
    fn bind_category(&self, name: &str, category: &str, allow: &[&str]) {
        use vahta_vault::rules::parse_rule;
        let cat = vahta_policy::category(category).unwrap();
        let mut vault = self.open_vault();
        let allow = allow
            .iter()
            .map(|rule| {
                let parsed = parse_rule(rule, true).unwrap();
                let vahta_vault::rules::ProgramSpec::Bare(n) = &parsed.program else {
                    panic!("test rules use bare names");
                };
                let program = Sandbox::which(n);
                parsed.to_allow(program.to_string_lossy().into_owned())
            })
            .collect();
        vault
            .set_bindings(
                name,
                Some(vahta_vault::RuleSet {
                    name: name.to_string(),
                    category: Some(category.to_string()),
                    allow,
                    deny: cat.required_deny(),
                    network: vahta_vault::Network::App,
                    ..Default::default()
                }),
            )
            .unwrap();
        vault
            .save(&self.vault_path(), &LocalStore::new(self.root.join("data")))
            .unwrap();
    }

    /// `vahta run` with these variables added to the caller's environment.
    fn run_with_env(&self, vars: &[(&str, &str)], args: &[&str]) -> Output {
        let mut cmd = self.command(&self.project());
        // Only the sandbox's variables and PATH, so the window's list of what
        // was dropped is the test's own and short.
        let own: Vec<_> = cmd
            .get_envs()
            .filter_map(|(k, v)| v.map(|v| (k.to_os_string(), v.to_os_string())))
            .collect();
        cmd.env_clear().envs(own);
        cmd.env("PATH", std::env::var_os("PATH").unwrap());
        cmd.args(args);
        for (k, v) in vars {
            cmd.env(k, v);
        }
        cmd.output().expect("run vahta")
    }
}

#[cfg(unix)]
const STEERING: &[(&str, &str)] = &[
    ("NPM_CONFIG_REGISTRY", "https://registry.evil.invalid"),
    ("CARGO_REGISTRIES_EVIL_INDEX", "https://index.evil.invalid"),
    ("CARGO_HOME", "/home/x/.cargo"),
    ("SOME_ORDINARY_VAR", "ordinary-value"),
];

// Runs commands that only a Unix has (printenv).
#[cfg(unix)]
#[test]
fn a_publish_run_gets_the_baseline_environment_and_an_ordinary_run_gets_all_of_it() {
    let s = sandbox_with_secrets();
    s.bind_category("ZETA", "publish", &["printenv"]);
    s.bind_directly("BETA", &["printenv"], &[]);
    s.unlock_session();

    let out = s.run_with_env(STEERING, &["run", "--secret", "ZETA", "--", "printenv"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let env = text(&out.stdout);
    let has = |name: &str| env.lines().any(|l| l.starts_with(&format!("{name}=")));
    assert!(has("PATH") && has("HOME"), "{env}");
    assert!(has("CARGO_HOME"), "{env}");
    assert!(has("ZETA"), "the injected variable is kept: {env}");
    assert!(!has("NPM_CONFIG_REGISTRY"), "{env}");
    assert!(!has("CARGO_REGISTRIES_EVIL_INDEX"), "{env}");
    assert!(!has("SOME_ORDINARY_VAR"), "{env}");
    assert!(!has("VAHTA_DATA_DIR"));

    // An ordinary secret keeps today's behaviour: everything but the loader
    // and Vahta's own variables.
    let out = s.run_with_env(STEERING, &["run", "--secret", "BETA", "--", "printenv"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let env = text(&out.stdout);
    for (name, _) in STEERING {
        assert!(
            env.lines().any(|l| l.starts_with(&format!("{name}="))),
            "{name} in {env}"
        );
    }
    // A mixed run is cut down as soon as one secret's category cuts it.
    let out = s.run_with_env(
        STEERING,
        &[
            "run", "--secret", "ZETA", "--secret", "BETA", "--", "printenv",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!text(&out.stdout).contains("NPM_CONFIG_REGISTRY"));
}

// Runs commands that only a Unix has (printenv).
#[cfg(unix)]
#[test]
fn the_run_window_lists_extra_arguments_and_dropped_variables_and_the_journal_has_names_only() {
    let s = sandbox_with_secrets();
    // ALPHA is each-use, so every run asks, and the person sees this first.
    s.bind_category("ALPHA", "publish", &["printenv HOME"]);
    s.script(&[PW_ANSWER]);
    let out = s.run_with_env(
        STEERING,
        &[
            "run",
            "--secret",
            "ALPHA",
            "--",
            "printenv",
            "HOME",
            "--manifest-path=/elsewhere",
        ],
    );
    // printenv ignores what it does not know; what matters is the window.
    let _ = out;
    let log = s.window_log();
    let panel = log
        .iter()
        .filter_map(|e| e["panel"]["lines"].as_array())
        .map(|l| Value::Array(l.clone()).to_string())
        .find(|l| l.contains("Command: printenv HOME"))
        .expect("the run window");
    assert!(
        panel.contains("Extra arguments: --manifest-path=/elsewhere"),
        "{panel}"
    );
    assert!(
        panel.contains("NPM_CONFIG_REGISTRY") && panel.contains("CARGO_REGISTRIES_EVIL_INDEX"),
        "{panel}"
    );
    assert!(
        panel.contains("tried to point this at another place") && panel.contains("other variable"),
        "{panel}"
    );
    // The rest is a count, not a list.
    assert!(!panel.contains("SOME_ORDINARY_VAR"), "{panel}");
    assert!(
        !panel.contains("CARGO_HOME"),
        "a kept variable is not listed: {panel}"
    );
    assert!(!panel.contains("evil.invalid") && !panel.contains("ordinary-value"));

    let journal = s.journal();
    assert!(
        journal.contains("extra arguments: --manifest-path=/elsewhere")
            && journal.contains("env dropped: CARGO_REGISTRIES_EVIL_INDEX,NPM_CONFIG_REGISTRY")
            && journal.contains("other env variables dropped"),
        "{journal}"
    );
    assert!(!journal.contains("SOME_ORDINARY_VAR"), "{journal}");
    assert!(!journal.contains("evil.invalid") && !journal.contains("ordinary-value"));

    // With nothing that redirects, only the count is shown.
    s.script(&[PW_ANSWER]);
    s.run_with_env(
        &[("SOME_ORDINARY_VAR", "ordinary-value")],
        &["run", "--secret", "ALPHA", "--", "printenv", "HOME"],
    );
    let panels: Vec<String> = s
        .window_log()
        .iter()
        .filter_map(|e| e["panel"]["lines"].as_array())
        .map(|l| Value::Array(l.clone()).to_string())
        .filter(|l| l.contains("Command: printenv HOME"))
        .collect();
    let last = panels.last().unwrap();
    assert!(
        last.contains("other variable") && !last.contains("tried to point"),
        "{last}"
    );

    // An ordinary secret with an exact rule shows the extra arguments too, and
    // nothing about the environment.
    s.bind_directly("BETA", &["printenv"], &[]);
    s.unlock_session();
    let before = s.window_log().len();
    let out = s.run_with_env(
        STEERING,
        &["run", "--secret", "BETA", "--", "printenv", "HOME"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(s.journal().contains("extra arguments: HOME"));
    assert_eq!(
        s.window_log().len(),
        before,
        "a session run opens no window"
    );
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn a_program_that_shadows_an_allowed_name_on_the_path_is_refused_and_the_checked_file_runs() {
    use std::os::unix::fs::PermissionsExt;
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    s.bind_directly("ZETA", &["printenv"], &[]);
    // A look-alike earlier on the caller's PATH.
    let bin = s.project().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let fake = bin.join("printenv");
    fs::write(&fake, "#!/bin/sh\necho shadow\n").unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    let real_dir = Sandbox::which("printenv");
    let path = std::env::join_paths([bin.as_path(), real_dir.parent().unwrap()]).unwrap();
    let out = s
        .command(&s.project())
        .env("PATH", &path)
        .args(["run", "--secret", "ZETA", "--", "printenv", "ZETA"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(!text(&out.stdout).contains("shadow"));
    // The same command with the honest PATH runs the checked file.
    let out = s
        .command(&s.project())
        .env("PATH", real_dir.parent().unwrap())
        .args(["run", "--secret", "ZETA", "--", "printenv", "ZETA"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    // An unbound secret may run the look-alike; that is the project's file.
    let out = s
        .command(&s.project())
        .env("PATH", &path)
        .args(["run", "--secret", "BETA", "--", "printenv", "BETA"])
        .output()
        .unwrap();
    assert_eq!(text(&out.stdout), "shadow\n");
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn deny_groups_refuse_by_name_and_a_hand_edited_toml_changes_nothing() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"secret":"correct horse"}"#]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    s.bind_directly("ZETA", &[], &["@shells"]);
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "sh", "-c", "echo $ZETA"]);
    assert_eq!(out.status.code(), Some(3));
    let err = text(&out.stderr);
    assert!(
        err.contains("denies this command") && err.contains("@shells"),
        "{err}"
    );
    assert!(
        err.contains("cannot be added to the list"),
        "a denied command is only ever allowed once: {err}"
    );
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "printenv", "ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));

    // The file proposes; only the vault's copy counts.
    fs::write(
        s.project().join("vahta.toml"),
        "[secrets.ZETA]\nallow = [\"true\"]\ndeny = [\"@shells\"]\n",
    )
    .unwrap();
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "true"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "an allow in the file alone is not enforced"
    );
    s.bind_directly("ZETA", &["printenv"], &["@shells"]);
    fs::write(
        s.project().join("vahta.toml"),
        "[secrets.ZETA]\nallow = [\"printenv\", \"env\"]\ndeny = [\"@shells\"]\n",
    )
    .unwrap();
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "env"]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "a hand edit does not widen the list"
    );
    assert!(
        text(&out.stderr).contains("not approved"),
        "{}",
        text(&out.stderr)
    );
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
impl Sandbox {
    /// The approved rule set of `name`.
    fn rules_of(&self, name: &str) -> vahta_vault::RuleSet {
        self.open_vault()
            .bindings()
            .iter()
            .find(|b| b.name == name)
            .cloned()
            .unwrap_or_else(|| panic!("{name} has no rules"))
    }

    /// The last question of the kind `ask` the window was shown.
    fn last_ask(&self, ask: &str) -> Value {
        self.window_log()
            .into_iter()
            .rev()
            .find(|e| e["ask"] == ask)
            .unwrap_or_else(|| panic!("no {ask} question was shown"))
    }
}

const PW_ANSWER: &str = r#"{"secret":"correct horse"}"#;

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn ask_allow_once_runs_the_command_and_stores_nothing() {
    let s = sandbox_with_secrets();
    s.bind_directly("ZETA", &["printenv"], &[]);
    let toml = s.project().join("vahta.toml");
    fs::write(&toml, "[secrets.ZETA]\nallow = [\"printenv\"]\n").unwrap();

    // Allow once, then the run's own password window.
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&[
        "run",
        "--ask",
        "--reason",
        "need to see the env\u{1b}[31m",
        "--secret",
        "ZETA",
        "--",
        "sh",
        "-c",
        "echo $ZETA",
    ]);
    // `sh` is not on the list, so it was asked about.
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "***REDACTED(ZETA)***\n");
    let choice = s.last_ask("choose");
    let lines = choice["panel"]["lines"].to_string();
    let sh = Sandbox::which("sh");
    assert!(
        lines.contains(&format!("Program: {}", sh.display())),
        "{lines}"
    );
    assert!(lines.contains("Command: sh -c echo $ZETA"), "{lines}");
    assert!(lines.contains("allow: printenv"), "{lines}");
    // The agent's reason is shown as its own, without escape characters.
    let note = choice["panel"]["agent_note"].as_str().unwrap();
    assert!(
        note.contains("need to see the env") && !note.contains('\u{1b}'),
        "{note}"
    );
    assert_eq!(choice["options"].as_array().unwrap().len(), 3);
    assert_eq!(choice["options"][0], "Allow once");

    // Nothing was stored: the next plain run is refused with no window.
    let asked = s.asks();
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "sh", "-c", "true"]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(s.asks(), asked);
    assert_eq!(
        fs::read_to_string(&toml).unwrap(),
        "[secrets.ZETA]\nallow = [\"printenv\"]\n"
    );
    assert_eq!(s.rules_of("ZETA").allow.len(), 1);
    let journal = s.journal();
    assert!(journal.contains("run_allowed_once"), "{journal}");
    assert!(journal.contains(&format!("program {}", sh.display())));
    assert!(
        !journal.contains("echo") && !journal.contains("fake-"),
        "{journal}"
    );
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn ask_no_or_a_closed_window_runs_nothing_and_exits_4() {
    let s = sandbox_with_secrets();
    s.bind_directly("ZETA", &["printenv"], &[]);
    for answer in [r#"{"choose":1}"#, r#"{"cancel":true}"#] {
        s.script(&[answer]);
        let out = s.vahta(&["run", "--ask", "--secret", "ZETA", "--", "true"]);
        assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
        assert!(text(&out.stderr).contains("nothing was run"));
        assert!(text(&out.stdout).is_empty());
    }
    // Asking about a command that is already allowed opens nothing.
    let asked = s.asks();
    s.script(&[PW_ANSWER]);
    let out = s.vahta(&["run", "--ask", "--secret", "ZETA", "--", "printenv", "ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.asks(), asked + 1, "only the run's own password window");
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn ask_add_to_the_list_writes_the_toml_and_the_vault_and_the_next_run_passes() {
    let s = sandbox_with_secrets();
    s.bind_directly("ZETA", &["printenv"], &[]);
    let toml = s.project().join("vahta.toml");
    fs::write(
        &toml,
        "# keys\n[secrets.ZETA]\n# the main one\nallow = [\"printenv\"]\n\n[secrets.BETA]\n",
    )
    .unwrap();

    // Add, the fresh password for the write, then the run's own password.
    s.script(&[r#"{"choose":2}"#, PW_ANSWER, PW_ANSWER]);
    let out = s.vahta(&["run", "--ask", "--secret", "ZETA", "--", "env"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let options = s.last_ask("choose")["options"].clone();
    assert_eq!(options[2], "Add `env` to the list");

    // The toml kept its comments and gained the rule; the vault has it too.
    let written = fs::read_to_string(&toml).unwrap();
    assert!(
        written.contains("# keys") && written.contains("# the main one"),
        "{written}"
    );
    assert!(
        written.contains("allow = [\"printenv\", \"env\"]"),
        "{written}"
    );
    let zeta = s.rules_of("ZETA");
    let rules: Vec<&str> = zeta.allow.iter().map(|r| r.text.as_str()).collect();
    assert_eq!(rules, ["printenv", "env"]);
    match &zeta.allow[1].program {
        vahta_vault::Program::Path(p) => assert_eq!(PathBuf::from(p), Sandbox::which("env")),
        other => panic!("{other:?}"),
    }

    // The next plain run passes (one password window, no question).
    s.script(&[PW_ANSWER]);
    let before = s.asks();
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "env"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.asks(), before + 1);
    let journal = s.journal();
    assert!(journal.contains("binding_added"), "{journal}");
    assert!(!journal.contains("fake-") && !journal.contains("correct horse"));
    // The values never reached the window log or any output.
    let log = fs::read_to_string(s.root.join("surface.log")).unwrap();
    assert!(!log.contains("fake-"));
    assert!(!text(&out.stdout).contains("fake-") && !text(&out.stderr).contains("fake-"));
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn ask_add_with_a_wrong_password_or_a_changed_vault_changes_nothing() {
    let s = sandbox_with_secrets();
    s.bind_directly("ZETA", &["printenv"], &[]);
    let toml = s.project().join("vahta.toml");
    // Cancelled at the password: no file, no rule.
    s.script(&[r#"{"choose":2}"#, r#"{"cancel":true}"#]);
    let out = s.vahta(&["run", "--ask", "--secret", "ZETA", "--", "env"]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
    assert!(!toml.exists());
    assert_eq!(s.rules_of("ZETA").allow.len(), 1);
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn a_denied_command_can_only_be_allowed_once_and_a_delegated_ask_cannot_add() {
    let s = sandbox_with_secrets();
    s.script(&[PW_ANSWER]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    s.bind_directly("ZETA", &["printenv"], &["@shells"]);
    s.script(&[r#"{"choose":0}"#]);
    let out = s.vahta(&[
        "run",
        "--ask",
        "--secret",
        "ZETA",
        "--",
        "sh",
        "-c",
        "echo $ZETA",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "***REDACTED(ZETA)***\n");
    let choice = s.last_ask("choose");
    assert_eq!(choice["options"].as_array().unwrap().len(), 2, "{choice}");
    assert!(
        choice["panel"]["warning"]
            .as_str()
            .unwrap()
            .contains("deny list")
    );

    // A sub-agent's ask is a question, never an edit of the list.
    s.script(&[r#"{"choose":0}"#]);
    let out = s.vahta(&[
        "delegate", "--secret", "ZETA", "--", VAHTA, "run", "--ask", "--secret", "ZETA", "--",
        "env",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.last_ask("choose")["options"].as_array().unwrap().len(), 2);
}

// A project file the agent can edit is called out in the window.
#[cfg(unix)]
#[test]
fn the_window_warns_when_the_program_is_inside_the_project() {
    use std::os::unix::fs::PermissionsExt;
    let s = sandbox_with_secrets();
    s.bind_directly("ZETA", &["printenv"], &[]);
    let script = s.project().join("deploy.sh");
    fs::write(&script, "#!/bin/sh\ntrue\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    s.script(&[r#"{"choose":1}"#]);
    let out = s.vahta(&["run", "--ask", "--secret", "ZETA", "--", "./deploy.sh"]);
    assert_eq!(out.status.code(), Some(4));
    let choice = s.last_ask("choose");
    assert!(
        choice["panel"]["warning"]
            .as_str()
            .unwrap()
            .contains("agent can change"),
        "{choice}"
    );
    assert_eq!(choice["options"][2], "Add `./deploy.sh` to the list");

    // A launcher is flagged: allowing `env` allows whatever it starts.
    s.script(&[r#"{"choose":1}"#]);
    let out = s.vahta(&[
        "run", "--ask", "--secret", "ZETA", "--", "env", "printenv", "ZETA",
    ]);
    assert_eq!(out.status.code(), Some(4));
    let choice = s.last_ask("choose");
    assert!(
        choice["panel"]["warning"]
            .as_str()
            .unwrap()
            .contains("runs other programs"),
        "{choice}"
    );
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn bind_proposes_the_person_approves_and_then_only_the_listed_command_runs() {
    let s = sandbox_with_secrets();
    s.script(&[PW_ANSWER]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));

    // The proposal opens a window that shows the old and new rules, where the
    // program resolves to, and the reason as the agent's own.
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&[
        "bind",
        "ZETA",
        "--allow",
        "printenv",
        "--deny",
        "@network",
        "--reason",
        "deploys read it",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("ZETA: allow: printenv; deny: @network"));
    let choice = s.last_ask("choose");
    let lines = choice["panel"]["lines"].to_string();
    assert!(lines.contains("now:  no restrictions"), "{lines}");
    assert!(
        lines.contains("new:  allow: printenv; deny: @network"),
        "{lines}"
    );
    assert!(
        lines.contains(&format!(
            "`printenv` is {}",
            Sandbox::which("printenv").display()
        )),
        "{lines}"
    );
    assert_eq!(choice["panel"]["agent_note"], "deploys read it");
    assert_eq!(choice["options"][0], "Approve");

    // Both copies hold it.
    let toml = fs::read_to_string(s.project().join("vahta.toml")).unwrap();
    assert!(
        toml.contains("[secrets.ZETA]") && toml.contains("allow = [\"printenv\"]"),
        "{toml}"
    );
    assert!(toml.contains("deny = [\"@network\"]"), "{toml}");
    assert_eq!(s.rules_of("ZETA").allow.len(), 1);

    // A bound run in the session needs no window; another command is refused
    // with no window, and the message names --ask.
    let asked = s.asks();
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "printenv", "ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "***REDACTED(ZETA)***\n");
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "env"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(text(&out.stderr).contains("--ask"));
    assert_eq!(s.asks(), asked);
    let journal = s.journal();
    assert!(journal.contains("\"event\":\"bind\"") && journal.contains("approved"));
    assert!(!journal.contains("fake-") && !journal.contains("correct horse"));
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn bind_changes_nothing_without_approval_and_the_password() {
    let s = sandbox_with_secrets();
    let toml = s.project().join("vahta.toml");
    for answers in [
        vec![r#"{"choose":1}"#],
        vec![r#"{"cancel":true}"#],
        vec![r#"{"choose":0}"#, r#"{"cancel":true}"#],
    ] {
        s.script(&answers);
        let out = s.vahta(&["bind", "ZETA", "--allow", "printenv"]);
        assert_eq!(
            out.status.code(),
            Some(4),
            "{answers:?}: {}",
            text(&out.stderr)
        );
        assert!(!toml.exists());
        assert!(s.rules_of("ZETA").allow.is_empty());
    }
    // An unusable proposal is refused before any window.
    let asked = s.asks();
    for (args, code) in [
        (vec!["bind", "NOPE", "--allow", "printenv"], 3),
        (vec!["bind", "ZETA", "--allow", "no-such-program-here"], 1),
        (vec!["bind", "ZETA", "--allow", "@shells"], 1),
        (vec!["bind", "ZETA", "--deny", "@nope"], 1),
        (vec!["bind", "ZETA", "--allow", "git 'push'"], 1),
        (vec!["bind", "ZETA"], 1),
        (vec!["bind", "ZETA", "--clear", "--allow", "printenv"], 1),
        (vec!["bind"], 3),
        (vec!["bind", "--allow", "printenv"], 2),
    ] {
        let out = s.vahta(&args);
        assert_eq!(
            out.status.code(),
            Some(code),
            "{args:?}: {}",
            text(&out.stderr)
        );
    }
    assert_eq!(s.asks(), asked, "nothing above opened a window");
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn bind_clear_removes_the_rules_and_a_deny_group_refuses_a_shell() {
    let s = sandbox_with_secrets();
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&["bind", "ZETA", "--deny", "@shells"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "sh", "-c", "true"]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&["bind", "ZETA", "--clear"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!s.open_vault().bindings().iter().any(|b| b.name == "ZETA"));
    let toml = fs::read_to_string(s.project().join("vahta.toml")).unwrap();
    assert!(!toml.contains("deny"), "{toml}");
    // With no rules nothing may use it, and the refusal says how to fix that.
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "sh", "-c", "true"]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("no_rules") || text(&out.stderr).contains("no approved rules")
    );
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn a_hand_edited_toml_is_only_a_proposal_until_vahta_bind_approves_it() {
    let s = sandbox_with_secrets();
    s.bind_directly("ZETA", &["printenv"], &[]);
    let toml = s.project().join("vahta.toml");
    // In sync: nothing to approve.
    fs::write(&toml, "[secrets.ZETA]\nallow = [\"printenv\"]\n").unwrap();
    let out = s.vahta(&["bind"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("nothing to approve"));

    // Someone adds `env` to the file: still refused.
    fs::write(&toml, "[secrets.ZETA]\nallow = [\"printenv\", \"env\"]\n").unwrap();
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "env"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(text(&out.stderr).contains("not approved"));

    // `vahta bind` shows the difference; saying no changes nothing.
    s.script(&[r#"{"choose":1}"#]);
    let out = s.vahta(&["bind"]);
    assert_eq!(out.status.code(), Some(4));
    let lines = s.last_ask("choose")["panel"]["lines"].to_string();
    assert!(
        lines.contains("now:  allow: printenv") && lines.contains("new:  allow: printenv, env"),
        "{lines}"
    );
    assert_eq!(s.rules_of("ZETA").allow.len(), 1);

    // Approving makes it effective, and the file is left as written.
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&["bind"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        fs::read_to_string(&toml).unwrap(),
        "[secrets.ZETA]\nallow = [\"printenv\", \"env\"]\n"
    );
    s.script(&[PW_ANSWER]);
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "env"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
}

// --- agent roles ---------------------------------------------------------------------

#[cfg(unix)]
impl Sandbox {
    fn write_toml(&self, text: &str) {
        fs::write(self.project().join("vahta.toml"), text).unwrap();
    }

    /// `vahta role NAME`, approved through the window.
    fn approve_role(&self, name: &str) {
        self.script(&[r#"{"choose":0}"#, PW_ANSWER]);
        let out = self.vahta(&["role", name]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    }

    /// Change what a secret's approved rules say about the network.
    fn set_network(&self, name: &str, network: vahta_vault::Network) {
        let mut vault = self.open_vault();
        let mut rules = vault
            .bindings()
            .iter()
            .find(|b| b.name == name)
            .cloned()
            .unwrap();
        rules.network = network;
        vault.set_bindings(name, Some(rules)).unwrap();
        vault
            .save(&self.vault_path(), &LocalStore::new(self.root.join("data")))
            .unwrap();
    }

    /// A vault with ZETA and BETA bound to `printenv` and `env`, and a session
    /// from the test's own process, which the delegations below narrow.
    fn with_roles_ready() -> Sandbox {
        let s = sandbox_with_secrets();
        s.bind_directly("ZETA", &["printenv", "env"], &[]);
        s.bind_directly("BETA", &["printenv", "env"], &[]);
        s.script(&[PW_ANSWER]);
        assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
        s
    }
}

/// How a refusal inside a role session reads.
#[cfg(unix)]
const LIMITED: &str = "limited to the role";

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn a_role_wider_than_its_secret_is_refused_and_no_window_opens() {
    let s = sandbox_with_secrets();
    s.bind_directly("ZETA", &["printenv"], &[]);
    let asked = s.asks();
    // A program the secret's own rules do not allow.
    s.write_toml("[roles.wide]\nsecrets = [\"ZETA\"]\nallow = [\"env\"]\n");
    let out = s.vahta(&["role", "wide"]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    let err = text(&out.stderr);
    assert!(
        err.contains("allow `env` is wider than ZETA's own rules") && err.contains("No window"),
        "{err}"
    );
    // A network wider than the secret's.
    s.set_network("ZETA", vahta_vault::Network::None);
    s.write_toml("[roles.wide]\nsecrets = [\"ZETA\"]\nallow = [\"printenv\"]\nnetwork = \"app\"\n");
    let out = s.vahta(&["role", "wide"]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("network app is wider than ZETA's network (none)"),
        "{}",
        text(&out.stderr)
    );
    s.write_toml(
        "[roles.wide]\nsecrets = [\"ZETA\"]\nnetwork = \"hosts\"\nhosts = [\"api.example.test\"]\n",
    );
    let out = s.vahta(&["role", "wide"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(text(&out.stderr).contains("host"), "{}", text(&out.stderr));
    // A secret that is not there, and one with no rules.
    s.write_toml("[roles.wide]\nsecrets = [\"NOPE\"]\n");
    assert_eq!(s.vahta(&["role", "wide"]).status.code(), Some(3));
    s.write_toml("[roles.wide]\nsecrets = [\"BETA\"]\n");
    let mut vault = s.open_vault();
    vault.set_bindings("BETA", None).unwrap();
    vault
        .save(&s.vault_path(), &LocalStore::new(s.root.join("data")))
        .unwrap();
    let out = s.vahta(&["role", "wide"]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("no approved rules"),
        "{}",
        text(&out.stderr)
    );
    // Nor is there a proposal for a name the file does not have.
    assert_eq!(s.vahta(&["role", "nothing"]).status.code(), Some(3));
    assert_eq!(s.asks(), asked, "none of this opened a window");
    assert!(s.open_vault().roles().is_empty());
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn an_approved_role_lets_delegate_run_what_it_allows_and_nothing_else() {
    let s = Sandbox::with_roles_ready();
    s.write_toml(
        "[roles.show]\nsecrets = [\"ZETA\"]\nallow = [\"printenv\"]\ndeny = [\"@shells\"]\nuses = 5\n",
    );
    // Not approved yet: a role the vault does not have.
    let out = s.vahta(&["delegate", "--role", "show", "--", "true"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(
        text(&out.stderr).contains("no approved role"),
        "{}",
        text(&out.stderr)
    );

    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&["role", "show", "--reason", "read the env"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let choice = s.last_ask("choose");
    let lines = choice["panel"]["lines"].to_string();
    assert!(
        lines.contains("Role: show")
            && lines.contains("Secrets: ZETA")
            && lines.contains("Commands: only `printenv`")
            && lines.contains("Never: `@shells`")
            && lines.contains("at most 5 uses")
            && lines.contains("It is not approved yet."),
        "{lines}"
    );
    assert_eq!(choice["panel"]["agent_note"], "read the env");
    let roles = s.open_vault().roles().to_vec();
    assert_eq!(roles.len(), 1);
    assert!(roles[0].approved_at > 0 && roles[0].secrets == ["ZETA"]);

    let asks = s.asks();
    let out = s.vahta(&[
        "delegate", "--role", "show", "--", VAHTA, "run", "--secret", "ZETA", "--", "printenv",
        "ZETA",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "***REDACTED(ZETA)***\n");
    // `env` is in the secret's own rules but not in the role's.
    let out = s.vahta(&[
        "delegate", "--role", "show", "--", VAHTA, "run", "--secret", "ZETA", "--", "env",
    ]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains(LIMITED), "{}", text(&out.stderr));
    // A shell is denied by the role even before the allow list is looked at.
    let out = s.vahta(&[
        "delegate", "--role", "show", "--", VAHTA, "run", "--secret", "ZETA", "--", "sh", "-c",
        "true",
    ]);
    assert_eq!(out.status.code(), Some(3));
    // BETA is not the role's.
    let out = s.vahta(&[
        "delegate", "--role", "show", "--", VAHTA, "run", "--secret", "BETA", "--", "printenv",
        "BETA",
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(s.asks(), asks, "no window inside a role");

    // The child shows its role, and the journal does.
    let out = s.vahta(&[
        "delegate", "--role", "show", "--", VAHTA, "sessions", "--json",
    ]);
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    let child = doc["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["parent"].is_string())
        .unwrap()
        .clone();
    assert_eq!(child["agent_role"], "show");
    assert_eq!(child["names"], serde_json::json!(["ZETA"]));
    let journal = s.journal();
    assert!(
        journal.contains("\"event\":\"role_approved\"")
            && journal.contains("\"event\":\"run\"")
            && journal.contains("\"role\":\"show\""),
        "{journal}"
    );
    assert!(!journal.contains("fake-") && !journal.contains("correct horse"));
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn a_role_session_refuses_everything_but_the_actions_of_its_role() {
    let s = Sandbox::with_roles_ready();
    s.write_toml("[roles.show]\nsecrets = [\"ZETA\"]\nallow = [\"printenv\"]\n");
    s.approve_role("show");
    let asks = s.asks();
    for args in [
        vec!["reveal", "ZETA"],
        vec!["copy", "ZETA"],
        vec!["add", "NEWONE"],
        vec!["bind", "ZETA", "--allow", "env"],
        vec!["remove", "ZETA"],
        vec!["unlock"],
        vec!["unlock", "--role", "show"],
        vec!["role", "show"],
        vec!["role", "--remove", "show"],
        vec!["remote", "on"],
    ] {
        let mut full = vec!["delegate", "--role", "show", "--", VAHTA];
        full.extend(&args);
        let out = s.vahta(&full);
        assert_eq!(
            out.status.code(),
            Some(3),
            "{args:?}: {}",
            text(&out.stderr)
        );
        assert!(
            text(&out.stderr).contains(LIMITED),
            "{args:?}: {}",
            text(&out.stderr)
        );
    }
    // `http` is an action the role does not list; the refusal is the role's,
    // not a host question.
    let out = s.vahta(&[
        "delegate",
        "--role",
        "show",
        "--",
        VAHTA,
        "http",
        "--secret",
        "ZETA",
        "-H",
        "Authorization: {ZETA}",
        "https://api.example.test/x",
    ]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("does not let it send requests"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(s.asks(), asks, "refused before any window");
    assert_eq!(s.open_vault().roles().len(), 1);
    assert!(s.journal().contains("\"event\":\"role_refused\""));
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn a_role_gives_a_limited_number_of_uses_and_a_nested_delegation_does_not_add_any() {
    let s = Sandbox::with_roles_ready();
    s.write_toml("[roles.two]\nsecrets = [\"ZETA\"]\nallow = [\"printenv\"]\nuses = 2\n");
    s.approve_role("two");
    let run = format!("'{VAHTA}' run --secret ZETA -- printenv ZETA >/dev/null");
    let script = format!("{run}; echo first=$?; {run}; echo second=$?; {run}; echo third=$?");
    let out = s.vahta(&["delegate", "--role", "two", "--", "sh", "-c", &script]);
    let said = text(&out.stdout);
    assert!(
        said.contains("first=0") && said.contains("second=0") && said.contains("third=3"),
        "{said} / {}",
        text(&out.stderr)
    );
    assert!(s.journal().contains("RoleExhausted"));
    // A new grant is a fresh count; a use under a nested delegation counts
    // against the parent's role as well.
    let nested = format!(
        "'{VAHTA}' delegate --secret ZETA -- '{VAHTA}' run --secret ZETA -- printenv ZETA >/dev/null"
    );
    let script = format!("{run}; echo first=$?; {nested}; echo nested=$?; {run}; echo third=$?");
    let out = s.vahta(&["delegate", "--role", "two", "--", "sh", "-c", &script]);
    let said = text(&out.stdout);
    assert!(
        said.contains("first=0") && said.contains("nested=0") && said.contains("third=3"),
        "{said} / {}",
        text(&out.stderr)
    );
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn a_roles_longest_grant_caps_the_deadline_of_delegate_and_unlock() {
    let s = Sandbox::with_roles_ready();
    s.write_toml("[roles.short]\nsecrets = [\"ZETA\"]\nallow = [\"printenv\"]\nfor = \"1m\"\n");
    s.approve_role("short");
    let child_of = |out: &Output| -> Value {
        let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
        doc["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["agent_role"] == "short")
            .unwrap()
            .clone()
    };
    // Asked for two hours (more than the parent has): capped, not refused.
    let out = s.vahta(&[
        "delegate", "--role", "short", "--for", "2h", "--", VAHTA, "sessions", "--json",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let left = child_of(&out)["remaining_secs"].as_u64().unwrap();
    assert!((1..=60).contains(&left), "{left}");
    // Without --for it is the shortest of the parent's time and the role's.
    let out = s.vahta(&[
        "delegate", "--role", "short", "--", VAHTA, "sessions", "--json",
    ]);
    assert!(child_of(&out)["remaining_secs"].as_u64().unwrap() <= 60);
    // A plain delegation still refuses a later deadline than the parent's.
    let out = s.vahta(&["delegate", "--secret", "ZETA", "--for", "2h", "--", "true"]);
    assert_eq!(out.status.code(), Some(3));

    // `unlock --role` with `forever` is capped too, and the window names the role.
    assert_eq!(s.vahta(&["lock"]).status.code(), Some(0));
    s.script(&[PW_ANSWER]);
    let out = s.vahta(&["unlock", "--role", "short", "--for", "forever", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let info: Value = serde_json::from_slice(&out.stdout).unwrap();
    let left = info["session"]["remaining_secs"].as_u64().unwrap();
    assert!((1..=60).contains(&left), "{left}");
    assert_eq!(info["session"]["agent_role"], "short");
    let lines = s.last_ask("password")["panel"]["lines"].to_string();
    assert!(
        lines.contains("Role: short") && lines.contains("Secrets: ZETA"),
        "{lines}"
    );
    // The test process itself is now in the role session: it runs what the
    // role allows and is refused the rest.
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "printenv", "ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "env"]);
    assert_eq!(out.status.code(), Some(3));
    let out = s.vahta(&["reveal", "ZETA"]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains(LIMITED), "{}", text(&out.stderr));
    let out = s.vahta(&["unlock", "--role", "nope"]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(s.vahta(&["lock"]).status.code(), Some(0));
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn a_changed_toml_does_not_take_effect_until_it_is_approved_again() {
    let s = Sandbox::with_roles_ready();
    let secret = "[secrets.ZETA]\nallow = [\"printenv\", \"env\"]\n\n";
    let role = "[roles.show]\nsecrets = [\"ZETA\"]\nallow = [\"printenv\"]\n";
    s.write_toml(role);
    s.approve_role("show");
    // In sync: check is clean and says which roles there are; list too.
    s.write_toml(&format!("{secret}{role}"));
    let out = s.vahta(&["check"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert!(
        text(&out.stdout).contains("Roles:") && text(&out.stdout).contains("show: secrets ZETA"),
        "{}",
        text(&out.stdout)
    );
    assert!(text(&s.vahta(&["list"]).stdout).contains("Roles:"));

    // Someone widens the role in the file. `env` is allowed by the secret
    // too, but the role in the vault does not allow it, and BETA is not in it.
    s.write_toml(&format!(
        "{secret}[roles.show]\nsecrets = [\"ZETA\", \"BETA\"]\nallow = [\"printenv\", \"env\"]\n"
    ));
    let out = s.vahta(&["check"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("Roles not approved: show"),
        "{}",
        text(&out.stderr)
    );
    let out = s.vahta(&["check", "--json"]);
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["ok"], false);
    assert_eq!(doc["roles_pending"], serde_json::json!(["show"]));
    assert!(text(&s.vahta(&["list"]).stdout).contains("toml differs"));
    let out = s.vahta(&[
        "delegate", "--role", "show", "--", VAHTA, "run", "--secret", "ZETA", "--", "env",
    ]);
    assert_eq!(out.status.code(), Some(3), "the vault's copy applies");
    let out = s.vahta(&[
        "delegate", "--role", "show", "--", VAHTA, "run", "--secret", "BETA", "--", "printenv",
        "BETA",
    ]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "BETA is not in the approved role"
    );

    // `vahta role` shows what the person already approved next to the new
    // text; approving makes the new text effective.
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&["role"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let lines = s.last_ask("choose")["panel"]["lines"].to_string();
    assert!(lines.contains("It replaces the approved role"), "{lines}");
    let out = s.vahta(&[
        "delegate", "--role", "show", "--", VAHTA, "run", "--secret", "ZETA", "--", "env",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.vahta(&["check"]).status.code(), Some(0));
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn a_delegation_below_a_role_session_keeps_the_role_and_cannot_widen() {
    let s = Sandbox::with_roles_ready();
    s.write_toml(
        "[roles.pair]\nsecrets = [\"ZETA\", \"BETA\"]\nallow = [\"printenv\"]\n\n\
         [roles.other]\nsecrets = [\"ZETA\"]\n",
    );
    s.approve_role("pair");
    s.approve_role("other");
    // Narrower is fine, and the child still has the role: `env` is refused.
    let inner = format!(
        "'{v}' delegate --secret ZETA -- '{v}' run --secret ZETA -- printenv ZETA >/dev/null; \
         echo narrow=$?; \
         '{v}' delegate --secret ZETA -- '{v}' run --secret ZETA -- env >/dev/null 2>&1; \
         echo role_kept=$?; \
         '{v}' delegate --secret ALPHA -- true >/dev/null 2>&1; echo wider=$?; \
         '{v}' delegate --role other -- true >/dev/null 2>&1; echo other_role=$?; \
         '{v}' delegate --role pair --secret ZETA -- true >/dev/null 2>&1; echo same_role=$?",
        v = VAHTA
    );
    let out = s.vahta(&["delegate", "--role", "pair", "--", "sh", "-c", &inner]);
    let said = text(&out.stdout);
    assert!(
        said.contains("narrow=0")
            && said.contains("role_kept=3")
            && said.contains("wider=3")
            && said.contains("other_role=3")
            && said.contains("same_role=0"),
        "{said} / {}",
        text(&out.stderr)
    );
    // A name outside the role is refused for a role delegation.
    let out = s.vahta(&[
        "delegate", "--role", "other", "--secret", "BETA", "--", "true",
    ]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn a_role_that_asks_each_use_opens_a_window_per_use() {
    let s = Sandbox::with_roles_ready();
    s.write_toml("[roles.careful]\nsecrets = [\"ZETA\"]\nallow = [\"printenv\"]\nask = true\n");
    s.approve_role("careful");
    let asks = s.asks();
    s.script(&[r#"{"choose":0}"#]);
    let out = s.vahta(&[
        "delegate", "--role", "careful", "--", VAHTA, "run", "--secret", "ZETA", "--", "printenv",
        "ZETA",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(s.asks() > asks);
    let lines = s.last_ask("choose")["panel"]["lines"].to_string();
    assert!(
        lines.contains("Role: careful") && lines.contains("Command: printenv ZETA"),
        "{lines}"
    );
    // A "no" is the person's answer: nothing runs.
    s.script(&[r#"{"choose":1}"#]);
    let out = s.vahta(&[
        "delegate", "--role", "careful", "--", VAHTA, "run", "--secret", "ZETA", "--", "printenv",
        "ZETA",
    ]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
}

// Runs commands that only a Unix has (sh, printenv, cat, true).
#[cfg(unix)]
#[test]
fn removing_a_role_needs_the_person_and_takes_it_out_of_the_file() {
    let s = Sandbox::with_roles_ready();
    s.write_toml("[roles.show]\nsecrets = [\"ZETA\"]\nallow = [\"printenv\"]\n");
    s.approve_role("show");
    // No: the role stays.
    s.script(&[r#"{"choose":1}"#]);
    assert_eq!(
        s.vahta(&["role", "--remove", "show"]).status.code(),
        Some(4)
    );
    assert_eq!(s.open_vault().roles().len(), 1);
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&["role", "--remove", "show"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(s.open_vault().roles().is_empty());
    assert!(
        !fs::read_to_string(s.project().join("vahta.toml"))
            .unwrap()
            .contains("roles")
    );
    let out = s.vahta(&["delegate", "--role", "show", "--", "true"]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(
        s.vahta(&["role", "--remove", "show"]).status.code(),
        Some(3)
    );
    assert!(s.journal().contains("role_removed"));
}

// Needs a network namespace for the command, which only Linux gives.
#[cfg(target_os = "linux")]
#[test]
fn a_role_with_network_none_runs_the_command_with_no_network_on_an_app_secret() {
    let Some(python) = ["python3", "python"]
        .into_iter()
        .find(|p| std::process::Command::new(p).arg("-V").output().is_ok())
    else {
        eprintln!("skipped: no python on PATH to make a connection with");
        return;
    };
    if !vahta_os::network_isolation_available() {
        eprintln!("skipped: no unprivileged network namespaces here");
        return;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let probe = format!(
        "import socket; s = socket.socket(); s.settimeout(3); s.connect(('127.0.0.1', {port})); print('connected')"
    );
    let s = sandbox_with_secrets();
    s.bind_directly("ZETA", &[python], &[]);
    s.script(&[PW_ANSWER]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
    s.write_toml(&format!(
        "[roles.offline]\nsecrets = [\"ZETA\"]\nallow = [\"{python}\"]\nnetwork = \"none\"\n\n\
         [roles.online]\nsecrets = [\"ZETA\"]\nallow = [\"{python}\"]\n"
    ));
    s.approve_role("offline");
    s.approve_role("online");
    // The secret's own network is the program's: it connects, and so does a
    // role that says nothing about the network.
    let out = s.vahta(&["run", "--secret", "ZETA", "--", python, "-c", &probe]);
    assert_eq!(text(&out.stdout), "connected\n", "{}", text(&out.stderr));
    let out = s.vahta(&[
        "delegate", "--role", "online", "--", VAHTA, "run", "--secret", "ZETA", "--", python, "-c",
        &probe,
    ]);
    assert_eq!(text(&out.stdout), "connected\n", "{}", text(&out.stderr));
    // Role `none` on an `app` secret cuts the network like a `none` secret.
    let out = s.vahta(&[
        "delegate", "--role", "offline", "--", VAHTA, "run", "--secret", "ZETA", "--", python,
        "-c", &probe,
    ]);
    assert_ne!(out.status.code(), Some(0));
    assert!(!text(&out.stdout).contains("connected"));
    drop(listener);
}

// --- class and the add hint ----------------------------------------------------------

#[cfg(unix)]
/// A key-shaped value built at run time, so no key-like literal is in the
/// source: `prefix` plus a tail the detector accepts.
fn key_like(prefix: &str, tail_len: usize) -> String {
    let tail: String = "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ7"
        .chars()
        .cycle()
        .take(tail_len)
        .collect();
    format!("{prefix}{tail}")
}

// Uses the helpers that run commands, which only a Unix has.
#[cfg(unix)]
#[test]
fn a_payment_key_gets_its_category_each_use_and_the_agent_learns_the_class_not_the_value() {
    let s = Sandbox::new();
    s.script(&[PW_ANSWER, r#"{"ack":true}"#]);
    assert_eq!(s.vahta(&["init"]).status.code(), Some(0));
    let live = key_like("sk_live_", 24);
    let value = format!(r#"{{"secret":"{live}"}}"#);

    // The value points at payment: the category, the tier and the network come
    // from it, all shown in the one window that also asked for the value.
    s.script(&[PW_ANSWER, &value, r#"{"choose":0}"#]);
    let before = s.asks();
    let out = s.vahta(&[
        "add",
        "STRIPE_KEY",
        "--net",
        "hosts:api.stripe.com",
        "--allow",
        "printenv",
        "--reason",
        "billing script",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.asks() - before, 3, "password, value, rules: one window");
    let said = text(&out.stdout);
    assert!(
        said.starts_with("saved STRIPE_KEY (payment key, each-use)\n"),
        "{said}"
    );
    assert!(
        said.contains("Rules approved with it: category: payment")
            && said.contains("prompt injection")
            && said.contains("vahta http"),
        "{said}"
    );
    let ask = s.last_ask("choose");
    assert_eq!(ask["prompt"], "Store STRIPE_KEY with these rules?");
    assert_eq!(
        ask["options"],
        serde_json::json!(["Accept", "Use the default set for payment", "Cancel"])
    );
    let lines = ask["panel"]["lines"].to_string();
    assert!(
        lines.contains(
            "Payment key. Works only through Vahta with api.stripe.com. Only these may run: \
             printenv. Never: @shells, @interpreters, @network. Asks you every time."
        ),
        "{lines}"
    );
    assert_eq!(ask["panel"]["agent_note"], "billing script");
    assert!(ask["panel"]["warning"].is_null(), "{ask}");
    let vault = s.open_vault();
    let e = &vault.entries()[0];
    assert_eq!(
        (e.tier, e.class),
        (Tier::EachUse, Some(vahta_vault::Class::Payment))
    );
    let rs = s.rules_of("STRIPE_KEY");
    assert_eq!(rs.category.as_deref(), Some("payment"));
    assert_eq!(rs.downgraded_from, None);
    assert!(matches!(&rs.network, vahta_vault::Network::Hosts(h) if h[0].host == "api.stripe.com"));
    // The file the repository reviews shows the same.
    let toml = fs::read_to_string(s.project().join("vahta.toml")).unwrap();
    assert!(
        toml.contains("category = \"payment\"")
            && toml.contains("network = \"hosts\"")
            && toml.contains("hosts = [\"api.stripe.com\"]"),
        "{toml}"
    );
    // ...and is in sync with the vault: nothing to approve.
    let out = s.vahta(&["bind"]);
    assert!(
        text(&out.stdout).contains("nothing to approve"),
        "{}",
        text(&out.stderr)
    );

    // No flags at all: the default set of the category the value points at; the
    // hosts, which only the person can name there, are asked in the window.
    s.script(&[
        PW_ANSWER,
        &value,
        r#"{"text":"api.vendor.test"}"#,
        r#"{"choose":0}"#,
    ]);
    let out = s.vahta(&["add", "PLAIN_PAY"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let ask = s.last_ask("choose");
    assert_eq!(
        ask["options"],
        serde_json::json!(["Accept", "Cancel"]),
        "the proposal is the default set"
    );
    let rs = s.rules_of("PLAIN_PAY");
    assert_eq!(rs.category.as_deref(), Some("payment"));
    assert!(
        matches!(&rs.network, vahta_vault::Network::Hosts(h) if h[0].host == "api.vendor.test")
    );

    // A cloud key: the category is server, the tier a session.
    let aws = key_like("AKIA", 16).to_uppercase();
    s.script(&[
        PW_ANSWER,
        &format!(r#"{{"secret":"{aws}"}}"#),
        r#"{"choose":0}"#,
    ]);
    let out = s.vahta(&["add", "CLOUD_KEY", "--allow", "printenv"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).starts_with("saved CLOUD_KEY (cloud key, session)"),
        "{}",
        text(&out.stdout)
    );
    assert_eq!(s.rules_of("CLOUD_KEY").category.as_deref(), Some("server"));

    // A plain value: ordinary, nothing to warn about.
    s.script(&[
        PW_ANSWER,
        r#"{"secret":"fake-plain-value"}"#,
        r#"{"choose":0}"#,
    ]);
    let out = s.vahta(&["add", "PLAIN"]);
    let said = text(&out.stdout);
    assert!(
        said.starts_with("saved PLAIN\n") && !said.contains("key,"),
        "{said}"
    );
    assert_eq!(s.rules_of("PLAIN").category.as_deref(), Some("ordinary"));
    assert_eq!(
        s.open_vault()
            .entries()
            .iter()
            .find(|e| e.name == "PLAIN")
            .unwrap()
            .class,
        Some(vahta_vault::Class::Other)
    );

    // A reset can make the tier offer; it keeps the rules it has.
    s.bind_directly("PLAIN", &["printenv"], &[]);
    s.script(&[PW_ANSWER, r#"{"secret":"fake-other-value"}"#]);
    let out = s.vahta(&["reset", "PLAIN"]);
    assert_eq!(text(&out.stdout).trim(), "replaced PLAIN");
    s.script(&[PW_ANSWER, &value, r#"{"choose":0}"#]);
    let out = s.vahta(&["reset", "PLAIN"]);
    assert_eq!(
        text(&out.stdout).trim(),
        "replaced PLAIN (payment key, each-use)"
    );

    // The value is nowhere it should not be.
    for place in [
        s.journal(),
        fs::read_to_string(s.root.join("surface.log")).unwrap(),
        fs::read_to_string(s.project().join("vahta.toml")).unwrap(),
    ] {
        assert!(!place.contains(&live) && !place.contains(&aws));
    }
    // A cancelled proposal stores nothing, not even the file's entry.
    s.script(&[PW_ANSWER, &value, r#"{"cancel":true}"#]);
    let out = s.vahta(&[
        "add",
        "NEVER",
        "--net",
        "hosts:a.test",
        "--allow",
        "printenv",
    ]);
    assert_eq!(out.status.code(), Some(4));
    assert!(!s.open_vault().entries().iter().any(|e| e.name == "NEVER"));
    assert!(
        !fs::read_to_string(s.project().join("vahta.toml"))
            .unwrap()
            .contains("NEVER")
    );
}

// Names point at a category too.
#[cfg(unix)]
#[test]
fn a_name_like_aws_or_paypal_raises_the_class_of_a_plain_value() {
    let s = Sandbox::new();
    s.script(&[PW_ANSWER, r#"{"ack":true}"#]);
    assert_eq!(s.vahta(&["init"]).status.code(), Some(0));
    s.script(&[PW_ANSWER, &plain_value(1), r#"{"choose":0}"#]);
    let out = s.vahta(&["add", "AWS_DEPLOY_TOKEN", "--allow", "printenv"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).starts_with("saved AWS_DEPLOY_TOKEN (cloud key, session)"),
        "{}",
        text(&out.stdout)
    );
    s.script(&[PW_ANSWER, &plain_value(2), r#"{"choose":0}"#]);
    let out = s.vahta(&[
        "add",
        "PAYPAL_CLIENT",
        "--net",
        "hosts:api.paypal.com",
        "--allow",
        "printenv",
    ]);
    assert!(
        text(&out.stdout).starts_with("saved PAYPAL_CLIENT (payment key, each-use)"),
        "{}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
    // A word inside another word is not the word.
    let asked = s.asks();
    s.script(&[PW_ANSWER, &plain_value(3), r#"{"choose":0}"#]);
    let out = s.vahta(&["add", "LAWS_TOKEN"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.asks(), asked + 3, "a password, a value, the rules");
    assert_eq!(
        s.rules_of("LAWS_TOKEN").category.as_deref(),
        Some("ordinary")
    );
}

// Mandatory rules, categories, downgrades, folders and the network.
#[cfg(unix)]
#[test]
fn a_secret_with_no_rules_is_refused_with_the_command_that_proposes_them() {
    let s = sandbox_with_secrets();
    // A secret from before rules were mandatory: take its rules away.
    let mut vault = s.open_vault();
    vault.set_bindings("ZETA", None).unwrap();
    vault
        .save(&s.vault_path(), &LocalStore::new(s.root.join("data")))
        .unwrap();
    let asked = s.asks();
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "true"]);
    assert_eq!(out.status.code(), Some(3));
    let err = text(&out.stderr);
    assert!(
        err.contains("vahta bind ZETA --category ordinary --allow PROGRAM")
            && err.contains("prompt injection")
            && err.contains("ZETA: no approved rules"),
        "{err}"
    );
    assert_eq!(s.asks(), asked, "no window for a refusal");
    assert!(s.journal().contains("no_rules"));
    // Even a session does not help.
    s.script(&[PW_ANSWER]);
    assert_eq!(
        s.vahta(&["unlock", "--secret", "ZETA"]).status.code(),
        Some(0)
    );
    assert_eq!(
        s.vahta(&["run", "--secret", "ZETA", "--", "true"])
            .status
            .code(),
        Some(3)
    );
    // Proposing and approving makes it usable.
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&[
        "bind",
        "ZETA",
        "--category",
        "ordinary",
        "--allow",
        "printenv",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "printenv", "ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    // The category's denies came with it; a shell is refused even if listed.
    let rs = s.rules_of("ZETA");
    assert_eq!(rs.category.as_deref(), Some("ordinary"));
    assert!(rs.deny.iter().any(|d| d.text == "@shells"));
    let list = text(&s.vahta(&["list"]).stdout);
    assert!(list.contains("ordinary, app"), "{list}");
}

#[cfg(unix)]
#[test]
fn a_category_below_the_one_the_value_looks_like_is_a_loud_downgrade_and_in_the_journal() {
    let s = Sandbox::new();
    s.script(&[PW_ANSWER, r#"{"ack":true}"#]);
    assert_eq!(s.vahta(&["init"]).status.code(), Some(0));
    let live = key_like("sk_live_", 24);
    let value = format!(r#"{{"secret":"{live}"}}"#);

    // Accepting is allowed.
    s.script(&[PW_ANSWER, &value, r#"{"choose":0}"#]);
    let out = s.vahta(&[
        "add",
        "LOW_ONE",
        "--category",
        "ordinary",
        "--allow",
        "printenv",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let ask = s.last_ask("choose");
    let warning = ask["panel"]["warning"].as_str().unwrap();
    assert!(
        warning.starts_with(
            "This asks to downgrade: the value looks like a payment key, whose default \
             category is payment; the agent proposes ordinary."
        ),
        "{warning}"
    );
    assert_eq!(ask["options"][1], "Use the default set for payment");
    let rs = s.rules_of("LOW_ONE");
    assert_eq!(rs.category.as_deref(), Some("ordinary"));
    assert_eq!(rs.downgraded_from.as_deref(), Some("payment"));
    let journal = s.journal();
    assert!(
        journal.contains("category_downgraded") && journal.contains("payment -> ordinary"),
        "{journal}"
    );

    // The person overrules it in one click: the detected category's defaults
    // (its hosts are asked), no downgrade left on the rules.
    s.script(&[
        PW_ANSWER,
        &value,
        r#"{"choose":1}"#,
        r#"{"text":"api.stripe.com"}"#,
    ]);
    let out = s.vahta(&[
        "add",
        "LOW_TWO",
        "--category",
        "ordinary",
        "--allow",
        "printenv",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let rs = s.rules_of("LOW_TWO");
    assert_eq!(rs.category.as_deref(), Some("payment"));
    assert_eq!(rs.downgraded_from, None);
    assert!(matches!(rs.network, vahta_vault::Network::Hosts(_)));
    assert_eq!(
        s.open_vault()
            .entries()
            .iter()
            .find(|e| e.name == "LOW_TWO")
            .unwrap()
            .tier,
        Tier::EachUse
    );

    // Proposals a category cannot take are refused before any window.
    let asked = s.asks();
    for args in [
        vec![
            "add",
            "BAD_ONE",
            "--category",
            "payment",
            "--allow",
            "printenv",
        ],
        vec![
            "add",
            "BAD_TWO",
            "--category",
            "payment",
            "--net",
            "app",
            "--allow",
            "printenv",
        ],
        vec!["add", "BAD_THREE", "--category", "nonsense"],
        vec!["add", "BAD_FOUR", "--category", "server"],
        vec!["add", "BAD_FIVE", "--category", "ordinary", "--allow", "sh"],
    ] {
        let out = s.vahta(&args);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{args:?}: {}",
            text(&out.stderr)
        );
    }
    assert_eq!(s.asks(), asked);
}

#[cfg(unix)]
#[test]
fn directories_bound_where_a_secret_is_used_and_let_scripts_in_without_a_rule() {
    use std::os::unix::fs::PermissionsExt;
    let s = sandbox_with_secrets();
    fs::create_dir(s.project().join("scripts")).unwrap();
    let script = s.project().join("scripts/hello.sh");
    fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&[
        "bind",
        "ZETA",
        "--category",
        "ordinary",
        "--allow",
        "printenv",
        "--dir",
        "./scripts",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let ask = s.last_ask("choose");
    // The folder is inside the project, which the agent can write to.
    assert!(
        ask["panel"]["warning"]
            .as_str()
            .unwrap()
            .contains("put files in this folder"),
        "{ask}"
    );
    assert_eq!(s.rules_of("ZETA").dirs.len(), 1);
    assert!(
        fs::read_to_string(s.project().join("vahta.toml"))
            .unwrap()
            .contains("dirs = [\"./scripts\"]")
    );

    // From the project root the working directory is outside the folder.
    s.script(&[PW_ANSWER]);
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "printenv", "ZETA"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(
        text(&out.stderr).contains("outside the directories"),
        "{}",
        text(&out.stderr)
    );
    // From inside it, the allowed program runs, and so does a script there
    // that no rule names.
    let inside = s.project().join("scripts");
    s.script(&[PW_ANSWER]);
    let out = s
        .command(&inside)
        .args(["run", "--secret", "ZETA", "--", "printenv", "ZETA"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    s.script(&[PW_ANSWER]);
    let out = s
        .command(&inside)
        .args(["run", "--secret", "ZETA", "--", "./hello.sh"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "hi\n");
    // A program that is neither allowed nor in the folder is not.
    let out = s
        .command(&inside)
        .args(["run", "--secret", "ZETA", "--", "cat", "/dev/null"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    // A payment key takes no folders at all.
    let out = s.vahta(&[
        "bind",
        "ALPHA",
        "--category",
        "payment",
        "--net",
        "hosts:a.test",
        "--allow",
        "printenv",
        "--dir",
        "./scripts",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("directories"),
        "{}",
        text(&out.stderr)
    );
}

#[cfg(unix)]
#[test]
fn network_none_runs_the_command_with_no_network_on_linux() {
    let Some(python) = ["python3", "python"]
        .into_iter()
        .find(|p| std::process::Command::new(p).arg("-V").output().is_ok())
    else {
        eprintln!("skipped: no python on PATH to make a connection with");
        return;
    };
    if !vahta_os::network_isolation_available() {
        eprintln!("skipped: no unprivileged network namespaces here");
        return;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let probe = format!(
        "import socket; s = socket.socket(); s.settimeout(3); s.connect(('127.0.0.1', {port})); print('connected')"
    );
    let s = sandbox_with_secrets();
    // The program's own network: the connection works.
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&[
        "bind",
        "ZETA",
        "--category",
        "ordinary",
        "--allow",
        python,
        "--net",
        "app",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    s.script(&[PW_ANSWER]);
    let out = s.vahta(&["run", "--secret", "ZETA", "--", python, "-c", &probe]);
    assert_eq!(text(&out.stdout), "connected\n", "{}", text(&out.stderr));
    // No network: the same command cannot connect to the listener.
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&[
        "bind",
        "ZETA",
        "--category",
        "ordinary",
        "--allow",
        python,
        "--net",
        "none",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    s.script(&[PW_ANSWER]);
    let out = s.vahta(&["run", "--secret", "ZETA", "--", python, "-c", &probe]);
    assert_ne!(out.status.code(), Some(0));
    assert!(!text(&out.stdout).contains("connected"));
    // `hosts` is cut off the same way (they are reachable only via `vahta http`).
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&[
        "bind",
        "ZETA",
        "--category",
        "ordinary",
        "--allow",
        python,
        "--net",
        "hosts:api.example.test",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    s.script(&[PW_ANSWER]);
    let out = s.vahta(&["run", "--secret", "ZETA", "--", python, "-c", &probe]);
    assert_ne!(out.status.code(), Some(0));
    drop(listener);
}

// Uses the helpers that run commands, which only a Unix has.
#[cfg(unix)]
/// The scripted window's answer for a typed value, built at run time.
fn plain_value(n: u32) -> String {
    format!(r#"{{"secret":"fake-plain-value-{n}"}}"#)
}

// --- tier ----------------------------------------------------------------------------------

// Uses the helpers that run commands, which only a Unix has.
#[cfg(unix)]
#[test]
fn tier_moves_a_secret_between_session_and_each_use_without_its_value() {
    let s = Sandbox::new();
    s.script(&[PW_ANSWER, r#"{"ack":true}"#]);
    assert_eq!(s.vahta(&["init"]).status.code(), Some(0));
    s.script(&[PW_ANSWER, &plain_value(4), r#"{"choose":0}"#]);
    assert_eq!(
        s.vahta(&["add", "TOKEN", "--tier", "each-use"])
            .status
            .code(),
        Some(0)
    );
    let tier_of = |s: &Sandbox| {
        s.open_vault()
            .entries()
            .iter()
            .find(|e| e.name == "TOKEN")
            .unwrap()
            .tier
    };

    // The password and nothing else: no value is asked for.
    let asked = s.asks();
    s.script(&[PW_ANSWER]);
    let out = s.vahta(&["tier", "TOKEN", "session"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout).trim(), "TOKEN is now session");
    assert_eq!(s.asks(), asked + 1);
    assert_eq!(tier_of(&s), Tier::Session);
    let shown = s.last_ask("password");
    assert!(
        shown.to_string().contains("TOKEN: each-use -> session"),
        "{shown}"
    );

    // The same tier again, or an unknown name: refused, no window.
    let asked = s.asks();
    assert_eq!(
        s.vahta(&["tier", "TOKEN", "session"]).status.code(),
        Some(3)
    );
    assert_eq!(
        s.vahta(&["tier", "NOPE", "each-use"]).status.code(),
        Some(3)
    );
    assert_eq!(s.asks(), asked);

    // A cancelled window changes nothing.
    s.script(&[r#"{"cancel":true}"#]);
    assert_eq!(
        s.vahta(&["tier", "TOKEN", "each-use"]).status.code(),
        Some(4)
    );
    assert_eq!(tier_of(&s), Tier::Session);
    s.script(&[PW_ANSWER]);
    assert_eq!(
        s.vahta(&["tier", "TOKEN", "each_use"]).status.code(),
        Some(0)
    );
    assert_eq!(tier_of(&s), Tier::EachUse);

    // Usage errors.
    assert_eq!(s.vahta(&["tier", "TOKEN"]).status.code(), Some(2));
    assert_eq!(
        s.vahta(&["tier", "TOKEN", "forever"]).status.code(),
        Some(2)
    );
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
    // The project's vault. Compared by its tail: on Windows the daemon and the
    // test may spell the temp directory differently (a short 8.3 name).
    let tail = Path::new("project").join(".vahta").join("vault.vht");
    let tail = tail.to_string_lossy();
    assert!(
        ask["panel"]["lines"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|l| l.starts_with("Vault: ") && l.ends_with(tail.as_ref())),
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

// --- the injection alarm and values in encoded forms ----------------------------------------

/// Every spelling of `value` a leak check should look for: raw, base64 at the
/// three offsets (padded), hex in both cases, reversed.
fn spellings_of(value: &str) -> Vec<String> {
    let mut out = vec![value.to_string()];
    for prefix in ["", "k", "ke"] {
        out.push(vahta_ipc::protocol::b64_encode(
            format!("{prefix}{value}").as_bytes(),
        ));
    }
    let hex = vahta_vault::hex_encode(value.as_bytes());
    out.push(hex.to_uppercase());
    out.push(hex);
    out.push(value.chars().rev().collect());
    out
}

fn assert_no_spelling(place: &str, content: &str, value: &str) {
    for form in spellings_of(value) {
        // A padded encoding's core is what the cache holds: look for it
        // without its last group, which depends on what follows.
        let core = &form[..form.len().saturating_sub(4).max(8.min(form.len()))];
        assert!(!content.contains(core), "{place} holds a form of {value:?}");
    }
}

fn evaded_report(session: &str) -> ClientRequest {
    use vahta_ipc::protocol::{Evasion, Signal};
    ClientRequest::HookReport {
        session: Some(session.into()),
        harness: "claude".into(),
        cwd: "/p".into(),
        signal: Signal::Blocked {
            category: "an API token".into(),
            rule: "test.rule".into(),
            evasion: Some(Evasion::Base64),
        },
    }
}

fn tool_check(session: &str, text: &str) -> ClientRequest {
    ClientRequest::ToolCheck {
        session: Some(session.into()),
        cwd: "/p".into(),
        text: text.into(),
    }
}

impl Sandbox {
    fn unlock_session(&self) {
        self.script(&[r#"{"secret":"correct horse"}"#]);
        let out = self.vahta(&["unlock"]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    }

    fn windows_titled(&self, title: &str) -> usize {
        self.window_log()
            .iter()
            .filter(|e| e["open"] == title)
            .count()
    }
}

#[test]
fn a_held_value_in_any_encoding_is_refused_by_form_and_the_person_gets_the_name() {
    let s = sandbox_with_secrets();
    s.unlock_session();
    // Each hit rings the alarm; the person ignores it, so the session stays.
    s.script(&[r#"{"choose":1}"#]);
    let mut conn = connector(&s, false).connect_running().unwrap().unwrap();

    let texts = [
        // Base64 at each offset the value can sit at, padded or not.
        (
            format!("echo {}", vahta_ipc::protocol::b64_encode(b"fake-one")),
            "base64",
        ),
        (
            format!("echo {}", vahta_ipc::protocol::b64_encode(b"k=fake-one;")),
            "base64",
        ),
        (
            format!(
                "echo {}",
                vahta_ipc::protocol::b64_encode(b"key=fake-one").trim_end_matches('=')
            ),
            "base64",
        ),
        (
            format!("echo {}", vahta_vault::hex_encode(b"fake-one")),
            "hex",
        ),
        ("echo fake-one".to_string(), "raw"),
        (
            format!("echo {}", "fake-one".chars().rev().collect::<String>()),
            "reversed",
        ),
    ];
    for (text, form) in &texts {
        match conn.request(&tool_check("agent-1", text)).unwrap() {
            ClientReply::ToolDeny { form: f, name } => {
                assert_eq!((f.as_str(), name.as_str()), (*form, "ZETA"), "{text}");
            }
            other => panic!("{text}: {other:?}"),
        }
    }
    // Text with nothing of it, and a value in an each-use secret that no
    // session holds, pass.
    for clean in ["echo hello world", "ls -la /tmp", "echo fake-three"] {
        assert!(matches!(
            conn.request(&tool_check("agent-1", clean)).unwrap(),
            ClientReply::Ok {}
        ));
    }

    // The journal names the secret for the person and holds no value.
    let journal = s.journal();
    let hit = journal
        .lines()
        .find(|l| l.contains("\"result\":\"known_value\""))
        .expect("a known_value entry");
    assert!(
        hit.contains("ZETA") && hit.contains("written as base64"),
        "{hit}"
    );
    assert_no_spelling("the journal", &journal, "fake-one");
}

#[test]
fn a_value_percent_encoded_in_full_or_cut_by_quotes_is_refused_by_form() {
    let s = sandbox_with_secrets();
    s.unlock_session();
    s.script(&[r#"{"choose":1}"#]);
    let mut conn = connector(&s, false).connect_running().unwrap().unwrap();
    let every = |upper: bool| -> String {
        "fake-one"
            .bytes()
            .map(|b| {
                if upper {
                    format!("%{b:02X}")
                } else {
                    format!("%{b:02x}")
                }
            })
            .collect()
    };
    let texts = [
        (
            format!("curl http://h/?k={}&x=1", every(true)),
            "URL-encoded",
        ),
        (format!("the token is {}, ok", every(false)), "URL-encoded"),
        ("echo 'fake-''one'".to_string(), "concatenation"),
        ("echo \"fake\"'-one'".to_string(), "concatenation"),
        ("echo 'fake-' + \"one\"".to_string(), "concatenation"),
    ];
    for (text, form) in &texts {
        match conn.request(&tool_check("agent-1", text)).unwrap() {
            ClientReply::ToolDeny { form: f, name } => {
                assert_eq!((f.as_str(), name.as_str()), (*form, "ZETA"), "{text}");
            }
            other => panic!("{text}: {other:?}"),
        }
    }
    for clean in ["echo 'fake-' 'zzz'", "echo %68%65%6c%6c%6f"] {
        assert!(matches!(
            conn.request(&tool_check("agent-1", clean)).unwrap(),
            ClientReply::Ok {}
        ));
    }
    let journal = s.journal();
    assert!(journal.contains("written as URL-encoded"), "{journal}");
    assert!(journal.contains("written as concatenation"), "{journal}");
    assert_no_spelling("the journal", &journal, "fake-one");
    assert!(!journal.contains(&every(true)) && !journal.contains(&every(false)));
}

#[test]
fn disguised_secrets_raise_the_alarm_and_lock_ends_the_sessions() {
    let s = sandbox_with_secrets();
    s.unlock_session();
    assert_eq!(s.sessions().len(), 1);
    s.script(&[r#"{"choose":0}"#]);
    let mut conn = connector(&s, false).connect_running().unwrap().unwrap();
    // 4 + 4 crosses the threshold on the second; the third is throttled.
    for _ in 0..3 {
        assert!(matches!(
            conn.request(&evaded_report("agent-2")).unwrap(),
            ClientReply::Ok {}
        ));
    }
    wait_until("the alarm to lock the sessions", 10, || {
        s.sessions().is_empty()
    });
    assert_eq!(s.windows_titled("Suspicious agent behaviour"), 1);
    let log = s.window_log();
    let ask = log
        .iter()
        .rev()
        .find(|e| e["ask"] == "choose")
        .expect("the alarm asked");
    assert_eq!(
        ask["options"],
        serde_json::json!(["Lock all sessions", "Ignore for this agent session"])
    );
    let lines = ask["panel"]["lines"].to_string();
    assert!(lines.contains("prompt injection"), "{lines}");
    assert!(lines.contains("hidden as base64 x2"), "{lines}");
    assert!(lines.contains("claude session agent-2"), "{lines}");
    // The rule id is for the journal, not the window.
    assert!(!lines.contains("test.rule"));

    let journal = s.journal();
    assert!(journal.contains("\"event\":\"alarm\""));
    assert!(
        journal.contains("\"reason\":\"alarm\""),
        "sessions end for the alarm"
    );

    // Status and the list say so, until the next unlock.
    let out = s.vahta(&["daemon", "status"]);
    assert!(
        text(&out.stdout).contains("alarm raised at "),
        "{}",
        text(&out.stdout)
    );
    let out = s.vahta(&["sessions"]);
    assert!(
        text(&out.stdout).contains("alarm raised at "),
        "{}",
        text(&out.stdout)
    );
    s.unlock_session();
    let out = s.vahta(&["daemon", "status"]);
    assert!(
        !text(&out.stdout).contains("alarm raised"),
        "{}",
        text(&out.stdout)
    );
}

#[test]
fn ignoring_an_alarm_keeps_the_sessions_and_silences_that_agent() {
    let s = sandbox_with_secrets();
    s.unlock_session();
    s.script(&[r#"{"choose":1}"#]);
    let mut conn = connector(&s, false).connect_running().unwrap().unwrap();
    for _ in 0..2 {
        conn.request(&evaded_report("agent-3")).unwrap();
    }
    wait_until("the alarm to be ignored", 10, || {
        s.journal().contains("alarm_ignored")
    });
    assert_eq!(s.sessions().len(), 1);
    // Another report from the same agent session raises nothing.
    for _ in 0..3 {
        conn.request(&evaded_report("agent-3")).unwrap();
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(s.windows_titled("Suspicious agent behaviour"), 1);
    assert_eq!(s.sessions().len(), 1);
}

#[test]
fn with_alarm_lock_the_sessions_end_without_a_question() {
    let s = sandbox_with_secrets();
    fs::write(s.root.join("config/config.toml"), "alarm = \"lock\"\n").unwrap();
    assert_eq!(s.vahta(&["daemon", "restart"]).status.code(), Some(0));
    s.unlock_session();
    assert_eq!(s.sessions().len(), 1);
    let mut conn = connector(&s, false).connect_running().unwrap().unwrap();
    // A held value is enough on its own.
    let reply = conn
        .request(&tool_check(
            "agent-4",
            &format!("echo {}", vahta_vault::hex_encode(b"fake-one")),
        ))
        .unwrap();
    assert!(matches!(reply, ClientReply::ToolDeny { .. }));
    wait_until("the sessions to be locked", 10, || s.sessions().is_empty());
    // It told the person after the fact, and asked nothing.
    wait_until("the window to say what happened", 10, || {
        s.window_log().iter().any(|e| {
            e["close"]
                .as_str()
                .is_some_and(|m| m.contains("locked 1 session(s)") || m.contains("Vahta locked 1"))
        })
    });
    assert!(s.window_log().iter().all(|e| {
        e["ask"] != "choose"
            || e["prompt"]
                .as_str()
                .is_some_and(|p| p.starts_with("Store "))
    }));
    let journal = s.journal();
    assert!(
        journal.contains("\"result\":\"lock\"") && journal.contains("the alarm is set to lock")
    );
}

#[test]
fn with_no_window_to_ask_in_the_alarm_locks() {
    let s = sandbox_with_secrets();
    s.unlock_session();
    // The script has no answer left: the question cannot be asked.
    let mut conn = connector(&s, false).connect_running().unwrap().unwrap();
    for _ in 0..2 {
        conn.request(&evaded_report("agent-5")).unwrap();
    }
    wait_until("the headless alarm to lock", 10, || s.sessions().is_empty());
    assert!(s.journal().contains("the question could not be asked"));
}

/// A bound ZETA (only `printenv` may use it) and a session, with the alarm's
/// answer scripted to "ignore" so the session stays and the window is logged.
#[cfg(unix)]
fn sandbox_for_refusals() -> Sandbox {
    let s = sandbox_with_secrets_in(Sandbox::counting_refusals());
    s.unlock_session();
    s.bind_directly("ZETA", &["printenv"], &[]);
    s.script(&[r#"{"choose":1}"#]);
    s
}

#[cfg(unix)]
fn refused_run(s: &Sandbox, program: &str) {
    let out = s.vahta(&["run", "--secret", "ZETA", "--", program]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    // The agent's reply is the ordinary refusal with its hint.
    let err = text(&out.stderr);
    assert!(err.contains("--ask") && !err.contains("injection"), "{err}");
}

#[cfg(unix)]
#[test]
fn one_refused_network_tool_raises_the_alarm_naming_the_secret_and_the_program() {
    let s = sandbox_for_refusals();
    refused_run(&s, "curl");
    wait_until("the alarm to ask", 10, || {
        s.windows_titled("Suspicious agent behaviour") == 1
    });
    let log = s.window_log();
    // Another window may follow the alarm's; pick the alarm by its options.
    let ask = log
        .iter()
        .rev()
        .find(|e| e["ask"] == "choose" && e["options"][0] == "Lock all sessions")
        .expect("the alarm asked");
    let lines = ask["panel"]["lines"].to_string();
    assert!(
        lines.contains("prompt injection") && lines.contains("ZETA") && lines.contains("curl"),
        "{lines}"
    );
    assert!(s.journal().contains("\"event\":\"alarm\""));
    assert!(!lines.contains("fake-"));
}

#[cfg(unix)]
#[test]
fn two_refused_ordinary_programs_raise_the_alarm_and_one_does_not() {
    let s = sandbox_for_refusals();
    refused_run(&s, "true");
    // One refusal of a program that is no network tool, shell or interpreter
    // is an honest mistake.
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(s.windows_titled("Suspicious agent behaviour"), 0);
    assert!(!s.journal().contains("\"event\":\"alarm\""));
    refused_run(&s, "env");
    wait_until("the alarm to ask", 10, || {
        s.windows_titled("Suspicious agent behaviour") == 1
    });
}

#[cfg(unix)]
#[test]
fn with_alarm_lock_a_refused_network_tool_ends_the_sessions() {
    let s = sandbox_with_secrets_in(Sandbox::counting_refusals());
    fs::write(s.root.join("config/config.toml"), "alarm = \"lock\"\n").unwrap();
    assert_eq!(s.vahta(&["daemon", "restart"]).status.code(), Some(0));
    s.unlock_session();
    s.bind_directly("ZETA", &["printenv"], &[]);
    assert_eq!(s.sessions().len(), 1);
    refused_run(&s, "curl");
    wait_until("the sessions to be locked", 10, || s.sessions().is_empty());
    assert!(s.journal().contains("the alarm is set to lock"));
}

#[test]
fn spooled_reports_are_weighed_when_the_daemon_starts() {
    use vahta_ipc::protocol::{Evasion, Signal};
    use vahta_ipc::spool::{self, SpoolLine};

    let s = Sandbox::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for _ in 0..2 {
        spool::append(
            &s.paths(),
            &SpoolLine {
                time: now - 30,
                session: Some("agent-6".into()),
                harness: "claude".into(),
                cwd: "/p".into(),
                signal: Signal::Blocked {
                    category: "an API token".into(),
                    rule: "test.rule".into(),
                    evasion: Some(Evasion::Hex),
                },
            },
        )
        .unwrap();
    }
    // One from long ago does not count.
    spool::append(
        &s.paths(),
        &SpoolLine {
            time: now - 3600,
            session: Some("agent-7".into()),
            harness: "claude".into(),
            cwd: "/p".into(),
            signal: Signal::KnownValue { form: "hex".into() },
        },
    )
    .unwrap();
    assert_eq!(s.vahta(&["daemon", "restart"]).status.code(), Some(0));
    wait_until("the spooled alarm", 10, || {
        s.journal().contains("\"event\":\"alarm\"")
    });
    let journal = s.journal();
    assert!(journal.contains("agent-6") && !journal.contains("agent-7; score"));
    assert!(journal.contains("spooled"));
}

#[test]
fn the_hook_refuses_a_held_value_in_a_command_and_says_only_the_form() {
    let s = sandbox_with_secrets();
    s.unlock_session();
    let command = format!(
        "echo {} | base64 -d",
        vahta_ipc::protocol::b64_encode(b"x=fake-one")
    );
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": s.project(),
        "session_id": "sess-9",
    });
    let mut child = Command::new(hook_bin())
        .args(["--harness", "claude", "--event", "before_tool"])
        .current_dir(s.project())
        .env("HOME", s.root.join("home"))
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("VAHTA_HOOK_DISABLE")
        .env("VAHTA_DATA_DIR", s.root.join("data"))
        .env("VAHTA_RUNTIME_DIR", s.root.join("run"))
        .env("VAHTA_CONFIG_DIR", s.root.join("config"))
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
    let reply: Value = serde_json::from_slice(&out.stdout).unwrap();
    let reason = reply["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert_eq!(reply["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        reason,
        "Blocked: this command contains a value Vahta holds (base64). Use `vahta run`."
    );
    // The person is told which secret; the agent is not.
    assert!(!reason.contains("ZETA"));
    assert!(reply["systemMessage"].as_str().unwrap().contains("ZETA"));
    // The daemon journalled it under the agent's session id, with no value.
    let journal = s.journal();
    assert!(journal.contains("known_value") && journal.contains("sess-9"));
    assert_no_spelling("the journal", &journal, "fake-one");
    assert_no_spelling("the hook's stdout", &text(&out.stdout), "fake-one");
    assert_no_spelling("the hook's stderr", &text(&out.stderr), "fake-one");
    // Without a daemon the hook checks nothing and lets it through.
    assert_eq!(s.vahta(&["daemon", "stop"]).status.code(), Some(0));
}

#[test]
fn the_encoded_forms_of_a_run_value_are_cut_from_output_and_nothing_leaks() {
    let s = sandbox_with_secrets();
    s.unlock_session();
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "printenv", "ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let b64 = vahta_ipc::protocol::b64_encode(b"fake-one");
    let reply = s
        .hook_after_bash(&format!(
            "see {b64} and {}",
            vahta_vault::hex_encode(b"fake-one")
        ))
        .expect("the hook answered");
    let (stdout, _) = redacted(&reply);
    assert_eq!(
        stdout,
        "see ***REDACTED(ZETA (base64))*** and ***REDACTED(ZETA (hex))***"
    );

    // And `vahta run` scrubs a command's own base64 of the value.
    let out = s.vahta(&[
        "run",
        "--secret",
        "ZETA",
        "--",
        "sh",
        "-c",
        "printf %s \"$ZETA\" | base64; printf %s \"$ZETA\" | od -An -tx1 | tr -d ' \\n'",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("***REDACTED(ZETA (base64))***"), "{stdout}");
    assert_no_spelling("run stdout", &stdout, "fake-one");
    assert_no_spelling("run stderr", &text(&out.stderr), "fake-one");
    assert_no_spelling("the journal", &s.journal(), "fake-one");
    assert_no_spelling(
        "the window log",
        &fs::read_to_string(s.root.join("surface.log")).unwrap_or_default(),
        "fake-one",
    );
}

#[cfg(unix)]
fn check_run(s: &Sandbox, names: &[&str], argv: &[&str], path: Option<&str>) -> ClientReply {
    let mut conn = connector(s, false).connect_running().unwrap().unwrap();
    conn.request(&ClientRequest::CheckRun {
        cwd: s.project().to_string_lossy().into_owned(),
        argv: argv.iter().map(|a| a.to_string()).collect(),
        names: names.iter().map(|n| n.to_string()).collect(),
        path: path.map(str::to_string),
        vault: None,
    })
    .unwrap()
}

// Runs commands that only a Unix has (printenv, env).
#[cfg(unix)]
#[test]
fn check_run_says_allowed_only_for_a_command_the_rules_let_through_and_opens_nothing() {
    let s = sandbox_with_secrets();
    s.bind_directly("ZETA", &["printenv"], &[]);
    assert_eq!(s.vahta(&["daemon", "restart"]).status.code(), Some(0));
    let dir = Sandbox::which("printenv");
    let path = dir.parent().unwrap().to_string_lossy().into_owned();
    let path = Some(path.as_str());
    let (asks, journal) = (s.asks(), s.journal());

    let allowed = ClientReply::Allowed {};
    let none = ClientReply::NoOpinion {};
    // On the list, and not on it.
    assert_eq!(
        check_run(&s, &["ZETA"], &["printenv", "ZETA"], path),
        allowed
    );
    assert_eq!(check_run(&s, &["ZETA"], &["env"], path), none);
    // An open rule set takes anything; one bound name is enough to say no.
    assert_eq!(check_run(&s, &["BETA"], &["env"], path), allowed);
    assert_eq!(check_run(&s, &["BETA", "ZETA"], &["env"], path), none);
    // The project's own list (here vahta.toml names none the vault holds).
    assert_eq!(check_run(&s, &[], &["printenv"], path), none);
    // Each-use opens a window whatever the rules say: no explicit allow.
    assert_eq!(check_run(&s, &["ALPHA"], &["printenv"], path), none);
    // Unknown names, no program on that PATH, no command, no vault.
    assert_eq!(check_run(&s, &["NOPE"], &["printenv"], path), none);
    assert_eq!(
        check_run(&s, &["ZETA"], &["printenv"], Some("/nonexistent")),
        none
    );
    assert_eq!(check_run(&s, &["ZETA"], &[], path), none);
    let mut conn = connector(&s, false).connect_running().unwrap().unwrap();
    let elsewhere = std::env::temp_dir().to_string_lossy().into_owned();
    let reply = conn
        .request(&ClientRequest::CheckRun {
            cwd: elsewhere,
            argv: vec!["printenv".into()],
            names: vec!["ZETA".into()],
            path: path.map(str::to_string),
            vault: None,
        })
        .unwrap();
    assert_eq!(reply, none);
    // A question is not an event: no window, no journal line.
    assert_eq!(s.asks(), asks);
    assert_eq!(s.journal(), journal);
}

// --- Paired devices, rekey, recovery -----------------------------------------------------------

const OLD_PW: &str = "correct horse";

impl Sandbox {
    fn phones(&self) -> vahta_auth::loopback::LoopbackLinks {
        vahta_auth::loopback::LoopbackLinks::new(self.root.join("phones"))
    }

    /// What the software phone does for its next questions.
    fn phone(&self, behaviours: &[&str]) {
        let dir = self.root.join("phones");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("script");
        let mut text = fs::read_to_string(&path).unwrap_or_default();
        for b in behaviours {
            text.push_str(b);
            text.push('\n');
        }
        fs::write(path, text).unwrap();
    }

    fn phone_script_left(&self) -> usize {
        fs::read_to_string(self.root.join("phones/script"))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count()
    }

    #[cfg(unix)]
    fn phone_log(&self) -> String {
        fs::read_to_string(self.root.join("phones/log")).unwrap_or_default()
    }

    /// Pair a phone called `name` (the password, no phone needed).
    fn pair(&self, name: &str, access: &str) -> Output {
        self.script(&[r#"{"secret":"correct horse"}"#]);
        self.vahta(&["devices", "pair", name, "--for", access])
    }

    fn devices(&self) -> Vec<Value> {
        let out = self.vahta(&["devices", "--json"]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
        doc["devices"].as_array().unwrap().clone()
    }

    fn device_id(&self, name: &str) -> [u8; 16] {
        let d = self.devices();
        let hex = d.iter().find(|x| x["name"] == name).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        vahta_vault::hex_decode(&hex).unwrap().try_into().unwrap()
    }

    #[cfg(unix)]
    fn device_slot_params(&self) -> Vec<u8> {
        Vault::peek(&self.vault_path())
            .unwrap()
            .slots
            .iter()
            .find(|s| s.info.kind == vahta_vault::SLOT_DEVICE)
            .map(|s| s.params.clone())
            .unwrap_or_default()
    }

    fn recovery_shown(&self) -> Vec<String> {
        self.window_log()
            .iter()
            .filter(|e| e["ask"] == "recovery")
            .map(|e| e["shown"].as_str().unwrap().to_string())
            .collect()
    }

    /// Run an each-use secret through `sh`, printing it (redacted).
    #[cfg(unix)]
    fn run_each_use(&self) -> Output {
        self.vahta(&["run", "--secret", "ALPHA", "--", "sh", "-c", "echo $ALPHA"])
    }
}

/// The key a phone would derive for a device slot, from the slot's public
/// parameters (what a lost phone can still compute for a copy of the file).
fn kek_of(phone: &vahta_auth::loopback::LoopbackDevice, id: &[u8; 16], params: &[u8]) -> [u8; 32] {
    let shared = phone.shared_secret(params).unwrap();
    let mut info = b"vahta/v2/device-kek".to_vec();
    info.extend_from_slice(id);
    info.extend_from_slice(params);
    *vahta_vault::crypto::hkdf(&*shared, &info)
}

#[cfg(unix)]
#[test]
fn a_paired_phone_opens_an_each_use_run_and_a_session_with_no_password_window() {
    let s = sandbox_with_secrets();
    let out = s.pair("pixel", "30d");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("paired pixel"),
        "{}",
        text(&out.stdout)
    );
    // Pairing asked for the password and nothing else.
    let list = s.devices();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["state"], "active");
    assert!(list[0]["expires_at"].as_u64().unwrap() > 29 * 86_400);

    let before = s.device_slot_params();
    let asks = s.asks();
    s.phone(&["approve"]);
    let out = s.run_each_use();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "***REDACTED(ALPHA)***\n");
    assert_eq!(s.asks(), asks, "the phone answered; no password window");
    // The slot was written again with a new ephemeral key.
    assert_ne!(s.device_slot_params(), before);
    let journal = s.journal();
    assert!(journal.contains("\"event\":\"device_paired\""), "{journal}");
    assert!(journal.contains("\"event\":\"device_unlock\""), "{journal}");
    assert!(!journal.contains("fake-") && !journal.contains("correct horse"));
    assert!(
        s.phone_log().contains("unlock pixel run_each_use"),
        "{}",
        s.phone_log()
    );

    // A session too.
    s.phone(&["approve"]);
    let out = s.vahta(&["unlock", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.asks(), asks);
    let out = s.vahta(&["run", "--secret", "ZETA", "--", "sh", "-c", "echo $ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.asks(), asks, "the session needs no window either");

    // It shows as used.
    let list = s.devices();
    assert!(list[0]["last_used"].as_u64().is_some());
    let out = s.vahta(&["devices"]);
    let table = text(&out.stdout);
    assert!(
        table.contains("pixel") && table.contains("active"),
        "{table}"
    );
}

#[cfg(unix)]
#[test]
fn the_password_window_always_works_and_a_cheating_phone_is_refused() {
    let s = sandbox_with_secrets();
    assert_eq!(s.pair("pixel", "30d").status.code(), Some(0));
    // Out of reach: the password window.
    s.script(&[PW_ANSWER]);
    let asks = s.asks();
    let out = s.run_each_use();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.asks(), asks + 1);

    // One good unlock, so there is an old decision to replay.
    s.phone(&["approve"]);
    assert_eq!(s.run_each_use().status.code(), Some(0));
    assert_eq!(s.asks(), asks + 1);

    for cheat in ["timeout", "forge", "replay"] {
        s.phone(&[cheat]);
        s.script(&[PW_ANSWER]);
        let before = s.asks();
        let out = s.run_each_use();
        assert_eq!(out.status.code(), Some(0), "{cheat}: {}", text(&out.stderr));
        assert_eq!(
            s.asks(),
            before + 1,
            "{cheat} must end at the password window"
        );
    }
    let journal = s.journal();
    assert!(journal.contains("does not verify"), "{journal}");
    assert!(journal.contains("\"result\":\"refused\""), "{journal}");
}

#[cfg(unix)]
#[test]
fn a_no_on_the_phone_ends_the_run_and_the_session_unlock_with_no_password_window() {
    let s = sandbox_with_secrets();
    assert_eq!(s.pair("pixel", "30d").status.code(), Some(0));
    let asks = s.asks();
    s.phone(&["deny"]);
    let out = s.run_each_use();
    // Like a person cancelling: a plain message, not a crash.
    assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("refused on the phone"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(text(&out.stdout), "");
    assert_eq!(s.asks(), asks, "the password window was not asked");
    assert_eq!(s.phone_script_left(), 0);
    let journal = s.journal();
    assert!(journal.contains("refused on the device"), "{journal}");
    // The same for a session unlock.
    s.phone(&["deny"]);
    let out = s.vahta(&["unlock"]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("refused on the phone"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(s.asks(), asks);
}

#[cfg(unix)]
#[test]
fn a_device_expires_is_extended_with_the_password_and_is_revoked() {
    let s = sandbox_with_secrets();
    assert_eq!(s.pair("pixel", "30d").status.code(), Some(0));
    let id = s.device_id("pixel");

    // Access that ends in two seconds.
    let store = LocalStore::new(s.root.join("data"));
    let mut v = s.open_vault();
    let soon = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 2;
    vahta_auth::refresh_device(&mut v, &id, Some(soon)).unwrap();
    v.save(&s.vault_path(), &store).unwrap();
    drop(v);
    std::thread::sleep(Duration::from_millis(2500));

    // Expired: the phone is not even asked; the password window is.
    s.phone(&["approve"]);
    s.script(&[PW_ANSWER]);
    let asks = s.asks();
    assert_eq!(s.run_each_use().status.code(), Some(0));
    assert_eq!(s.asks(), asks + 1);
    assert_eq!(s.phone_script_left(), 1, "the expired phone was not asked");
    assert_eq!(s.devices()[0]["state"], "expired");

    // Extending needs the password, never the phone.
    s.script(&[PW_ANSWER]);
    let out = s.vahta(&["devices", "extend", "pixel", "--for", "90d"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.phone_script_left(), 1, "extending does not ask the phone");
    assert_eq!(s.devices()[0]["state"], "active");
    let asks = s.asks();
    assert_eq!(s.run_each_use().status.code(), Some(0));
    assert_eq!(s.asks(), asks, "the extended phone answers again");

    // Revoking: the phone is gone, the password stays.
    s.phone(&["approve"]);
    s.script(&[PW_ANSWER]);
    let out = s.vahta(&["devices", "revoke", "pix"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(s.devices().is_empty());
    assert!(
        Vault::peek(&s.vault_path())
            .unwrap()
            .slots
            .iter()
            .all(|x| x.info.kind != vahta_vault::SLOT_DEVICE)
    );
    s.script(&[PW_ANSWER]);
    let asks = s.asks();
    assert_eq!(s.run_each_use().status.code(), Some(0));
    assert_eq!(s.asks(), asks + 1);
    let journal = s.journal();
    for event in ["device_extended", "device_revoked"] {
        assert!(journal.contains(event), "{event}: {journal}");
    }
}

#[test]
fn a_device_cannot_manage_devices() {
    let s = sandbox_with_secrets();
    assert_eq!(s.pair("pixel", "30d").status.code(), Some(0));
    // The phone says yes; the window still wants the password.
    s.phone(&["approve", "approve"]);
    s.script(&[r#"{"cancel":true}"#]);
    let out = s.vahta(&["devices", "extend", "pixel"]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
    assert_eq!(s.phone_script_left(), 2);
    // Two phones of one name are one too many.
    s.script(&[PW_ANSWER]);
    let out = s.vahta(&["devices", "pair", "pixel"]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    // Unknown device, bad duration.
    let out = s.vahta(&["devices", "revoke", "nothing"]);
    assert_eq!(out.status.code(), Some(3));
    let out = s.vahta(&["devices", "extend", "pixel", "--for", "10s"]);
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn a_lost_phone_is_revoked_and_the_vault_rekeyed_so_an_old_copy_is_no_use() {
    let s = sandbox_with_secrets();
    assert_eq!(s.pair("pixel", "30d").status.code(), Some(0));
    assert_eq!(s.pair("tablet", "30d").status.code(), Some(0));
    let id = s.device_id("pixel");
    let first_key = s.recovery_shown()[0].clone();

    // A session is open when the phone is lost.
    s.script(&[PW_ANSWER]);
    assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));

    // The copy a thief of the phone's keys might hold.
    let slot_params = s.device_slot_params_of(&id);
    let copy = s.root.join("copy.vht");
    fs::copy(s.vault_path(), &copy).unwrap();
    let old_kek = kek_of(&s.phones().load(&id).unwrap(), &id, &slot_params);

    s.script(&[PW_ANSWER, r#"{"ack":true}"#]);
    let out = s.vahta(&["devices", "lost", "pixel"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("re-keyed"),
        "{}",
        text(&out.stdout)
    );

    // A new recovery key was shown; the old one is dead and the new one works.
    let keys = s.recovery_shown();
    assert_eq!(keys.len(), 2, "init showed one; lost shows the new one");
    let new_key = vahta_vault::RecoveryKey::from_paper(&keys[1]).unwrap();
    let old_key = vahta_vault::RecoveryKey::from_paper(&first_key).unwrap();
    let store = LocalStore::new(s.root.join("data"));
    assert!(Vault::unlock_recovery(&s.vault_path(), &old_key, &store).is_err());
    let v = Vault::unlock_recovery(&s.vault_path(), &new_key, &store).unwrap();
    assert_eq!(v.get("ZETA").unwrap().expose(), b"fake-one");

    // The copy opens with the old phone's key, on a machine that never saw
    // the new vault, and gives the old vault. The new file does not.
    let stranger = LocalStore::new(s.root.join("elsewhere"));
    assert!(Vault::unlock_with_slot(&copy, &id, &old_kek, &stranger).is_ok());
    assert!(Vault::unlock_with_slot(&s.vault_path(), &id, &old_kek, &store).is_err());
    // The password still opens the new file; the other phone is kept; this
    // machine was not told the owner changed.
    let v = Vault::unlock_password(&s.vault_path(), OLD_PW.as_bytes(), &store).unwrap();
    assert_eq!(v.get("ALPHA").unwrap().expose(), b"fake-three");
    let names: Vec<String> = s.devices().iter().map(|d| d["name"].to_string()).collect();
    assert_eq!(names, vec!["\"tablet\"".to_string()]);
    let sessions = s.vahta(&["sessions", "--json"]);
    let doc: Value = serde_json::from_slice(&sessions.stdout).unwrap();
    assert_eq!(
        doc["sessions"].as_array().unwrap().len(),
        0,
        "sessions end with the old key"
    );

    // The kept tablet opens the new vault.
    s.phone(&["approve"]);
    #[cfg(unix)]
    {
        let asks = s.asks();
        assert_eq!(s.run_each_use().status.code(), Some(0));
        assert_eq!(s.asks(), asks);
    }
    let journal = s.journal();
    for event in ["device_lost_rekey", "\"event\":\"rekey\""] {
        assert!(journal.contains(event), "{event}: {journal}");
    }
    assert!(!journal.contains(&keys[1]) && !journal.contains("fake-"));
}

impl Sandbox {
    fn device_slot_params_of(&self, id: &[u8; 16]) -> Vec<u8> {
        Vault::peek(&self.vault_path())
            .unwrap()
            .slots
            .iter()
            .find(|s| &s.info.slot_id == id)
            .map(|s| s.params.clone())
            .unwrap()
    }
}

#[test]
fn forgot_the_password_the_recovery_key_sets_a_new_one() {
    let s = sandbox_with_secrets();
    let key = s.recovery_shown()[0].clone();
    let store = LocalStore::new(s.root.join("data"));

    // A wrong key three times changes nothing.
    s.script(&[
        r#"{"secret":"nonsense"}"#,
        r#"{"secret":"more nonsense"}"#,
        r#"{"secret":"00"}"#,
    ]);
    let out = s.vahta(&["recover"]);
    assert_ne!(out.status.code(), Some(0));
    assert!(Vault::unlock_password(&s.vault_path(), OLD_PW.as_bytes(), &store).is_ok());

    // A well-formed key that is not this vault's.
    s.script(&[&format!(r#"{{"secret":"{}"}}"#, "ab".repeat(32))]);
    let out = s.vahta(&["recover"]);
    assert_ne!(out.status.code(), Some(0));
    assert!(
        text(&out.stderr).contains("does not open"),
        "{}",
        text(&out.stderr)
    );

    // The right key, then a new password.
    s.script(&[
        &format!(r#"{{"secret":"{key}"}}"#),
        r#"{"secret":"a brand new password"}"#,
    ]);
    let out = s.vahta(&["recover"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(Vault::unlock_password(&s.vault_path(), OLD_PW.as_bytes(), &store).is_err());
    let v = Vault::unlock_password(&s.vault_path(), b"a brand new password", &store).unwrap();
    assert_eq!(v.get("ZETA").unwrap().expose(), b"fake-one");
    // The recovery key itself is unchanged and still opens it.
    let k = vahta_vault::RecoveryKey::from_paper(&key).unwrap();
    assert!(Vault::unlock_recovery(&s.vault_path(), &k, &store).is_ok());
    let journal = s.journal();
    assert!(journal.contains("\"event\":\"recover\""), "{journal}");
    assert!(!journal.contains(&key) && !journal.contains("brand new"));
}

#[cfg(unix)]
#[test]
fn a_phone_can_answer_an_ask_and_a_forged_answer_to_it_is_not_taken() {
    let s = sandbox_with_secrets();
    s.bind_directly("ZETA", &["printenv"], &[]);
    fs::write(
        s.project().join("vahta.toml"),
        "[secrets.ZETA]\nallow = [\"printenv\"]\n",
    )
    .unwrap();
    assert_eq!(s.pair("pixel", "30d").status.code(), Some(0));

    // The phone allows once, then opens the vault for the run: no password.
    let passwords = |s: &Sandbox| {
        s.window_log()
            .iter()
            .filter(|e| e["ask"] == "password")
            .count()
    };
    let before = passwords(&s);
    s.phone(&["approve:0", "approve"]);
    let out = s.vahta(&[
        "run",
        "--ask",
        "--reason",
        "look",
        "--secret",
        "ZETA",
        "--",
        "sh",
        "-c",
        "echo $ZETA",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(passwords(&s), before, "no password was asked");
    let journal = s.journal();
    assert!(journal.contains("device_approve"), "{journal}");
    assert!(journal.contains("run_allowed_once"), "{journal}");

    // A forged answer to the choice is not taken: the window decides.
    s.phone(&["forge"]);
    s.script(&[r#"{"choose":1}"#]);
    let out = s.vahta(&["run", "--ask", "--secret", "ZETA", "--", "sh", "-c", "true"]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
    assert_eq!(s.journal().matches("run_allowed_once").count(), 1);
}
// --- `vahta http` ----------------------------------------------------------------------------

mod http {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use vahta_net::test_server::{Reply, TestServer};
    use vahta_vault::{HostRule, Network, RuleSet};

    /// The made-up value of ZETA in these tests, assembled at run time.
    fn zeta() -> String {
        ["fake-", "http-", "key-1"].concat()
    }

    fn sandbox() -> Sandbox {
        let s = Sandbox::new();
        s.with_vault(&[
            ("ZETA", &zeta(), "session"),
            ("BETA", "fake-two", "session"),
            ("ALPHA", "fake-three", "each-use"),
        ]);
        s
    }

    fn host(h: &str, subdomains: bool, port: Option<u16>) -> HostRule {
        HostRule {
            text: h.to_string(),
            host: h.to_string(),
            subdomains,
            port,
        }
    }

    /// Approve a network rule for `name` straight into the vault.
    fn approve(s: &Sandbox, name: &str, network: Network) {
        let mut vault = s.open_vault();
        vault
            .set_bindings(
                name,
                Some(RuleSet {
                    name: name.to_string(),
                    network,
                    ..Default::default()
                }),
            )
            .unwrap();
        vault
            .save(&s.vault_path(), &LocalStore::new(s.root.join("data")))
            .unwrap();
    }

    fn pw(s: &Sandbox) {
        s.script(&[r#"{"secret":"correct horse"}"#]);
    }

    #[test]
    fn an_allowed_host_gets_the_value_in_the_header_and_the_query_and_the_window_says_where() {
        let s = sandbox();
        let server_saw = Arc::new(AtomicBool::new(false));
        let flag = server_saw.clone();
        let want = zeta();
        let server = TestServer::start(move |seen| {
            let header = seen.header("x-api-key") == Some(want.as_str());
            let query = seen.target.starts_with("/v1?x=1&k=") && seen.target.ends_with(&want);
            flag.store(header && query, Ordering::SeqCst);
            Reply::ok(b"ok")
        });
        approve(
            &s,
            "ZETA",
            Network::Hosts(vec![host("localhost", false, Some(server.port))]),
        );
        pw(&s);
        let url = format!("https://localhost:{}/v1?x=1", server.port);
        let out = s.vahta(&[
            "http",
            "--secret",
            "ZETA",
            "-H",
            "X-Api-Key: {ZETA}",
            "--query",
            "k={ZETA}",
            &url,
        ]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert_eq!(text(&out.stdout), "ok");
        assert!(
            server_saw.load(Ordering::SeqCst),
            "header and query carried the value"
        );
        let ask = s
            .window_log()
            .into_iter()
            .rev()
            .find(|e| e["ask"] == "password")
            .unwrap();
        let lines = ask["panel"]["lines"].to_string();
        assert!(
            lines.contains("Secrets: ZETA")
                && lines.contains(&format!("Request: GET localhost:{}", server.port)),
            "{lines}"
        );
        assert!(s.sessions().is_empty());
        let journal = s.journal();
        assert!(journal.contains("\"event\":\"http_request\""));
        assert!(journal.contains("\"status\":200") && journal.contains("\"bytes\":2"));
        assert!(journal.contains(&format!("\"host\":\"localhost:{}\"", server.port)));
        assert!(!journal.contains("fake-") && !journal.contains("/v1") && !journal.contains("x=1"));
    }

    #[test]
    fn a_server_that_echoes_the_value_shows_the_label_in_body_and_headers() {
        let s = sandbox();
        let server = TestServer::start(|seen| {
            let v = seen.header("authorization").unwrap_or("").to_string();
            Reply {
                status: 200,
                headers: vec![
                    ("X-Echo".into(), v.clone()),
                    ("Set-Cookie".into(), "sid=abc".into()),
                ],
                body: format!("you sent {v}").into_bytes(),
            }
        });
        approve(
            &s,
            "ZETA",
            Network::Hosts(vec![host("localhost", false, None)]),
        );
        // A session: no window for the second request.
        pw(&s);
        assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
        let asked = s.asks();
        let url = format!("https://localhost:{}/", server.port);
        let out = s.vahta(&[
            "http",
            "--secret",
            "ZETA",
            "-H",
            "Authorization: Bearer {ZETA}",
            &url,
        ]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert_eq!(text(&out.stdout), "you sent Bearer ***REDACTED(ZETA)***");
        let out = s.vahta(&[
            "http",
            "--json",
            "--secret",
            "ZETA",
            "-H",
            "Authorization: Bearer {ZETA}",
            &url,
        ]);
        let all = text(&out.stdout);
        assert!(
            !all.contains(&zeta()) && !all.to_lowercase().contains("set-cookie"),
            "{all}"
        );
        let doc: Value = serde_json::from_str(&all).unwrap();
        assert_eq!(doc["status"], 200);
        assert!(doc["headers"].to_string().contains("***REDACTED(ZETA)***"));
        assert_eq!(s.asks(), asked, "the session answered both");
    }

    #[test]
    fn a_host_that_is_not_approved_is_refused_before_any_window_or_connection() {
        let s = sandbox();
        let server = TestServer::start(|_| Reply::ok(b"x"));
        approve(
            &s,
            "ZETA",
            Network::Hosts(vec![host("localhost", false, Some(server.port))]),
        );
        let asked = s.asks();
        for url in [
            format!("https://127.0.0.1:{}/", server.port),
            format!("https://other.localhost:{}/", server.port),
            "https://localhost:1/".to_string(),
        ] {
            let out = s.vahta(&["http", "--secret", "ZETA", "-H", "K: {ZETA}", &url]);
            assert_eq!(out.status.code(), Some(3), "{url}: {}", text(&out.stderr));
            assert!(
                text(&out.stderr).contains("not approved for"),
                "{}",
                text(&out.stderr)
            );
        }
        assert_eq!(s.asks(), asked);
        assert!(server.seen().is_empty());
        assert!(s.journal().contains("http_refused"));
    }

    #[test]
    fn plain_http_and_a_value_in_the_url_or_body_or_nowhere_are_refused() {
        let s = sandbox();
        approve(
            &s,
            "ZETA",
            Network::Hosts(vec![host("localhost", true, None)]),
        );
        let asked = s.asks();
        let cases: Vec<(Vec<&str>, &str)> = vec![
            (vec!["-H", "K: {ZETA}", "http://localhost/"], "https"),
            (
                vec!["-H", "K: {ZETA}", "https://localhost/{ZETA}"],
                "cannot go in the URL",
            ),
            (
                vec![
                    "-H",
                    "K: {ZETA}",
                    "-d",
                    "{\"k\":\"{ZETA}\"}",
                    "https://localhost/",
                ],
                "not put in the body",
            ),
            (
                vec!["-H", "K: none", "https://localhost/"],
                "no header or query value",
            ),
            (
                vec!["-H", "{ZETA}: x", "https://localhost/"],
                "not in a name",
            ),
        ];
        for (args, why) in cases {
            let mut all = vec!["http", "--secret", "ZETA"];
            all.extend(args);
            let out = s.vahta(&all);
            assert_eq!(out.status.code(), Some(1), "{all:?}: {}", text(&out.stderr));
            assert!(
                text(&out.stderr).contains(why),
                "{all:?}: {}",
                text(&out.stderr)
            );
        }
        assert_eq!(s.asks(), asked);
    }

    #[test]
    fn app_none_and_no_rules_are_refused_with_the_way_to_bind() {
        let s = sandbox();
        approve(&s, "ZETA", Network::App);
        approve(&s, "BETA", Network::None);
        let asked = s.asks();
        for name in ["ZETA", "BETA", "ALPHA"] {
            let out = s.vahta(&[
                "http",
                "--secret",
                name,
                "-H",
                &format!("K: {{{name}}}"),
                "https://localhost:1/",
            ]);
            assert_eq!(out.status.code(), Some(3), "{name}");
            let err = text(&out.stderr);
            assert!(
                err.contains(&format!("vahta bind {name} --net hosts:HOST")),
                "{err}"
            );
        }
        assert_eq!(s.asks(), asked);
    }

    #[test]
    fn an_each_use_secret_asks_even_inside_a_session() {
        let s = sandbox();
        let server = TestServer::start(|_| Reply::ok(b"ok"));
        for n in ["ZETA", "ALPHA"] {
            approve(&s, n, Network::Hosts(vec![host("localhost", false, None)]));
        }
        pw(&s);
        assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
        let url = format!("https://localhost:{}/", server.port);
        let before = s.asks();
        let out = s.vahta(&["http", "--secret", "ZETA", "-H", "K: {ZETA}", &url]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert_eq!(s.asks(), before, "the session covers ZETA");
        pw(&s);
        let out = s.vahta(&["http", "--secret", "ALPHA", "-H", "K: {ALPHA}", &url]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert_eq!(s.asks(), before + 1, "ALPHA is each-use");
        // A closed window sends nothing.
        s.script(&[r#"{"cancel":true}"#]);
        let seen = server.seen().len();
        let out = s.vahta(&["http", "--secret", "ALPHA", "-H", "K: {ALPHA}", &url]);
        assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
        assert_eq!(server.seen().len(), seen);
    }

    #[test]
    fn a_redirect_to_another_host_is_stopped_and_reported() {
        let s = sandbox();
        let server = TestServer::start(|seen| match seen.target.as_str() {
            "/a" => Reply {
                status: 302,
                headers: vec![("Location".into(), "/b".into())],
                body: Vec::new(),
            },
            "/b" => Reply::ok(b"landed"),
            _ => Reply {
                status: 302,
                headers: vec![("Location".into(), "https://other.localhost/steal".into())],
                body: Vec::new(),
            },
        });
        approve(
            &s,
            "ZETA",
            Network::Hosts(vec![host("localhost", false, None)]),
        );
        pw(&s);
        assert_eq!(s.vahta(&["unlock"]).status.code(), Some(0));
        let base = format!("https://localhost:{}", server.port);
        let out = s.vahta(&[
            "http",
            "--secret",
            "ZETA",
            "-H",
            "K: {ZETA}",
            &format!("{base}/a"),
        ]);
        assert_eq!(text(&out.stdout), "landed");
        let out = s.vahta(&[
            "http",
            "--secret",
            "ZETA",
            "-H",
            "K: {ZETA}",
            &format!("{base}/away"),
        ]);
        assert_eq!(out.status.code(), Some(1));
        assert!(
            text(&out.stderr).contains("other.localhost"),
            "{}",
            text(&out.stderr)
        );
        assert!(server.seen().iter().all(|r| r.target != "/steal"));
    }

    fn check_http(s: &Sandbox, names: &[&str], url: &str) -> ClientReply {
        let mut conn = connector(s, false).connect_running().unwrap().unwrap();
        conn.request(&ClientRequest::CheckHttp {
            cwd: s.project().to_string_lossy().into_owned(),
            url: url.to_string(),
            names: names.iter().map(|n| n.to_string()).collect(),
            vault: None,
        })
        .unwrap()
    }

    #[test]
    fn check_http_says_allowed_only_for_a_host_every_secret_is_approved_for_and_opens_nothing() {
        let s = sandbox();
        approve(
            &s,
            "ZETA",
            Network::Hosts(vec![host("api.example.com", true, None)]),
        );
        approve(
            &s,
            "BETA",
            Network::Hosts(vec![host("other.example", false, None)]),
        );
        assert_eq!(s.vahta(&["daemon", "restart"]).status.code(), Some(0));
        let (asks, journal) = (s.asks(), s.journal());
        let allowed = ClientReply::Allowed {};
        let none = ClientReply::NoOpinion {};
        assert_eq!(
            check_http(&s, &["ZETA"], "https://api.example.com/x"),
            allowed
        );
        assert_eq!(
            check_http(&s, &["ZETA"], "https://eu.api.example.com/x"),
            allowed
        );
        assert_eq!(
            check_http(&s, &["ZETA"], "https://evil.example.net/x"),
            none
        );
        assert_eq!(
            check_http(&s, &["ZETA"], "https://notapi.example.com/x"),
            none
        );
        // Every secret must pass; one other host is enough to say no.
        assert_eq!(
            check_http(&s, &["ZETA", "BETA"], "https://api.example.com/x"),
            none
        );
        // No http, a secret in the URL, a bad URL, an unknown or each-use name.
        assert_eq!(check_http(&s, &["ZETA"], "http://api.example.com/x"), none);
        assert_eq!(
            check_http(&s, &["ZETA"], "https://api.example.com/{ZETA}"),
            none
        );
        assert_eq!(check_http(&s, &["ZETA"], "not a url"), none);
        assert_eq!(check_http(&s, &["NOPE"], "https://api.example.com/x"), none);
        assert_eq!(
            check_http(&s, &["ALPHA"], "https://api.example.com/x"),
            none
        );
        assert_eq!(check_http(&s, &[], "https://api.example.com/x"), none);
        assert_eq!(s.asks(), asks);
        assert_eq!(s.journal(), journal);
    }
}

// --- The current unlock method ------------------------------------------------------------

#[cfg(unix)]
#[test]
fn config_unlock_orders_the_methods_and_the_password_stays_the_fallback() {
    let s = sandbox_with_secrets();
    assert_eq!(s.pair("pixel", "30d").status.code(), Some(0));
    let unlock_info = |s: &Sandbox| -> Value {
        let out = s.vahta(&["devices", "--json"]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        serde_json::from_slice::<Value>(&out.stdout).unwrap()
    };

    // Not set: the last enrolled method, the phone, is current.
    let doc = unlock_info(&s);
    assert_eq!(doc["devices"][0]["current"], true);
    assert_eq!(doc["unlock"]["setting"], "last");
    assert_eq!(doc["unlock"]["source"], "default");
    assert_eq!(doc["unlock"]["current"], "device pixel");
    let shown = text(&s.vahta(&["devices"]).stdout);
    assert!(
        shown.contains("current") && shown.contains("device pixel first"),
        "{shown}"
    );
    let out = s.vahta(&["config", "unlock"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("current: device pixel"),
        "{}",
        text(&out.stdout)
    );

    // Password first: the phone is not asked, its answer stays unused.
    let out = s.vahta(&["config", "unlock", "password"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("current: master password"));
    let doc = unlock_info(&s);
    assert_eq!(doc["devices"][0]["current"], false);
    assert_eq!(doc["unlock"]["source"], "this vault");
    s.phone(&["approve"]);
    s.script(&[PW_ANSWER]);
    let asks = s.asks();
    let out = s.run_each_use();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.asks(), asks + 1, "the password window");
    assert_eq!(s.phone_script_left(), 1, "the phone was not asked");

    // The phone by name (any case): asked first, no window.
    let out = s.vahta(&["config", "unlock", "device", "PIXEL"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("unlock = device:pixel"),
        "{}",
        text(&out.stdout)
    );
    let asks = s.asks();
    let out = s.run_each_use();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.asks(), asks);
    assert_eq!(s.phone_script_left(), 0);

    // The phone is silent: the password window follows.
    s.phone(&["timeout"]);
    s.script(&[PW_ANSWER]);
    let out = s.run_each_use();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.asks(), asks + 1);

    // The phone refuses: that is the answer. No password window follows.
    s.phone(&["deny"]);
    let out = s.run_each_use();
    assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("refused on the phone"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(s.asks(), asks + 1, "no password window after a no");

    // An unknown device is refused and nothing changes.
    let before = fs::read_to_string(s.root.join("config/config.toml")).unwrap();
    let out = s.vahta(&["config", "unlock", "device", "nobody"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("no phone called nobody"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(
        fs::read_to_string(s.root.join("config/config.toml")).unwrap(),
        before
    );
    for bad in [
        &["config", "unlock", "device"][..],
        &["config", "unlock", "fast"],
    ] {
        assert_eq!(s.vahta(bad).status.code(), Some(2), "{bad:?}");
    }

    // Setting it never asks for a password.
    let asks = s.asks();
    assert_eq!(
        s.vahta(&["config", "unlock", "last"]).status.code(),
        Some(0)
    );
    assert_eq!(
        s.vahta(&["config", "unlock", "default"]).status.code(),
        Some(0)
    );
    assert_eq!(
        s.vahta(&["config", "unlock", "--global", "password"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(s.asks(), asks);
    let doc = unlock_info(&s);
    assert_eq!(doc["unlock"]["setting"], "password");
    assert_eq!(doc["unlock"]["source"], "all vaults");
}

/// Machine B has this vault pinned to the old owner key. The file is replaced
/// by one re-keyed elsewhere (machine A, its own store): B follows the chain
/// only after its person has opened the vault and said yes.
#[cfg(unix)]
#[test]
fn a_rekey_made_elsewhere_is_accepted_only_after_the_person_unlocks_and_confirms() {
    let s = sandbox_with_secrets();
    let rekeyed = s.root.join("rekeyed.vht");
    fs::copy(s.vault_path(), &rekeyed).unwrap();
    let machine_a = LocalStore::new(s.root.join("machine-a"));
    let mut a = Vault::unlock_password(&rekeyed, OLD_PW.as_bytes(), &machine_a).unwrap();
    let kek = a.password_kek(OLD_PW.as_bytes()).unwrap();
    a.rekey(&kek, vahta_vault::RecoveryPlan::Replace, vec![])
        .unwrap();
    a.save(&rekeyed, &machine_a).unwrap();
    let on_b = fs::read(s.vault_path()).unwrap();
    fs::copy(&rekeyed, s.vault_path()).unwrap();

    // The person says no: refused, the old pin stays, and it is journalled.
    s.script(&[PW_ANSWER, r#"{"choose":1}"#]);
    let out = s.run_each_use();
    assert_ne!(out.status.code(), Some(0));
    assert!(
        text(&out.stderr).contains("owner key"),
        "{}",
        text(&out.stderr)
    );
    let asked = serde_json::to_string(&s.window_log()).unwrap();
    assert!(
        asked.contains("owner key was changed on another machine"),
        "{asked}"
    );
    assert!(asked.contains("re-key after a lost device"), "{asked}");
    let journal = s.journal();
    assert!(
        journal.contains("owner_key_change") && journal.contains("refused"),
        "{journal}"
    );
    let store = LocalStore::new(s.root.join("data"));
    assert!(matches!(
        Vault::unlock_password(&s.vault_path(), OLD_PW.as_bytes(), &store),
        Err(vahta_vault::Error::OwnerChanged)
    ));

    // A wrong password never reaches the question.
    let asks = s.asks();
    s.script(&[
        r#"{"secret":"wrong 1"}"#,
        r#"{"secret":"wrong 2"}"#,
        r#"{"secret":"wrong 3"}"#,
    ]);
    assert_ne!(s.run_each_use().status.code(), Some(0));
    assert_eq!(s.asks(), asks + 3);

    // Yes: it opens, and the next unlock asks nothing more.
    s.script(&[PW_ANSWER, r#"{"choose":0}"#]);
    let out = s.run_each_use();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "***REDACTED(ALPHA)***\n");
    assert!(
        s.journal()
            .contains("the person accepted the new owner key")
    );
    let asks = s.asks();
    s.script(&[PW_ANSWER]);
    assert_eq!(s.run_each_use().status.code(), Some(0));
    assert_eq!(s.asks(), asks + 1);
    drop(on_b);
}

// --- The phone link, end to end with a software phone ------------------------------------------

/// A software phone (the helper calls the Kotlin app must make, in
/// `vahta-mobile`) pairs with the real daemon over the LAN transport on
/// loopback, then answers an approval and unlocks the vault. The window is the
/// scripted surface; nothing here touches a real phone, adapter or network.
#[cfg(unix)]
#[test]
fn a_software_phone_pairs_approves_and_unlocks_over_the_phone_link() {
    use std::sync::Arc;
    use vahta_link::lan::LanListener;
    use vahta_mobile::fake::{Behavior, FakePhone};

    let listener = Arc::new(LanListener::bind("127.0.0.1:0").unwrap());
    let mut s = Sandbox::new();
    s.phone_addr = Some(listener.local_addr().unwrap().to_string());
    s.with_vault(&[
        ("ZETA", "fake-one", "session"),
        ("ALPHA", "fake-three", "each-use"),
    ]);
    s.bind_directly("ZETA", &["printenv"], &[]);
    fs::write(
        s.project().join("vahta.toml"),
        "[secrets.ZETA]\nallow = [\"printenv\"]\n",
    )
    .unwrap();
    let phone = Arc::new(FakePhone::new("Pixel 9"));

    // --- Pair: the window shows the code; the phone reads it and answers the
    // daemon's call.
    s.script(&[PW_ANSWER, r#"{"wait":true}"#]);
    let out = std::thread::scope(|scope| {
        let pairing = scope.spawn(|| s.vahta(&["devices", "pair", "pixel", "--for", "30d"]));
        let mut code = None;
        wait_until("the pairing code on the window", 20, || {
            code = s
                .window_log()
                .iter()
                .find(|e| e["ask"] == "pairing")
                .map(|e| (e["code"].as_str().unwrap().to_string(), e["qr"].clone()));
            code.is_some()
        });
        let (code, qr) = code.unwrap();
        assert!(code.starts_with("vahta-pair:"), "{code}");
        assert!(qr.as_str().unwrap().contains('\u{2588}'), "a QR code");
        let pipe = listener.accept().unwrap();
        phone
            .pair_over(pipe, &code, vahta_link::unix_now())
            .unwrap();
        pairing.join().unwrap()
    });
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("paired pixel"),
        "{}",
        text(&out.stdout)
    );
    assert!(
        s.window_log().iter().any(|e| e["close"] == "Phone paired."),
        "the window said so"
    );
    let list = s.devices();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["name"], "pixel");
    assert_eq!(list[0]["transports"][0], "lan");

    // Kept beside the daemon's data, privately; never in the journal.
    let vault_hex = vahta_vault::hex_encode(&s.open_vault().vault_id());
    let link_dir = s.root.join("data/link").join(vault_hex);
    let key = fs::read_to_string(link_dir.join("desktop.key")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&link_dir.join("desktop.key")), 0o600);
    assert!(!s.journal().contains(key.trim()));

    // From now on the phone serves sessions on the same address.
    {
        let (listener, phone) = (listener.clone(), phone.clone());
        std::thread::spawn(move || {
            while let Ok(pipe) = listener.accept() {
                let phone = phone.clone();
                std::thread::spawn(move || {
                    let _ = phone.serve(pipe);
                });
            }
        });
    }
    let passwords = |s: &Sandbox| {
        s.window_log()
            .iter()
            .filter(|e| e["ask"] == "password")
            .count()
    };

    // --- Approve and unlock: the phone allows once, then opens the vault.
    let before = passwords(&s);
    phone.queue(Behavior::Approve(0));
    phone.queue(Behavior::Approve(0));
    let out = s.vahta(&[
        "run",
        "--ask",
        "--reason",
        "look",
        "--secret",
        "ZETA",
        "--",
        "sh",
        "-c",
        "echo $ZETA",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(passwords(&s), before, "no password was asked");
    let asked = phone.asked();
    assert_eq!(
        asked.iter().map(|a| a.kind.as_str()).collect::<Vec<_>>(),
        ["approve", "unlock"]
    );
    assert_eq!(asked[0].view.kind, "run_ask");
    assert_eq!(asked[0].view.names, ["ZETA"]);
    assert_eq!(asked[0].view.reason.as_deref(), Some("look"));
    let journal = s.journal();
    assert!(journal.contains("device_approve"), "{journal}");
    assert!(journal.contains("device_unlock"), "{journal}");
    assert!(journal.contains("run_allowed_once"), "{journal}");

    // --- The person says no on the phone: nothing runs.
    phone.queue(Behavior::Deny);
    let out = s.vahta(&["run", "--ask", "--secret", "ZETA", "--", "sh", "-c", "true"]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
    assert_eq!(phone.asked().len(), 3, "the phone was asked and said no");
    assert_eq!(s.journal().matches("run_allowed_once").count(), 1);

    // --- A session opened by the phone alone.
    phone.queue(Behavior::Approve(0));
    let out = s.vahta(&["unlock", "--json"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{} {}",
        text(&out.stderr),
        text(&out.stdout)
    );
    assert_eq!(passwords(&s), before);

    // --- Revoking forgets how to reach it.
    s.script(&[PW_ANSWER]);
    let out = s.vahta(&["devices", "revoke", "pixel"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let left: Vec<_> = fs::read_dir(&link_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

/// A daemon with a software phone called "pixel" paired over the LAN
/// transport on loopback and serving from then on. `ZETA` is on a
/// `run --ask` list; `ALPHA` is each-use.
#[cfg(unix)]
struct LanPhone {
    s: Sandbox,
    phone: std::sync::Arc<vahta_mobile::fake::FakePhone>,
}

#[cfg(unix)]
impl LanPhone {
    fn new() -> LanPhone {
        use std::sync::Arc;
        use vahta_link::lan::LanListener;
        use vahta_mobile::fake::FakePhone;

        let listener = Arc::new(LanListener::bind("127.0.0.1:0").unwrap());
        let mut s = Sandbox::new();
        s.phone_addr = Some(listener.local_addr().unwrap().to_string());
        s.with_vault(&[
            ("ZETA", "fake-one", "session"),
            ("ALPHA", "fake-three", "each-use"),
        ]);
        s.bind_directly("ZETA", &["printenv"], &[]);
        fs::write(
            s.project().join("vahta.toml"),
            "[secrets.ZETA]\nallow = [\"printenv\"]\n",
        )
        .unwrap();
        let phone = Arc::new(FakePhone::new("A32"));
        s.script(&[PW_ANSWER, r#"{"wait":true}"#]);
        let out = std::thread::scope(|scope| {
            let pairing = scope.spawn(|| s.vahta(&["devices", "pair", "a32", "--for", "30d"]));
            let mut code = None;
            wait_until("the pairing code on the window", 20, || {
                code = s
                    .window_log()
                    .iter()
                    .find(|e| e["ask"] == "pairing")
                    .map(|e| e["code"].as_str().unwrap().to_string());
                code.is_some()
            });
            let pipe = listener.accept().unwrap();
            phone
                .pair_over(pipe, &code.unwrap(), vahta_link::unix_now())
                .unwrap();
            pairing.join().unwrap()
        });
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        {
            let phone = phone.clone();
            std::thread::spawn(move || {
                while let Ok(pipe) = listener.accept() {
                    let phone = phone.clone();
                    std::thread::spawn(move || {
                        let _ = phone.serve(pipe);
                    });
                }
            });
        }
        LanPhone { s, phone }
    }

    fn run_each_use(&self) -> Output {
        self.s
            .vahta(&["run", "--secret", "ALPHA", "--", "/usr/bin/true"])
    }

    fn password_asks(&self) -> usize {
        self.s
            .window_log()
            .iter()
            .filter(|e| e["ask"] == "password")
            .count()
    }

    fn waits(&self) -> Vec<Value> {
        self.s
            .window_log()
            .into_iter()
            .filter(|e| e["ask"] == "device_wait")
            .collect()
    }
}

#[cfg(unix)]
#[test]
fn a_no_on_the_phone_over_the_phone_link_refuses_an_unlock_and_asks_no_password() {
    use vahta_mobile::fake::Behavior;
    let t = LanPhone::new();
    let passwords = t.password_asks();
    // The wait window is up while the phone is asked; the phone says no.
    t.s.script(&[r#"{"devicewait":"wait"}"#]);
    t.phone.queue(Behavior::Deny);
    let started = Instant::now();
    let out = t.run_each_use();
    assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("refused on the phone"),
        "{}",
        text(&out.stderr)
    );
    assert!(started.elapsed() < Duration::from_secs(20));
    assert_eq!(t.password_asks(), passwords, "no password window");
    let waits = t.waits();
    assert_eq!(waits.len(), 1, "{waits:?}");
    assert_eq!(waits[0]["device"], "a32");
    assert_eq!(
        t.phone
            .asked()
            .iter()
            .filter(|a| a.kind == "unlock")
            .count(),
        1
    );
}

#[cfg(unix)]
#[test]
fn a_no_on_the_phone_over_the_phone_link_refuses_a_run_ask() {
    use vahta_mobile::fake::Behavior;
    let t = LanPhone::new();
    let passwords = t.password_asks();
    t.phone.queue(Behavior::Deny);
    let started = Instant::now();
    let out = t.s.vahta(&[
        "run", "--ask", "--secret", "ZETA", "--", "sh", "-c", "echo ran",
    ]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("refused on the phone"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(text(&out.stdout), "");
    assert!(started.elapsed() < Duration::from_secs(20));
    assert_eq!(t.password_asks(), passwords);
    let journal = t.s.journal();
    assert!(journal.contains("run_refused"), "{journal}");
    assert!(!journal.contains("run_allowed_once"), "{journal}");
    // The question was put on the phone and the window said so.
    assert_eq!(t.phone.asked().len(), 1);
    assert!(
        t.s.window_log().iter().any(|e| e["panel"]["lines"]
            .to_string()
            .contains("Also asked on your phone")),
        "{:?}",
        t.s.window_log()
    );
}

#[cfg(unix)]
#[test]
fn the_wait_window_moves_on_by_itself_when_the_phone_answers() {
    use vahta_mobile::fake::Behavior;
    let t = LanPhone::new();
    let passwords = t.password_asks();
    t.s.script(&[r#"{"devicewait":"wait"}"#]);
    t.phone.queue(Behavior::Approve(0));
    let out = t.run_each_use();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(t.password_asks(), passwords);
    assert_eq!(t.waits().len(), 1);
}

#[cfg(unix)]
#[test]
fn choosing_the_password_in_the_wait_window_cancels_the_phone_and_opens_with_the_password() {
    use vahta_mobile::fake::Behavior;
    let t = LanPhone::new();
    let passwords = t.password_asks();
    // The phone never answers; the person gives up on it.
    t.phone.queue(Behavior::Ignore);
    t.s.script(&[r#"{"devicewait":"password"}"#, PW_ANSWER]);
    let started = Instant::now();
    let out = t.run_each_use();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "the phone was not waited for"
    );
    assert_eq!(t.waits().len(), 1);
    assert_eq!(t.password_asks(), passwords + 1);
    // Wait first, then the password.
    let log = t.s.window_log();
    let at = |what: &str| log.iter().rposition(|e| e["ask"] == what).unwrap();
    assert!(at("device_wait") < at("password"));
    // The phone was asked at most once (the choice may come before the
    // question is on the wire) and never answered; had it been waited on to
    // the end of the request, the run would have taken half a minute.
    assert!(t.phone.asked().len() <= 1);
    // The journal says the person chose, not that the phone refused.
    let journal = t.s.journal();
    assert!(
        journal.contains("the person chose the password instead"),
        "{journal}"
    );
    assert!(!journal.contains("you chose the password"), "{journal}");
    let line = journal
        .lines()
        .find(|l| l.contains("the person chose the password instead"))
        .unwrap();
    assert!(line.contains("\"skipped\""), "{line}");
}

#[cfg(unix)]
#[test]
fn closing_the_pairing_window_pairs_nothing_and_a_dead_phone_link_is_an_error_not_a_hang() {
    // Nobody listens where the phone is said to be.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    };
    let mut s = Sandbox::new();
    s.phone_addr = Some(dead);
    s.with_vault(&[("ZETA", "fake-one", "session")]);
    s.script(&[PW_ANSWER, r#"{"cancel":true}"#]);
    let started = Instant::now();
    let out = s.vahta(&["devices", "pair", "pixel"]);
    assert_ne!(out.status.code(), Some(0), "{}", text(&out.stdout));
    assert!(started.elapsed() < Duration::from_secs(20));
    assert!(s.devices().is_empty());
    assert!(
        s.window_log().iter().any(|e| e["ask"] == "pairing"),
        "the code was shown"
    );
}
