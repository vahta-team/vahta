//! The connectors vault (`--connector`), against a real daemon in a sandbox with
//! a scripted prompt window and a temp HOME, like `remote.rs`.
//!
//! The harness is stood in for by the test process itself: a test build of the
//! daemon takes `VAHTA_TEST_CONNECTOR_PARENT` as the name of a parent process
//! that counts as every harness. A sandbox made without it has the test process
//! for what it is, a parent that is no harness.

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
            .env_remove("VAHTA_TEST_IDLE_SECONDS")
            .env("VAHTA_TEST_SURFACE", self.root.join("script.jsonl"))
            .env("VAHTA_TEST_SURFACE_LOG", self.root.join("surface.log"))
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .env("VAHTA_TEST_RELAY_CONNECT", "127.0.0.1")
            .env("VAHTA_TEST_MUTE_REFUSAL_ALARM", "1");
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
        let s = Sandbox::new(as_harness);
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

    fn unlock(&self) {
        self.script(&[PW_ANSWER]);
        let out = self.vahta(&self.root, &["unlock", "--connector", "--for", "8h"]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert!(text(&out.stdout).contains("connectors session"));
    }

    fn run_connector(&self, name: &str, command: &[&str]) -> Output {
        let mut args = vec!["run", "--connector", "--secret", name, "--"];
        args.extend_from_slice(command);
        self.vahta(&self.root, &args)
    }
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
fn with_no_session_a_launch_is_refused_at_once_and_the_refusal_is_seen_in_status() {
    let s = Sandbox::with_connector(true);
    let windows = s.windows();
    let started = std::time::Instant::now();
    let out = s.run_connector(KEY, &["printenv", KEY]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "the refusal is fast"
    );
    let err = text(&out.stderr);
    assert!(err.contains("no connectors session"), "{err}");
    assert!(err.contains("vahta unlock --connector"), "{err}");
    assert!(!text(&out.stdout).contains(&value_of("a")));
    assert_eq!(s.windows(), windows, "no window was opened");
    assert!(s.journal().contains("no_session"));
    // The person finds out in `vahta daemon status` and in `list --connector`.
    let status = s.vahta(&s.root, &["daemon", "status"]);
    let shown = text(&status.stdout);
    assert!(
        shown.contains(&format!("connector {KEY} was refused at"))
            && shown.contains("no connectors session")
            && shown.contains("vahta unlock --connector"),
        "{shown}"
    );
    let list = s.vahta(&s.root, &["list", "--connector"]);
    assert!(text(&list.stdout).contains(&format!("connector {KEY} was refused at")));
    // Unlocking and starting again works, with no window for the run.
    s.unlock();
    let windows = s.windows();
    let out = s.run_connector(KEY, &["printenv", KEY]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.windows(), windows);
}

#[test]
fn a_parent_that_is_no_harness_is_refused_and_marked_suspicious() {
    let s = Sandbox::with_connector(false);
    s.unlock();
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
    s.unlock();
    let out = s.run_connector(KEY, &["printenv", KEY]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("no harnesses or no allow rule"));
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
    let out = s.run_connector(KEY, &["printenv", KEY]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("no connectors session"));
    // And the connectors session covers no project secret.
    s.unlock();
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
    let net = format!("hosts:other.localhost:{}", server.port);
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
    s.unlock();
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
