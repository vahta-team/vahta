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

use vahta_daemon::client::{ClientError, Connector};
use vahta_daemon::paths::Paths;
use vahta_daemon::protocol::{
    ClientReply, ClientRequest, Hello, HelloKind, HelloReply, PROTOCOL, read_frame, write_frame,
};

static NEXT: AtomicU32 = AtomicU32::new(0);

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
            .env_remove("VAHTA_TEST_IDLE_SECONDS");
        cmd
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
