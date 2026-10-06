//! `vahta daemon run|status|stop|restart`, and the way every other command
//! reaches the daemon.
//!
//! The daemon is started on demand by the command line, never by the hook, one
//! per user, and exits when idle. `run` is the daemon itself, in this process;
//! the others talk to it.

use std::ffi::OsString;
use std::io::Write;

use serde_json::json;
use vahta_daemon::client::{ClientError, Connection, Connector};
use vahta_daemon::config::Config;
use vahta_daemon::paths::Paths;
use vahta_daemon::protocol::{ClientReply, ClientRequest, RefusalKind, StatusInfo};
use vahta_daemon::server::{self, Options, ServerError};

use crate::{EXIT_CANCELLED, EXIT_CLEAN, EXIT_DAEMON, EXIT_FAILED, EXIT_REFUSED, EXIT_USAGE, Env};

pub const DAEMON_USAGE: &str = "\
usage: vahta daemon run
       vahta daemon status [--json]
       vahta daemon stop
       vahta daemon restart

The daemon owns the vault: it holds the sessions, opens the prompt window and
runs `vahta run`. One runs per user. The commands start it when they need it
and it exits after ten idle minutes (idle_minutes in config.toml).

  run       run the daemon in this process (the commands start it this way)
  status    say whether it is running; exit 5 when it is not
  stop      stop it; this ends every session
  restart   stop it and start a fresh one; this ends every session

options:
  --json                 machine-readable status
  -h, --help             show this help
";

/// The paths for this process: the store root the command line already worked
/// out, and the runtime and config directories from the environment.
pub fn paths(env: &Env) -> Result<Paths, String> {
    Paths::from_env(env.data_dir.clone()).map_err(|e| e.to_string())
}

/// How to reach the daemon, starting it if `start`.
pub fn connector(env: &Env, start: bool) -> Result<Connector, String> {
    let start = if start {
        let exe = std::env::current_exe()
            .map_err(|e| format!("cannot find the vahta executable to start the daemon: {e}"))?;
        Some(vec![
            exe.into_os_string(),
            OsString::from("daemon"),
            OsString::from("run"),
        ])
    } else {
        None
    };
    Ok(Connector {
        paths: paths(env)?,
        version: vahta_daemon::VERSION.to_string(),
        start,
    })
}

/// Connect for `command`, starting the daemon if need be. `Err` is the exit
/// code, after the reason has been written to `stderr`.
pub fn connect(env: &Env, command: &str, stderr: &mut dyn Write) -> Result<Connection, i32> {
    let connector = connector(env, true).map_err(|msg| {
        let _ = writeln!(stderr, "vahta {command}: error: {msg}");
        EXIT_DAEMON
    })?;
    connector.connect().map_err(|e| {
        let _ = writeln!(stderr, "vahta {command}: error: {e}");
        EXIT_DAEMON
    })
}

fn status_text(s: &StatusInfo) -> String {
    format!(
        "running: vahta daemon {} (pid {}), {} session(s), {} connection(s), up {}s\nruntime: {}",
        s.version, s.pid, s.sessions, s.connections, s.uptime_secs, s.runtime_dir
    )
}

pub fn run(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let mut json = false;
    let mut sub: Option<&str> = None;
    for a in args {
        match a.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                let _ = stdout.write_all(DAEMON_USAGE.as_bytes());
                return EXIT_CLEAN;
            }
            s if !s.starts_with('-') && sub.is_none() => sub = Some(s),
            other => {
                let _ = write!(
                    stderr,
                    "vahta daemon: error: unrecognised argument: {other}\n\n{DAEMON_USAGE}"
                );
                return EXIT_USAGE;
            }
        }
    }
    match sub {
        Some("run") => run_daemon(env, stderr),
        Some("status") => status(env, json, stdout, stderr),
        Some("stop") => stop(env, stdout, stderr),
        Some("restart") => restart(env, stdout, stderr),
        _ => {
            let _ = write!(stderr, "{DAEMON_USAGE}");
            EXIT_USAGE
        }
    }
}

fn run_daemon(env: &Env, stderr: &mut dyn Write) -> i32 {
    let paths = match paths(env) {
        Ok(p) => p,
        Err(msg) => {
            let _ = writeln!(stderr, "vahta daemon: error: {msg}");
            return EXIT_DAEMON;
        }
    };
    let config = match Config::load(&paths.config_file()) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "vahta daemon: error: {e}");
            return EXIT_DAEMON;
        }
    };
    let mut options = Options::new(paths, config);
    vahta_daemon::testing::apply_overrides(&mut options);
    match server::run(options) {
        Ok(()) => EXIT_CLEAN,
        // Two commands started a daemon at once and this one lost: not a
        // failure, the other is serving.
        Err(ServerError::AlreadyRunning) => EXIT_CLEAN,
        Err(e) => {
            let _ = writeln!(stderr, "vahta daemon: error: {e}");
            EXIT_DAEMON
        }
    }
}

fn running(env: &Env, stderr: &mut dyn Write) -> Result<Option<(Connector, Connection)>, i32> {
    let connector = connector(env, false).map_err(|msg| {
        let _ = writeln!(stderr, "vahta daemon: error: {msg}");
        EXIT_DAEMON
    })?;
    match connector.connect_running() {
        Ok(Some(conn)) => Ok(Some((connector, conn))),
        Ok(None) => Ok(None),
        Err(e) => {
            let _ = writeln!(stderr, "vahta daemon: error: {e}");
            Err(EXIT_DAEMON)
        }
    }
}

fn status_of(conn: &mut Connection) -> Result<StatusInfo, ClientError> {
    match conn.request(&ClientRequest::Status {})? {
        ClientReply::Status(s) => Ok(s),
        _ => Err(ClientError::Unavailable("unexpected reply".to_string())),
    }
}

fn status(env: &Env, json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let (_, mut conn) = match running(env, stderr) {
        Ok(Some(found)) => found,
        Ok(None) => {
            if json {
                let _ = writeln!(stdout, "{}", json!({"running": false}));
            } else {
                let _ = writeln!(stdout, "not running");
            }
            return EXIT_DAEMON;
        }
        Err(code) => return code,
    };
    match status_of(&mut conn) {
        Ok(s) => {
            if json {
                let doc = json!({
                    "running": true,
                    "version": s.version,
                    "pid": s.pid,
                    "sessions": s.sessions,
                    "connections": s.connections,
                    "uptime_secs": s.uptime_secs,
                    "runtime_dir": s.runtime_dir,
                });
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&doc).unwrap_or_default()
                );
            } else {
                let _ = writeln!(stdout, "{}", status_text(&s));
            }
            EXIT_CLEAN
        }
        Err(e) => {
            let _ = writeln!(stderr, "vahta daemon: error: {e}");
            EXIT_DAEMON
        }
    }
}

/// Stop a running daemon and wait for it to leave. `Ok(None)` when none was
/// running; `Ok(Some(n))` is how many sessions it was holding.
fn stop_running(env: &Env, stderr: &mut dyn Write) -> Result<Option<usize>, i32> {
    let Some((connector, mut conn)) = running(env, stderr)? else {
        return Ok(None);
    };
    let sessions = conn.daemon.sessions;
    if let Err(e) = conn.request(&ClientRequest::Stop {}) {
        let _ = writeln!(stderr, "vahta daemon: error: {e}");
        return Err(EXIT_DAEMON);
    }
    drop(conn);
    connector.wait_until_gone().map_err(|e| {
        let _ = writeln!(stderr, "vahta daemon: error: {e}");
        EXIT_DAEMON
    })?;
    Ok(Some(sessions))
}

fn stop(env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    match stop_running(env, stderr) {
        Ok(None) => {
            let _ = writeln!(stdout, "not running");
            EXIT_CLEAN
        }
        Ok(Some(n)) => {
            let _ = writeln!(stdout, "stopped ({n} session(s) ended)");
            EXIT_CLEAN
        }
        Err(code) => code,
    }
}

fn restart(env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let ended = match stop_running(env, stderr) {
        Ok(n) => n.unwrap_or(0),
        Err(code) => return code,
    };
    let mut conn = match connect(env, "daemon", stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let _ = writeln!(stdout, "restarted ({ended} session(s) ended)");
    match status_of(&mut conn) {
        Ok(s) => {
            let _ = writeln!(stdout, "{}", status_text(&s));
            EXIT_CLEAN
        }
        Err(e) => {
            let _ = writeln!(stderr, "vahta daemon: error: {e}");
            EXIT_DAEMON
        }
    }
}

/// Send `request` to the daemon, starting it if need be, and report the reply
/// the way every daemon-backed command does. Returns the exit code.
pub fn request(
    env: &Env,
    command: &str,
    request: &ClientRequest,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let mut conn = match connect(env, command, stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };
    match conn.request(request) {
        Ok(reply) => report(command, &reply, json, stdout, stderr),
        Err(e) => {
            let _ = writeln!(stderr, "vahta {command}: error: {e}");
            EXIT_DAEMON
        }
    }
}

/// Print a reply and give the exit code: 0 done, 3 refused (structured), 4
/// cancelled or timed out in the window, 1 for anything that went wrong.
pub fn report(
    command: &str,
    reply: &ClientReply,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    match reply {
        ClientReply::Done { message } => {
            if json {
                let _ = writeln!(stdout, "{}", json!({"ok": true, "message": message}));
            } else {
                let _ = writeln!(stdout, "{message}");
            }
            EXIT_CLEAN
        }
        ClientReply::Ok {} => EXIT_CLEAN,
        ClientReply::Refused(r) => {
            if json {
                let doc = json!({"ok": false, "refused": r});
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string(&doc).unwrap_or_default()
                );
            } else {
                let _ = writeln!(stderr, "vahta {command}: refused: {}", r.message);
                for n in &r.names {
                    let _ = writeln!(stderr, "  {}: {}", n.name, refusal_text(n.why));
                }
            }
            EXIT_REFUSED
        }
        ClientReply::Cancelled { message } => {
            if json {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({"ok": false, "cancelled": true, "message": message})
                );
            } else {
                let _ = writeln!(stderr, "vahta {command}: {message}");
            }
            EXIT_CANCELLED
        }
        ClientReply::Error { message } => {
            if json {
                let _ = writeln!(stdout, "{}", json!({"ok": false, "error": message}));
            } else {
                let _ = writeln!(stderr, "vahta {command}: error: {message}");
            }
            EXIT_FAILED
        }
        ClientReply::Status(_) | ClientReply::Session(_) | ClientReply::Sessions { .. } => {
            let _ = writeln!(stderr, "vahta {command}: error: unexpected reply");
            EXIT_FAILED
        }
    }
}

fn refusal_text(why: RefusalKind) -> &'static str {
    match why {
        RefusalKind::UnknownName => "not in this vault",
        RefusalKind::EachUse => {
            "an each-use secret; it needs the password every time and no session may hold it"
        }
        RefusalKind::OutOfScope => "not covered by this session",
        RefusalKind::NotASubset => "not in the parent session",
        RefusalKind::LaterDeadline => "outlasts the parent session",
        RefusalKind::NoVault => "no vault",
        RefusalKind::NothingToDo => "nothing to do",
        RefusalKind::Exists => "already exists",
        RefusalKind::NoAnchor => "no process to anchor a session to",
    }
}
