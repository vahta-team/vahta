//! `vahta unlock`, `lock` and `sessions`.
//!
//! `vahta unlock` is meant to be called by the agent. A window opens, the
//! person reads what is being approved and types the password, and from then on
//! `vahta run` from that agent's process tree needs no window. `lock` and
//! `sessions kill` end sessions without a password: they can only take access
//! away.

use std::io::Write;

use serde_json::json;
use vahta_ipc::protocol::{ClientReply, ClientRequest, DurationSpec, SessionInfo};

use crate::daemon_cmd;
use crate::{EXIT_CLEAN, EXIT_DAEMON, EXIT_FAILED, EXIT_USAGE, Env};

pub const UNLOCK_USAGE: &str = "\
usage: vahta unlock [--secret NAME]... [--for DURATION] [--label TEXT] [--json]

Open a session. A window opens where you read what is being approved and type
the vault password; then `vahta run` from this process tree (the agent that
called this, and everything it starts) uses the secrets with no window.

  --secret NAME     only this secret (repeatable); without it, every
                    session-tier secret in the project's vault. Naming an
                    each-use secret, or one that does not exist, refuses the
                    whole request (exit 3) before any window opens.
  --for DURATION    how long: 30m (default; session_minutes in config.toml),
                    2h, 90s, 1h30m, a clock (1:30:00), or `forever` for
                    until revoked
  --label TEXT      a description for the window, shown marked as coming from
                    the agent and not verified (one line, 200 characters)
  --json            machine-readable result, and refusals

A session lets `vahta run` use secrets and nothing else: revealing, copying,
exporting and every change always ask for the password.
";

pub const LOCK_USAGE: &str = "\
usage: vahta lock [--all] [--json]

End this project's sessions, or with --all every session. No password is needed:
this can only take access away. A command that is already running keeps the
values it was given; ending a session cannot take them back.

  --all     every session, not only this project's
  --json    machine-readable result
";

pub const SESSIONS_USAGE: &str = "\
usage: vahta sessions [--json]
       vahta sessions kill ID

List the sessions the daemon holds, or end one and every session below it. No
password is needed. The list shows ids, the secrets covered, the process each
belongs to, the time left and how many times it has been used; never a value.

  --json    machine-readable list
";

/// `30m`, `2h`, `90s`, `1h30m`, `2d`, a clock (`1:30:00`) or `forever`.
pub fn parse_duration(text: &str) -> Result<DurationSpec, String> {
    let text = text.trim().to_lowercase();
    if text == "forever" {
        return Ok(DurationSpec::Forever {});
    }
    vahta_ipc::duration::parse_secs(&text)
        .map(|secs| DurationSpec::Secs { secs })
        .ok_or_else(|| {
            format!("invalid --for value: {text:?} (use 30m, 2h, 90s, 1h30m, 1:30:00, or forever)")
        })
}

fn human_secs(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h{:02}m", secs / 3600, secs % 3600 / 60)
    } else if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

fn left_text(info: &SessionInfo) -> String {
    info.remaining_secs
        .map_or("until revoked".to_string(), human_secs)
}

pub fn run_unlock(
    args: &[String],
    env: &Env,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let mut names: Vec<String> = Vec::new();
    let mut duration = DurationSpec::Default {};
    let mut label = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        let mut value = |what: &str| -> Result<String, String> {
            let v = args
                .get(i)
                .cloned()
                .ok_or_else(|| format!("{what} expects a value"))?;
            i += 1;
            Ok(v)
        };
        let result = match a {
            "-h" | "--help" => {
                let _ = stdout.write_all(UNLOCK_USAGE.as_bytes());
                return EXIT_CLEAN;
            }
            "--json" => {
                json = true;
                Ok(())
            }
            "--secret" => value("--secret").map(|v| names.push(v)),
            "--for" => value("--for")
                .and_then(|v| parse_duration(&v))
                .map(|d| duration = d),
            "--label" => value("--label").map(|v| label = Some(v)),
            other => Err(format!("unrecognised argument: {other}")),
        };
        if let Err(msg) = result {
            let _ = write!(stderr, "vahta unlock: error: {msg}\n\n{UNLOCK_USAGE}");
            return EXIT_USAGE;
        }
    }
    let request = ClientRequest::Unlock {
        cwd: env.cwd.to_string_lossy().into_owned(),
        names: (!names.is_empty()).then_some(names),
        duration,
        label,
    };
    let mut conn = match daemon_cmd::connect(env, "unlock", stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };
    match conn.request(&request) {
        Ok(ClientReply::Session(info)) => {
            if json {
                let _ = writeln!(stdout, "{}", json!({"ok": true, "session": &*info}));
            } else {
                let _ = writeln!(
                    stdout,
                    "session {} open for {}",
                    info.id,
                    info.names.join(", ")
                );
                let _ = writeln!(
                    stdout,
                    "belongs to {} (pid {}) and everything it starts; {}",
                    info.anchor_exe,
                    info.anchor_pid,
                    match info.remaining_secs {
                        Some(s) => format!("lasts {}", human_secs(s)),
                        None => "lasts until revoked".to_string(),
                    }
                );
            }
            EXIT_CLEAN
        }
        Ok(other) => daemon_cmd::report("unlock", &other, json, stdout, stderr),
        Err(e) => {
            let _ = writeln!(stderr, "vahta unlock: error: {e}");
            EXIT_DAEMON
        }
    }
}

pub fn run_lock(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let (mut all, mut json) = (false, false);
    for a in args {
        match a.as_str() {
            "--all" => all = true,
            "--json" => json = true,
            "-h" | "--help" => {
                let _ = stdout.write_all(LOCK_USAGE.as_bytes());
                return EXIT_CLEAN;
            }
            other => {
                let _ = write!(
                    stderr,
                    "vahta lock: error: unrecognised argument: {other}\n\n{LOCK_USAGE}"
                );
                return EXIT_USAGE;
            }
        }
    }
    let request = ClientRequest::Lock {
        cwd: env.cwd.to_string_lossy().into_owned(),
        all,
    };
    daemon_cmd::request(env, "lock", &request, json, stdout, stderr)
}

fn list_text(sessions: &[SessionInfo]) -> String {
    if sessions.is_empty() {
        return "no sessions".to_string();
    }
    let mut rows = vec![vec![
        "ID".to_string(),
        "PARENT".to_string(),
        "SECRETS".to_string(),
        "BELONGS TO".to_string(),
        "LEFT".to_string(),
        "USES".to_string(),
        "PROJECT".to_string(),
    ]];
    for s in sessions {
        rows.push(vec![
            s.id.clone(),
            s.parent.clone().unwrap_or_else(|| "-".to_string()),
            s.names.join(","),
            format!("{} ({})", s.anchor_exe, s.anchor_pid),
            left_text(s),
            s.uses.to_string(),
            s.project.clone(),
        ]);
    }
    let widths: Vec<usize> = (0..7)
        .map(|c| rows.iter().map(|r| r[c].chars().count()).max().unwrap_or(0))
        .collect();
    rows.iter()
        .map(|r| {
            r.iter()
                .enumerate()
                .map(|(c, cell)| format!("{cell:<w$}", w = widths[c]))
                .collect::<Vec<_>>()
                .join("  ")
                .trim_end()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn run_sessions(
    args: &[String],
    env: &Env,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    if args.first().map(String::as_str) == Some("kill") {
        return match args {
            [_, id] if !id.starts_with('-') => daemon_cmd::request(
                env,
                "sessions",
                &ClientRequest::SessionKill { id: id.clone() },
                false,
                stdout,
                stderr,
            ),
            _ => {
                let _ = write!(
                    stderr,
                    "vahta sessions: error: kill expects one session id\n\n{SESSIONS_USAGE}"
                );
                EXIT_USAGE
            }
        };
    }
    let mut json = false;
    for a in args {
        match a.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                let _ = stdout.write_all(SESSIONS_USAGE.as_bytes());
                return EXIT_CLEAN;
            }
            other => {
                let _ = write!(
                    stderr,
                    "vahta sessions: error: unrecognised argument: {other}\n\n{SESSIONS_USAGE}"
                );
                return EXIT_USAGE;
            }
        }
    }
    // Listing never starts a daemon: with none running there are no sessions.
    let connector = match daemon_cmd::connector(env, false) {
        Ok(c) => c,
        Err(msg) => {
            let _ = writeln!(stderr, "vahta sessions: error: {msg}");
            return EXIT_DAEMON;
        }
    };
    let sessions = match connector.connect_running() {
        Ok(None) => Vec::new(),
        Ok(Some(mut conn)) => match conn.request(&ClientRequest::Sessions {}) {
            Ok(ClientReply::Sessions { sessions }) => sessions,
            Ok(_) | Err(_) => {
                let _ = writeln!(stderr, "vahta sessions: error: the daemon did not answer");
                return EXIT_FAILED;
            }
        },
        Err(e) => {
            let _ = writeln!(stderr, "vahta sessions: error: {e}");
            return EXIT_DAEMON;
        }
    };
    if json {
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&json!({"sessions": sessions})).unwrap_or_default()
        );
    } else {
        let _ = writeln!(stdout, "{}", list_text(&sessions));
    }
    EXIT_CLEAN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        let secs = |t: &str| match parse_duration(t).unwrap() {
            DurationSpec::Secs { secs } => secs,
            other => panic!("{other:?}"),
        };
        assert_eq!(secs("30m"), 1800);
        assert_eq!(secs("2h"), 7200);
        assert_eq!(secs("90s"), 90);
        assert_eq!(secs("1h30m"), 5400);
        assert_eq!(secs(" 2D "), 172_800);
        assert_eq!(parse_duration("forever").unwrap(), DurationSpec::Forever {});
        for bad in ["", "30", "m", "1x", "-5m", "1.5h", "5m3", "forevah"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
        // No overflow.
        assert!(parse_duration("99999999999999999999d").is_err());
        assert!(parse_duration("18446744073709551615d").is_err());
    }
}
