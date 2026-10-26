//! `vahta hooks pause|resume|status`: the one way for an agent to get a change
//! to a harness's hook settings.
//!
//! The hook guard refuses an agent's edit of the hook settings. An agent that
//! must make one runs `vahta hooks pause --for 15m --reason "..."`. The daemon
//! opens a window that says what is being allowed and for how long, the
//! agent's reason (marked unverified) and whose vault password it wants. When
//! the person agrees, the pause is written to `pause.json` in Vahta's data
//! directory (which the hook keeps agents out of). Vahta's hooks stay in
//! place and keep running: only the hook guard and the watchdog step aside for
//! that harness until the time is up (at most 1 hour); then the watchdog looks
//! again and asks the person about what it finds. `resume` ends a pause at once
//! and needs no password: it only restores protection.

use std::io::Write;

use vahta_ipc::duration::{human, parse_secs};
use vahta_ipc::protocol::ClientRequest;
use vahta_setup::guard::{self, DEFAULT_PAUSE_SECS, MAX_PAUSE_SECS, PauseKind};

use crate::daemon_cmd;
use crate::{EXIT_CLEAN, EXIT_USAGE, Env};

pub const USAGE: &str = "\
usage: vahta hooks pause [--for DURATION] [--reason TEXT] [--harness NAME]...
       vahta hooks resume [--harness NAME]...
       vahta hooks status [--json]

Let an agent change the hook settings of a coding agent for a while.

  pause    allow changes to Vahta's hook settings for DURATION (default 15m,
           at most 1h). A window shows the person the harnesses, the time and
           your reason (marked unverified), and asks for the approval of a
           vault it names. Vahta's hooks stay on and cannot be removed this
           way: an edit that drops them or sets disableAllHooks is refused,
           the watchdog puts them back at once if they go, and secrets,
           protected files and the alarm are still watched. It applies to the
           whole harness, not to one session.
  resume   end a pause now. No password.
  status   say which pauses are running and until when.

options:
  --for DURATION     how long (10m, 30m, 1h)
  --reason TEXT      why; shown to the person
  --harness NAME     claude, codex or cursor; repeat for several (default:
                     every harness that has Vahta's hooks)
  --json             machine-readable status
  -h, --help         show this help

A pause never removes Vahta's hooks. A change to Vahta's hook settings made
without one is refused.
";

pub fn run(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let usage_error = |stderr: &mut dyn Write, msg: &str| {
        let _ = write!(stderr, "vahta hooks: error: {msg}\n\n{USAGE}");
        EXIT_USAGE
    };
    let mut sub: Option<&str> = None;
    let mut secs: Option<u64> = None;
    let mut reason: Option<String> = None;
    let mut harnesses: Vec<String> = Vec::new();
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        match a {
            "-h" | "--help" => {
                let _ = stdout.write_all(USAGE.as_bytes());
                return EXIT_CLEAN;
            }
            "--json" => json = true,
            "--for" | "--reason" | "--harness" => {
                let Some(v) = args.get(i) else {
                    return usage_error(stderr, &format!("{a} expects a value"));
                };
                i += 1;
                match a {
                    "--for" => match parse_secs(v) {
                        Some(s) if s >= 1 => secs = Some(s),
                        _ => return usage_error(stderr, &format!("{v:?} is not a duration")),
                    },
                    "--reason" => reason = Some(v.clone()),
                    _ => {
                        if !vahta_harness::HARNESSES.contains(&v.as_str()) {
                            return usage_error(
                                stderr,
                                &format!("{v:?} is not a harness (claude, codex, cursor)"),
                            );
                        }
                        if !harnesses.contains(v) {
                            harnesses.push(v.clone());
                        }
                    }
                }
            }
            s if !s.starts_with('-') && sub.is_none() => sub = Some(s),
            other => return usage_error(stderr, &format!("unrecognised argument: {other}")),
        }
    }
    match sub {
        Some("pause") => {
            let secs = secs.unwrap_or(DEFAULT_PAUSE_SECS);
            if secs > MAX_PAUSE_SECS {
                return usage_error(
                    stderr,
                    &format!("a pause lasts at most {}", human(MAX_PAUSE_SECS)),
                );
            }
            daemon_cmd::request(
                env,
                "hooks",
                &ClientRequest::HooksPause {
                    cwd: env.cwd.display().to_string(),
                    harnesses,
                    secs,
                    reason,
                },
                json,
                stdout,
                stderr,
            )
        }
        Some("resume") => daemon_cmd::request(
            env,
            "hooks",
            &ClientRequest::HooksResume { harnesses },
            json,
            stdout,
            stderr,
        ),
        Some("status") => status(env, json, stdout, stderr),
        _ => {
            let _ = write!(stderr, "{USAGE}");
            EXIT_USAGE
        }
    }
}

fn status(env: &Env, json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let Ok(paths) = daemon_cmd::paths(env) else {
        let _ = writeln!(
            stderr,
            "vahta hooks: error: cannot tell where Vahta keeps its files"
        );
        return crate::EXIT_FAILED;
    };
    let now = vahta_ipc::state::now();
    let pauses: Vec<_> = guard::read_pauses(&paths.data)
        .into_iter()
        .filter(|p| p.until > now)
        .collect();
    if json {
        let items: Vec<_> = pauses
            .iter()
            .map(|p| {
                serde_json::json!({
                    "harness": p.harness,
                    "until": p.until,
                    "seconds_left": p.until - now,
                    "reason": p.reason,
                    "allows": match p.kind {
                        PauseKind::Edit => "hook_settings_edits",
                        PauseKind::Off => "hooks_removed",
                    },
                })
            })
            .collect();
        let _ = writeln!(stdout, "{}", serde_json::json!({"paused": items}));
        return EXIT_CLEAN;
    }
    if pauses.is_empty() {
        let _ = writeln!(stdout, "nothing is paused");
    }
    for p in &pauses {
        let what = match p.kind {
            PauseKind::Edit => "the agent may change the hook settings",
            PauseKind::Off => "Vahta's hooks are out",
        };
        let _ = writeln!(
            stdout,
            "{}: paused, {what}, {} left{}",
            p.harness,
            human(p.until - now),
            if p.reason.is_empty() {
                String::new()
            } else {
                format!(" (reason given: {})", p.reason)
            }
        );
    }
    EXIT_CLEAN
}
