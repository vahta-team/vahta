//! `vahta journal`: the person reads what Vahta did lately, in plain words.
//!
//! Reads `<data dir>/journal.jsonl` itself (no daemon needed, none started).
//! The journal never holds a value or a password; this prints only the fields
//! the daemon writes (time, event, names, peer, result, reason), cleaned of
//! control characters, and for an event it does not know only the name and the
//! result. There is no integrity data in the journal yet, so nothing is
//! verified.
//!
//! Person-only: the hook refuses it from an agent's Bash tool, because it
//! would show an agent which of its actions were noticed.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, IsTerminal, Write};

use serde_json::Value;
use vahta_ipc::paths::connectors_vault;
use vahta_vault::Vault;

use crate::daemon_cmd::utc_text;
use crate::{EXIT_CLEAN, EXIT_FAILED, EXIT_USAGE, Env};

pub const USAGE: &str = "\
usage: vahta journal [--last N] [--since DURATION] [--secret NAME]
                     [--kind KIND]... [--json]

Show recent events from Vahta's journal, oldest first, one line each, in UTC.
A line that starts with `!` is suspicious. Names and wording only, never a
value. It needs no daemon.

  --last N          the last N events that match (default 30)
  --since DURATION  only events newer than this (30m, 2h, 1d, 1h30m)
  --secret NAME     only events that name this secret
  --kind KIND       only this kind of event (repeat to allow several):
                      suspicious  alarms, hook stops, tampering, refused launches
                                  that look like an attack, notifications
                      refused     anything Vahta refused
                      run         runs and requests with a secret
                      session     sessions opening, ending, locking
                      connector   the connectors vault, its sessions and launches
                      notified    desktop notifications that were sent
                      vault       changes to a vault and its secrets
                      device      paired devices, members and transfers
                      daemon      the daemon starting and stopping
  --json            the matching lines as they are in the file

Run it in your own terminal: an agent is refused, because it would show the
agent which of its actions were noticed.
";

const KINDS: &[&str] = &[
    "suspicious",
    "refused",
    "run",
    "session",
    "connector",
    "notified",
    "vault",
    "device",
    "daemon",
];

/// The fields of a journal line that this command knows.
#[derive(Default)]
struct Line {
    time: u64,
    event: String,
    vault: Option<String>,
    names: Vec<String>,
    peer_exe: Option<String>,
    peer_pid: Option<u32>,
    result: Option<String>,
    reason: Option<String>,
    host: Option<String>,
    method: Option<String>,
    status: Option<u16>,
}

impl Line {
    /// The known fields of one line; `None` when it is not a JSON object.
    fn of(text: &str) -> Option<Line> {
        let v: Value = serde_json::from_str(text).ok()?;
        let obj = v.as_object()?;
        let string = |k: &str| obj.get(k).and_then(Value::as_str).map(str::to_string);
        let number = |k: &str| obj.get(k).and_then(Value::as_u64);
        Some(Line {
            time: number("time").unwrap_or(0),
            event: string("event").unwrap_or_default(),
            vault: string("vault"),
            names: obj
                .get("names")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|n| n.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            peer_exe: string("peer_exe"),
            peer_pid: number("peer_pid").and_then(|n| u32::try_from(n).ok()),
            result: string("result"),
            reason: string("reason"),
            host: string("host"),
            method: string("method"),
            status: number("status").and_then(|n| u16::try_from(n).ok()),
        })
    }
}

struct Args {
    last: usize,
    since: Option<u64>,
    only: Option<String>,
    kinds: Vec<String>,
    json: bool,
}

fn parse(args: &[String]) -> Result<Option<Args>, String> {
    let mut a = Args {
        last: 30,
        since: None,
        only: None,
        kinds: Vec::new(),
        json: false,
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = |name: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--json" => a.json = true,
            "--last" => {
                a.last = value("--last")?
                    .parse()
                    .map_err(|_| "--last needs a number".to_string())?;
            }
            "--since" => {
                let v = value("--since")?;
                a.since = Some(
                    vahta_ipc::duration::parse_secs(&v)
                        .filter(|s| *s > 0)
                        .ok_or_else(|| {
                            format!("invalid --since value: {v:?} (use 30m, 2h, 1d, 1h30m)")
                        })?,
                );
            }
            "--secret" => a.only = Some(value("--secret")?),
            "--kind" => {
                let k = value("--kind")?;
                if !KINDS.contains(&k.as_str()) {
                    return Err(format!("unknown kind {k:?} (one of {})", KINDS.join(", ")));
                }
                a.kinds.push(k);
            }
            other => return Err(format!("unrecognised argument: {other}")),
        }
    }
    Ok(Some(a))
}

/// Text from the journal made safe to print: no control characters, bounded.
fn clean(raw: &str, max: usize) -> String {
    let s: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(max)
        .collect();
    s.trim().to_string()
}

fn harness_title(word: &str) -> String {
    match word {
        "claude" => "Claude Code".to_string(),
        "codex" => "Codex".to_string(),
        "cursor" => "Cursor".to_string(),
        other => clean(other, 40),
    }
}

/// `claude pid 42` found in a reason, as `(harness, pid)`.
fn harness_pid(reason: &str) -> Option<(String, String)> {
    let words: Vec<&str> = reason.split([' ', ';']).filter(|w| !w.is_empty()).collect();
    let i = words.iter().position(|w| *w == "pid")?;
    let pid = words.get(i + 1)?;
    let who = words.get(i.checked_sub(1)?)?;
    pid.chars()
        .all(|c| c.is_ascii_digit())
        .then(|| (harness_title(who), (*pid).to_string()))
}

impl Line {
    fn reason(&self) -> &str {
        self.reason.as_deref().unwrap_or("")
    }

    fn result(&self) -> &str {
        self.result.as_deref().unwrap_or("")
    }

    /// Something that is really off, not merely refused or unusual.
    fn suspicious(&self) -> bool {
        let by_event = matches!(
            self.event.as_str(),
            "alarm"
                | "hook_report"
                | "hook_tamper"
                | "hook_tamper_kept"
                | "cwd_refused"
                | "notified"
        );
        let routine_alarm_line =
            self.event == "alarm" && matches!(self.result(), "locked" | "no_answer");
        (by_event && !routine_alarm_line) || self.reason().contains("suspicious")
    }

    fn refused(&self) -> bool {
        self.result() == "refused" || self.event.ends_with("_refused")
    }

    fn connector(&self, connectors_vault_id: Option<&str>) -> bool {
        self.event == "notified"
            || self.reason().contains("connectors")
            || self.reason().contains("not_from_harness")
            || (self.vault.is_some() && self.vault.as_deref() == connectors_vault_id)
    }

    fn in_kind(&self, kind: &str, connectors_vault_id: Option<&str>) -> bool {
        let e = self.event.as_str();
        match kind {
            "suspicious" => self.suspicious(),
            "refused" => self.refused(),
            "connector" => self.connector(connectors_vault_id),
            "notified" => e == "notified",
            "run" => matches!(
                e,
                "run" | "run_end" | "run_refused" | "http_request" | "http_refused"
            ),
            "session" => matches!(
                e,
                "session_start"
                    | "session_end"
                    | "session_extension"
                    | "session_refused"
                    | "sessions_stale"
                    | "lock"
                    | "sleep_lock"
                    | "lock_on_sleep"
            ),
            "vault" => matches!(
                e,
                "init"
                    | "bind"
                    | "tier"
                    | "remove"
                    | "import"
                    | "reveal"
                    | "copy"
                    | "copy_cleared"
                    | "rekey"
                    | "recover"
                    | "remote_set"
                    | "role_approved"
                    | "role_removed"
                    | "harden"
            ),
            "device" => {
                e.starts_with("device_") || e.starts_with("member") || e.starts_with("transfer")
            }
            "daemon" => e.starts_with("daemon_") || e == "connection",
            _ => false,
        }
    }

    /// The line in plain words.
    fn phrase(&self) -> String {
        let names = clean(&self.names.join(", "), 120);
        let with = if names.is_empty() {
            String::new()
        } else {
            format!(" with {names}")
        };
        let by = match (&self.peer_exe, self.peer_pid) {
            (Some(exe), Some(pid)) => format!(" by {} (pid {pid})", clean(exe, 40)),
            (Some(exe), None) => format!(" by {}", clean(exe, 40)),
            _ => String::new(),
        };
        let result = clean(self.result(), 40);
        let reason = clean(self.reason(), 160);
        let tail = |r: &str| {
            if r.is_empty() {
                String::new()
            } else {
                format!(" ({r})")
            }
        };
        match self.event.as_str() {
            "run" => match result.as_str() {
                "started" => format!("run{with}{by}: started{}", tail(&reason)),
                "cancelled" => {
                    format!("run{with}{by}: cancelled, the client went away; nothing ran")
                }
                _ => format!("run{with}{by}: {result}{}", tail(&reason)),
            },
            "run_end" => format!("run{with} ended{}", tail(&reason)),
            "run_refused" => {
                if reason.contains("not_from_harness") {
                    format!(
                        "refused: not started by the harness the connector{with} is bound to{by}"
                    )
                } else {
                    format!("refused: run{with}{by}{}", tail(&reason))
                }
            }
            "session_start" => match harness_pid(&reason) {
                Some((who, pid)) if reason.starts_with("connectors") => format!(
                    "connectors session opened for {who} pid {pid}{}",
                    tail(&names)
                ),
                _ => format!("session opened{with}{by}{}", tail(&reason)),
            },
            "session_end" => match harness_pid(&reason) {
                Some((who, pid)) if reason.contains("connectors") => {
                    let why = reason.split(';').next().unwrap_or("").trim();
                    format!("connectors session for {who} pid {pid} ended{}", tail(why))
                }
                _ => format!("session ended{with}{}", tail(&reason)),
            },
            "session_refused" => format!("refused: session{with}{}", tail(&reason)),
            "lock" => format!("sessions locked{}", tail(&reason)),
            "alarm" => format!("ALARM {result}{}", tail(&reason)),
            "alarm_ignored" => format!("alarm ignored by you{}", tail(&reason)),
            "notified" => format!(
                "desktop notification sent: {reason_word}{with}",
                reason_word = notice_words(&result_or(&self.result, &reason))
            ),
            "hook_report" => format!("the hook stopped an agent: {result}{}", tail(&reason)),
            "hook_tamper" | "hook_tamper_kept" => {
                format!("hook settings changed: {result}{}", tail(&reason))
            }
            "cwd_refused" => format!("refused: a client claimed a directory it is not in{by}"),
            "http_request" => format!(
                "http {} {}{with}: {}",
                clean(self.method.as_deref().unwrap_or(""), 10),
                clean(self.host.as_deref().unwrap_or(""), 80),
                self.status.map_or(result.clone(), |s| s.to_string())
            ),
            "http_refused" => format!("refused: http{with}{by}{}", tail(&reason)),
            "daemon_start" => "the daemon started".to_string(),
            "daemon_stop" | "daemon_stop_requested" => "the daemon stopped".to_string(),
            "daemon_idle_exit" => "the daemon exited, idle".to_string(),
            known if KNOWN.contains(&known) => {
                let mut s = known.replace('_', " ");
                s.push_str(&with);
                s.push_str(&by);
                if !result.is_empty() {
                    s.push_str(&format!(": {result}"));
                }
                s.push_str(&tail(&reason));
                s
            }
            // An event this version does not know: its name and result only.
            other => format!("{}: {result}", clean(other, 40)),
        }
    }
}

/// The kind a `notified` line carries, in the reason (the daemon writes it as
/// the result's reason).
fn result_or(result: &Option<String>, reason: &str) -> String {
    if reason.is_empty() {
        result.clone().unwrap_or_default()
    } else {
        reason.to_string()
    }
}

fn notice_words(kind: &str) -> &'static str {
    match kind {
        "not_from_harness" => "a process that is not the harness tried to start a server",
        "command_not_allowed" => "a command outside the rules was refused",
        "value_in_output" => "a server printed its own key",
        "refusal_burst" => "many launches were refused in a short time",
        _ => "something about a connector",
    }
}

/// Events whose other fields are the daemon's own wording.
const KNOWN: &[&str] = &[
    "init",
    "bind",
    "tier",
    "remove",
    "import",
    "reveal",
    "copy",
    "copy_cleared",
    "rekey",
    "recover",
    "remote_set",
    "role_approved",
    "role_removed",
    "role_refused",
    "harden",
    "delegate_refused",
    "category_downgraded",
    "prompt_secret",
    "value_warning",
    "session_extension",
    "sessions_stale",
    "sleep_lock",
    "lock_on_sleep",
    "device_unlock",
    "device_approve",
    "device_paired",
    "device_revoked",
    "device_extended",
    "device_lost_rekey",
    "member_added",
    "member_removed",
    "member_joined",
    "member_extended",
    "member_add_refused",
    "transfer_made",
    "transfer_imported",
    "package_made",
    "identity_created",
    "owner_key_change",
    "output_allow",
    "output_saved",
    "output_redacted",
    "output_possible",
    "output_observed",
    "transcript_scrub",
    "hooks_paused",
    "hooks_resumed",
    "hooks_restored",
    "hook_spool",
    "guard_start",
    "connection",
];

pub fn run(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let a = match parse(args) {
        Ok(Some(a)) => a,
        Ok(None) => {
            let _ = stdout.write_all(USAGE.as_bytes());
            return EXIT_CLEAN;
        }
        Err(msg) => {
            let _ = write!(stderr, "vahta journal: error: {msg}\n\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    let Some(data) = env.data_dir.as_ref() else {
        let _ = writeln!(
            stderr,
            "vahta journal: error: cannot tell where Vahta keeps its data on this machine \
             (set VAHTA_DATA_DIR)"
        );
        return EXIT_FAILED;
    };
    let file = match std::fs::File::open(data.join("journal.jsonl")) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !a.json {
                let _ = writeln!(stdout, "no journal yet");
            }
            return EXIT_CLEAN;
        }
        Err(e) => {
            let _ = writeln!(stderr, "vahta journal: error: cannot read the journal: {e}");
            return EXIT_FAILED;
        }
    };
    let connectors_id = Vault::peek(&connectors_vault(data))
        .ok()
        .map(|p| vahta_vault::hex_encode(&p.vault_id));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let oldest = a.since.map(|s| now.saturating_sub(s));
    let mut kept: VecDeque<(String, Line)> = VecDeque::new();
    for text in BufReader::new(file).lines().map_while(Result::ok) {
        let Some(line) = Line::of(&text) else {
            continue;
        };
        if oldest.is_some_and(|t| line.time < t) {
            continue;
        }
        if a.only.as_ref().is_some_and(|s| !line.names.contains(s)) {
            continue;
        }
        if !a.kinds.is_empty()
            && !a
                .kinds
                .iter()
                .any(|k| line.in_kind(k, connectors_id.as_deref()))
        {
            continue;
        }
        kept.push_back((text, line));
        if kept.len() > a.last {
            kept.pop_front();
        }
    }
    let color =
        !a.json && std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    for (raw, line) in &kept {
        if a.json {
            let _ = writeln!(stdout, "{raw}");
            continue;
        }
        let suspicious = line.suspicious();
        let text = format!(
            "{}  {} {}",
            utc_text(line.time),
            if suspicious { "!" } else { " " },
            line.phrase()
        );
        if suspicious && color {
            let _ = writeln!(stdout, "\x1b[31m{text}\x1b[0m");
        } else {
            let _ = writeln!(stdout, "{text}");
        }
    }
    if kept.is_empty() && !a.json {
        let _ = writeln!(stdout, "no matching events");
    }
    EXIT_CLEAN
}
