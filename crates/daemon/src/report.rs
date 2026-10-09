//! What the hook refused, as the daemon hears it ([`ClientRequest::HookReport`]
//! and the spool the hook writes when no daemon runs).
//!
//! Each report is journalled as `hook_report`, with the signal's kind as the
//! result and its details (category, rule, path, how a value was hidden) as
//! the reason. Every field came from a process an agent drives, so each is
//! cleaned like any other label before it is written. Reports are also the
//! evidence the injection alarm weighs (`alarm.rs`), and a `ToolCheck` is how
//! the daemon finds a held value, in any encoding, in a tool call about to
//! run.
//!
//! [`ClientRequest::HookReport`]: crate::protocol::ClientRequest::HookReport

use std::sync::Arc;
use std::time::{Duration, Instant};

use vahta_ipc::spool::{self, SpoolLine};

use crate::alarm::{self, Subject};
use crate::encoded::Form;
use crate::journal::{Entry, Journal};
use crate::ops::{Ctx, Flow};
use crate::output::anchor_of;
use crate::paths::Paths;
use crate::protocol::{ClientReply, Signal};
use crate::server::Shared;
use crate::surface::sanitize_label;

/// The longest a cleaned field is kept.
const MAX_FIELD: usize = 120;

fn clean(raw: &str) -> String {
    sanitize_label(raw)
        .map(|l| l.chars().take(MAX_FIELD).collect())
        .unwrap_or_default()
}

/// The journal's reason for a report: what was seen, never a value.
fn details(harness: &str, session: Option<&str>, signal: &Signal) -> String {
    let what = match signal {
        Signal::Blocked {
            category,
            rule,
            evasion,
        }
        | Signal::Observed {
            category,
            rule,
            evasion,
        } => {
            let mut s = format!("{}; rule {}", clean(category), clean(rule));
            if let Some(e) = evasion {
                s.push_str(&format!("; hidden as {}", e.as_str()));
            }
            s
        }
        Signal::VahtaFileTouch { path } => format!("path {}", clean(path)),
        Signal::AgentGuard { command } => format!("command {}", clean(command)),
        Signal::HookTamper { file, what } => format!("{} in {}", clean(what), clean(file)),
        Signal::KnownValue { form } => format!("a held value written as {}", clean(form)),
    };
    match session {
        Some(s) => format!("{}; {what}; agent session {}", clean(harness), clean(s)),
        None => format!("{}; {what}", clean(harness)),
    }
}

/// The agent a live report is about: its session id when the payload had
/// one, else the agent process the report came from.
fn subject_of(ctx: &Ctx<'_>, harness: &str, session: Option<&str>) -> Subject {
    if let Some(id) = session.map(clean).filter(|s| !s.is_empty()) {
        return Subject {
            key: format!("session:{id}"),
            shown: format!("{} session {id}", clean(harness)),
        };
    }
    match anchor_of(ctx) {
        Some((a, exe)) => Subject {
            key: format!("anchor:{}:{}", a.pid, a.start_time),
            shown: format!("{} (pid {})", clean(&exe), a.pid),
        },
        None => Subject {
            key: "unknown".to_string(),
            shown: format!("{} (unknown process)", clean(harness)),
        },
    }
}

/// A report from a hook that reached a running daemon: journalled, and
/// weighed by the alarm.
pub(crate) fn hook_report(
    shared: &Arc<Shared>,
    ctx: &Ctx<'_>,
    session: Option<&str>,
    harness: &str,
    signal: &Signal,
) -> Flow<ClientReply> {
    ctx.journal(
        Entry::new("hook_report").result(signal.kind(), Some(&details(harness, session, signal))),
    );
    let subject = subject_of(ctx, harness, session);
    if let Some(verdict) = shared.alarm.record(&subject, signal, Instant::now()) {
        alarm::raise(shared, subject, verdict);
    }
    Ok(ClientReply::Ok {})
}

/// The hook asks, before a tool call, whether its text carries a value held
/// for this agent in any form. A hit is journalled by name (for the person),
/// weighed by the alarm, and answered with the form only (for the agent).
pub(crate) fn tool_check(
    shared: &Arc<Shared>,
    ctx: &Ctx<'_>,
    session: Option<&str>,
    text: &str,
) -> Flow<ClientReply> {
    let chain = vahta_os::ancestor_chain(ctx.pid, vahta_os::MAX_ANCESTORS);
    // Taken one after the other, never one inside the other.
    let mut found: Option<(String, Form)> = None;
    if let Ok(sessions) = shared.sessions.lock() {
        found = sessions
            .covering(&chain)
            .into_iter()
            .find_map(|s| s.forms.find_text(text).map(|(n, f)| (n.to_string(), f)));
    }
    if found.is_none()
        && let Some((anchor, _)) = anchor_of(ctx)
        && let Ok(outputs) = shared.outputs.lock()
    {
        found = outputs.run_find(&anchor, text);
    }
    let Some((name, form)) = found else {
        return Ok(ClientReply::Ok {});
    };
    let signal = Signal::KnownValue {
        form: form.as_str().to_string(),
    };
    let subject = subject_of(ctx, "", session);
    ctx.journal(
        Entry::new("hook_report")
            .names(std::slice::from_ref(&name))
            .result(
                signal.kind(),
                Some(&format!("written as {}; {}", form.as_str(), subject.shown)),
            ),
    );
    if let Some(verdict) = shared.alarm.record(&subject, &signal, Instant::now()) {
        alarm::raise(shared, subject, verdict);
    }
    Ok(ClientReply::ToolDeny {
        form: form.as_str().to_string(),
        name,
    })
}

/// The reports hooks spooled while no daemon ran, as they were read.
pub(crate) type Spooled = Vec<SpoolLine>;

/// At startup: journal what hooks spooled while no daemon ran, and empty the
/// spool. The lines are returned for the alarm, which weighs them once the
/// daemon is up ([`feed_spooled`]).
pub(crate) fn ingest_spool(paths: &Paths, journal: &Journal) -> Spooled {
    let drained = match spool::drain(paths) {
        Ok(d) => d,
        Err(e) => {
            journal.record(Entry::new("hook_spool").result("unreadable", Some(&e.to_string())));
            return Vec::new();
        }
    };
    for SpoolLine {
        time,
        session,
        harness,
        signal,
        ..
    } in &drained.lines
    {
        let mut entry = Entry::new("hook_report").result(
            signal.kind(),
            Some(&format!(
                "{}; spooled",
                details(harness, session.as_deref(), signal)
            )),
        );
        entry.time = *time;
        journal.record(entry);
    }
    if drained.full || drained.unreadable > 0 {
        journal.record(Entry::new("hook_spool").result(
            if drained.full { "full" } else { "partial" },
            Some(&format!(
                "{} reports read, {} lines unreadable{}",
                drained.lines.len(),
                drained.unreadable,
                if drained.full {
                    "; the spool was full, so later reports were dropped"
                } else {
                    ""
                }
            )),
        ));
    }
    drained.lines
}

/// Weigh spooled reports at the time they were written: an agent that
/// probed the hook while no daemon ran has the same score as one that did so
/// with a daemon.
pub(crate) fn feed_spooled(shared: &Arc<Shared>, lines: Spooled) {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let now = Instant::now();
    for line in lines {
        let subject = match line.session.as_deref().map(clean).filter(|s| !s.is_empty()) {
            Some(id) => Subject {
                key: format!("session:{id}"),
                shown: format!("{} session {id}", clean(&line.harness)),
            },
            None => Subject {
                key: format!("spool:{}", clean(&line.harness)),
                shown: format!(
                    "{} (reported while Vahta was not running)",
                    clean(&line.harness)
                ),
            },
        };
        let age = Duration::from_secs(now_unix.saturating_sub(line.time));
        let Some(at) = now.checked_sub(age) else {
            continue;
        };
        if let Some(verdict) = shared.alarm.record(&subject, &line.signal, at) {
            alarm::raise(shared, subject, verdict);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Evasion;

    #[test]
    fn details_name_the_find_and_clean_what_an_agent_wrote() {
        let s = Signal::Blocked {
            category: "an API token\u{1b}[31m".into(),
            rule: "gitleaks.github-pat".into(),
            evasion: Some(Evasion::Base64),
        };
        let d = details("claude", Some("abc"), &s);
        assert_eq!(
            d,
            "claude; an API token; rule gitleaks.github-pat; hidden as base64; agent session abc"
        );
        assert!(!d.contains('\u{1b}'));
    }
}
