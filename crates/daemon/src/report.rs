//! What the hook refused, as the daemon hears it ([`ClientRequest::HookReport`]
//! and the spool the hook writes when no daemon runs).
//!
//! Each report is journalled as `hook_report`, with the signal's kind as the
//! result and its details (category, rule, path, how a value was hidden) as
//! the reason. Every field came from a process an agent drives, so each is
//! cleaned like any other label before it is written. Reports are also the
//! evidence the injection alarm will weigh.
//!
//! [`ClientRequest::HookReport`]: crate::protocol::ClientRequest::HookReport

use vahta_ipc::spool::{self, SpoolLine};

use crate::journal::{Entry, Journal};
use crate::ops::{Ctx, Flow};
use crate::paths::Paths;
use crate::protocol::{ClientReply, Signal};
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
    };
    match session {
        Some(s) => format!("{}; {what}; agent session {}", clean(harness), clean(s)),
        None => format!("{}; {what}", clean(harness)),
    }
}

/// A report from a hook that reached a running daemon.
pub(crate) fn hook_report(
    ctx: &Ctx<'_>,
    session: Option<&str>,
    harness: &str,
    signal: &Signal,
) -> Flow<ClientReply> {
    ctx.journal(
        Entry::new("hook_report").result(signal.kind(), Some(&details(harness, session, signal))),
    );
    Ok(ClientReply::Ok {})
}

/// At startup: journal what hooks spooled while no daemon ran, and empty the
/// spool.
pub(crate) fn ingest_spool(paths: &Paths, journal: &Journal) {
    let drained = match spool::drain(paths) {
        Ok(d) => d,
        Err(e) => {
            journal.record(Entry::new("hook_spool").result("unreadable", Some(&e.to_string())));
            return;
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
