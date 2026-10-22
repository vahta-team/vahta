//! Asking a running daemon about a tool's output.
//!
//! The hook never starts a daemon and never waits long for one: it runs on
//! every tool call. If one is running, of this version, and answers within
//! [`WAIT`], its answer is the cut list: the detector's finds plus the values
//! it holds for this agent, minus what the person has let through, and a
//! reference to the original it kept. Anything else (no daemon, another
//! version, an error, silence) is `None`, and the hook cuts what its own
//! detector found. That is never less than it cut before there was a daemon.
//!
//! The person's `hook_output` setting is read here too: `observe` makes the
//! hook change nothing and only tell the daemon what it saw.
//!
//! [`report`] tells the daemon what the hook refused, for its journal and its
//! alarm, and spools the report when no daemon runs.

use std::sync::mpsc;
use std::time::Duration;

use vahta_ipc::client::Connector;
use vahta_ipc::config::{Config, HookOutput, HookTool};
use vahta_ipc::paths::Paths;
use vahta_ipc::protocol::{
    ClientReply, ClientRequest, OutputSpan, PromptDecision, Signal, TranscriptRoots,
};
use vahta_ipc::spool::{self, SpoolLine};

use crate::redact::Cut;

/// How long the hook waits for the daemon's answer.
const WAIT: Duration = Duration::from_millis(300);

/// The daemon's answer to a scan.
pub struct Answer {
    pub cuts: Vec<Cut>,
    pub reference: Option<String>,
}

/// What the hook sends.
pub struct Scan {
    pub cwd: String,
    pub tool: String,
    pub texts: Vec<String>,
    pub cuts: Vec<Cut>,
    pub possible: Vec<String>,
}

/// The person's choice for the hook (`hook_output` in `config.toml`). A
/// config that cannot be read is the default, redaction: the hook fails
/// toward cutting, not toward letting through.
pub fn hook_output() -> HookOutput {
    Paths::from_env(None)
        .ok()
        .and_then(|p| Config::load(&p.config_file()).ok())
        .map(|c| c.hook_output)
        .unwrap_or_default()
}

/// The person's choice for a secret in a tool call (`hook_tool` in
/// `config.toml`). A config that cannot be read is the default, block.
pub fn hook_tool() -> HookTool {
    Paths::from_env(None)
        .ok()
        .and_then(|p| Config::load(&p.config_file()).ok())
        .map(|c| c.hook_tool)
        .unwrap_or_default()
}

/// How a request to the daemon went.
enum Delivery {
    Answered(ClientReply),
    /// No daemon of this version is running (none at all, another version, or
    /// one that is not well).
    NoDaemon,
    /// A daemon was there but failed or did not answer in time.
    Lost,
}

/// Send `request` to a running daemon of this version and read its reply,
/// waiting at most [`WAIT`].
fn deliver(paths: Paths, request: ClientRequest) -> Delivery {
    deliver_within(paths, request, WAIT)
}

/// [`deliver`] with another limit.
fn deliver_within(paths: Paths, request: ClientRequest, wait: Duration) -> Delivery {
    let connector = Connector {
        paths,
        version: vahta_ipc::VERSION.to_string(),
        start: None,
    };
    let (tx, rx) = mpsc::channel();
    // On a thread, so a daemon that hangs costs the hook `WAIT` and no more;
    // the thread goes with the process.
    std::thread::spawn(move || {
        let delivery = match connector.connect_running() {
            Ok(Some(mut conn)) => {
                if !conn.daemon.ok || conn.daemon.version != connector.version {
                    Delivery::NoDaemon
                } else {
                    match conn.request(&request) {
                        Ok(reply) => Delivery::Answered(reply),
                        Err(_) => Delivery::Lost,
                    }
                }
            }
            Ok(None) => Delivery::NoDaemon,
            Err(_) => Delivery::NoDaemon,
        };
        let _ = tx.send(delivery);
    });
    rx.recv_timeout(wait).unwrap_or(Delivery::Lost)
}

/// Send `request` to a running daemon of this version and read its reply,
/// waiting at most [`WAIT`]; `None` for anything else.
fn ask(request: ClientRequest) -> Option<ClientReply> {
    let paths = Paths::from_env(None).ok()?;
    match deliver(paths, request) {
        Delivery::Answered(reply) => Some(reply),
        _ => None,
    }
}

/// Tell the daemon what the hook refused. With no daemon to hear it, the
/// report goes to the spool, which the next daemon journals; a daemon that
/// was there but did not answer is not written twice. Never fails the hook.
pub fn report(harness: &str, session: Option<String>, cwd: String, signal: Signal) {
    let Ok(paths) = Paths::from_env(None) else {
        return;
    };
    let request = ClientRequest::HookReport {
        session: session.clone(),
        harness: harness.to_string(),
        cwd: cwd.clone(),
        signal: signal.clone(),
    };
    if let Delivery::NoDaemon = deliver(paths.clone(), request) {
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = spool::append(
            &paths,
            &SpoolLine {
                time,
                session,
                harness: harness.to_string(),
                cwd,
                signal,
            },
        );
    }
}

/// The shortest text that can carry a held value: the daemon's own floor
/// (`MIN_EXACT`).
const MIN_CHECKED: usize = 8;
/// A tool call larger than this is checked in pieces, each a frame of its own
/// (a frame is at most 1 MiB, and JSON escaping can double a text).
const CHECK_CHUNK: usize = 256 * 1024;
/// How much of one piece the next repeats, so a value across the cut is
/// still whole in one of them. A value's encoded form longer than this, split
/// by a cut, is missed.
const CHECK_OVERLAP: usize = 8 * 1024;
/// At most this many pieces are sent: a text past 2 MiB is checked in its
/// first pieces only.
const CHECK_PIECES: usize = 8;

/// A held value the daemon found in a tool call: how it was written (what the
/// agent may be told) and its name (for the person only).
pub struct Held {
    pub form: String,
    pub name: String,
}

/// Ask a running daemon whether `text` carries a value it holds for this
/// agent, in any form (raw, base64, hex, URL-encoded, reversed). Only when a
/// daemon of this version runs and answers within [`WAIT`]; anything else is
/// `None`, and the call goes on to what the hook's own detector decided.
pub fn tool_check(session: Option<String>, cwd: &str, text: &str) -> Option<Held> {
    if text.len() < MIN_CHECKED {
        return None;
    }
    let paths = Paths::from_env(None).ok()?;
    let mut start = 0;
    for _ in 0..CHECK_PIECES {
        let mut end = (start + CHECK_CHUNK).min(text.len());
        while !text.is_char_boundary(end) {
            end += 1;
        }
        let request = ClientRequest::ToolCheck {
            session: session.clone(),
            cwd: cwd.to_string(),
            text: text[start..end].to_string(),
        };
        match deliver(paths.clone(), request) {
            Delivery::Answered(ClientReply::ToolDeny { form, name }) => {
                return Some(Held { form, name });
            }
            Delivery::Answered(_) => {}
            // No daemon, or one that did not answer: no check, and no
            // second try for the next piece.
            Delivery::NoDaemon | Delivery::Lost => return None,
        }
        if end >= text.len() {
            break;
        }
        start = end.saturating_sub(CHECK_OVERLAP);
        while !text.is_char_boundary(start) {
            start += 1;
        }
    }
    None
}

/// How long the hook waits for the person to answer the window of a prompt
/// with a secret in it: a little under the 120 s the harness allows the hook
/// (the daemon's own wait is shorter still). `VAHTA_HOOK_PROMPT_WAIT_MS` can
/// only shorten it, for tests; a longer one is ignored.
const PROMPT_WAIT: Duration = Duration::from_secs(115);

fn prompt_wait() -> Duration {
    std::env::var("VAHTA_HOOK_PROMPT_WAIT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_millis)
        .map_or(PROMPT_WAIT, |d| d.min(PROMPT_WAIT))
}

/// The longest prompt sent to the daemon whole (a frame is at most 1 MiB, and
/// JSON escaping can multiply a text by six). A longer one is not put before
/// the person; the hook holds it.
pub const MAX_PROMPT: usize = 160 * 1024;

/// What the daemon says about a prompt's text.
#[derive(Default)]
pub struct InputCheck {
    /// The held values it carries.
    pub names: Vec<String>,
    /// Saved pastes the person asked the agent to propose rules for, which this
    /// prompt is the first to be able to tell it.
    pub bind: Vec<String>,
}

/// The names of the held values a prompt carries, when a daemon of this
/// version runs and answers within [`WAIT`] (checked in pieces, like a tool
/// call). Anything else is empty: nothing is known.
pub fn input_names(session: Option<String>, cwd: &str, text: &str) -> InputCheck {
    let mut check = InputCheck::default();
    if text.len() < MIN_CHECKED {
        return check;
    }
    let Ok(paths) = Paths::from_env(None) else {
        return check;
    };
    let mut start = 0;
    for _ in 0..CHECK_PIECES {
        let mut end = (start + CHECK_CHUNK).min(text.len());
        while !text.is_char_boundary(end) {
            end += 1;
        }
        let request = ClientRequest::CheckInput {
            session: session.clone(),
            cwd: cwd.to_string(),
            text: text[start..end].to_string(),
        };
        match deliver(paths.clone(), request) {
            Delivery::Answered(ClientReply::InputNames { names: found, bind }) => {
                for n in found {
                    if !check.names.contains(&n) {
                        check.names.push(n);
                    }
                }
                for n in bind {
                    if !check.bind.contains(&n) {
                        check.bind.push(n);
                    }
                }
            }
            Delivery::Answered(_) => {}
            Delivery::NoDaemon | Delivery::Lost => return check,
        }
        if end >= text.len() {
            break;
        }
        start = end.saturating_sub(CHECK_OVERLAP);
        while !text.is_char_boundary(start) {
            start += 1;
        }
    }
    check
}

/// What came of asking the person about a prompt.
pub enum PromptOutcome {
    /// A false alarm: the prompt goes on.
    Send,
    /// Saved in the project's vault under this name; the prompt must not go.
    /// `bind`: the person asked for the agent to propose rules for it now.
    Saved { name: String, bind: bool },
    /// The person chose not to send it, or gave no answer.
    Held { no_answer: bool },
    /// Another window is open, or this process asked too often.
    Busy { limited: bool },
    /// No daemon of this version to ask, or it failed or did not answer in
    /// time.
    Unasked,
}

/// Ask a running daemon to put a prompt with a secret in it before the
/// person, and wait for the answer (up to [`PROMPT_WAIT`]).
pub fn prompt_ask(
    session: Option<String>,
    harness: &str,
    cwd: &str,
    text: &str,
    detected: Option<String>,
) -> PromptOutcome {
    let Ok(paths) = Paths::from_env(None) else {
        return PromptOutcome::Unasked;
    };
    let request = ClientRequest::PromptAsk {
        session,
        harness: harness.to_string(),
        cwd: cwd.to_string(),
        text: text.to_string(),
        detected,
        roots: TranscriptRoots::from_env(dirs::home_dir().as_deref()),
    };
    match deliver_within(paths, request, prompt_wait()) {
        Delivery::Answered(ClientReply::PromptAnswer { answer }) => match answer {
            PromptDecision::Send {} => PromptOutcome::Send,
            PromptDecision::Saved { name, bind } => PromptOutcome::Saved { name, bind },
            PromptDecision::Held { no_answer } => PromptOutcome::Held { no_answer },
            PromptDecision::Busy { limited } => PromptOutcome::Busy { limited },
        },
        _ => PromptOutcome::Unasked,
    }
}

/// Ask a running daemon whether `argv` passes the rules of every secret in
/// `names` (the project's list when empty), with no window. Only when a daemon
/// of this version runs and answers `Allowed` within [`WAIT`]; every other
/// outcome (no daemon, another version, a refusal, silence) is `false`, and the
/// harness's own permission flow decides.
pub fn run_allowed(
    cwd: &str,
    argv: Vec<String>,
    names: Vec<String>,
    vault: Option<String>,
) -> bool {
    let request = ClientRequest::CheckRun {
        cwd: cwd.to_string(),
        argv,
        names,
        path: std::env::var("PATH").ok(),
        vault,
    };
    matches!(ask(request), Some(ClientReply::Allowed {}))
}

/// The same for a `vahta http`: would a request to `url` with `names` pass
/// their approved host lists? Every other outcome is `false`.
pub fn http_allowed(cwd: &str, url: String, names: Vec<String>, vault: Option<String>) -> bool {
    let request = ClientRequest::CheckHttp {
        cwd: cwd.to_string(),
        url,
        names,
        vault,
    };
    matches!(ask(request), Some(ClientReply::Allowed {}))
}

pub fn scan(scan: Scan) -> Option<Answer> {
    let request = ClientRequest::OutputScan {
        cwd: scan.cwd,
        tool: scan.tool,
        texts: scan.texts,
        spans: scan
            .cuts
            .into_iter()
            .map(|c| OutputSpan {
                text: c.text,
                start: c.range.start,
                end: c.range.end,
                label: c.label,
            })
            .collect(),
        possible: scan.possible,
    };
    match ask(request)? {
        ClientReply::OutputSpans { spans, reference } => Some(Answer {
            cuts: spans
                .into_iter()
                .map(|s| Cut {
                    text: s.text,
                    range: s.start..s.end,
                    label: s.label,
                })
                .collect(),
            reference,
        }),
        _ => None,
    }
}

/// Observe mode: tell a running daemon what was seen, for its journal. Its
/// answer does not matter.
pub fn observed(tool: String, kinds: Vec<String>, likely: usize, possible: usize) {
    let _ = ask(ClientRequest::OutputObserved {
        tool,
        kinds,
        likely,
        possible,
    });
}

/// Tell the daemon a session began or ended, so it can tell a running
/// session's transcript from a closed one and clean the marked one at the end.
/// Its answer does not matter.
pub fn session_note(session: Option<String>, harness: &str, cwd: String, ended: bool) {
    transcript_note(session, harness, cwd, ended, false);
}

/// Tell the daemon the hook cut a secret out of a tool's output in this
/// session (or could not), so that the session's transcript is cleaned when the
/// session ends. Its answer does not matter, and with no daemon there is no one
/// to tell.
pub fn session_dirty(session: Option<String>, harness: &str, cwd: String) {
    if session.is_some() {
        transcript_note(session, harness, cwd, false, true);
    }
}

fn transcript_note(session: Option<String>, harness: &str, cwd: String, ended: bool, dirty: bool) {
    let home = dirs::home_dir();
    let _ = ask(ClientRequest::TranscriptNote {
        harness: harness.to_string(),
        session,
        cwd,
        ended,
        roots: vahta_ipc::protocol::TranscriptRoots::from_env(home.as_deref()),
        dirty,
    });
}
