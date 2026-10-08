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
use vahta_ipc::config::{Config, HookOutput};
use vahta_ipc::paths::Paths;
use vahta_ipc::protocol::{ClientReply, ClientRequest, OutputSpan, Signal};
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
    rx.recv_timeout(WAIT).unwrap_or(Delivery::Lost)
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
