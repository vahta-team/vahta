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

use std::sync::mpsc;
use std::time::Duration;

use vahta_ipc::client::Connector;
use vahta_ipc::config::{Config, HookOutput};
use vahta_ipc::paths::Paths;
use vahta_ipc::protocol::{ClientReply, ClientRequest, OutputSpan};

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

/// Send `request` to a running daemon of this version and read its reply,
/// waiting at most [`WAIT`]; `None` for anything else.
fn ask(request: ClientRequest) -> Option<ClientReply> {
    let paths = Paths::from_env(None).ok()?;
    let connector = Connector {
        paths,
        version: vahta_ipc::VERSION.to_string(),
        start: None,
    };
    let (tx, rx) = mpsc::channel();
    // On a thread, so a daemon that hangs costs the hook `WAIT` and no more;
    // the thread goes with the process.
    std::thread::spawn(move || {
        let reply = (|| {
            let mut conn = connector.connect_running().ok()??;
            if !conn.daemon.ok || conn.daemon.version != connector.version {
                return None;
            }
            conn.request(&request).ok()
        })();
        let _ = tx.send(reply);
    });
    rx.recv_timeout(WAIT).ok().flatten()
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
