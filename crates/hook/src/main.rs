//! `vahta-hook --harness <claude|codex|cursor> --event <before_tool|prompt|after_tool|before_read>`
//!
//! Reads one harness event on stdin and answers on stdout. Every failure
//! (unreadable input, bad JSON, an unknown shape) is an allow: empty stdout,
//! exit 0. A broken hook must never brick the agent.

use std::io::{Read, Write};

use serde_json::Value;
use vahta_harness::{Decision, Event, Kind, Manifest};

const DISABLE_ENV: &str = "VAHTA_HOOK_DISABLE";

/// `--harness X --event Y`, in either order, nothing else.
fn parse_args() -> Option<(String, Kind)> {
    let mut harness = None;
    let mut kind = None;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--harness" => harness = Some(args.next()?),
            "--event" => kind = Some(Kind::parse(&args.next()?)?),
            _ => return None,
        }
    }
    Some((harness?, kind?))
}

fn decide(kind: Kind, ev: &Event) -> Decision {
    match kind {
        Kind::BeforeTool => match vahta_detect::find_secret_kind(&ev.text) {
            Some(secret) => Decision::Deny {
                user_message: format!(
                    "vahta blocked a tool call that carried a possible secret ({secret})."
                ),
                agent_message: format!(
                    "Inline credential-shaped token detected ({secret}). Keep secrets out of \
                     commands and files: never paste the value into a command, a file or a tool \
                     argument. Run the command with `vahta run` so the value never appears on \
                     argv, in files, or in chat."
                ),
            },
            None => Decision::Allow,
        },
        Kind::Prompt => match vahta_detect::find_secret_kind(&ev.text) {
            Some(secret) => {
                let msg = format!(
                    "vahta blocked this message: it looks like it contains a secret ({secret}). \
                     Keep the secret out of the chat, store it instead, and send the message \
                     again without it."
                );
                Decision::Deny { user_message: msg.clone(), agent_message: msg }
            }
            None => Decision::Allow,
        },
        Kind::AfterTool => match vahta_detect::find_secret_kind(&ev.text) {
            Some(secret) => Decision::Notice {
                user_message: format!(
                    "vahta: a secret ({secret}) reached the transcript; rotate it."
                ),
                agent_message: format!(
                    "A secret ({secret}) reached the transcript through this tool's output. \
                     Treat it as exposed: tell the user to rotate it, and do not repeat the value."
                ),
            },
            None => Decision::Allow,
        },
        // Reading files is judged separately; here a read is allowed.
        Kind::BeforeRead => Decision::Allow,
    }
}

/// An event from a payload serde_json could not read: all of its strings,
/// for the kinds that are decided on text. A file read needs its fields, so
/// it is left to fail open.
fn unparsed_event(kind: Kind, raw: &str) -> Option<Event> {
    if raw.trim().is_empty() || kind == Kind::BeforeRead {
        return None;
    }
    let mut strings: Vec<String> = Vec::new();
    vahta_scan::json::for_each_string(raw, &mut |_, s| strings.push(s.to_string()));
    Some(Event { kind: Some(kind), text: strings.join("\n"), ..Event::default() })
}

fn run() -> Option<vahta_harness::Output> {
    if std::env::var_os(DISABLE_ENV).is_some_and(|v| !v.is_empty()) {
        return None;
    }
    let (harness, kind) = parse_args()?;
    let manifest: Manifest = vahta_harness::manifest(&harness)?.ok()?;
    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw).ok()?;
    let event = match serde_json::from_str::<Value>(&raw) {
        Ok(payload) => manifest.normalise(kind, &payload)?,
        // serde_json refuses documents nested past 128 levels, and failing
        // open there would let a secret through simply by wrapping it deeply
        // (the Python hook reads ~1000 levels). Any payload serde cannot read
        // is instead read by the scanner's tree-free token walk: every string,
        // escapes decoded, no depth limit. It may deny; it never builds a tree.
        Err(_) => unparsed_event(kind, &raw)?,
    };
    let out = manifest.render(kind, &decide(kind, &event));
    Some(out)
}

fn main() {
    let Some(out) = run() else { return };
    let _ = std::io::stdout().write_all(&out.stdout);
    let _ = std::io::stderr().write_all(&out.stderr);
    if out.exit_code != 0 {
        std::process::exit(out.exit_code);
    }
}
