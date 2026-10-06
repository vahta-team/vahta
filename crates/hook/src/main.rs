//! `vahta-hook --harness <claude|codex|cursor> --event <kind> [--setup N]`
//!
//! Kinds: `before_tool`, `before_read`, `prompt`, `after_tool`, `session_start`.
//! Reads one harness event on stdin and answers on stdout. Every failure
//! (unreadable input, bad JSON, an unknown shape) is an allow: empty stdout,
//! exit 0. A broken hook must never brick the agent.
//!
//! The payload is hostile input (it carries what the agent wrote), so it is
//! read with `vahta-json`, not serde: no depth limit short of the memory
//! limits below, `json.loads`-faithful. Replies are rendered with serde_json
//! from the trusted TOML templates, because that is a writer, not a reader.

mod readguard;

use std::io::{Read, Write};

use vahta_harness::{Decision, Event, Kind, Manifest};
use vahta_json::{Limits, ParseError};

const DISABLE_ENV: &str = "VAHTA_HOOK_DISABLE";

/// Past these a payload is not built into a tree; its strings are walked
/// instead. Generous: a real payload is a few levels and a few hundred nodes.
const LIMITS: Limits = Limits {
    depth: 100_000,
    nodes: 1_000_000,
};

struct Args {
    harness: String,
    kind: Kind,
    /// The setup version this hook was installed at; absent means unknown.
    setup: Option<u32>,
}

fn parse_args() -> Option<Args> {
    let mut harness = None;
    let mut kind = None;
    let mut setup = None;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--harness" => harness = Some(args.next()?),
            "--event" => kind = Some(Kind::parse(&args.next()?)?),
            // An unreadable number is "unknown", which stays silent.
            "--setup" => setup = args.next()?.parse().ok(),
            _ => return None,
        }
    }
    Some(Args {
        harness: harness?,
        kind: kind?,
        setup,
    })
}

fn secret_in(text: &str, what: &str, notice: bool) -> Decision {
    let Some(secret) = vahta_detect::find_secret_kind(text) else {
        return Decision::Allow;
    };
    match (what, notice) {
        ("tool", _) => Decision::Deny {
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
        ("prompt", _) => {
            let msg = format!(
                "vahta blocked this message: it looks like it contains a secret ({secret}). \
                 Keep the secret out of the chat, store it instead, and send the message \
                 again without it."
            );
            Decision::Deny {
                user_message: msg.clone(),
                agent_message: msg,
            }
        }
        _ => Decision::Notice {
            user_message: format!("vahta: a secret ({secret}) reached the transcript; rotate it."),
            agent_message: format!(
                "A secret ({secret}) reached the transcript through this tool's output. \
                 Treat it as exposed: tell the user to rotate it, and do not repeat the value."
            ),
        },
    }
}

/// Refusing to touch one of Vahta's own files: names the path, never content.
fn deny_vahta_file(file: &str) -> Decision {
    let msg = format!(
        "vahta blocked access to `{file}`: it is part of Vahta's own files (a vault, its lock or \
         backups, or Vahta's local store and journal). Do not read, change, move or delete it; use \
         the `vahta` commands, which keep values out of the transcript."
    );
    Decision::Deny {
        user_message: msg.clone(),
        agent_message: msg,
    }
}

/// The first of Vahta's own files a tool call is about, if any: the file a
/// write tool names, the files a patch touches, or what a shell command reads,
/// writes, removes, moves or copies.
fn vahta_file_touched(ev: &Event) -> Option<String> {
    let cwd = ev.cwd.as_deref();
    match ev.group {
        Some(vahta_harness::Group::Write) => {
            if let Some(path) = ev.path.as_deref()
                && readguard::is_vahta_path(path, cwd)
            {
                return Some(path.to_string());
            }
            readguard::vahta_file_in_patch(&ev.text, cwd)
        }
        Some(vahta_harness::Group::Shell) => readguard::vahta_file_in_command(&ev.text, cwd),
        _ => None,
    }
}

/// Refusing to read a file: names the file and the kind, never a value.
fn deny_read(file: &str, kind: &str) -> Decision {
    let msg = format!(
        "vahta blocked reading `{file}`: it holds credentials ({kind}). Do not read it; run the \
         command that needs it with `vahta run` so the values never reach the transcript."
    );
    Decision::Deny {
        user_message: msg.clone(),
        agent_message: msg,
    }
}

fn decide(m: &Manifest, args: &Args, ev: &Event) -> Decision {
    match args.kind {
        Kind::BeforeTool => {
            // Vahta's own files first: they are refused whatever is in the
            // call, and the answer names the path, not the text.
            if let Some(file) = vahta_file_touched(ev) {
                return deny_vahta_file(&file);
            }
            let by_text = secret_in(&ev.text, "tool", false);
            if by_text != Decision::Allow || ev.group != Some(vahta_harness::Group::Shell) {
                return by_text;
            }
            match readguard::secret_file_in_command(&ev.text, ev.cwd.as_deref()) {
                Some((file, kind)) => deny_read(&file, &kind),
                None => Decision::Allow,
            }
        }
        Kind::BeforeRead => {
            let Some(file) = ev.path.as_deref() else {
                return Decision::Allow;
            };
            if readguard::is_vahta_path(file, ev.cwd.as_deref()) {
                return deny_vahta_file(file);
            }
            match readguard::secret_kind_in(file, ev.cwd.as_deref(), ev.content.as_deref()) {
                Some(kind) => deny_read(file, &kind),
                None => Decision::Allow,
            }
        }
        Kind::Prompt => secret_in(&ev.text, "prompt", false),
        Kind::AfterTool => secret_in(&ev.text, "output", true),
        Kind::SessionStart => match args.setup {
            Some(n) if n < m.setup_version => {
                let line = format!(
                    "vahta: setup for {} is outdated (v{n} \u{2192} v{}); run `vahta setup --{}`",
                    m.title, m.setup_version, m.name
                );
                Decision::Notice {
                    agent_message: format!("{line}. Mention this to the user once."),
                    user_message: line,
                }
            }
            _ => Decision::Allow,
        },
    }
}

/// An event from a payload too big or too deep to build as a tree: read by the
/// tree-free token walk, so a secret is not let through for being wrapped
/// deeply. Text kinds get every string; a file read gets the strings under the
/// manifest's path and content keys.
fn unbuilt_event(m: &Manifest, kind: Kind, raw: &str) -> Option<Event> {
    let spec = m.event(kind)?;
    let leaf = |p: &Option<vahta_harness::OneOrMany>| -> Vec<String> {
        p.iter()
            .flat_map(|p| p.iter())
            .map(|p| p.rsplit('.').next().unwrap_or(p).to_string())
            .collect()
    };
    let (path_keys, content_keys) = (leaf(&spec.file_path), leaf(&spec.content));
    let mut ev = Event {
        kind: Some(kind),
        ..Event::default()
    };
    let mut strings: Vec<String> = Vec::new();
    vahta_json::for_each_string(raw, &mut |key, s| {
        if kind == Kind::BeforeRead {
            match key {
                Some(k) if ev.path.is_none() && path_keys.iter().any(|p| p == k) => {
                    ev.path = Some(s.to_string())
                }
                Some(k) if ev.content.is_none() && content_keys.iter().any(|p| p == k) => {
                    ev.content = Some(s.to_string())
                }
                _ => {}
            }
        } else {
            strings.push(s.to_string());
        }
    });
    ev.text = strings.join("\n");
    Some(ev)
}

fn run() -> Option<vahta_harness::Output> {
    if std::env::var_os(DISABLE_ENV).is_some_and(|v| !v.is_empty()) {
        return None;
    }
    let args = parse_args()?;
    let manifest: Manifest = vahta_harness::manifest(&args.harness)?.ok()?;
    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw).ok()?;
    let event = match vahta_json::parse_limited(&raw, LIMITS) {
        Ok(payload) => manifest.normalise(args.kind, &payload)?,
        // Not JSON at all: nothing to judge.
        Err(ParseError::Invalid) => return None,
        // Valid so far but past the limits: never fail open on size.
        Err(ParseError::TooDeep | ParseError::TooMany) => {
            unbuilt_event(&manifest, args.kind, &raw)?
        }
    };
    Some(manifest.render(args.kind, &decide(&manifest, &args, &event)))
}

fn main() {
    let Some(out) = run() else { return };
    let _ = std::io::stdout().write_all(&out.stdout);
    let _ = std::io::stderr().write_all(&out.stderr);
    if out.exit_code != 0 {
        std::process::exit(out.exit_code);
    }
}
