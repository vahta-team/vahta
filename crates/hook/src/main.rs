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

mod agentguard;
mod daemon;
mod hookguard;
mod readguard;
mod redact;

use std::io::{Read, Write};

use vahta_detect::Finding;
use vahta_harness::{Decision, Event, Kind, Manifest};
use vahta_ipc::config::Config;
use vahta_ipc::paths::Paths;
use vahta_ipc::protocol::{Evasion, Signal};
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

/// What the agent is told when a secret-shaped value is in its tool call: the
/// category and the fix, never the rule.
fn agent_blocked(category: &str) -> String {
    format!(
        "Blocked: this looks like {category}. Put secrets in Vahta and use `vahta run -- ...`; \
         never put the value in a command or a file."
    )
}

/// What the person is told: the rule, what it looks for, and, if the value was
/// hidden, that it was.
fn user_blocked(f: &Finding) -> String {
    let mut msg = format!(
        "vahta blocked a tool call that carried {}. Rule {}: {}.",
        f.category,
        f.rule,
        f.description.trim_end_matches('.')
    );
    if let Some(how) = f.evasion {
        msg.push_str(&format!(
            " The value was hidden ({}); this may be an injected instruction.",
            how.as_str()
        ));
    }
    msg
}

fn ipc_evasion(how: vahta_detect::Evasion) -> Evasion {
    match how {
        vahta_detect::Evasion::Base64 => Evasion::Base64,
        vahta_detect::Evasion::Concat => Evasion::Concat,
        vahta_detect::Evasion::Hex => Evasion::Hex,
    }
}

/// A secret-shaped value in a tool call: refused, or in observe mode (the
/// person's `hook_tool`, or the rule's own `mode`) let through and reported.
/// A hidden value is refused either way.
fn tool_secret(ev: &Event) -> (Decision, Option<Signal>) {
    let detection = vahta_detect::detect(&ev.text);
    if let Some(why) = detection.truncated {
        // The rules did not run in full: the journal should say so.
        daemon::observed(
            ev.tool.clone(),
            vec![format!("scan_truncated ({why:?})")],
            0,
            0,
        );
    }
    let Some(f) = detection.finding else {
        return (Decision::Allow, None);
    };
    let category = f.category.clone();
    let rule = f.rule.clone();
    let evasion = f.evasion.map(ipc_evasion);
    if f.evasion.is_none()
        && (f.mode == vahta_detect::Mode::Observe
            || daemon::hook_tool() == vahta_ipc::config::HookTool::Observe)
    {
        let signal = Signal::Observed {
            category,
            rule,
            evasion,
        };
        return (Decision::Allow, Some(signal));
    }
    let deny = Decision::Deny {
        user_message: user_blocked(&f),
        agent_message: agent_blocked(&category),
    };
    let signal = Signal::Blocked {
        category,
        rule,
        evasion,
    };
    (deny, Some(signal))
}

/// A secret in what the person typed, or in a tool's output that cannot be
/// rewritten. A hidden value is not looked for here, and neither is a rule in
/// observe mode: this is a plain look.
fn secret_in(text: &str, what: &str) -> Decision {
    let Some(f) = vahta_detect::find_secret(text)
        .filter(|f| f.evasion.is_none() && f.mode == vahta_detect::Mode::Block)
    else {
        return Decision::Allow;
    };
    let (category, rule) = (&f.category, &f.rule);
    match what {
        "prompt" => {
            let msg = format!(
                "vahta blocked this message: it looks like it contains {category} (rule {rule}). \
                 Keep the secret out of the chat, store it instead, and send the message \
                 again without it."
            );
            Decision::Deny {
                user_message: msg.clone(),
                agent_message: msg,
            }
        }
        _ => Decision::Notice {
            user_message: format!(
                "vahta: {category} reached the transcript (rule {rule}); rotate it."
            ),
            agent_message: format!(
                "{} reached the transcript through this tool's output. \
                 Treat it as exposed: tell the user to rotate it, and do not repeat the value.",
                capitalise(category)
            ),
        },
    }
}

/// Refusing a tool call that carries a value Vahta holds. The agent hears
/// how it was written, never which secret; the person hears the name.
fn deny_known_value(held: &daemon::Held) -> Decision {
    Decision::Deny {
        user_message: format!(
            "vahta blocked a tool call that carried the value of {} ({}). This may be an \
             injected instruction.",
            held.name, held.form
        ),
        agent_message: format!(
            "Blocked: this command contains a value Vahta holds ({}). Use `vahta run`.",
            held.form
        ),
    }
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
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

/// Refusing a change that would weaken Vahta's hooks: the agent is told to ask.
fn deny_hook_tamper(t: &hookguard::Tampering) -> Decision {
    let msg = format!(
        "vahta blocked a change to `{}`: it {}, and Vahta's hooks are what watch what agents do. \
         Changing hook settings goes through Vahta: ask the person with \
         `vahta hooks pause --for 1h --reason \"...\"`.",
        t.file, t.what
    );
    Decision::Deny {
        user_message: msg.clone(),
        agent_message: msg,
    }
}

/// Refusing a Vahta command that is for the person only.
fn deny_vahta_command(invocation: &str) -> Decision {
    let msg = if invocation.ends_with("_surface") {
        format!(
            "vahta blocked `{invocation}`: it is Vahta's prompt window, which only Vahta opens, for \
             the person. Do not run it."
        )
    } else {
        format!(
            "vahta blocked `{invocation}`: it shows or copies a secret value, which is for the \
             person, not an agent (a window can be captured, the clipboard can be read). Ask the \
             person to run it in their own terminal if they need it; to use a value, run the \
             command that needs it with `vahta run`."
        )
    };
    Decision::Deny {
        user_message: msg.clone(),
        agent_message: msg,
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

/// The answer to the event, and what to tell the daemon about it: each refusal
/// of something an agent tried is evidence for its alarm.
fn decide(m: &Manifest, args: &Args, ev: &Event) -> (Decision, Option<Signal>) {
    match args.kind {
        Kind::BeforeTool => {
            // Commands for the person only, then Vahta's own files: both are
            // refused whatever else is in the call, and the answer names the
            // command or the path, not the text.
            if ev.group == Some(vahta_harness::Group::Shell)
                && let Some(invocation) = agentguard::forbidden_command(&ev.text)
            {
                let signal = Signal::AgentGuard {
                    command: invocation.clone(),
                };
                return (deny_vahta_command(&invocation), Some(signal));
            }
            if let Some(file) = vahta_file_touched(ev) {
                let signal = Signal::VahtaFileTouch { path: file.clone() };
                return (deny_vahta_file(&file), Some(signal));
            }
            if let Some(t) = hookguard::tampering(ev) {
                let signal = Signal::HookTamper {
                    file: t.file.clone(),
                    what: t.what.clone(),
                };
                return (deny_hook_tamper(&t), Some(signal));
            }
            let (by_text, text_signal) = tool_secret(ev);
            if by_text != Decision::Allow {
                return (by_text, text_signal);
            }
            // A value Vahta holds for this agent, written any way. The daemon
            // records the signal itself (it knows the name); the hook only
            // refuses.
            if let Some(held) = daemon::tool_check(
                ev.session_id.clone(),
                ev.cwd.as_deref().unwrap_or_default(),
                &ev.text,
            ) {
                return (deny_known_value(&held), None);
            }
            if ev.group != Some(vahta_harness::Group::Shell) {
                return (by_text, text_signal);
            }
            // Observed in the text, but a file a command reads is refused still.
            match readguard::secret_file_in_command(&ev.text, ev.cwd.as_deref()) {
                Some((file, kind)) => (deny_read(&file, &kind), Some(read_signal(&kind))),
                None => (Decision::Allow, text_signal),
            }
        }
        Kind::BeforeRead => {
            let Some(file) = ev.path.as_deref() else {
                return (Decision::Allow, None);
            };
            if readguard::is_vahta_path(file, ev.cwd.as_deref()) {
                let signal = Signal::VahtaFileTouch {
                    path: file.to_string(),
                };
                return (deny_vahta_file(file), Some(signal));
            }
            match readguard::secret_kind_in(file, ev.cwd.as_deref(), ev.content.as_deref()) {
                Some(kind) => (deny_read(file, &kind), Some(read_signal(&kind))),
                None => (Decision::Allow, None),
            }
        }
        // The person typed the prompt: a refusal there is not the agent's doing.
        Kind::Prompt => (secret_in(&ev.text, "prompt"), None),
        Kind::AfterTool => (after_tool(m, ev), None),
        Kind::SessionStart => (session_start(m, args), None),
    }
}

/// Reading a file that holds credentials, as the daemon hears it.
fn read_signal(kind: &str) -> Signal {
    Signal::Blocked {
        category: format!("a file with credentials ({kind})"),
        rule: "read_guard".to_string(),
        evasion: None,
    }
}

fn session_start(m: &Manifest, args: &Args) -> Decision {
    match args.setup {
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
        _ => guard_reminder(),
    }
}

/// When the person turned the hook watchdog off, a reminder at the start of a
/// session: weekly, and monthly after three declines. Only the answer "off"
/// is reminded; one not given yet is for `vahta setup` and `vahta check` to
/// say. Writes the time of the reminder, and reads two small files.
fn guard_reminder() -> Decision {
    use vahta_ipc::config::Guard;
    let Ok(paths) = Paths::from_env(None) else {
        return Decision::Allow;
    };
    if Config::load(&paths.config_file())
        .ok()
        .and_then(|c| c.guard)
        != Some(Guard::Off)
    {
        return Decision::Allow;
    }
    let file = vahta_ipc::state::state_file(&paths);
    let mut state = vahta_ipc::state::State::load(&file);
    let now = vahta_ipc::state::now();
    if !state.reminder_due(now) {
        return Decision::Allow;
    }
    state.guard_reminded_at = now;
    let _ = state.save(&file);
    let line = "vahta: the hook watchdog is off, so nothing notices if an agent removes Vahta's \
                hooks; `vahta setup --guard on` turns it on"
        .to_string();
    Decision::Notice {
        agent_message: format!("{line}. Mention this to the user once."),
        user_message: line,
    }
}

/// A tool's result, about to reach the model. Where the harness can rewrite
/// it, every likely secret in it is cut out first and the model is told; a
/// merely possible one is left, and only the daemon's journal hears of it.
/// With a daemon running, the values it holds for this agent are cut too, and
/// it keeps the original so the agent can ask the person for it. Where no
/// rewrite is possible (a result too deep to rebuild, or a harness with no
/// rewrite for this tool), the person and the model are told a secret reached
/// the transcript, as before.
fn after_tool(m: &Manifest, ev: &Event) -> Decision {
    if daemon::hook_output() == vahta_ipc::config::HookOutput::Observe {
        return observe(ev);
    }
    let mcp = ev.group == Some(vahta_harness::Group::Mcp);
    let Some(output) = ev.output.as_ref().filter(|_| m.can_redact(mcp)) else {
        return secret_in(&ev.text, "output");
    };
    let texts = redact::texts_of(output);
    let (found, possible) = redact::detector_cuts(&texts);
    let asked = daemon::scan(daemon::Scan {
        cwd: ev.cwd.clone().unwrap_or_default(),
        tool: ev.tool.clone(),
        texts,
        cuts: found.clone(),
        possible,
    });
    // The daemon's list already holds the detector's finds, less what the
    // person let through; without a daemon, the detector's stand.
    let (cuts, reference) = match asked {
        Some(answer) => (answer.cuts, answer.reference),
        None => (found, None),
    };
    if cuts.is_empty() {
        return Decision::Allow;
    }
    let mut rewritten = output.clone();
    redact::apply(&mut rewritten, &cuts);
    let (agent_message, user_message) = redact_messages(&cuts, reference.as_deref());
    Decision::Redact {
        output: rewritten,
        mcp,
        agent_message,
        user_message,
    }
}

/// Observe mode (`hook_output = "observe"`): the output is not changed. The
/// person and the model are told a secret reached the transcript, exactly as
/// before redaction existed, and a running daemon journals what was seen.
fn observe(ev: &Event) -> Decision {
    let texts = match &ev.output {
        Some(output) => redact::texts_of(output),
        None => vec![ev.text.clone()],
    };
    let (likely, possible) = redact::detector_cuts(&texts);
    if !likely.is_empty() || !possible.is_empty() {
        let mut kinds: Vec<String> = likely.iter().map(|c| c.label.clone()).collect();
        kinds.extend(possible.iter().cloned());
        kinds.dedup();
        daemon::observed(ev.tool.clone(), kinds, likely.len(), possible.len());
    }
    secret_in(&ev.text, "output")
}

/// What the model and the person are told about a redaction. Names labels and
/// counts, never a value. The person hears of it only when there is no
/// reference: then nothing can be let through, and they should know.
fn redact_messages(cuts: &[redact::Cut], reference: Option<&str>) -> (String, String) {
    let n = cuts.len();
    let (values, what) = if n == 1 {
        ("value", "value was")
    } else {
        ("values", "values were")
    };
    let labels = redact::labels(cuts);
    let head = format!(
        "vahta: {n} secret {what} redacted from this tool's output before you saw it ({labels}); \
         each is shown as ***REDACTED(...)***."
    );
    match reference {
        Some(r) => (
            format!(
                "{head} If you really need them in your context, run \
                 `vahta output allow {r} --reason \"<why>\"`: the person decides in a window, \
                 and the output is printed if they agree. Otherwise, to use a secret, run the \
                 command that needs it with `vahta run`."
            ),
            String::new(),
        ),
        None => (
            format!(
                "{head} The original was not kept, so it cannot be shown to you. Do not try to \
                 recover it: to use a secret, run the command that needs it with `vahta run`."
            ),
            format!(
                "vahta redacted {n} secret {values} ({labels}) from a tool's output before the \
                 model saw it."
            ),
        ),
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
    let (decision, signal) = decide(&manifest, &args, &event);
    if let Some(signal) = signal {
        daemon::report(
            &args.harness,
            event.session_id.clone(),
            event.cwd.clone().unwrap_or_default(),
            signal,
        );
    }
    Some(manifest.render(args.kind, &decision))
}

fn main() {
    let Some(out) = run() else { return };
    let _ = std::io::stdout().write_all(&out.stdout);
    let _ = std::io::stderr().write_all(&out.stderr);
    if out.exit_code != 0 {
        std::process::exit(out.exit_code);
    }
}
