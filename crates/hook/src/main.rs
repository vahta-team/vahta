//! `vahta-hook --harness <claude|codex|cursor> --event <kind> [--setup N]`
//!
//! Kinds: `before_tool`, `before_read`, `prompt`, `after_tool`, `session_start`,
//! `session_end`, `permission_request`.
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
mod runallow;
mod strict;

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
        vahta_detect::Evasion::Percent => Evasion::Encoded,
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

/// A secret in a tool's output that cannot be rewritten. A hidden value is not
/// looked for here, and neither is a rule in observe mode: this is a plain look.
fn secret_in(harness: &str, text: &str) -> Decision {
    let Some(f) = vahta_detect::find_secret(text)
        .filter(|f| f.evasion.is_none() && f.mode == vahta_detect::Mode::Block)
    else {
        return Decision::Allow;
    };
    let (category, rule) = (&f.category, &f.rule);
    Decision::Notice {
        user_message: format!("vahta: {category} reached the transcript (rule {rule}); rotate it."),
        agent_message: format!(
            "{} reached the transcript through this tool's output. \
             Treat it as exposed: tell the user to rotate it, and do not repeat the value.{}",
            capitalise(category),
            scrub_hint(harness)
        ),
    }
}

/// What the person types, with a secret in it. The detector's rules or a value
/// Vahta holds (any form) put the prompt before the person in a window, which
/// waits: "false alarm" lets it go, "save" stores the value in the project's
/// vault and holds the prompt, "do nothing" holds it. Where no window can be
/// shown (no daemon, silence past the wait, a prompt too large to show) a
/// detected secret holds the prompt: this fails closed. A held value alone is
/// known to the daemon only, so without it there is nothing to find; instead,
/// with no daemon, any long key-like string holds the prompt (`strict.rs`).
fn prompt(args: &Args, ev: &Event) -> Decision {
    let found = vahta_detect::find_secret(&ev.text)
        .filter(|f| f.evasion.is_none() && f.mode == vahta_detect::Mode::Block);
    let cwd = ev.cwd.as_deref().unwrap_or_default();
    let checked = daemon::input_names(ev.session_id.clone(), cwd, &ev.text);
    // With no daemon the hook is the only judge and cannot ask the person, so a
    // prompt the detector passed is looked at again with a lower threshold.
    let strict = if found.is_none() && !checked.reached {
        strict::long_token(&ev.text)
    } else {
        None
    };
    let held: Vec<String> = checked.names.iter().map(|n| safe_name(n)).collect();
    if found.is_none() && held.is_empty() && strict.is_none() {
        // A clean prompt after the person saved a paste and asked for rules:
        // the blocked one is gone from the agent's context, so this one tells it.
        return if checked.bind.is_empty() {
            Decision::Allow
        } else {
            bind_now(&checked.bind)
        };
    }
    let value_of = format!("the value of {}, a secret Vahta holds", held.join(", "));
    let what = match (&found, strict) {
        (Some(f), _) if !held.is_empty() => {
            format!("{} (rule {}) and {value_of}", f.category, f.rule)
        }
        (Some(f), _) => format!("{} (rule {})", f.category, f.rule),
        (None, Some(n)) => format!(
            "a long key-like string ({n} characters; Vahta cannot tell a key from other text \
             while its daemon is not running)"
        ),
        (None, None) => value_of,
    };
    // Which secret to use instead of writing it out.
    let hint = if held.is_empty() {
        String::new()
    } else {
        format!(" {}", use_all_instead(&held))
    };
    let not_sent = |why: &str| {
        let msg = format!(
            "vahta blocked this message: it looks like it contains {what}. {why} Keep the \
             secret out of the chat, store it instead, and send the message again without it.{hint}"
        );
        Decision::Deny {
            user_message: msg.clone(),
            agent_message: msg,
        }
    };
    if ev.text.len() > daemon::MAX_PROMPT {
        return not_sent("The message is too large to show in a window.");
    }
    let outcome = daemon::prompt_ask(
        ev.session_id.clone(),
        &args.harness,
        cwd,
        &ev.text,
        found.as_ref().map(|f| f.category.clone()),
    );
    match outcome {
        daemon::PromptOutcome::Send => Decision::Allow,
        daemon::PromptOutcome::Saved { name, bind } => saved(&name, bind),
        daemon::PromptOutcome::Held { no_answer: false } => Decision::Deny {
            user_message: format!(
                "vahta did not send this message because it contained a secret. Send it again \
                 without the secret.{hint}"
            ),
            agent_message: format!("The message was not sent because it contained a secret.{hint}"),
        },
        daemon::PromptOutcome::Held { no_answer: true } => {
            not_sent("Nobody answered Vahta's window in time, so it was not sent.")
        }
        daemon::PromptOutcome::Busy { limited } => not_sent(if limited {
            "Too many checks were opened in a short time, so this one was not."
        } else {
            "Another check is open, so this one was not shown."
        }),
        daemon::PromptOutcome::Unasked => {
            not_sent("Vahta could not ask you about it (no daemon answered), so it was not sent.")
        }
    }
}

/// The message after the person saved a pasted value: the name to use instead,
/// the hint that it still needs rules, and, if the person asked for it in the
/// window, the instruction for the agent to start the bind flow. The person
/// decided; the agent only gets the instruction.
fn saved(name: &str, bind: bool) -> Decision {
    let sent = format!(
        "Saved as {name}. Your message was not sent; send it again without the key \
         (refer to it as {name})."
    );
    let user_message = if bind {
        format!(
            "{sent} The agent will be asked to propose rules for {name} with your next message; \
             you approve them in one window."
        )
    } else {
        format!(
            "{sent} {name} has no rules yet: ask the agent to propose them (`vahta bind {name}`) \
             before it is used."
        )
    };
    let agent_message = if bind {
        format!(
            "{sent} The person asked you to set up rules for {name} now: propose them for \
             [secrets.{name}] in vahta.toml (allow, network, dirs; ask the person if unsure what \
             it is for), then run `vahta bind {name}` so the person can approve them in one \
             window. Do not ask for the value."
        )
    } else {
        format!(
            "{sent} {name} has no rules yet; when the person wants to use it, propose rules for \
             [secrets.{name}] in vahta.toml and run `vahta bind {name}`."
        )
    };
    Decision::Deny {
        user_message,
        agent_message,
    }
}

/// The clean prompt that follows a save the person asked rules for: the agent
/// is told, with the secret's name only, to start the bind flow.
fn bind_now(names: &[String]) -> Decision {
    let list = names.join(", ");
    Decision::Notice {
        user_message: format!(
            "vahta: asked the agent to propose rules for {list}; you approve them in one window."
        ),
        agent_message: format!(
            "The person saved a pasted secret to the project vault as {list} and asked you to \
             set up its rules now. Before using it: propose rules for [secrets.NAME] in \
             vahta.toml for each (allow, network, dirs; ask the person if unsure what it is \
             for), then run `vahta bind NAME` so the person can approve them in one window. \
             Never ask for the value."
        ),
    }
}

/// What the agent is told about a secret it must not write out: its name, and
/// the way to use it without writing it. The name is from the daemon but is
/// put in a sentence for the model, so only the characters a name has pass.
fn use_instead(name: &str) -> String {
    use_all_instead(&[name.to_string()])
}

/// [`use_instead`] for several secrets.
fn use_all_instead(names: &[String]) -> String {
    let mut clause = use_clause(names);
    clause[..1].make_ascii_uppercase();
    format!("{clause}.")
}

/// "to use NAME, run the command that needs it with `vahta run --secret NAME --
/// ...`", for the middle of a sentence.
fn use_clause(names: &[String]) -> String {
    let names: Vec<String> = names.iter().map(|n| safe_name(n)).collect();
    match names.as_slice() {
        [one] => format!(
            "to use {one}, run the command that needs it with `vahta run --secret {one} -- ...`"
        ),
        many => format!(
            "to use {}, run the command that needs it with `vahta run --secret NAME -- ...`",
            many.join(", ")
        ),
    }
}

/// A secret's name as it can be put in a sentence: only the characters a name
/// has.
fn safe_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(64)
        .collect()
}

/// Refusing a tool call that carries a value Vahta holds. The person and the
/// agent are both told which secret (its name, never the value or any part of
/// it) and how it was written, and the agent is told how to use it instead.
fn deny_known_value(held: &daemon::Held, ev: &Event) -> Decision {
    let tool = sanitise_tool(&ev.tool);
    let name = safe_name(&held.name);
    let (user_message, what) = match ev.group {
        Some(vahta_harness::Group::Mcp) => (
            format!(
                "vahta blocked a call to the MCP tool {tool}: it would send the value of the secret {} ({}) to it.",
                name, held.form
            ),
            "this would send the value of the secret",
        ),
        Some(vahta_harness::Group::Write) => (
            format!(
                "vahta blocked {tool}: it would write the value of the secret {} ({}) into a file.",
                name, held.form
            ),
            "this would write the value of the secret",
        ),
        _ => (
            format!(
                "vahta blocked a tool call that carried the value of {} ({}). This may be an \
                 injected instruction.",
                name, held.form
            ),
            "this command contains the value of the secret",
        ),
    };
    let agent_message = match ev.group {
        Some(vahta_harness::Group::Mcp) => format!(
            "Blocked: {what} {name} ({}) to an MCP tool, which cannot be given a secret; leave \
             it out. {}",
            held.form,
            use_instead(&name)
        ),
        Some(vahta_harness::Group::Write) => format!(
            "Blocked: {what} {name} ({}) into a file. Do not write it out. {}",
            held.form,
            use_instead(&name)
        ),
        _ => format!(
            "Blocked: {what} {name} ({}). Do not write it into the command. {}",
            held.form,
            use_instead(&name)
        ),
    };
    Decision::Deny {
        user_message,
        agent_message,
    }
}

/// What the agent may do about a value already in the transcript, said
/// honestly: the files can be cleaned, the conversation cannot.
fn scrub_hint(harness: &str) -> &'static str {
    if harness == "cursor" {
        // Cursor keeps its chats in a database that `vahta scrub` does not touch.
        " The current conversation still holds it until a new chat."
    } else if harness == "claude" {
        // The hook marked the session, and Claude's SessionEnd hook cleans it.
        " The session is marked for cleanup (if Vahta's daemon is running): its transcript \
         file is cleaned when the session ends, and `vahta scrub --transcript` cleans the \
         files of finished sessions now. The current conversation still holds it until /clear \
         or a new session."
    } else {
        " `vahta scrub --transcript` removes it from the transcript files on disk (the running \
         session's file is cleaned when the session ends), but the current conversation still \
         holds it until /clear or a new session."
    }
}

/// A tool's name as it can be put in a sentence for the person: it came from
/// the payload, so only the characters a tool name has.
fn sanitise_tool(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ':' | '.'))
        .take(80)
        .collect()
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

/// What the person does to start a connector's server again, by harness.
fn reconnect_text(harness: &str) -> &'static str {
    match harness {
        "claude" => "reconnect it with `/mcp` in Claude Code",
        "codex" => "restart the Codex session",
        "cursor" => "reload the MCP server in Cursor's settings",
        _ => "reconnect it in the harness",
    }
}

/// Refusing a Vahta command that is for the person only.
fn deny_vahta_command(invocation: &str, harness: &str) -> Decision {
    let msg = if invocation.ends_with("--connector") {
        let reconnect = reconnect_text(harness);
        if invocation.contains(" unlock ") || invocation.contains(" run ") {
            format!(
                "vahta blocked `{invocation}`: there is nothing to run. The connectors vault is \
                 unlocked by the person, in a password window that opens when the harness \
                 starts an MCP server; an agent cannot start a connector's server or unlock it. \
                 If a server failed to start, ask the person to {reconnect} (they enter the \
                 connectors password when the window opens)."
            )
        } else {
            format!(
                "vahta blocked `{invocation}`: the connectors vault is set up by the person in \
                 their own terminal. The harness starts a connector's server itself, and the \
                 person unlocks it in a password window that opens then; there is nothing to run \
                 from here. Ask the person if a connector needs a change, or, if a server failed \
                 to start, to {reconnect}."
            )
        }
    } else if invocation.ends_with("_surface") {
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

/// A tool call about to run. `explicit` says whether this harness can be told
/// "allow" out loud for this event.
fn before_tool(ev: &Event, explicit: bool, harness: &str) -> (Decision, Option<Signal>) {
    // Commands for the person only, then Vahta's own files: both are
    // refused whatever else is in the call, and the answer names the
    // command or the path, not the text.
    if ev.group == Some(vahta_harness::Group::Shell)
        && let Some(invocation) = agentguard::forbidden_command(&ev.text)
    {
        let signal = Signal::AgentGuard {
            command: invocation.clone(),
        };
        return (deny_vahta_command(&invocation, harness), Some(signal));
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
        return (deny_known_value(&held, ev), None);
    }
    if ev.group != Some(vahta_harness::Group::Shell) {
        return (by_text, text_signal);
    }
    // Observed in the text, but a file a command reads is refused still.
    match readguard::secret_file_in_command(&ev.text, ev.cwd.as_deref()) {
        Some((file, kind)) => (deny_read(&file, &kind), Some(read_signal(&kind))),
        None if text_signal.is_none() => (allow_or_approve(ev, explicit), None),
        None => (Decision::Allow, text_signal),
    }
}

/// `dir` made absolute against `cwd` by the text alone, so it reads the same on
/// every OS: a path absolute in either convention (`/x`, `C:\x`, `C:/x`,
/// `\\server\share`) stays as it is, anything else is joined to `cwd` with `/`.
fn absolute_in(cwd: &str, dir: String) -> String {
    let b = dir.as_bytes();
    let absolute = b.first() == Some(&b'/')
        || (b.len() >= 3
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && matches!(b[2], b'/' | b'\\'))
        || dir.starts_with("\\\\");
    if absolute {
        dir
    } else {
        format!("{}/{dir}", cwd.trim_end_matches(['/', '\\']))
    }
}

/// A call nothing refused. Silence (`Allow`), unless it is one `vahta run` (or
/// `vahta http`) that the secret's own rules let through: then the harness is told so, and need
/// not ask the person. Needs a shell call, a harness that can hear it, and a
/// daemon that answers in time with a yes.
fn allow_or_approve(ev: &Event, explicit: bool) -> Decision {
    // Leaving the sandbox is the person's to approve, not ours.
    if !explicit || ev.group != Some(vahta_harness::Group::Shell) || ev.sandbox_off {
        return Decision::Allow;
    }
    let (Some(call), Some(cwd)) = (runallow::parse(&ev.text), ev.cwd.as_deref()) else {
        return Decision::Allow;
    };
    // `--vault DIR` is relative to the directory the command runs in.
    let absolute = |v: Option<String>| v.map(|v| absolute_in(cwd, v));
    let (names, allowed, what) = match call {
        runallow::Call::Run(c) => (
            c.names.clone(),
            daemon::run_allowed(cwd, c.argv, c.names, absolute(c.vault)),
            "the command is within",
        ),
        runallow::Call::Http(c) => (
            c.names.clone(),
            daemon::http_allowed(cwd, c.url, c.names, absolute(c.vault)),
            "the request goes to a host within",
        ),
    };
    if !allowed {
        return Decision::Allow;
    }
    let whose = match names.as_slice() {
        [] => "this project's secrets".to_string(),
        [one] => one.clone(),
        many => many.join(", "),
    };
    Decision::AllowExplicit {
        reason: format!("Vahta: {what} {whose}'s approved rules"),
    }
}

/// The answer to the event, and what to tell the daemon about it: each refusal
/// of something an agent tried is evidence for its alarm.
fn decide(m: &Manifest, args: &Args, ev: &Event) -> (Decision, Option<Signal>) {
    match args.kind {
        Kind::BeforeTool => before_tool(ev, m.can_allow_explicit(Kind::BeforeTool), &args.harness),
        // Codex asks the hook when it is about to ask the person. The same
        // judgement as before the call; the only thing worth saying is an
        // allow, and the refusals were already made (and reported) there.
        Kind::PermissionRequest => {
            let (decision, _) = before_tool(
                ev,
                m.can_allow_explicit(Kind::PermissionRequest),
                &args.harness,
            );
            (decision, None)
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
        Kind::Prompt => (prompt(args, ev), None),
        Kind::AfterTool => (after_tool(m, ev), None),
        Kind::SessionStart => (session_start(m, args), None),
        // Nothing to say; `run` tells the daemon.
        Kind::SessionEnd => (Decision::Allow, None),
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
        return observe(m, ev);
    }
    let mcp = ev.group == Some(vahta_harness::Group::Mcp);
    let Some(output) = ev.output.as_ref().filter(|_| m.can_redact(mcp)) else {
        return secret_in(&m.name, &ev.text);
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
fn observe(m: &Manifest, ev: &Event) -> Decision {
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
    secret_in(&m.name, &ev.text)
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
    let known = redact::known_names(cuts);
    let head = format!(
        "vahta: {n} secret {what} redacted from this tool's output before you saw it ({labels}); \
         each is shown as ***REDACTED(...)***."
    );
    // Which secrets, and how to use them without printing them.
    let how = if known.is_empty() {
        "to use a secret, run the command that needs it with `vahta run`".to_string()
    } else {
        use_clause(&known)
    };
    match reference {
        Some(r) => (
            format!(
                "{head} If you really need them in your context, run \
                 `vahta output allow {r} --reason \"<why>\"`: the person decides in a window, \
                 and the output is printed if they agree. Otherwise, {how}."
            ),
            String::new(),
        ),
        None => (
            format!(
                "{head} The original was not kept, so it cannot be shown to you. Do not try to \
                 recover it: {how}."
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
    if matches!(args.kind, Kind::SessionStart | Kind::SessionEnd) {
        daemon::session_note(
            event.session_id.clone(),
            &args.harness,
            event.cwd.clone().unwrap_or_default(),
            args.kind == Kind::SessionEnd,
        );
    }
    let (decision, signal) = decide(&manifest, &args, &event);
    // A secret cut out of an output (or one that reached the transcript): the
    // transcript is marked for the cleanup at the session's end, by the hook
    // itself, so the agent need not run anything.
    if args.kind == Kind::AfterTool
        && matches!(decision, Decision::Redact { .. } | Decision::Notice { .. })
    {
        daemon::session_dirty(
            event.session_id.clone(),
            &args.harness,
            event.cwd.clone().unwrap_or_default(),
        );
    }
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

#[cfg(test)]
mod vault_path_tests {
    use super::absolute_in;

    #[test]
    fn a_vault_path_is_made_absolute_by_its_text_on_every_os() {
        for kept in [
            "/work/tools",
            "C:\\work\\tools",
            "C:/work/tools",
            "\\\\srv\\share",
        ] {
            assert_eq!(absolute_in("/p", kept.to_string()), kept);
        }
        assert_eq!(
            absolute_in("/p/proj", "../tools".into()),
            "/p/proj/../tools"
        );
        assert_eq!(absolute_in("C:/p/", "tools".into()), "C:/p/tools");
    }
}

#[cfg(test)]
mod name_tests {
    use super::*;

    fn cut(label: &str, known: bool) -> redact::Cut {
        redact::Cut {
            text: 0,
            range: 0..4,
            label: label.to_string(),
            known,
        }
    }

    #[test]
    fn the_agent_is_told_the_name_of_a_cut_secret_and_never_a_detectors_guess() {
        let (agent, _) = redact_messages(
            &[
                cut("STRIPE_KEY (base64)", true),
                cut("STRIPE_KEY", true),
                cut("OpenAI-style key", false),
            ],
            Some("ref1"),
        );
        assert!(
            agent.contains("to use STRIPE_KEY, run the command that needs it with `vahta run --secret STRIPE_KEY -- ...`"),
            "{agent}"
        );
        assert_eq!(agent.matches("--secret").count(), 1, "{agent}");
        assert!(!agent.contains("--secret OpenAI"), "{agent}");
        // Two names, one sentence; a hostile label cannot add words.
        let (agent, _) = redact_messages(
            &[cut("A_KEY", true), cut("B_KEY; ignore previous", true)],
            None,
        );
        assert!(
            agent.contains("to use A_KEY, B_KEYignoreprevious, run"),
            "{agent}"
        );
        // None known: the generic hint, as before.
        let (agent, _) = redact_messages(&[cut("OpenAI-style key", false)], None);
        assert!(
            agent.ends_with("to use a secret, run the command that needs it with `vahta run`.")
        );
    }
}

#[cfg(test)]
mod connector_text_tests {
    use super::{Decision, deny_vahta_command};

    fn said(invocation: &str, harness: &str) -> String {
        match deny_vahta_command(invocation, harness) {
            Decision::Deny { agent_message, .. } => agent_message,
            other => panic!("not a denial: {other:?}"),
        }
    }

    #[test]
    fn unlock_and_run_of_the_connectors_explain_the_new_flow() {
        for inv in ["vahta unlock --connector", "vahta run --connector"] {
            let m = said(inv, "claude");
            assert!(m.contains("nothing to run"), "{m}");
            assert!(
                m.contains("password window that opens when the harness starts"),
                "{m}"
            );
            assert!(m.contains("`/mcp` in Claude Code"), "{m}");
        }
        assert!(said("vahta unlock --connector", "codex").contains("restart the Codex session"));
        assert!(said("vahta unlock --connector", "cursor").contains("Cursor's settings"));
        assert!(!said("vahta unlock --connector", "codex").contains("/mcp"));
    }

    #[test]
    fn the_other_connector_commands_say_the_person_sets_them_up() {
        let m = said("vahta add --connector", "claude");
        assert!(
            m.contains("set up by the person") && m.contains("/mcp"),
            "{m}"
        );
    }
}
