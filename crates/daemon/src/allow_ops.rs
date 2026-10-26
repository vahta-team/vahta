//! An agent asks the person about one refused tool call: the hook's
//! [`ClientRequest::ToolRefuse`] and the agent's `vahta allow REF`
//! ([`ClientRequest::ToolAllow`]).
//!
//! **Refuse.** The hook's detector refused a tool call (a Bash command, a
//! write, an MCP input). The hook sends the call's text; the daemon keeps a
//! keyed hash of it (HMAC-SHA256 under a key drawn at start, over the harness
//! session, the project directory, the tool and the text) and, in memory only,
//! the spans the detector's matchers find in it, under a short reference the
//! agent is told. The same message also asks "did the person let exactly this
//! call through?": if so, the hook is told to pass it, once.
//!
//! **Allow.** The agent, from its own process tree, names the reference and a
//! reason (shown to the person as unverified). A window says what was refused,
//! by which rule, and what matched (a vendor-format key as its kind, length
//! and four characters at each end; a value found only by the name it was
//! assigned to, when the matcher is unsure of it, whole), and offers three
//! ways out: let this call through once, save the value in the project's vault
//! (the agent is told the name only), or refuse. No answer in the window's
//! time is a refusal. One window at a time and four a minute, as for a prompt
//! (`input_ops.rs`); every ask also weighs a little for the injection alarm.
//!
//! "Once" is five minutes, for the same session in the same project, and for
//! the exact same text: any change is a new refusal, and the allowance is used
//! up by the first retry. A harness that asks the hook twice for one call
//! (Codex's permission request) is answered the second time without using
//! anything up.
//!
//! Nothing here is on disk. The journal gets names, kinds and results, never a
//! value or any of the command.
//!
//! [`ClientRequest::ToolRefuse`]: crate::protocol::ClientRequest::ToolRefuse
//! [`ClientRequest::ToolAllow`]: crate::protocol::ClientRequest::ToolAllow

use std::path::PathBuf;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use vahta_os::ProcessId;
use zeroize::Zeroizing;

use vahta_detect::Confidence;
use vahta_vault::Vault;

use crate::input_ops::{ALARM_SHARE, ASK_WAIT, Admit, MAX_WINDOWS, offer_bind, suggested_name};
use crate::journal::Entry;
use crate::ops::{Ctx, Flow, error, find_vault, from_surface, refused};
use crate::output::{Asked, HeldCut, anchor_of, save};
use crate::protocol::{ClientReply, RefusalKind};
use crate::surface::sanitize_label;

/// How long a refusal is kept for the agent to ask about.
const KEEP_FOR: Duration = Duration::from_secs(10 * 60);
/// How long a call the person let through may be retried.
pub(crate) const ALLOW_FOR: Duration = Duration::from_secs(5 * 60);
/// How long after its use an allowance still answers a peek (the second hook
/// event of the same call).
const USED_GRACE: Duration = Duration::from_secs(2 * 60);
/// At most this many refusals are kept; the oldest goes first.
const MAX_KEPT: usize = 16;
/// At most this many allowances; the oldest goes first.
const MAX_ALLOWED: usize = 64;
/// At most this many spans of one refusal are kept and shown.
const MAX_SPANS: usize = 6;
/// How much of the call's start the window shows, with the finds hidden.
const SHOW_START: usize = 100;
/// The longest whole value a window shows.
const SHOW_WHOLE: usize = 80;
/// How much one `vahta allow` weighs for the injection alarm, of its
/// threshold: ten in ten minutes raise it. A refusal that is a false alarm is
/// asked about once or twice.
const ASK_SHARE: f64 = 0.1;
/// A value shorter than this shows nothing of itself, not even its ends.
const ENDS_FROM: usize = 24;

/// One find in a refused call: its kind and the value, in memory only.
#[derive(Clone)]
struct Found {
    kind: String,
    sure: bool,
    value: Zeroizing<String>,
}

/// A refused call the agent may ask about.
#[derive(Clone)]
struct Kept {
    anchor: ProcessId,
    hash: [u8; 32],
    session: Option<String>,
    harness: String,
    cwd: String,
    tool: String,
    path: Option<String>,
    category: String,
    rule: String,
    description: String,
    found: Vec<Found>,
    /// The start of the call with the finds hidden; `None` when the call has
    /// no place to hide them (so nothing of it may be shown).
    start: Option<String>,
    expires: Instant,
}

impl Kept {
    /// A vendor-format key is one a rule names by its prefix, or a find the
    /// name it was assigned to does not explain.
    fn vendor_format(&self) -> bool {
        self.rule.starts_with("vahta.prefix.") || self.found.iter().any(|f| !heuristic(&f.kind))
    }
}

/// A find that is a value assigned to a secret-like name, not a key shape.
fn heuristic(kind: &str) -> bool {
    kind.ends_with(" assignment") || kind.ends_with(" flag value")
}

struct Allowance {
    anchor: ProcessId,
    hash: [u8; 32],
    expires: Instant,
    /// When the retry used it up.
    used: Option<Instant>,
}

/// The refused calls and the allowances, as keyed hashes where they are looked
/// up by the call.
pub(crate) struct Refusals {
    key: Zeroizing<[u8; 32]>,
    kept: Vec<(String, Kept)>,
    allowed: Vec<Allowance>,
}

impl Refusals {
    /// A fresh table with a new key; `None` when the system random generator
    /// fails.
    pub fn new() -> Option<Refusals> {
        Some(Refusals {
            key: Zeroizing::new(vahta_vault::crypto::random::<32>().ok()?),
            kept: Vec::new(),
            allowed: Vec::new(),
        })
    }

    /// The call as a hash: the session, the directory, the tool and the text
    /// each end where the next begins, so none can be moved into another.
    fn hash(&self, session: Option<&str>, cwd: &str, tool: &str, text: &str) -> [u8; 32] {
        // HMAC takes a key of any length; `new_from_slice` cannot fail.
        let mut mac = match <Hmac<Sha256> as Mac>::new_from_slice(&self.key[..]) {
            Ok(m) => m,
            Err(_) => return [0; 32],
        };
        for part in [
            session.unwrap_or("").as_bytes(),
            cwd.as_bytes(),
            tool.as_bytes(),
        ] {
            mac.update(&(part.len() as u64).to_le_bytes());
            mac.update(part);
        }
        mac.update(text.as_bytes());
        mac.finalize().into_bytes().into()
    }

    fn sweep(&mut self, now: Instant) {
        self.kept.retain(|(_, k)| k.expires > now);
        self.allowed.retain(|a| a.expires > now);
    }

    /// Whether the person has let this call through. `use_up`: the answer is
    /// the use (a retry); without it, a look (the second event of one call),
    /// which also holds for a short while after the use.
    fn passes(&mut self, anchor: &ProcessId, hash: &[u8; 32], now: Instant, use_up: bool) -> bool {
        self.sweep(now);
        let Some(a) = self
            .allowed
            .iter_mut()
            .find(|a| &a.anchor == anchor && &a.hash == hash)
        else {
            return false;
        };
        match a.used {
            None => {
                if use_up {
                    a.used = Some(now);
                }
                true
            }
            Some(at) => !use_up && now.saturating_duration_since(at) < USED_GRACE,
        }
    }

    /// Keep `kept` under a reference: the one it already has, if the same
    /// call is kept already.
    fn keep(&mut self, kept: Kept, now: Instant) -> Option<String> {
        self.sweep(now);
        if let Some((reference, old)) = self
            .kept
            .iter_mut()
            .find(|(_, k)| k.anchor == kept.anchor && k.hash == kept.hash)
        {
            *old = kept;
            return Some(reference.clone());
        }
        let reference = vahta_vault::hex_encode(&vahta_vault::crypto::random::<4>().ok()?);
        if self.kept.len() >= MAX_KEPT {
            self.kept.remove(0);
        }
        self.kept.push((reference.clone(), kept));
        Some(reference)
    }

    fn get(&mut self, reference: &str, anchor: &ProcessId, now: Instant) -> Option<Kept> {
        self.sweep(now);
        self.kept
            .iter()
            .find(|(r, k)| r == reference && &k.anchor == anchor)
            .map(|(_, k)| k.clone())
    }

    fn forget(&mut self, reference: &str) {
        self.kept.retain(|(r, _)| r != reference);
    }

    /// The person let the call kept under `reference` through, once.
    fn allow_once(&mut self, anchor: ProcessId, hash: [u8; 32], now: Instant) {
        self.allowed
            .retain(|a| !(a.anchor == anchor && a.hash == hash));
        if self.allowed.len() >= MAX_ALLOWED {
            self.allowed.remove(0);
        }
        self.allowed.push(Allowance {
            anchor,
            hash,
            expires: now + ALLOW_FOR,
            used: None,
        });
    }
}

/// What the hook tells the daemon about a refused call.
pub(crate) struct Refused<'a> {
    pub session: Option<&'a str>,
    pub harness: &'a str,
    pub cwd: &'a str,
    pub tool: &'a str,
    pub path: Option<&'a str>,
    pub text: &'a str,
    pub category: &'a str,
    pub rule: &'a str,
    pub description: &'a str,
    pub peek: bool,
}

fn no(reference: Option<String>) -> ClientReply {
    ClientReply::ToolRefusal {
        pass: false,
        reference,
    }
}

/// `text` with the finds hidden, at most [`SHOW_START`] characters of its
/// first line.
fn start_of(text: &str, spans: &[vahta_detect::SecretSpan]) -> String {
    let mut out = String::new();
    let mut at = 0;
    for s in spans {
        if s.range.start < at || s.range.end > text.len() {
            continue;
        }
        out.push_str(&text[at..s.range.start]);
        out.push_str("***");
        at = s.range.end;
    }
    out.push_str(&text[at..]);
    let line = out.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let shown: String = line.chars().take(SHOW_START).collect();
    sanitize_label(&shown).unwrap_or_default()
}

/// `ToolRefuse`: is this call one the person let through, and if not, keep it
/// for the agent to ask about.
pub(crate) fn tool_refuse(ctx: &Ctx<'_>, r: Refused<'_>) -> ClientReply {
    let Some((anchor, _)) = anchor_of(ctx) else {
        return no(None);
    };
    let now = Instant::now();
    let hash = {
        let Ok(mut table) = ctx.shared.refusals.lock() else {
            return no(None);
        };
        let hash = table.hash(r.session, r.cwd, r.tool, r.text);
        if table.passes(&anchor, &hash, now, !r.peek) {
            drop(table);
            if !r.peek {
                ctx.journal(Entry::new("tool_allow_used").result(
                    "passed",
                    Some(&format!("{}; tool {}", r.harness, label(r.tool))),
                ));
            }
            return ClientReply::ToolRefusal {
                pass: true,
                reference: None,
            };
        }
        hash
    };
    if r.peek {
        return no(None);
    }
    let spans = vahta_detect::find_secret_spans(r.text);
    let start = (!spans.is_empty()).then(|| start_of(r.text, &spans));
    let found: Vec<Found> = spans
        .iter()
        .take(MAX_SPANS)
        .filter(|s| s.range.end <= r.text.len())
        .map(|s| Found {
            kind: sanitize_label(&s.kind).unwrap_or_else(|| "a secret".to_string()),
            sure: s.confidence == Confidence::Likely,
            value: Zeroizing::new(r.text[s.range.clone()].to_string()),
        })
        .collect();
    let kept = Kept {
        anchor,
        hash,
        session: r.session.map(str::to_string),
        harness: r.harness.to_string(),
        cwd: r.cwd.to_string(),
        tool: label(r.tool),
        path: r.path.and_then(sanitize_label),
        category: label(r.category),
        rule: label(r.rule),
        description: label(r.description),
        found,
        start,
        expires: now + KEEP_FOR,
    };
    let reference = ctx
        .shared
        .refusals
        .lock()
        .ok()
        .and_then(|mut t| t.keep(kept, now));
    no(reference)
}

fn label(raw: &str) -> String {
    crate::output::clean_label(raw)
}

/// What a window shows of one find.
fn describe(f: &Found) -> String {
    let len = f.value.chars().count();
    if heuristic(&f.kind) && !f.sure {
        // The matcher is unsure it is a secret: seeing what it saw is the way
        // to tell. The person's own screen; the value is not a key.
        let whole: String = f.value.chars().take(SHOW_WHOLE).collect();
        let whole = sanitize_label(&whole).unwrap_or_default();
        return format!("  - {}, {len} characters: {whole}", f.kind);
    }
    match ends_of_four(&f.value) {
        Some(ends) => format!("  - {}, {len} characters, {ends}", f.kind),
        None => format!("  - {}, {len} characters", f.kind),
    }
}

/// The first and last four characters of a value long enough that its ends
/// tell little.
fn ends_of_four(value: &str) -> Option<String> {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < ENDS_FROM {
        return None;
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    sanitize_label(&format!("{head}...{tail}"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Way {
    Allow,
    Save,
    Refuse,
}

fn cancelled(message: &str) -> ClientReply {
    ClientReply::Cancelled {
        message: message.to_string(),
    }
}

/// `ToolAllow`: ask the person about the refused call kept under `reference`.
pub(crate) fn allow(ctx: &Ctx<'_>, reference: &str, reason: Option<String>) -> Flow<ClientReply> {
    let not_here = || {
        refused(
            RefusalKind::UnknownToolCall,
            "no refused tool call is kept under that reference for this agent (one is kept for \
             10 minutes, and only its own agent may ask); nothing was allowed",
        )
    };
    let (anchor, anchor_exe) = anchor_of(ctx).ok_or_else(not_here)?;
    let kept = ctx
        .shared
        .refusals
        .lock()
        .map_err(|_| error("the table of refused calls is unusable"))?
        .get(reference, &anchor, Instant::now())
        .ok_or_else(not_here)?;

    let kinds: Vec<String> = {
        let mut k: Vec<String> = Vec::new();
        for f in &kept.found {
            if !k.contains(&f.kind) {
                k.push(f.kind.clone());
            }
        }
        k
    };
    let vendor = kept.vendor_format();
    let record = |result: &str, note: Option<&str>| {
        let mut what = format!("ref {reference}; tool {}; rule {}", kept.tool, kept.rule);
        if let Some(note) = note {
            what.push_str("; ");
            what.push_str(note);
        }
        ctx.journal(
            Entry::new("tool_allow")
                .names(&kinds)
                .result(result, Some(&what)),
        );
    };

    // Every ask weighs a little with the alarm, together with the refusals
    // that led to it; too many windows weigh a lot.
    let subject = crate::report::subject_of(ctx, &kept.harness, kept.session.as_deref());
    let muted = crate::testing::refusal_alarm_muted();
    let score = |share: f64, what: &str| {
        if !muted
            && let Some(verdict) = ctx.shared.alarm.record_scored(
                &subject,
                crate::alarm::THRESHOLD * share,
                what.to_string(),
                Instant::now(),
            )
        {
            crate::alarm::raise(ctx.shared, subject.clone(), verdict);
        }
    };
    score(ASK_SHARE, "asked to let a refused tool call through");
    let _permit = match ctx
        .shared
        .prompt_gate
        .admit(&format!("allow:{}", subject.key))
    {
        Admit::Go(p) => p,
        Admit::Busy => {
            record("busy", None);
            return Err(cancelled(
                "another window of Vahta's is open, so this one was not shown; try again in a \
                 moment",
            ));
        }
        Admit::TooMany => {
            record(
                "rate_limited",
                Some(&format!(
                    "suspicious: {} asked for more than {MAX_WINDOWS} windows in a minute",
                    subject.shown
                )),
            );
            score(ALARM_SHARE, "too many requests to allow a tool call");
            return Err(cancelled(
                "too many requests in a short time; the person was not asked",
            ));
        }
    };

    // The vault to save into: the session's own comes first, as for an output
    // (Claude Code reports the agent's directory, not where a command went).
    let chain = vahta_os::ancestor_chain(ctx.pid, vahta_os::MAX_ANCESTORS);
    let session_vault: Option<PathBuf> = ctx
        .shared
        .sessions
        .lock()
        .ok()
        .and_then(|s| s.covering(&chain).first().map(|s| s.vault_path.clone()));
    let vault: Option<PathBuf> =
        session_vault.or_else(|| find_vault(&kept.cwd).ok().map(|(_, path)| path));
    let taken = |name: &str| match &vault {
        Some(path) => Vault::peek(path)
            .map(|p| p.entries.iter().any(|e| e.name == name))
            .unwrap_or(true),
        None => false,
    };
    let saveable = vault.is_some() && !kept.found.is_empty();
    let suggestion = kept
        .found
        .first()
        .map(|f| suggested_name(&f.kind, &taken))
        .unwrap_or_default();

    let title = "An agent asks to let a refused tool call through";
    let mut lines = vec![
        format!("Agent: {anchor_exe} (pid {})", anchor.pid),
        format!("Tool: {}", kept.tool),
        format!(
            "Directory: {}",
            sanitize_label(&kept.cwd).unwrap_or_default()
        ),
    ];
    match (&kept.path, &kept.start) {
        (Some(path), _) => lines.push(format!("File: {path}")),
        (None, Some(start)) if !start.is_empty() => {
            lines.push(format!("Starts with: {start}"));
        }
        _ => {}
    }
    lines.push(format!(
        "Vahta refused it as {} (rule {}: {}).",
        kept.category,
        kept.rule,
        kept.description.trim_end_matches('.')
    ));
    if kept.found.is_empty() {
        lines.push(
            "  - the rule does not say where in the call; nothing of it is shown".to_string(),
        );
    } else {
        lines.push("It matched:".to_string());
        lines.extend(kept.found.iter().map(describe));
    }
    if let Some(path) = &vault
        && saveable
    {
        lines.push(format!("Vault: {}", path.display()));
    }
    lines.push(format!(
        "With no answer in {} seconds the call stays refused.",
        ASK_WAIT.as_secs()
    ));
    let mut panel = ctx.panel(title, lines);
    panel.agent_note = reason.as_deref().and_then(sanitize_label);
    panel.warning = Some(if vendor {
        "This looks like a real key's format. Say yes only if you know it is not a secret."
            .to_string()
    } else {
        "Say yes only if the match is not a secret. The agent's reason is not checked.".to_string()
    });

    let mut ways = vec![Way::Allow];
    let mut options = vec!["False alarm \u{2014} let it through once".to_string()];
    if saveable {
        ways.push(Way::Save);
        options.push(format!(
            "It is a secret \u{2014} save to the project vault as {suggestion}"
        ));
    }
    ways.push(Way::Refuse);
    options.push("Refuse".to_string());

    let mut window = ctx.window(title)?;
    let way = window
        .choose_within(&panel, "What should Vahta do?", &options, ASK_WAIT)
        .map_err(from_surface)?
        .and_then(|i| ways.get(i).copied());
    let forget = || {
        if let Ok(mut t) = ctx.shared.refusals.lock() {
            t.forget(reference);
        }
    };
    match way {
        Some(Way::Allow) => {
            if let Ok(mut t) = ctx.shared.refusals.lock() {
                t.allow_once(anchor, kept.hash, Instant::now());
            }
            forget();
            if vendor {
                record(
                    "allowed_once_vendor_format",
                    Some("a vendor-format match was let through"),
                );
            } else {
                record("allowed_once", None);
            }
            window.close(Some("The call may go through once."));
            Ok(ClientReply::Done {
                message: format!(
                    "the person allowed it once. Retry the same call, unchanged, within {} \
                     minutes; any change to it is checked again",
                    ALLOW_FOR.as_secs() / 60
                ),
            })
        }
        Some(Way::Save) => {
            let Some(vault_path) = &vault else {
                return Err(error("there is no vault to save into"));
            };
            let asked = Asked {
                texts: Zeroizing::new(kept.found.iter().map(|f| f.value.to_string()).collect()),
                cuts: Vec::new(),
                cwd: kept.cwd.clone(),
                tool: kept.tool.clone(),
            };
            let cuts: Vec<HeldCut> = kept
                .found
                .iter()
                .enumerate()
                .map(|(i, f)| HeldCut {
                    text: i,
                    start: 0,
                    end: f.value.len(),
                    label: f.kind.clone(),
                    exact: false,
                })
                .collect();
            panel.lines.push(format!(
                "Press Enter at the name to take {suggestion}; the vault password follows."
            ));
            match save(
                ctx,
                window.as_mut(),
                &mut panel,
                vault_path,
                &asked,
                &cuts,
                Some(&suggestion),
            ) {
                Ok(name) => {
                    forget();
                    let bind = offer_bind(
                        window.as_mut(),
                        ctx,
                        &name,
                        "The tool call was not allowed.",
                    );
                    ctx.journal(
                        Entry::new("tool_allow")
                            .names(std::slice::from_ref(&name))
                            .result(
                                if bind {
                                    "saved_bind_offered_yes"
                                } else {
                                    "saved_bind_offered_no"
                                },
                                Some(&format!("ref {reference}; rule {}", kept.rule)),
                            ),
                    );
                    window.close(Some(&format!("Saved {name}. The call stays refused.")));
                    Ok(ClientReply::Done {
                        message: saved_message(&name, bind),
                    })
                }
                Err(reply) => {
                    // Cancelled, a wrong password, a taken name: nothing was
                    // stored, and the call stays refused.
                    record("save_failed", None);
                    window.close(Some("Nothing was saved. The call stays refused."));
                    Err(reply)
                }
            }
        }
        Some(Way::Refuse) => {
            forget();
            record("refused", None);
            window.close(Some("The call stays refused."));
            Err(cancelled(
                "the person refused; the call stays refused. Keep the secret out of it: put it \
                 in Vahta and use `vahta run -- ...`",
            ))
        }
        None => {
            record("no_answer", None);
            window.close(Some("No answer. The call stays refused."));
            Err(cancelled(
                "the person did not answer in time; the call stays refused",
            ))
        }
    }
}

/// What the agent is told after the person saved the value: the name, never
/// the value, and whether it is to propose rules now.
fn saved_message(name: &str, bind: bool) -> String {
    let base = format!(
        "the person says it is a secret and saved it as {name}; the call stays refused. Do not \
         write the value out: run the command that needs it with \
         `vahta run --secret {name} -- COMMAND`."
    );
    if bind {
        format!(
            "{base} The person asked you to set up rules for {name} now: propose them for \
             [secrets.{name}] in vahta.toml (allow, network, dirs; ask the person if unsure \
             what it is for), then run `vahta bind {name}` so the person can approve them in \
             one window. Do not ask for the value."
        )
    } else {
        format!(
            "{base} {name} has no rules yet; when the person wants to use it, propose rules \
             for [secrets.{name}] in vahta.toml and run `vahta bind {name}`."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u32) -> ProcessId {
        ProcessId {
            pid: n,
            start_time: u64::from(n) * 7,
        }
    }

    fn kept(anchor: ProcessId, hash: [u8; 32], now: Instant) -> Kept {
        Kept {
            anchor,
            hash,
            session: None,
            harness: "claude".to_string(),
            cwd: "/p".to_string(),
            tool: "Bash".to_string(),
            path: None,
            category: "a secret".to_string(),
            rule: "r".to_string(),
            description: "d".to_string(),
            found: Vec::new(),
            start: None,
            expires: now + KEEP_FOR,
        }
    }

    #[test]
    fn the_hash_is_keyed_and_tells_session_directory_tool_and_text_apart() {
        let (a, b) = (Refusals::new().unwrap(), Refusals::new().unwrap());
        let h = a.hash(Some("s1"), "/p", "Bash", "ls");
        assert_eq!(h, a.hash(Some("s1"), "/p", "Bash", "ls"));
        assert_ne!(h, a.hash(Some("s2"), "/p", "Bash", "ls"));
        assert_ne!(h, a.hash(None, "/p", "Bash", "ls"));
        assert_ne!(h, a.hash(Some("s1"), "/q", "Bash", "ls"));
        assert_ne!(h, a.hash(Some("s1"), "/p", "Write", "ls"));
        assert_ne!(h, a.hash(Some("s1"), "/p", "Bash", "ls "));
        // Text cannot be moved across a boundary into the tool name.
        assert_ne!(
            a.hash(Some("s1"), "/p", "Bash", "xls"),
            a.hash(Some("s1"), "/p", "Bashx", "ls")
        );
        assert_ne!(h, b.hash(Some("s1"), "/p", "Bash", "ls"));
    }

    #[test]
    fn an_allowance_is_used_once_for_its_agent_and_runs_out() {
        let now = Instant::now();
        let mut t = Refusals::new().unwrap();
        let h = t.hash(Some("s1"), "/p", "Bash", "ls");
        assert!(!t.passes(&pid(1), &h, now, true));
        t.allow_once(pid(1), h, now);
        // Another agent, another call: no.
        assert!(!t.passes(&pid(2), &h, now, true));
        assert!(!t.passes(
            &pid(1),
            &t.hash(Some("s1"), "/p", "Bash", "ls -l"),
            now,
            true
        ));
        // A look does not use it up; the retry does, and only once.
        assert!(t.passes(&pid(1), &h, now, false));
        assert!(t.passes(&pid(1), &h, now, true));
        assert!(!t.passes(&pid(1), &h, now, true));
        // The second event of the same call still sees it, for a while.
        assert!(t.passes(&pid(1), &h, now + Duration::from_secs(30), false));
        assert!(!t.passes(
            &pid(1),
            &h,
            now + USED_GRACE + Duration::from_secs(1),
            false
        ));
        // Unused, it runs out.
        t.allow_once(pid(1), h, now);
        assert!(!t.passes(&pid(1), &h, now + ALLOW_FOR + Duration::from_secs(1), true));
    }

    #[test]
    fn a_refusal_is_kept_under_one_reference_for_its_agent_only() {
        let now = Instant::now();
        let mut t = Refusals::new().unwrap();
        let h = t.hash(None, "/p", "Bash", "ls");
        let r = t.keep(kept(pid(1), h, now), now).unwrap();
        assert_eq!(r.len(), 8);
        // The same call again is the same reference.
        assert_eq!(
            t.keep(kept(pid(1), h, now), now).as_deref(),
            Some(r.as_str())
        );
        assert!(t.get(&r, &pid(1), now).is_some());
        assert!(t.get(&r, &pid(2), now).is_none());
        assert!(t.get("nope", &pid(1), now).is_none());
        t.forget(&r);
        assert!(t.get(&r, &pid(1), now).is_none());
        let r = t.keep(kept(pid(1), h, now), now).unwrap();
        assert!(
            t.get(&r, &pid(1), now + KEEP_FOR + Duration::from_secs(1))
                .is_none()
        );
    }

    #[test]
    fn only_so_many_refusals_are_kept() {
        let now = Instant::now();
        let mut t = Refusals::new().unwrap();
        let first = t.keep(kept(pid(1), [0; 32], now), now).unwrap();
        for i in 1..=MAX_KEPT as u8 {
            t.keep(kept(pid(1), [i; 32], now), now).unwrap();
        }
        assert!(t.get(&first, &pid(1), now).is_none());
        assert_eq!(t.kept.len(), MAX_KEPT);
    }

    #[test]
    fn the_start_of_a_call_hides_the_finds() {
        let text = "curl -H 'X: abcdefghij' https://x\nsecond";
        let spans = vec![vahta_detect::SecretSpan {
            range: 12..22,
            kind: "k".to_string(),
            confidence: Confidence::Likely,
        }];
        assert_eq!(start_of(text, &spans), "curl -H 'X: ***' https://x");
    }

    #[test]
    fn a_window_shows_a_sure_key_by_its_ends_and_an_unsure_name_whole() {
        let key = ["ab", "cdefghijklmnopqrstuvw", "wxyz"].concat();
        let sure = Found {
            kind: "OpenAI-style key".to_string(),
            sure: true,
            value: Zeroizing::new(key),
        };
        assert_eq!(
            describe(&sure),
            "  - OpenAI-style key, 27 characters, abcd...wxyz"
        );
        let unsure = Found {
            kind: "PASSWORD assignment".to_string(),
            sure: false,
            value: Zeroizing::new("passwordField".to_string()),
        };
        assert_eq!(
            describe(&unsure),
            "  - PASSWORD assignment, 13 characters: passwordField"
        );
        // A sure assignment is masked like a key; a short value shows no ends.
        let short = Found {
            kind: "API_KEY assignment".to_string(),
            sure: true,
            value: Zeroizing::new("abcdefgh".to_string()),
        };
        assert_eq!(describe(&short), "  - API_KEY assignment, 8 characters");
    }
}
