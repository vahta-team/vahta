//! Secrets in what the person types: the hook's two questions about a prompt
//! ([`ClientRequest::CheckInput`] and [`ClientRequest::PromptAsk`]).
//!
//! **Check.** Which values the daemon holds for the caller's agent does the
//! text carry, in any form? The matcher is the scrubber's, over the same
//! values a tool's output is scrubbed of (`output::known_values`). The reply is
//! names only.
//!
//! **Ask.** The hook found a secret in a prompt (its detector, a held value,
//! or both) and waits. If every value in it is one the person already called a
//! false alarm, it goes on at once. Otherwise a window says what was found
//! (a kind, a length, the first and last characters of a long value, never the
//! value) and offers three ways out: send it, save it in the project's vault
//! and hold the message, or hold the message. No answer in [`ASK_WAIT`] holds
//! it. Holding is always safe; sending is only ever the person's word.
//!
//! "Send it" is remembered until the daemon exits as HMAC-SHA256 hashes of
//! the values under a key drawn at start (as `output.rs` keeps what it let
//! through), so the same paste does not ask twice. Nothing of it is on disk.
//!
//! [`ClientRequest::CheckInput`]: crate::protocol::ClientRequest::CheckInput
//! [`ClientRequest::PromptAsk`]: crate::protocol::ClientRequest::PromptAsk

use std::collections::{HashMap, VecDeque};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use vahta_detect::Confidence;
use vahta_vault::{Vault, valid_name};

use crate::journal::Entry;
use crate::ops::{Ctx, Flow, find_vault, from_surface};
use crate::output::{Asked, HeldCut, anchor_of, known_values, save};
use crate::protocol::{ClientReply, PromptDecision};
use crate::scrub::Scrubber;
use crate::surface::sanitize_label;

/// How long the window waits for the person. The hook gives up later (it is
/// told 120 s by its harness), so the daemon's "held" arrives first.
pub const ASK_WAIT: Duration = Duration::from_secs(100);
/// At most this many false alarms are remembered; the oldest goes first.
const MAX_REMEMBERED: usize = 4096;
/// At most this many values are listed in the window.
const MAX_LISTED: usize = 6;
/// A value shorter than this shows nothing of itself, not even its ends.
const SHOW_ENDS_FROM: usize = 16;

/// How long a second `PromptAsk` waits for the open window to close.
const WAIT_FOR_OPEN: Duration = Duration::from_secs(3);
/// Windows one requesting process tree may open in [`PER`].
const MAX_WINDOWS: usize = 4;
const PER: Duration = Duration::from_secs(60);
/// How much a refused request weighs for the injection alarm, of its threshold:
/// two in a minute raise it. A person pasting secrets does not do that.
const ALARM_SHARE: f64 = 0.5;

/// One prompt window at a time, and a few per minute per requester. A request
/// can come from any local process, so a flood must not bury the person in
/// windows.
#[derive(Default)]
pub(crate) struct Gate {
    state: Mutex<GateState>,
    freed: Condvar,
}

#[derive(Default)]
struct GateState {
    open: bool,
    recent: HashMap<String, VecDeque<Instant>>,
}

/// Held while a window is open; dropping it lets the next request in.
pub(crate) struct Permit<'a>(&'a Gate);

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if let Ok(mut s) = self.0.state.lock() {
            s.open = false;
        }
        self.0.freed.notify_one();
    }
}

enum Admit<'a> {
    Go(Permit<'a>),
    /// Another window stayed open.
    Busy,
    /// `key` opened too many windows lately.
    TooMany,
}

impl Gate {
    fn admit(&self, key: &str) -> Admit<'_> {
        let Ok(mut s) = self.state.lock() else {
            return Admit::Busy;
        };
        let now = Instant::now();
        s.recent.retain(|_, q| {
            q.retain(|t| now.saturating_duration_since(*t) < PER);
            !q.is_empty()
        });
        if s.recent.get(key).is_some_and(|q| q.len() >= MAX_WINDOWS) {
            return Admit::TooMany;
        }
        let deadline = now + WAIT_FOR_OPEN;
        while s.open {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Admit::Busy;
            }
            s = match self.freed.wait_timeout(s, left) {
                Ok((g, _)) => g,
                Err(_) => return Admit::Busy,
            };
        }
        s.open = true;
        s.recent
            .entry(key.to_string())
            .or_default()
            .push_back(Instant::now());
        Admit::Go(Permit(self))
    }
}

/// The values the person said were no secret, as keyed hashes.
pub(crate) struct Remembered {
    key: Zeroizing<[u8; 32]>,
    seen: Vec<[u8; 32]>,
}

impl Remembered {
    /// A fresh table with a new key; `None` when the system random generator
    /// fails.
    pub fn new() -> Option<Remembered> {
        Some(Remembered {
            key: Zeroizing::new(vahta_vault::crypto::random::<32>().ok()?),
            seen: Vec::new(),
        })
    }

    /// `domain` keeps a held value, a detector's find and a whole message from
    /// ever hashing alike.
    fn hash(&self, domain: u8, value: &[u8]) -> [u8; 32] {
        // HMAC takes a key of any length; `new_from_slice` cannot fail.
        let mut mac = match <Hmac<Sha256> as Mac>::new_from_slice(&self.key[..]) {
            Ok(m) => m,
            Err(_) => return [0; 32],
        };
        mac.update(&[domain]);
        mac.update(value);
        mac.finalize().into_bytes().into()
    }

    fn contains(&self, hash: &[u8; 32]) -> bool {
        self.seen.contains(hash)
    }

    fn add(&mut self, hash: [u8; 32]) {
        if self.seen.contains(&hash) {
            return;
        }
        if self.seen.len() >= MAX_REMEMBERED {
            self.seen.remove(0);
        }
        self.seen.push(hash);
    }
}

/// Where the held values are in `text`, with the name of each: the scrubber's
/// matcher over every value held for the caller, in every form.
fn known_in(ctx: &Ctx<'_>, text: &str) -> Vec<(usize, usize, String)> {
    let chain = vahta_os::ancestor_chain(ctx.pid, vahta_os::MAX_ANCESTORS);
    let anchor = anchor_of(ctx);
    let values = known_values(ctx, &chain, anchor.as_ref().map(|(a, _)| a));
    if values.is_empty() {
        return Vec::new();
    }
    Scrubber::new(values).spans(text.as_bytes())
}

/// `CheckInput`: the names of the held values `text` carries.
pub(crate) fn check_input(ctx: &Ctx<'_>, text: &str) -> ClientReply {
    let mut names: Vec<String> = Vec::new();
    for (_, _, name) in known_in(ctx, text) {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    ClientReply::InputNames { names }
}

/// One thing found in a prompt.
struct Found {
    /// What the window calls it: a detector's kind, or a held value's name.
    label: String,
    /// A held value: `label` is a secret's name.
    known: bool,
    range: Range<usize>,
    hash: [u8; 32],
}

/// What a window shows of a value: its ends, when it is long enough that its
/// ends tell little.
fn ends_of(value: &str) -> Option<String> {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < SHOW_ENDS_FROM {
        return None;
    }
    let head: String = chars[..2].iter().collect();
    let tail: String = chars[chars.len() - 2..].iter().collect();
    sanitize_label(&format!("{head}...{tail}"))
}

/// A name for the vault that the kind of secret suggests: `OpenAI-style key`
/// is `OPENAI_KEY`, `an Anthropic-style API key` is `ANTHROPIC_API_KEY`.
fn suggested_name(kind: &str, taken: &dyn Fn(&str) -> bool) -> String {
    const NOISE: [&str; 7] = ["a", "an", "style", "assignment", "flag", "value", "the"];
    let words: Vec<String> = kind
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|w| !w.is_empty() && !NOISE.contains(&w.to_ascii_lowercase().as_str()))
        .map(|w| w.to_ascii_uppercase())
        .collect();
    let mut base = words.join("_");
    if base.is_empty() {
        base = "PASTED_SECRET".to_string();
    }
    if base.starts_with(|c: char| c.is_ascii_digit()) {
        base.insert_str(0, "SECRET_");
    }
    let mut name = base.clone();
    let mut n = 2;
    while !valid_name(&name) || taken(&name) {
        if n > 99 {
            return "PASTED_SECRET".to_string();
        }
        name = format!("{base}_{n}");
        n += 1;
    }
    name
}

/// What the person chose, by position in the window.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Way {
    Send,
    Save,
    Nothing,
}

fn held(no_answer: bool) -> ClientReply {
    ClientReply::PromptAnswer {
        answer: PromptDecision::Held { no_answer },
    }
}

/// `PromptAsk`: decide what happens to a prompt that carries a secret.
pub(crate) fn prompt_ask(
    ctx: &Ctx<'_>,
    harness: &str,
    cwd: &str,
    text: String,
    detected: Option<String>,
) -> Flow<ClientReply> {
    let text = Zeroizing::new(text);
    let remembered = |ctx: &Ctx<'_>, domain: u8, value: &[u8]| -> [u8; 32] {
        ctx.shared
            .remembered
            .lock()
            .map(|r| r.hash(domain, value))
            .unwrap_or([0; 32])
    };

    // What was found: held values first, then what the detector's rules see
    // outside them. The hook's own verdict gates the detector: a rule in
    // observe mode asks nothing here either.
    let mut found: Vec<Found> = Vec::new();
    for (start, end, name) in known_in(ctx, &text) {
        let hash = remembered(ctx, b'k', &text.as_bytes()[start..end]);
        found.push(Found {
            label: name,
            known: true,
            range: start..end,
            hash,
        });
    }
    if let Some(category) = &detected {
        for span in vahta_detect::find_secret_spans(&text) {
            if span.confidence != Confidence::Likely
                || found.iter().any(|f| {
                    f.known && f.range.start < span.range.end && span.range.start < f.range.end
                })
            {
                continue;
            }
            let hash = remembered(ctx, b'd', &text.as_bytes()[span.range.clone()]);
            found.push(Found {
                label: span.kind,
                known: false,
                range: span.range,
                hash,
            });
        }
        // A find with no place in the text (a rule that is not a span): the
        // whole message stands for it, and cannot be saved.
        if !found.iter().any(|f| !f.known) {
            let hash = remembered(ctx, b'w', text.as_bytes());
            found.push(Found {
                label: sanitize_label(category).unwrap_or_else(|| "a secret".to_string()),
                known: false,
                range: 0..0,
                hash,
            });
        }
    }
    if found.is_empty() {
        return Ok(ClientReply::PromptAnswer {
            answer: PromptDecision::Send {},
        });
    }
    let names: Vec<String> = found
        .iter()
        .filter(|f| f.known)
        .map(|f| f.label.clone())
        .collect();
    let record = |result: &str, found: &[Found]| {
        ctx.journal(Entry::new("prompt_secret").names(&names).result(
            result,
            Some(&format!(
                "{harness}; {} held, {} detected",
                found.iter().filter(|f| f.known).count(),
                found.iter().filter(|f| !f.known).count()
            )),
        ));
    };
    let is_remembered = |f: &Found| {
        ctx.shared
            .remembered
            .lock()
            .is_ok_and(|r| r.contains(&f.hash))
    };
    if found.iter().all(is_remembered) {
        record("send_remembered", &found);
        return Ok(ClientReply::PromptAnswer {
            answer: PromptDecision::Send {},
        });
    }

    // One window at a time, a few a minute per requester.
    let subject = crate::report::subject_of(ctx, harness, None);
    let _permit = match ctx.shared.prompt_gate.admit(&subject.key) {
        Admit::Go(p) => p,
        Admit::Busy => {
            record("busy", &found);
            return Ok(ClientReply::PromptAnswer {
                answer: PromptDecision::Busy { limited: false },
            });
        }
        Admit::TooMany => {
            ctx.journal(Entry::new("prompt_secret").result(
                "rate_limited",
                Some(&format!(
                    "suspicious: {} asked for more than {MAX_WINDOWS} prompt windows in a minute",
                    subject.shown
                )),
            ));
            if !crate::testing::refusal_alarm_muted()
                && let Some(verdict) = ctx.shared.alarm.record_scored(
                    &subject,
                    crate::alarm::THRESHOLD * ALARM_SHARE,
                    "too many prompt windows".to_string(),
                    Instant::now(),
                )
            {
                crate::alarm::raise(ctx.shared, subject, verdict);
            }
            return Ok(ClientReply::PromptAnswer {
                answer: PromptDecision::Busy { limited: true },
            });
        }
    };

    // The window.
    let title = "A secret in your message";
    let shown_cwd = sanitize_label(cwd).unwrap_or_default();
    let mut lines = vec![format!(
        "Your message to {} has not been sent. It seems to contain:",
        sanitize_label(harness).unwrap_or_else(|| "the agent".to_string())
    )];
    for f in found.iter().take(MAX_LISTED) {
        let value = &text[f.range.clone()];
        let len = if f.range.is_empty() {
            text.chars().count()
        } else {
            value.chars().count()
        };
        let line = if f.known {
            format!(
                "  - the value of {}, a secret Vahta holds, {len} characters",
                f.label
            )
        } else if f.range.is_empty() {
            format!(
                "  - {} somewhere in the message ({len} characters in all)",
                f.label
            )
        } else {
            match ends_of(value) {
                Some(ends) => format!("  - {}, {len} characters, {ends}", f.label),
                None => format!("  - {}, {len} characters", f.label),
            }
        };
        lines.push(line);
    }
    if found.len() > MAX_LISTED {
        lines.push(format!("  - and {} more", found.len() - MAX_LISTED));
    }
    if !shown_cwd.is_empty() {
        lines.push(format!("Directory: {shown_cwd}"));
    }

    // Saving needs a vault in the message's project, and a value to save.
    let vault: Option<PathBuf> = find_vault(cwd).ok().map(|(_, path)| path);
    let saveable: Vec<&Found> = found
        .iter()
        .filter(|f| !f.known && !f.range.is_empty())
        .collect();
    let taken = |name: &str| match &vault {
        Some(path) => Vault::peek(path)
            .map(|p| p.entries.iter().any(|e| e.name == name))
            .unwrap_or(true),
        None => false,
    };
    let suggestion = saveable
        .first()
        .map(|f| suggested_name(&f.label, &taken))
        .unwrap_or_default();
    if let Some(path) = &vault
        && !saveable.is_empty()
    {
        lines.push(format!("Vault: {}", path.display()));
    }
    lines.push(format!(
        "With no answer in {} seconds the message is not sent.",
        ASK_WAIT.as_secs()
    ));
    let panel = ctx.panel(title, lines);

    let mut ways = vec![Way::Send];
    let mut options = vec![if saveable.is_empty() {
        "Send it anyway".to_string()
    } else {
        "False alarm \u{2014} send it".to_string()
    }];
    if vault.is_some() && !saveable.is_empty() {
        ways.push(Way::Save);
        options.push(format!("Save to the project vault as {suggestion}"));
    }
    ways.push(Way::Nothing);
    options.push("Do nothing".to_string());

    let mut window = ctx.window(title)?;
    let way = window
        .choose_within(&panel, "What should Vahta do?", &options, ASK_WAIT)
        .map_err(from_surface)?
        .and_then(|i| ways.get(i).copied());
    match way {
        Some(Way::Send) => {
            if let Ok(mut r) = ctx.shared.remembered.lock() {
                for f in &found {
                    r.add(f.hash);
                }
            }
            record("send", &found);
            window.close(Some("Your message goes on."));
            Ok(ClientReply::PromptAnswer {
                answer: PromptDecision::Send {},
            })
        }
        Some(Way::Save) => {
            let Some(vault_path) = &vault else {
                return Err(crate::ops::error("there is no vault to save into"));
            };
            let asked = Asked {
                texts: Zeroizing::new(vec![text.to_string()]),
                cuts: Vec::new(),
                cwd: cwd.to_string(),
                tool: "prompt".to_string(),
            };
            let cuts: Vec<HeldCut> = saveable
                .iter()
                .map(|f| HeldCut {
                    text: 0,
                    start: f.range.start,
                    end: f.range.end,
                    label: f.label.clone(),
                    exact: false,
                })
                .collect();
            let mut panel = panel;
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
                    record("saved", &found);
                    window.close(Some(&format!("Saved {name}. Your message was not sent.")));
                    Ok(ClientReply::PromptAnswer {
                        answer: PromptDecision::Saved { name },
                    })
                }
                Err(_) => {
                    // Cancelled, a wrong password, a taken name: nothing was
                    // stored, and the message does not go.
                    record("save_failed", &found);
                    window.close(Some("Nothing was saved. Your message was not sent."));
                    Ok(held(false))
                }
            }
        }
        Some(Way::Nothing) => {
            record("held", &found);
            window.close(Some("Your message was not sent."));
            Ok(held(false))
        }
        None => {
            record("no_answer", &found);
            window.close(Some("No answer. Your message was not sent."));
            Ok(held(true))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_comes_from_the_kind() {
        let free = |_: &str| false;
        assert_eq!(suggested_name("OpenAI-style key", &free), "OPENAI_KEY");
        assert_eq!(
            suggested_name("an Anthropic-style API key", &free),
            "ANTHROPIC_API_KEY"
        );
        assert_eq!(suggested_name("API_KEY assignment", &free), "API_KEY");
        assert_eq!(suggested_name("--password flag value", &free), "PASSWORD");
        assert_eq!(suggested_name("???", &free), "PASTED_SECRET");
        assert_eq!(
            suggested_name("1password token", &free),
            "SECRET_1PASSWORD_TOKEN"
        );
    }

    #[test]
    fn a_taken_name_gets_a_number() {
        let taken = |n: &str| n == "GITHUB_TOKEN" || n == "GITHUB_TOKEN_2";
        assert_eq!(suggested_name("GitHub token", &taken), "GITHUB_TOKEN_3");
    }

    #[test]
    fn a_window_shows_the_ends_of_a_long_value_only() {
        assert_eq!(ends_of("short-value"), None);
        let long = ["ab", "cdefghijklmnopq", "yz"].concat();
        assert_eq!(ends_of(&long).as_deref(), Some("ab...yz"));
    }

    #[test]
    fn false_alarms_are_remembered_by_keyed_hash() {
        let Some(mut r) = Remembered::new() else {
            return;
        };
        let h = r.hash(b'd', b"value-one");
        assert!(!r.contains(&h));
        r.add(h);
        assert!(r.contains(&r.hash(b'd', b"value-one")));
        assert!(!r.contains(&r.hash(b'k', b"value-one")));
        assert!(!r.contains(&r.hash(b'd', b"value-two")));
        assert_ne!(
            Remembered::new().map(|o| o.hash(b'd', b"value-one")),
            Some(h)
        );
    }
}
