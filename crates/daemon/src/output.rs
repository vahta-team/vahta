//! Secrets in a tool's output: what the hook asks the daemon after every tool
//! call, and what the person may let through.
//!
//! **Scan.** The hook sends the strings of a tool's output and what its
//! detector would cut. The daemon adds every place where a value it holds for
//! the caller's agent appears: the values of the sessions that cover the
//! caller, and the values injected into runs that the caller's anchor started
//! (kept for [`RUN_VALUES_FOR`] after the run, and only while the anchor
//! lives). It drops what the person has already let through for that anchor,
//! and if anything is left to cut, keeps the original in memory under a short
//! reference for [`HOLD_FOR`], so the agent can ask the person for it. The
//! reply says where to cut and names what; it never carries a value.
//!
//! **Release.** `vahta output allow <ref>` (see `output_allow` below) asks the
//! person in a window. "Show" sends the original back to that command, the one
//! deliberate case of a client receiving a value, and puts the hashes of the
//! cut values on the anchor's release list, so the hook lets them through from
//! then on: for the life of the anchor's session, or [`RELEASE_FOR`] without
//! one.
//!
//! The hashes are HMAC-SHA256 under a key this daemon draws at start and never
//! writes down, so the list says nothing about a value to anyone who reads the
//! daemon's memory without the key. The originals and the run values are
//! wiped when they go. None of it is ever on disk; the journal gets the
//! reference, the names and kinds, and never a value.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use vahta_os::ProcessId;
use zeroize::Zeroizing;

use vahta_vault::{Kind, Tier, Vault, valid_name};

use crate::anchor;
use crate::encoded::{EncodedSet, Form};
use crate::journal::Entry;
use crate::ops::{
    Ctx, Flow, cancelled, error, find_vault, from_surface, from_vault, refused, unlock,
};
use crate::protocol::{ClientReply, OutputSpan, Panel, RefusalKind};
use crate::scrub::Scrubber;
use crate::session_ops::nodes_of;
use crate::surface::sanitize_label;

/// How long an original is kept for the agent to ask about.
pub const HOLD_FOR: Duration = Duration::from_secs(10 * 60);
/// An output larger than this is cut but not kept: it gets no reference.
pub const MAX_HELD_BYTES: usize = 768 * 1024;
/// How many originals are kept at once; the oldest goes first.
const MAX_HELD: usize = 32;
/// How long a let-through value stays let through when the anchor has no
/// session.
pub const RELEASE_FOR: Duration = Duration::from_secs(30 * 60);
/// How long the values of a run are looked for in later output, after the
/// run: a command may have written one to a file the agent reads next.
pub const RUN_VALUES_FOR: Duration = Duration::from_secs(30 * 60);
/// The shortest value matched exactly. A shorter one would cut ordinary
/// words out of every output; it is the detector's own floor.
pub const MIN_EXACT: usize = 8;

/// One value cut out of a held output, before cuts that overlap are merged.
#[derive(Debug, Clone)]
pub(crate) struct HeldCut {
    pub text: usize,
    pub start: usize,
    pub end: usize,
    pub label: String,
    /// The daemon knew the value: `label` is a secret's name.
    pub exact: bool,
}

/// An original output, kept for the agent to ask about.
pub(crate) struct Held {
    pub texts: Zeroizing<Vec<String>>,
    pub cuts: Vec<HeldCut>,
    pub anchor: ProcessId,
    pub cwd: String,
    pub tool: String,
    pub expires: Instant,
}

/// Until when a let-through value stays let through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Until {
    Session(String),
    Time(Instant),
}

struct Release {
    hash: [u8; 32],
    until: Until,
}

struct RunValues {
    values: Vec<(String, Zeroizing<Vec<u8>>)>,
    /// The values in their encoded forms (see `encoded.rs`), rebuilt when a
    /// run adds some and dropped with them.
    forms: EncodedSet,
    expires: Instant,
}

pub(crate) struct Outputs {
    key: Zeroizing<[u8; 32]>,
    held: Vec<(String, Held)>,
    released: HashMap<ProcessId, Vec<Release>>,
    runs: HashMap<ProcessId, RunValues>,
}

impl Outputs {
    /// A new table with a fresh key; `None` when the system random generator
    /// fails.
    pub fn new() -> Option<Outputs> {
        Some(Outputs {
            key: Zeroizing::new(vahta_vault::crypto::random::<32>().ok()?),
            held: Vec::new(),
            released: HashMap::new(),
            runs: HashMap::new(),
        })
    }

    pub fn hash(&self, value: &[u8]) -> [u8; 32] {
        // HMAC takes a key of any length; `new_from_slice` cannot fail.
        let mut mac = match <Hmac<Sha256> as Mac>::new_from_slice(&self.key[..]) {
            Ok(m) => m,
            Err(_) => return [0; 32],
        };
        mac.update(value);
        mac.finalize().into_bytes().into()
    }

    pub fn is_released(&self, anchor: &ProcessId, hash: &[u8; 32]) -> bool {
        self.released
            .get(anchor)
            .is_some_and(|list| list.iter().any(|r| &r.hash == hash))
    }

    pub fn release(&mut self, anchor: ProcessId, hashes: Vec<[u8; 32]>, until: Until) {
        let list = self.released.entry(anchor).or_default();
        for hash in hashes {
            list.retain(|r| r.hash != hash);
            list.push(Release {
                hash,
                until: until.clone(),
            });
        }
    }

    /// Remember what a run started under `anchor` was given.
    pub fn note_run(&mut self, anchor: ProcessId, values: &[(String, Vec<u8>)], now: Instant) {
        let entry = self.runs.entry(anchor).or_insert_with(|| RunValues {
            values: Vec::new(),
            forms: EncodedSet::default(),
            expires: now,
        });
        for (name, value) in values {
            if value.len() < MIN_EXACT {
                continue;
            }
            entry.values.retain(|(n, _)| n != name);
            entry
                .values
                .push((name.clone(), Zeroizing::new(value.clone())));
        }
        entry.forms = EncodedSet::build(entry.values.iter().map(|(n, v)| (n.as_str(), &v[..])));
        // Build the search tables now, not in the middle of a tool call.
        let _ = entry.forms.find(b"");
        entry.expires = now + RUN_VALUES_FOR;
    }

    /// Every form of the values runs under `anchor` were given, to look for
    /// in later output.
    pub fn run_targets(&self, anchor: &ProcessId) -> Vec<(String, Vec<u8>)> {
        self.runs
            .get(anchor)
            .map(|r| r.forms.targets())
            .unwrap_or_default()
    }

    /// The first value (in any form) that a run under `anchor` was given and
    /// `text` carries: its name and form.
    pub fn run_find(&self, anchor: &ProcessId, text: &[u8]) -> Option<(String, Form)> {
        self.runs
            .get(anchor)?
            .forms
            .find(text)
            .map(|(n, f)| (n.to_string(), f))
    }

    #[cfg(test)]
    pub fn run_values(&self, anchor: &ProcessId) -> Vec<(String, Vec<u8>)> {
        self.runs
            .get(anchor)
            .map(|r| {
                r.values
                    .iter()
                    .map(|(n, v)| (n.clone(), v.to_vec()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Keep `held` under a new reference; `None` when no random reference
    /// could be drawn.
    pub fn hold(&mut self, held: Held) -> Option<String> {
        let reference = vahta_vault::hex_encode(&vahta_vault::crypto::random::<6>().ok()?);
        if self.held.len() >= MAX_HELD {
            self.held.remove(0);
        }
        self.held.push((reference.clone(), held));
        Some(reference)
    }

    pub fn get(&self, reference: &str) -> Option<&Held> {
        self.held
            .iter()
            .find(|(r, _)| r == reference)
            .map(|(_, h)| h)
    }

    /// Drop what has run out: originals past their time, let-through values
    /// whose session ended or whose time passed, run values past their time or
    /// whose anchor is gone.
    pub fn sweep(
        &mut self,
        now: Instant,
        alive: &dyn Fn(&ProcessId) -> bool,
        session_alive: &dyn Fn(&str) -> bool,
    ) {
        self.held.retain(|(_, h)| h.expires > now);
        for list in self.released.values_mut() {
            list.retain(|r| match &r.until {
                Until::Session(id) => session_alive(id),
                Until::Time(t) => *t > now,
            });
        }
        self.released
            .retain(|anchor, list| !list.is_empty() && alive(anchor));
        self.runs
            .retain(|anchor, r| r.expires > now && alive(anchor));
    }
}

/// The caller's anchor, chosen as `unlock` chooses it, and its name.
pub(crate) fn anchor_of(ctx: &Ctx<'_>) -> Option<(ProcessId, String)> {
    let nodes = nodes_of(ctx);
    let i = anchor::select(&nodes, vahta_os::MIN_PID).ok()?;
    Some((nodes[i].id, nodes[i].exe.clone()))
}

/// Widen `start..end` outward to character boundaries of `text`.
fn on_boundaries(text: &str, mut start: usize, mut end: usize) -> (usize, usize) {
    while start > 0 && !text.is_char_boundary(start) {
        start -= 1;
    }
    while end < text.len() && !text.is_char_boundary(end) {
        end += 1;
    }
    (start, end)
}

/// A label from the hook, made fit for a window and the journal.
fn clean_label(raw: &str) -> String {
    sanitize_label(raw)
        .map(|l| l.chars().take(64).collect())
        .unwrap_or_else(|| "secret".to_string())
}

/// The values the daemon holds for a caller with this chain and anchor, each
/// in every form it might be written in: the sessions that cover it, and its
/// anchor's recent runs. Read from the caches built when they were opened, so
/// a scan opens no vault.
fn values_for(
    ctx: &Ctx<'_>,
    chain: &[ProcessId],
    anchor: Option<&ProcessId>,
) -> Vec<(String, Vec<u8>)> {
    let mut values: Vec<(String, Vec<u8>)> = Vec::new();
    if let Ok(sessions) = ctx.shared.sessions.lock() {
        for s in sessions.covering(chain) {
            values.extend(s.forms.targets());
        }
    }
    if let (Some(anchor), Ok(outputs)) = (anchor, ctx.shared.outputs.lock()) {
        values.extend(outputs.run_targets(anchor));
    }
    values
}

/// The cuts the hook proposed, checked: in range, on boundaries, labelled.
fn checked_hook_cuts(texts: &[String], spans: Vec<OutputSpan>) -> Vec<HeldCut> {
    spans
        .into_iter()
        .filter_map(|s| {
            let text = texts.get(s.text)?;
            if s.start >= s.end || s.end > text.len() {
                return None;
            }
            let (start, end) = on_boundaries(text, s.start, s.end);
            Some(HeldCut {
                text: s.text,
                start,
                end,
                label: clean_label(&s.label),
                exact: false,
            })
        })
        .collect()
}

/// Cuts that overlap merged, per text, in order. A secret's name wins over a
/// detector's kind: the daemon's match is the proof.
pub(crate) fn merged(cuts: &[HeldCut]) -> Vec<HeldCut> {
    let mut sorted: Vec<HeldCut> = cuts.to_vec();
    sorted.sort_by_key(|c| (c.text, c.start, !c.exact));
    let mut out: Vec<HeldCut> = Vec::new();
    for c in sorted {
        match out.last_mut() {
            Some(last) if last.text == c.text && c.start < last.end => {
                last.end = last.end.max(c.end);
                if c.exact && !last.exact {
                    last.label = c.label;
                    last.exact = true;
                }
            }
            _ => out.push(c),
        }
    }
    out
}

pub(crate) fn scan(
    ctx: &Ctx<'_>,
    cwd: String,
    tool: String,
    texts: Vec<String>,
    spans: Vec<OutputSpan>,
    possible: Vec<String>,
) -> Flow<ClientReply> {
    let texts = Zeroizing::new(texts);
    let chain = vahta_os::ancestor_chain(ctx.pid, vahta_os::MAX_ANCESTORS);
    let anchor = anchor_of(ctx);
    let mut cuts = checked_hook_cuts(&texts, spans);

    // The values this daemon holds for the caller, wherever they appear.
    let values = values_for(ctx, &chain, anchor.as_ref().map(|(a, _)| a));
    if !values.is_empty() {
        let scrubber = Scrubber::new(values);
        for (i, text) in texts.iter().enumerate() {
            for (start, end, name) in scrubber.spans(text.as_bytes()) {
                let (start, end) = on_boundaries(text, start, end);
                cuts.push(HeldCut {
                    text: i,
                    start,
                    end,
                    label: name,
                    exact: true,
                });
            }
        }
    }

    // What the person has let through for this agent stays let through.
    if let (Some((anchor, _)), Ok(outputs)) = (&anchor, ctx.shared.outputs.lock()) {
        cuts.retain(|c| {
            let value = &texts[c.text].as_bytes()[c.start..c.end];
            !outputs.is_released(anchor, &outputs.hash(value))
        });
    }

    let finals = merged(&cuts);
    let tool_shown = clean_label(&tool);
    if finals.is_empty() {
        if !possible.is_empty() {
            let kinds: Vec<String> = possible.iter().map(|k| clean_label(k)).collect();
            ctx.journal(
                Entry::new("output_possible")
                    .names(&kinds)
                    .result("left", Some(&format!("tool {tool_shown}"))),
            );
        }
        return Ok(ClientReply::OutputSpans {
            spans: Vec::new(),
            reference: None,
        });
    }

    let total: usize = texts.iter().map(String::len).sum();
    let reference = match &anchor {
        Some((anchor, _)) if total <= MAX_HELD_BYTES => {
            let held = Held {
                texts,
                cuts: cuts.clone(),
                anchor: *anchor,
                cwd,
                tool: tool_shown.clone(),
                expires: Instant::now() + HOLD_FOR,
            };
            ctx.shared
                .outputs
                .lock()
                .ok()
                .and_then(|mut o| o.hold(held))
        }
        _ => None,
    };
    let mut labels: Vec<String> = Vec::new();
    for c in &finals {
        if !labels.contains(&c.label) {
            labels.push(c.label.clone());
        }
    }
    let anchor_text = match &anchor {
        Some((a, exe)) => format!("anchor {exe} pid {}", a.pid),
        None => "no anchor".to_string(),
    };
    ctx.journal(Entry::new("output_redacted").names(&labels).result(
        "redacted",
        Some(&format!(
            "tool {tool_shown}; {} cut; ref {}; {anchor_text}",
            finals.len(),
            reference.as_deref().unwrap_or("none"),
        )),
    ));
    Ok(ClientReply::OutputSpans {
        spans: finals
            .into_iter()
            .map(|c| OutputSpan {
                text: c.text,
                start: c.start,
                end: c.end,
                label: c.label,
            })
            .collect(),
        reference,
    })
}

/// The hook in observe mode saw secrets in a tool's output and changed
/// nothing: journal what, by kind and count.
pub(crate) fn observed(
    ctx: &Ctx<'_>,
    tool: &str,
    kinds: &[String],
    likely: usize,
    possible: usize,
) -> Flow<ClientReply> {
    let kinds: Vec<String> = kinds.iter().take(32).map(|k| clean_label(k)).collect();
    let anchor_text = match anchor_of(ctx) {
        Some((a, exe)) => format!("anchor {exe} pid {}", a.pid),
        None => "no anchor".to_string(),
    };
    ctx.journal(Entry::new("output_observed").names(&kinds).result(
        "observed",
        Some(&format!(
            "tool {}; {likely} likely, {possible} possible; {anchor_text}",
            clean_label(tool)
        )),
    ));
    Ok(ClientReply::Ok {})
}

// --- vahta output allow -------------------------------------------------------------

/// The longest line of context a window shows around a cut value.
const CONTEXT_CHARS: usize = 100;

/// The line of `text` around `which`, with every cut in `cuts` (all of this
/// text, in order) masked as `***`, made one plain line and cut short. A
/// window can be captured, so it shows where a value was, never the value.
fn context(text: &str, cuts: &[&HeldCut], which: &HeldCut) -> String {
    let line_start = text[..which.start].rfind('\n').map_or(0, |i| i + 1);
    let line_end = text[which.end..]
        .find('\n')
        .map_or(text.len(), |i| which.end + i);
    let mut out = String::new();
    let mut pos = line_start;
    for c in cuts {
        if c.end <= line_start || c.start >= line_end || c.end <= pos {
            continue;
        }
        out.push_str(&text[pos..c.start.max(pos)]);
        out.push_str("***");
        pos = c.end.min(line_end);
    }
    out.push_str(&text[pos..line_end]);
    let plain = sanitize_label(&out).unwrap_or_default();
    if plain.chars().count() > CONTEXT_CHARS {
        let cut: String = plain.chars().take(CONTEXT_CHARS).collect();
        format!("{cut}...")
    } else {
        plain
    }
}

/// One line per value cut: what it is, how long, and where, masked.
fn cut_lines(texts: &[String], finals: &[HeldCut]) -> Vec<String> {
    finals
        .iter()
        .map(|f| {
            let text = &texts[f.text];
            let same: Vec<&HeldCut> = finals.iter().filter(|c| c.text == f.text).collect();
            let what = if f.exact {
                format!("{} (a secret Vahta holds)", f.label)
            } else {
                format!("looks like: {}", f.label)
            };
            format!(
                "  - {what}, {} characters, in: {}",
                text[f.start..f.end].chars().count(),
                context(text, &same, f)
            )
        })
        .collect()
}

const SHOW: usize = 0;
const SAVE: usize = 2;

/// What `allow` needs of a held output, copied out from under the lock.
struct Asked {
    texts: Zeroizing<Vec<String>>,
    cuts: Vec<HeldCut>,
    cwd: String,
    tool: String,
}

pub(crate) fn allow(ctx: &Ctx<'_>, reference: &str, reason: Option<String>) -> Flow<ClientReply> {
    let not_here = || {
        refused(
            RefusalKind::UnknownOutput,
            "no output is kept under that reference for this agent (an output is kept for 10 \
             minutes, and only its own agent may ask for it); nothing was shown",
        )
    };
    // The agent that asks must be the one whose hook made the reference.
    let (anchor, anchor_exe) = anchor_of(ctx).ok_or_else(not_here)?;
    let asked = {
        let outputs = ctx
            .shared
            .outputs
            .lock()
            .map_err(|_| error("the output table is unusable"))?;
        let held = outputs
            .get(reference)
            .filter(|h| h.anchor == anchor)
            .ok_or_else(not_here)?;
        Asked {
            texts: held.texts.clone(),
            cuts: held.cuts.clone(),
            cwd: held.cwd.clone(),
            tool: held.tool.clone(),
        }
    };
    let chain = vahta_os::ancestor_chain(ctx.pid, vahta_os::MAX_ANCESTORS);
    // The covering session's id and its vault.
    let session: Option<(String, PathBuf)> = ctx.shared.sessions.lock().ok().and_then(|s| {
        s.covering(&chain)
            .first()
            .map(|s| (s.id.clone(), s.vault_path.clone()))
    });
    // The vault to save into, and without a session the one whose password
    // approves showing. The session's own comes first: Claude Code reports the
    // agent's working directory, not the one a command `cd`-ed into, so the
    // directory alone may have no vault, or another one.
    let vault: Option<PathBuf> = match (&session, find_vault(&asked.cwd)) {
        (Some((_, path)), _) => Some(path.clone()),
        (None, Ok((_, path))) => Some(path),
        (None, Err(_)) => {
            return Err(refused(
                RefusalKind::NoVault,
                format!(
                    "this agent has no session, and there is no Vahta vault in {} whose \
                     password could approve showing the output; nothing was shown",
                    asked.cwd
                ),
            ));
        }
    };

    let finals = merged(&asked.cuts);
    let mut labels: Vec<String> = Vec::new();
    for f in &finals {
        if !labels.contains(&f.label) {
            labels.push(f.label.clone());
        }
    }
    let record = |result: &str| {
        ctx.journal(Entry::new("output_allow").names(&labels).result(
            result,
            Some(&format!(
                "ref {reference}; anchor {anchor_exe} pid {}",
                anchor.pid
            )),
        ));
    };

    let title = "Show a tool's output to the agent";
    let mut lines = vec![
        format!("Tool: {}", asked.tool),
        format!("Directory: {}", asked.cwd),
        format!("Agent: {anchor_exe} (pid {})", anchor.pid),
        "Cut from the output before the agent saw it:".to_string(),
    ];
    lines.extend(cut_lines(&asked.texts, &finals));
    if let Some(path) = &vault {
        lines.push(format!("Vault: {}", path.display()));
    }
    lines.push(match &session {
        Some(_) => "This agent has a session open: no password is needed to show it.".to_string(),
        None => "This agent has no session: showing it needs the vault password.".to_string(),
    });
    let mut panel = ctx.panel(title, lines);
    panel.agent_note = reason.as_deref().and_then(sanitize_label);
    panel.warning = Some(
        "Shown values enter the agent's context and stay there. Only say yes if the agent \
         really needs them."
            .to_string(),
    );
    let mut options = vec!["Show to the agent".to_string(), "No".to_string()];
    if vault.is_some() {
        options.push("Save as a secret".to_string());
    }
    let mut window = ctx.window(title)?;
    let choice = window
        .choose(&panel, "What should Vahta do?", &options)
        .map_err(from_surface)?;
    match choice {
        Some(SHOW) => {
            if session.is_none()
                && let Some(vault_path) = &vault
            {
                // The password only approves; the vault is not changed.
                drop(unlock(ctx, window.as_mut(), vault_path, &panel)?);
            }
            let until = match &session {
                Some((id, _)) => Until::Session(id.clone()),
                None => Until::Time(Instant::now() + RELEASE_FOR),
            };
            if let Ok(mut outputs) = ctx.shared.outputs.lock() {
                let hashes: Vec<[u8; 32]> = asked
                    .cuts
                    .iter()
                    .map(|c| outputs.hash(&asked.texts[c.text].as_bytes()[c.start..c.end]))
                    .collect();
                outputs.release(anchor, hashes, until);
            }
            record("shown");
            window.close(Some("Shown to the agent."));
            // The strings the tool gave, one after another; an empty one
            // (a Bash command's empty stderr) adds nothing.
            let parts: Vec<&str> = asked
                .texts
                .iter()
                .map(String::as_str)
                .filter(|t| !t.is_empty())
                .collect();
            Ok(ClientReply::OutputReleased {
                text: parts.join("\n"),
            })
        }
        Some(SAVE) => {
            let Some(vault_path) = &vault else {
                return Err(error("there is no vault to save into"));
            };
            let saved = save(
                ctx,
                window.as_mut(),
                &mut panel,
                vault_path,
                &asked,
                &finals,
            )?;
            record("saved");
            window.close(Some(&format!("Saved {saved}.")));
            Ok(ClientReply::Done {
                message: format!(
                    "saved as {saved}; the output stays redacted. To use it, run the command \
                     that needs it with `vahta run --secret {saved} -- COMMAND`"
                ),
            })
        }
        _ => {
            record("declined");
            window.close(None);
            Err(ClientReply::Cancelled {
                message: "the person did not agree; the output stays redacted".to_string(),
            })
        }
    }
}

/// "Save as a secret": which value (if there are several), its name and tier,
/// then the vault password, which every write needs fresh. Returns the name.
fn save(
    ctx: &Ctx<'_>,
    window: &mut dyn crate::surface::Window,
    panel: &mut Panel,
    vault_path: &std::path::Path,
    asked: &Asked,
    finals: &[HeldCut],
) -> Flow<String> {
    let which = if finals.len() == 1 {
        0
    } else {
        let options: Vec<String> = cut_lines(&asked.texts, finals)
            .into_iter()
            .map(|l| l.trim_start_matches("  - ").to_string())
            .collect();
        window
            .choose(panel, "Which value should be saved?", &options)
            .map_err(from_surface)?
            .ok_or_else(cancelled)?
    };
    let chosen = &finals[which];
    let value = Zeroizing::new(asked.texts[chosen.text][chosen.start..chosen.end].to_string());
    let taken = |name: &str| {
        Vault::peek(vault_path)
            .map(|p| p.entries.iter().any(|e| e.name == name))
            .unwrap_or(false)
    };
    let mut name = None;
    for _ in 0..3 {
        let typed = window
            .ask_text(panel, "Name for the new secret")
            .map_err(from_surface)?
            .ok_or_else(cancelled)?;
        let typed = typed.trim().to_string();
        if !valid_name(&typed) {
            panel.warning = Some(
                "A name is letters, digits and underscores, not starting with a digit.".to_string(),
            );
        } else if taken(&typed) {
            panel.warning = Some(format!(
                "The vault already has {typed}; choose another name."
            ));
        } else {
            name = Some(typed);
            break;
        }
    }
    let name = name.ok_or_else(|| error("no usable name was given; nothing was saved"))?;
    panel.warning = None;
    panel.lines.push(format!("Save as: {name}"));
    let tiers = [
        "session: a session may use it".to_string(),
        "each-use: the password every time".to_string(),
    ];
    let tier = match window
        .choose(panel, "Which tier?", &tiers)
        .map_err(from_surface)?
        .ok_or_else(cancelled)?
    {
        0 => Tier::Session,
        _ => Tier::EachUse,
    };
    let mut vault = unlock(ctx, window, vault_path, panel)?;
    if vault.entries().iter().any(|e| e.name == name) {
        return Err(error(
            "the vault changed while the window was open; nothing was saved",
        ));
    }
    vault
        .set(&name, value.as_bytes(), Kind::Env, tier)
        .map_err(from_vault)?;
    vault.save(vault_path, ctx.store()).map_err(from_vault)?;
    ctx.journal(
        Entry::new("output_saved")
            .vault(&vault.vault_id())
            .names(std::slice::from_ref(&name))
            .result("ok", None),
    );
    Ok(name)
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

    fn held(anchor: ProcessId, expires: Instant) -> Held {
        Held {
            texts: Zeroizing::new(vec!["x".to_string()]),
            cuts: Vec::new(),
            anchor,
            cwd: "/p".to_string(),
            tool: "Bash".to_string(),
            expires,
        }
    }

    #[test]
    fn the_release_hash_is_keyed_and_per_anchor() {
        let mut a = Outputs::new().unwrap();
        let b = Outputs::new().unwrap();
        let h = a.hash(b"fake-value-123");
        assert_eq!(h, a.hash(b"fake-value-123"));
        assert_ne!(h, a.hash(b"fake-value-124"));
        // Another daemon's key gives another hash: the list means nothing
        // without the key.
        assert_ne!(h, b.hash(b"fake-value-123"));
        a.release(pid(10), vec![h], Until::Time(Instant::now() + RELEASE_FOR));
        assert!(a.is_released(&pid(10), &h));
        assert!(!a.is_released(&pid(11), &h));
    }

    #[test]
    fn releases_expire_with_their_time_their_session_or_their_anchor() {
        let now = Instant::now();
        let mut o = Outputs::new().unwrap();
        let (h1, h2, h3) = (
            o.hash(b"one-value"),
            o.hash(b"two-value"),
            o.hash(b"three-val"),
        );
        o.release(
            pid(10),
            vec![h1],
            Until::Time(now + Duration::from_secs(60)),
        );
        o.release(pid(10), vec![h2], Until::Session("s1".to_string()));
        o.release(
            pid(20),
            vec![h3],
            Until::Time(now + Duration::from_secs(600)),
        );
        let alive_all = |_: &ProcessId| true;
        o.sweep(now + Duration::from_secs(30), &alive_all, &|_| true);
        assert!(o.is_released(&pid(10), &h1) && o.is_released(&pid(10), &h2));
        // The time passes for the first; the session ends for the second.
        o.sweep(now + Duration::from_secs(61), &alive_all, &|id| id != "s1");
        assert!(!o.is_released(&pid(10), &h1));
        assert!(!o.is_released(&pid(10), &h2));
        assert!(o.is_released(&pid(20), &h3));
        // An anchor that is gone takes its list with it.
        o.sweep(now + Duration::from_secs(62), &|p| p.pid != 20, &|_| true);
        assert!(!o.is_released(&pid(20), &h3));
    }

    #[test]
    fn held_outputs_and_run_values_expire() {
        let now = Instant::now();
        let mut o = Outputs::new().unwrap();
        let r = o.hold(held(pid(10), now + HOLD_FOR)).unwrap();
        assert_eq!(r.len(), 12);
        assert!(o.get(&r).is_some());
        assert!(o.get("nope").is_none());
        o.note_run(
            pid(10),
            &[
                ("LONG".to_string(), b"fake-long-value".to_vec()),
                ("SHORT".to_string(), b"short".to_vec()),
            ],
            now,
        );
        // Too short to match exactly: not kept.
        let names: Vec<String> = o.run_values(&pid(10)).into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["LONG"]);
        let alive = |_: &ProcessId| true;
        o.sweep(now + HOLD_FOR + Duration::from_secs(1), &alive, &|_| true);
        assert!(o.get(&r).is_none());
        assert_eq!(o.run_values(&pid(10)).len(), 1);
        o.sweep(
            now + RUN_VALUES_FOR + Duration::from_secs(1),
            &alive,
            &|_| true,
        );
        assert!(o.run_values(&pid(10)).is_empty());
    }

    #[test]
    fn only_so_many_outputs_are_held() {
        let now = Instant::now();
        let mut o = Outputs::new().unwrap();
        let first = o.hold(held(pid(1), now + HOLD_FOR)).unwrap();
        for _ in 0..MAX_HELD {
            o.hold(held(pid(1), now + HOLD_FOR)).unwrap();
        }
        assert!(o.get(&first).is_none());
        assert_eq!(o.held.len(), MAX_HELD);
    }

    #[test]
    fn overlapping_cuts_merge_and_a_name_beats_a_kind() {
        let cut = |text, start, end, label: &str, exact| HeldCut {
            text,
            start,
            end,
            label: label.to_string(),
            exact,
        };
        let m = merged(&[
            cut(0, 5, 20, "OpenAI-style key", false),
            cut(0, 5, 20, "OPENAI", true),
            cut(0, 30, 40, "API_KEY assignment", false),
            cut(1, 0, 4, "B", true),
        ]);
        let shown: Vec<(usize, usize, usize, &str)> = m
            .iter()
            .map(|c| (c.text, c.start, c.end, c.label.as_str()))
            .collect();
        assert_eq!(
            shown,
            [
                (0, 5, 20, "OPENAI"),
                (0, 30, 40, "API_KEY assignment"),
                (1, 0, 4, "B")
            ]
        );
    }

    #[test]
    fn a_cut_from_the_hook_is_checked() {
        let texts = vec!["é abc".to_string()];
        let span = |text, start, end| OutputSpan {
            text,
            start,
            end,
            label: "\u{1b}[31mkind\nfake".to_string(),
        };
        let cuts = checked_hook_cuts(&texts, vec![span(0, 1, 4), span(0, 4, 99), span(3, 0, 1)]);
        assert_eq!(cuts.len(), 1);
        // Widened to the character it began inside, and the label made plain.
        assert_eq!((cuts[0].start, cuts[0].end), (0, 4));
        assert_eq!(cuts[0].label, "kind fake");
    }
}
