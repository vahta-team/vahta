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
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use vahta_os::ProcessId;
use zeroize::Zeroizing;

use crate::anchor;
use crate::journal::Entry;
use crate::ops::{Ctx, Flow};
use crate::protocol::{ClientReply, OutputSpan};
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
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "read by `vahta output allow`, which comes next")
)]
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
#[expect(dead_code, reason = "read by `vahta output allow`, which comes next")]
pub(crate) struct Held {
    pub texts: Zeroizing<Vec<String>>,
    pub cuts: Vec<HeldCut>,
    pub anchor: ProcessId,
    pub anchor_exe: String,
    pub cwd: String,
    pub tool: String,
    pub expires: Instant,
}

/// Until when a let-through value stays let through.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "read by `vahta output allow`, which comes next")
)]
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

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read by `vahta output allow`, which comes next")
    )]
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
        entry.expires = now + RUN_VALUES_FOR;
    }

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

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read by `vahta output allow`, which comes next")
    )]
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

/// The values the daemon holds for a caller with this chain and anchor: the
/// sessions that cover it, and its anchor's recent runs.
fn values_for(
    ctx: &Ctx<'_>,
    chain: &[ProcessId],
    anchor: Option<&ProcessId>,
) -> Vec<(String, Vec<u8>)> {
    let mut values: Vec<(String, Vec<u8>)> = Vec::new();
    if let Ok(sessions) = ctx.shared.sessions.lock() {
        for s in sessions.covering(chain) {
            // A file that cannot be read, or a session gone stale, only means
            // fewer exact matches; the detector still runs.
            let Ok(bytes) = vahta_vault::read_file(&s.vault_path) else {
                continue;
            };
            for name in &s.scope {
                if let Ok(v) = s.keys.open(&bytes, name, ctx.store()) {
                    values.push((name.clone(), v.expose().to_vec()));
                }
            }
        }
    }
    if let (Some(anchor), Ok(outputs)) = (anchor, ctx.shared.outputs.lock()) {
        values.extend(outputs.run_values(anchor));
    }
    values.retain(|(_, v)| v.len() >= MIN_EXACT);
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
        Some((anchor, exe)) if total <= MAX_HELD_BYTES => {
            let held = Held {
                texts,
                cuts: cuts.clone(),
                anchor: *anchor,
                anchor_exe: exe.clone(),
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
            anchor_exe: "agent".to_string(),
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
