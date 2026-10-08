//! Secret-detection rules as data.
//!
//! The rules live in two TOML files, turned into Rust statics by the build
//! script (so the hook, which starts afresh for every tool call, parses
//! nothing at run time):
//!
//! * `rules/vahta.toml`: our own rules, the shared allow-list and the samples
//!   every rule is tested with. Edited by hand.
//! * `rules/imported.toml`: vendor token shapes imported from gitleaks (MIT)
//!   and, where gitleaks lacks them, from Betterleaks and Veles through
//!   Kingfisher (MIT, Apache-2.0). Written by `cargo run -p vahta-rules
//!   --example import`; never edited by hand. Each rule names its true origin
//!   in `source`. The licence texts are in `NOTICE`.
//!
//! # How a text is matched
//!
//! One Aho-Corasick automaton holds every rule's keywords (lowercase, ASCII
//! case-insensitive). A rule is considered only when one of its keywords occurs
//! in the text, so an ordinary command touches no regex at all. A considered
//! rule's regex is compiled the first time it is needed, in a per-rule
//! `OnceLock`, and then run; a match must pass the rule's entropy floor and
//! the allow-lists before it is a hit.
//!
//! # Limits
//!
//! Every limit is a constant here, so the cost of a call is bounded before the
//! text is read:
//!
//! * [`MAX_SCAN_BYTES`]: the size of one scan window. A longer text is read in
//!   windows overlapping by [`WINDOW_OVERLAP`], up to [`MAX_TOTAL_BYTES`]; past
//!   that the rest is not read ([`Truncated::Bytes`]) and the caller's built-in
//!   detector is all that covers it.
//! * [`MAX_RULES_PER_CALL`]: at most this many rules get their regex compiled
//!   and run for one text; the ones with the longest keyword match go first
//!   ([`Truncated::Rules`]).
//! * [`REGEX_SIZE_LIMIT`]: a rule whose regex compiles past this size is
//!   skipped (a test makes sure none is).
//! * [`MAX_MATCHES_PER_RULE`]: a rule's regex is run for at most this many
//!   matches per text.
//!
//! Never returns or logs secret *values*: a hit is a byte range.

use std::ops::Range;
use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind, MatchKind};
use regex::{Regex, RegexBuilder};

mod schema;

pub use schema::{Class, Mode, Target};

/// The size of one scan window, in bytes.
pub const MAX_SCAN_BYTES: usize = 1 << 20;
/// Windows of a longer text overlap by this much, so a credential on a seam is
/// whole in one of them.
pub const WINDOW_OVERLAP: usize = 4096;
/// The most of one text the rules read, in windows; the rest is not scanned.
pub const MAX_TOTAL_BYTES: usize = 8 << 20;
/// At most this many rules are compiled and run for one text.
pub const MAX_RULES_PER_CALL: usize = 32;
/// The compiled size past which a rule's regex is refused.
pub const REGEX_SIZE_LIMIT: usize = 1 << 20;
/// A rule's regex is run for at most this many matches per text.
pub const MAX_MATCHES_PER_RULE: usize = 16;

/// Values that are known not to be credentials, for one rule or for all.
#[derive(Debug)]
pub struct Allow {
    /// A value containing one of these (lowercase compare) is let through.
    pub stopwords: &'static [&'static str],
    /// A target matching one of these regexes is let through.
    pub regexes: &'static [&'static str],
    pub target: Target,
}

/// One sample for a rule's test: pieces joined at load, so the data file never
/// holds a credential-shaped string.
#[derive(Debug)]
pub struct Sample {
    /// True when the rule must hit it, false when it must not.
    pub hit: bool,
    pub parts: &'static [&'static str],
}

impl Sample {
    pub fn text(&self) -> String {
        self.parts.concat()
    }
}

/// A sample for a rule that lives in another file than the rule (the imported
/// rules are generated, so their samples are written by hand in `vahta.toml`).
#[derive(Debug)]
pub struct RuleSample {
    pub rule: &'static str,
    pub hit: bool,
    pub parts: &'static [&'static str],
}

impl RuleSample {
    pub fn text(&self) -> String {
        self.parts.concat()
    }
}

#[derive(Debug)]
pub struct Rule {
    /// `gitleaks.<id>`, `betterleaks.<id>`, `veles.<id>` or `vahta.<id>`.
    pub id: &'static str,
    /// Where the rule came from, with the pinned revision.
    pub source: &'static str,
    /// Shown to the person.
    pub description: &'static str,
    /// Shown to the agent, with its article: "an API token".
    pub category: &'static str,
    pub class: Class,
    /// Lowercase; a rule is considered only when one occurs in the text.
    pub keywords: &'static [&'static str],
    pub regex: &'static str,
    /// The capture group that holds the credential; 0 is the first group that
    /// matched anything, or the whole match when there is none.
    pub secret_group: usize,
    /// Minimum Shannon entropy (bits per byte) of the credential.
    pub entropy: Option<f64>,
    pub allow: &'static [Allow],
    pub mode: Mode,
    pub tests: &'static [Sample],
    compiled: OnceLock<Option<Regex>>,
    allow_compiled: OnceLock<Vec<(Regex, Target)>>,
}

include!(concat!(env!("OUT_DIR"), "/rules_data.rs"));

fn build(pattern: &str) -> Option<Regex> {
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .ok()
}

impl Rule {
    /// The rule's regex, compiled on first use; `None` when it does not
    /// compile within [`REGEX_SIZE_LIMIT`].
    pub fn regex(&self) -> Option<&Regex> {
        self.compiled.get_or_init(|| build(self.regex)).as_ref()
    }

    fn allow_regexes(&self) -> &[(Regex, Target)] {
        self.allow_compiled.get_or_init(|| {
            self.allow
                .iter()
                .flat_map(|a| a.regexes.iter().map(move |r| (r, a.target)))
                .filter_map(|(r, t)| build(r).map(|re| (re, t)))
                .collect()
        })
    }
}

/// The keyword automaton, built the first time a text is scanned.
pub struct Engine {
    keywords: Option<AhoCorasick>,
    /// For each automaton pattern, its rule's index and the keyword's length.
    owners: Vec<(usize, usize)>,
    common_regexes: OnceLock<Vec<Regex>>,
}

static ENGINE: OnceLock<Engine> = OnceLock::new();

pub fn engine() -> &'static Engine {
    ENGINE.get_or_init(Engine::new)
}

/// Every rule, in file order.
pub fn rules() -> &'static [Rule] {
    &RULES
}

/// The samples written apart from their rules.
pub fn samples() -> &'static [RuleSample] {
    &SAMPLES
}

impl Engine {
    fn new() -> Engine {
        let mut patterns: Vec<&str> = Vec::new();
        let mut owners = Vec::new();
        for (i, rule) in RULES.iter().enumerate() {
            for kw in rule.keywords {
                patterns.push(kw);
                owners.push((i, kw.len()));
            }
        }
        let keywords = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            // Measured: building the contiguous NFA takes under a millisecond
            // for these ~500 keywords, the DFA three, and a hook pays the
            // build on every call. Scanning a megabyte takes 3 ms either way.
            .kind(Some(AhoCorasickKind::ContiguousNFA))
            .build(&patterns)
            .ok();
        Engine {
            keywords,
            owners,
            common_regexes: OnceLock::new(),
        }
    }

    /// The rules to run for `text`: those with a keyword in it, the longest
    /// keyword match first, at most [`MAX_RULES_PER_CALL`].
    fn candidates(&self, text: &str) -> (Vec<usize>, bool) {
        let Some(ac) = &self.keywords else {
            return (Vec::new(), false);
        };
        let mut best: Vec<usize> = vec![0; RULES.len()];
        let mut found: Vec<usize> = Vec::new();
        for m in ac.find_overlapping_iter(text) {
            let (rule, len) = self.owners[m.pattern().as_usize()];
            if best[rule] == 0 {
                found.push(rule);
            }
            best[rule] = best[rule].max(len);
        }
        // Longest keyword first (a vendor prefix before a bare word), then
        // file order; stable, so the result does not depend on text order.
        found.sort_by(|a, b| best[*b].cmp(&best[*a]).then(a.cmp(b)));
        let over = found.len() > MAX_RULES_PER_CALL;
        found.truncate(MAX_RULES_PER_CALL);
        (found, over)
    }

    fn common_regexes(&self) -> &[Regex] {
        self.common_regexes
            .get_or_init(|| COMMON_REGEXES.iter().filter_map(|r| build(r)).collect())
    }

    /// Does the allow-list let this match through?
    fn allowed(&self, rule: &Rule, text: &str, whole: &Range<usize>, core: &Range<usize>) -> bool {
        let value = &text[core.clone()];
        let lower = value.to_ascii_lowercase();
        let stop = |words: &[&str]| words.iter().any(|w| lower.contains(w));
        if stop(COMMON_STOPWORDS) || rule.allow.iter().any(|a| stop(a.stopwords)) {
            return true;
        }
        if self.common_regexes().iter().any(|re| re.is_match(value)) {
            return true;
        }
        rule.allow_regexes().iter().any(|(re, target)| {
            let haystack = match target {
                Target::Value => value,
                Target::Matched => &text[whole.clone()],
                Target::Line => line_around(text, whole.start),
            };
            re.is_match(haystack)
        })
    }

    /// A text longer than [`MAX_SCAN_BYTES`] is read in windows of that size
    /// that overlap by [`WINDOW_OVERLAP`], so padding cannot push a credential
    /// out of reach; past [`MAX_TOTAL_BYTES`] the rest is not read.
    fn run(&self, text: &str, first_only: bool) -> Scan {
        if text.len() <= MAX_SCAN_BYTES {
            return self.run_window(text, first_only);
        }
        let end = floor_boundary(text, text.len().min(MAX_TOTAL_BYTES));
        let mut out = Scan {
            hits: Vec::new(),
            truncated: (text.len() > end).then_some(Truncated::Bytes),
        };
        let mut start = 0;
        while start < end {
            let stop = floor_boundary(text, (start + MAX_SCAN_BYTES).min(end));
            let part = self.run_window(&text[start..stop], first_only);
            for h in part.hits {
                let range = h.range.start + start..h.range.end + start;
                if !out
                    .hits
                    .iter()
                    .any(|o| o.rule == h.rule && o.range == range)
                {
                    out.hits.push(RuleHit {
                        range,
                        rule: h.rule,
                    });
                }
            }
            if part.truncated.is_some() {
                out.truncated = out.truncated.or(part.truncated);
            }
            if (first_only && !out.hits.is_empty()) || stop >= end {
                break;
            }
            start = ceil_boundary(text, stop - WINDOW_OVERLAP);
        }
        out
    }

    fn run_window(&self, text: &str, first_only: bool) -> Scan {
        let (candidates, over) = self.candidates(text);
        let mut hits = Vec::new();
        'rules: for index in candidates {
            let rule = &RULES[index];
            let Some(re) = rule.regex() else { continue };
            for caps in re.captures_iter(text).take(MAX_MATCHES_PER_RULE) {
                let Some(whole) = caps.get(0) else { continue };
                let core = if rule.secret_group == 0 {
                    // As gitleaks reads it: the first group that matched
                    // something, else the whole match.
                    (1..caps.len())
                        .filter_map(|i| caps.get(i))
                        .find(|m| !m.as_str().is_empty())
                        .unwrap_or(whole)
                } else {
                    caps.get(rule.secret_group).unwrap_or(whole)
                };
                if core.as_str().is_empty() {
                    continue;
                }
                if let Some(floor) = rule.entropy
                    && shannon(core.as_str()) < floor
                {
                    continue;
                }
                if self.allowed(rule, text, &whole.range(), &core.range()) {
                    continue;
                }
                hits.push(RuleHit {
                    range: core.range(),
                    rule: index,
                });
                if first_only {
                    break 'rules;
                }
                break;
            }
        }
        Scan {
            hits,
            truncated: over.then_some(Truncated::Rules),
        }
    }
}

fn floor_boundary(text: &str, mut at: usize) -> usize {
    while at > 0 && !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

fn ceil_boundary(text: &str, mut at: usize) -> usize {
    while at < text.len() && !text.is_char_boundary(at) {
        at += 1;
    }
    at
}

/// The line of `text` that holds byte `at`.
fn line_around(text: &str, at: usize) -> &str {
    let start = text[..at].rfind('\n').map_or(0, |i| i + 1);
    let end = text[at..].find('\n').map_or(text.len(), |i| at + i);
    &text[start..end]
}

/// Shannon entropy in bits per byte.
pub fn shannon(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = f64::from(*c) / n;
            -p * p.log2()
        })
        .sum()
}

/// Why a scan did not cover everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Truncated {
    /// The text is longer than [`MAX_TOTAL_BYTES`]: its tail was not scanned.
    Bytes,
    /// More than [`MAX_RULES_PER_CALL`] rules had a keyword in the text.
    Rules,
}

/// One rule's find: where the credential is and which rule found it.
#[derive(Debug, Clone)]
pub struct RuleHit {
    /// The credential's byte range in the scanned text.
    pub range: Range<usize>,
    rule: usize,
}

impl RuleHit {
    pub fn rule(&self) -> &'static Rule {
        &RULES[self.rule]
    }
}

/// What a scan found, and whether it was cut short.
#[derive(Debug)]
pub struct Scan {
    pub hits: Vec<RuleHit>,
    pub truncated: Option<Truncated>,
}

/// Run the rules over `text`: at most one hit per rule.
pub fn scan(text: &str) -> Scan {
    engine().run(text, false)
}

/// The first hit only: what a hook needs, and cheaper.
pub fn first_hit(text: &str) -> Scan {
    engine().run(text, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_a_single_symbol_is_zero() {
        assert_eq!(shannon("aaaa"), 0.0);
        assert!((shannon("abcd") - 2.0).abs() < 1e-9);
    }

    #[test]
    fn the_line_around_a_byte() {
        let t = "one\ntwo three\nfour";
        assert_eq!(line_around(t, 6), "two three");
        assert_eq!(line_around(t, 0), "one");
        assert_eq!(line_around(t, 15), "four");
    }
}
