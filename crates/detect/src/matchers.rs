//! The four match shapes: vendor prefix, Bearer, assignment, flag form.
//!
//! Ported from `key_amnesia.detect_py`. Every pattern here is hand-rolled
//! rather than handed to a regex engine, for two reasons that happen to point
//! the same way.
//!
//! The first is that they *cannot* be handed to one. `_FLAG_FORM` carries a
//! negative lookbehind `(?<![\w./=-])` **and** a backreference `(?P=q)`, and
//! Rust's `regex` crate supports neither; the legacy `ASSIGN` pattern is
//! backreferenced too, though it is off the hot path by design and is not
//! ported.
//!
//! The second is cold start. This code runs in a fresh process on every tool
//! call the agent makes, and a regex engine would compile its patterns on each
//! one. Matching directly keeps the crate dependency-free and the startup cost
//! at zero.
//!
//! What is *not* hand-waved: Python's `\b`, `\w` and `\s` are Unicode-aware,
//! and the classes below reproduce that rather than assuming ASCII input.

use crate::classify::{Confidence, classify_value};

/// Python's `\w`: alphanumeric or underscore, Unicode-aware.
#[inline]
fn is_word(c: char) -> bool {
    crate::primitives::is_word_python(c)
}

/// Python's `\s` on `str`. See `primitives::is_python_space` for why this
/// is not `char::is_whitespace`.
#[inline]
fn is_space(c: char) -> bool {
    crate::primitives::is_python_space(c)
}

/// One position of the text being matched.
///
/// The matchers below run over a slice of these. For text that is entirely
/// ASCII the slice is the text's own bytes (`u8`): no 4x-wide `Vec<char>` is
/// built and every comparison is a byte comparison. Any other text is decoded
/// to `Vec<char>` and takes the exact Unicode path. Both instantiate the same
/// source, so the ASCII fast path is the general algorithm, not a second copy
/// of it, and `ch()` is the identity on the characters ASCII text can hold.
trait Unit: Copy {
    fn ch(self) -> char;
}

impl Unit for char {
    #[inline(always)]
    fn ch(self) -> char {
        self
    }
}

impl Unit for u8 {
    /// Only ever instantiated over bytes of an all-ASCII `str`.
    #[inline(always)]
    fn ch(self) -> char {
        self as char
    }
}

fn collect_string<U: Unit>(units: &[U]) -> String {
    units.iter().map(|u| u.ch()).collect()
}

/// `\b` at index `at`: exactly one side is a word character.
fn at_word_boundary<U: Unit>(chars: &[U], at: usize) -> bool {
    let before = if at == 0 {
        false
    } else {
        is_word(chars[at - 1].ch())
    };
    let after = if at >= chars.len() {
        false
    } else {
        is_word(chars[at].ch())
    };
    before != after
}

// --- vendor prefixes -------------------------------------------------------

/// Character classes used by the vendor patterns, kept alongside the literal
/// so one table describes each rule completely.
#[derive(Clone, Copy)]
enum TailClass {
    /// `[A-Za-z0-9_-]`
    WordDash,
    /// `[A-Za-z0-9_]`
    Word,
    /// `[0-9A-Z]`
    UpperDigit,
    /// `[A-Za-z0-9]`
    Alnum,
    /// `[A-Za-z0-9-]`
    AlnumDash,
    /// `[0-9A-Za-z_-]`
    GoogleTail,
}

impl TailClass {
    /// Membership of one byte. Every class is ASCII-only, so a non-ASCII
    /// byte (part of a multi-byte character) is never a member.
    #[inline]
    fn contains_byte(self, c: u8) -> bool {
        match self {
            TailClass::WordDash | TailClass::GoogleTail => {
                c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
            }
            TailClass::Word => c.is_ascii_alphanumeric() || c == b'_',
            TailClass::UpperDigit => c.is_ascii_uppercase() || c.is_ascii_digit(),
            TailClass::Alnum => c.is_ascii_alphanumeric(),
            TailClass::AlnumDash => c.is_ascii_alphanumeric() || c == b'-',
        }
    }
}

/// One vendor rule: a literal opener, then a run of `tail` of at least
/// `min_tail` characters, with `\b` on both ends.
struct PrefixRule {
    kind: &'static str,
    /// Literal openers. `gh[pousr]_` and `xox[baprs]-` expand to several.
    literals: &'static [&'static str],
    tail: TailClass,
    min_tail: usize,
    /// True when the source pattern is `{n}` rather than `{n,}`. Only AWS is
    /// written that way, and the difference is visible: `AKIA` followed by 24
    /// uppercase characters does **not** match, because a fixed count cannot
    /// backtrack to satisfy the trailing `\b`.
    exact: bool,
}

/// Order matters and is not leftmost-match: Anthropic is checked before the
/// more general OpenAI pattern so the reported kind is the specific one.
const PREFIX_RULES: &[PrefixRule] = &[
    PrefixRule {
        kind: "Anthropic-style key",
        literals: &["sk-ant-"],
        tail: TailClass::WordDash,
        min_tail: 20,
        exact: false,
    },
    PrefixRule {
        kind: "OpenAI-style key",
        literals: &["sk-"],
        tail: TailClass::WordDash,
        min_tail: 20,
        exact: false,
    },
    PrefixRule {
        kind: "AWS access key id",
        literals: &["AKIA"],
        tail: TailClass::UpperDigit,
        min_tail: 16,
        exact: true,
    },
    PrefixRule {
        kind: "GitHub fine-grained PAT",
        literals: &["github_pat_"],
        tail: TailClass::Word,
        min_tail: 20,
        exact: false,
    },
    PrefixRule {
        kind: "GitHub PAT",
        literals: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        tail: TailClass::Word,
        min_tail: 20,
        exact: false,
    },
    PrefixRule {
        kind: "GitLab PAT",
        literals: &["glpat-"],
        tail: TailClass::WordDash,
        min_tail: 20,
        exact: false,
    },
    PrefixRule {
        kind: "Slack token",
        literals: &["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"],
        tail: TailClass::AlnumDash,
        min_tail: 20,
        exact: false,
    },
    PrefixRule {
        kind: "Google API key",
        literals: &["AIza"],
        tail: TailClass::GoogleTail,
        min_tail: 20,
        exact: false,
    },
    PrefixRule {
        kind: "Stripe secret key",
        literals: &["sk_live_"],
        tail: TailClass::Alnum,
        min_tail: 20,
        exact: false,
    },
    PrefixRule {
        kind: "Stripe restricted key",
        literals: &["rk_live_"],
        tail: TailClass::Alnum,
        min_tail: 20,
        exact: false,
    },
    PrefixRule {
        kind: "npm token",
        literals: &["npm_"],
        tail: TailClass::Alnum,
        min_tail: 20,
        exact: false,
    },
];

/// `\b` at byte offset `at` of `text` (a char boundary). Same predicate as
/// [`at_word_boundary`], read straight off the UTF-8 instead of a `Vec<char>`.
#[inline]
fn word_boundary_at(text: &str, at: usize) -> bool {
    let before = text[..at].chars().next_back().is_some_and(is_word);
    let after = text[at..].chars().next().is_some_and(is_word);
    before != after
}

/// Does `rule` match anywhere in `text`?
///
/// The trailing `\b` is why this is not a simple run-length check. The tail
/// class contains `-`, which is *not* a word character, so after consuming the
/// maximal run the boundary may fail — and Python's engine then backtracks,
/// shortening the run until the boundary holds or the minimum is breached.
/// That backtracking is reproduced here rather than approximated.
///
/// Works on bytes rather than a `Vec<char>`: every literal and every tail
/// class is ASCII, so an occurrence of a literal is an occurrence in the
/// character sequence too (UTF-8 is self-synchronising: an ASCII byte is never
/// part of a multi-byte sequence), and the run it opens consists of ASCII
/// bytes, one per character, so byte arithmetic equals character arithmetic.
/// Only the two characters *around* the run can be non-ASCII, and those are
/// decoded in place for `\b`.
fn rule_matches(rule: &PrefixRule, text: &str) -> bool {
    let bytes = text.as_bytes();
    for literal in rule.literals {
        let mut from = 0usize;
        while let Some(rel) = text[from..].find(literal) {
            let start = from + rel;
            // Resume one character on, as the scan-by-position original does.
            from = start + 1;
            if !word_boundary_at(text, start) {
                continue;
            }
            let run_start = start + literal.len();
            let mut end = run_start;
            while end < bytes.len() && rule.tail.contains_byte(bytes[end]) {
                end += 1;
            }
            if rule.exact {
                // `{n}` consumes exactly n and cannot give any back, so the
                // trailing boundary either holds at n or the rule fails here.
                let want = run_start + rule.min_tail;
                if end >= want && word_boundary_at(text, want) {
                    return true;
                }
            } else {
                while end >= run_start + rule.min_tail {
                    if word_boundary_at(text, end) {
                        return true;
                    }
                    end -= 1;
                }
            }
        }
    }
    false
}

/// Rules (as a bitmask over [`PREFIX_RULES`] indices) whose literals can open
/// with this byte pair; 0 for any pair that opens none. One lookup per byte
/// pair finds the (rare) places where a literal could start, so the common
/// case — source text with no vendor prefix — never reaches the per-rule
/// matching at all. Kept in step with the table by a unit test below.
#[inline]
fn rules_opened_by(b0: u8, b1: u8) -> u32 {
    match (b0, b1) {
        (b's', b'k') => 1 << 0 | 1 << 1 | 1 << 8, // sk-ant-, sk-, sk_live_
        (b'A', b'K') => 1 << 2,                   // AKIA
        (b'g', b'i') => 1 << 3,                   // github_pat_
        (b'g', b'h') => 1 << 4,                   // ghp_ gho_ ghu_ ghs_ ghr_
        (b'g', b'l') => 1 << 5,                   // glpat-
        (b'x', b'o') => 1 << 6,                   // xoxb- xoxa- ...
        (b'A', b'I') => 1 << 7,                   // AIza
        (b'r', b'k') => 1 << 9,                   // rk_live_
        (b'n', b'p') => 1 << 10,                  // npm_
        _ => 0,
    }
}

/// The screen in front of [`rules_opened_by`]: a byte can open a literal if
/// its `OPENER_FIRST` bits and the next byte's `OPENER_SECOND` bits overlap.
/// Bit 0 = `s`/`r` then `k`; bit 1 = `A` then `K`/`I`; bit 2 = `g` then
/// `i`/`h`/`l`; bit 3 = `x` then `o`; bit 4 = `n` then `p`. It may pass pairs
/// that open nothing (it is only a screen); it must pass every pair
/// `rules_opened_by` accepts, which a unit test checks over all 65536 pairs.
const OPENER_FIRST: [u8; 256] = {
    let mut t = [0u8; 256];
    t[b's' as usize] = 1;
    t[b'r' as usize] = 1;
    t[b'A' as usize] = 2;
    t[b'g' as usize] = 4;
    t[b'x' as usize] = 8;
    t[b'n' as usize] = 16;
    t
};
const OPENER_SECOND: [u8; 256] = {
    let mut t = [0u8; 256];
    t[b'k' as usize] = 1;
    t[b'K' as usize] = 2;
    t[b'I' as usize] = 2;
    t[b'i' as usize] = 4;
    t[b'h' as usize] = 4;
    t[b'l' as usize] = 4;
    t[b'o' as usize] = 8;
    t[b'p' as usize] = 16;
    t
};

/// Name the vendor whose prefix appears in `text`, if any.
pub fn find_prefix_kind(text: &str) -> Option<&'static str> {
    // One pass finds which rules have any literal in the text at all. Most
    // text has none, and text that mentions a literal (this very file) usually
    // has one or two, so the per-rule matching below runs for a handful of
    // rules instead of all eleven. Rule order is untouched: the first present
    // rule that actually matches wins, as before.
    let bytes = text.as_bytes();
    let mut present = 0u32;
    for i in 0..bytes.len().saturating_sub(1) {
        // Branch-free screen: two table lookups and an AND, taken only at the
        // rare positions where a literal's first two bytes both line up. A
        // plain `match` on the pair here mispredicts on ordinary text, since
        // `s`, `g`, `n`, `r` and `k` are common letters.
        if OPENER_FIRST[bytes[i] as usize] & OPENER_SECOND[bytes[i + 1] as usize] == 0 {
            continue;
        }
        let (b0, b1) = (bytes[i], bytes[i + 1]);
        let mut open = rules_opened_by(b0, b1) & !present;
        while open != 0 {
            let ri = open.trailing_zeros() as usize;
            open &= open - 1;
            let rest = &bytes[i..];
            if PREFIX_RULES[ri]
                .literals
                .iter()
                .any(|l| rest.starts_with(l.as_bytes()))
            {
                present |= 1 << ri;
            }
        }
    }
    if present == 0 {
        return None;
    }
    PREFIX_RULES
        .iter()
        .enumerate()
        .find(|(ri, rule)| present & (1 << ri) != 0 && rule_matches(rule, text))
        .map(|(_, rule)| rule.kind)
}

// --- Bearer ----------------------------------------------------------------

#[inline]
fn is_bearer_value_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '=' | '/')
}

/// `(?i)\bBearer\s+([A-Za-z0-9._\-+=/]{16,})` — the captured value.
fn find_bearer_value<U: Unit>(chars: &[U]) -> Option<String> {
    const WORD: [char; 6] = ['b', 'e', 'a', 'r', 'e', 'r'];
    let mut start = 0usize;
    while start + WORD.len() <= chars.len() {
        let matched = chars[start..start + WORD.len()]
            .iter()
            .zip(WORD)
            .all(|(c, w)| crate::primitives::fold_ci(c.ch()) == w);
        if !matched || !at_word_boundary(chars, start) {
            start += 1;
            continue;
        }
        let mut i = start + WORD.len();
        let space_start = i;
        while i < chars.len() && is_space(chars[i].ch()) {
            i += 1;
        }
        if i == space_start {
            start += 1;
            continue;
        }
        let value_start = i;
        while i < chars.len() && is_bearer_value_char(chars[i].ch()) {
            i += 1;
        }
        if i - value_start >= 16 {
            return Some(collect_string(&chars[value_start..i]));
        }
        start += 1;
    }
    None
}

/// Tier of the Bearer value, or `None` if there is no Bearer capture.
pub fn classify_bearer_capture(text: &str) -> Confidence {
    // Prefilter: no ASCII-case-insensitive "bearer" in the bytes means no
    // match. Sound for non-ASCII text too: `fold_ci` maps only U+0130, U+0131,
    // U+017F and U+212A to ASCII (`i`, `i`, `s`, `k`), none of which is a
    // letter of "bearer", so a non-ASCII character can never stand in for one.
    let bytes = text.as_bytes();
    if !bytes
        .windows(6)
        .any(|w| w[0] | 0x20 == b'b' && w.eq_ignore_ascii_case(b"bearer"))
    {
        return Confidence::None;
    }
    let found = if text.is_ascii() {
        find_bearer_value(bytes)
    } else {
        find_bearer_value(&text.chars().collect::<Vec<char>>())
    };
    match found {
        Some(value) => classify_value(&value).0,
        None => Confidence::None,
    }
}

// --- the secret-name vocabulary --------------------------------------------

/// `(?i)^(?:[a-z0-9]+[_-])*(?:api[_-]?key|token|secret|password|passwd|private[_-]?key)$`
pub fn is_secret_name(name: &str) -> bool {
    // `name.strip().strip("'\"")`, with Python's whitespace; then `(?i)`
    // folding, which is one character to one character, so positions hold.
    let trimmed = name
        .trim_matches(crate::primitives::is_python_space)
        .trim_matches(|c| c == '\'' || c == '"');
    let chars: Vec<char> = trimmed.chars().map(crate::primitives::fold_ci).collect();

    // Try every suffix that a `(?:[a-z0-9]+[_-])*` prefix could leave behind.
    let mut starts = vec![0usize];
    let mut i = 0usize;
    while i < chars.len() {
        let seg_start = i;
        while i < chars.len() && (chars[i].is_ascii_lowercase() || chars[i].is_ascii_digit()) {
            i += 1;
        }
        if i == seg_start || i >= chars.len() || (chars[i] != '_' && chars[i] != '-') {
            break;
        }
        i += 1;
        starts.push(i);
    }

    starts.iter().any(|&s| keyword_matches_exactly(&chars[s..]))
}

/// The keyword alternation, anchored to the end of `rest`.
fn keyword_matches_exactly(rest: &[char]) -> bool {
    let s: String = rest.iter().collect();
    if matches!(s.as_str(), "token" | "secret" | "password" | "passwd") {
        return true;
    }
    for (head, tail) in [("api", "key"), ("private", "key")] {
        if let Some(after) = s.strip_prefix(head) {
            let after = match after.strip_prefix(['_', '-']) {
                Some(rest) => rest,
                None => after,
            };
            if after == tail {
                return true;
            }
        }
    }
    false
}

// --- assignment form -------------------------------------------------------

/// Bound on the leftward walk. Without it a long alphanumeric run before each
/// keyword reintroduces the quadratic behaviour the rewrite removed.
const MAX_NAME_PREFIX: usize = 256;

/// ASCII only, deliberately: `char::is_alphanumeric` is Unicode-aware and
/// would capture names the original `[a-z0-9]` class never did. The Python
/// side carries the same warning.
#[inline]
fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

/// `fold_ci(c)` as an index byte: the folded ASCII letter, or 0 for anything
/// that does not fold to ASCII (which no keyword letter can be).
#[inline(always)]
fn fold_byte(c: char) -> u8 {
    let f = crate::primitives::fold_ci(c);
    if f.is_ascii() { f as u8 } else { 0 }
}

/// Screen tables for [`find_assign_keywords`]: bit 0 = `a` then `p` (api),
/// bit 1 = `p` then `r` (private), bit 2 = `p` then `a` (passw...), bit 3 =
/// `t` then `o` (token), bit 4 = `s` then `e` (secret). A pair passes when the
/// first letter's bits and the second letter's bits overlap.
const KW_FIRST: [u8; 256] = {
    let mut t = [0u8; 256];
    t[b'a' as usize] = 1;
    t[b'p' as usize] = 2 | 4;
    t[b't' as usize] = 8;
    t[b's' as usize] = 16;
    t
};
const KW_SECOND: [u8; 256] = {
    let mut t = [0u8; 256];
    t[b'p' as usize] = 1;
    t[b'r' as usize] = 2;
    t[b'a' as usize] = 4;
    t[b'o' as usize] = 8;
    t[b'e' as usize] = 16;
    t
};

/// Keyword occurrences of `_ASSIGN_KEYWORD`, as (start, end) in characters.
fn find_assign_keywords<U: Unit>(chars: &[U]) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    let mut i = 0usize;

    while i < chars.len() {
        // Every keyword begins with one of these, so one comparison skips the
        // overwhelming majority of positions. Python gets the same effect for
        // free from a compiled alternation, which is a DFA; without this the
        // port tries six literals at every character and loses its advantage
        // on keyword-dense text such as source files.
        //
        // The first letter also says which keyword can possibly match here
        // (`a`: api_key; `p`: private_key, password, passwd; `t`: token; `s`:
        // secret), so only those are tried. The original order is kept; the
        // candidates it skips are the ones that already fail on this letter.
        //
        // Before that, a two-letter screen: every keyword opens `ap`, `pr`,
        // `pa`, `to` or `se` (case-folded), which is rare even though the first
        // letters are among the commonest in English and in identifiers.
        // Two table lookups and an AND keep the hot loop free of the branch
        // mispredictions a per-letter `match` costs.
        if i + 1 >= chars.len()
            || KW_FIRST[fold_byte(chars[i].ch()) as usize]
                & KW_SECOND[fold_byte(chars[i + 1].ch()) as usize]
                == 0
        {
            i += 1;
            continue;
        }
        let found = match crate::primitives::fold_ci(chars[i].ch()) {
            'a' => match_optional_sep_pair(chars, i, "api", "key"),
            't' => match_literal_ci(chars, i, "token"),
            's' => match_literal_ci(chars, i, "secret"),
            'p' => match_optional_sep_pair(chars, i, "private", "key")
                .or_else(|| match_literal_ci(chars, i, "password"))
                .or_else(|| match_literal_ci(chars, i, "passwd")),
            _ => None,
        };
        match found {
            Some(end) => {
                out.push((i, end));
                i = end;
            }
            None => i += 1,
        }
    }
    out
}

/// Case-insensitive literal match at `at`, allocation-free.
///
/// Every keyword here is ASCII, so the literal is compared byte by byte
/// against lowercased characters. Collecting the literal into a `Vec<char>`
/// per call instead — which the first version of this did — costs one
/// allocation per input position per keyword, and the repository's own
/// quadratic-blowup guards caught it: 256 KiB of adversarial input took over
/// a second where Python took a fraction of one.
fn match_literal_ci<U: Unit>(chars: &[U], at: usize, literal: &str) -> Option<usize> {
    let lit = literal.as_bytes();
    if at + lit.len() > chars.len() {
        return None;
    }
    for (offset, &want) in lit.iter().enumerate() {
        let c = crate::primitives::fold_ci(chars[at + offset].ch());
        if !c.is_ascii() || c as u8 != want {
            return None;
        }
    }
    Some(at + lit.len())
}

fn match_optional_sep_pair<U: Unit>(
    chars: &[U],
    at: usize,
    head: &str,
    tail: &str,
) -> Option<usize> {
    let after_head = match_literal_ci(chars, at, head)?;
    let after_sep = if after_head < chars.len()
        && (chars[after_head].ch() == '_' || chars[after_head].ch() == '-')
    {
        after_head + 1
    } else {
        after_head
    };
    match_literal_ci(chars, after_sep, tail)
}

/// The parsed tail of an assignment: `nq2`, `q`, `value`, `q2`.
struct AssignTail {
    nq2: Option<char>,
    q: Option<char>,
    value: String,
    q2: Option<char>,
    #[allow(dead_code)]
    end: usize,
}

/// `(?P<nq2>['"]?)\s*[:=]\s*(?P<q>['"]?)(?P<value>[^\s'"]{8,})(?P<q2>['"]?)`,
/// anchored at `at`.
fn match_assign_tail<U: Unit>(chars: &[U], at: usize) -> Option<AssignTail> {
    let mut i = at;

    let nq2 = if i < chars.len() && (chars[i].ch() == '\'' || chars[i].ch() == '"') {
        let c = chars[i].ch();
        i += 1;
        Some(c)
    } else {
        None
    };

    while i < chars.len() && is_space(chars[i].ch()) {
        i += 1;
    }
    if i >= chars.len() || (chars[i].ch() != ':' && chars[i].ch() != '=') {
        return None;
    }
    i += 1;
    while i < chars.len() && is_space(chars[i].ch()) {
        i += 1;
    }

    let q = if i < chars.len() && (chars[i].ch() == '\'' || chars[i].ch() == '"') {
        let c = chars[i].ch();
        i += 1;
        Some(c)
    } else {
        None
    };

    let value_start = i;
    while i < chars.len()
        && !is_space(chars[i].ch())
        && chars[i].ch() != '\''
        && chars[i].ch() != '"'
    {
        i += 1;
    }
    if i - value_start < 8 {
        return None;
    }
    let value = collect_string(&chars[value_start..i]);

    let q2 = if i < chars.len() && (chars[i].ch() == '\'' || chars[i].ch() == '"') {
        let c = chars[i].ch();
        i += 1;
        Some(c)
    } else {
        None
    };

    Some(AssignTail {
        nq2,
        q,
        value,
        q2,
        end: i,
    })
}

/// Yield `(name, value)` pairs equivalent to the legacy `ASSIGN`, linearly.
///
/// Never returns values to callers outside `scan_text_hits`.
pub fn iter_assignments(text: &str) -> Vec<(String, String)> {
    if text.is_empty() {
        return Vec::new();
    }
    if text.is_ascii() {
        assignments_in(text.as_bytes())
    } else {
        assignments_in(&text.chars().collect::<Vec<char>>())
    }
}

fn assignments_in<U: Unit>(chars: &[U]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (kw_start, kw_end) in find_assign_keywords(chars) {
        // Walk left across `[a-z0-9]+[_-]` groups, bounded.
        let mut i = kw_start;
        let floor = kw_start.saturating_sub(MAX_NAME_PREFIX);
        while i > floor && (chars[i - 1].ch() == '_' || chars[i - 1].ch() == '-') {
            let mut j = i - 1;
            while j > floor && is_name_char(chars[j - 1].ch()) {
                j -= 1;
            }
            if j == i - 1 {
                break;
            }
            i = j;
        }

        let Some(tail) = match_assign_tail(chars, kw_end) else {
            continue;
        };

        // The legacy `(?P=nq)` only pairs quotes inside the match: a quote
        // immediately before the name is usually JSON wrapping, not a quoted
        // key, so an opener is required only when the tail captured a closer.
        if let Some(nq2) = tail.nq2 {
            if i == 0 || chars[i - 1].ch() != nq2 {
                continue;
            }
        }
        // Value quotes: a closer is required only when an opener was captured.
        if let Some(q) = tail.q {
            if tail.q2 != Some(q) {
                continue;
            }
        }

        let name = collect_string(&chars[i..kw_end]);
        out.push((name, tail.value));
    }
    out
}

// --- flag form -------------------------------------------------------------

pub const REASON_FLAG_FORM: &str = "flag-form";

/// THE ONE LINE TO FLIP. `[Likely]` fires only on strong value signals;
/// `[Likely, Possible]` additionally fires on word-shaped and low-transition
/// values, which is where most real `--password <value>` leaks land.
pub const FLAG_FORM_FIRE_TIERS: [Confidence; 2] = [Confidence::Likely, Confidence::Possible];

/// The value class is what keeps the recommended usage quiet. It excludes
/// `$` `` ` `` `(` `)` so `--token "$GITHUB_TOKEN"` stays silent, `<` `>` `|`
/// `&` `;` so redirection does, and `=` and quotes because those are the
/// assignment form's job.
#[inline]
fn is_flag_value_char(c: char) -> bool {
    !(is_space(c)
        || matches!(
            c,
            '\'' | '"' | '`' | ';' | '|' | '&' | '<' | '>' | '(' | ')' | '$' | '=' | '\\'
        ))
}

/// `^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$` — naming an environment variable is
/// indirection, not a value, and is the whole point of the product.
fn is_env_name_value(value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    if chars.is_empty() || !chars[0].is_ascii_uppercase() {
        return false;
    }
    let mut i = 1usize;
    while i < chars.len() && (chars[i].is_ascii_uppercase() || chars[i].is_ascii_digit()) {
        i += 1;
    }
    let mut groups = 0usize;
    while i < chars.len() && chars[i] == '_' {
        i += 1;
        let start = i;
        while i < chars.len() && (chars[i].is_ascii_uppercase() || chars[i].is_ascii_digit()) {
            i += 1;
        }
        if i == start {
            return false;
        }
        groups += 1;
    }
    groups >= 1 && i == chars.len()
}

/// `^(?:\.{1,2}/|/|~/|[A-Za-z]:[\\/])` — pointing at a file, not holding one.
fn is_path_value(value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    if chars.is_empty() {
        return false;
    }
    if chars[0] == '/' {
        return true;
    }
    if chars[0] == '~' && chars.get(1) == Some(&'/') {
        return true;
    }
    if chars[0] == '.' {
        if chars.get(1) == Some(&'/') {
            return true;
        }
        if chars.get(1) == Some(&'.') && chars.get(2) == Some(&'/') {
            return true;
        }
    }
    if chars[0].is_ascii_alphabetic()
        && chars.get(1) == Some(&':')
        && matches!(chars.get(2), Some('\\') | Some('/'))
    {
        return true;
    }
    false
}

/// Yield `(flag_name, value)` for space-separated `--api-key <value>` forms.
///
/// Kept separate from [`iter_assignments`] by design, and merged only at
/// [`crate::hits::scan_text_hits`], so the legacy `ASSIGN` differential on the
/// Python side stays intact.
pub fn iter_flag_values(text: &str) -> Vec<(String, String)> {
    if text.is_empty() || !text.contains('-') {
        return Vec::new();
    }
    if text.is_ascii() {
        flag_values_in(text.as_bytes())
    } else {
        flag_values_in(&text.chars().collect::<Vec<char>>())
    }
}

fn flag_values_in<U: Unit>(chars: &[U]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < chars.len() {
        // Only a `-` can open a match, so test that first: the lookbehind below
        // costs a Unicode class lookup on the previous character, and nearly
        // every position fails this cheaper test. Both conditions must hold,
        // so the order does not change the result.
        if chars[i].ch() != '-' {
            i += 1;
            continue;
        }
        // `(?<![\w./=-])` — the lookbehind, which no Rust regex can express.
        let preceded_ok = i == 0
            || !(is_word(chars[i - 1].ch()) || matches!(chars[i - 1].ch(), '.' | '/' | '=' | '-'));
        if !preceded_ok {
            i += 1;
            continue;
        }

        let mut j = i + 1;
        if j < chars.len() && chars[j].ch() == '-' {
            j += 1;
        }
        if j >= chars.len() || !chars[j].ch().is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        let name_start = j;
        j += 1;
        while j < chars.len()
            && (chars[j].ch().is_ascii_alphanumeric()
                || chars[j].ch() == '_'
                || chars[j].ch() == '-')
        {
            j += 1;
        }
        let name = collect_string(&chars[name_start..j]);

        let sep_start = j;
        while j < chars.len() && (chars[j].ch() == ' ' || chars[j].ch() == '\t') {
            j += 1;
        }
        if j == sep_start {
            i += 1;
            continue;
        }

        let q = if j < chars.len() && (chars[j].ch() == '\'' || chars[j].ch() == '"') {
            let c = chars[j].ch();
            j += 1;
            Some(c)
        } else {
            None
        };

        // First value character additionally excludes a leading `-`, so
        // `mysql --password --host=db` reads the next flag as a flag.
        if j >= chars.len() || !is_flag_value_char(chars[j].ch()) || chars[j].ch() == '-' {
            i += 1;
            continue;
        }
        let value_start = j;
        j += 1;
        while j < chars.len() && is_flag_value_char(chars[j].ch()) {
            j += 1;
        }
        if j - value_start < 8 {
            i += 1;
            continue;
        }
        let value = collect_string(&chars[value_start..j]);

        // `(?P=q)`: a closer is required only when an opener was captured.
        if let Some(q) = q {
            if chars.get(j).map(|u| u.ch()) != Some(q) {
                i += 1;
                continue;
            }
            j += 1;
        }

        if is_secret_name(&name) && !is_env_name_value(&value) && !is_path_value(&value) {
            out.push((name, value));
        }
        // `finditer` does not overlap: resume after the whole match.
        i = j;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- fast paths against their reference implementations ----------------

    /// The pre-optimisation prefix matcher, over `Vec<char>`, kept as the
    /// oracle for the byte-level one.
    fn reference_rule_matches(rule: &PrefixRule, chars: &[char]) -> bool {
        for literal in rule.literals {
            let lit: Vec<char> = literal.chars().collect();
            let mut start = 0usize;
            while start + lit.len() <= chars.len() {
                if chars[start..start + lit.len()] != lit[..] || !at_word_boundary(chars, start) {
                    start += 1;
                    continue;
                }
                let run_start = start + lit.len();
                let mut end = run_start;
                while end < chars.len() && rule.tail.contains_byte_char(chars[end]) {
                    end += 1;
                }
                if rule.exact {
                    let want = run_start + rule.min_tail;
                    if end >= want && at_word_boundary(chars, want) {
                        return true;
                    }
                } else {
                    while end >= run_start + rule.min_tail {
                        if at_word_boundary(chars, end) {
                            return true;
                        }
                        end -= 1;
                    }
                }
                start += 1;
            }
        }
        false
    }

    impl TailClass {
        fn contains_byte_char(self, c: char) -> bool {
            c.is_ascii() && self.contains_byte(c as u8)
        }
    }

    /// Strings stitched from fragments that sit on every edge the fast paths
    /// care about: literal openers and near-misses, run lengths around the
    /// minimum, boundary characters (word, non-word, non-ASCII), the four
    /// non-ASCII characters that case-fold to ASCII, quotes, separators.
    fn fragment_strings(count: usize) -> Vec<String> {
        const FRAGS: &[&str] = &[
            "sk-",
            "sk-ant-",
            "sk_live_",
            "rk_live_",
            "AKIA",
            "AIza",
            "github_pat_",
            "ghp_",
            "gho_",
            "glpat-",
            "xoxb-",
            "xox",
            "npm_",
            "sk",
            "gh",
            "AK",
            "AI",
            "Bearer ",
            "bearer\t",
            "BEARER  ",
            "token",
            "TOKEN",
            "api_key",
            "api-key",
            "apikey",
            "private-key",
            "secret",
            "password",
            "passwd",
            "passw",
            "\u{17f}ecret",
            "\u{212a}ey",
            "\u{130}",
            "\u{131}",
            "é",
            "Я",
            "٣",
            "\u{2028}",
            "\u{1c}",
            " ",
            "\t",
            "\n",
            "=",
            ":",
            "'",
            "\"",
            "-",
            "--",
            "_",
            ".",
            "/",
            "abcdefgh",
            "ABCDEFGHIJKLMNOPQRST",
            "0123456789012345",
            "Zx9Qw3Er7Ty1Ui5Op2As",
            "a",
            "Q",
            "7",
            "(",
            ")",
            "[",
            "]",
            "$",
            "`",
            "x",
            "0",
            "1",
        ];
        let mut x = 0x9E3779B97F4A7C15u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        (0..count)
            .map(|_| {
                let n = 1 + next() % 14;
                (0..n)
                    .map(|_| FRAGS[(next() % FRAGS.len() as u64) as usize])
                    .collect::<String>()
            })
            .collect()
    }

    #[test]
    fn byte_level_prefix_matcher_agrees_with_the_char_level_one() {
        for text in fragment_strings(200_000) {
            let chars: Vec<char> = text.chars().collect();
            let want = PREFIX_RULES
                .iter()
                .find(|r| reference_rule_matches(r, &chars))
                .map(|r| r.kind);
            assert_eq!(find_prefix_kind(&text), want, "{text:?}");
        }
    }

    #[test]
    fn ascii_byte_path_agrees_with_the_char_path() {
        for text in fragment_strings(200_000) {
            if !text.is_ascii() {
                continue;
            }
            let chars: Vec<char> = text.chars().collect();
            assert_eq!(
                assignments_in(text.as_bytes()),
                assignments_in(&chars),
                "{text:?}"
            );
            assert_eq!(
                flag_values_in(text.as_bytes()),
                flag_values_in(&chars),
                "{text:?}"
            );
            assert_eq!(
                find_bearer_value(text.as_bytes()),
                find_bearer_value(&chars),
                "{text:?}"
            );
        }
    }

    #[test]
    fn keyword_screen_loses_no_keyword() {
        // Reference: try every keyword at every position, no screen.
        fn unscreened(chars: &[char]) -> Vec<(usize, usize)> {
            let mut out = Vec::new();
            let mut i = 0;
            'o: while i < chars.len() {
                for (head, tail) in [("api", "key"), ("private", "key")] {
                    if let Some(end) = match_optional_sep_pair(chars, i, head, tail) {
                        out.push((i, end));
                        i = end;
                        continue 'o;
                    }
                }
                for kw in ["token", "secret", "password", "passwd"] {
                    if let Some(end) = match_literal_ci(chars, i, kw) {
                        out.push((i, end));
                        i = end;
                        continue 'o;
                    }
                }
                i += 1;
            }
            out
        }
        for text in fragment_strings(200_000) {
            let chars: Vec<char> = text.chars().collect();
            assert_eq!(find_assign_keywords(&chars), unscreened(&chars), "{text:?}");
        }
    }

    #[test]
    fn opener_screen_passes_every_opening_pair() {
        for b0 in 0..=255u8 {
            for b1 in 0..=255u8 {
                if rules_opened_by(b0, b1) != 0 {
                    assert!(
                        OPENER_FIRST[b0 as usize] & OPENER_SECOND[b1 as usize] != 0,
                        "screen drops pair {b0} {b1}"
                    );
                }
            }
        }
    }

    #[test]
    fn opener_table_covers_every_literal() {
        for (ri, rule) in PREFIX_RULES.iter().enumerate() {
            for lit in rule.literals {
                let b = lit.as_bytes();
                assert!(
                    rules_opened_by(b[0], b[1]) & (1 << ri) != 0,
                    "rule {ri} literal {lit} not reachable from its opening pair"
                );
            }
        }
    }

    #[test]
    fn secret_name_vocabulary() {
        assert!(is_secret_name("api_key"));
        assert!(is_secret_name("apikey"));
        assert!(is_secret_name("API-KEY"));
        assert!(is_secret_name("token"));
        assert!(is_secret_name("db_password"));
        assert!(is_secret_name("my_private_key"));
        assert!(!is_secret_name("keystore"));
        assert!(!is_secret_name("tokenizer"));
        assert!(!is_secret_name("host"));
    }

    #[test]
    fn env_names_and_paths_are_indirection_not_values() {
        assert!(is_env_name_value("GOOGLE_API_KEY"));
        assert!(is_env_name_value("PG_PASSWORD_2"));
        assert!(!is_env_name_value("GOOGLE"));
        assert!(!is_env_name_value("lower_case"));
        assert!(is_path_value("./token.txt"));
        assert!(is_path_value("/run/secrets/db"));
        assert!(is_path_value("~/keys"));
        assert!(is_path_value("C:\\keys"));
        assert!(!is_path_value("plainvalue"));
    }
}
