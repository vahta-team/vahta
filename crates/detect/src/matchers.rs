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

use crate::classify::{classify_value, Confidence};

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

/// `\b` at byte offset `at`: exactly one side is a word character.
fn at_word_boundary(chars: &[char], at: usize) -> bool {
    let before = if at == 0 { false } else { is_word(chars[at - 1]) };
    let after = if at >= chars.len() {
        false
    } else {
        is_word(chars[at])
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
    #[inline]
    fn contains(self, c: char) -> bool {
        match self {
            TailClass::WordDash => c.is_ascii_alphanumeric() || c == '_' || c == '-',
            TailClass::Word => c.is_ascii_alphanumeric() || c == '_',
            TailClass::UpperDigit => c.is_ascii_uppercase() || c.is_ascii_digit(),
            TailClass::Alnum => c.is_ascii_alphanumeric(),
            TailClass::AlnumDash => c.is_ascii_alphanumeric() || c == '-',
            TailClass::GoogleTail => c.is_ascii_alphanumeric() || c == '_' || c == '-',
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

/// Does `rule` match anywhere in `chars`?
///
/// The trailing `\b` is why this is not a simple run-length check. The tail
/// class contains `-`, which is *not* a word character, so after consuming the
/// maximal run the boundary may fail — and Python's engine then backtracks,
/// shortening the run until the boundary holds or the minimum is breached.
/// That backtracking is reproduced here rather than approximated.
fn rule_matches(rule: &PrefixRule, chars: &[char]) -> bool {
    for literal in rule.literals {
        let lit: Vec<char> = literal.chars().collect();
        let mut start = 0usize;
        while start + lit.len() <= chars.len() {
            if chars[start..start + lit.len()] != lit[..] {
                start += 1;
                continue;
            }
            if !at_word_boundary(chars, start) {
                start += 1;
                continue;
            }
            let run_start = start + lit.len();
            let mut end = run_start;
            while end < chars.len() && rule.tail.contains(chars[end]) {
                end += 1;
            }
            if rule.exact {
                // `{n}` consumes exactly n and cannot give any back, so the
                // trailing boundary either holds at n or the rule fails here.
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

/// Name the vendor whose prefix appears in `text`, if any.
pub fn find_prefix_kind(text: &str) -> Option<&'static str> {
    if text.is_empty() {
        return None;
    }
    let chars: Vec<char> = text.chars().collect();
    PREFIX_RULES
        .iter()
        .find(|rule| rule_matches(rule, &chars))
        .map(|rule| rule.kind)
}

// --- Bearer ----------------------------------------------------------------

#[inline]
fn is_bearer_value_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '=' | '/')
}

/// `(?i)\bBearer\s+([A-Za-z0-9._\-+=/]{16,})` — the captured value.
fn find_bearer_value(chars: &[char]) -> Option<String> {
    const WORD: [char; 6] = ['b', 'e', 'a', 'r', 'e', 'r'];
    let mut start = 0usize;
    while start + WORD.len() <= chars.len() {
        let matched = chars[start..start + WORD.len()]
            .iter()
            .zip(WORD)
            .all(|(c, w)| crate::primitives::fold_ci(*c) == w);
        if !matched || !at_word_boundary(chars, start) {
            start += 1;
            continue;
        }
        let mut i = start + WORD.len();
        let space_start = i;
        while i < chars.len() && is_space(chars[i]) {
            i += 1;
        }
        if i == space_start {
            start += 1;
            continue;
        }
        let value_start = i;
        while i < chars.len() && is_bearer_value_char(chars[i]) {
            i += 1;
        }
        if i - value_start >= 16 {
            return Some(chars[value_start..i].iter().collect());
        }
        start += 1;
    }
    None
}

/// Tier of the Bearer value, or `None` if there is no Bearer capture.
pub fn classify_bearer_capture(text: &str) -> Confidence {
    let chars: Vec<char> = text.chars().collect();
    match find_bearer_value(&chars) {
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

    starts
        .iter()
        .any(|&s| keyword_matches_exactly(&chars[s..]))
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

/// Keyword occurrences of `_ASSIGN_KEYWORD`, as (start, end) in characters.
fn find_assign_keywords(chars: &[char]) -> Vec<(usize, usize)> {
    const KEYWORDS: [&str; 4] = ["token", "secret", "password", "passwd"];
    let mut out: Vec<(usize, usize)> = Vec::new();
    let mut i = 0usize;

    'outer: while i < chars.len() {
        // Every keyword begins with one of these, so one comparison skips the
        // overwhelming majority of positions. Python gets the same effect for
        // free from a compiled alternation, which is a DFA; without this the
        // port tries six literals at every character and loses its advantage
        // on keyword-dense text such as source files.
        if !matches!(crate::primitives::fold_ci(chars[i]), 'a' | 't' | 's' | 'p') {
            i += 1;
            continue;
        }

        // `api[_-]?key` and `private[_-]?key`
        for (head, tail) in [("api", "key"), ("private", "key")] {
            if let Some(end) = match_optional_sep_pair(chars, i, head, tail) {
                out.push((i, end));
                i = end;
                continue 'outer;
            }
        }
        for kw in KEYWORDS {
            if let Some(end) = match_literal_ci(chars, i, kw) {
                out.push((i, end));
                i = end;
                continue 'outer;
            }
        }
        i += 1;
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
fn match_literal_ci(chars: &[char], at: usize, literal: &str) -> Option<usize> {
    let lit = literal.as_bytes();
    if at + lit.len() > chars.len() {
        return None;
    }
    for (offset, &want) in lit.iter().enumerate() {
        let c = crate::primitives::fold_ci(chars[at + offset]);
        if !c.is_ascii() || c as u8 != want {
            return None;
        }
    }
    Some(at + lit.len())
}

fn match_optional_sep_pair(
    chars: &[char],
    at: usize,
    head: &str,
    tail: &str,
) -> Option<usize> {
    let after_head = match_literal_ci(chars, at, head)?;
    let after_sep = if after_head < chars.len()
        && (chars[after_head] == '_' || chars[after_head] == '-')
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
fn match_assign_tail(chars: &[char], at: usize) -> Option<AssignTail> {
    let mut i = at;

    let nq2 = if i < chars.len() && (chars[i] == '\'' || chars[i] == '"') {
        let c = chars[i];
        i += 1;
        Some(c)
    } else {
        None
    };

    while i < chars.len() && is_space(chars[i]) {
        i += 1;
    }
    if i >= chars.len() || (chars[i] != ':' && chars[i] != '=') {
        return None;
    }
    i += 1;
    while i < chars.len() && is_space(chars[i]) {
        i += 1;
    }

    let q = if i < chars.len() && (chars[i] == '\'' || chars[i] == '"') {
        let c = chars[i];
        i += 1;
        Some(c)
    } else {
        None
    };

    let value_start = i;
    while i < chars.len() && !is_space(chars[i]) && chars[i] != '\'' && chars[i] != '"' {
        i += 1;
    }
    if i - value_start < 8 {
        return None;
    }
    let value: String = chars[value_start..i].iter().collect();

    let q2 = if i < chars.len() && (chars[i] == '\'' || chars[i] == '"') {
        let c = chars[i];
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
    let mut out = Vec::new();
    if text.is_empty() {
        return out;
    }
    let chars: Vec<char> = text.chars().collect();

    for (kw_start, kw_end) in find_assign_keywords(&chars) {
        // Walk left across `[a-z0-9]+[_-]` groups, bounded.
        let mut i = kw_start;
        let floor = kw_start.saturating_sub(MAX_NAME_PREFIX);
        while i > floor && (chars[i - 1] == '_' || chars[i - 1] == '-') {
            let mut j = i - 1;
            while j > floor && is_name_char(chars[j - 1]) {
                j -= 1;
            }
            if j == i - 1 {
                break;
            }
            i = j;
        }

        let Some(tail) = match_assign_tail(&chars, kw_end) else {
            continue;
        };

        // The legacy `(?P=nq)` only pairs quotes inside the match: a quote
        // immediately before the name is usually JSON wrapping, not a quoted
        // key, so an opener is required only when the tail captured a closer.
        if let Some(nq2) = tail.nq2 {
            if i == 0 || chars[i - 1] != nq2 {
                continue;
            }
        }
        // Value quotes: a closer is required only when an opener was captured.
        if let Some(q) = tail.q {
            if tail.q2 != Some(q) {
                continue;
            }
        }

        let name: String = chars[i..kw_end].iter().collect();
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
    let mut out = Vec::new();
    if text.is_empty() || !text.contains('-') {
        return out;
    }
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0usize;

    while i < chars.len() {
        // `(?<![\w./=-])` — the lookbehind, which no Rust regex can express.
        let preceded_ok = i == 0
            || !(is_word(chars[i - 1]) || matches!(chars[i - 1], '.' | '/' | '=' | '-'));
        if !preceded_ok || chars[i] != '-' {
            i += 1;
            continue;
        }

        let mut j = i + 1;
        if j < chars.len() && chars[j] == '-' {
            j += 1;
        }
        if j >= chars.len() || !chars[j].is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        let name_start = j;
        j += 1;
        while j < chars.len()
            && (chars[j].is_ascii_alphanumeric() || chars[j] == '_' || chars[j] == '-')
        {
            j += 1;
        }
        let name: String = chars[name_start..j].iter().collect();

        let sep_start = j;
        while j < chars.len() && (chars[j] == ' ' || chars[j] == '\t') {
            j += 1;
        }
        if j == sep_start {
            i += 1;
            continue;
        }

        let q = if j < chars.len() && (chars[j] == '\'' || chars[j] == '"') {
            let c = chars[j];
            j += 1;
            Some(c)
        } else {
            None
        };

        // First value character additionally excludes a leading `-`, so
        // `mysql --password --host=db` reads the next flag as a flag.
        if j >= chars.len() || !is_flag_value_char(chars[j]) || chars[j] == '-' {
            i += 1;
            continue;
        }
        let value_start = j;
        j += 1;
        while j < chars.len() && is_flag_value_char(chars[j]) {
            j += 1;
        }
        if j - value_start < 8 {
            i += 1;
            continue;
        }
        let value: String = chars[value_start..j].iter().collect();

        // `(?P=q)`: a closer is required only when an opener was captured.
        if let Some(q) = q {
            if chars.get(j) != Some(&q) {
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
