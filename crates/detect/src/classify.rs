//! Tier decision for a single captured value.
//!
//! Ported from `key_amnesia.detect_py::classify_value`. The thresholds and the
//! evidence behind them live in that module's docstring and are not restated;
//! what is restated here is only what a reader of *this* file could otherwise
//! get wrong.
//!
//! No pattern in this layer needs a regex engine. `_FUNC_CALL`, `_TYPE_ANN`,
//! `_UUID_SHAPE` and `_HEX_LIKELY` are all simple enough to match directly,
//! which keeps the crate dependency-free — and keeps pattern compilation out
//! of a cold start that runs on every tool call the agent makes.

use crate::primitives::{CharClass, char_class, entropy, vowel_bearing_segments};

/// Length floor, inherited from the 0.4.9 assignment heuristic.
pub const MIN_VALUE_LEN: usize = 8;

/// The *possible* gate, never the likely-floor. Shannon cannot separate
/// identifiers from random tokens — measured overlap is in the Python
/// docstring.
pub const SHANNON_POSSIBLE_FLOOR: f64 = 3.0;

/// Lowest floor that excludes the entire measured identifier band (ceiling
/// 0.45) while still admitting JWT-shaped (0.71) and random fixtures (1.00).
pub const LIKELY_TRANSITION_FLOOR: f64 = 0.50;

/// Hex-32 transitions at 0.42, below the floor, so hex is an explicit
/// exception rather than a reason to lower it.
pub const HEX_LIKELY_MIN_LEN: usize = 16;

pub const STRIPPED_UUID_LEN: usize = 32;

pub const MIN_VOWEL_SEGMENTS_FOR_POSSIBLE: usize = 2;

/// Confidence tier. Deliberately not a score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    None,
    Possible,
    Likely,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::None => "none",
            Confidence::Possible => "possible",
            Confidence::Likely => "likely",
        }
    }
}

pub const REASON_UUID: &str = "uuid";
/// An `mcp.json` whose top level has neither `mcpServers` nor `servers`.
pub const REASON_UNCONFIRMED_MCP: &str = "unconfirmed-mcp-shape";
pub const NAMED_WEAKENING_FUNCTION_CALL: &str = "function-call";
pub const NAMED_WEAKENING_TYPE_ANNOTATION: &str = "type-annotation";
pub const NAMED_WEAKENING_WORD_SHAPED_PASSPHRASE: &str = "word-shaped-passphrase";
pub const NAMED_WEAKENING_IDENTIFIER: &str = "identifier";
pub const NAMED_WEAKENING_LOW_TRANSITION: &str = "low-transition";

pub const NAMED_WEAKENINGS: [&str; 5] = [
    NAMED_WEAKENING_FUNCTION_CALL,
    NAMED_WEAKENING_TYPE_ANNOTATION,
    NAMED_WEAKENING_WORD_SHAPED_PASSPHRASE,
    NAMED_WEAKENING_IDENTIFIER,
    NAMED_WEAKENING_LOW_TRANSITION,
];

const PLACEHOLDER_VALUES: [&str; 18] = [
    "test123",
    "test1234",
    "changeme",
    "change_me",
    "changethis",
    "password",
    "password123",
    "secret",
    "yourkey",
    "your_api_key",
    "your-api-key",
    "placeholder",
    "example",
    "dummy",
    "fake",
    "sample",
    "xxxxxxxx",
    "12345678",
];

/// `value.strip("'\"")` — any mix of the two quote characters, both ends.
fn strip_quotes(value: &str) -> &str {
    value.trim_matches(|c| c == '\'' || c == '"')
}

/// Python lowercases with `str.lower()`, which is full Unicode case folding
/// for the simple cases; `to_lowercase` matches it for everything reachable
/// here. Compared against a fixed ASCII set, so only ASCII can match anyway.
pub fn is_placeholder(value: &str) -> bool {
    let stripped = strip_quotes(value);
    if stripped.is_ascii() {
        // Fast path, no allocation. For ASCII input `str::to_lowercase` is
        // exactly ASCII lowercasing, so comparing case-insensitively against
        // the (lowercase) table is the same test. Non-ASCII input takes the
        // exact path below: U+212A KELVIN SIGN lowercases to ASCII `k`, so it
        // can spell `your_api_key` and must keep doing so.
        return PLACEHOLDER_VALUES
            .iter()
            .any(|p| stripped.eq_ignore_ascii_case(p))
            || is_run_of_ascii(stripped, b'x', 6)
            || is_run_of_ascii(stripped, b'0', 6)
            || is_run_of_ascii(stripped, b'1', 6);
    }
    let v = stripped.to_lowercase();
    if PLACEHOLDER_VALUES.contains(&v.as_str()) {
        return true;
    }
    is_run_of(&v, 'x', 6) || is_run_of(&v, '0', 6) || is_run_of(&v, '1', 6)
}

/// [`is_run_of`] over an ASCII string that has not been lowercased yet:
/// `want` is lowercase, and matches either case.
fn is_run_of_ascii(s: &str, want: u8, min: usize) -> bool {
    s.len() >= min && s.bytes().all(|b| b.to_ascii_lowercase() == want)
}

/// `re.fullmatch(r"c{min,}")` — the whole string is one character, repeated at
/// least `min` times.
fn is_run_of(s: &str, want: char, min: usize) -> bool {
    let mut n = 0usize;
    for c in s.chars() {
        if c != want {
            return false;
        }
        n += 1;
    }
    n >= min
}

/// Words that mark a value as made up for a test or an example.
const TEST_MARKERS: [&str; 9] = [
    "fake",
    "dummy",
    "example",
    "sample",
    "placeholder",
    "test",
    "mock",
    "stub",
    "demo",
];
const MARKED_WORD_MAX: usize = 12;
const MARKED_NUMBER_MAX: usize = 4;

/// A value spelled as words and short numbers, one of them a test marker:
/// `fake-plain-value-1` is a test value, `fake-aB3xQ9mK2pL7vN4wZ8` is not,
/// because its second part is not a word. Each part between `-`, `_` or `.`
/// is a word (ASCII letters of one case, with a vowel, at most 12) or a number
/// of at most 4 digits. A real credential is not spelled that way; a
/// passphrase is, which is why a marker word is required.
pub fn is_marked_test_value(value: &str) -> bool {
    let v = strip_quotes(value);
    if !v.is_ascii() {
        return false;
    }
    let mut parts = 0usize;
    let mut marked = false;
    for part in v.split(['-', '_', '.']) {
        parts += 1;
        let b = part.as_bytes();
        if !b.is_empty() && b.len() <= MARKED_NUMBER_MAX && b.iter().all(u8::is_ascii_digit) {
            continue;
        }
        let lower = b.iter().all(u8::is_ascii_lowercase);
        let upper = b.iter().all(u8::is_ascii_uppercase);
        if b.is_empty() || b.len() > MARKED_WORD_MAX || !(lower || upper) {
            return false;
        }
        if !b.iter().any(|c| {
            matches!(
                c.to_ascii_lowercase(),
                b'a' | b'e' | b'i' | b'o' | b'u' | b'y'
            )
        }) {
            return false;
        }
        marked = marked || TEST_MARKERS.iter().any(|m| part.eq_ignore_ascii_case(m));
    }
    parts >= 2 && marked
}

pub fn compact_hex(value: &str) -> String {
    value.replace('-', "")
}

pub fn is_nil_or_all_zero(value: &str) -> bool {
    // `compact_hex(value)` without building it: skip the dashes in place.
    let mut any = false;
    for c in value.chars().filter(|&c| c != '-') {
        if c != '0' {
            return false;
        }
        any = true;
    }
    any
}

/// `^[0-9a-fA-F]{8}-{4}-{4}-{4}-{12}$`
/// `is_hex_run(&compact_hex(s), min_len)` without the intermediate string.
fn is_dashless_hex_run(s: &str, min_len: usize) -> bool {
    let mut n = 0usize;
    for c in s.chars().filter(|&c| c != '-') {
        if !c.is_ascii_hexdigit() {
            return false;
        }
        n += 1;
    }
    n >= min_len
}

fn is_uuid_shape(value: &str) -> bool {
    const WIDTHS: [usize; 5] = [8, 4, 4, 4, 12];
    // Exactly five dash-separated groups, checked without collecting them.
    let mut groups = value.split('-');
    for w in WIDTHS {
        let Some(g) = groups.next() else {
            return false;
        };
        if g.chars().count() != w || !g.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }
    groups.next().is_none()
}

/// Hyphenated UUID or 32-character hex. Nil is excluded before this is called.
pub fn uuid_or_stripped_hex(value: &str) -> bool {
    if is_uuid_shape(value) {
        return true;
    }
    // The dash-stripped form, counted and checked in place. 32 hex digits
    // satisfy the 16-digit run minimum too, so only the count and the digit
    // test remain.
    let mut n = 0usize;
    for c in value.chars().filter(|&c| c != '-') {
        if !c.is_ascii_hexdigit() {
            return false;
        }
        n += 1;
    }
    n == STRIPPED_UUID_LEN && n >= HEX_LIKELY_MIN_LEN
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Length in characters of the identifier starting at `chars[i]`, or 0.
/// Length of the ASCII identifier starting at byte `i`, 0 if none.
///
/// The identifier alphabet is ASCII, so scanning bytes gives the same lengths
/// as scanning characters, and a byte offset reached this way is also the
/// character offset (everything before it was ASCII). The callers below rely
/// on that to avoid collecting the value into a `Vec<char>`; the only other
/// things they test are ASCII punctuation, which no UTF-8 continuation byte
/// can imitate.
fn ident_len(bytes: &[u8], i: usize) -> usize {
    if i >= bytes.len() || !is_ident_start(bytes[i] as char) {
        return 0;
    }
    let mut j = i + 1;
    while j < bytes.len() && is_ident_char(bytes[j] as char) {
        j += 1;
    }
    j - i
}

/// `^ident(\.ident)*\(.*\)$` — a call expression, which is code rather than a
/// credential. Named weakening 1.
pub fn is_function_call(value: &str) -> bool {
    let chars = value.as_bytes();
    let mut i = ident_len(chars, 0);
    if i == 0 {
        return false;
    }
    while i < chars.len() && chars[i] == b'.' {
        let n = ident_len(chars, i + 1);
        if n == 0 {
            return false;
        }
        i += 1 + n;
    }
    // `\(.*\)$` — `.` does not match a newline in Python without DOTALL, so a
    // value containing one cannot satisfy the tail.
    if i >= chars.len() || chars[i] != b'(' || *chars.last().unwrap() != b')' {
        return false;
    }
    if chars.len() < i + 2 {
        return false;
    }
    !chars[i + 1..chars.len() - 1].contains(&b'\n')
}

/// `^ident\[.+\]$` — a subscripted type. Named weakening 2.
pub fn is_type_annotation(value: &str) -> bool {
    let chars = value.as_bytes();
    let i = ident_len(chars, 0);
    if i == 0 || i >= chars.len() || chars[i] != b'[' {
        return false;
    }
    if *chars.last().unwrap() != b']' {
        return false;
    }
    let inner = &chars[i + 1..chars.len() - 1];
    !inner.is_empty() && !inner.contains(&b'\n')
}

/// Classify a captured value. Never returns the value.
///
/// The order of the checks is the behaviour: a placeholder is rejected before
/// shape is considered, a UUID is promoted before the transition floor can
/// demote it, and the word-shaped demotion is applied only when there are no
/// digits — otherwise a JWT would demote through its own base64 segments.
/// `re.match(r"\$\{\{|\{\{|\$\{[A-Za-z_]|\$\(|\$[A-Za-z_]|%[A-Za-z_][A-Za-z0-9_]*%")`:
/// the value starts with a reference to where the credential comes from (a
/// shell variable, a CI expression, a template, a command substitution, a
/// Windows `%VAR%`), so it is not the credential. Without this the text after
/// the reference (a URL, a JSON escape) made the value look random. `$` then a
/// digit (a bcrypt hash) is not a reference.
pub fn starts_with_reference(value: &str) -> bool {
    let b = value.as_bytes();
    let ident_start = |i: usize| b.get(i).is_some_and(|c| is_ident_start(*c as char));
    match b {
        [b'$', b'{', b'{', ..] | [b'{', b'{', ..] | [b'$', b'(', ..] => true,
        [b'$', b'{', ..] => ident_start(2),
        [b'$', ..] => ident_start(1),
        [b'%', ..] => {
            let n = ident_len(b, 1);
            n > 0 && b.get(1 + n) == Some(&b'%')
        }
        _ => false,
    }
}

pub fn classify_value(value: &str) -> (Confidence, Option<&'static str>) {
    let v = strip_quotes(value);

    if v.chars().count() < MIN_VALUE_LEN {
        return (Confidence::None, None);
    }
    if is_placeholder(v)
        || is_marked_test_value(v)
        || is_nil_or_all_zero(v)
        || starts_with_reference(v)
    {
        return (Confidence::None, None);
    }
    if is_function_call(v) {
        return (Confidence::None, Some(NAMED_WEAKENING_FUNCTION_CALL));
    }
    if is_type_annotation(v) {
        return (Confidence::None, Some(NAMED_WEAKENING_TYPE_ANNOTATION));
    }

    // Promoted before the transition floor can demote it. Measured: hex-32
    // rates 0.42, because a hex alphabet does not alternate character classes
    // the way base62 does. Hyphens are not the cause - they are class "other"
    // and raise the rate.
    if uuid_or_stripped_hex(v) {
        return (Confidence::Likely, Some(REASON_UUID));
    }

    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    for c in v.chars() {
        match char_class(c) {
            CharClass::Upper => has_upper = true,
            CharClass::Lower => has_lower = true,
            CharClass::Digit => has_digit = true,
            CharClass::Other => {}
        }
    }
    let classes = usize::from(has_upper) + usize::from(has_lower) + usize::from(has_digit);
    if classes < 2 {
        return (Confidence::None, None);
    }
    if entropy(v) < SHANNON_POSSIBLE_FLOOR {
        return (Confidence::None, None);
    }

    if !has_digit && vowel_bearing_segments(v) >= MIN_VOWEL_SEGMENTS_FOR_POSSIBLE {
        let first_is_upper = v
            .chars()
            .next()
            .is_some_and(|c| char_class(c) == CharClass::Upper);
        return if first_is_upper {
            (
                Confidence::Possible,
                Some(NAMED_WEAKENING_WORD_SHAPED_PASSPHRASE),
            )
        } else {
            (Confidence::Possible, Some(NAMED_WEAKENING_IDENTIFIER))
        };
    }

    if is_dashless_hex_run(v, HEX_LIKELY_MIN_LEN) {
        return (Confidence::Likely, None);
    }

    if crate::primitives::transition_rate(v) >= LIKELY_TRANSITION_FLOOR {
        return (Confidence::Likely, None);
    }
    (Confidence::Possible, Some(NAMED_WEAKENING_LOW_TRANSITION))
}

/// The 0.4.9 hook meaning: possible or likely, i.e. not none.
pub fn assignment_is_secret(value: &str) -> bool {
    !matches!(classify_value(value).0, Confidence::None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_starting_with_a_reference_is_none() {
        // Built from pieces: the product's own hook reads this file too.
        let d = "$";
        for v in [
            format!("{d}{{GH_TOKEN}}@github.com/o/r.git"),
            format!("{d}{{{{ secrets.GITHUB_TOKEN }}}}@x"),
            "{{TEMPLATE_NAME}}\\n".to_string(),
            format!("{d}(cat .token-file)Xy9"),
            format!("{d}TOKEN/path/Ab9"),
            "%TOKEN%Ab9xyz".to_string(),
        ] {
            assert!(starts_with_reference(&v), "{v}");
            assert_eq!(classify_value(&v).0, Confidence::None, "{v}");
        }
        for v in [
            format!("{d}2b{d}12{d}aB3xQ9mK2pL7vN4wZ8"),
            "%aB3xQ9mK2pL7vN4wZ8".to_string(),
            format!("{d}{{"),
            format!("{d}9abc"),
            "aB3xQ9mK2pL7vN4wZ8".to_string(),
        ] {
            assert!(!starts_with_reference(&v), "{v}");
        }
    }

    #[test]
    fn a_value_marked_as_a_test_value_is_none() {
        // Built from pieces: the product's own hook reads this file too.
        let j = |parts: &[&str]| parts.join("-");
        for v in [
            j(&["fake", "plain", "value", "1"]),
            j(&["dummy", "token"]),
            "TEST_API_KEY_2024".to_string(),
            "example.secret.value".to_string(),
        ] {
            assert!(is_marked_test_value(&v), "{v}");
            assert_eq!(classify_value(&v).0, Confidence::None, "{v}");
        }
        for v in [
            // A random part is not a word.
            j(&["fake", "aB3xQ9mK2pL7vN4wZ8"]),
            j(&["test", "qzx7Kp"]),
            // No marker: a passphrase stays what it was.
            j(&["correct", "horse", "battery", "1"]),
            // A long number, mixed case, one part only, an empty part.
            j(&["fake", "123456789"]),
            j(&["Fake", "value"]),
            "fakevalue1".to_string(),
            "fake--value".to_string(),
        ] {
            assert!(!is_marked_test_value(&v), "{v}");
        }
        assert_eq!(
            classify_value(&j(&["fake", "aB3xQ9mK2pL7vN4wZ8"])).0,
            Confidence::Likely
        );
    }

    #[test]
    fn too_short_is_none() {
        assert_eq!(classify_value("abc"), (Confidence::None, None));
    }

    #[test]
    fn placeholders_are_none() {
        assert_eq!(classify_value("changeme"), (Confidence::None, None));
        assert_eq!(classify_value("xxxxxxxx"), (Confidence::None, None));
        assert_eq!(classify_value("00000000"), (Confidence::None, None));
    }

    #[test]
    fn a_call_expression_is_weakened_to_none() {
        assert_eq!(
            classify_value("GetTokenFromCache()"),
            (Confidence::None, Some(NAMED_WEAKENING_FUNCTION_CALL))
        );
        assert_eq!(
            classify_value("os.environ.get(x)"),
            (Confidence::None, Some(NAMED_WEAKENING_FUNCTION_CALL))
        );
    }

    #[test]
    fn a_subscripted_type_is_weakened_to_none() {
        assert_eq!(
            classify_value("Optional[SecretStr]"),
            (Confidence::None, Some(NAMED_WEAKENING_TYPE_ANNOTATION))
        );
    }

    /// The promotion earns its place on values whose transition rate would
    /// otherwise demote them. Hyphens raise the rate rather than lowering it,
    /// so the hyphenated form is not the interesting case - the stripped hex
    /// is, at a measured 0.42.
    #[test]
    fn uuid_is_promoted_past_the_transition_floor() {
        let hex32 = "a1b2c3d4e5f6789012345678abcdef01";
        assert!(crate::primitives::transition_rate(hex32) < LIKELY_TRANSITION_FLOOR);
        assert_eq!(
            classify_value(hex32),
            (Confidence::Likely, Some(REASON_UUID))
        );

        let uuid = "4f8a1c9e-2b7d-4e63-9a15-0c8bd3f7e214";
        assert!(crate::primitives::transition_rate(uuid) > LIKELY_TRANSITION_FLOOR);
        assert_eq!(
            classify_value(uuid),
            (Confidence::Likely, Some(REASON_UUID))
        );
    }

    #[test]
    fn quotes_are_stripped_before_anything_else() {
        assert_eq!(classify_value("\"changeme\""), (Confidence::None, None));
        assert_eq!(classify_value("'changeme'"), (Confidence::None, None));
    }
}
