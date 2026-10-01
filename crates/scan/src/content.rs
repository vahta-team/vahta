//! Reading a file and turning it into findings.
//!
//! Ports, from `src/key_amnesia/scan_py.py`:
//!   `_safe_read_text` (220), `_dotenv_finding` (233), `_json_key_names` (276),
//!   `scan_text_for_leaks` (290), `_inline_findings` (405),
//!   `_findings_for_path` (646),
//! plus `parse_dotenv` from `src/key_amnesia/dotenv_import.py:22`.
//!
//! Python is the specification, including where it is arguably wrong.
//!
//! Never emits a secret *value*: a [`Finding`] carries a path, a kind, secret
//! *names* and counts, and nothing in this module ever puts a value in a
//! reason string, a name list, or an error.

use crate::filenames::{filename_kind, is_content_scannable};
use crate::finding::{Finding, Scope};
use std::path::Path;
use vahta_detect::scan_text_hits;

pub use vahta_detect::REASON_UNCONFIRMED_MCP;

// --- Python string primitives ----------------------------------------------

/// `str.isspace()` — the detector's definition, so the two crates cannot
/// disagree. Why it is not `char::is_whitespace`: U+001C..U+001F, which makes
/// `_dotenv_finding`'s `if v.strip()` see `"\x1f"` as empty.
use vahta_detect::is_python_space;

/// Python's `str.strip()`.
fn py_strip(s: &str) -> &str {
    s.trim_matches(is_python_space)
}

/// Python's `str.rstrip()`.
fn py_rstrip(s: &str) -> &str {
    s.trim_end_matches(is_python_space)
}

/// Python's `str.lstrip()`.
fn py_lstrip(s: &str) -> &str {
    s.trim_start_matches(is_python_space)
}

/// Python's `str.splitlines()`.
///
/// Not `str::lines`, which only knows `\n` and `\r\n`. The boundary set was
/// read out of the interpreter by asking which of U+0000..U+3000 split
/// `"a" + c + "b"` in two: `\n`, `\v`, `\f`, `\r`, U+001C, U+001D, U+001E,
/// U+0085, U+2028 and U+2029, with `\r\n` counting as one boundary. Note
/// U+001F is **not** one, although `str.strip()` does strip it.
///
/// A dotenv file using `\v` or U+2028 as its line terminator therefore yields
/// entries in Python where `str::lines` would yield none.
fn py_splitlines(text: &str) -> Vec<&str> {
    #[inline]
    fn is_break(c: char) -> bool {
        matches!(
            c,
            '\n' | '\u{b}'
                | '\u{c}'
                | '\r'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        )
    }
    let mut out: Vec<&str> = Vec::new();
    let mut start = 0usize;
    let mut resume = 0usize;
    for (i, c) in text.char_indices() {
        if i < resume {
            continue;
        }
        if is_break(c) {
            out.push(&text[start..i]);
            let mut next = i + c.len_utf8();
            if c == '\r' && text[next..].starts_with('\n') {
                next += 1;
            }
            start = next;
            resume = next;
        }
    }
    // A trailing boundary does not produce a final empty element, exactly as
    // `splitlines()` does not.
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

/// `str(path)`.
///
/// One knowing divergence: Python's `Path` normalises on construction, so
/// `str(Path("./a/.env"))` is `"a/.env"` and `str(Path("a//b"))` is `"a/b"`,
/// while this reproduces what it was handed. The walker is what builds these
/// paths and it produces neither form, so normalising here would only add a
/// second, disagreeing notion of a path.
pub(crate) fn path_str(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// `path.name` — the empty string when there is none, as pathlib reports it.
///
/// `Path::file_name` already returns `None` for `/`, `.` and a path ending in
/// `..`, which is what `pathlib` calls `""`.
pub(crate) fn path_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

// --- _safe_read_text -------------------------------------------------------

/// `_safe_read_text`. `None` on an OS error, or when a NUL appears in the
/// first 4096 bytes. Decodes lossily — never fails on invalid UTF-8.
///
/// Python reads the *whole* file and then slices, so `limit` caps what is
/// decoded rather than what is read; a truncating slice routinely cuts a
/// multi-byte sequence in half. That is safe to mirror with
/// `String::from_utf8_lossy`: checked against the interpreter,
/// `bytes.decode("utf-8", errors="replace")` substitutes one U+FFFD per
/// *maximal subpart* exactly as Rust does — `b"\xf0\x9f\x92"` gives one
/// replacement character in both, `b"\xc0\xaf"` gives two in both, and
/// `b"\xed\xa0\x80"` (a surrogate spelled as UTF-8) gives three in both.
///
/// The NUL guard reads `data[:4096]` of the *already truncated* buffer, so a
/// `limit` below 4096 shrinks the window the guard sees too.
pub fn safe_read_text(path: &std::path::Path, limit: usize) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    safe_text_from_bytes(&data, limit)
}

/// [`safe_read_text`] on bytes already in hand.
fn safe_text_from_bytes(data: &[u8], limit: usize) -> Option<String> {
    let data = &data[..data.len().min(limit)];
    let head = &data[..data.len().min(4096)];
    if head.contains(&0u8) {
        return None;
    }
    Some(String::from_utf8_lossy(data).into_owned())
}

/// `_safe_read_text` at its default `limit` of `_MAX_CONTENT_BYTES`.
fn safe_read_text_default(path: &Path) -> Option<String> {
    safe_read_text(path, crate::MAX_CONTENT_BYTES)
}

// --- parse_dotenv ----------------------------------------------------------

/// `[A-Za-z_][A-Za-z0-9_]*` at the start of `s`; 0 when it does not match.
///
/// ASCII by construction: the Python character classes are spelled out as
/// ASCII ranges, so a name like `KÉY` matches neither side.
fn dotenv_name_len(s: &str) -> usize {
    let b = s.as_bytes();
    if b.is_empty() || !(b[0].is_ascii_alphabetic() || b[0] == b'_') {
        return 0;
    }
    let mut i = 1;
    while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
        i += 1;
    }
    i
}

/// `_LINE_RE.match(line)`: `^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$`.
///
/// Hand-rolled, like every matcher in `vahta-detect`, because the crate is
/// dependency-free and `regex` is not available. The backtracking the engine
/// would do is enumerated rather than simulated:
///
/// * `(?:export\s+)?` is greedy, so the engine tries it present first and
///   falls back to absent — that is the outer loop. The fallback is
///   load-bearing: `export=abc` has no whitespace after `export`, so the group
///   cannot match and the name becomes `export` itself.
/// * `\s+`, `[A-Za-z0-9_]*` and the `\s*` before `=` are each greedy and
///   **cannot usefully backtrack**. Giving a character back would leave a
///   whitespace character where a name character must start, or a name
///   character where `=` must be — and the classes do not overlap. So each is
///   taken at its maximum and no shorter length is retried.
/// * `\s*(.*)$` after the `=` always succeeds: `.` cannot match a newline, and
///   a line from `splitlines()` holds none.
fn match_dotenv_line(line: &str) -> Option<(&str, &str)> {
    for with_export in [true, false] {
        let mut rest = line;
        if with_export {
            let Some(after) = rest.strip_prefix("export") else {
                continue;
            };
            let trimmed = py_lstrip(after);
            if trimmed.len() == after.len() {
                // `\s+` needs at least one whitespace character.
                continue;
            }
            rest = trimmed;
        }
        let name_len = dotenv_name_len(rest);
        if name_len == 0 {
            continue;
        }
        let (name, after_name) = rest.split_at(name_len);
        let Some(after_eq) = py_lstrip(after_name).strip_prefix('=') else {
            continue;
        };
        return Some((name, py_lstrip(after_eq)));
    }
    None
}

/// `_unquote`.
fn unquote(raw_value: &str) -> String {
    let value = py_strip(raw_value);
    let b = value.as_bytes();
    // Python's `len(value) >= 2` counts characters and this counts bytes, but
    // the two agree here: the test also requires the first and last *bytes* to
    // be an ASCII quote, and a one-character string cannot hold two of those.
    if b.len() >= 2 && b[0] == b'"' && b[b.len() - 1] == b'"' {
        return value[1..value.len() - 1].to_string();
    }
    if b.len() >= 2 && b[0] == b'\'' && b[b.len() - 1] == b'\'' {
        return value[1..value.len() - 1].to_string();
    }
    // Unquoted: an inline ` #comment` is dropped, a bare `#` with no preceding
    // space is not. Note the separator is a literal space, not `\s` — a tab
    // before the `#` leaves the comment in the value.
    if let Some(i) = value.find(" #") {
        return py_rstrip(&value[..i]).to_string();
    }
    value.to_string()
}

/// `parse_dotenv`, preserving insertion order, so a `Vec` and not a map.
///
/// The `Vec` *is* a Python `dict`, and a duplicated name behaves like one: the
/// **first** occurrence fixes the position and the **last** one supplies the
/// value. `A=1\nB=2\nA=3` gives `[("A", "3"), ("B", "2")]`, verified against
/// the interpreter — `_dotenv_finding` reports `entries.keys()`, so getting
/// this wrong changes both the order and the count of reported names.
///
/// Takes the text rather than a path, because the file read in the Python
/// signature belongs to [`dotenv_finding`], its only caller.
pub fn parse_dotenv(text: &str) -> Vec<(String, String)> {
    let mut result: Vec<(String, String)> = Vec::new();
    for raw_line in py_splitlines(text) {
        let line = py_strip(raw_line);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, raw_value)) = match_dotenv_line(line) else {
            continue;
        };
        let value = unquote(raw_value);
        match result.iter_mut().find(|(n, _)| n == name) {
            Some(slot) => slot.1 = value,
            None => result.push((name.to_string(), value)),
        }
    }
    result
}

// --- _json_key_names -------------------------------------------------------

/// What `json.loads` made of a document.
#[derive(Debug, PartialEq, Eq)]
enum JsonTop {
    /// A valid top-level object, with its keys in `dict` order.
    Object(Vec<String>),
    /// Valid JSON that is not an object.
    NotAnObject,
    /// What `json.loads` raises `JSONDecodeError` for.
    Invalid,
}

/// Hand-rolled, iterative, and deliberately as strict as `json.loads`.
///
/// The crate is dependency-free and stays that way, so there is no serde to
/// lean on — and a *lenient* parser would be a divergence with teeth, because
/// `_json_key_names` reports `[]` for malformed JSON while a lenient parse
/// would report key names, inflating `secret_count` for every
/// `credentials.json` the scan touches. Every rule below was read out of
/// CPython's decoder rather than from the JSON grammar:
///
/// * Whitespace is `[ \t\n\r]` only. A leading `\f` or U+00A0 is an error, and
///   so is a UTF-8 BOM (`json.loads` has a dedicated message for that one).
/// * `NaN`, `Infinity` and `-Infinity` are **accepted** — Python's default
///   `parse_constant` allows them. Case is exact: `nan`, `Nan` and `INFINITY`
///   are errors, and so are `+Infinity` and `-NaN`.
/// * Numbers follow `-?(0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?` over **ASCII**
///   digits — the C scanner does not accept U+0663, even though the pure
///   Python fallback's `\d` would. The fractional and exponent parts are
///   optional *as a whole*, so `1.` and `1e` consume just the `1` and then
///   fail at the delimiter check rather than inside the number.
/// * A trailing comma is an error, in an object and in an array alike.
/// * Raw control characters below U+0020 inside a string are errors; U+007F is
///   fine.
/// * The only escapes are `" \ / b f n r t` and `uXXXX` with exactly four
///   ASCII hex digits. `\U0001F600` and `\a` are errors.
/// * Anything but whitespace after the top-level value is `Extra data`.
///
/// Two knowing divergences, both unavoidable:
///
/// * A **lone surrogate** escape is accepted by `json.loads`, which puts it in
///   the `str`: `{"\ud800": 1}` yields the key `'\ud800'`. A Rust `String`
///   cannot hold one, so it becomes U+FFFD. Only the reported *name* differs,
///   and it was never a value — though two distinct lone surrogates do
///   collapse to one key here, which is the one place the count can differ.
/// * Very deep nesting. This parser is iterative with an explicit stack, so it
///   accepts depths at which `json.loads` raises `RecursionError` (around
///   100 000 on this interpreter; 2000 still parses). Since `_json_key_names`
///   catches only `JSONDecodeError`, Python *crashes* there rather than
///   returning `[]`, so there is no behaviour to agree with — and recursing to
///   match it would trade a Python exception for an aborted process.
fn json_top_level(text: &str) -> JsonTop {
    let b = text.as_bytes();
    let mut i = 0usize;

    #[inline]
    fn skip_ws(b: &[u8], i: &mut usize) {
        while *i < b.len() && matches!(b[*i], b' ' | b'\t' | b'\n' | b'\r') {
            *i += 1;
        }
    }

    /// Consume an exact literal, or leave `i` alone and fail.
    #[inline]
    fn literal(b: &[u8], i: &mut usize, lit: &[u8]) -> bool {
        if b.len() - *i >= lit.len() && &b[*i..*i + lit.len()] == lit {
            *i += lit.len();
            true
        } else {
            false
        }
    }

    /// `(0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?`, already past any leading `-`.
    fn number_body(b: &[u8], i: &mut usize) -> bool {
        if *i >= b.len() {
            return false;
        }
        if b[*i] == b'0' {
            *i += 1;
        } else if b[*i].is_ascii_digit() {
            while *i < b.len() && b[*i].is_ascii_digit() {
                *i += 1;
            }
        } else {
            return false;
        }
        // `(\.\d+)?` — taken only when a digit actually follows the dot.
        if *i + 1 < b.len() && b[*i] == b'.' && b[*i + 1].is_ascii_digit() {
            *i += 1;
            while *i < b.len() && b[*i].is_ascii_digit() {
                *i += 1;
            }
        }
        // `([eE][-+]?\d+)?` — likewise all or nothing.
        if *i < b.len() && (b[*i] == b'e' || b[*i] == b'E') {
            let mut j = *i + 1;
            if j < b.len() && (b[j] == b'+' || b[j] == b'-') {
                j += 1;
            }
            if j < b.len() && b[j].is_ascii_digit() {
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                *i = j;
            }
        }
        true
    }

    /// Four ASCII hex digits as a code unit.
    fn hex4(b: &[u8], i: &mut usize) -> Option<u32> {
        if *i + 4 > b.len() {
            return None;
        }
        let mut v = 0u32;
        for k in 0..4 {
            let d = (b[*i + k] as char).to_digit(16)?;
            v = v * 16 + d;
        }
        *i += 4;
        Some(v)
    }

    /// A string, with `*i` just past the opening quote. `None` is invalid JSON.
    fn string(text: &str, b: &[u8], i: &mut usize) -> Option<String> {
        let mut out = String::new();
        loop {
            if *i >= b.len() {
                return None; // Unterminated string
            }
            match b[*i] {
                b'"' => {
                    *i += 1;
                    return Some(out);
                }
                b'\\' => {
                    *i += 1;
                    if *i >= b.len() {
                        return None;
                    }
                    let e = b[*i];
                    *i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = hex4(b, i)?;
                            if (0xd800..0xdc00).contains(&hi) {
                                // A surrogate pair, when a low one follows.
                                if b.len() - *i >= 6 && b[*i] == b'\\' && b[*i + 1] == b'u' {
                                    let save = *i;
                                    *i += 2;
                                    let lo = hex4(b, i)?;
                                    if (0xdc00..0xe000).contains(&lo) {
                                        let cp = 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00);
                                        out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                                        continue;
                                    }
                                    // Not a low surrogate: rewind and let that
                                    // escape be read on its own next pass,
                                    // which is what CPython does.
                                    *i = save;
                                }
                                out.push('\u{fffd}'); // lone high surrogate
                            } else if (0xdc00..0xe000).contains(&hi) {
                                out.push('\u{fffd}'); // lone low surrogate
                            } else {
                                out.push(char::from_u32(hi).unwrap_or('\u{fffd}'));
                            }
                        }
                        _ => return None, // Invalid \escape
                    }
                }
                0x00..=0x1f => return None, // Invalid control character
                _ => {
                    // One whole UTF-8 character. `text` is a `&str`, so the
                    // byte at `*i` is a character boundary here.
                    let c = text[*i..].chars().next()?;
                    out.push(c);
                    *i += c.len_utf8();
                }
            }
        }
    }

    /// Which container we are inside, innermost last.
    enum Ctx {
        Array,
        Object,
    }

    let mut stack: Vec<Ctx> = Vec::new();
    let mut root_keys: Option<Vec<String>> = None;

    /// `dict` semantics: a repeated key does not get a second entry in
    /// `keys()`, and keeps its first position.
    fn record(root_keys: &mut Option<Vec<String>>, stack_len: usize, key: String) {
        if stack_len != 1 {
            return;
        }
        if let Some(keys) = root_keys.as_mut() {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    }

    skip_ws(b, &mut i);
    // Loop head: a value is expected at `i`.
    'value: loop {
        if i >= b.len() {
            return JsonTop::Invalid;
        }
        match b[i] {
            b'{' => {
                i += 1;
                if stack.is_empty() {
                    root_keys = Some(Vec::new());
                }
                stack.push(Ctx::Object);
                skip_ws(b, &mut i);
                if i < b.len() && b[i] == b'}' {
                    i += 1;
                    stack.pop();
                    // Falls through to the after-a-value handling below.
                } else {
                    // A key must follow, and must be double-quoted.
                    if i >= b.len() || b[i] != b'"' {
                        return JsonTop::Invalid;
                    }
                    i += 1;
                    let Some(key) = string(text, b, &mut i) else {
                        return JsonTop::Invalid;
                    };
                    record(&mut root_keys, stack.len(), key);
                    skip_ws(b, &mut i);
                    if i >= b.len() || b[i] != b':' {
                        return JsonTop::Invalid;
                    }
                    i += 1;
                    skip_ws(b, &mut i);
                    continue 'value;
                }
            }
            b'[' => {
                i += 1;
                stack.push(Ctx::Array);
                skip_ws(b, &mut i);
                if i < b.len() && b[i] == b']' {
                    i += 1;
                    stack.pop();
                    // Falls through.
                } else {
                    continue 'value;
                }
            }
            b'"' => {
                i += 1;
                if string(text, b, &mut i).is_none() {
                    return JsonTop::Invalid;
                }
            }
            b't' => {
                if !literal(b, &mut i, b"true") {
                    return JsonTop::Invalid;
                }
            }
            b'f' => {
                if !literal(b, &mut i, b"false") {
                    return JsonTop::Invalid;
                }
            }
            b'n' => {
                if !literal(b, &mut i, b"null") {
                    return JsonTop::Invalid;
                }
            }
            b'N' => {
                if !literal(b, &mut i, b"NaN") {
                    return JsonTop::Invalid;
                }
            }
            b'I' => {
                if !literal(b, &mut i, b"Infinity") {
                    return JsonTop::Invalid;
                }
            }
            b'-' => {
                if !literal(b, &mut i, b"-Infinity") {
                    i += 1;
                    if !number_body(b, &mut i) {
                        return JsonTop::Invalid;
                    }
                }
            }
            b'0'..=b'9' => {
                if !number_body(b, &mut i) {
                    return JsonTop::Invalid;
                }
            }
            _ => return JsonTop::Invalid,
        }

        // A value has just completed. Close containers while they end, and
        // step to the next element when they do not.
        loop {
            if stack.is_empty() {
                skip_ws(b, &mut i);
                if i != b.len() {
                    return JsonTop::Invalid; // Extra data
                }
                return match root_keys {
                    Some(keys) => JsonTop::Object(keys),
                    None => JsonTop::NotAnObject,
                };
            }
            skip_ws(b, &mut i);
            if i >= b.len() {
                return JsonTop::Invalid;
            }
            match stack.last().expect("the stack is non-empty here") {
                Ctx::Array => match b[i] {
                    b',' => {
                        i += 1;
                        skip_ws(b, &mut i);
                        // A trailing comma is an error, so `]` cannot follow.
                        if i < b.len() && b[i] == b']' {
                            return JsonTop::Invalid;
                        }
                        continue 'value;
                    }
                    b']' => {
                        i += 1;
                        stack.pop();
                    }
                    _ => return JsonTop::Invalid,
                },
                Ctx::Object => match b[i] {
                    b',' => {
                        i += 1;
                        skip_ws(b, &mut i);
                        if i >= b.len() || b[i] != b'"' {
                            // Covers `{"a":1,}` and `{"a":1,,"b":2}` alike.
                            return JsonTop::Invalid;
                        }
                        i += 1;
                        let Some(key) = string(text, b, &mut i) else {
                            return JsonTop::Invalid;
                        };
                        record(&mut root_keys, stack.len(), key);
                        skip_ws(b, &mut i);
                        if i >= b.len() || b[i] != b':' {
                            return JsonTop::Invalid;
                        }
                        i += 1;
                        skip_ws(b, &mut i);
                        continue 'value;
                    }
                    b'}' => {
                        i += 1;
                        stack.pop();
                    }
                    _ => return JsonTop::Invalid,
                },
            }
        }
    }
}

/// `_json_key_names`: top-level object keys, never values.
///
/// Must agree with `json.loads` on **validity**, not just on well-formed
/// input: Python returns `[]` for malformed JSON, for valid non-object JSON,
/// and for an unreadable file alike, so a lenient parser silently reports keys
/// where Python reports none.
///
/// Note the read goes through `_safe_read_text` at its default limit, so a
/// `credentials.json` over 256 kB is truncated and therefore invalid, and one
/// with a NUL in its first 4096 bytes is unreadable. Both give `[]`.
pub fn json_key_names(path: &std::path::Path) -> Vec<String> {
    let Some(text) = safe_read_text_default(path) else {
        return Vec::new();
    };
    json_key_names_of(&text)
}

fn json_key_names_of(text: &str) -> Vec<String> {
    match json_top_level(text) {
        JsonTop::Object(keys) => keys,
        JsonTop::NotAnObject | JsonTop::Invalid => Vec::new(),
    }
}

// --- scan_text_for_leaks ---------------------------------------------------

/// `scan_text_for_leaks`: likely names plus an optional prefix kind.
pub fn scan_text_for_leaks(text: &str) -> (Vec<String>, Option<&'static str>) {
    if text.is_empty() {
        return (Vec::new(), None);
    }
    let hits = scan_text_hits(text);
    (hits.likely_names, hits.prefix)
}

// --- _dotenv_finding -------------------------------------------------------

/// `_dotenv_finding`. Three shapes: no entries, entries but all empty, and
/// the ordinary case — only the last is `importable`.
///
/// Reads the file the way `parse_dotenv` does, which is **not**
/// `_safe_read_text`: `path.read_text(encoding="utf-8", errors="replace")` has
/// no byte limit and no NUL guard, so a dotenv holding a NUL still parses
/// where a `.json` of the same bytes would be refused.
pub fn dotenv_finding(path: &std::path::Path, scope: Scope) -> Option<Finding> {
    // `except OSError: return None`.
    let data = std::fs::read(path).ok()?;
    dotenv_finding_of(path, &data, scope)
}

fn dotenv_finding_of(path: &std::path::Path, data: &[u8], scope: Scope) -> Option<Finding> {
    let text = String::from_utf8_lossy(data);
    let entries = parse_dotenv(&text);

    // Names only; drop empty values from the count (placeholders often empty).
    let names: Vec<String> = entries
        .iter()
        .filter(|(_, v)| !py_strip(v).is_empty())
        .map(|(n, _)| n.clone())
        .collect();

    let mut f = Finding::new(path_str(path), "dotenv", scope);
    f.confidence = "certain".to_string();

    if names.is_empty() && entries.is_empty() {
        // Empty / comment-only .env — still a LEAK *file* if it exists and
        // looks like a dotenv path agents will open; count 0 secrets.
        f.reason = "dotenv file (no KEY=VALUE entries)".to_string();
        return Some(f);
    }
    if names.is_empty() {
        f.secret_names = entries.into_iter().map(|(n, _)| n).collect();
        f.reason = "dotenv file (empty values only)".to_string();
        return Some(f);
    }
    f.reason = format!("dotenv file with {} secret name(s)", names.len());
    f.secret_count = names.len() as i64;
    f.secret_names = names;
    f.importable = true;
    Some(f)
}

// --- _inline_findings ------------------------------------------------------

/// `_inline_findings`: up to three findings from one text, one per tier.
pub fn inline_findings(
    path: &std::path::Path,
    text: &str,
    scope: Scope,
    kind: &str,
    high_reason: &str,
    possible_reason: &str,
) -> Vec<Finding> {
    let hits = scan_text_hits(text);
    let path = path_str(path);
    let mut out: Vec<Finding> = Vec::new();

    if let Some(prefix) = hits.prefix {
        let mut f = Finding::new(path.clone(), kind, scope);
        f.secret_count = 1;
        f.reason = format!("inline credential-shaped token ({prefix})");
        f.confidence = "certain".to_string();
        out.push(f);
    }
    if !hits.likely_names.is_empty() || hits.bearer_likely {
        let count = if hits.likely_names.is_empty() {
            1
        } else {
            hits.likely_names.len()
        };
        // A Bearer with no named assignment is phrased as the token, not with
        // the caller's reason.
        let reason = if hits.bearer_likely && hits.likely_names.is_empty() {
            "inline credential-shaped token (Bearer token)".to_string()
        } else {
            high_reason.to_string()
        };
        let mut f = Finding::new(path.clone(), kind, scope);
        f.secret_names = hits.likely_names.clone();
        f.secret_count = count as i64;
        f.reason = reason;
        f.confidence = "likely".to_string();
        f.reasons = hits.likely_reasons.clone();
        f.reason_counts = hits.likely_reason_counts.clone();
        out.push(f);
    }
    if !hits.possible_names.is_empty() || hits.bearer_possible {
        let count = if hits.possible_names.is_empty() {
            1
        } else {
            hits.possible_names.len()
        };
        let mut f = Finding::new(path, kind, scope);
        f.secret_names = hits.possible_names.clone();
        f.secret_count = count as i64;
        f.reason = possible_reason.to_string();
        f.confidence = "possible".to_string();
        f.reasons = hits.possible_reasons.clone();
        f.reason_counts = hits.possible_reason_counts.clone();
        out.push(f);
    }
    out
}

// --- the git_config matchers ----------------------------------------------

/// `re.search(r"(?i)(token|password|authorization|_authToken)\s*=", text)`.
///
/// Hand-rolled: `regex` is not a dependency and will not become one.
///
/// **The `(?i)` makes `_authToken` redundant.** Case-insensitively, any
/// `_authToken=` already contains `token=` at offset 5, so the fourth
/// alternative can never be the only one that matches. It is kept because the
/// job is to port the behaviour, not to tidy the pattern, and dropping an
/// alternative from a ported regex is how a port starts drifting.
///
/// `\s` is Python's, which is `str.isspace()` — it matches U+001C..U+001F,
/// checked against the interpreter, so `token\x1c=` does match.
fn git_config_keyword_assign(text: &str) -> bool {
    const KEYWORDS: [&str; 4] = ["token", "password", "authorization", "_authtoken"];
    let chars: Vec<char> = text.chars().collect();
    for start in 0..chars.len() {
        for kw in KEYWORDS {
            let kb = kw.as_bytes();
            if start + kb.len() > chars.len() {
                continue;
            }
            let matched = kb.iter().enumerate().all(|(k, &want)| {
                let c = chars[start + k];
                c.is_ascii() && (c as u8).to_ascii_lowercase() == want
            });
            if !matched {
                continue;
            }
            // `\s*=`
            let mut j = start + kb.len();
            while j < chars.len() && is_python_space(chars[j]) {
                j += 1;
            }
            if j < chars.len() && chars[j] == '=' {
                return true;
            }
        }
    }
    false
}

/// `re.search(r"https?://[^/\s:]+:[^/\s]+@", text)`.
///
/// **Unreachable in `_findings_for_path`, and ported anyway.** Python only
/// consults it when `"://" not in text`, and this pattern begins with
/// `https?://` — so it cannot match when that substring is absent. The branch
/// is dead; the port keeps it so the two implementations have the same shape
/// and a later edit to the outer condition does not silently lose it.
/// Confirmed against the interpreter over 26 inputs: the pattern matched only
/// where `"://" in text` already held.
///
/// Backtracking, enumerated rather than simulated: `[^/\s:]+` cannot give a
/// character back, because the `:` that must follow is excluded from its own
/// class, so only the maximal run can work. `[^/\s]+` *can*, because `@` is in
/// its class — greedy matching walks back to an `@`, and for a boolean any `@`
/// in the run will do.
fn git_config_url_credentials(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let at = |i: usize| -> Option<char> { chars.get(i).copied() };
    for start in 0..n {
        // `https?://`
        let mut i = start;
        let mut ok = true;
        for want in ['h', 't', 't', 'p'] {
            if at(i) != Some(want) {
                ok = false;
                break;
            }
            i += 1;
        }
        if !ok {
            continue;
        }
        if at(i) == Some('s') {
            i += 1;
        }
        if at(i) != Some(':') || at(i + 1) != Some('/') || at(i + 2) != Some('/') {
            continue;
        }
        i += 3;
        // `[^/\s:]+`, maximal — see above for why nothing shorter is tried.
        let seg_start = i;
        while i < n && chars[i] != '/' && chars[i] != ':' && !is_python_space(chars[i]) {
            i += 1;
        }
        if i == seg_start || at(i) != Some(':') {
            continue;
        }
        i += 1;
        // `[^/\s]+@` — at least one character before the `@`.
        let tail_start = i;
        let mut found = false;
        while i < n && chars[i] != '/' && !is_python_space(chars[i]) {
            if chars[i] == '@' && i > tail_start {
                found = true;
                break;
            }
            i += 1;
        }
        if found {
            return true;
        }
    }
    false
}

// --- _findings_for_path ----------------------------------------------------

/// `_findings_for_path`: the whole per-file decision.
pub fn findings_for_path(path: &std::path::Path, scope: Scope) -> Vec<Finding> {
    findings_from(path, scope, None)
}

/// [`findings_for_path`] for a file whose bytes the caller already holds (a
/// harness that hands over the content it is about to read): the same
/// decision, nothing read from disk. `path` still names the file, because the
/// name decides the kind.
pub fn findings_for_content(path: &std::path::Path, content: &[u8], scope: Scope) -> Vec<Finding> {
    findings_from(path, scope, Some(content))
}

/// The bytes of the file: the caller's, or the disk's (`None` on an OS error).
fn file_bytes<'a>(path: &Path, given: Option<&'a [u8]>) -> Option<std::borrow::Cow<'a, [u8]>> {
    match given {
        Some(b) => Some(std::borrow::Cow::Borrowed(b)),
        None => std::fs::read(path).ok().map(std::borrow::Cow::Owned),
    }
}

/// `_safe_read_text` at its default limit, from `given` or the disk.
fn text_of(path: &Path, given: Option<&[u8]>) -> Option<String> {
    safe_text_from_bytes(&file_bytes(path, given)?, crate::MAX_CONTENT_BYTES)
}

fn findings_from(path: &std::path::Path, scope: Scope, given: Option<&[u8]>) -> Vec<Finding> {
    let name = path_name(path);
    // `path.as_posix()`; on this platform `str(path)` already uses `/`.
    let posix = path_str(path);
    let kind = filename_kind(&posix, &name);

    if kind == Some("dotenv") {
        return file_bytes(path, given)
            .and_then(|d| dotenv_finding_of(path, &d, scope))
            .into_iter()
            .collect();
    }

    if let Some(kind) = kind {
        let mut names: Vec<String> = Vec::new();
        let mut count: usize = 1;
        let mut reason = format!("sensitive filename ({kind})");

        match kind {
            "credentials.json" => {
                names = text_of(path, given).map(|t| json_key_names_of(&t)).unwrap_or_default();
                count = names.len().max(1);
                reason = format!("credentials.json ({count} top-level key name(s))");
            }
            "mcp_config" => {
                names = text_of(path, given).map(|t| json_key_names_of(&t)).unwrap_or_default();
                count = names.len().max(1);
                let confirmed = names.iter().any(|k| k == "mcpServers" || k == "servers");
                if confirmed {
                    let mut f = Finding::new(posix, kind, scope);
                    f.secret_names = names;
                    f.secret_count = count as i64;
                    f.reason = format!("MCP config ({count} top-level key name(s))");
                    f.confidence = "certain".to_string();
                    return vec![f];
                }
                // Unrecognised shape: demote to possible, do not drop.
                // Presence/shape finding: one per file, not per top-level key —
                // so `secret_count` is 1 even when several names are reported.
                let mut f = Finding::new(posix, kind, scope);
                f.secret_names = names;
                f.secret_count = 1;
                f.reason =
                    "unconfirmed MCP config shape (no top-level mcpServers/servers)".to_string();
                f.confidence = "possible".to_string();
                f.reasons = vec![REASON_UNCONFIRMED_MCP.to_string()];
                f.reason_counts = vec![(REASON_UNCONFIRMED_MCP.to_string(), 1)];
                return vec![f];
            }
            ".npmrc" | ".pypirc" => {
                reason = format!("{kind} (may contain registry auth tokens)");
            }
            "ssh_private_key" => {
                reason = "SSH private key file".to_string();
            }
            "shell_history" => {
                // `if not text` is true for `None` *and* for `""`.
                let text = text_of(path, given).unwrap_or_default();
                if text.is_empty() {
                    return Vec::new();
                }
                return inline_findings(
                    path,
                    &text,
                    scope,
                    kind,
                    "shell history with credential-shaped content",
                    "shell history with possible identifier- or passphrase-shaped content",
                );
            }
            "git_config" => {
                let text = text_of(path, given).unwrap_or_default();
                if !git_config_keyword_assign(&text) && !text.contains("://") {
                    // This inner test can never succeed here — see
                    // `git_config_url_credentials`. Kept verbatim anyway.
                    if !git_config_url_credentials(&text) {
                        return Vec::new();
                    }
                }
                reason = "git config may embed credentials".to_string();
            }
            _ => {}
        }

        let mut f = Finding::new(posix, kind, scope);
        f.secret_names = names;
        f.secret_count = count as i64;
        f.reason = reason;
        f.confidence = "certain".to_string();
        return vec![f];
    }

    if !is_content_scannable(&name) {
        return Vec::new();
    }
    let text = text_of(path, given).unwrap_or_default();
    if text.is_empty() {
        return Vec::new();
    }
    inline_findings(
        path,
        &text,
        scope,
        "inline",
        "assignment pattern matching secret-guard vocabulary",
        "possible identifier- or passphrase-shaped assignment",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A temporary directory of our own, since `tempfile` is not a dependency.
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            // Unique without a dependency: pid plus a monotonic counter.
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "vahta-scan-content-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            TmpDir(dir)
        }

        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let p = self.0.join(name);
            std::fs::write(&p, bytes).expect("write fixture");
            p
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A value that classifies as `likely` without being anyone's credential.
    /// Assembled at runtime rather than written out whole.
    fn likely_value() -> String {
        ["aB3xQ9mK2pL7", "vN4wZ8rT6"].concat()
    }

    // --- Python string primitives ----------------------------------------

    /// The four separators are the whole divergence, read out of the
    /// interpreter: `chr(c).isspace()` over U+0000..U+3000 is Unicode
    /// `White_Space` plus exactly these.
    #[test]
    fn python_whitespace_adds_the_c0_separators() {
        for c in ['\u{1c}', '\u{1d}', '\u{1e}', '\u{1f}'] {
            assert!(is_python_space(c), "{c:?} is whitespace to Python");
            assert!(!c.is_whitespace(), "{c:?} is not whitespace to Rust");
        }
        // Everything Rust calls whitespace, Python does too.
        for c in [' ', '\t', '\n', '\u{85}', '\u{a0}', '\u{2028}', '\u{3000}'] {
            assert!(is_python_space(c));
        }
        assert!(!is_python_space('\u{200b}')); // zero width space: neither
        assert_eq!(py_strip("\u{1f}abc\u{1f}"), "abc");
        assert_eq!(py_strip("\u{a0}abc\u{1680}"), "abc");
    }

    /// Expectations taken from `("a" + chr(c) + "b").splitlines()`, not guessed.
    #[test]
    fn splitlines_knows_more_boundaries_than_rust_lines() {
        assert_eq!(py_splitlines("a\nb\n"), vec!["a", "b"]);
        assert_eq!(py_splitlines("a\r\nb"), vec!["a", "b"]);
        assert_eq!(py_splitlines("a\rb"), vec!["a", "b"]);
        assert_eq!(py_splitlines("a\u{b}b"), vec!["a", "b"]);
        assert_eq!(py_splitlines("a\u{c}b"), vec!["a", "b"]);
        assert_eq!(py_splitlines("a\u{1c}b"), vec!["a", "b"]);
        assert_eq!(py_splitlines("a\u{1e}b"), vec!["a", "b"]);
        assert_eq!(py_splitlines("a\u{85}b"), vec!["a", "b"]);
        assert_eq!(py_splitlines("a\u{2028}b"), vec!["a", "b"]);
        assert_eq!(py_splitlines("a\u{2029}b"), vec!["a", "b"]);
        // U+001F strips but does not split.
        assert_eq!(py_splitlines("a\u{1f}b"), vec!["a\u{1f}b"]);
        assert_eq!(py_splitlines(""), Vec::<&str>::new());
        assert_eq!(py_splitlines("\n"), vec![""]);
    }

    // --- safe_read_text ---------------------------------------------------

    #[test]
    fn safe_read_text_refuses_a_nul_and_missing_files() {
        let d = TmpDir::new("safe");
        let p = d.write("bin", b"abc\0def");
        assert_eq!(safe_read_text(&p, crate::MAX_CONTENT_BYTES), None);
        assert_eq!(safe_read_text(&d.0.join("absent"), 16), None);
        // A NUL past the 4096-byte window is not seen.
        let mut late = vec![b'a'; 5000];
        late.push(0);
        let p = d.write("late", &late);
        assert!(safe_read_text(&p, crate::MAX_CONTENT_BYTES).is_some());
    }

    #[test]
    fn safe_read_text_truncates_before_decoding() {
        let d = TmpDir::new("trunc");
        let p = d.write("t", b"abcdefgh");
        assert_eq!(safe_read_text(&p, 3).as_deref(), Some("abc"));
        assert_eq!(safe_read_text(&p, 100).as_deref(), Some("abcdefgh"));
    }

    /// `bytes.decode("utf-8", errors="replace")` substitutes one U+FFFD per
    /// maximal subpart, and so does `String::from_utf8_lossy`. The expected
    /// counts here came from the interpreter:
    /// `b"\xf0\x9f\x92".decode("utf-8", "replace")` is one U+FFFD,
    /// `b"\xc0\xaf"` is two, `b"\xed\xa0\x80"` is three.
    #[test]
    fn lossy_decoding_matches_pythons_replace_handler() {
        let d = TmpDir::new("lossy");
        for (bytes, expect_replacements) in [
            (&b"\xf0\x9f\x92"[..], 1usize),
            (&b"\xe1\x80"[..], 1),
            (&b"\xff"[..], 1),
            (&b"\xc0\xaf"[..], 2),
            (&b"\xed\xa0\x80"[..], 3),
            (&b"\xe0\x80\x80"[..], 3),
        ] {
            let p = d.write("x", bytes);
            let text = safe_read_text(&p, crate::MAX_CONTENT_BYTES).expect("read");
            assert_eq!(
                text.chars().filter(|c| *c == '\u{fffd}').count(),
                expect_replacements,
                "bytes {bytes:?}"
            );
        }
        // A four-byte emoji cut by `[:limit]` yields exactly one U+FFFD, which
        // is what `[:4]` then `decode(..., "replace")` gives in Python.
        let p = d.write("emoji", "ab\u{1f600}".as_bytes());
        assert_eq!(safe_read_text(&p, 4).as_deref(), Some("ab\u{fffd}"));
    }

    // --- parse_dotenv -----------------------------------------------------

    /// Every expectation below was produced by running Python's `_LINE_RE`
    /// plus `_unquote` over the same input, not written from belief.
    #[test]
    fn parse_dotenv_matches_the_interpreter() {
        let cases: &[(&str, &[(&str, &str)])] = &[
            ("A=1\nB=2\n", &[("A", "1"), ("B", "2")]),
            // `dict` semantics: first position, last value.
            ("A=1\nB=2\nA=3\n", &[("A", "3"), ("B", "2")]),
            ("  # comment\nA = 1  \n", &[("A", "1")]),
            ("export A=1\n", &[("A", "1")]),
            // The optional group has to be given up here: no `\s+` after
            // `export`, so `export` is itself the name.
            ("export=abc\n", &[("export", "abc")]),
            ("exportA=1\n", &[("exportA", "1")]),
            ("export  export = x\n", &[("export", "x")]),
            ("export 123=x\n", &[]),
            ("export foo bar=x\n", &[]),
            ("A=\"quoted value\"\n", &[("A", "quoted value")]),
            ("A='quoted value'\n", &[("A", "quoted value")]),
            ("A=\"unbalanced\n", &[("A", "\"unbalanced")]),
            ("A=bare # comment\n", &[("A", "bare")]),
            ("A=bare#nospace\n", &[("A", "bare#nospace")]),
            ("A=x\t#tab-hash\n", &[("A", "x\t#tab-hash")]),
            ("A=\"v # not comment\"\n", &[("A", "v # not comment")]),
            ("A=\"\n", &[("A", "\"")]),
            ("A=\"v\" extra\n", &[("A", "\"v\" extra")]),
            ("A=B=C\n", &[("A", "B=C")]),
            ("A=\" spaced \"\n", &[("A", " spaced ")]),
            ("1A=x\n", &[]),
            ("A-B=x\n", &[]),
            ("_A=x\n", &[("_A", "x")]),
            ("no equals here\n", &[]),
            ("#A=1\n", &[]),
            ("a=1\nA=2\n", &[("a", "1"), ("A", "2")]),
            // Unicode whitespace around the `=` and inside the value.
            ("A\u{a0}=\u{a0}1\n", &[("A", "1")]),
            ("A=\u{1f}1\u{1f}\n", &[("A", "1")]),
            // `\v` and U+2028 are line boundaries to `splitlines()`.
            ("A=v1\u{b}B=v2\n", &[("A", "v1"), ("B", "v2")]),
            ("A=v1\u{2028}B=v2\n", &[("A", "v1"), ("B", "v2")]),
        ];
        for (text, want) in cases {
            let got = parse_dotenv(text);
            let want: Vec<(String, String)> = want
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            assert_eq!(got, want, "input {text:?}");
        }
    }

    // --- json_key_names ---------------------------------------------------

    /// Expectations read out of `json.loads`, input by input.
    #[test]
    fn json_validity_matches_json_loads() {
        let object: &[(&str, &[&str])] = &[
            (r#"{"a": 1, "b": 2}"#, &["a", "b"]),
            // Python's `NaN`/`Infinity` extension is on by default.
            (r#"{"a": NaN}"#, &["a"]),
            (r#"{"a": Infinity, "b": -Infinity}"#, &["a", "b"]),
            // A duplicate key keeps its first position and gets no second slot.
            (r#"{"a": 1, "b": 2, "a": 3}"#, &["a", "b"]),
            (r#"{"A": 1}"#, &["A"]),
            (r#"{"😀": 1}"#, &["\u{1f600}"]),
            (r#"{}"#, &[]),
            ("\t\n\r {\"a\":1} \n", &["a"]),
            (r#"{"a":1E+2}"#, &["a"]),
            (r#"{"a":-0.0e10}"#, &["a"]),
            (r#"{"a":"\/"}"#, &["a"]),
            (r#"{"a":"tab\there"}"#, &["a"]),
            (r#"{"nested":{"a":1},"b":2}"#, &["nested", "b"]),
            (r#"{"":1}"#, &[""]),
            (r#"{"\\":1}"#, &["\\"]),
            (r#"{"\"":1}"#, &["\""]),
            (r#"{"a":[{"b":[1,2,{"c":null}]}]}"#, &["a"]),
            (r#"{"a":"\u007f"}"#, &["a"]),
            (r#"{"a":[NaN,Infinity]}"#, &["a"]),
            ("{\"a\":\"\u{7f}\"}", &["a"]),
        ];
        for (text, want) in object {
            let want: Vec<String> = want.iter().map(|s| s.to_string()).collect();
            assert_eq!(json_top_level(text), JsonTop::Object(want), "input {text:?}");
        }

        for text in [
            "[1,2]",
            "\"hello\"",
            "42",
            "null",
            "true",
            "NaN",
            "-Infinity",
            "[]",
        ] {
            assert_eq!(json_top_level(text), JsonTop::NotAnObject, "input {text:?}");
        }

        for text in [
            r#"{"a": 1, "b": 2,}"#,
            r#"{'a': 1}"#,
            r#"{a: 1}"#,
            r#"{"a": nan}"#,
            r#"{"a":Nan}"#,
            r#"{"a":INFINITY}"#,
            r#"{"a":Infinit}"#,
            r#"{"a":+Infinity}"#,
            r#"{"a":-NaN}"#,
            "",
            "   ",
            "\u{c}{\"a\":1}",
            "\u{a0}{\"a\":1}",
            "\u{feff}{\"a\":1}",
            r#"{"a":01}"#,
            r#"{"a":00}"#,
            r#"{"a":1.}"#,
            r#"{"a":.5}"#,
            r#"{"a":1e}"#,
            r#"{"a":1e+}"#,
            r#"{"a":-}"#,
            r#"{"a":+1}"#,
            r#"{"a":[1,]}"#,
            r#"{"a":{"b":}}"#,
            r#"{"a":"x"}{"b":2}"#,
            r#"{"a":"\x41"}"#,
            r#"{"a":"\U0001F600"}"#,
            r#"{"a":"\a"}"#,
            "{\"a\":\"tab\there\"}",
            r#"{"a":1}extra"#,
            r#"{1: 2}"#,
            r#"{"a"}"#,
            r#"{"a":}"#,
            r#"{,}"#,
            r#"{"a":"unterminated}"#,
            r#"{"a":1"#,
            r#"{"a":tRue}"#,
            r#"{"a":truex}"#,
            r#"{"a":1,,"b":2}"#,
            r#"{"\u00":1}"#,
            r#"{"\uZZZZ":1}"#,
            "[1 2]",
            r#"{"a":[}"#,
            r#"{"a":[1"#,
            "{]",
            "[}",
            // ASCII digits only: the C scanner rejects U+0663.
            "{\"a\": 1\u{663}}",
            "{\"a\": \u{663}}",
            "{\"a\":1}\0",
        ] {
            assert_eq!(json_top_level(text), JsonTop::Invalid, "input {text:?}");
        }
    }

    /// A lone surrogate escape: `json.loads` keeps it, a Rust `String` cannot,
    /// so it becomes U+FFFD.
    #[test]
    fn a_lone_surrogate_key_becomes_the_replacement_character() {
        assert_eq!(
            json_top_level(r#"{"\ud800": 1}"#),
            JsonTop::Object(vec!["\u{fffd}".to_string()])
        );
        // The one place the key *count* can differ: Python reports two distinct
        // lone-surrogate keys where these collapse into one.
        assert_eq!(
            json_top_level(r#"{"\ud83d":1,"\ude00":2}"#),
            JsonTop::Object(vec!["\u{fffd}".to_string()])
        );
        // A high surrogate followed by a non-low escape: Python gives
        // '\ud83dA', so two characters, the first unrepresentable here.
        assert_eq!(
            json_top_level(r#"{"\ud83dA":1}"#),
            JsonTop::Object(vec!["\u{fffd}A".to_string()])
        );
    }

    #[test]
    fn json_key_names_reads_the_file_and_gives_up_quietly() {
        let d = TmpDir::new("json");
        let good = d.write("credentials.json", br#"{"client_id":1,"refresh_ref":2}"#);
        assert_eq!(json_key_names(&good), vec!["client_id", "refresh_ref"]);

        let bad = d.write("bad.json", br#"{"client_id":1,}"#);
        assert_eq!(json_key_names(&bad), Vec::<String>::new());

        let arr = d.write("arr.json", b"[1,2,3]");
        assert_eq!(json_key_names(&arr), Vec::<String>::new());

        assert_eq!(json_key_names(&d.0.join("absent.json")), Vec::<String>::new());

        // A NUL in the first 4096 bytes makes the file unreadable, so `[]`
        // even though the JSON around it would have been fine.
        let nul = d.write("nul.json", b"{\"a\":\0}");
        assert_eq!(json_key_names(&nul), Vec::<String>::new());
    }

    /// Deep nesting must not blow the stack — the parser is iterative.
    #[test]
    fn deep_nesting_does_not_recurse() {
        let deep = format!("{}{}", "[".repeat(50_000), "]".repeat(50_000));
        assert_eq!(json_top_level(&deep), JsonTop::NotAnObject);
        let unbalanced = "[".repeat(50_000);
        assert_eq!(json_top_level(&unbalanced), JsonTop::Invalid);
    }

    // --- dotenv_finding ---------------------------------------------------

    #[test]
    fn dotenv_finding_has_three_shapes() {
        let d = TmpDir::new("dotenv");

        // Comment-only: a LEAK file, zero secrets, not importable.
        let empty = d.write("empty.env", b"# nothing here\n\n");
        let f = dotenv_finding(&empty, Scope::Project).expect("finding");
        assert_eq!(f.reason, "dotenv file (no KEY=VALUE entries)");
        assert_eq!(f.secret_count, 0);
        assert!(f.secret_names.is_empty());
        assert!(!f.importable);
        assert_eq!(f.confidence, "certain");

        // Entries present, every value empty: names reported, count zero.
        let blank = d.write("blank.env", b"A=\nB=   \nC=\"\"\n");
        let f = dotenv_finding(&blank, Scope::Project).expect("finding");
        assert_eq!(f.reason, "dotenv file (empty values only)");
        assert_eq!(f.secret_names, vec!["A", "B", "C"]);
        assert_eq!(f.secret_count, 0);
        assert!(!f.importable);

        // The ordinary case: four entries, one of them empty and dropped.
        let mixed = d.write("mixed.env", b"A=one\nEMPTY=\nB=two\nC=three\n");
        let f = dotenv_finding(&mixed, Scope::Project).expect("finding");
        assert_eq!(f.reason, "dotenv file with 3 secret name(s)");
        assert_eq!(f.secret_names, vec!["A", "B", "C"]);
        assert_eq!(f.secret_count, 3);
        assert!(f.importable);
        assert_eq!(f.path, mixed.to_string_lossy());
        assert_eq!(f.scope, Scope::Project);

        assert!(dotenv_finding(&d.0.join("absent.env"), Scope::Project).is_none());
    }

    /// `if v.strip()` uses Python's whitespace, so a U+001F-only value counts
    /// as empty. Rust's `trim` would call it non-empty and flip the shape.
    #[test]
    fn a_separator_only_value_is_empty_to_python() {
        let d = TmpDir::new("sep");
        let p = d.write("sep.env", "A=\u{1f}\n".as_bytes());
        let f = dotenv_finding(&p, Scope::Project).expect("finding");
        assert_eq!(f.reason, "dotenv file (empty values only)");
        assert_eq!(f.secret_count, 0);
        assert!(!f.importable);
    }

    /// `parse_dotenv` does not go through `_safe_read_text`, so a NUL does not
    /// stop it — where a `.json` of the same bytes would be refused outright.
    #[test]
    fn a_nul_does_not_stop_the_dotenv_read() {
        let d = TmpDir::new("nul");
        let p = d.write("nul.env", b"A=one\0two\nB=three\n");
        let f = dotenv_finding(&p, Scope::Project).expect("finding");
        assert_eq!(f.secret_names, vec!["A", "B"]);
        assert!(f.importable);
        // And the contrast, on the very same bytes.
        assert_eq!(safe_read_text(&p, crate::MAX_CONTENT_BYTES), None);
    }

    // --- inline_findings --------------------------------------------------

    #[test]
    fn inline_findings_split_by_tier() {
        let p = Path::new("/tmp/example.py");
        let text = format!("API_KEY = \"{}\"\n", likely_value());
        let out = inline_findings(
            p,
            &text,
            Scope::Project,
            "inline",
            "assignment pattern matching secret-guard vocabulary",
            "possible identifier- or passphrase-shaped assignment",
        );
        assert_eq!(out.len(), 1, "one likely finding, no prefix, no possible");
        assert_eq!(out[0].confidence, "likely");
        assert_eq!(out[0].secret_names, vec!["API_KEY"]);
        assert_eq!(out[0].secret_count, 1);
        assert_eq!(
            out[0].reason,
            "assignment pattern matching secret-guard vocabulary"
        );
        assert_eq!(out[0].kind, "inline");
        assert_eq!(out[0].path, "/tmp/example.py");

        // A vendor prefix gives a `certain` finding with no names at all.
        let prefixed = format!("value = {}", ["sk-ant-", "aaaabbbbccccddddeeee"].concat());
        let out = inline_findings(p, &prefixed, Scope::Project, "inline", "high", "possible");
        assert_eq!(out[0].confidence, "certain");
        assert_eq!(out[0].secret_count, 1);
        assert!(out[0].secret_names.is_empty());
        assert_eq!(
            out[0].reason,
            "inline credential-shaped token (Anthropic-style key)"
        );

        assert!(inline_findings(p, "x = 1\n", Scope::Project, "inline", "h", "p").is_empty());
    }

    /// A Bearer with no named assignment gets its own reason, not the
    /// caller's — the one place `high_reason` is overridden.
    #[test]
    fn a_bare_bearer_overrides_the_high_reason() {
        let text = format!("Bearer {}", likely_value());
        let out = inline_findings(
            Path::new("/tmp/h"),
            &text,
            Scope::Project,
            "inline",
            "the caller's high reason",
            "the caller's possible reason",
        );
        let likely = out
            .iter()
            .find(|f| f.confidence == "likely")
            .expect("a likely finding");
        assert!(likely.secret_names.is_empty(), "no named assignment");
        assert_eq!(likely.reason, "inline credential-shaped token (Bearer token)");
        assert_eq!(likely.secret_count, 1);
    }

    // --- the git_config matchers ------------------------------------------

    /// Verdicts taken from running the Python patterns over the same inputs;
    /// `kw` is the keyword pattern and `url` the URL one.
    #[test]
    fn git_config_matchers_agree_with_the_interpreter() {
        for (text, kw, url) in [
            ("[user]\n\tname = x\n", false, false),
            ("token=x", true, false),
            ("TOKEN =x", true, false),
            ("Password\t= y", true, false),
            ("authorization  =z", true, false),
            ("_authToken=q", true, false),
            ("mytokenizer=1", false, false),
            ("token\u{1c}=x", true, false),
            ("token\u{a0}=x", true, false),
            ("token", false, false),
            ("url = https://example.com/x", false, false),
            ("https://u:p@h/", false, true),
            ("http://u:p@h", false, true),
            ("https://u@h", false, false),
            ("https://:p@h", false, false),
            ("https://u:p/x@h", false, false),
            ("https://u: p@h", false, false),
            ("https://a:b:c@h", false, true),
            ("https://u:p@", false, true),
            ("ftp://u:p@h", false, false),
            ("xhttps://u:p@h", false, true),
            ("no credentials at all", false, false),
        ] {
            assert_eq!(
                git_config_keyword_assign(text),
                kw,
                "keyword pattern on {text:?}"
            );
            assert_eq!(
                git_config_url_credentials(text),
                url,
                "url pattern on {text:?}"
            );
            // Why the inner branch of the Python condition is unreachable:
            // whenever the URL pattern fires, `"://"` is already present.
            if url {
                assert!(text.contains("://"));
            }
        }
    }

    // --- findings_for_path ------------------------------------------------

    #[test]
    fn findings_for_path_dispatches_on_filename() {
        let d = TmpDir::new("dispatch");

        let env = d.write(".env", b"A=one\nB=two\n");
        let out = findings_for_path(&env, Scope::Project);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, "dotenv");
        assert_eq!(out[0].secret_count, 2);

        let key = d.write("id_rsa", b"-----BEGIN OPENSSH PRIVATE KEY-----\n");
        let out = findings_for_path(&key, Scope::Project);
        assert_eq!(out[0].kind, "ssh_private_key");
        assert_eq!(out[0].reason, "SSH private key file");
        assert_eq!(out[0].secret_count, 1);
        assert!(out[0].secret_names.is_empty());
        assert_eq!(out[0].confidence, "certain");

        let npmrc = d.write(".npmrc", b"registry=https://registry.npmjs.org/\n");
        let out = findings_for_path(&npmrc, Scope::Project);
        assert_eq!(out[0].reason, ".npmrc (may contain registry auth tokens)");

        let creds = d.write("credentials.json", br#"{"client_id":1,"secret_ref":2}"#);
        let out = findings_for_path(&creds, Scope::Project);
        assert_eq!(out[0].reason, "credentials.json (2 top-level key name(s))");
        assert_eq!(out[0].secret_names, vec!["client_id", "secret_ref"]);
        assert_eq!(out[0].secret_count, 2);

        // A file with no interesting name and no interesting content.
        let plain = d.write("notes.md", b"nothing to see\n");
        assert!(findings_for_path(&plain, Scope::Project).is_empty());

        // A suffix that is never content-scanned is not even read: this same
        // text would fire as `inline` under a `.sh` name.
        let png_text = format!("PASSWORD={}\n", likely_value());
        let png = d.write("logo.png", png_text.as_bytes());
        assert!(findings_for_path(&png, Scope::Project).is_empty());
        let sh = d.write("deploy.sh", png_text.as_bytes());
        assert_eq!(findings_for_path(&sh, Scope::Project).len(), 1);
    }

    /// Unparseable JSON: `max(len(names), 1)` keeps the count at one while the
    /// name list stays empty.
    #[test]
    fn a_broken_credentials_json_still_counts_one() {
        let d = TmpDir::new("broken");
        let broken = d.write("credentials.json", b"not json");
        let out = findings_for_path(&broken, Scope::Project);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].reason, "credentials.json (1 top-level key name(s))");
        assert_eq!(out[0].secret_count, 1);
        assert!(out[0].secret_names.is_empty());
    }

    #[test]
    fn mcp_config_is_confirmed_by_its_top_level_keys() {
        let d = TmpDir::new("mcp");
        let confirmed = d.write("mcp.json", br#"{"mcpServers":{},"other":1}"#);
        let out = findings_for_path(&confirmed, Scope::Project);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].confidence, "certain");
        assert_eq!(out[0].reason, "MCP config (2 top-level key name(s))");
        assert_eq!(out[0].secret_count, 2);
        assert!(out[0].reasons.is_empty());

        let d2 = TmpDir::new("mcp2");
        let unconfirmed = d2.write("mcp.json", br#"{"somethingElse":{},"more":2}"#);
        let out = findings_for_path(&unconfirmed, Scope::Project);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].confidence, "possible");
        assert_eq!(
            out[0].reason,
            "unconfirmed MCP config shape (no top-level mcpServers/servers)"
        );
        // One per file, not per key, even though two names are reported.
        assert_eq!(out[0].secret_count, 1);
        assert_eq!(out[0].secret_names, vec!["somethingElse", "more"]);
        assert_eq!(out[0].reasons, vec![REASON_UNCONFIRMED_MCP]);
        assert_eq!(
            out[0].reason_counts,
            vec![(REASON_UNCONFIRMED_MCP.to_string(), 1)]
        );
    }

    #[test]
    fn git_config_is_dropped_unless_it_could_embed_credentials() {
        let d = TmpDir::new("git");
        let dull = d.write(".gitconfig", b"[user]\n\tname = Someone\n\temail = a@b.c\n");
        assert!(findings_for_path(&dull, Scope::Project).is_empty());

        let d2 = TmpDir::new("git2");
        let with_url = d2.write(".gitconfig", b"[remote \"o\"]\n\turl = https://h/r.git\n");
        let out = findings_for_path(&with_url, Scope::Project);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, "git_config");
        assert_eq!(out[0].reason, "git config may embed credentials");
        assert_eq!(out[0].secret_count, 1);

        let d3 = TmpDir::new("git3");
        let with_kw = d3.write(".gitconfig", b"[http]\n\tauthorization = something\n");
        assert_eq!(findings_for_path(&with_kw, Scope::Project).len(), 1);
    }

    #[test]
    fn an_empty_or_unreadable_shell_history_yields_nothing() {
        let d = TmpDir::new("hist");
        let empty = d.write(".bash_history", b"");
        assert!(findings_for_path(&empty, Scope::Project).is_empty());

        let d2 = TmpDir::new("hist2");
        let binary = d2.write(".bash_history", b"ls\0\n");
        assert!(findings_for_path(&binary, Scope::Project).is_empty());

        let d3 = TmpDir::new("hist3");
        let real = d3.write(
            ".bash_history",
            format!("export API_KEY={}\nls -la\n", likely_value()).as_bytes(),
        );
        let out = findings_for_path(&real, Scope::Project);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, "shell_history");
        assert_eq!(out[0].reason, "shell history with credential-shaped content");
        assert_eq!(out[0].secret_names, vec!["API_KEY"]);
    }

    #[test]
    fn scan_text_for_leaks_is_empty_for_empty_text() {
        assert_eq!(scan_text_for_leaks(""), (Vec::new(), None));
        let (names, prefix) = scan_text_for_leaks(&format!("API_KEY={}", likely_value()));
        assert_eq!(names, vec!["API_KEY"]);
        assert_eq!(prefix, None);
    }
}
