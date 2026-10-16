//! The values Vahta holds, in the forms an agent might write them in.
//!
//! A tool call or an output that carries a held value as plain text is easy
//! to catch. One that carries it base64-encoded, in hex, URL-encoded or
//! reversed is the same leak in a coat, and an agent that is prompt-injected
//! (or just clever) will try it. So for every value of at least
//! [`MIN_EXACT`] bytes the daemon keeps these forms, and looks for all of
//! them:
//!
//! * **raw**;
//! * **base64**, standard and URL-safe alphabets, at the three byte offsets a
//!   value can sit at inside a longer encoded text. The pattern is each
//!   form's *stable core*: the characters that depend on the value's bytes
//!   alone and not on the bytes before or after it. That core is a substring
//!   of the padded and the unpadded encoding alike, so one pattern finds
//!   both. Where the value ends in the middle of a character, the longer
//!   patterns that include it (and the padding) are kept too, so a redaction
//!   covers a value encoded by itself to its last character;
//! * **hex**, lower and upper case;
//! * **URL-encoded** (percent-encoding, upper and lower case);
//! * **reversed** bytes;
//! * **JSON-escaped**, for a value with a quote, a backslash, a control
//!   character (a newline, a tab) or the like in it: a program that prints
//!   JSON writes `\"`, `\\`, `\n`, and the harness that reads it decodes it
//!   back to the value. The common spellings are kept: `\n` or `\u000a`,
//!   `\u00xx` in lower or upper case, `/` plain or as `\/`, non-ASCII as
//!   `\uXXXX`, `<`, `>`, `&` as `<`, and the plain spelling escaped a
//!   second time (JSON inside a JSON string).
//!
//! Forms that come out identical (a value with no `+` or `/` encodes the same
//! in both base64 alphabets) are kept once.
//!
//! Two forms are not precomputed but undone in the text that is checked
//! ([`EncodedSet::find_text`]): **percent-encoding** of any bytes, in any mix
//! of upper and lower case (`%41%42`, with some characters left plain), is
//! decoded once and the raw values are looked for in what comes out; and
//! **joined literals** (`'ab''cd'`, `"ab" + "cd"`) are folded by the
//! detector's own pass ([`vahta_detect::evasion::folded_windows`]) and the
//! raw values looked for in those. Both are bounded by the text itself.
//!
//! **Sensitivity.** The cache is exactly as sensitive as the keys a session
//! already holds: with it, anyone who can read the daemon's memory has every
//! value of the session. So it is built when the session is opened (or a run
//! given its values), kept in [`Zeroizing`] buffers, never written anywhere,
//! and dropped (and overwritten) with the session or the run. The search
//! automaton is built from the forms on first use and dropped with them; its
//! tables cannot be overwritten, because the library owns them, so they stay
//! in freed memory until reused. The process is not dumpable and its memory
//! locked (see `harden_process`).

use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, MatchKind};
use zeroize::Zeroizing;

use crate::output::MIN_EXACT;

/// How a value was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    Raw,
    Base64,
    Hex,
    UrlEncoded,
    Reversed,
    /// As the inside of a JSON string (`\"`, `\\`, `\n`, `\u00XX`).
    JsonEscaped,
    /// Pieces of the value in adjacent or added string literals.
    Concat,
}

impl Form {
    /// What the agent and the person are told.
    pub fn as_str(self) -> &'static str {
        match self {
            Form::Raw => "raw",
            Form::Base64 => "base64",
            Form::Hex => "hex",
            Form::UrlEncoded => "URL-encoded",
            Form::Reversed => "reversed",
            Form::JsonEscaped => "JSON-escaped",
            Form::Concat => "concatenation",
        }
    }
}

struct Entry {
    name: String,
    form: Form,
    bytes: Zeroizing<Vec<u8>>,
}

/// The forms of a session's (or a run's) values.
#[derive(Default)]
pub struct EncodedSet {
    entries: Vec<Entry>,
    /// Built on first search.
    matcher: OnceLock<Option<AhoCorasick>>,
}

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The base64 characters of `bytes` (no padding) in `alphabet`.
fn b64_unpadded(bytes: &[u8], alphabet: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(alphabet[(n >> (18 - 6 * i)) as usize & 63]);
        }
    }
    out
}

/// The base64 patterns for `value` sitting at byte offset `offset` (0, 1 or
/// 2) inside a longer text: first its stable core, the characters decided by
/// the value's bytes alone. Then, when the value ends in the middle of a
/// character, the core with that last character, and with the padding too:
/// they match only where the value is the end of the encoded text, and
/// make an output redaction cover the whole of a value encoded by itself
/// rather than leave its last six bits behind.
fn b64_patterns(value: &[u8], offset: usize, alphabet: &[u8; 64]) -> Vec<Vec<u8>> {
    let mut padded = vec![0u8; offset];
    padded.extend_from_slice(value);
    let all = b64_unpadded(&padded, alphabet);
    let bits = 8 * padded.len();
    // The first character wholly inside the value's bits, and the last.
    let start = (8 * offset).div_ceil(6);
    let end = bits / 6;
    let Some(core) = all.get(start..end) else {
        return Vec::new();
    };
    let mut out = vec![core.to_vec()];
    if end < all.len() {
        out.push(all[start..].to_vec());
        let mut with_padding = all[start..].to_vec();
        while !(with_padding.len() + start).is_multiple_of(4) {
            with_padding.push(b'=');
        }
        out.push(with_padding);
    }
    out
}

fn hex(bytes: &[u8], upper: bool) -> Vec<u8> {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(digits[usize::from(b >> 4)]);
        out.push(digits[usize::from(b & 15)]);
    }
    out
}

fn percent(bytes: &[u8], upper: bool) -> Vec<u8> {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = Vec::with_capacity(bytes.len() * 3);
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(digits[usize::from(b >> 4)]);
            out.push(digits[usize::from(b & 15)]);
        }
    }
    out
}

/// Every byte of `bytes` as `%XX`.
fn percent_all(bytes: &[u8], upper: bool) -> Vec<u8> {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = Vec::with_capacity(bytes.len() * 3);
    for &b in bytes {
        out.push(b'%');
        out.push(digits[usize::from(b >> 4)]);
        out.push(digits[usize::from(b & 15)]);
    }
    out
}

/// How a JSON encoder spells its output; each field is a choice real
/// encoders make differently.
#[derive(Clone, Copy, Default)]
struct JsonStyle {
    /// `/` as `\/`.
    slash: bool,
    /// `\n`, `\r`, `\t`, `\b`, `\f` as `\u000a` and the like.
    long_ctl: bool,
    /// `\"` and `\\` as `\u0022` and `\u005c`.
    long_quote: bool,
    /// Hex digits of `\u` escapes in upper case.
    upper: bool,
    /// Everything outside ASCII as `\uXXXX` (a surrogate pair above U+FFFF).
    ascii: bool,
    /// `<`, `>`, `&` and U+2028/2029 as `\u` escapes.
    html: bool,
}

/// `value` as the inside of a JSON string, or `None` when that is `value`
/// itself.
fn json_escaped(value: &[u8], style: JsonStyle) -> Option<Vec<u8>> {
    let digits: &[u8; 16] = if style.upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let unit = |out: &mut Vec<u8>, u: u16| {
        out.extend_from_slice(b"\\u");
        for shift in [12, 8, 4, 0] {
            out.push(digits[usize::from((u >> shift) & 15)]);
        }
    };
    let mut out = Vec::with_capacity(value.len() + 8);
    // Bytes that are not UTF-8 pass as they are; they have no escape.
    let chars: Vec<Result<char, u8>> = match std::str::from_utf8(value) {
        Ok(t) => t.chars().map(Ok).collect(),
        Err(_) => value
            .iter()
            .map(|&b| if b < 0x80 { Ok(char::from(b)) } else { Err(b) })
            .collect(),
    };
    for c in chars {
        let c = match c {
            Ok(c) => c,
            Err(b) => {
                out.push(b);
                continue;
            }
        };
        let (short, long) = match c {
            '"' => (Some(b'"'), style.long_quote),
            '\\' => (Some(b'\\'), style.long_quote),
            '\n' => (Some(b'n'), style.long_ctl),
            '\r' => (Some(b'r'), style.long_ctl),
            '\t' => (Some(b't'), style.long_ctl),
            '\u{8}' => (Some(b'b'), style.long_ctl),
            '\u{c}' => (Some(b'f'), style.long_ctl),
            _ => (None, false),
        };
        match (c, short) {
            (_, Some(s)) if !long => out.extend_from_slice(&[b'\\', s]),
            (_, Some(_)) => unit(&mut out, c as u16),
            ('/', _) if style.slash => out.extend_from_slice(b"\\/"),
            ('<' | '>' | '&' | '\u{2028}' | '\u{2029}', _) if style.html => {
                unit(&mut out, c as u16)
            }
            (c, _) if c < ' ' => unit(&mut out, c as u16),
            (c, _) if style.ascii && !c.is_ascii() => {
                let mut pair = [0u16; 2];
                for &u in c.encode_utf16(&mut pair).iter() {
                    unit(&mut out, u);
                }
            }
            (c, _) => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    (out != value).then_some(out)
}

/// The JSON spellings of `value` that differ from it, each once.
fn json_forms(value: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for bits in 0..64u8 {
        let style = JsonStyle {
            slash: bits & 1 != 0,
            long_ctl: bits & 2 != 0,
            long_quote: bits & 4 != 0,
            upper: bits & 8 != 0,
            ascii: bits & 16 != 0,
            html: bits & 32 != 0,
        };
        if let Some(e) = json_escaped(value, style)
            && !out.contains(&e)
        {
            out.push(e);
        }
    }
    // JSON inside a JSON string: the usual spelling, escaped again.
    if let Some(once) = json_escaped(value, JsonStyle::default())
        && let Some(twice) = json_escaped(&once, JsonStyle::default())
        && !out.contains(&twice)
    {
        out.push(twice);
    }
    out
}

/// `text` with each `%XX` run decoded, or `None` when it has none. Never
/// longer than `text`.
fn percent_decoded(text: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let hexval = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = Zeroizing::new(Vec::with_capacity(text.len()));
    let mut any = false;
    let mut i = 0;
    while i < text.len() {
        if text[i] == b'%'
            && let (Some(h), Some(l)) = (
                text.get(i + 1).copied().and_then(hexval),
                text.get(i + 2).copied().and_then(hexval),
            )
        {
            out.push(h << 4 | l);
            any = true;
            i += 3;
            continue;
        }
        out.push(text[i]);
        i += 1;
    }
    any.then_some(out)
}

/// Every form of `value`, each at least [`MIN_EXACT`] bytes, none twice.
fn forms_of(value: &[u8]) -> Vec<(Form, Zeroizing<Vec<u8>>)> {
    let mut out: Vec<(Form, Zeroizing<Vec<u8>>)> = Vec::new();
    let mut add = |form: Form, bytes: Vec<u8>| {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() >= MIN_EXACT && !out.iter().any(|(_, b)| **b == *bytes) {
            out.push((form, bytes));
        }
    };
    add(Form::Raw, value.to_vec());
    for alphabet in [STD, URL] {
        for offset in 0..3 {
            for pattern in b64_patterns(value, offset, alphabet) {
                add(Form::Base64, pattern);
            }
        }
    }
    add(Form::Hex, hex(value, false));
    add(Form::Hex, hex(value, true));
    add(Form::UrlEncoded, percent(value, true));
    add(Form::UrlEncoded, percent(value, false));
    // Every byte encoded, which an output redaction needs as a pattern;
    // `find_text` reaches it in a tool call by decoding.
    add(Form::UrlEncoded, percent_all(value, true));
    add(Form::UrlEncoded, percent_all(value, false));
    add(Form::Reversed, value.iter().rev().copied().collect());
    for pattern in json_forms(value) {
        add(Form::JsonEscaped, pattern);
    }
    out
}

impl EncodedSet {
    /// The forms of `values`, as `(name, bytes)`. A value shorter than
    /// [`MIN_EXACT`] has none: it would match ordinary words.
    pub fn build<'a>(values: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> EncodedSet {
        let mut entries = Vec::new();
        for (name, value) in values {
            if value.len() < MIN_EXACT {
                continue;
            }
            for (form, bytes) in forms_of(value) {
                entries.push(Entry {
                    name: name.to_string(),
                    form,
                    bytes,
                });
            }
        }
        EncodedSet {
            entries,
            matcher: OnceLock::new(),
        }
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The forms of the values named in `names` only, for a delegated
    /// session that narrows its parent's.
    pub fn subset(&self, names: &[String]) -> EncodedSet {
        EncodedSet {
            entries: self
                .entries
                .iter()
                .filter(|e| names.contains(&e.name))
                .map(|e| Entry {
                    name: e.name.clone(),
                    form: e.form,
                    bytes: e.bytes.clone(),
                })
                .collect(),
            matcher: OnceLock::new(),
        }
    }

    /// The first (leftmost, then longest) held value in `text`, in any
    /// form: its name and how it was written.
    pub fn find(&self, text: &[u8]) -> Option<(&str, Form)> {
        let matcher = self
            .matcher
            .get_or_init(|| {
                if self.entries.is_empty() {
                    return None;
                }
                AhoCorasick::builder()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(self.entries.iter().map(|e| &e.bytes[..]))
                    .ok()
            })
            .as_ref()?;
        let m = matcher.find(text)?;
        let e = &self.entries[m.pattern().as_usize()];
        Some((&e.name, e.form))
    }

    /// [`find`](Self::find) in the text of a tool call: as it is, then with
    /// its `%XX` runs decoded (a raw value found there was URL-encoded), then
    /// with its joined string literals folded (it was concatenated).
    pub fn find_text(&self, text: &str) -> Option<(&str, Form)> {
        if self.entries.is_empty() {
            return None;
        }
        if let Some(hit) = self.find(text.as_bytes()) {
            return Some(hit);
        }
        if let Some(decoded) = percent_decoded(text.as_bytes())
            && let Some((name, form)) = self.find(&decoded)
        {
            return Some((
                name,
                if form == Form::Raw {
                    Form::UrlEncoded
                } else {
                    form
                },
            ));
        }
        for window in vahta_detect::evasion::folded_windows(text) {
            if let Some((name, form)) = self.find(window.as_bytes()) {
                return Some((
                    name,
                    if form == Form::Raw {
                        Form::Concat
                    } else {
                        form
                    },
                ));
            }
        }
        None
    }

    /// Everything to look for in an output, as the scrubber takes it: the raw
    /// value under its name and each other form under `NAME (form)`.
    pub fn targets(&self) -> Vec<(String, Vec<u8>)> {
        self.targets_where(|_| true)
    }

    /// The same without the raw values, for a caller that has them already.
    pub fn encoded_targets(&self) -> Vec<(String, Vec<u8>)> {
        self.targets_where(|f| f != Form::Raw)
    }

    fn targets_where(&self, keep: impl Fn(Form) -> bool) -> Vec<(String, Vec<u8>)> {
        self.entries
            .iter()
            .filter(|e| keep(e.form))
            .map(|e| {
                let label = match e.form {
                    Form::Raw => e.name.clone(),
                    other => format!("{} ({})", e.name, other.as_str()),
                };
                (label, e.bytes.to_vec())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALUE: &[u8] = b"fake-one-value!";

    fn one(value: &'static [u8]) -> EncodedSet {
        EncodedSet::build([("NAME", value)])
    }

    fn std_b64(bytes: &[u8]) -> String {
        let mut s = String::from_utf8(b64_unpadded(bytes, STD)).unwrap();
        while !s.len().is_multiple_of(4) {
            s.push('=');
        }
        s
    }

    #[test]
    fn base64_at_every_offset_is_found_padded_or_not() {
        let set = one(VALUE);
        for prefix in ["", "x", "xy", "xyz", "wxyz1"] {
            for suffix in ["", "q", "qr", "qrs"] {
                let mut text = prefix.as_bytes().to_vec();
                text.extend_from_slice(VALUE);
                text.extend_from_slice(suffix.as_bytes());
                let padded = std_b64(&text);
                for t in [padded.clone(), padded.trim_end_matches('=').to_string()] {
                    let hit = set.find(t.as_bytes());
                    assert_eq!(
                        hit,
                        Some(("NAME", Form::Base64)),
                        "{prefix:?} {suffix:?} {t}"
                    );
                }
            }
        }
    }

    #[test]
    fn url_safe_base64_hex_percent_and_reversed() {
        let value: &'static [u8] = b"fake>>one???value~";
        let set = one(value);
        let url = String::from_utf8(b64_unpadded(value, URL)).unwrap();
        assert!(url.contains('-') || url.contains('_'));
        assert_eq!(set.find(url.as_bytes()).unwrap().1, Form::Base64);
        let hx = String::from_utf8(hex(value, true)).unwrap();
        assert_eq!(set.find(hx.as_bytes()).unwrap().1, Form::Hex);
        let hx = String::from_utf8(hex(value, false)).unwrap();
        assert_eq!(set.find(hx.as_bytes()).unwrap().1, Form::Hex);
        assert_eq!(
            set.find(b"https://x/?q=fake%3E%3Eone%3F%3F%3Fvalue~")
                .unwrap()
                .1,
            Form::UrlEncoded
        );
        let rev: Vec<u8> = value.iter().rev().copied().collect();
        assert_eq!(set.find(&rev).unwrap().1, Form::Reversed);
        assert_eq!(set.find(value).unwrap().1, Form::Raw);
    }

    #[test]
    fn a_fully_percent_encoded_value_is_found_in_either_case_and_in_a_sentence() {
        let set = one(b"fake-one-value!");
        let enc = |upper: bool| String::from_utf8(percent_all(b"fake-one-value!", upper)).unwrap();
        for e in [enc(true), enc(false)] {
            for text in [
                e.clone(),
                format!("the token is {e}, ok"),
                format!("http://h/?k={e}&x=1"),
            ] {
                assert_eq!(
                    set.find_text(&text),
                    Some(("NAME", Form::UrlEncoded)),
                    "{text}"
                );
            }
        }
        // Mixed case and a partial mix of plain and encoded characters.
        assert_eq!(
            set.find_text("%66%41ke-one%2dvalue%21").map(|h| h.1),
            None,
            "a changed letter is another value"
        );
        assert_eq!(
            set.find_text("%66ake%2done-%76alue%21").map(|h| h.1),
            Some(Form::UrlEncoded)
        );
        // Not a hit: a lone percent, an invalid escape, a decoded text without it.
        assert!(set.find_text("100% sure %zz %4").is_none());
        assert!(set.find_text("%68%65%6c%6c%6f").is_none());
    }

    #[test]
    fn a_value_cut_by_quotes_is_found_by_the_folded_text() {
        let set = one(b"fake-one-value!");
        for text in [
            "echo 'fake-on''e-value!'",
            "echo \"fake-\"'one-value!'",
            "echo 'fake-one'\"-value!\"",
            "k = \"fake-one\" + \"-value!\"",
            "python -c \"k = 'fake-' + 'one-value!'\"",
        ] {
            assert_eq!(set.find_text(text), Some(("NAME", Form::Concat)), "{text}");
        }
        assert!(set.find_text("echo 'fake-' 'other'").is_none());
    }

    #[test]
    fn short_values_and_other_text_have_nothing() {
        assert!(one(b"short").is_empty());
        let set = one(VALUE);
        assert!(set.find(b"echo hello world, nothing to see").is_none());
        assert!(set.find(b"").is_none());
        assert!(EncodedSet::default().find(b"anything").is_none());
    }

    #[test]
    fn identical_forms_are_kept_once_and_labelled() {
        let set = one(b"abcdefgh");
        // Plain letters: the standard percent-encoding and the URL-safe
        // alphabet add nothing the raw value and standard base64 lack (the
        // every-byte percent-encoding does).
        let labels: Vec<String> = set.targets().into_iter().map(|(l, _)| l).collect();
        assert_eq!(labels[0], "NAME");
        assert!(labels.contains(&"NAME (base64)".to_string()));
        let plain = String::from_utf8(percent(b"abcdefgh", true)).unwrap();
        assert!(
            !set.targets()
                .iter()
                .any(|(l, b)| l.contains("URL") && b == plain.as_bytes())
        );
        let mut seen = set.targets();
        seen.sort_by(|a, b| a.1.cmp(&b.1));
        seen.dedup_by(|a, b| a.1 == b.1);
        assert_eq!(seen.len(), set.targets().len());
    }

    #[test]
    fn a_subset_keeps_only_its_names() {
        let set = EncodedSet::build([("A", &b"fake-aaaa-aaaa"[..]), ("B", &b"fake-bbbb-bbbb"[..])]);
        let sub = set.subset(&["B".to_string()]);
        assert_eq!(sub.find(b"fake-bbbb-bbbb").map(|h| h.0), Some("B"));
        assert!(sub.find(b"fake-aaaa-aaaa").is_none());
    }

    fn json_hit(set: &EncodedSet, text: &str) -> bool {
        set.find(text.as_bytes()) == Some(("NAME", Form::JsonEscaped))
    }

    #[test]
    fn a_json_escaped_value_is_found_in_every_common_spelling() {
        let set = one(b"ab\"cd\\ef\r\n\tgh/ij");
        for text in [
            r#"{"t":"ab\"cd\\ef\r\n\tgh/ij"}"#,
            r#"{"t":"ab\"cd\\ef\r\n\tgh\/ij"}"#,
            r#"{"t":"ab\"cd\\ef\u000d\u000a\u0009gh/ij"}"#,
            r#"{"t":"ab\"cd\\ef\u000D\u000A\u0009gh\/ij"}"#,
            r#"{"t":"ab\u0022cd\u005cef\u000d\u000a\u0009gh/ij"}"#,
            // Inside a JSON string that is itself in JSON.
            r#"{"t":"{\"x\":\"ab\\\"cd\\\\ef\\r\\n\\tgh/ij\"}"}"#,
        ] {
            assert!(json_hit(&set, text), "{text}");
        }
        // Not the decoded value, and not a different escape.
        assert_eq!(set.find(b"ab\"cd\\ef\r\n\tgh/ij").unwrap().1, Form::Raw);
        assert!(set.find(br#"ab\"cd\\ef\r\n\tgh/ik"#).is_none());
    }

    #[test]
    fn json_escapes_of_non_ascii_and_markup_characters() {
        let set = one("a<b>&caf\u{e9}\u{1f600}x\"".as_bytes());
        for text in [
            r#"a<b>&caf\u00e9\ud83d\ude00x\""#,
            r#"a\u003cb\u003e\u0026caf\u00e9\ud83d\ude00x\""#,
            r#"a\u003Cb\u003E\u0026caf\u00E9\uD83D\uDE00x\""#,
            "a<b>&caf\u{e9}\u{1f600}x\\\"",
        ] {
            assert!(json_hit(&set, text), "{text}");
        }
    }

    #[test]
    fn a_value_with_no_json_escapes_has_no_json_form() {
        let set = one(VALUE);
        assert!(
            set.targets().iter().all(|(l, _)| !l.contains("JSON")),
            "{:?}",
            set.targets()
        );
        // A value that is not UTF-8 still gets the escapes it has.
        let set = one(b"ab\"\xff\xfecdefgh");
        let mut text = b"x ab\\\"".to_vec();
        text.extend_from_slice(b"\xff\xfecdefgh y");
        assert_eq!(set.find(&text), Some(("NAME", Form::JsonEscaped)));
    }
}
