//! A secret hidden from a plain look at the text: base64 or hex of it, or
//! pieces of it joined by the shell or the language.
//!
//! This runs only when nothing else hit. Each form is undone once (depth 1)
//! and the result is scanned as ordinary text by the caller's `scan`. A hit
//! here is always a block, whatever the rule says, and is at least Likely:
//! encoding a credential-shaped value is itself the sign.
//!
//! Every pass is bounded by the constants below, so the cost does not grow with
//! the text: a megabyte of base64 is 16 runs of at most [`MAX_DECODED_BYTES`].
//!
//! Never returns or logs values.

use crate::finding::Evasion;

/// Base64 or base64url runs shorter than this are not decoded.
pub const MIN_BASE64_RUN: usize = 24;
/// Hex runs shorter than this are not decoded (a SHA-1 is 40 and not text).
pub const MIN_HEX_RUN: usize = 40;
/// At most this many base64 runs (the longest) and as many hex runs are decoded.
pub const MAX_DECODED_RUNS: usize = 16;
/// A run is decoded to at most this many bytes.
pub const MAX_DECODED_BYTES: usize = 64 * 1024;
/// A decoded run must be this share printable text, or it is binary.
const PRINTABLE_SHARE: f64 = 0.9;
/// At most this many literal chains are folded.
pub const MAX_CHAINS: usize = 64;
/// A literal longer than this, or over more than one line, is not part of a
/// chain: a stray apostrophe in prose or a lifetime in Rust pairs with the next
/// one far away, and that is not a value cut in two.
pub const MAX_PIECE_BYTES: usize = 256;
/// A folded chain is scanned with this much text before it ...
const CONTEXT_BEFORE: usize = 160;
/// ... and this much after.
const CONTEXT_AFTER: usize = 32;

/// Undo each form in turn and ask `scan` about what comes out.
pub fn find<T>(text: &str, scan: &dyn Fn(&str) -> Option<T>) -> Option<(T, Evasion)> {
    if text.len() < MIN_BASE64_RUN {
        return None;
    }
    for decoded in base64_runs(text) {
        if let Some(found) = scan(&decoded) {
            return Some((found, Evasion::Base64));
        }
    }
    for decoded in hex_runs(text) {
        if let Some(found) = scan(&decoded) {
            return Some((found, Evasion::Hex));
        }
    }
    for (folded, plain) in concat_windows(text) {
        // A window cut out of the text can hit on its own context; only what
        // the joining adds counts.
        if scan(&plain).is_none()
            && let Some(found) = scan(&folded)
        {
            return Some((found, Evasion::Concat));
        }
    }
    None
}

// --- base64 and hex ---------------------------------------------------------

fn is_b64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_')
}

/// Runs of `ok` bytes at least `min` long, as byte ranges.
fn runs(text: &str, min: usize, ok: fn(u8) -> bool) -> Vec<(usize, usize)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !ok(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && ok(b[i]) {
            i += 1;
        }
        if i - start >= min {
            out.push((start, i));
        }
    }
    out
}

/// The longest runs, in text order.
fn longest(mut found: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    found.sort_by(|a, b| (b.1 - b.0).cmp(&(a.1 - a.0)).then(a.0.cmp(&b.0)));
    found.truncate(MAX_DECODED_RUNS);
    found.sort_unstable();
    found
}

/// Texts decoded from base64 runs that decode to mostly printable text.
fn base64_runs(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (s, e) in longest(runs(text, MIN_BASE64_RUN, is_b64)) {
        let run = &text.as_bytes()[s..e];
        // A single case or class, or a path, is not an encoder's output.
        let classes = [
            run.iter().any(u8::is_ascii_lowercase),
            run.iter().any(u8::is_ascii_uppercase),
            run.iter().any(u8::is_ascii_digit),
        ];
        if classes.iter().filter(|c| **c).count() < 2 {
            continue;
        }
        if let Some(decoded) = decode_base64(run).and_then(printable) {
            out.push(decoded);
        }
    }
    out
}

/// Texts decoded from hex runs that decode to mostly printable text.
fn hex_runs(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (s, e) in longest(runs(text, MIN_HEX_RUN, |b| b.is_ascii_hexdigit())) {
        let run = &text.as_bytes()[s..e];
        let bytes: Vec<u8> = run
            .as_chunks::<2>()
            .0
            .iter()
            .take(MAX_DECODED_BYTES)
            .filter_map(|p| Some(hex_val(p[0])? << 4 | hex_val(p[1])?))
            .collect();
        if let Some(decoded) = printable(bytes) {
            out.push(decoded);
        }
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Standard and URL-safe alphabets together, padding optional.
fn decode_base64(run: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(run.len() / 4 * 3 + 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in run {
        acc = acc << 6 | u32::from(b64_val(b)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
            if out.len() >= MAX_DECODED_BYTES {
                break;
            }
        }
    }
    Some(out)
}

/// The bytes as text, if they are text and not binary.
fn printable(bytes: Vec<u8>) -> Option<String> {
    if bytes.len() < 8 {
        return None;
    }
    let ok = bytes
        .iter()
        .filter(|b| b.is_ascii_graphic() || matches!(b, b' ' | b'\n' | b'\t' | b'\r'))
        .count();
    if (ok as f64) < PRINTABLE_SHARE * bytes.len() as f64 {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

// --- literal pieces joined ---------------------------------------------------

/// A quoted literal in the text.
struct Piece {
    /// Byte range of the opening quote through the closing one.
    start: usize,
    end: usize,
    /// What is between the quotes, escapes left alone.
    content: String,
}

/// Quoted literals in order, for the quote characters in `quotes`, line by line.
/// A line with an odd number of one of those quote characters (an apostrophe in
/// a comment, a lifetime in Rust) cannot be paired reliably, and a wrong pairing
/// turns the text between two literals into a "literal", so that line is left
/// out.
fn pieces(text: &str, quotes: &[u8]) -> Vec<Piece> {
    let mut out = Vec::new();
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let b = line.as_bytes();
        let balanced = quotes
            .iter()
            .all(|q| b.iter().filter(|c| *c == q).count() % 2 == 0);
        if balanced {
            line_pieces(offset, line, quotes, &mut out);
        }
        offset += line.len();
        if out.len() > 8 * MAX_CHAINS * 8 {
            break;
        }
    }
    out
}

fn line_pieces(offset: usize, line: &str, quotes: &[u8], out: &mut Vec<Piece>) {
    let b = line.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let q = b[i];
        if !quotes.contains(&q) {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < b.len() && b[j] != q {
            if q == b'"' && b[j] == b'\\' {
                j += 1;
            }
            j += 1;
        }
        if j >= b.len() {
            return;
        }
        // A literal too long to be a piece of a secret is not a chain member,
        // but its end is still where the next one starts.
        if j - i <= MAX_PIECE_BYTES
            && let Some(content) = line.get(i + 1..j)
        {
            out.push(Piece {
                start: offset + i,
                end: offset + j + 1,
                content: content.to_string(),
            });
        }
        i = j + 1;
    }
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':' | b'/' | b'@' | b'=' | b'+')
}

/// A bare word at least this long beside a literal is part of the value.
const MIN_STUCK: usize = 3;

/// Length of the run of word characters at the start of `bytes`.
fn bare_run<'a>(bytes: impl Iterator<Item = &'a u8>) -> usize {
    bytes
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'/' | b':' | b'@'))
        .count()
}

/// What to put between two literals that are one value, if `gap` lets them be:
/// nothing for whitespace (adjacent literals, as Python reads them) or for a
/// `+`, `.` or `..` operator; the gap itself for bare word characters
/// (`ab'cd'ef'gh'`).
fn joins(gap: &str) -> Option<&str> {
    if gap.len() > 64 {
        return None;
    }
    let t = gap.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\\');
    if t.is_empty() || matches!(t, "+" | "." | "..") {
        return Some("");
    }
    (gap.bytes().all(is_word_byte)).then_some(gap)
}

/// The text of each chain of joined literals, put back in its context, for a
/// caller that looks for values it knows (the daemon's held values) and not
/// for shapes. At most [`MAX_CHAINS`] per reading of the quotes.
pub fn folded_windows(text: &str) -> Vec<String> {
    concat_windows(text).into_iter().map(|(f, _)| f).collect()
}

/// Each chain of two or more literals, joined and put back in its context.
///
/// Read three ways, because quotes nest in a shell command: both kinds at once
/// (`export K='ab''cd'`), single quotes alone (`python -c "k = 'ab' + 'cd'"`),
/// and double quotes alone (`sh -c 'echo "ab" "cd"'`).
fn concat_windows(text: &str) -> Vec<(String, String)> {
    if text.bytes().filter(|b| *b == b'\'' || *b == b'"').count() < 2 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for quotes in [&b"'\""[..], b"'", b"\""] {
        chains(text, &pieces(text, quotes), &mut out);
    }
    out
}

fn chains(text: &str, all: &[Piece], out: &mut Vec<(String, String)>) {
    let mut i = 0;
    while i < all.len() && out.len() < MAX_CHAINS {
        let mut j = i;
        let mut joined = all[i].content.clone();
        while j + 1 < all.len() {
            let Some(between) = joins(&text[all[j].end..all[j + 1].start]) else {
                break;
            };
            joined.push_str(between);
            joined.push_str(&all[j + 1].content);
            j += 1;
        }
        // A lone literal stuck to a bare word of three or more characters
        // (`K=sk-ant-'api03...'`) is a chain of two as well. One or two
        // letters are a string prefix (`b"..."`, `r'...'`, `f"..."`), not a
        // value cut in two.
        let lone_and_stuck = j == i
            && !all[i].content.contains(char::is_whitespace)
            && (bare_run(text.as_bytes()[..all[i].start].iter().rev()) >= MIN_STUCK
                || bare_run(text.as_bytes()[all[i].end..].iter()) >= MIN_STUCK);
        if j > i || lone_and_stuck {
            let (start, end) = (all[i].start, all[j].end);
            let before = floor_boundary(text, start.saturating_sub(CONTEXT_BEFORE));
            let after = floor_boundary(text, (end + CONTEXT_AFTER).min(text.len()));
            // The words just outside the quotes (`sk-ant-'..'`) are part of
            // the value, and the name before them is its context.
            let mut window = String::with_capacity(joined.len() + CONTEXT_BEFORE + CONTEXT_AFTER);
            window.push_str(&text[before..start]);
            window.push_str(&joined);
            window.push_str(&text[end..after]);
            out.push((window, text[before..after].to_string()));
        }
        i = j + 1;
    }
}

/// The largest char boundary at or below `at`.
fn floor_boundary(text: &str, mut at: usize) -> usize {
    while at > 0 && !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(bytes: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in bytes.chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            for k in 0..4 {
                if k <= c.len() {
                    out.push(A[(n >> (18 - 6 * k) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    #[test]
    fn base64_round_trips_at_every_alignment() {
        for n in 20..40 {
            let text: String = (0..n).map(|i| (b'a' + (i % 26) as u8) as char).collect();
            let enc = b64(text.as_bytes());
            let dec = decode_base64(enc.trim_end_matches('=').as_bytes()).unwrap();
            assert_eq!(dec, text.as_bytes(), "{n}");
        }
    }

    #[test]
    fn binary_is_not_text() {
        assert!(printable(vec![0, 1, 2, 3, 200, 201, 202, 203, 4, 5]).is_none());
        assert!(printable(b"NAME=some visible text".to_vec()).is_some());
    }

    #[test]
    fn a_hash_is_not_decoded_as_text() {
        let sha = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        assert!(hex_runs(sha).is_empty());
    }

    #[test]
    fn literal_chains() {
        let t = "echo 'ab''cd' \"ef\" + \"gh\" x 'ij'.'kl'";
        let w = concat_windows(t);
        assert!(w.iter().any(|(s, _)| s.contains("abcd")), "{w:?}");
        assert!(w.iter().any(|(s, _)| s.contains("efgh")), "{w:?}");
        assert!(w.iter().any(|(s, _)| s.contains("ijkl")), "{w:?}");
    }

    #[test]
    fn folded_windows_hold_the_joined_text() {
        let w = folded_windows("curl -d 'tok=ab'\"cd\"'ef' x");
        assert!(w.iter().any(|s| s.contains("tok=abcdef")), "{w:?}");
        assert!(folded_windows("echo hello").is_empty());
    }

    #[test]
    fn plain_text_has_no_chains() {
        assert!(concat_windows("git commit -m 'one' -m 'two'").is_empty());
        assert!(concat_windows("echo hello").is_empty());
    }
}
