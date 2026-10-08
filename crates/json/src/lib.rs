//! `vahta-json`: a JSON parser that agrees with CPython's `json.loads`, built
//! for hostile input.
//!
//! Purpose: read text an attacker or a careless agent wrote (agent transcripts,
//! hook payloads) exactly the way Python's `json.loads` would, without being
//! defeated by its shape. Iterative, so nesting cannot overflow the stack, and
//! with **unbounded depth** unless a caller sets [`Limits`] (depth and node
//! count) to bound memory. When a document is over the limits, or too big to
//! parse, [`for_each_string`] is a tree-free token walk that still reports
//! every string, decoded, in memory bounded by the largest one. No
//! dependencies, no unsafe code.
//!
//! Hand-rolled, no dependencies, and **not** a general-purpose JSON library:
//! it exists because a `--deep` scan must accept and reject exactly the lines
//! Python's does. A transcript line Python parses and this does not is a
//! secret never looked at; one this parses and Python rejects is a finding
//! Python would not report. Both are bugs, so where `json.loads` is odd, this
//! is odd the same way. Every rule below is pinned by a test (it was
//! also compared against the interpreter on generated input while ka was
//! tested alongside).
//!
//! # What Python's parser does that a strict RFC 8259 one does not
//!
//! * `NaN`, `Infinity` and `-Infinity` are values.
//! * Only space, tab, LF and CR are whitespace. Not `\x0b`, `\x0c`, NBSP or
//!   U+FEFF (which `json.loads` rejects up front as a BOM).
//! * Control characters (below U+0020) inside a string are an error; DEL and
//!   everything above are not.
//! * `\u` takes exactly four hex digits. A high surrogate escape followed by a
//!   low surrogate escape combines into one scalar; any other surrogate escape
//!   is accepted on its own (see below).
//! * Duplicate object keys: the **last value wins**, at the **position of the
//!   first** occurrence (`dict` semantics). Anything that iterates an object
//!   sees that order.
//! * Floats saturate to infinity (`1e999`).
//! * Leading zeros, `1.`, `.5`, `+1`, trailing commas, single quotes and
//!   comments are all errors.
//!
//! # Lone surrogates
//!
//! `"\ud800"` is accepted by Python and yields a `str` holding a surrogate code
//! point, which a Rust `String` cannot hold. What Python does with such a
//! string next is: run the detector over it, and — only if it is a dict key —
//! test it against the secret-name vocabulary, which is ASCII plus a few
//! case-folding look-alikes and so can never contain a surrogate. In the
//! detector a surrogate is a character that is not a letter, digit, space,
//! quote or word character, it counts as one character, and two *different*
//! surrogates count as two distinct characters for entropy.
//!
//! So each lone surrogate is mapped to its own private-use scalar,
//! `U+10F800 + (surrogate - U+D800)`: also not a letter, digit, space or word
//! character, one character, and distinct from every other surrogate. The two
//! behave identically in the detector, which was checked against the
//! interpreter rather than assumed. The one divergence this leaves is a document that
//! contains a **real** character in `U+10F800..=U+10FFFF` alongside a lone
//! surrogate in the same string, where entropy could differ by one distinct
//! symbol. Those code points are unassigned private use in supplementary
//! plane 16 and appear in no transcript; the alternative of refusing the line
//! would diverge far more often.
//!
//! # Depth
//!
//! The parser is iterative, so nesting cannot overflow the stack, and [`Value`]
//! has an iterative `Drop`. [`parse`] has no depth limit: depth is bounded by
//! the length of the input. A caller that must bound memory uses
//! [`parse_bounded`], which gives up with [`ParseError::TooDeep`] as soon as
//! nesting passes its limit, before the tree is built.
//!
//! # Where this deliberately differs from CPython
//!
//! `json.loads` raises `RecursionError` on a document nested past a few tens
//! of thousands of levels, and `ValueError` on an integer of more than 4300
//! digits; neither is a `JSONDecodeError`, so in Python one such transcript
//! line aborts the whole `--deep` scan. Here both are ordinary values: the
//! line is parsed and scanned like any other, because it may hold a real key.
//!
//! Never carries or logs secret values beyond holding the strings it is given.

use std::collections::HashMap;

/// First of the 2048 private-use scalars standing in for `U+D800..=U+DFFF`.
const SURROGATE_BASE: u32 = 0x10F800;

/// A parsed JSON value. Object entries are in `dict` order, duplicates
/// already resolved.
#[derive(Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// Decimal digits with an optional leading `-`; `-0` is normalised to `0`
    /// as Python's `int` does. Never a number the scanner would not read.
    Int(String),
    Float(f64),
    Str(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

/// Why a parse did not produce a [`Value`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// `json.JSONDecodeError`. Callers skip the input.
    Invalid,
    /// Nesting passed the limit given to [`parse_bounded`]. Says nothing about
    /// whether the text is valid JSON: the parse stopped at the limit.
    TooDeep,
    /// More values than [`Limits::nodes`] allows. Like [`ParseError::TooDeep`],
    /// says nothing about validity.
    TooMany,
}

/// What a bounded parse may build. Depth bounds the open frames; nodes bound
/// the finished tree, which a wide line (`[1,1,1,...]`) grows by tens of bytes
/// per two bytes of text however shallow it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub depth: usize,
    pub nodes: usize,
}

impl Limits {
    pub const NONE: Limits = Limits {
        depth: usize::MAX,
        nodes: usize::MAX,
    };
}

impl Value {
    pub fn is_container(&self) -> bool {
        matches!(self, Value::Array(_) | Value::Object(_))
    }

    /// An unambiguous, order-preserving text form, for comparing against the
    /// interpreter. Strings are code point lists, floats are bit patterns
    /// (`nan` for every NaN), so nothing depends on how either side prints.
    /// Iterative: deep values are the point of the exercise.
    pub fn canonical(&self) -> String {
        enum Step<'a> {
            Val(&'a Value),
            Raw(&'static str),
        }
        let mut out = String::new();
        let mut work = vec![Step::Val(self)];
        while let Some(step) = work.pop() {
            match step {
                Step::Raw(s) => out.push_str(s),
                Step::Val(v) => match v {
                    Value::Null => out.push('n'),
                    Value::Bool(true) => out.push('t'),
                    Value::Bool(false) => out.push('f'),
                    Value::Int(s) => {
                        out.push('i');
                        out.push_str(s);
                        out.push(';');
                    }
                    Value::Float(f) => {
                        out.push('d');
                        if f.is_nan() {
                            out.push_str("nan");
                        } else {
                            out.push_str(&format!("{:016x}", f.to_bits()));
                        }
                        out.push(';');
                    }
                    Value::Str(s) => canonical_str(&mut out, s),
                    Value::Array(items) => {
                        out.push('[');
                        work.push(Step::Raw("]"));
                        for item in items.iter().rev() {
                            work.push(Step::Val(item));
                        }
                    }
                    Value::Object(entries) => {
                        out.push('{');
                        work.push(Step::Raw("}"));
                        for (_, val) in entries.iter().rev() {
                            work.push(Step::Val(val));
                        }
                        // Keys are written up front, in order; values follow
                        // as the worklist unwinds. Unambiguous because the
                        // key count is fixed by the array of keys that opens.
                        let mut keys = String::new();
                        for (k, _) in entries {
                            canonical_str(&mut keys, k);
                        }
                        out.push_str(&keys);
                        out.push('|');
                    }
                },
            }
        }
        out
    }
}

fn canonical_str(out: &mut String, s: &str) {
    out.push('s');
    let mut first = true;
    for c in s.chars() {
        if !first {
            out.push('.');
        }
        first = false;
        out.push_str(&format!("{:x}", c as u32));
    }
    out.push(';');
}

impl Drop for Value {
    /// Iterative, so dropping a document nested tens of thousands deep cannot
    /// overflow the stack the way the derived recursive drop would.
    fn drop(&mut self) {
        fn take(v: &mut Value, work: &mut Vec<Value>) {
            match v {
                Value::Array(items) => work.append(items),
                Value::Object(entries) => {
                    for (_, val) in entries.drain(..) {
                        work.push(val);
                    }
                }
                _ => {}
            }
        }
        let mut work = Vec::new();
        take(self, &mut work);
        while let Some(mut v) = work.pop() {
            take(&mut v, &mut work);
        }
    }
}

/// An open container. Objects are boxed so a frame stays small: a document a
/// million levels deep holds a million of these at once.
enum Frame {
    Array(Vec<Value>),
    Object(Box<Object>),
}

struct Object {
    entries: Vec<(String, Value)>,
    /// Built only once an object is large, so a many-keyed object is not
    /// quadratic and a small one pays nothing.
    index: Option<HashMap<String, usize>>,
    key: Option<String>,
}

const INDEX_AFTER: usize = 16;

impl Object {
    fn new() -> Self {
        Object {
            entries: Vec::with_capacity(1),
            index: None,
            key: None,
        }
    }

    /// `dict[key] = value`: replaces in place, so the first position is kept.
    fn insert(&mut self, key: String, value: Value) {
        if let Some(index) = &mut self.index {
            if let Some(&at) = index.get(&key) {
                self.entries[at].1 = value;
            } else {
                index.insert(key.clone(), self.entries.len());
                self.entries.push((key, value));
            }
            return;
        }
        if let Some(at) = self.entries.iter().position(|(k, _)| *k == key) {
            self.entries[at].1 = value;
            return;
        }
        self.entries.push((key, value));
        if self.entries.len() > INDEX_AFTER {
            self.index = Some(
                self.entries
                    .iter()
                    .enumerate()
                    .map(|(i, (k, _))| (k.clone(), i))
                    .collect(),
            );
        }
    }
}

struct Parser<'a> {
    text: &'a str,
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    /// Four hex digits at `at`; `None` when fewer than four or any is not
    /// `[0-9a-fA-F]`.
    fn hex4(&self, at: usize) -> Option<u32> {
        let digits = self.b.get(at..at + 4)?;
        let mut v = 0u32;
        for &d in digits {
            v = v * 16 + (d as char).to_digit(16)?;
        }
        Some(v)
    }

    /// A string body, with `self.i` just past the opening quote.
    fn string(&mut self) -> Result<String, ParseError> {
        let mut out = String::new();
        let mut run = self.i;
        loop {
            let Some(&c) = self.b.get(self.i) else {
                return Err(ParseError::Invalid); // Unterminated string
            };
            match c {
                b'"' => {
                    out.push_str(&self.text[run..self.i]);
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    out.push_str(&self.text[run..self.i]);
                    self.i += 1;
                    let Some(&e) = self.b.get(self.i) else {
                        return Err(ParseError::Invalid);
                    };
                    self.i += 1;
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
                            let hi = self.hex4(self.i).ok_or(ParseError::Invalid)?;
                            self.i += 4;
                            let mut cp = hi;
                            if (0xD800..0xDC00).contains(&hi)
                                && self.b.get(self.i) == Some(&b'\\')
                                && self.b.get(self.i + 1) == Some(&b'u')
                            {
                                // CPython reads the second escape eagerly: a
                                // malformed one is an error even when the
                                // first would have stood alone.
                                let lo = self.hex4(self.i + 2).ok_or(ParseError::Invalid)?;
                                if (0xDC00..0xE000).contains(&lo) {
                                    cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                                    self.i += 6;
                                }
                            }
                            out.push(scalar(cp));
                        }
                        _ => return Err(ParseError::Invalid), // Invalid \escape
                    }
                    run = self.i;
                }
                0x00..=0x1f => return Err(ParseError::Invalid), // Invalid control character
                _ => self.i += 1,
            }
        }
    }

    /// A number starting at `self.i`, which is `-` or an ASCII digit.
    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.i;
        let digit = |p: &Self, at: usize| p.b.get(at).is_some_and(u8::is_ascii_digit);
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'1'..=b'9') => {
                while digit(self, self.i) {
                    self.i += 1;
                }
            }
            Some(b'0') => self.i += 1,
            _ => return Err(ParseError::Invalid),
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') && digit(self, self.i + 1) {
            is_float = true;
            self.i += 2;
            while digit(self, self.i) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            let mut j = self.i + 1;
            if matches!(self.b.get(j), Some(b'+' | b'-')) {
                j += 1;
            }
            if digit(self, j) {
                while digit(self, j) {
                    j += 1;
                }
                is_float = true;
                self.i = j;
            }
            // Otherwise the `e` is left unread and the caller rejects it.
        }
        let token = &self.text[start..self.i];
        if is_float {
            // Rust's parse rounds correctly and saturates to infinity, as
            // `float()` does.
            return Ok(Value::Float(token.parse::<f64>().unwrap_or(f64::NAN)));
        }
        // No digit cap: CPython's 4300-digit `ValueError` is not reproduced.
        // The digits are kept as text; they never reach the detector.
        Ok(Value::Int(if token == "-0" {
            "0".to_string()
        } else {
            token.to_string()
        }))
    }

    /// Does `word` start at `self.i`?
    fn literal(&mut self, word: &str) -> bool {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            true
        } else {
            false
        }
    }

    /// `"key" :` with `self.i` just past the opening quote.
    fn key(&mut self) -> Result<String, ParseError> {
        let key = self.string()?;
        self.skip_ws();
        if self.peek() != Some(b':') {
            return Err(ParseError::Invalid);
        }
        self.i += 1;
        self.skip_ws();
        Ok(key)
    }
}

/// A code point as a `char`: a surrogate becomes its private-use stand-in.
fn scalar(cp: u32) -> char {
    if (0xD800..0xE000).contains(&cp) {
        char::from_u32(SURROGATE_BASE + (cp - 0xD800)).unwrap_or('\u{fffd}')
    } else {
        char::from_u32(cp).unwrap_or('\u{fffd}')
    }
}

/// `json.loads(text)`.
pub fn parse(text: &str) -> Result<Value, ParseError> {
    parse_bounded(text, usize::MAX)
}

/// [`parse`], refusing nesting deeper than `max_depth`.
///
/// Depth is the number of containers open at once, an empty `[]` or `{}`
/// counting as one: `[[1]]` is depth 2, and `max_depth` itself is allowed. The
/// check is made when a container opens, so a hostile document costs at most
/// `max_depth` open frames before the parse stops with
/// [`ParseError::TooDeep`] — the memory a caller is bounding.
pub fn parse_bounded(text: &str, max_depth: usize) -> Result<Value, ParseError> {
    parse_limited(
        text,
        Limits {
            depth: max_depth,
            nodes: usize::MAX,
        },
    )
}

/// [`parse`] within `limits`: [`ParseError::TooDeep`] past the depth,
/// [`ParseError::TooMany`] past the node count. Every value counts as a node,
/// containers included.
pub fn parse_limited(text: &str, limits: Limits) -> Result<Value, ParseError> {
    let max_depth = limits.depth;
    let mut nodes = 0usize;
    let mut p = Parser {
        text,
        b: text.as_bytes(),
        i: 0,
    };
    let mut stack: Vec<Frame> = Vec::new();
    p.skip_ws();

    'value: loop {
        nodes += 1;
        if nodes > limits.nodes {
            return Err(ParseError::TooMany);
        }
        // A value is expected at `p.i`.
        let mut value = match p.peek().ok_or(ParseError::Invalid)? {
            b'"' => {
                p.i += 1;
                Value::Str(p.string()?)
            }
            b'{' => {
                if stack.len() >= max_depth {
                    return Err(ParseError::TooDeep);
                }
                p.i += 1;
                p.skip_ws();
                if p.peek() == Some(b'}') {
                    p.i += 1;
                    Value::Object(Vec::new())
                } else {
                    if p.peek() != Some(b'"') {
                        return Err(ParseError::Invalid);
                    }
                    p.i += 1;
                    let mut obj = Object::new();
                    obj.key = Some(p.key()?);
                    stack.push(Frame::Object(Box::new(obj)));
                    continue 'value;
                }
            }
            b'[' => {
                if stack.len() >= max_depth {
                    return Err(ParseError::TooDeep);
                }
                p.i += 1;
                p.skip_ws();
                if p.peek() == Some(b']') {
                    p.i += 1;
                    Value::Array(Vec::new())
                } else {
                    stack.push(Frame::Array(Vec::with_capacity(1)));
                    continue 'value;
                }
            }
            b'n' if p.literal("null") => Value::Null,
            b't' if p.literal("true") => Value::Bool(true),
            b'f' if p.literal("false") => Value::Bool(false),
            b'N' if p.literal("NaN") => Value::Float(f64::NAN),
            b'I' if p.literal("Infinity") => Value::Float(f64::INFINITY),
            b'-' if p.literal("-Infinity") => Value::Float(f64::NEG_INFINITY),
            b'-' | b'0'..=b'9' => p.number()?,
            _ => return Err(ParseError::Invalid),
        };

        // A value is complete: hand it to its container, closing containers
        // for as long as they end.
        loop {
            match stack.last_mut() {
                None => {
                    p.skip_ws();
                    return if p.i == p.b.len() {
                        Ok(value)
                    } else {
                        Err(ParseError::Invalid)
                    };
                }
                Some(Frame::Array(items)) => {
                    items.push(value);
                    p.skip_ws();
                    match p.peek() {
                        Some(b']') => {
                            p.i += 1;
                            let Some(Frame::Array(done)) = stack.pop() else {
                                unreachable!("the frame was just matched as an array")
                            };
                            value = Value::Array(done);
                        }
                        Some(b',') => {
                            p.i += 1;
                            p.skip_ws();
                            continue 'value;
                        }
                        _ => return Err(ParseError::Invalid),
                    }
                }
                Some(Frame::Object(obj)) => {
                    let key = obj.key.take().ok_or(ParseError::Invalid)?;
                    obj.insert(key, value);
                    p.skip_ws();
                    match p.peek() {
                        Some(b'}') => {
                            p.i += 1;
                            let Some(Frame::Object(done)) = stack.pop() else {
                                unreachable!("the frame was just matched as an object")
                            };
                            value = Value::Object(done.entries);
                        }
                        Some(b',') => {
                            p.i += 1;
                            p.skip_ws();
                            if p.peek() != Some(b'"') {
                                return Err(ParseError::Invalid);
                            }
                            p.i += 1;
                            obj.key = Some(p.key()?);
                            continue 'value;
                        }
                        _ => return Err(ParseError::Invalid),
                    }
                }
            }
        }
    }
}

/// Every string in `text` in value position, decoded, in reading order, each
/// with the member key just before it when it is an object member's value
/// (`f(Some(key), value)`); keys themselves are not reported as strings.
///
/// A token walk with no tree, for text that is too big to parse: memory is the
/// largest single string. It never fails. It does not check structure, so it
/// reads invalid JSON too: a string with a malformed escape or no closing quote
/// is passed raw. Duplicate keys are not resolved, so it may report a member
/// `dict` semantics would have overwritten — more, never less.
pub fn for_each_string(text: &str, f: &mut dyn FnMut(Option<&str>, &str)) {
    let b = text.as_bytes();
    let mut i = 0usize;
    let mut key: Option<String> = None;
    while i < b.len() {
        match b[i] {
            b'"' => {
                let (s, next) = string_token(text, i);
                i = next;
                let mut j = i;
                while j < b.len() && matches!(b[j], b' ' | b'\t' | b'\n' | b'\r') {
                    j += 1;
                }
                if b.get(j) == Some(&b':') {
                    key = Some(s);
                    i = j + 1;
                } else {
                    f(key.take().as_deref(), &s);
                }
            }
            b' ' | b'\t' | b'\n' | b'\r' => i += 1,
            _ => {
                // Any other token ends a pending member: its value is not a
                // string.
                key = None;
                i += 1;
            }
        }
    }
}

/// The string token opening at `start` (a `"`), decoded, and the index just
/// past it. Undecodable or unterminated: the raw body, up to the closing quote
/// or the end.
fn string_token(text: &str, start: usize) -> (String, usize) {
    let b = text.as_bytes();
    let mut end = start + 1;
    while end < b.len() && b[end] != b'"' {
        end += if b[end] == b'\\' { 2 } else { 1 };
    }
    let end = end.min(b.len());
    let mut p = Parser {
        text,
        b,
        i: start + 1,
    };
    match p.string() {
        Ok(s) if p.i == end + 1 => (s, end + 1),
        // `end` is a quote or the end of the text, both char boundaries.
        _ => (text[start + 1..end].to_string(), (end + 1).min(b.len())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> Value {
        parse(s).unwrap_or_else(|e| panic!("{s:?} should parse, got {e:?}"))
    }

    fn bad(s: &str) {
        assert_eq!(
            parse(s).err(),
            Some(ParseError::Invalid),
            "{s:?} should be rejected"
        );
    }

    fn string_of(v: &Value) -> &str {
        match v {
            Value::Str(s) => s,
            other => panic!("not a string: {other:?}"),
        }
    }

    #[test]
    fn the_scalars() {
        assert_eq!(ok("null"), Value::Null);
        assert_eq!(ok("true"), Value::Bool(true));
        assert_eq!(ok(" false\t\r\n"), Value::Bool(false));
        assert_eq!(ok("-12"), Value::Int("-12".into()));
        assert_eq!(ok("\"a\""), Value::Str("a".into()));
    }

    #[test]
    fn nan_and_the_infinities_are_values() {
        assert!(matches!(&ok("NaN"), Value::Float(f) if f.is_nan()));
        assert_eq!(ok("Infinity"), Value::Float(f64::INFINITY));
        assert_eq!(ok("-Infinity"), Value::Float(f64::NEG_INFINITY));
        assert!(matches!(&ok("[NaN,-Infinity,1]"), Value::Array(a) if a.len() == 3));
        // ...but only spelled exactly.
        for s in [
            "nan",
            "inf",
            "+Infinity",
            "Infinit",
            "-NaN",
            "-Inf",
            "NaNa",
            "infinity",
        ] {
            bad(s);
        }
    }

    #[test]
    fn what_python_rejects_is_rejected() {
        for s in [
            "[1,]",
            "{\"a\":1,}",
            "[,1]",
            "{,}",
            "[1 2]",
            "{'a':1}",
            "['a']",
            "// c\n1",
            "/* c */1",
            "{\"a\" 1}",
            "{\"a\":}",
            "{1:2}",
            "[",
            "{",
            "\"abc",
            "",
            "  ",
            "01",
            "-",
            "+1",
            ".5",
            "1.",
            "1e",
            "1e+",
            "--1",
            "[01]",
            "tru",
            "nul",
            "[1]]",
            "1 2",
            "{\"a\":1}x",
            "\u{feff}1",
            "\u{a0}1",
            "\u{b}1",
            "\u{c}1",
        ] {
            bad(s);
        }
    }

    #[test]
    fn only_four_characters_are_whitespace() {
        assert_eq!(ok(" \t\n\r1 \t\n\r"), Value::Int("1".into()));
        bad("\u{b}1");
        bad("1\u{c}");
        bad("\u{2028}1");
    }

    #[test]
    fn numbers() {
        assert_eq!(ok("0"), Value::Int("0".into()));
        assert_eq!(ok("-0"), Value::Int("0".into()));
        assert_eq!(ok("-0.0"), Value::Float(-0.0));
        assert_eq!(ok("1E2"), Value::Float(100.0));
        assert_eq!(ok("1.5e-3"), Value::Float(0.0015));
        assert_eq!(ok("1e999"), Value::Float(f64::INFINITY));
        assert_eq!(ok("-1e999"), Value::Float(f64::NEG_INFINITY));
        assert_eq!(ok("1e-999"), Value::Float(0.0));
        assert_eq!(
            ok("123456789012345678901234567890"),
            Value::Int("123456789012345678901234567890".into())
        );
    }

    #[test]
    fn integers_have_no_digit_cap() {
        // CPython raises ValueError over 4300 digits; this is a number.
        for n in [4300, 4301, 100_000] {
            let big = "9".repeat(n);
            assert_eq!(ok(&big), Value::Int(big.clone()));
            assert_eq!(ok(&format!("-{big}")), Value::Int(format!("-{big}")));
            assert!(parse(&format!("[1,{big},{{\"a\":{big}}}]")).is_ok());
            assert!(parse(&format!("{big}.5")).is_ok());
            assert!(parse(&format!("{big}e1")).is_ok());
        }
        // Order of failure is order of reading, as ever.
        let big = "9".repeat(5000);
        assert_eq!(
            parse(&format!("[x,{big}]")).err(),
            Some(ParseError::Invalid)
        );
        assert_eq!(
            parse(&format!("[{big},x]")).err(),
            Some(ParseError::Invalid)
        );
    }

    #[test]
    fn duplicate_keys_last_value_first_position() {
        let v = ok(r#"{"a":1,"b":2,"a":3}"#);
        assert_eq!(
            v,
            Value::Object(vec![
                ("a".into(), Value::Int("3".into())),
                ("b".into(), Value::Int("2".into())),
            ])
        );
    }

    #[test]
    fn duplicate_keys_in_a_large_object_keep_first_position() {
        let mut text = String::from("{");
        for i in 0..40 {
            text.push_str(&format!("\"k{i}\":{i},"));
        }
        text.push_str("\"k3\":\"last\",\"k39\":\"last\"}");
        let parsed = ok(&text);
        let Value::Object(entries) = &parsed else {
            panic!("object")
        };
        assert_eq!(entries.len(), 40);
        assert_eq!(entries[3].0, "k3");
        assert_eq!(entries[3].1, Value::Str("last".into()));
        assert_eq!(entries[39].1, Value::Str("last".into()));
        assert_eq!(entries[0].0, "k0");
    }

    #[test]
    fn escapes() {
        assert_eq!(
            string_of(&ok(r#""\"\\\/\b\f\n\r\t""#)),
            "\"\\/\u{8}\u{c}\n\r\t"
        );
        assert_eq!(string_of(&ok(r#""Aé€""#)), "A\u{e9}\u{20ac}");
        assert_eq!(string_of(&ok(r#""é""#)), "\u{e9}");
        for s in [
            r#""\x41""#,
            r#""\u12""#,
            r#""\u12g4""#,
            r#""\"#,
            r#""\a""#,
            r#""\u""#,
        ] {
            bad(s);
        }
    }

    #[test]
    fn control_characters_in_strings_are_rejected_but_del_is_not() {
        bad("\"a\u{0}b\"");
        bad("\"a\nb\"");
        bad("\"a\tb\"");
        assert_eq!(string_of(&ok("\"a\u{7f}b\"")), "a\u{7f}b");
        assert_eq!(string_of(&ok("\"a\u{85}\u{2028}b\"")), "a\u{85}\u{2028}b");
    }

    #[test]
    fn a_surrogate_pair_combines() {
        assert_eq!(string_of(&ok(r#""😀""#)), "\u{1F600}");
        assert_eq!(string_of(&ok(r#""😀""#)), "\u{1F600}");
        assert_eq!(string_of(&ok(r#""x𐀀y""#)), "x\u{10000}y");
        assert_eq!(string_of(&ok(r#""􏿿""#)), "\u{10FFFF}");
    }

    #[test]
    fn a_lone_surrogate_is_accepted_and_kept_distinct() {
        let a = string_of(&ok(r#""\ud800""#)).to_string();
        let b = string_of(&ok(r#""\udc00""#)).to_string();
        let c = string_of(&ok(r#""\udfff""#)).to_string();
        assert_eq!(a.chars().count(), 1);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_eq!(a.chars().next().map(|c| c as u32), Some(0x10F800));
        assert_eq!(c.chars().next().map(|c| c as u32), Some(0x10FFFF));
    }

    #[test]
    fn surrogates_that_do_not_pair_stay_separate() {
        // high, high-low pair: the first is lone.
        let s = string_of(&ok(r#""\ud800😀""#)).to_string();
        let cs: Vec<u32> = s.chars().map(|c| c as u32).collect();
        assert_eq!(cs, vec![0x10F800, 0x1F600]);
        // low then high: both lone, in order.
        let s = string_of(&ok(r#""\udc00\ud800""#)).to_string();
        assert_eq!(
            s.chars().map(|c| c as u32).collect::<Vec<_>>(),
            vec![0x10F800 + 0x400, 0x10F800]
        );
        // high followed by an ordinary escape.
        let s = string_of(&ok(r#""\ud800A""#)).to_string();
        assert_eq!(
            s.chars().map(|c| c as u32).collect::<Vec<_>>(),
            vec![0x10F800, 0x41]
        );
        // high followed by another kind of escape, and by plain text.
        assert_eq!(string_of(&ok(r#""\ud800\n""#)).chars().count(), 2);
        assert_eq!(string_of(&ok(r#""\ud800abc""#)).chars().count(), 4);
        // a lone low surrogate after a completed pair.
        assert_eq!(string_of(&ok(r#""😀\ude00""#)).chars().count(), 2);
    }

    #[test]
    fn a_malformed_second_escape_after_a_high_surrogate_is_an_error() {
        // CPython reads it eagerly, so this is invalid rather than "lone".
        bad(r#""\ud800\u12""#);
        bad(r#""\ud800\uzzzz""#);
        bad(r#""\ud800\u"#);
    }

    #[test]
    fn lone_surrogates_are_keys_too() {
        let v = ok(r#"{"\ud800":1,"\udc00":2,"\ud800":3}"#);
        let Value::Object(e) = &v else {
            panic!("object")
        };
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].1, Value::Int("3".into()));
    }

    #[test]
    fn nested_containers_and_order() {
        let v = ok(r#" {"z":[1,{"y":null}],"a":{}} "#);
        assert_eq!(
            v.canonical(),
            ok(r#"{"z":[1,{"y":null}],"a":{}}"#).canonical()
        );
        let Value::Object(e) = &v else { panic!() };
        assert_eq!(e[0].0, "z");
        assert_eq!(e[1].0, "a");
    }

    #[test]
    fn canonical_distinguishes_what_it_should() {
        assert_ne!(ok("[1,2]").canonical(), ok("[12]").canonical());
        assert_ne!(ok("{\"a\":1}").canonical(), ok("{\"b\":1}").canonical());
        assert_ne!(
            ok("{\"a\":1,\"b\":2}").canonical(),
            ok("{\"b\":2,\"a\":1}").canonical()
        );
        assert_ne!(ok("0.0").canonical(), ok("-0.0").canonical());
        assert_eq!(
            ok("NaN").canonical(),
            ok("[NaN]").canonical().replace(['[', ']'], "")
        );
    }

    #[test]
    fn the_depth_bound_allows_its_limit_and_refuses_one_more() {
        let arrays = |n: usize| format!("{}1{}", "[".repeat(n), "]".repeat(n));
        let objects = |n: usize| format!("{}1{}", "{\"a\":".repeat(n), "}".repeat(n));
        for limit in [1usize, 2, 17, 1000] {
            assert!(parse_bounded(&arrays(limit), limit).is_ok());
            assert!(parse_bounded(&objects(limit), limit).is_ok());
            assert_eq!(
                parse_bounded(&arrays(limit + 1), limit),
                Err(ParseError::TooDeep)
            );
            assert_eq!(
                parse_bounded(&objects(limit + 1), limit),
                Err(ParseError::TooDeep)
            );
        }
        // An empty container is a level too, and the innermost one is where
        // the count tips over.
        assert!(parse_bounded("[[]]", 2).is_ok());
        assert_eq!(parse_bounded("[[]]", 1), Err(ParseError::TooDeep));
        assert_eq!(parse_bounded("{}", 0), Err(ParseError::TooDeep));
        // Scalars have no depth, and siblings do not accumulate.
        assert!(parse_bounded("1", 0).is_ok());
        assert!(parse_bounded("[[1],[2],[3]]", 2).is_ok());
        // Stopping at the limit says nothing about validity beyond it.
        assert_eq!(parse_bounded("[[[[x", 2), Err(ParseError::TooDeep));
        assert_eq!(parse_bounded("[x", 2), Err(ParseError::Invalid));
    }

    #[test]
    fn deep_nesting_neither_overflows_the_stack_nor_panics() {
        // A million deep, then dropped: the iterative drop is exercised as
        // much as the iterative parse. No depth limit, so no error either.
        let n = 1_000_000;
        let arr = format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(parse(&arr).is_ok());
        let obj = format!("{}1{}", "{\"a\":".repeat(n), "}".repeat(n));
        assert!(parse(&obj).is_ok());
        // Unterminated is merely invalid, however deep.
        assert_eq!(parse(&"[".repeat(n)).err(), Some(ParseError::Invalid));
        assert_eq!(parse(&"{\"a\":".repeat(n)).err(), Some(ParseError::Invalid));
    }

    #[test]
    fn multibyte_text_passes_through() {
        assert_eq!(
            string_of(&ok("\"h\u{e9}llo \u{1F600} \u{4e16}\"")),
            "h\u{e9}llo \u{1F600} \u{4e16}"
        );
    }
    #[test]
    fn the_node_limit_counts_every_value() {
        let lim = |nodes| Limits {
            depth: usize::MAX,
            nodes,
        };
        // `[1,2]` is three values: the array and two numbers.
        assert!(parse_limited("[1,2]", lim(3)).is_ok());
        assert_eq!(
            parse_limited("[1,2]", lim(2)).err(),
            Some(ParseError::TooMany)
        );
        assert_eq!(
            parse_limited("{\"a\":{}}", lim(1)).err(),
            Some(ParseError::TooMany)
        );
        let wide = format!("[{}1]", "1,".repeat(100_000));
        assert_eq!(
            parse_limited(&wide, lim(1000)).err(),
            Some(ParseError::TooMany)
        );
        assert!(parse_limited(&wide, Limits::NONE).is_ok());
    }

    fn strings_of(text: &str) -> Vec<(Option<String>, String)> {
        let mut out = Vec::new();
        for_each_string(text, &mut |k, v| {
            out.push((k.map(str::to_string), v.to_string()))
        });
        out
    }

    #[test]
    fn the_token_walk_reports_values_with_their_keys() {
        let got = strings_of(r#"{"a": "x", "b": [ "y", {"c" : "z"} ], "d": 1, "e": "w"}"#);
        let want = [
            (Some("a"), "x"),
            (None, "y"),
            (Some("c"), "z"),
            (Some("e"), "w"),
        ];
        let want: Vec<_> = want
            .iter()
            .map(|(k, v)| (k.map(str::to_string), v.to_string()))
            .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn the_token_walk_decodes_escapes_and_keeps_malformed_strings_raw() {
        assert_eq!(
            strings_of(r#"{"API\u005fKEY": "a\"b"}"#),
            vec![(Some("API_KEY".into()), "a\"b".into())]
        );
        // A malformed escape and an unterminated string come through raw.
        assert_eq!(
            strings_of(r#"["bad \q esc", "open"#),
            vec![(None, "bad \\q esc".into()), (None, "open".into())]
        );
        // A key whose value is not a string does not leak onto the next string.
        assert_eq!(strings_of(r#"{"k": [1], "x"]"#), vec![(None, "x".into())]);
        // Not JSON at all, and multibyte text after a backslash: no panic.
        assert_eq!(
            strings_of("garbage \"\\\u{e9}\" ]]"),
            vec![(None, "\\\u{e9}".into())]
        );
        assert!(strings_of("[[[[").is_empty());
    }
}
