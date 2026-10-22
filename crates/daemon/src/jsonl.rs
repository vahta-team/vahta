//! Taking secrets out of a JSON Lines file without disturbing the rest of it.
//!
//! A harness transcript is one JSON document per line. A value in it sits
//! inside a string literal, possibly escaped (`\"`, `\n`, `é`), and a
//! tool's output that is itself JSON carries the value escaped a second time.
//! So the cleaner reads each line as text, finds the string literals, decodes
//! each (as JSON does), cleans the decoded text, and writes a literal back
//! **only for a string that changed**. Everything else on the line, and every
//! line that held nothing, is copied byte for byte: key order, number
//! spellings, spacing and line endings are the harness's own. Every
//! replacement is a marker made of plain characters, written as a legal JSON
//! string, so a line that was valid JSON stays valid JSON.
//!
//! The line is never built into a tree, so there is no depth limit to trip
//! over: a line nested a thousand levels deep is cleaned like any other.
//!
//! What a cleaner looks for: the values the daemon holds (each in every form
//! it knows, plus the JSON-escaped spelling of each, one and two levels deep,
//! for a value that sits inside a string of JSON), and the detector's likely
//! finds. A value is replaced by `***REDACTED(NAME)***`, a detector find by
//! `***REDACTED(kind)***`, as in a tool's output.
//!
//! Rewriting a file is two passes: a read-only count, and, when there is
//! something to remove and the file is closed, a second pass into a temp file
//! next to it, fsynced and renamed over it. The file's permissions and
//! modification time are kept, and if the file changed under us (the harness
//! appended) the rename is not done.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::SystemTime;

use aho_corasick::{AhoCorasick, MatchKind};
use vahta_detect::{Confidence, find_secret_spans};

/// A line longer than this is copied unread: past what any harness writes,
/// and not worth holding in memory.
const MAX_LINE: usize = 64 * 1024 * 1024;
/// The detector reads a string up to this long; past it (an image, a dump) only
/// the values the daemon holds are looked for.
const DETECT_MAX: usize = 4 * 1024 * 1024;

/// What was found, as counts and names. Never a value.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Tally {
    /// Places a value the daemon holds was found.
    pub values: usize,
    /// Places the detector found a likely secret.
    pub patterns: usize,
    /// The secrets' names behind `values`, each once (no form suffix).
    pub names: BTreeSet<String>,
    /// How many bytes of the file the pass read.
    pub consumed: u64,
}

impl Tally {
    pub fn total(&self) -> usize {
        self.values + self.patterns
    }
}

/// `NAME (base64)` is the secret `NAME`.
pub(crate) fn base_name(label: &str) -> &str {
    label.split(" (").next().unwrap_or(label)
}

/// A value to find, labelled `NAME` or `NAME (form)`.
pub(crate) type Value = (String, Vec<u8>);

pub(crate) struct Cleaner {
    ac: Option<AhoCorasick>,
    /// The label of each pattern in `ac`.
    labels: Vec<String>,
}

/// `s` as the inside of a JSON string.
pub(crate) fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

impl Cleaner {
    pub fn new(values: &[Value]) -> Cleaner {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut labels: Vec<String> = Vec::new();
        for (label, bytes) in values {
            if bytes.is_empty() {
                continue;
            }
            let mut forms: Vec<Vec<u8>> = vec![bytes.clone()];
            if let Ok(text) = std::str::from_utf8(bytes) {
                let once = escape(text);
                let twice = escape(&once);
                for e in [once, twice] {
                    if forms.iter().all(|f| f != e.as_bytes()) {
                        forms.push(e.into_bytes());
                    }
                }
            }
            for f in forms {
                patterns.push(f);
                labels.push(label.clone());
            }
        }
        let ac = if patterns.is_empty() {
            None
        } else {
            AhoCorasick::builder()
                .match_kind(MatchKind::Standard)
                .build(&patterns)
                .ok()
        };
        Cleaner { ac, labels }
    }

    /// `text` with what it holds replaced, or `None` when it holds nothing.
    pub fn clean(&self, text: &str, tally: &mut Tally) -> Option<String> {
        struct Cut {
            start: usize,
            end: usize,
            label: String,
            exact: bool,
        }
        let mut cuts: Vec<Cut> = Vec::new();
        if let Some(ac) = &self.ac {
            for m in ac.find_overlapping_iter(text) {
                cuts.push(Cut {
                    start: m.start(),
                    end: m.end(),
                    label: self.labels[m.pattern().as_usize()].clone(),
                    exact: true,
                });
            }
        }
        if (8..=DETECT_MAX).contains(&text.len()) {
            for s in find_secret_spans(text) {
                if s.confidence == Confidence::Likely {
                    cuts.push(Cut {
                        start: s.range.start,
                        end: s.range.end,
                        label: crate::output::clean_label(&s.kind),
                        exact: false,
                    });
                }
            }
        }
        if cuts.is_empty() {
            return None;
        }
        // Earliest first; at one start the longest, a secret's name before a
        // detector's kind. Overlapping or touching cuts become one.
        cuts.sort_by_key(|c| (c.start, std::cmp::Reverse(c.end), !c.exact));
        let mut merged: Vec<Cut> = Vec::new();
        for c in cuts {
            match merged.last_mut() {
                Some(last) if c.start <= last.end => {
                    last.end = last.end.max(c.end);
                    if c.exact && !last.exact {
                        last.label = c.label;
                        last.exact = true;
                    }
                }
                _ => merged.push(c),
            }
        }
        let mut out = String::with_capacity(text.len());
        let mut pos = 0;
        for c in &merged {
            let (mut start, mut end) = (c.start, c.end);
            while start > pos && !text.is_char_boundary(start) {
                start -= 1;
            }
            while end < text.len() && !text.is_char_boundary(end) {
                end += 1;
            }
            if start < pos {
                continue;
            }
            out.push_str(&text[pos..start]);
            out.push_str("***REDACTED(");
            out.push_str(&c.label);
            out.push_str(")***");
            pos = end;
            if c.exact {
                tally.values += 1;
                tally.names.insert(base_name(&c.label).to_string());
            } else {
                tally.patterns += 1;
            }
        }
        out.push_str(&text[pos..]);
        Some(out)
    }
}

// --- one line ---------------------------------------------------------------

fn hex4(b: &[u8]) -> Option<u32> {
    if b.len() < 4 {
        return None;
    }
    let mut n = 0u32;
    for &c in &b[..4] {
        n = n * 16 + (c as char).to_digit(16)?;
    }
    Some(n)
}

/// The text a string literal's inside stands for. A lone surrogate becomes
/// U+FFFD, as lossy readers do.
fn decode(inner: &str) -> String {
    let b = inner.as_bytes();
    let mut out = String::with_capacity(inner.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            // Copy the run up to the next backslash whole: it is valid UTF-8.
            let next = inner[i..].find('\\').map_or(b.len(), |p| i + p);
            out.push_str(&inner[i..next]);
            i = next;
            continue;
        }
        i += 1;
        let Some(&e) = b.get(i) else { break };
        i += 1;
        match e {
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'b' => out.push('\u{8}'),
            b'f' => out.push('\u{c}'),
            b'u' => {
                let Some(hi) = hex4(&b[i..]) else {
                    out.push('u');
                    continue;
                };
                i += 4;
                let code = if (0xD800..0xDC00).contains(&hi)
                    && b.get(i) == Some(&b'\\')
                    && b.get(i + 1) == Some(&b'u')
                    && let Some(lo) = hex4(&b[(i + 2).min(b.len())..])
                    && (0xDC00..0xE000).contains(&lo)
                {
                    i += 6;
                    0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                } else {
                    hi
                };
                out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
            }
            // `"`, `\`, `/`, and anything else: the character itself.
            _ => {
                let start = i - 1;
                let end = inner[start..]
                    .chars()
                    .next()
                    .map_or(start + 1, |c| start + c.len_utf8());
                out.push_str(&inner[start..end]);
                i = end;
            }
        }
    }
    out
}

/// `line` with `clean` applied to every string value (object keys are the
/// harness's, not data). `None` when no string changed.
pub(crate) fn clean_line(
    line: &str,
    clean: &mut dyn FnMut(&str) -> Option<String>,
) -> Option<String> {
    let b = line.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0; // `line[..copied]` is already in `out`
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'"' {
            i += 1;
            continue;
        }
        let open = i + 1;
        let mut j = open;
        while j < b.len() && b[j] != b'"' {
            j += if b[j] == b'\\' { 2 } else { 1 };
        }
        let close = j.min(b.len());
        let inner = &line[open..close];
        // An unterminated literal (a line cut short) is cleaned like a closed one.
        i = close + 1;
        let mut k = i;
        while k < b.len() && matches!(b[k], b' ' | b'\t' | b'\r' | b'\n') {
            k += 1;
        }
        if b.get(k) == Some(&b':') {
            continue;
        }
        let decoded = if inner.contains('\\') {
            decode(inner)
        } else {
            inner.to_string()
        };
        if let Some(new) = clean(&decoded) {
            let buf = out.get_or_insert_with(|| String::with_capacity(line.len()));
            buf.push_str(&line[copied..open]);
            buf.push_str(&escape(&new));
            copied = close;
        }
    }
    out.map(|mut buf| {
        buf.push_str(&line[copied..]);
        buf
    })
}

// --- one file ---------------------------------------------------------------

/// Read `path` line by line, clean each, and write the result to `sink` when
/// there is one. Counts what was found.
fn pass(path: &Path, cleaner: &Cleaner, sink: Option<&mut dyn Write>) -> io::Result<Tally> {
    pass_file(File::open(path)?, cleaner, sink)
}

/// [`pass`] over a file already open.
fn pass_file(file: File, cleaner: &Cleaner, mut sink: Option<&mut dyn Write>) -> io::Result<Tally> {
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let mut tally = Tally::default();
    let mut raw: Vec<u8> = Vec::new();
    loop {
        raw.clear();
        // `read_until` buffers a whole line; a line past the cap is the
        // sink's to copy, unread, in pieces.
        let n = reader
            .by_ref()
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut raw)?;
        if n == 0 {
            break;
        }
        tally.consumed += n as u64;
        if raw.len() > MAX_LINE {
            if let Some(w) = sink.as_deref_mut() {
                w.write_all(&raw)?;
                tally.consumed += io::copy(&mut reader, w)?;
            } else {
                tally.consumed += io::copy(&mut reader, &mut io::sink())?;
            }
            break;
        }
        let body_end = raw.len() - raw.ends_with(b"\n") as usize;
        let body_end = body_end - raw[..body_end].ends_with(b"\r") as usize;
        let changed = std::str::from_utf8(&raw[..body_end])
            .ok()
            .and_then(|line| clean_line(line, &mut |s| cleaner.clean(s, &mut tally)));
        if let Some(w) = sink.as_deref_mut() {
            match changed {
                Some(new) => {
                    w.write_all(new.as_bytes())?;
                    w.write_all(&raw[body_end..])?;
                }
                None => w.write_all(&raw)?,
            }
        }
    }
    Ok(tally)
}

/// What a read-only pass over the file finds.
pub(crate) fn count(path: &Path, cleaner: &Cleaner) -> io::Result<Tally> {
    pass(path, cleaner, None)
}

/// How a rewrite ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Rewrite {
    Done(Tally),
    /// The file changed while being cleaned; nothing was written.
    Changed,
}

fn stamp(path: &Path) -> io::Result<(u64, SystemTime)> {
    let m = std::fs::metadata(path)?;
    Ok((m.len(), m.modified()?))
}

/// What was appended to the file after `read` bytes of it were read, copied to
/// the end of the file now at `path`: the harness may have written to the old
/// file between the last read and the rename. A line the harness was in the
/// middle of writing at that moment is the one thing this cannot save.
fn carry_over(old: &mut File, read: u64, path: &Path) {
    let Ok(len) = old.metadata().map(|m| m.len()) else {
        return;
    };
    if len <= read {
        return;
    }
    let mut tail = Vec::new();
    let copied = old
        .seek(SeekFrom::Start(read))
        .and_then(|_| old.take(len - read).read_to_end(&mut tail));
    if copied.is_ok()
        && let Ok(mut now) = OpenOptions::new().append(true).open(path)
    {
        let _ = now.write_all(&tail);
    }
}

/// Replace `path` with its cleaned self, atomically. The file is read twice
/// (see the module doc); it is only replaced if it is the file the first read
/// saw, so a harness that appended in between loses nothing.
pub(crate) fn rewrite(path: &Path, cleaner: &Cleaner) -> io::Result<Rewrite> {
    let before = stamp(path)?;
    let meta = std::fs::metadata(path)?;
    let mut old = File::open(path)?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.vahta-{}.tmp", std::process::id()));
    let result = (|| -> io::Result<Rewrite> {
        let file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        let mut w = BufWriter::with_capacity(256 * 1024, file);
        let tally = pass_file(old.try_clone()?, cleaner, Some(&mut w))?;
        w.flush()?;
        let file = w.into_inner().map_err(|e| e.into_error())?;
        file.set_permissions(meta.permissions())?;
        // The harness orders and resumes sessions by this time.
        file.set_modified(before.1)?;
        file.sync_all()?;
        drop(file);
        if stamp(path)? != before {
            return Ok(Rewrite::Changed);
        }
        std::fs::rename(&tmp, path)?;
        carry_over(&mut old, tally.consumed, path);
        #[cfg(unix)]
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(Rewrite::Done(tally))
    })();
    if !matches!(result, Ok(Rewrite::Done(_))) {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// How many times a rewrite of a file the harness keeps appending to is tried
/// again when it grew in the meantime.
const APPEND_RETRIES: usize = 5;
/// The largest file [`drop_lines`] holds in memory.
const MAX_DROP_FILE: u64 = 512 * 1024 * 1024;
const APPEND_PAUSE: std::time::Duration = std::time::Duration::from_millis(80);

/// [`rewrite`] for a file that is appended to while it is open (a prompt
/// history): when the harness appended during the pass nothing was replaced, so
/// the pass is made again, a few times. Never replaces a file it did not read in
/// full; the result is [`Rewrite::Changed`] only if it never got a quiet moment.
pub(crate) fn rewrite_retrying(path: &Path, cleaner: &Cleaner) -> io::Result<Rewrite> {
    let mut last = Rewrite::Changed;
    for attempt in 0..APPEND_RETRIES {
        if attempt > 0 {
            std::thread::sleep(APPEND_PAUSE);
        }
        last = rewrite(path, cleaner)?;
        if matches!(last, Rewrite::Done(_)) {
            break;
        }
    }
    Ok(last)
}

/// Replace `path` without the lines for which `drop_line` says so (it gets the
/// line's text, without its terminator; a line that is not UTF-8 is kept).
/// Everything else is copied byte for byte. Atomic like [`rewrite`], and retried
/// like [`rewrite_retrying`] when the harness appended in the meantime. The
/// number of lines dropped; the file is not touched when there are none.
pub(crate) fn drop_lines(path: &Path, drop_line: &dyn Fn(&str) -> bool) -> io::Result<usize> {
    for attempt in 0..APPEND_RETRIES {
        if attempt > 0 {
            std::thread::sleep(APPEND_PAUSE);
        }
        let before = stamp(path)?;
        if before.0 > MAX_DROP_FILE {
            return Err(io::Error::other(
                "the file is too large to rewrite in memory",
            ));
        }
        let meta = std::fs::metadata(path)?;
        let mut old = File::open(path)?;
        let mut kept: Vec<u8> = Vec::new();
        let mut dropped = 0usize;
        let mut consumed = 0u64;
        {
            let mut reader = BufReader::with_capacity(256 * 1024, old.try_clone()?);
            let mut raw: Vec<u8> = Vec::new();
            loop {
                raw.clear();
                let n = reader
                    .by_ref()
                    .take(MAX_LINE as u64 + 1)
                    .read_until(b'\n', &mut raw)?;
                if n == 0 {
                    break;
                }
                consumed += n as u64;
                let body_end = raw.len() - raw.ends_with(b"\n") as usize;
                let body_end = body_end - raw[..body_end].ends_with(b"\r") as usize;
                let gone = raw.len() <= MAX_LINE
                    && std::str::from_utf8(&raw[..body_end]).is_ok_and(drop_line);
                if gone {
                    dropped += 1;
                } else {
                    kept.extend_from_slice(&raw);
                }
            }
        }
        if dropped == 0 {
            return Ok(0);
        }
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let tmp = dir.join(format!(".{name}.vahta-{}.tmp", std::process::id()));
        let done = (|| -> io::Result<bool> {
            let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            file.write_all(&kept)?;
            file.set_permissions(meta.permissions())?;
            file.set_modified(before.1)?;
            file.sync_all()?;
            drop(file);
            if stamp(path)? != before {
                return Ok(false);
            }
            std::fs::rename(&tmp, path)?;
            carry_over(&mut old, consumed, path);
            #[cfg(unix)]
            if let Ok(d) = File::open(dir) {
                let _ = d.sync_all();
            }
            Ok(true)
        })();
        if !matches!(done, Ok(true)) {
            let _ = std::fs::remove_file(&tmp);
        }
        if done? {
            return Ok(dropped);
        }
    }
    Err(io::Error::other("the file kept changing"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cleaner(name: &str, value: &str) -> Cleaner {
        Cleaner::new(&[(name.to_string(), value.as_bytes().to_vec())])
    }

    fn run(c: &Cleaner, line: &str) -> (Option<String>, Tally) {
        let mut t = Tally::default();
        let out = clean_line(line, &mut |s| c.clean(s, &mut t));
        (out, t)
    }

    #[test]
    fn decode_and_escape_agree_with_json() {
        for s in ["plain", "a\"b\\c\nd\te", "é€😀", "\u{1}\u{1f}x", "a/b"] {
            let json = serde_json::to_string(s).unwrap();
            let inner = &json[1..json.len() - 1];
            assert_eq!(decode(inner), s);
            assert_eq!(
                serde_json::from_str::<String>(&format!("\"{}\"", escape(s))).unwrap(),
                s
            );
        }
        assert_eq!(decode("\\u00e9\\ud83d\\ude00\\/"), "é😀/");
        assert_eq!(decode("\\ud83dx"), "\u{FFFD}x");
    }

    #[test]
    fn a_line_without_a_hit_is_not_touched_and_a_hit_keeps_the_rest() {
        let value = ["fake", "-", "value", "-", "1234567"].concat();
        let c = cleaner("TOKEN", &value);
        let clean = r#"{"a":  1.50, "b":["x","y"],"c":{"d":null}}"#;
        assert_eq!(run(&c, clean).0, None);
        let line = format!(r#"{{"z":1.0,"a": "id {value} end","b":true}}"#);
        let (out, t) = run(&c, &line);
        let out = out.unwrap();
        assert_eq!(
            out,
            r#"{"z":1.0,"a": "id ***REDACTED(TOKEN)*** end","b":true}"#
        );
        assert_eq!((t.values, t.patterns), (1, 0));
        assert!(serde_json::from_str::<serde_json::Value>(&out).is_ok());
    }

    #[test]
    fn the_escaped_forms_are_found_in_a_string_and_in_json_inside_a_string() {
        let value = ["fa\"ke", "-quo\\te-", "va\nlue"].concat();
        let c = cleaner("TOKEN", &value);
        let inner = serde_json::to_string(&value).unwrap();
        // As a string field.
        let direct = format!(r#"{{"t":{inner}}}"#);
        let (out, _) = run(&c, &direct);
        assert_eq!(out.unwrap(), r#"{"t":"***REDACTED(TOKEN)***"}"#);
        // A tool result that is JSON text carrying the value.
        let nested = serde_json::to_string(&format!(r#"{{"k":{inner}}}"#)).unwrap();
        let line = format!(r#"{{"result":{nested}}}"#);
        let (out, t) = run(&c, &line);
        let out = out.unwrap();
        assert_eq!(t.values, 1);
        assert!(!out.contains("quo"), "{out}");
        let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(doc["result"].as_str().unwrap().contains("REDACTED(TOKEN)"));
    }

    #[test]
    fn keys_and_unterminated_lines_and_crlf() {
        let value = ["fake", "-key-", "abcdef"].concat();
        let c = cleaner("K", &value);
        let (out, _) = run(&c, &format!(r#"{{"{value}":"v"}}"#));
        assert_eq!(out, None);
        let (out, _) = run(&c, &format!(r#"{{"a":"x {value}"#));
        assert_eq!(out.unwrap(), r#"{"a":"x ***REDACTED(K)***"#);
    }

    #[test]
    fn deep_nesting_is_no_problem() {
        let value = ["fake", "-key-", "abcdef"].concat();
        let c = cleaner("K", &value);
        let line = format!("{}\"{value}\"{}", "[".repeat(5000), "]".repeat(5000));
        let (out, t) = run(&c, &line);
        assert_eq!(t.values, 1);
        assert!(out.unwrap().contains("REDACTED(K)"));
    }

    #[test]
    fn overlapping_values_leave_no_fragment() {
        let c = Cleaner::new(&[
            ("A".to_string(), b"abcdefgh".to_vec()),
            ("B".to_string(), b"efghijkl".to_vec()),
        ]);
        let mut t = Tally::default();
        let out = c.clean("xx abcdefghijkl yy", &mut t).unwrap();
        assert_eq!(out, "xx ***REDACTED(A)*** yy");
    }

    #[test]
    fn a_file_is_rewritten_in_place_keeping_other_lines_and_the_time() {
        let value = ["fake", "-file-", "value-9"].concat();
        let c = cleaner("TOKEN", &value);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s.jsonl");
        let keep = "{\"a\":  1.50,\"b\":\"fine\"}\r\n";
        let hit = format!("{{\"t\":\"{value}\"}}\n");
        let last = "{\"z\":\"no newline at the end\"}";
        std::fs::write(&p, format!("{keep}{hit}{last}")).unwrap();
        let old = SystemTime::now() - std::time::Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert_eq!(count(&p, &c).unwrap().values, 1);
        let r = rewrite(&p, &c).unwrap();
        assert!(matches!(r, Rewrite::Done(t) if t.values == 1));
        let now = std::fs::read_to_string(&p).unwrap();
        assert_eq!(
            now,
            format!("{keep}{{\"t\":\"***REDACTED(TOKEN)***\"}}\n{last}")
        );
        assert_eq!(std::fs::metadata(&p).unwrap().modified().unwrap(), old);
        assert_eq!(count(&p, &c).unwrap().total(), 0);
        // No temp file left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
