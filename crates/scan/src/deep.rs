//! The `--deep` scan: fixed home-directory candidates plus agent transcripts.
//!
//! A port of `_deep_candidate_paths`, `iter_agent_transcript_files`,
//! `_apply_secret_keys`, `_scan_transcript_payload`, `_findings_for_transcript`
//! and `scan_deep` from `key_amnesia.scan_py`, which remains the specification.
//!
//! Nothing here reads the environment or asks who the user is. The caller
//! supplies the home directory and, for the one Windows-flavoured candidate
//! list, the value of `APPDATA`; the Python bindings obtain those the way
//! Python does (`Path.home()`, `os.environ`), so a test that patches either
//! reaches this code.
//!
//! Never carries secret values: it parses transcripts, hands the strings to
//! the detector, and keeps names, tiers and line numbers.
//!
//! # Where this deliberately diverges from Python
//!
//! Three inputs make Python's transcript scan *raise* instead of skipping the
//! line, because the exception is not a `json.JSONDecodeError`: nesting deeper
//! than about 990 levels (`collect_strings` is a recursive generator),
//! nesting deeper than the JSON scanner tolerates (`RecursionError`), and an
//! integer of more than 4300 digits (`ValueError`). Uncaught, each aborts the
//! whole `ka scan --deep` and discards every finding, so one hostile line hides
//! every other secret, including one on that very line.
//!
//! That is a bug, and it is not reproduced. Such a line is parsed and scanned
//! like any other: the parser, the walkers and the destructor are all
//! iterative, so depth costs heap proportional to the line (which is bounded by
//! [`MAX_TRANSCRIPT_BYTES`]) and never stack. Heap is capped too, by
//! [`MAX_JSON_DEPTH`] and [`MAX_JSON_NODES`]: past either a line is read by a
//! token walk instead of being built into a tree. Everything else matches
//! Python.
//!
//! JSON inside a string is unwrapped exactly one level, as in Python: only
//! strings of the transcript itself are re-parsed, and a string inside such a
//! document that itself looks like JSON is neither re-parsed nor scanned. That
//! bounds the extra work to one parse per string, so nothing can multiply.

use std::collections::{HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use vahta_detect::{
    Confidence, HitSet, classify_value, is_secret_name, looks_like_json_container, scan_text_hits,
    scan_texts,
};

use crate::content::{findings_for_path, path_name, path_str};
use crate::finding::{Finding, Scope};
use crate::json::{self, Value};
use crate::walk::sort_findings;

/// Tick the progress callback every this many JSONL lines (`_PROGRESS_LINE_EVERY`).
pub const PROGRESS_LINE_EVERY: usize = 2000;

/// Transcripts larger than this are not opened (`_MAX_TRANSCRIPT_BYTES`).
pub const MAX_TRANSCRIPT_BYTES: u64 = 100 * 1024 * 1024;

/// Why a deep scan stopped. `E` is whatever the progress callback fails with.
#[derive(Debug, PartialEq, Eq)]
pub enum DeepError<E> {
    /// The progress callback raised; propagated, as in Python.
    Progress(E),
}

/// `progress(stage, done, total)`.
pub type ProgressFn<'a, E> = dyn FnMut(&str, usize, usize) -> Result<(), E> + 'a;

// --- paths -----------------------------------------------------------------

/// `Path.resolve()` (non-strict): symlinks resolved wherever the path exists,
/// the rest appended and normalised. Unlike `fs::canonicalize`, never fails
/// for a path that does not exist.
pub fn resolve_non_strict(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|c| c.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let mut pending: VecDeque<OsString> = absolute
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            _ => None,
        })
        .collect();
    let mut resolved = anchor(&absolute);
    let mut links = 0usize;
    while let Some(part) = pending.pop_front() {
        if part == ".." {
            resolved.pop();
            continue;
        }
        let next = resolved.join(&part);
        let is_link = std::fs::symlink_metadata(&next).is_ok_and(|m| m.file_type().is_symlink());
        if !is_link {
            resolved = next;
            continue;
        }
        links += 1;
        match std::fs::read_link(&next) {
            // A loop: keep the link itself, as Python's non-strict resolve does.
            Ok(_) if links > 40 => resolved = next,
            Ok(target) => {
                if target.is_absolute() {
                    resolved = anchor(&target);
                }
                let mut head: Vec<OsString> = target
                    .components()
                    .filter_map(|c| match c {
                        Component::Normal(n) => Some(n.to_os_string()),
                        Component::ParentDir => Some(OsString::from("..")),
                        _ => None,
                    })
                    .collect();
                while let Some(h) = head.pop() {
                    pending.push_front(h);
                }
            }
            Err(_) => resolved = next,
        }
    }
    resolved
}

/// The prefix and root of an absolute path: `/` on Unix, `C:\\` or a UNC
/// share on Windows. Dropping the prefix would land on the current drive.
fn anchor(path: &Path) -> PathBuf {
    let anchor: PathBuf = path
        .components()
        .take_while(|c| matches!(c, Component::Prefix(_) | Component::RootDir))
        .collect();
    if anchor.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        anchor
    }
}

/// `_deep_candidate_paths`.
///
/// `appdata` is `os.environ.get("APPDATA")`; unset or empty adds nothing.
/// Python iterates a `frozenset` for the SSH key names, so *its* order varies
/// from run to run (hash randomisation); this one is fixed, and `scan_deep`
/// sorts its output, so nothing observable depends on it.
pub fn deep_candidate_paths(home: &Path, appdata: Option<&OsStr>) -> Vec<PathBuf> {
    let home = resolve_non_strict(home);
    let mut candidates: Vec<PathBuf> = Vec::new();

    for name in [
        ".env",
        ".env.local",
        ".npmrc",
        ".pypirc",
        ".gitconfig",
        ".git-credentials",
        ".bash_history",
        ".zsh_history",
        ".zhistory",
        ".python_history",
        ".node_repl_history",
    ] {
        candidates.push(home.join(name));
    }

    let ssh = home.join(".ssh");
    for key_name in ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"] {
        candidates.push(ssh.join(key_name));
    }

    candidates.push(home.join(".cursor").join("mcp.json"));
    candidates.push(home.join(".claude").join("mcp.json"));
    candidates.push(
        home.join(".config")
            .join("claude")
            .join("claude_desktop_config.json"),
    );
    candidates.push(
        home.join(".config")
            .join("Cursor")
            .join("User")
            .join("mcp.json"),
    );

    if let Some(appdata) = appdata.filter(|a| !a.is_empty()) {
        let appdata = Path::new(appdata);
        candidates.push(appdata.join("Claude").join("claude_desktop_config.json"));
        candidates.push(appdata.join("Cursor").join("User").join("mcp.json"));
        candidates.push(
            appdata
                .join("Microsoft")
                .join("Windows")
                .join("PowerShell")
                .join("PSReadLine")
                .join("ConsoleHost_history.txt"),
        );
    }
    candidates
}

/// Entries of `dir` whose name satisfies `matches`, in directory order, as
/// `glob`'s wildcard selector yields them: files, directories, anything.
fn matching_entries(dir: &Path, matches: &dyn Fn(&str) -> bool, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if matches(&entry.file_name().to_string_lossy()) {
            out.push(entry.path());
        }
    }
}

/// `root.rglob(pattern)` in the order CPython 3.14's `pathlib` produces.
///
/// `**` does not follow symlinked directories. A directory's own matches are
/// emitted when its parent discovers it, and the walk then continues from the
/// most recently discovered directory (a stack), so sibling directories are
/// expanded in reverse directory order. Older interpreters walk in a different
/// order; the order is observable only through which of two names for one
/// file survives de-duplication, and through the order of progress messages.
fn rglob(root: &Path, matches: &dyn Fn(&str) -> bool) -> Vec<PathBuf> {
    let mut out = Vec::new();
    matching_entries(root, matches, &mut out);
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            // `entry.is_dir(follow_symlinks=False)`.
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                let path = entry.path();
                matching_entries(&path, matches, &mut out);
                stack.push(path);
            }
        }
    }
    out
}

/// `fnmatch` of `*.jsonl`.
fn is_jsonl(name: &str) -> bool {
    name.ends_with(".jsonl")
}

/// `fnmatch` of `rollout-*.jsonl`: the prefix and suffix may not overlap.
fn is_rollout_jsonl(name: &str) -> bool {
    name.len() >= "rollout-".len() + ".jsonl".len()
        && name.starts_with("rollout-")
        && name.ends_with(".jsonl")
}

/// `iter_agent_transcript_files`: Claude Code, Codex and Copilot CLI session
/// transcripts under `home`. Not a home walk.
pub fn iter_agent_transcript_files(home: &Path) -> Vec<PathBuf> {
    let home = resolve_non_strict(home);
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut out: Vec<PathBuf> = Vec::new();

    let mut emit = |path: PathBuf, out: &mut Vec<PathBuf>| {
        if !path.is_file() {
            return;
        }
        let Ok(key) = std::fs::canonicalize(&path) else {
            return;
        };
        if seen.insert(key) {
            out.push(path);
        }
    };

    let claude_projects = home.join(".claude").join("projects");
    if claude_projects.is_dir() {
        for path in rglob(&claude_projects, &is_jsonl) {
            emit(path, &mut out);
        }
    }

    for sub in ["sessions", "archived_sessions"] {
        let root = home.join(".codex").join(sub);
        if !root.is_dir() {
            continue;
        }
        for path in rglob(&root, &is_rollout_jsonl) {
            emit(path, &mut out);
        }
    }

    // `glob("*/events.jsonl")`: each direct child that is a directory (links
    // followed), then the literal name if it exists at all.
    let copilot_state = home.join(".copilot").join("session-state");
    if copilot_state.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&copilot_state) {
            for entry in entries.flatten() {
                let dir = entry.path();
                if !dir.is_dir() {
                    continue;
                }
                let candidate = dir.join("events.jsonl");
                if std::fs::symlink_metadata(&candidate).is_ok() {
                    emit(candidate, &mut out);
                }
            }
        }
    }
    out
}

// --- the transcript payload -------------------------------------------------

/// `collect_strings`: every string value, pre-order. Iterative, so depth is
/// unlimited.
fn collect_strings<'a>(root: &'a Value, f: &mut dyn FnMut(&'a str)) {
    let mut stack: Vec<&'a Value> = vec![root];
    while let Some(node) = stack.pop() {
        match node {
            Value::Str(s) => f(s),
            Value::Array(items) => stack.extend(items.iter().rev()),
            Value::Object(entries) => stack.extend(entries.iter().rev().map(|(_, v)| v)),
            _ => {}
        }
    }
}

/// `iter_secret_keyed_strings`: `(key, value)` where the key is in the
/// secret-name vocabulary and the value is a string, pre-order, a pair before
/// anything inside its value. Iterative, so depth is unlimited.
fn secret_keyed_strings(root: &Value, f: &mut dyn FnMut(&str, &str)) {
    enum Item<'a> {
        Node(&'a Value),
        Entry(&'a str, &'a Value),
    }
    let mut stack = vec![Item::Node(root)];
    while let Some(item) = stack.pop() {
        match item {
            Item::Node(node) => match node {
                Value::Object(entries) => {
                    stack.extend(entries.iter().rev().map(|(k, v)| Item::Entry(k, v)));
                }
                Value::Array(items) => stack.extend(items.iter().rev().map(Item::Node)),
                _ => {}
            },
            Item::Entry(key, value) => {
                if let Value::Str(s) = value {
                    if is_secret_name(key) {
                        f(key, s);
                    }
                }
                stack.push(Item::Node(value));
            }
        }
    }
}

/// One secret-named key whose string value classified as likely or possible:
/// what `_apply_secret_keys` records, kept so a tree can be dropped before the
/// record is applied. Holds the name, never the value.
type KeyRecord = (String, Confidence, Vec<String>);

fn key_record(key: &str, val: &str) -> Option<KeyRecord> {
    let (tier, reason) = classify_value(val);
    if !matches!(tier, Confidence::Likely | Confidence::Possible) {
        return None;
    }
    let reasons: Vec<String> = reason.map(|r| vec![r.to_string()]).unwrap_or_default();
    Some((key.to_string(), tier, reasons))
}

fn key_records(node: &Value) -> Vec<KeyRecord> {
    let mut out = Vec::new();
    secret_keyed_strings(node, &mut |key, val| out.extend(key_record(key, val)));
    out
}

fn apply_key_records(acc: &mut HitSet, records: &[KeyRecord]) {
    for (key, tier, reasons) in records {
        let mut extra = HitSet::default();
        extra.record_assignment(key, *tier, reasons);
        acc.merge(&extra);
    }
}

/// `_apply_secret_keys`: classify secret-named dict keys that never appear as
/// assignment text.
pub fn apply_secret_keys(acc: &mut HitSet, node: &Value) {
    apply_key_records(acc, &key_records(node));
}

/// How deeply one transcript line (or one JSON document inside a string) may
/// nest before it is no longer parsed.
///
/// An unbounded parse costs heap in proportion to depth: each open container
/// is a frame plus its first element, around 150-200 bytes, so a single
/// 100 MB line of `[` was about 4 GB resident. Capping at one million bounds
/// the parse to roughly 200 MB, however hostile the line, while staying far
/// past anything a real transcript holds (a few dozen levels) and past the
/// depth at which Python itself gives up.
///
/// Over the cap the tree is never built. The line is read without one (see
/// `scan_unparsed_line`), with its hits attributed to the same line number as
/// any parsed line's, so nothing is skipped and the scan does not abort: a key
/// inside a million-deep line is still found, by its prefix, by assignment
/// text, or by a secret-named key, escaped spellings included.
///
/// A line over the cap is not checked for being valid JSON; if it is not, it
/// is still scanned as text, which at worst reports a secret in garbage.
pub const MAX_JSON_DEPTH: usize = 1_000_000;

/// How many values one transcript line (or one JSON document inside a string)
/// may hold before it is no longer parsed into a tree.
///
/// Depth alone does not bound memory: a shallow but wide line, `[1,1,1,...]`,
/// is two bytes of text per value and tens of bytes of tree, so a 100 MB line
/// would be gigabytes. Two million values is a few hundred megabytes at most,
/// and far past a real transcript line. Over it the line takes the same
/// text path as one over [`MAX_JSON_DEPTH`].
pub const MAX_JSON_NODES: usize = 2_000_000;

/// The product's limits for one transcript line.
pub const TRANSCRIPT_LIMITS: json::Limits = json::Limits {
    depth: MAX_JSON_DEPTH,
    nodes: MAX_JSON_NODES,
};

/// What one document unwrapped out of a string contributes: the hits of its
/// strings, and its secret-named keys. Computed as soon as the document is
/// parsed, so the tree is dropped before the next one is built and a line
/// holding thousands of such strings holds one tree at a time.
struct Nested {
    text: Option<HitSet>,
    keys: Vec<KeyRecord>,
}

impl Nested {
    fn of_tree(doc: &Value) -> Nested {
        let mut batch: Vec<&str> = Vec::new();
        collect_strings(doc, &mut |s| {
            if !looks_like_json_container(s) {
                batch.push(s);
            }
        });
        let text = (!batch.is_empty()).then(|| scan_texts(&batch));
        Nested {
            text,
            keys: key_records(doc),
        }
    }

    /// The same, from a token walk, for a document too big to parse. Strings
    /// that again look like JSON are dropped, as from a tree.
    fn of_text(doc: &str) -> Nested {
        let mut text: Option<HitSet> = None;
        let mut keys = Vec::new();
        json::for_each_string(doc, &mut |key, s| {
            if let Some(key) = key.filter(|k| is_secret_name(k)) {
                keys.extend(key_record(key, s));
            }
            if !looks_like_json_container(s) {
                text.get_or_insert_with(HitSet::default)
                    .merge(&scan_text_hits(s));
            }
        });
        Nested { text, keys }
    }
}

/// A document in a string, unwrapped within `limits`; `None` when it is not a
/// JSON container (it is then scanned as text). Past the limits it is read by
/// the token walk instead of being built.
fn unwrap_nested(s: &str, limits: json::Limits) -> Option<Nested> {
    match json::parse_limited(s, limits) {
        Ok(v) if v.is_container() => Some(Nested::of_tree(&v)),
        Ok(_) | Err(json::ParseError::Invalid) => None,
        Err(json::ParseError::TooDeep | json::ParseError::TooMany) => Some(Nested::of_text(s)),
    }
}

fn finish(mut acc: HitSet, nested: &[Nested], top_keys: &[KeyRecord]) -> HitSet {
    for n in nested {
        if let Some(text) = &n.text {
            acc.merge(text);
        }
    }
    apply_key_records(&mut acc, top_keys);
    for n in nested {
        apply_key_records(&mut acc, &n.keys);
    }
    acc
}

/// A transcript line too big to parse into a tree (past [`TRANSCRIPT_LIMITS`]),
/// scanned without one.
///
/// The whole line goes through the detector as text, which reads anything
/// outside strings too, valid JSON or not. Then a token walk scans each decoded
/// string the way a parsed line's strings are scanned — unwrapping strings that
/// hold JSON, and classifying secret-named keys — so a name spelled with a
/// `\\u` escape is found as it would be from the tree. Memory is the largest
/// single string plus one unwrapped document at a time.
fn scan_unparsed_line(line: &str, limits: json::Limits) -> HitSet {
    let mut acc = scan_texts(&[line]);
    let mut text = HitSet::default();
    let mut nested: Vec<Nested> = Vec::new();
    let mut top_keys: Vec<KeyRecord> = Vec::new();
    json::for_each_string(line, &mut |key, s| {
        if let Some(key) = key.filter(|k| is_secret_name(k)) {
            top_keys.extend(key_record(key, s));
        }
        if looks_like_json_container(s) {
            if let Some(n) = unwrap_nested(s, limits) {
                nested.push(n);
                return;
            }
        }
        text.merge(&scan_text_hits(s));
    });
    acc.merge(&finish(text, &nested, &top_keys));
    acc
}

/// `_scan_transcript_payload`: run the detector over a parsed line's strings
/// and its secret-named keys.
///
/// A string that is itself a JSON object or array is unwrapped once and not
/// scanned as text (the assignment matcher on serialised JSON plus the key walk
/// would count it twice); strings of the unwrapped document are scanned, and
/// one of those that again looks like JSON is dropped, as in Python. Never
/// returns values.
pub fn scan_transcript_payload(obj: &Value) -> HitSet {
    scan_transcript_payload_limited(obj, TRANSCRIPT_LIMITS)
}

/// [`scan_transcript_payload`] with the depth limit for strings that hold JSON
/// given explicitly (the node limit stays [`MAX_JSON_NODES`]).
pub fn scan_transcript_payload_bounded(obj: &Value, max_depth: usize) -> HitSet {
    scan_transcript_payload_limited(
        obj,
        json::Limits {
            depth: max_depth,
            nodes: MAX_JSON_NODES,
        },
    )
}

/// [`scan_transcript_payload`] within `limits`. A string holding JSON past
/// them is not built into a tree: it is scanned as text, as before, and also
/// read by the token walk, so its keys and strings still count.
pub fn scan_transcript_payload_limited(obj: &Value, limits: json::Limits) -> HitSet {
    let mut acc = HitSet::default();
    let mut nested: Vec<Nested> = Vec::new();

    let mut batch: Vec<&str> = Vec::new();
    collect_strings(obj, &mut |s| {
        if looks_like_json_container(s) {
            match json::parse_limited(s, limits) {
                Ok(v) if v.is_container() => {
                    nested.push(Nested::of_tree(&v));
                    return;
                }
                Ok(_) | Err(json::ParseError::Invalid) => {}
                Err(json::ParseError::TooDeep | json::ParseError::TooMany) => {
                    nested.push(Nested::of_text(s));
                }
            }
        }
        batch.push(s);
    });
    if !batch.is_empty() {
        acc.merge(&scan_texts(&batch));
    }

    finish(acc, &nested, &key_records(obj))
}

// --- one transcript ----------------------------------------------------------

/// Lines as Python's text-mode iteration yields them: split on `\n`, `\r\n`
/// and a lone `\r`, terminators dropped. Nothing else (`\x0b`, `\x0c`,
/// ` `, ...) ends a line, unlike `str.splitlines`.
fn universal_lines(text: &str) -> impl Iterator<Item = &str> {
    let b = text.as_bytes();
    let mut i = 0usize;
    std::iter::from_fn(move || {
        if i >= b.len() {
            return None;
        }
        let start = i;
        while i < b.len() && b[i] != b'\n' && b[i] != b'\r' {
            i += 1;
        }
        let line = &text[start..i];
        if i < b.len() {
            if b[i] == b'\r' && b.get(i + 1) == Some(&b'\n') {
                i += 2;
            } else {
                i += 1;
            }
        }
        Some(line)
    })
}

/// `_findings_for_transcript`: scan one JSONL session transcript. Names, tiers
/// and line numbers only.
///
/// Read as UTF-8 with invalid bytes replaced (`errors="replace"`), split into
/// lines Python's way, each stripped with `str.strip()`; a line that is blank
/// or is not JSON is skipped. An unreadable file, or one over
/// [`MAX_TRANSCRIPT_BYTES`], gives no findings.
pub fn findings_for_transcript<E>(
    path: &Path,
    scope: Scope,
    progress: Option<&mut ProgressFn<'_, E>>,
) -> Result<Vec<Finding>, DeepError<E>> {
    findings_for_transcript_with_limits(path, scope, progress, TRANSCRIPT_LIMITS)
}

/// [`findings_for_transcript`] with the nesting limit given explicitly (see
/// [`MAX_JSON_DEPTH`]); tests pass a small one rather than building a
/// million-deep line.
pub fn findings_for_transcript_with_depth<E>(
    path: &Path,
    scope: Scope,
    progress: Option<&mut ProgressFn<'_, E>>,
    max_depth: usize,
) -> Result<Vec<Finding>, DeepError<E>> {
    let limits = json::Limits {
        depth: max_depth,
        nodes: MAX_JSON_NODES,
    };
    findings_for_transcript_with_limits(path, scope, progress, limits)
}

/// [`findings_for_transcript`] within explicit `limits`; tests pass small ones.
pub fn findings_for_transcript_with_limits<E>(
    path: &Path,
    scope: Scope,
    mut progress: Option<&mut ProgressFn<'_, E>>,
    limits: json::Limits,
) -> Result<Vec<Finding>, DeepError<E>> {
    let Ok(meta) = std::fs::metadata(path) else {
        return Ok(Vec::new());
    };
    if meta.len() > MAX_TRANSCRIPT_BYTES {
        return Ok(Vec::new());
    }
    let Ok(bytes) = std::fs::read(path) else {
        return Ok(Vec::new());
    };
    let text = String::from_utf8_lossy(&bytes);
    let file_name = path_name(path);

    let mut certain_lines: Vec<usize> = Vec::new();
    let mut likely_lines: Vec<usize> = Vec::new();
    let mut possible_lines: Vec<usize> = Vec::new();
    let mut certain_names: Vec<String> = Vec::new();
    let mut likely_names: Vec<String> = Vec::new();
    let mut possible_names: Vec<String> = Vec::new();
    let mut likely_reasons: Vec<String> = Vec::new();
    let mut possible_reasons: Vec<String> = Vec::new();
    let mut likely_reason_counts: Vec<(String, usize)> = Vec::new();
    let mut possible_reason_counts: Vec<(String, usize)> = Vec::new();
    let mut seen_certain: HashSet<String> = HashSet::new();
    let mut seen_likely: HashSet<String> = HashSet::new();
    let mut seen_possible: HashSet<String> = HashSet::new();

    for (index, raw) in universal_lines(&text).enumerate() {
        let line_no = index + 1;
        if line_no % PROGRESS_LINE_EVERY == 0 {
            if let Some(p) = progress.as_deref_mut() {
                p(&file_name, line_no, 0).map_err(DeepError::Progress)?;
            }
        }
        let line = raw.trim_matches(vahta_detect::is_python_space);
        if line.is_empty() {
            continue;
        }
        let hits = match json::parse_limited(line, limits) {
            Ok(obj) => scan_transcript_payload_limited(&obj, limits),
            Err(json::ParseError::Invalid) => continue,
            // Too big to hold as a tree: scan it without one.
            Err(json::ParseError::TooDeep | json::ParseError::TooMany) => {
                scan_unparsed_line(line, limits)
            }
        };

        let has_certain = hits.prefix.is_some();
        let has_likely = !hits.likely_names.is_empty() || hits.bearer_likely;
        let has_possible = !hits.possible_names.is_empty() || hits.bearer_possible;
        if !has_certain && !has_likely && !has_possible {
            continue;
        }
        if has_certain {
            certain_lines.push(line_no);
            if let Some(prefix) = hits.prefix {
                if seen_certain.insert(prefix.to_string()) {
                    certain_names.push(prefix.to_string());
                }
            }
        }
        if has_likely {
            if !has_certain {
                likely_lines.push(line_no);
            }
            for name in &hits.likely_names {
                let key = name.to_uppercase();
                if seen_likely.contains(&key) || seen_certain.contains(&key) {
                    continue;
                }
                seen_likely.insert(key);
                likely_names.push(name.clone());
            }
            for reason in &hits.likely_reasons {
                if !likely_reasons.contains(reason) {
                    likely_reasons.push(reason.clone());
                }
            }
            for (reason, n) in &hits.likely_reason_counts {
                add_count(&mut likely_reason_counts, reason, *n);
            }
        }
        // Mixed higher-tier lines stay out of the possible hit lines (and so
        // out of `transcript_line_hit_count`), but possible names and reasons
        // are still recorded so histograms stay complete.
        if has_possible {
            if !has_certain && !has_likely {
                possible_lines.push(line_no);
            }
            for name in &hits.possible_names {
                let key = name.to_uppercase();
                if seen_possible.contains(&key)
                    || seen_likely.contains(&key)
                    || seen_certain.contains(&key)
                {
                    continue;
                }
                seen_possible.insert(key);
                possible_names.push(name.clone());
            }
            for reason in &hits.possible_reasons {
                if !possible_reasons.contains(reason) {
                    possible_reasons.push(reason.clone());
                }
            }
            for (reason, n) in &hits.possible_reason_counts {
                add_count(&mut possible_reason_counts, reason, *n);
            }
        }
    }

    const KIND: &str = "agent_session_transcript";
    let mut out: Vec<Finding> = Vec::new();

    if !certain_lines.is_empty() {
        let mut f = Finding::new(path_str(path), KIND, scope);
        f.secret_count = certain_lines.len() as i64;
        f.secret_names = certain_names;
        f.reason = format!(
            "agent session transcript: {} line(s) with vendor-prefix credential-shaped \
             content (advisory; false positives/negatives expected)",
            certain_lines.len()
        );
        f.hit_lines = certain_lines;
        f.confidence = "certain".to_string();
        out.push(f);
    }
    if !likely_lines.is_empty() || !likely_names.is_empty() {
        let reason = if !likely_lines.is_empty() {
            format!(
                "agent session transcript: {} line(s) with likely assignment-shaped content \
                 (advisory; false positives/negatives expected)",
                likely_lines.len()
            )
        } else {
            "agent session transcript: likely assignment-shaped names on higher-confidence lines"
                .to_string()
        };
        let mut f = Finding::new(path_str(path), KIND, scope);
        f.secret_count = likely_lines.len() as i64;
        f.secret_names = likely_names;
        f.reason = reason;
        f.hit_lines = likely_lines;
        f.confidence = "likely".to_string();
        f.reasons = likely_reasons;
        f.reason_counts = likely_reason_counts;
        out.push(f);
    }
    if !possible_lines.is_empty() || !possible_names.is_empty() {
        let reason = if !possible_lines.is_empty() {
            format!(
                "agent session transcript: {} line(s) with possible identifier- or \
                 passphrase-shaped content",
                possible_lines.len()
            )
        } else {
            "agent session transcript: possible identifier- or passphrase-shaped names on \
             higher-confidence lines"
                .to_string()
        };
        let mut f = Finding::new(path_str(path), KIND, scope);
        f.secret_count = possible_lines.len() as i64;
        f.secret_names = possible_names;
        f.reason = reason;
        f.hit_lines = possible_lines;
        f.confidence = "possible".to_string();
        f.reasons = possible_reasons;
        f.reason_counts = possible_reason_counts;
        out.push(f);
    }
    Ok(out)
}

fn add_count(counts: &mut Vec<(String, usize)>, reason: &str, n: usize) {
    match counts.iter_mut().find(|(r, _)| r == reason) {
        Some((_, total)) => *total += n,
        None => counts.push((reason.to_string(), n)),
    }
}

// --- scan_deep ----------------------------------------------------------------

/// `scan_deep`: the fixed home candidates, then every agent transcript.
///
/// `home` is resolved here, as Python resolves it. Candidates are scanned as
/// project files are, de-duplicated by resolved path; transcripts share that
/// de-duplication. `progress("agent transcripts", i, n)` is called once per
/// transcript, **before** it is checked against `seen`, and
/// `progress(file name, line, 0)` every [`PROGRESS_LINE_EVERY`] lines inside
/// one. Sorted by `(path, confidence)` at the end.
pub fn scan_deep<E>(
    home: &Path,
    appdata: Option<&OsStr>,
    progress: Option<&mut ProgressFn<'_, E>>,
) -> Result<Vec<Finding>, DeepError<E>> {
    scan_deep_with_threads(home, appdata, progress, crate::par::default_threads())
}

/// In-flight transcript bytes allowed at once in the parallel path.
const TRANSCRIPT_BUDGET_BYTES: u64 = 512 * 1024 * 1024;

/// What a worker hands back for one transcript.
struct TranscriptResult {
    key: PathBuf,
    /// Line numbers at which the per-file progress callback would have fired.
    ticks: Vec<usize>,
    /// `None` only if the scan was cancelled before it finished.
    findings: Option<Vec<Finding>>,
}

/// [`scan_deep`] on `threads` worker threads. The result and the sequence of
/// `progress` calls (and the error that ends it, if any) do not depend on
/// `threads`.
///
/// Transcripts are scanned by workers that record, rather than make, their
/// progress calls. The calling thread consumes results in file order and
/// replays, for each file, `("agent transcripts", i, n)`, then the de-dup
/// decision, then the recorded line ticks; so `progress` is only ever called
/// from the calling thread, in the sequential order, and the first error stops
/// the replay and cancels work not yet started. The work done for a file that
/// turns out to be a duplicate, or that comes after a failing call, is simply
/// discarded. `threads == 1` is the plain sequential loop.
pub fn scan_deep_with_threads<E>(
    home: &Path,
    appdata: Option<&OsStr>,
    mut progress: Option<&mut ProgressFn<'_, E>>,
    threads: usize,
) -> Result<Vec<Finding>, DeepError<E>> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();

    for path in deep_candidate_paths(home, appdata) {
        if !path.is_file() {
            continue;
        }
        let key = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        if !seen.insert(key) {
            continue;
        }
        for finding in findings_for_path(&path, Scope::Deep) {
            if finding.kind == "dotenv"
                && finding.secret_count == 0
                && finding.secret_names.is_empty()
            {
                continue;
            }
            findings.push(finding);
        }
    }

    let transcripts = iter_agent_transcript_files(home);
    let total = transcripts.len();
    if threads.min(total) <= 1 {
        for (index, path) in transcripts.iter().enumerate() {
            if let Some(p) = progress.as_deref_mut() {
                p("agent transcripts", index + 1, total).map_err(DeepError::Progress)?;
            }
            let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
            if !seen.insert(key) {
                continue;
            }
            for finding in findings_for_transcript(path, Scope::Deep, progress.as_deref_mut())? {
                seen.insert(PathBuf::from(&finding.path));
                findings.push(finding);
            }
        }
    } else {
        let want_ticks = progress.is_some();
        let cancel = AtomicBool::new(false);
        let mut failure: Option<E> = None;
        crate::par::ordered_map(
            &transcripts,
            threads,
            threads * 4,
            TRANSCRIPT_BUDGET_BYTES,
            |p| match std::fs::metadata(p) {
                Ok(m) if m.len() <= MAX_TRANSCRIPT_BYTES => m.len(),
                _ => 0,
            },
            |_, path| {
                let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
                let mut ticks = Vec::new();
                if cancel.load(Ordering::Relaxed) {
                    return TranscriptResult {
                        key,
                        ticks,
                        findings: None,
                    };
                }
                let mut record = |_: &str, line: usize, _: usize| -> Result<(), ()> {
                    ticks.push(line);
                    if cancel.load(Ordering::Relaxed) {
                        Err(())
                    } else {
                        Ok(())
                    }
                };
                let rec: Option<&mut ProgressFn<'_, ()>> =
                    if want_ticks { Some(&mut record) } else { None };
                let found = findings_for_transcript::<()>(path, Scope::Deep, rec).ok();
                TranscriptResult {
                    key,
                    ticks,
                    findings: found,
                }
            },
            |index, mut result| {
                let path = &transcripts[index];
                let mut step = || -> Result<(), E> {
                    if let Some(p) = progress.as_deref_mut() {
                        p("agent transcripts", index + 1, total)?;
                    }
                    if !seen.insert(result.key.clone()) {
                        return Ok(());
                    }
                    if let Some(p) = progress.as_deref_mut() {
                        let name = path_name(path);
                        for line in &result.ticks {
                            p(&name, *line, 0)?;
                        }
                    }
                    // `None` is only produced after `cancel`, which is only set
                    // once this consumer has already stopped.
                    for finding in result.findings.take().unwrap_or_default() {
                        seen.insert(PathBuf::from(&finding.path));
                        findings.push(finding);
                    }
                    Ok(())
                };
                match step() {
                    Ok(()) => true,
                    Err(e) => {
                        failure = Some(e);
                        cancel.store(true, Ordering::Relaxed);
                        false
                    }
                }
            },
        );
        if let Some(e) = failure {
            return Err(DeepError::Progress(e));
        }
    }

    sort_findings(&mut findings);
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temporary tree removed on drop. `tempfile` is not a dependency.
    struct Tree {
        root: PathBuf,
    }

    impl Tree {
        fn new(tag: &str) -> Tree {
            use std::sync::atomic::{AtomicU32, Ordering};
            static SEQ: AtomicU32 = AtomicU32::new(0);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let root = std::env::temp_dir().join(format!(
                "vahta-deep-{tag}-{}-{nanos}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&root).expect("create test root");
            // The scan resolves `home`; start from the resolved form so
            // expected paths compare equal.
            Tree {
                root: dunce::canonicalize(&root).expect("canonicalize"),
            }
        }

        fn write(&self, rel: &str, data: &[u8]) -> PathBuf {
            let p = self.root.join(rel);
            std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
            std::fs::write(&p, data).expect("write");
            p
        }

        fn text(&self, rel: &str, data: &str) -> PathBuf {
            self.write(rel, data.as_bytes())
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    // Credential-shaped values are assembled here, never written as literals.
    fn name() -> String {
        ["API", "_KEY"].concat()
    }
    const LIKELY_VALUE: &str = "aB3xQ9mK2pL7vN4wZ8";
    fn prefixed() -> String {
        ["s", "k-", "ant-", "abcdefghijklmnopqrstuvwxyz0123"].concat()
    }
    fn assignment_line() -> String {
        format!("{{\"text\": \"{}={}\"}}", name(), LIKELY_VALUE)
    }

    fn scan(path: &Path) -> Vec<Finding> {
        findings_for_transcript::<()>(path, Scope::Deep, None).expect("scan")
    }

    fn lines(text: &str) -> Vec<&str> {
        universal_lines(text).collect()
    }

    #[test]
    fn lines_split_on_lf_crlf_and_lone_cr_only() {
        assert_eq!(lines("a\nb\r\nc\rd"), vec!["a", "b", "c", "d"]);
        assert_eq!(lines("a\n"), vec!["a"]);
        assert_eq!(lines("a\n\n"), vec!["a", ""]);
        assert_eq!(lines("\r\n\r\n"), vec!["", ""]);
        assert_eq!(lines(""), Vec::<&str>::new());
        // Not line breaks to a Python file iterator, unlike `splitlines`.
        assert_eq!(
            lines("a\u{b}b\u{c}c\u{1c}d\u{85}e\u{2028}f"),
            vec!["a\u{b}b\u{c}c\u{1c}d\u{85}e\u{2028}f"]
        );
    }

    #[test]
    fn a_line_is_found_and_numbered_from_one() {
        let t = Tree::new("lines");
        let body = format!(
            "\n   \n{{\"text\": \"hello\"}}\nnot json\n{}\n",
            assignment_line()
        );
        let p = t.text("s.jsonl", &body);
        let found = scan(&p);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].confidence, "likely");
        assert_eq!(found[0].hit_lines, vec![5]);
        assert_eq!(found[0].secret_count, 1);
        assert_eq!(found[0].secret_names, vec![name()]);
        assert_eq!(found[0].kind, "agent_session_transcript");
        assert!(!format!("{found:?}").contains(LIKELY_VALUE));
    }

    #[test]
    fn a_lone_cr_and_crlf_both_end_lines() {
        let t = Tree::new("cr");
        let a = assignment_line();
        let p = t.text("s.jsonl", &format!("{{}}\r{{}}\r\n{a}\r"));
        assert_eq!(scan(&p)[0].hit_lines, vec![3]);
    }

    #[test]
    fn nbsp_and_other_unicode_whitespace_is_stripped_before_parsing() {
        let t = Tree::new("pad");
        let a = assignment_line();
        let p = t.text("s.jsonl", &format!("\u{a0}{a}\u{2028}\n\u{b}{a}\u{c}\n"));
        assert_eq!(scan(&p)[0].hit_lines, vec![1, 2]);
    }

    #[test]
    fn a_byte_order_mark_makes_the_first_line_unparseable() {
        let t = Tree::new("bom");
        let a = assignment_line();
        let mut data = vec![0xEF, 0xBB, 0xBF];
        data.extend_from_slice(format!("{a}\n{a}\n").as_bytes());
        let p = t.write("s.jsonl", &data);
        assert_eq!(scan(&p)[0].hit_lines, vec![2]);
    }

    #[test]
    fn invalid_utf8_is_replaced_not_fatal() {
        let t = Tree::new("utf8");
        let a = assignment_line();
        let mut data = b"\xff\xfe{}\n".to_vec();
        data.extend_from_slice(a.as_bytes());
        data.push(b'\n');
        let p = t.write("s.jsonl", &data);
        assert_eq!(scan(&p)[0].hit_lines, vec![2]);
        // ...and inside a string it does not break the line.
        let mut inside = b"{\"text\": \"\xc0\xaf ".to_vec();
        inside.extend_from_slice(format!("{}={}\"}}\n", name(), LIKELY_VALUE).as_bytes());
        let q = t.write("t.jsonl", &inside);
        assert_eq!(scan(&q)[0].hit_lines, vec![1]);
    }

    #[test]
    fn a_vendor_prefix_is_certain_and_outranks_a_name_on_its_line() {
        let t = Tree::new("certain");
        let line = format!(
            "{{\"text\": \"{} and {}={}\"}}",
            prefixed(),
            name(),
            LIKELY_VALUE
        );
        let p = t.text("s.jsonl", &format!("{line}\n"));
        let found = scan(&p);
        let by_conf: Vec<&str> = found.iter().map(|f| f.confidence.as_str()).collect();
        assert_eq!(by_conf, vec!["certain", "likely"]);
        assert_eq!(found[0].hit_lines, vec![1]);
        assert_eq!(found[0].secret_names, vec!["Anthropic-style key"]);
        // The name is on a higher-confidence line: recorded, not counted.
        assert!(found[1].hit_lines.is_empty());
        assert_eq!(found[1].secret_count, 0);
        assert!(found[1].reason.contains("on higher-confidence lines"));
    }

    #[test]
    fn json_inside_a_string_is_unwrapped_once() {
        let t = Tree::new("nested");
        let inner = format!(
            "{{\\\"{}\\\": \\\"{}\\\"}}",
            name().to_lowercase(),
            LIKELY_VALUE
        );
        let p = t.text("s.jsonl", &format!("{{\"content\": \"{inner}\"}}\n"));
        let found = scan(&p);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].hit_lines, vec![1]);
    }

    #[test]
    fn a_secret_named_key_is_found_without_any_assignment_text() {
        let t = Tree::new("key");
        let p = t.text(
            "s.jsonl",
            &format!(
                "{{\"args\": [{{\"{}\": \"{}\"}}]}}\n",
                name().to_lowercase(),
                LIKELY_VALUE
            ),
        );
        assert_eq!(scan(&p)[0].hit_lines, vec![1]);
    }

    #[test]
    fn a_duplicate_key_means_the_last_value_is_the_one_seen() {
        let t = Tree::new("dup");
        let n = name().to_lowercase();
        let hidden = format!("{{\"{n}\": \"{LIKELY_VALUE}\", \"{n}\": \"short\"}}\n");
        let shown = format!("{{\"{n}\": \"short\", \"{n}\": \"{LIKELY_VALUE}\"}}\n");
        assert!(scan(&t.text("a.jsonl", &hidden)).is_empty());
        assert_eq!(scan(&t.text("b.jsonl", &shown))[0].hit_lines, vec![1]);
    }

    #[test]
    fn a_lone_surrogate_in_a_value_does_not_stop_the_scan() {
        let t = Tree::new("surrogate");
        let p = t.text(
            "s.jsonl",
            &format!(
                "{{\"{}\": \"{}\\ud800{}\"}}\n",
                name().to_lowercase(),
                "aB3xQ9mK2",
                "pL7vN4wZ8"
            ),
        );
        assert_eq!(scan(&p)[0].hit_lines, vec![1]);
    }

    #[test]
    fn names_dedup_case_insensitively_across_lines_and_counts_accumulate() {
        let t = Tree::new("dedupe");
        let a = assignment_line();
        let b = a.replace(&name(), &name().to_lowercase());
        let p = t.text("s.jsonl", &format!("{a}\n{b}\n{a}\n"));
        let found = scan(&p);
        assert_eq!(found[0].secret_names.len(), 1);
        assert_eq!(found[0].hit_lines, vec![1, 2, 3]);
        assert_eq!(found[0].secret_count, 3);
    }

    #[test]
    fn progress_ticks_every_2000_lines_with_the_file_name_and_zero_total() {
        let t = Tree::new("progress");
        let p = t.text(
            "session.jsonl",
            &"{\"t\": \"ok\"}\n".repeat(PROGRESS_LINE_EVERY * 2 + 50),
        );
        let mut calls: Vec<(String, usize, usize)> = Vec::new();
        let mut cb = |s: &str, a: usize, b: usize| -> Result<(), ()> {
            calls.push((s.to_string(), a, b));
            Ok(())
        };
        findings_for_transcript(&p, Scope::Deep, Some(&mut cb)).expect("scan");
        assert_eq!(
            calls,
            vec![
                ("session.jsonl".to_string(), 2000, 0),
                ("session.jsonl".to_string(), 4000, 0)
            ]
        );
    }

    #[test]
    fn blank_lines_count_toward_the_progress_cadence() {
        let t = Tree::new("blank");
        let p = t.text("s.jsonl", &"\n".repeat(PROGRESS_LINE_EVERY));
        let mut n = 0;
        let mut cb = |_: &str, _: usize, _: usize| -> Result<(), ()> {
            n += 1;
            Ok(())
        };
        findings_for_transcript(&p, Scope::Deep, Some(&mut cb)).expect("scan");
        assert_eq!(n, 1);
    }

    #[test]
    fn an_error_from_the_progress_callback_stops_the_scan_and_propagates() {
        let t = Tree::new("progress-err");
        let p = t.text("s.jsonl", &"{}\n".repeat(PROGRESS_LINE_EVERY + 1));
        let mut cb = |_: &str, _: usize, _: usize| -> Result<(), &'static str> { Err("boom") };
        let r = findings_for_transcript(&p, Scope::Deep, Some(&mut cb));
        assert_eq!(r.err(), Some(DeepError::Progress("boom")));
    }

    #[test]
    fn an_unreadable_or_missing_transcript_gives_nothing() {
        let t = Tree::new("missing");
        assert!(scan(&t.root.join("nope.jsonl")).is_empty());
        assert!(scan(&t.root).is_empty()); // a directory
    }

    /// `depth` arrays around `inner`.
    fn wrapped_in_arrays(depth: usize, inner: &str) -> String {
        format!("{}{inner}{}", "[".repeat(depth), "]".repeat(depth))
    }

    fn quoted_assignment() -> String {
        format!("\"{}={}\"", name(), LIKELY_VALUE)
    }

    #[test]
    fn a_line_over_the_node_limit_is_read_without_a_tree_and_loses_nothing() {
        let t = Tree::new("wide");
        let lim = json::Limits {
            depth: MAX_JSON_DEPTH,
            nodes: 1000,
        };
        let filler = "1,".repeat(5000);
        // Wide, not deep: an escaped secret-named key, a planted vendor key, and
        // an assignment inside JSON inside a string, past five thousand values.
        let wide = format!(
            "[{filler}{}, \"x {} y\", {}]",
            escaped_key_object(),
            prefixed(),
            serde_free_quote(&format!("{{\"note\": {}}}", quoted_assignment())),
        );
        let p = t.text("w.jsonl", &format!("{{\"t\": \"ok\"}}\n{wide}\n"));
        let found =
            findings_for_transcript_with_limits::<()>(&p, Scope::Deep, None, lim).expect("scan");
        let of = |conf: &str| found.iter().find(|f| f.confidence == conf).expect(conf);
        assert_eq!(of("certain").hit_lines, vec![2]);
        assert_eq!(of("certain").secret_names, vec!["Anthropic-style key"]);
        let roomy =
            findings_for_transcript_with_limits::<()>(&p, Scope::Deep, None, TRANSCRIPT_LIMITS)
                .expect("scan");
        // The token walk finds the same names the parse does.
        let names = |f: &[Finding]| {
            let mut n: Vec<String> = f.iter().flat_map(|x| x.secret_names.clone()).collect();
            n.sort();
            n
        };
        assert_eq!(names(&found), names(&roomy));
        assert!(names(&found).iter().any(|n| n == "API_KEY"));
        assert!(!format!("{found:?}").contains(LIKELY_VALUE));
    }

    /// `s` as a JSON string literal.
    fn serde_free_quote(s: &str) -> String {
        let mut out = String::from("\"");
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }

    #[test]
    fn a_string_holding_json_past_the_limits_is_still_read() {
        let t = Tree::new("nested-wide");
        let lim = json::Limits {
            depth: MAX_JSON_DEPTH,
            nodes: 100,
        };
        let inner = format!("[{}{}]", "1,".repeat(500), escaped_key_object());
        let p = t.text(
            "n.jsonl",
            &format!("{{\"out\": {}}}\n", serde_free_quote(&inner)),
        );
        let found =
            findings_for_transcript_with_limits::<()>(&p, Scope::Deep, None, lim).expect("scan");
        assert!(
            found
                .iter()
                .any(|f| f.secret_names.iter().any(|n| n == "API_KEY")),
            "{found:?}"
        );
    }

    #[test]
    fn a_line_a_million_deep_is_scanned_without_overflowing_the_stack() {
        let t = Tree::new("deep");
        let n = 1_000_000;
        // Arrays, objects, and a secret at the bottom of each.
        let arrays = wrapped_in_arrays(n, &quoted_assignment());
        let objects = format!(
            "{}{}{}",
            "{\"a\":".repeat(n),
            quoted_assignment(),
            "}".repeat(n)
        );
        // A secret-named key whose value is a string, at the bottom.
        let keyed = format!(
            "{}{{\"{}\":\"{LIKELY_VALUE}\"}}{}",
            "[".repeat(n),
            name().to_lowercase(),
            "]".repeat(n)
        );
        // The same inside a string, which is unwrapped and walked.
        let inside = format!(
            "{{\"a\": \"{}\"}}",
            wrapped_in_arrays(n, &quoted_assignment().replace('"', "\\\""))
        );
        let p = t.text(
            "s.jsonl",
            &format!(
                "{}\n{arrays}\n{objects}\n{keyed}\n{inside}\n",
                assignment_line()
            ),
        );
        let found = scan(&p);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].hit_lines, vec![1, 2, 3, 4, 5]);
        assert!(!format!("{found:?}").contains(LIKELY_VALUE));
    }

    fn scan_capped(path: &Path, max_depth: usize) -> Vec<Finding> {
        findings_for_transcript_with_depth::<()>(path, Scope::Deep, None, max_depth).expect("scan")
    }

    /// The name spelled through a JSON escape (`API\u005fKEY`): the decoded key
    /// is `API_KEY`, which the key walk reports, but the raw text spells no
    /// assignment the text matcher could read. A hit on it proves the strings
    /// were decoded — by the parse, or past the cap by the token walk.
    fn escaped_key_object() -> String {
        format!("{{\"API\\u005fKEY\": \"{LIKELY_VALUE}\"}}")
    }

    #[test]
    fn a_line_over_the_cap_is_read_without_a_tree_and_loses_nothing() {
        let t = Tree::new("cap-edge");
        let cap = 50;
        // The object itself is one level: `cap - 1` arrays around it is depth `cap`.
        let at_cap = wrapped_in_arrays(cap - 1, &escaped_key_object());
        let over_cap = wrapped_in_arrays(cap, &escaped_key_object());
        let over_planted = wrapped_in_arrays(cap, &format!("\"x {} y\"", prefixed()));
        let over_assignment = wrapped_in_arrays(cap, &quoted_assignment());
        let p = t.text(
            "s.jsonl",
            &format!("{at_cap}\n{over_cap}\n{over_planted}\n{over_assignment}\n"),
        );
        let found = scan_capped(&p, cap);
        let of = |conf: &str| found.iter().find(|f| f.confidence == conf);

        // Line 1 (at the cap) was parsed; line 2 (over) was token-walked, and
        // the escaped key is read as a key in both.
        let likely = of("likely").expect("likely finding");
        assert_eq!(likely.hit_lines, vec![1, 2, 4]);
        // Line 3: the planted vendor key is found in the fallback, and counted
        // against its own line number like a parsed line's.
        let certain = of("certain").expect("certain finding");
        assert_eq!(certain.hit_lines, vec![3]);
        assert_eq!(certain.secret_names, vec!["Anthropic-style key"]);
        assert!(!format!("{found:?}").contains(LIKELY_VALUE));

        // The same four lines with a roomy cap are all parsed: lines 1 and 2
        // both report the key, and 3 and 4 still hit.
        let roomy = scan_capped(&p, cap + 10);
        let likely = roomy
            .iter()
            .find(|f| f.confidence == "likely")
            .expect("likely");
        assert_eq!(likely.hit_lines, vec![1, 2, 4]);
    }

    #[test]
    fn json_in_a_string_over_the_cap_is_scanned_as_text_not_unwrapped() {
        let t = Tree::new("cap-string");
        let cap = 50;
        let q = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let under = wrapped_in_arrays(cap, &quoted_assignment());
        let over = wrapped_in_arrays(cap + 1, &format!("\"x {} y\"", prefixed()));
        let p = t.text(
            "s.jsonl",
            &format!(
                "{{\"a\": \"{}\"}}\n{{\"a\": \"{}\"}}\n",
                q(&under),
                q(&over)
            ),
        );
        let found = scan_capped(&p, cap);
        let certain = found
            .iter()
            .find(|f| f.confidence == "certain")
            .expect("certain");
        assert_eq!(certain.hit_lines, vec![2]);
        let likely = found
            .iter()
            .find(|f| f.confidence == "likely")
            .expect("likely");
        assert_eq!(likely.hit_lines, vec![1]);
    }

    #[test]
    fn an_over_cap_line_does_not_stop_the_scan_or_hide_its_neighbours() {
        let t = Tree::new("cap-neighbours");
        let cap = 50;
        let hostile = wrapped_in_arrays(cap * 1000, "1");
        let p = t.text(
            "s.jsonl",
            &format!("{}\n{hostile}\n{}\n", assignment_line(), assignment_line()),
        );
        let found = scan_capped(&p, cap);
        assert_eq!(found[0].hit_lines, vec![1, 3]);
    }

    #[test]
    fn a_hundred_thousand_deep_line_over_a_small_cap_never_builds_the_tree() {
        // Memory sanity by construction: the parse stops after `cap` frames, so
        // a line that would need ten million never allocates them. (RSS for a
        // 100 MB line is measured outside the test, from Python.)
        let line = "[".repeat(10_000_000);
        assert_eq!(
            json::parse_bounded(&line, 1000).err(),
            Some(json::ParseError::TooDeep)
        );
        assert_eq!(MAX_JSON_DEPTH, 1_000_000);
    }

    #[test]
    fn deep_lines_without_secrets_are_clean_and_do_not_stop_the_scan() {
        let t = Tree::new("deep-clean");
        let deep = wrapped_in_arrays(1_000_000, "1");
        let p = t.text(
            "s.jsonl",
            &format!("{deep}\n{}\n{deep}\n", assignment_line()),
        );
        assert_eq!(scan(&p)[0].hit_lines, vec![2]);
    }

    #[test]
    fn integers_over_4300_digits_are_numbers_and_the_line_is_scanned() {
        let t = Tree::new("bigint");
        let big = "9".repeat(100_000);
        let top = format!("[{big}, {}]", quoted_assignment());
        let inner = format!(
            "{{\"a\": \"[{big}, {}]\"}}",
            quoted_assignment().replace('"', "\\\"")
        );
        let before = format!("[x, {big}]"); // invalid first: skipped, as in Python
        let p = t.text(
            "s.jsonl",
            &format!("{}\n{top}\n{inner}\n{before}\n[{big}]\n", assignment_line()),
        );
        assert_eq!(scan(&p)[0].hit_lines, vec![1, 2, 3]);
    }

    #[test]
    fn json_in_a_string_is_unwrapped_one_level_only() {
        // As in Python: a string of the unwrapped document that itself looks
        // like JSON is neither parsed again nor scanned, however deep the
        // chain of such strings goes.
        let t = Tree::new("levels");
        let q = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let level1 = format!("{{\"v\": {}}}", quoted_assignment());
        let level2 = format!("{{\"v\": \"{}\"}}", q(&level1));
        let level3 = format!("{{\"v\": \"{}\"}}", q(&level2));
        let p = t.text(
            "s.jsonl",
            &format!(
                "{{\"a\": \"{}\"}}\n{{\"a\": \"{}\"}}\n{{\"a\": \"{}\"}}\n",
                q(&level1),
                q(&level2),
                q(&level3)
            ),
        );
        // One level (line 1) is found; two or more levels (lines 2, 3) are not.
        assert_eq!(scan(&p)[0].hit_lines, vec![1]);
    }

    #[test]
    fn non_json_and_scalar_lines_are_skipped() {
        let t = Tree::new("skip");
        let body = "NaN\n[NaN]\n{'a': 1}\n42\n\"just a string\"\ntrue\n{\"a\": 1,}\n";
        assert!(scan(&t.text("s.jsonl", body)).is_empty());
    }

    // --- locating transcripts ------------------------------------------------

    fn names(home: &Path, found: Vec<PathBuf>) -> Vec<String> {
        let home = dunce::canonicalize(home).expect("canonicalize");
        let mut v: Vec<String> = found
            .iter()
            .map(|p| {
                p.strip_prefix(&home)
                    .unwrap_or(p)
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        v.sort();
        v
    }

    #[test]
    fn the_three_layouts_are_found_and_nothing_else() {
        let t = Tree::new("layouts");
        t.text(".claude/projects/p/a.jsonl", "{}");
        t.text(".claude/projects/p/deep/er/b.jsonl", "{}");
        t.text(".claude/projects/p/c.json", "{}");
        t.text(".claude/projects/.hidden/h.jsonl", "{}");
        t.text(".claude/other/x.jsonl", "{}");
        t.text(".codex/sessions/2026/01/01/rollout-1.jsonl", "{}");
        t.text(".codex/sessions/2026/01/01/other.jsonl", "{}");
        t.text(".codex/archived_sessions/rollout-2.jsonl", "{}");
        t.text(".codex/archived_sessions/rollout-.jsonl", "{}");
        t.text(".codex/archived_sessions/rollout.jsonl", "{}");
        t.text(".copilot/session-state/s1/events.jsonl", "{}");
        t.text(".copilot/session-state/s1/other.jsonl", "{}");
        t.text(".copilot/session-state/events.jsonl", "{}");
        t.text(".copilot/session-state/s2/nested/events.jsonl", "{}");
        let found = names(&t.root, iter_agent_transcript_files(&t.root));
        assert_eq!(
            found,
            vec![
                ".claude/projects/.hidden/h.jsonl",
                ".claude/projects/p/a.jsonl",
                ".claude/projects/p/deep/er/b.jsonl",
                ".codex/archived_sessions/rollout-.jsonl",
                ".codex/archived_sessions/rollout-2.jsonl",
                ".codex/sessions/2026/01/01/rollout-1.jsonl",
                ".copilot/session-state/s1/events.jsonl",
            ]
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_symlinked_directory_is_not_descended_into_by_the_recursive_glob() {
        let t = Tree::new("symdir");
        let outside = Tree::new("outside");
        outside.text("ext.jsonl", "{}");
        std::fs::create_dir_all(t.root.join(".claude/projects")).expect("mkdir");
        std::os::unix::fs::symlink(&outside.root, t.root.join(".claude/projects/linked"))
            .expect("link");
        assert!(names(&t.root, iter_agent_transcript_files(&t.root)).is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn a_symlinked_session_directory_is_followed_by_the_copilot_glob() {
        let t = Tree::new("copilot-link");
        let outside = Tree::new("copilot-out");
        outside.text("events.jsonl", "{}");
        std::fs::create_dir_all(t.root.join(".copilot/session-state")).expect("mkdir");
        std::os::unix::fs::symlink(&outside.root, t.root.join(".copilot/session-state/via"))
            .expect("link");
        assert_eq!(
            names(&t.root, iter_agent_transcript_files(&t.root)),
            vec![".copilot/session-state/via/events.jsonl"]
        );
    }

    #[test]
    fn a_directory_named_like_a_transcript_is_not_one_and_its_contents_still_are() {
        let t = Tree::new("dirname");
        t.text(".claude/projects/odd.jsonl/inner.jsonl", "{}");
        assert_eq!(
            names(&t.root, iter_agent_transcript_files(&t.root)),
            vec![".claude/projects/odd.jsonl/inner.jsonl"]
        );
    }

    #[test]
    #[cfg(unix)]
    fn two_names_for_one_file_yield_the_first_found() {
        let t = Tree::new("alias");
        let real = t.text(".claude/projects/a/real.jsonl", "{}");
        std::os::unix::fs::symlink(&real, t.root.join(".claude/projects/alias.jsonl"))
            .expect("link");
        assert_eq!(iter_agent_transcript_files(&t.root).len(), 1);
    }

    #[test]
    #[cfg(unix)]
    fn a_broken_symlink_is_not_a_transcript() {
        let t = Tree::new("broken");
        std::fs::create_dir_all(t.root.join(".claude/projects")).expect("mkdir");
        std::os::unix::fs::symlink(
            t.root.join("nowhere"),
            t.root.join(".claude/projects/b.jsonl"),
        )
        .expect("link");
        assert!(iter_agent_transcript_files(&t.root).is_empty());
    }

    #[test]
    fn a_missing_home_finds_nothing() {
        let t = Tree::new("nohome");
        assert!(iter_agent_transcript_files(&t.root.join("absent")).is_empty());
    }

    // --- candidates and the whole scan --------------------------------------

    #[test]
    fn candidate_paths_follow_python_and_appdata_adds_three() {
        // Absolute on every platform: a bare `/x` gets the cwd's drive on Windows.
        let home = &std::env::temp_dir().join("nonexistent-vahta-home");
        let base = deep_candidate_paths(home, None);
        assert_eq!(base.len(), 11 + 4 + 4);
        assert!(base.contains(&home.join(".env")));
        assert!(base.contains(&home.join(".ssh").join("id_ed25519")));
        assert!(
            base.contains(
                &home
                    .join(".config")
                    .join("claude")
                    .join("claude_desktop_config.json")
            )
        );
        assert_eq!(deep_candidate_paths(home, Some(OsStr::new(""))), base);
        let with = deep_candidate_paths(home, Some(OsStr::new("/appdata")));
        assert_eq!(with.len(), base.len() + 3);
        assert!(
            with.contains(
                &Path::new("/appdata")
                    .join("Claude")
                    .join("claude_desktop_config.json")
            )
        );
        assert!(
            with.contains(
                &Path::new("/appdata")
                    .join("Cursor")
                    .join("User")
                    .join("mcp.json")
            )
        );
        assert!(
            with.contains(
                &Path::new("/appdata")
                    .join("Microsoft")
                    .join("Windows")
                    .join("PowerShell")
                    .join("PSReadLine")
                    .join("ConsoleHost_history.txt")
            )
        );
    }

    #[test]
    #[cfg(unix)]
    fn resolve_non_strict_handles_links_dots_and_missing_tails() {
        let t = Tree::new("resolve");
        t.text("real/f", "x");
        std::os::unix::fs::symlink(t.root.join("real"), t.root.join("link")).expect("link");
        assert_eq!(
            resolve_non_strict(&t.root.join("link/f")),
            t.root.join("real/f")
        );
        assert_eq!(
            resolve_non_strict(&t.root.join("real/../real/./f")),
            t.root.join("real/f")
        );
        assert_eq!(
            resolve_non_strict(&t.root.join("link/missing/x")),
            t.root.join("real/missing/x")
        );
        assert_eq!(
            resolve_non_strict(&t.root.join("absent/../real")),
            t.root.join("real")
        );
        // A symlink loop does not hang.
        std::os::unix::fs::symlink(t.root.join("loop2"), t.root.join("loop1")).expect("link");
        std::os::unix::fs::symlink(t.root.join("loop1"), t.root.join("loop2")).expect("link");
        let _ = resolve_non_strict(&t.root.join("loop1/x"));
    }

    #[test]
    fn scan_deep_reports_home_files_and_transcripts_sorted() {
        let t = Tree::new("scan-deep");
        t.text(".env", &format!("{}={}\n", name(), LIKELY_VALUE));
        t.text(".ssh/id_rsa", "PRIVATE\n");
        t.text(
            ".claude/projects/p/s.jsonl",
            &format!("{}\n", assignment_line()),
        );
        t.text(
            ".codex/sessions/rollout-x.jsonl",
            &format!("{}\n", assignment_line()),
        );
        let found = scan_deep::<()>(&t.root, None, None).expect("scan");
        let kinds: Vec<(&str, &str)> = found
            .iter()
            .map(|f| (f.kind.as_str(), f.confidence.as_str()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("agent_session_transcript", "likely"),
                ("agent_session_transcript", "likely"),
                ("dotenv", "certain"),
                ("ssh_private_key", "certain"),
            ]
        );
        let paths: Vec<&str> = found.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.windows(2).all(|w| w[0] <= w[1]), "{paths:?}");
        assert!(found.iter().all(|f| f.scope == Scope::Deep));
    }

    #[test]
    #[cfg(unix)]
    fn scan_deep_drops_an_empty_dotenv_and_dedups_a_candidate_symlink() {
        let t = Tree::new("scan-deep-dedup");
        t.text(".env", "# nothing\n");
        t.text(".npmrc", "x\n");
        std::os::unix::fs::symlink(t.root.join(".npmrc"), t.root.join(".pypirc")).expect("link");
        let found = scan_deep::<()>(&t.root, None, None).expect("scan");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, ".npmrc");
    }

    #[test]
    #[cfg(unix)]
    fn scan_deep_ticks_per_transcript_before_deduplicating() {
        let t = Tree::new("scan-deep-progress");
        let real = t.text(".claude/projects/a/real.jsonl", "{}\n");
        std::os::unix::fs::symlink(&real, t.root.join(".claude/projects/alias.jsonl"))
            .expect("link");
        t.text(".claude/projects/b/other.jsonl", "{}\n");
        let mut calls: Vec<(String, usize, usize)> = Vec::new();
        let mut cb = |s: &str, a: usize, b: usize| -> Result<(), ()> {
            calls.push((s.to_string(), a, b));
            Ok(())
        };
        scan_deep(&t.root, None, Some(&mut cb)).expect("scan");
        // De-duplication by resolved path happens while *listing*, so the
        // alias is never counted; the tick still precedes the `seen` check in
        // `scan_deep` itself, which matters only for a transcript that is also
        // a home candidate.
        assert_eq!(
            calls,
            vec![
                ("agent transcripts".to_string(), 1, 2),
                ("agent transcripts".to_string(), 2, 2),
            ]
        );
    }

    #[test]
    fn scan_deep_stops_and_propagates_a_progress_error() {
        let t = Tree::new("scan-deep-error");
        t.text(".claude/projects/a/s.jsonl", "{}\n");
        let mut cb = |_: &str, _: usize, _: usize| -> Result<(), &'static str> { Err("nope") };
        assert_eq!(
            scan_deep(&t.root, None, Some(&mut cb)).err(),
            Some(DeepError::Progress("nope"))
        );
    }

    #[test]
    fn the_secret_key_walk_sees_a_pair_before_anything_inside_its_value() {
        let v = json::parse(r#"{"a": {"token": "x"}, "token": "y", "z": [{"password": "w"}]}"#)
            .expect("parse");
        let mut seen: Vec<(String, String)> = Vec::new();
        secret_keyed_strings(&v, &mut |k, s| seen.push((k.to_string(), s.to_string())));
        let expect: Vec<(String, String)> = [("token", "x"), ("token", "y"), ("password", "w")]
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        assert_eq!(seen, expect);
    }

    // --- parallel determinism ----------------------------------------------

    const THREAD_COUNTS: [usize; 6] = [1, 2, 3, 8, 16, 64];

    /// A fake home with many transcripts of mixed sizes, some with findings,
    /// one symlinked duplicate, and some long enough to tick line progress.
    fn many_transcripts() -> Tree {
        let t = Tree::new("par");
        for n in 0..40usize {
            let lines = match n % 5 {
                0 => PROGRESS_LINE_EVERY * 2 + 7,
                1 => 3,
                2 => PROGRESS_LINE_EVERY + 1,
                _ => 20,
            };
            let mut text = String::new();
            for l in 0..lines {
                if l % 97 == n % 97 && n % 3 != 1 {
                    text.push_str(&assignment_line());
                } else if l % 211 == 5 && n % 4 == 0 {
                    text.push_str(&format!("{{\"t\": \"{}\"}}", prefixed()));
                } else {
                    text.push_str("{\"t\": \"ok\"}");
                }
                text.push('\n');
            }
            t.text(&format!(".claude/projects/p{}/s{n}.jsonl", n % 4), &text);
        }
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink(
                t.root.join(".claude/projects/p0/s0.jsonl"),
                t.root.join(".claude/projects/p1/link.jsonl"),
            );
        }
        t
    }

    type Calls = Vec<(String, usize, usize)>;

    /// Run with `fail_at` (1-based call index that errors, if any).
    fn run(
        t: &Tree,
        threads: usize,
        fail_at: Option<usize>,
    ) -> (Calls, Result<Vec<Finding>, usize>) {
        let mut calls: Calls = Vec::new();
        let result = {
            let mut cb = |s: &str, a: usize, b: usize| -> Result<(), usize> {
                calls.push((s.to_string(), a, b));
                if Some(calls.len()) == fail_at {
                    Err(calls.len())
                } else {
                    Ok(())
                }
            };
            scan_deep_with_threads(&t.root, None, Some(&mut cb), threads)
                .map_err(|DeepError::Progress(e)| e)
        };
        (calls, result)
    }

    #[test]
    fn parallel_deep_scan_matches_sequential_including_progress() {
        let t = many_transcripts();
        let (base_calls, base) = run(&t, 1, None);
        assert!(base_calls.iter().any(|c| c.0 != "agent transcripts"));
        assert!(!base.as_ref().expect("ok").is_empty());
        for _ in 0..3 {
            for &n in &THREAD_COUNTS[1..] {
                let (calls, res) = run(&t, n, None);
                assert_eq!(calls, base_calls, "threads={n}");
                assert_eq!(res, base, "threads={n}");
            }
        }
        // And with no callback at all.
        let none = scan_deep_with_threads::<()>(&t.root, None, None, 8).expect("ok");
        assert_eq!(Ok(none), base);
    }

    #[test]
    fn progress_error_gives_same_calls_and_error_for_every_thread_count() {
        let t = many_transcripts();
        let total = run(&t, 1, None).0.len();
        for k in [1, 2, 3, 7, total / 2, total - 1, total] {
            let base = run(&t, 1, Some(k));
            assert_eq!(base.1, Err(k));
            assert_eq!(base.0.len(), k);
            for &n in &THREAD_COUNTS[1..] {
                assert_eq!(run(&t, n, Some(k)), base, "k={k} threads={n}");
            }
        }
    }
}
