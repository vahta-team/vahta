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
//! [`MAX_TRANSCRIPT_BYTES`]) and never stack. Everything else matches Python.
//!
//! JSON inside a string is unwrapped exactly one level, as in Python: only
//! strings of the transcript itself are re-parsed, and a string inside such a
//! document that itself looks like JSON is neither re-parsed nor scanned. That
//! bounds the extra work to one parse per string, so nothing can multiply.

use std::collections::{HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

use vahta_detect::{
    classify_value, is_secret_name, looks_like_json_container, scan_texts, Confidence, HitSet,
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
        std::env::current_dir().map(|c| c.join(path)).unwrap_or_else(|_| path.to_path_buf())
    };
    let mut pending: VecDeque<OsString> = absolute
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            _ => None,
        })
        .collect();
    let mut resolved = PathBuf::from("/");
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
                    resolved = PathBuf::from("/");
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
    candidates.push(home.join(".config").join("claude").join("claude_desktop_config.json"));
    candidates.push(home.join(".config").join("Cursor").join("User").join("mcp.json"));

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
    let Ok(entries) = std::fs::read_dir(dir) else { return };
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
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
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
        let Ok(key) = std::fs::canonicalize(&path) else { return };
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

/// `_apply_secret_keys`: classify secret-named dict keys that never appear as
/// assignment text.
pub fn apply_secret_keys(acc: &mut HitSet, node: &Value) {
    secret_keyed_strings(node, &mut |key, val| {
        let (tier, reason) = classify_value(val);
        if !matches!(tier, Confidence::Likely | Confidence::Possible) {
            return;
        }
        let mut extra = HitSet::default();
        let reasons: Vec<String> = reason.map(|r| vec![r.to_string()]).unwrap_or_default();
        extra.record_assignment(key, tier, &reasons);
        acc.merge(&extra);
    });
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
    let mut acc = HitSet::default();
    let mut nested_objs: Vec<Value> = Vec::new();

    {
        let mut batch: Vec<&str> = Vec::new();
        collect_strings(obj, &mut |s| {
            if looks_like_json_container(s) {
                if let Ok(v) = json::parse(s) {
                    if v.is_container() {
                        nested_objs.push(v);
                        return;
                    }
                }
            }
            batch.push(s);
        });
        if !batch.is_empty() {
            acc.merge(&scan_texts(&batch));
        }
    }

    for nested in &nested_objs {
        let mut batch: Vec<&str> = Vec::new();
        collect_strings(nested, &mut |s| {
            if !looks_like_json_container(s) {
                batch.push(s);
            }
        });
        if !batch.is_empty() {
            acc.merge(&scan_texts(&batch));
        }
    }

    apply_secret_keys(&mut acc, obj);
    for nested in &nested_objs {
        apply_secret_keys(&mut acc, nested);
    }
    acc
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
    mut progress: Option<&mut ProgressFn<'_, E>>,
) -> Result<Vec<Finding>, DeepError<E>> {
    let Ok(meta) = std::fs::metadata(path) else { return Ok(Vec::new()) };
    if meta.len() > MAX_TRANSCRIPT_BYTES {
        return Ok(Vec::new());
    }
    let Ok(bytes) = std::fs::read(path) else { return Ok(Vec::new()) };
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
        let Ok(obj) = json::parse(line) else { continue };
        let hits = scan_transcript_payload(&obj);

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
    mut progress: Option<&mut ProgressFn<'_, E>>,
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
            if finding.kind == "dotenv" && finding.secret_count == 0 && finding.secret_names.is_empty()
            {
                continue;
            }
            findings.push(finding);
        }
    }

    let transcripts = iter_agent_transcript_files(home);
    let total = transcripts.len();
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
            Tree { root: std::fs::canonicalize(&root).expect("canonicalize") }
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
        assert_eq!(lines("a\u{b}b\u{c}c\u{1c}d\u{85}e\u{2028}f"), vec!["a\u{b}b\u{c}c\u{1c}d\u{85}e\u{2028}f"]);
    }

    #[test]
    fn a_line_is_found_and_numbered_from_one() {
        let t = Tree::new("lines");
        let body = format!("\n   \n{{\"text\": \"hello\"}}\nnot json\n{}\n", assignment_line());
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
        let line = format!("{{\"text\": \"{} and {}={}\"}}", prefixed(), name(), LIKELY_VALUE);
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
        let inner = format!("{{\\\"{}\\\": \\\"{}\\\"}}", name().to_lowercase(), LIKELY_VALUE);
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
            &format!("{{\"args\": [{{\"{}\": \"{}\"}}]}}\n", name().to_lowercase(), LIKELY_VALUE),
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
            &format!("{{\"{}\": \"{}\\ud800{}\"}}\n", name().to_lowercase(), "aB3xQ9mK2", "pL7vN4wZ8"),
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
        let p = t.text("session.jsonl", &"{\"t\": \"ok\"}\n".repeat(PROGRESS_LINE_EVERY * 2 + 50));
        let mut calls: Vec<(String, usize, usize)> = Vec::new();
        let mut cb = |s: &str, a: usize, b: usize| -> Result<(), ()> {
            calls.push((s.to_string(), a, b));
            Ok(())
        };
        findings_for_transcript(&p, Scope::Deep, Some(&mut cb)).expect("scan");
        assert_eq!(
            calls,
            vec![("session.jsonl".to_string(), 2000, 0), ("session.jsonl".to_string(), 4000, 0)]
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
    fn a_line_a_million_deep_is_scanned_without_overflowing_the_stack() {
        let t = Tree::new("deep");
        let n = 1_000_000;
        // Arrays, objects, and a secret at the bottom of each.
        let arrays = wrapped_in_arrays(n, &quoted_assignment());
        let objects = format!("{}{}{}", "{\"a\":".repeat(n), quoted_assignment(), "}".repeat(n));
        // A secret-named key whose value is a string, at the bottom.
        let keyed = format!("{}{{\"{}\":\"{LIKELY_VALUE}\"}}{}", "[".repeat(n), name().to_lowercase(), "]".repeat(n));
        // The same inside a string, which is unwrapped and walked.
        let inside = format!("{{\"a\": \"{}\"}}", wrapped_in_arrays(n, &quoted_assignment().replace('"', "\\\"")));
        let p = t.text(
            "s.jsonl",
            &format!("{}\n{arrays}\n{objects}\n{keyed}\n{inside}\n", assignment_line()),
        );
        let found = scan(&p);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].hit_lines, vec![1, 2, 3, 4, 5]);
        assert!(!format!("{found:?}").contains(LIKELY_VALUE));
    }

    #[test]
    fn deep_lines_without_secrets_are_clean_and_do_not_stop_the_scan() {
        let t = Tree::new("deep-clean");
        let deep = wrapped_in_arrays(1_000_000, "1");
        let p = t.text("s.jsonl", &format!("{deep}\n{}\n{deep}\n", assignment_line()));
        assert_eq!(scan(&p)[0].hit_lines, vec![2]);
    }

    #[test]
    fn integers_over_4300_digits_are_numbers_and_the_line_is_scanned() {
        let t = Tree::new("bigint");
        let big = "9".repeat(100_000);
        let top = format!("[{big}, {}]", quoted_assignment());
        let inner = format!("{{\"a\": \"[{big}, {}]\"}}", quoted_assignment().replace('"', "\\\""));
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
            &format!("{{\"a\": \"{}\"}}\n{{\"a\": \"{}\"}}\n{{\"a\": \"{}\"}}\n", q(&level1), q(&level2), q(&level3)),
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
        let home = std::fs::canonicalize(home).expect("canonicalize");
        let mut v: Vec<String> = found
            .iter()
            .map(|p| p.strip_prefix(&home).unwrap_or(p).to_string_lossy().into_owned())
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
    fn a_symlinked_directory_is_not_descended_into_by_the_recursive_glob() {
        let t = Tree::new("symdir");
        let outside = Tree::new("outside");
        outside.text("ext.jsonl", "{}");
        std::fs::create_dir_all(t.root.join(".claude/projects")).expect("mkdir");
        std::os::unix::fs::symlink(&outside.root, t.root.join(".claude/projects/linked")).expect("link");
        assert!(names(&t.root, iter_agent_transcript_files(&t.root)).is_empty());
    }

    #[test]
    fn a_symlinked_session_directory_is_followed_by_the_copilot_glob() {
        let t = Tree::new("copilot-link");
        let outside = Tree::new("copilot-out");
        outside.text("events.jsonl", "{}");
        std::fs::create_dir_all(t.root.join(".copilot/session-state")).expect("mkdir");
        std::os::unix::fs::symlink(&outside.root, t.root.join(".copilot/session-state/via")).expect("link");
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
    fn two_names_for_one_file_yield_the_first_found() {
        let t = Tree::new("alias");
        let real = t.text(".claude/projects/a/real.jsonl", "{}");
        std::os::unix::fs::symlink(&real, t.root.join(".claude/projects/alias.jsonl")).expect("link");
        assert_eq!(iter_agent_transcript_files(&t.root).len(), 1);
    }

    #[test]
    fn a_broken_symlink_is_not_a_transcript() {
        let t = Tree::new("broken");
        std::fs::create_dir_all(t.root.join(".claude/projects")).expect("mkdir");
        std::os::unix::fs::symlink(t.root.join("nowhere"), t.root.join(".claude/projects/b.jsonl")).expect("link");
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
        let home = Path::new("/nonexistent-vahta-home");
        let base = deep_candidate_paths(home, None);
        assert_eq!(base.len(), 11 + 4 + 4);
        assert!(base.contains(&home.join(".env")));
        assert!(base.contains(&home.join(".ssh").join("id_ed25519")));
        assert!(base.contains(&home.join(".config/claude/claude_desktop_config.json")));
        assert_eq!(deep_candidate_paths(home, Some(OsStr::new(""))), base);
        let with = deep_candidate_paths(home, Some(OsStr::new("/appdata")));
        assert_eq!(with.len(), base.len() + 3);
        assert!(with.contains(&PathBuf::from("/appdata/Claude/claude_desktop_config.json")));
        assert!(with.contains(&PathBuf::from("/appdata/Cursor/User/mcp.json")));
        assert!(with.contains(&PathBuf::from(
            "/appdata/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
        )));
    }

    #[test]
    fn resolve_non_strict_handles_links_dots_and_missing_tails() {
        let t = Tree::new("resolve");
        t.text("real/f", "x");
        std::os::unix::fs::symlink(t.root.join("real"), t.root.join("link")).expect("link");
        assert_eq!(resolve_non_strict(&t.root.join("link/f")), t.root.join("real/f"));
        assert_eq!(resolve_non_strict(&t.root.join("real/../real/./f")), t.root.join("real/f"));
        assert_eq!(resolve_non_strict(&t.root.join("link/missing/x")), t.root.join("real/missing/x"));
        assert_eq!(resolve_non_strict(&t.root.join("absent/../real")), t.root.join("real"));
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
        t.text(".claude/projects/p/s.jsonl", &format!("{}\n", assignment_line()));
        t.text(".codex/sessions/rollout-x.jsonl", &format!("{}\n", assignment_line()));
        let found = scan_deep::<()>(&t.root, None, None).expect("scan");
        let kinds: Vec<(&str, &str)> = found.iter().map(|f| (f.kind.as_str(), f.confidence.as_str())).collect();
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
    fn scan_deep_ticks_per_transcript_before_deduplicating() {
        let t = Tree::new("scan-deep-progress");
        let real = t.text(".claude/projects/a/real.jsonl", "{}\n");
        std::os::unix::fs::symlink(&real, t.root.join(".claude/projects/alias.jsonl")).expect("link");
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
        assert_eq!(scan_deep(&t.root, None, Some(&mut cb)).err(), Some(DeepError::Progress("nope")));
    }

    #[test]
    fn the_secret_key_walk_sees_a_pair_before_anything_inside_its_value() {
        let v = json::parse(r#"{"a": {"token": "x"}, "token": "y", "z": [{"password": "w"}]}"#).expect("parse");
        let mut seen: Vec<(String, String)> = Vec::new();
        secret_keyed_strings(&v, &mut |k, s| seen.push((k.to_string(), s.to_string())));
        let expect: Vec<(String, String)> = [("token", "x"), ("token", "y"), ("password", "w")]
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        assert_eq!(seen, expect);
    }
}
