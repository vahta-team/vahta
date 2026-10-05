//! Counting and rendering findings.
//!
//! Ports, from `src/key_amnesia/scan_py.py` (the module held this code as
//! `scan.py` until a dispatcher took that name; the implementation and its
//! line numbers are unchanged):
//!   `_REASON_LABELS` (91), `_REASON_LABEL_ORDER` (98),
//!   `_HIT_LINES_DISPLAY_CAP` (85), `certain_count`/`likely_count`/
//!   `possible_count` (942-950), `transcript_line_hit_count` (956),
//!   `headline` (966), `_location_clause` (980), `_reason_bucket_counts` (1001),
//!   `format_count_summary` (1030), `format_gate_totals` (1055),
//!   `findings_to_json` (1066), `_format_hit_lines` (1096),
//!   `format_human_report` (1108), `importable_findings` (1175),
//!   `format_import_next_line` (1179).
//!
//! Every string here is compared verbatim by the Python suite. Punctuation,
//! the em dashes, the middle dots and the singular/plural switches are the
//! specification, not style.
//!
//! **Never emits secret values.** Everything rendered here comes from a path,
//! a kind, a secret *name*, a reason code or a count.

use crate::filenames::is_dotenv_filename;
use crate::finding::{Finding, Scope, gated_confidences, leak_count};
use crate::{STRICT_CERTAIN, STRICT_HIGH, STRICT_PARANOID};
use std::fs;
use std::path::{Path, PathBuf};

/// `_HIT_LINES_DISPLAY_CAP`: caps the human report's line lists; the full list
/// stays in `--json`.
pub const HIT_LINES_DISPLAY_CAP: usize = 20;

/// Reason codes this module names explicitly, from `detect_py`.
const REASON_UUID: &str = "uuid";
const NAMED_WEAKENING_IDENTIFIER: &str = "identifier";

/// `_REASON_LABEL_ORDER`: the order the summary prints known reasons in. It is
/// neither the order `_REASON_LABELS` is written in nor sorted order.
const REASON_LABEL_ORDER: [&str; 5] = [
    "identifier",
    "word-shaped-passphrase",
    "low-transition",
    "uuid",
    "unconfirmed-mcp-shape",
];

/// `_REASON_LABELS`, with Python's `dict.get(reason, reason)` fallback folded
/// in: an unknown reason code prints as itself.
///
/// Only `word-shaped-passphrase` is actually relabelled, to `passphrase`; the
/// other four map to themselves. Written out in full anyway, because the
/// Python dict is the specification and a future entry belongs here.
fn reason_label(reason: &str) -> &str {
    match reason {
        "identifier" => "identifier",
        "word-shaped-passphrase" => "passphrase",
        "low-transition" => "low-transition",
        "uuid" => "uuid",
        "unconfirmed-mcp-shape" => "unconfirmed-mcp-shape",
        other => other,
    }
}

/// The shared core of `certain_count`, `likely_count` and `possible_count` — a
/// sum of `secret_count`, as `leak_count` is, not a count of findings.
///
/// Compares the raw `confidence` string exactly as Python's `==` does, so a
/// finding with an empty or unrecognised confidence is counted in no tier.
pub fn tier_count(findings: &[Finding], confidence: &str) -> usize {
    findings
        .iter()
        .filter(|f| f.confidence == confidence)
        .map(|f| f.secret_count.max(0) as usize)
        .sum()
}

/// `certain_count`.
pub fn certain_count(findings: &[Finding]) -> usize {
    tier_count(findings, "certain")
}

/// `likely_count`.
pub fn likely_count(findings: &[Finding]) -> usize {
    tier_count(findings, "likely")
}

/// `possible_count`.
pub fn possible_count(findings: &[Finding]) -> usize {
    tier_count(findings, "possible")
}

/// `transcript_line_hit_count`: certain+likely, transcripts only.
///
/// Ungated by `--strict` on purpose — Python hard-codes the two tiers rather
/// than consulting `gated_confidences`, so `--strict paranoid` does not widen
/// this number even though it widens every other total.
pub fn transcript_line_hit_count(findings: &[Finding]) -> usize {
    findings
        .iter()
        .filter(|f| {
            f.kind == "agent_session_transcript"
                && (f.confidence == "certain" || f.confidence == "likely")
        })
        .map(|f| f.secret_count.max(0) as usize)
        .sum()
}

/// `headline`.
pub fn headline(findings: &[Finding], strict: &str) -> String {
    let n = leak_count(findings, strict);
    let unit = if n == 1 { "LEAK" } else { "LEAKs" };
    let plural = if n == 1 { "" } else { "s" };
    format!(
        "{n} {unit} found (--strict {strict}) — your agent can read \
         {n} secret{plural} {clause} (LEAK = Locally Exposed Agent Keys)",
        clause = location_clause(findings, strict),
    )
}

/// `_location_clause`.
fn location_clause(findings: &[Finding], strict: &str) -> String {
    let gate = gated_confidences(strict);
    let gated_sum = |want_project: bool| -> usize {
        findings
            .iter()
            .filter(|f| f.confidence_tier().is_some_and(|c| gate.contains(&c)))
            .filter(|f| (f.scope == Scope::Project) == want_project)
            .map(|f| f.secret_count.max(0) as usize)
            .sum()
    };
    let here = gated_sum(true);
    let away = gated_sum(false);
    // Python tests the truthiness of the two sums. Both are sums of
    // `max(n, 0)`, so zero is the only falsy value either can take.
    if away != 0 && here == 0 {
        return "on this machine, outside this project".to_string();
    }
    if away != 0 && here != 0 {
        return format!("on this machine — {here} in this project, {away} outside it");
    }
    "in this project".to_string()
}

/// Add `n` to `key`'s bucket, appending it in first-seen order — Python's
/// `counts[k] = counts.get(k, 0) + n` over an insertion-ordered dict.
fn bump(counts: &mut Vec<(String, usize)>, key: &str, n: usize) {
    match counts.iter_mut().find(|(k, _)| k == key) {
        Some(entry) => entry.1 += n,
        None => counts.push((key.to_string(), n)),
    }
}

/// `_reason_bucket_counts`. Insertion-ordered like Python's dict, so a `Vec`
/// of pairs rather than a map.
///
/// Three arms for the possible tier, and note that two of them use
/// `max(secret_count, 1)` — **1, not 0** — so a possible finding with a zero
/// count still contributes one to its bucket. The several-reasons arm instead
/// ignores `secret_count` and adds exactly 1 per reason.
///
/// Insertion order is **not observable** in this crate's rendered output.
/// `format_count_summary` is the only caller (in Python too: the sole
/// reference is `scan_py.py:1036`), and it prints `_REASON_LABEL_ORDER` first
/// and `sorted(buckets.items())` for anything left over, so every emitted
/// reason is placed either by a fixed list or by sort order. The accumulated
/// *values* are order-independent as well, being integer addition. Order is
/// preserved regardless, because this function is public and mirrors a Python
/// dict that a test may compare directly.
pub fn reason_bucket_counts(findings: &[Finding]) -> Vec<(String, usize)> {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for f in findings {
        if f.confidence == "possible" {
            if !f.reason_counts.is_empty() {
                for (reason, n) in &f.reason_counts {
                    bump(&mut counts, reason, *n);
                }
            } else if !f.reasons.is_empty() {
                if f.reasons.len() == 1 {
                    bump(&mut counts, &f.reasons[0], f.secret_count.max(1) as usize);
                } else {
                    // Several reasons: one apiece, whatever secret_count says.
                    for reason in &f.reasons {
                        bump(&mut counts, reason, 1);
                    }
                }
            } else {
                bump(
                    &mut counts,
                    NAMED_WEAKENING_IDENTIFIER,
                    f.secret_count.max(1) as usize,
                );
            }
        } else if f.confidence == "likely" && f.reasons.iter().any(|r| r == REASON_UUID) {
            // The likely tier feeds exactly one bucket, uuid, and only when
            // the finding names that reason.
            let n = f
                .reason_counts
                .iter()
                .find(|(k, _)| k == REASON_UUID)
                .map(|(_, n)| *n)
                .unwrap_or_else(|| f.secret_count.max(1) as usize);
            bump(&mut counts, REASON_UUID, n);
        }
    }
    counts
}

/// `format_count_summary`: the always-printed three-count line. Identical at
/// every `--strict`, because none of the three counts is gated.
pub fn format_count_summary(findings: &[Finding]) -> String {
    let base = format!(
        "{} certain · {} likely · {} possible",
        certain_count(findings),
        likely_count(findings),
        possible_count(findings),
    );
    let buckets = reason_bucket_counts(findings);
    if buckets.is_empty() {
        return base;
    }
    let mut parts: Vec<String> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for reason in REASON_LABEL_ORDER {
        if let Some((_, n)) = buckets.iter().find(|(k, _)| k == reason) {
            if *n > 0 {
                parts.push(format!("{} {}", n, reason_label(reason)));
                seen.push(reason);
            }
        }
    }
    // Python sorts `buckets.items()`, i.e. by key then value; keys are unique
    // so it is a sort by key. `sorted()` on `str` orders by code point, which
    // is exactly Rust's `str` ordering — verified against the interpreter,
    // including names differing only in case, where both give 'Z' < '_' < 'a'.
    let mut rest: Vec<&(String, usize)> = buckets.iter().collect();
    rest.sort_by(|a, b| a.0.cmp(&b.0));
    for (reason, n) in rest {
        // Python's guard is `n <= 0`; a bucket value is unsigned here, so only
        // zero can be skipped.
        if seen.contains(&reason.as_str()) || *n == 0 {
            continue;
        }
        parts.push(format!("{} {}", n, reason_label(reason)));
    }
    if parts.is_empty() {
        return base;
    }
    format!("{} ({})", base, parts.join(" · "))
}

/// `format_gate_totals`: the always-printed per-gate totals.
pub fn format_gate_totals(findings: &[Finding]) -> String {
    // Python's `max(len(...), ...)` over the three level names. `len()` on a
    // `str` counts code points, and Rust's `{:<width$}` pads a `&str` by
    // `chars().count()`, so the two agree. The names are ASCII, which makes
    // the width a constant 8 ("paranoid"), but it is computed rather than
    // written down because Python computes it.
    let width = [STRICT_CERTAIN, STRICT_HIGH, STRICT_PARANOID]
        .iter()
        .map(|s| s.chars().count())
        .max()
        .unwrap_or(0);
    let rows = [
        (STRICT_CERTAIN, leak_count(findings, STRICT_CERTAIN)),
        (STRICT_HIGH, leak_count(findings, STRICT_HIGH)),
        (STRICT_PARANOID, leak_count(findings, STRICT_PARANOID)),
    ];
    rows.iter()
        .map(|(name, n)| format!("--strict {name:<width$}  {n}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `_format_hit_lines`.
fn format_hit_lines(hit_lines: &[usize]) -> String {
    if hit_lines.is_empty() {
        return String::new();
    }
    let join = |ns: &[usize]| {
        ns.iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    if hit_lines.len() <= HIT_LINES_DISPLAY_CAP {
        return format!("\n      lines: {}", join(hit_lines));
    }
    let rest = hit_lines.len() - HIT_LINES_DISPLAY_CAP;
    format!(
        "\n      lines: {} (and {} more; see --json)",
        join(&hit_lines[..HIT_LINES_DISPLAY_CAP]),
        rest,
    )
}

/// `format_human_report`.
///
/// `project_root` is Python's `Path`, interpolated into the report by
/// `str(path)`; a `&str` is that string.
pub fn format_human_report(findings: &[Finding], project_root: &str, strict: &str) -> String {
    let mut lines: Vec<String> = vec![
        headline(findings, strict),
        String::new(),
        format_count_summary(findings),
        String::new(),
        format_gate_totals(findings),
        String::new(),
    ];
    let transcript_hits = transcript_line_hit_count(findings);
    if transcript_hits != 0 {
        let unit = if transcript_hits == 1 {
            "LEAK"
        } else {
            "LEAKs"
        };
        lines.push(format!(
            "{transcript_hits} {unit} found in agent session transcripts \
             (line-hits; advisory detection)"
        ));
        lines.push(String::new());
    }
    let gate = gated_confidences(strict);
    // A transcript finding with a zero count is dropped from the listing but
    // still counted above; a zero-count finding of any other kind is listed.
    let listed: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.confidence_tier().is_some_and(|c| gate.contains(&c)))
        .filter(|f| !(f.secret_count == 0 && f.kind == "agent_session_transcript"))
        .collect();
    if listed.is_empty() {
        lines.push("No locally exposed agent keys found under default exclusions.".to_string());
        // Python returns here, so neither "Values are never shown." nor the
        // advisory paragraph appears on an empty report.
        return lines.join("\n");
    }
    if listed.iter().any(|f| f.scope == Scope::Project) {
        lines.push(format!("Project root: {project_root}"));
        lines.push(String::new());
    }
    for (i, f) in listed.iter().enumerate() {
        let i = i + 1;
        let names = if f.secret_names.is_empty() {
            "(filename/presence)".to_string()
        } else {
            f.secret_names.join(", ")
        };
        let extra_reasons = if f.reasons.is_empty() {
            String::new()
        } else {
            format!("  reasons={}", f.reasons.join(","))
        };
        let importable = if f.importable { "  [importable]" } else { "" };
        lines.push(format!(
            "  [{i}] {path}\n      kind={kind}  count={count}  \
             scope={scope}  confidence={confidence}{extra_reasons}\n      \
             names: {names}\n      {reason}{importable}{hit_lines}",
            path = f.path,
            kind = f.kind,
            // The raw value, which Python prints unclamped: a negative count
            // contributes nothing to any total but is shown as it stands.
            count = f.secret_count,
            scope = f.scope.as_str(),
            confidence = f.confidence,
            reason = f.reason,
            hit_lines = format_hit_lines(&f.hit_lines),
        ));
        lines.push(String::new());
    }
    lines.push("Values are never shown.".to_string());
    if let Some(next_line) = format_import_next_line(findings, project_root) {
        lines.push(next_line);
    }
    lines.push(
        "Detection is advisory; false positives and false negatives are \
         expected. Word-shaped passphrases appear under possible, not the \
         default headline count."
            .to_string(),
    );
    lines.join("\n")
}

/// `importable_findings`.
pub fn importable_findings(findings: &[Finding]) -> Vec<&Finding> {
    findings
        .iter()
        .filter(|f| f.importable && f.secret_count > 0)
        .collect()
}

/// Python's `Path.resolve()`, which is non-strict: it resolves symlinks in
/// whatever prefix exists and appends the rest rather than failing.
///
/// `fs::canonicalize` alone is not that — it errors on a missing path, which
/// would send `format_import_next_line` down its fallback branch where Python
/// still produces a relative display path. Verified against the interpreter:
/// `Path("/tmp/definitely/does/not/exist/xyz/.env").resolve()` returns the
/// path unchanged, and `Path("/tmp/a/../b/.env").resolve()` returns
/// `/tmp/b/.env`, so `..` is normalised even through missing components.
fn resolve_lenient(p: &Path) -> PathBuf {
    if let Ok(real) = fs::canonicalize(p) {
        return real;
    }
    // Absolutise against the working directory, as `resolve()` does.
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(p),
            Err(_) => p.to_path_buf(),
        }
    };
    // Normalise `.` and `..` lexically.
    let mut norm = PathBuf::new();
    for component in abs.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                norm.pop();
            }
            other => norm.push(other.as_os_str()),
        }
    }
    // Resolve symlinks in the longest existing ancestor, keep the rest as is.
    for ancestor in norm.ancestors() {
        if let Ok(real) = fs::canonicalize(ancestor) {
            return match norm.strip_prefix(ancestor) {
                Ok(rest) => real.join(rest),
                Err(_) => norm,
            };
        }
    }
    norm
}

/// `format_import_next_line`: a `ka import` hint built only from dotenv paths
/// this scan discovered.
///
/// Uses `Finding.path` from the scan — never agent-supplied text — and emits
/// paths only, never a value.
pub fn format_import_next_line(findings: &[Finding], project_root: &str) -> Option<String> {
    let root = resolve_lenient(Path::new(project_root));
    let mut parts: Vec<String> = Vec::new();
    for f in importable_findings(findings) {
        let p = Path::new(&f.path);
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned());
        if !name.is_some_and(|n| is_dotenv_filename(&n)) {
            continue;
        }
        // Python catches ValueError from `relative_to` and falls back to the
        // *unresolved* path, not the resolved one.
        let display = match resolve_lenient(p).strip_prefix(&root) {
            Ok(rest) => {
                let rest = rest.to_string_lossy();
                // `Path.relative_to` returns `Path('.')` when the two paths
                // are equal and `as_posix()` renders that as "."; Rust's
                // `strip_prefix` yields an empty path for the same case.
                if rest.is_empty() {
                    ".".to_string()
                } else {
                    rest.into_owned()
                }
            }
            Err(_) => p.to_string_lossy().into_owned(),
        };
        parts.push(display);
    }
    if parts.is_empty() {
        return None;
    }
    Some(format!(
        "Next: in your own terminal, ka import {}",
        parts.join(" ")
    ))
}

/// Append `s` as a JSON string literal, matching `json.dumps`'s defaults.
///
/// `ensure_ascii` is on by default and the CLI does not turn it off, so every
/// code point above `~` is escaped: a non-ASCII secret *name* or path becomes
/// `\uXXXX`, and a character outside the BMP becomes a UTF-16 surrogate pair.
/// Verified against the interpreter: Cyrillic `ключ` becomes
/// `ключ`, `U+1F511` becomes `🔑`, `U+2028`
/// becomes ` `, DEL becomes `\u007f` (0x7f is escaped, being above `~`),
/// and tab and newline keep their short forms. Hex digits are lower case.
fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        let cp = ch as u32;
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            _ if cp < 0x20 => out.push_str(&format!("\\u{cp:04x}")),
            // 0x20..=0x7e go through literally.
            _ if cp < 0x7f => out.push(ch),
            _ if cp <= 0xffff => out.push_str(&format!("\\u{cp:04x}")),
            _ => {
                let v = cp - 0x1_0000;
                let hi = 0xd800 + (v >> 10);
                let lo = 0xdc00 + (v & 0x3ff);
                out.push_str(&format!("\\u{hi:04x}\\u{lo:04x}"));
            }
        }
    }
    out.push('"');
}

/// Open one `"key": ` at a given indent.
fn push_key(out: &mut String, indent: &str, key: &str) {
    out.push_str(indent);
    push_json_string(out, key);
    out.push_str(": ");
}

/// `findings_to_json`, already serialised.
///
/// Python returns a `dict` and `cli.py` prints `json.dumps(obj, indent=2)`;
/// this returns that text, without the trailing newline the CLI adds.
/// `sort_keys` is **off** at that call site, so keys appear in the order the
/// dict literal writes them and each finding in dataclass field order. With
/// `indent=2` an empty list or dict still renders inline as `[]` / `{}`. The
/// crate has no serialiser and must keep having none, so the text is emitted
/// by hand.
pub fn findings_to_json(findings: &[Finding], project_root: &str, strict: &str) -> String {
    let mut out = String::new();
    out.push_str("{\n");

    for (key, n) in [
        ("leak_count", leak_count(findings, strict)),
        ("certain_count", certain_count(findings)),
        ("likely_count", likely_count(findings)),
        ("possible_count", possible_count(findings)),
        ("strict_certain", leak_count(findings, STRICT_CERTAIN)),
        ("strict_high", leak_count(findings, STRICT_HIGH)),
        ("strict_paranoid", leak_count(findings, STRICT_PARANOID)),
        ("transcript_line_hits", transcript_line_hit_count(findings)),
    ] {
        push_key(&mut out, "  ", key);
        out.push_str(&format!("{n},\n"));
    }

    push_key(&mut out, "  ", "headline");
    push_json_string(&mut out, &headline(findings, strict));
    out.push_str(",\n");

    push_key(&mut out, "  ", "strict");
    push_json_string(&mut out, strict);
    out.push_str(",\n");

    push_key(&mut out, "  ", "project_root");
    push_json_string(&mut out, project_root);
    out.push_str(",\n");

    push_key(&mut out, "  ", "findings");
    if findings.is_empty() {
        out.push_str("[]");
    } else {
        out.push_str("[\n");
        for (i, f) in findings.iter().enumerate() {
            push_finding_json(&mut out, f);
            if i + 1 < findings.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  ]");
    }
    out.push_str(",\n");

    push_key(&mut out, "  ", "detection_note");
    push_json_string(
        &mut out,
        &format!(
            "Advisory heuristics; leak_count matches the --strict gate \
             ({strict}). certain_count / likely_count / possible_count are \
             ungated. Per-finding confidence and reasons are always present. \
             Values are never included."
        ),
    );
    out.push('\n');

    out.push('}');
    out
}

/// One `asdict(Finding)`. At `indent=2`, a list element of a top-level key
/// opens at 4 spaces, its keys sit at 6 and its own list items at 8.
fn push_finding_json(out: &mut String, f: &Finding) {
    out.push_str("    {\n");

    push_key(out, "      ", "path");
    push_json_string(out, &f.path);
    out.push_str(",\n");

    push_key(out, "      ", "kind");
    push_json_string(out, &f.kind);
    out.push_str(",\n");

    push_key(out, "      ", "secret_names");
    push_string_array(out, &f.secret_names);
    out.push_str(",\n");

    push_key(out, "      ", "secret_count");
    out.push_str(&f.secret_count.to_string());
    out.push_str(",\n");

    push_key(out, "      ", "reason");
    push_json_string(out, &f.reason);
    out.push_str(",\n");

    push_key(out, "      ", "importable");
    out.push_str(if f.importable { "true" } else { "false" });
    out.push_str(",\n");

    push_key(out, "      ", "scope");
    push_json_string(out, f.scope.as_str());
    out.push_str(",\n");

    push_key(out, "      ", "hit_lines");
    if f.hit_lines.is_empty() {
        out.push_str("[]");
    } else {
        out.push_str("[\n");
        for (i, n) in f.hit_lines.iter().enumerate() {
            out.push_str("        ");
            out.push_str(&n.to_string());
            if i + 1 < f.hit_lines.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("      ]");
    }
    out.push_str(",\n");

    push_key(out, "      ", "confidence");
    push_json_string(out, &f.confidence);
    out.push_str(",\n");

    push_key(out, "      ", "reasons");
    push_string_array(out, &f.reasons);
    out.push_str(",\n");

    push_key(out, "      ", "reason_counts");
    if f.reason_counts.is_empty() {
        out.push_str("{}");
    } else {
        out.push_str("{\n");
        for (i, (k, n)) in f.reason_counts.iter().enumerate() {
            push_key(out, "        ", k);
            out.push_str(&n.to_string());
            if i + 1 < f.reason_counts.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("      }");
    }
    out.push('\n');

    out.push_str("    }");
}

/// A `list[str]` field of a finding: inline when empty, one item per line at 8
/// spaces otherwise.
fn push_string_array(out: &mut String, items: &[String]) {
    if items.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (i, item) in items.iter().enumerate() {
        out.push_str("        ");
        push_json_string(out, item);
        if i + 1 < items.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("      ]");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deliberately distinct counts and names: equal ones would let a count of
    /// findings pass for a sum of secrets.
    fn f(path: &str, kind: &str, conf: &str, count: i64, scope: Scope) -> Finding {
        let mut x = Finding::new(path, kind, scope);
        x.confidence = conf.to_string();
        x.secret_count = count;
        x.reason = format!("{kind} reason");
        x
    }

    // --- counting ---

    #[test]
    fn tier_counts_sum_secret_counts_per_tier() {
        let all = [
            f("/a", "dotenv", "certain", 3, Scope::Project),
            f("/b", "inline", "likely", 5, Scope::Project),
            f("/c", "inline", "possible", 7, Scope::Deep),
            f("/d", "inline", "certain", 2, Scope::Deep),
        ];
        assert_eq!(certain_count(&all), 5);
        assert_eq!(likely_count(&all), 5);
        assert_eq!(possible_count(&all), 7);
    }

    #[test]
    fn a_blank_confidence_counts_in_no_tier() {
        let mut x = Finding::new("/a", "dotenv", Scope::Project);
        x.secret_count = 9;
        assert_eq!(certain_count(&[x.clone()]), 0);
        assert_eq!(likely_count(&[x.clone()]), 0);
        assert_eq!(possible_count(&[x]), 0);
    }

    #[test]
    fn a_negative_count_contributes_nothing_to_a_tier() {
        let all = [
            f("/a", "dotenv", "certain", -4, Scope::Project),
            f("/b", "dotenv", "certain", 6, Scope::Project),
        ];
        assert_eq!(certain_count(&all), 6);
    }

    #[test]
    fn transcript_hits_cover_certain_and_likely_only() {
        let all = [
            f("/t1", "agent_session_transcript", "certain", 4, Scope::Deep),
            f("/t2", "agent_session_transcript", "likely", 3, Scope::Deep),
            f(
                "/t3",
                "agent_session_transcript",
                "possible",
                9,
                Scope::Deep,
            ),
            f("/other", "dotenv", "certain", 11, Scope::Project),
        ];
        assert_eq!(transcript_line_hit_count(&all), 7);
    }

    // --- headline. Expected strings taken from the Python interpreter. ---

    #[test]
    fn headline_empty() {
        assert_eq!(
            headline(&[], STRICT_HIGH),
            "0 LEAKs found (--strict high) — your agent can read 0 secrets \
             in this project (LEAK = Locally Exposed Agent Keys)"
        );
    }

    #[test]
    fn headline_singular_switches_both_words() {
        let all = [f("/a", "dotenv", "certain", 1, Scope::Project)];
        assert_eq!(
            headline(&all, STRICT_HIGH),
            "1 LEAK found (--strict high) — your agent can read 1 secret \
             in this project (LEAK = Locally Exposed Agent Keys)"
        );
    }

    #[test]
    fn headline_deep_only_says_outside_this_project() {
        let all = [f("/a", "inline", "certain", 4, Scope::Deep)];
        assert_eq!(
            headline(&all, STRICT_HIGH),
            "4 LEAKs found (--strict high) — your agent can read 4 secrets \
             on this machine, outside this project \
             (LEAK = Locally Exposed Agent Keys)"
        );
    }

    #[test]
    fn headline_mixed_scopes_splits_the_count() {
        let all = [
            f("/a", "inline", "certain", 2, Scope::Project),
            f("/b", "inline", "certain", 3, Scope::Deep),
        ];
        assert_eq!(
            headline(&all, STRICT_HIGH),
            "5 LEAKs found (--strict high) — your agent can read 5 secrets \
             on this machine — 2 in this project, 3 outside it \
             (LEAK = Locally Exposed Agent Keys)"
        );
    }

    #[test]
    fn headline_names_the_strict_level_it_was_given() {
        let all = [f("/a", "inline", "possible", 6, Scope::Project)];
        assert_eq!(
            headline(&all, STRICT_PARANOID),
            "6 LEAKs found (--strict paranoid) — your agent can read \
             6 secrets in this project (LEAK = Locally Exposed Agent Keys)"
        );
        assert_eq!(
            headline(&all, STRICT_CERTAIN),
            "0 LEAKs found (--strict certain) — your agent can read \
             0 secrets in this project (LEAK = Locally Exposed Agent Keys)"
        );
    }

    // --- reason buckets ---

    #[test]
    fn reason_counts_win_over_reasons() {
        let mut x = f("/a", "inline", "possible", 5, Scope::Project);
        x.reasons = vec!["identifier".into(), "uuid".into()];
        x.reason_counts = vec![("uuid".into(), 2), ("low-transition".into(), 3)];
        assert_eq!(
            reason_bucket_counts(&[x]),
            vec![("uuid".to_string(), 2), ("low-transition".to_string(), 3)]
        );
    }

    /// One reason uses `max(secret_count, 1)`; several use one apiece. The
    /// difference between the two arms is the whole point of the branch.
    #[test]
    fn one_reason_takes_the_count_and_several_take_one_each() {
        let mut one = f("/a", "inline", "possible", 5, Scope::Project);
        one.reasons = vec!["low-transition".into()];
        assert_eq!(
            reason_bucket_counts(&[one]),
            vec![("low-transition".to_string(), 5)]
        );

        let mut many = f("/b", "inline", "possible", 5, Scope::Project);
        many.reasons = vec!["low-transition".into(), "identifier".into()];
        assert_eq!(
            reason_bucket_counts(&[many]),
            vec![
                ("low-transition".to_string(), 1),
                ("identifier".to_string(), 1)
            ]
        );
    }

    #[test]
    fn a_zero_count_possible_finding_still_contributes_one() {
        let mut one = f("/a", "inline", "possible", 0, Scope::Project);
        one.reasons = vec!["uuid".into()];
        assert_eq!(reason_bucket_counts(&[one]), vec![("uuid".to_string(), 1)]);

        // With no reasons at all it falls into the identifier bucket instead.
        let none = f("/b", "inline", "possible", 0, Scope::Project);
        assert_eq!(
            reason_bucket_counts(&[none]),
            vec![("identifier".to_string(), 1)]
        );
    }

    #[test]
    fn a_possible_finding_with_no_reasons_defaults_to_identifier() {
        let none = f("/b", "inline", "possible", 4, Scope::Project);
        assert_eq!(
            reason_bucket_counts(&[none]),
            vec![("identifier".to_string(), 4)]
        );
    }

    #[test]
    fn a_likely_finding_contributes_only_through_uuid() {
        let mut uuid = f("/a", "inline", "likely", 3, Scope::Project);
        uuid.reasons = vec!["uuid".into()];
        assert_eq!(reason_bucket_counts(&[uuid]), vec![("uuid".to_string(), 3)]);

        // A likely finding naming some other reason contributes nothing.
        let mut other = f("/b", "inline", "likely", 3, Scope::Project);
        other.reasons = vec!["low-transition".into()];
        assert!(reason_bucket_counts(&[other]).is_empty());

        // A certain finding never contributes, uuid or not.
        let mut certain = f("/c", "inline", "certain", 3, Scope::Project);
        certain.reasons = vec!["uuid".into()];
        assert!(reason_bucket_counts(&[certain]).is_empty());
    }

    #[test]
    fn a_likely_uuid_finding_prefers_its_reason_count() {
        let mut uuid = f("/a", "inline", "likely", 3, Scope::Project);
        uuid.reasons = vec!["uuid".into()];
        uuid.reason_counts = vec![("uuid".into(), 9)];
        assert_eq!(reason_bucket_counts(&[uuid]), vec![("uuid".to_string(), 9)]);
    }

    // --- summary and gate totals, verbatim from Python ---

    #[test]
    fn count_summary_without_buckets_is_the_bare_three_counts() {
        let all = [
            f("/a", "dotenv", "certain", 3, Scope::Project),
            f("/b", "inline", "likely", 5, Scope::Project),
        ];
        assert_eq!(
            format_count_summary(&all),
            "3 certain · 5 likely · 0 possible"
        );
    }

    /// The label order is `_REASON_LABEL_ORDER` — identifier, passphrase,
    /// low-transition, uuid — which is neither insertion order nor sorted. The
    /// findings go in deliberately reversed against the printed order.
    #[test]
    fn count_summary_prints_known_reasons_in_label_order() {
        let mut a = f("/a", "inline", "possible", 2, Scope::Project);
        a.reasons = vec!["uuid".into()];
        let mut b = f("/b", "inline", "possible", 3, Scope::Project);
        b.reasons = vec!["low-transition".into()];
        let mut c = f("/c", "inline", "possible", 4, Scope::Project);
        c.reasons = vec!["word-shaped-passphrase".into()];
        let mut d = f("/d", "inline", "possible", 5, Scope::Project);
        d.reasons = vec!["identifier".into()];
        let all = [a, b, c, d];
        assert_eq!(
            format_count_summary(&all),
            "0 certain · 0 likely · 14 possible \
             (5 identifier · 4 passphrase · 3 low-transition · 2 uuid)"
        );
    }

    /// An unknown reason code prints as itself, after every known one, in
    /// sorted order.
    #[test]
    fn count_summary_sorts_unknown_reasons_after_known_ones() {
        let mut a = f("/a", "inline", "possible", 2, Scope::Project);
        a.reasons = vec!["zzz-unknown".into()];
        let mut b = f("/b", "inline", "possible", 3, Scope::Project);
        b.reasons = vec!["aaa-unknown".into()];
        let mut c = f("/c", "inline", "possible", 4, Scope::Project);
        c.reasons = vec!["uuid".into()];
        let all = [a, b, c];
        assert_eq!(
            format_count_summary(&all),
            "0 certain · 0 likely · 9 possible \
             (4 uuid · 3 aaa-unknown · 2 zzz-unknown)"
        );
    }

    #[test]
    fn gate_totals_pad_the_level_names_to_a_common_width() {
        let all = [
            f("/a", "dotenv", "certain", 3, Scope::Project),
            f("/b", "inline", "likely", 5, Scope::Project),
            f("/c", "inline", "possible", 7, Scope::Deep),
        ];
        assert_eq!(
            format_gate_totals(&all),
            "--strict certain   3\n--strict high      8\n--strict paranoid  15"
        );
    }

    // --- hit lines ---

    #[test]
    fn hit_lines_under_the_cap_are_listed_in_full() {
        let mut x = f("/t", "agent_session_transcript", "certain", 3, Scope::Deep);
        x.hit_lines = vec![2, 7, 19];
        let report = format_human_report(&[x], "/proj", STRICT_HIGH);
        assert!(report.contains("\n      lines: 2, 7, 19"), "{report}");
        assert!(!report.contains("more; see --json"), "{report}");
    }

    #[test]
    fn hit_lines_over_the_cap_are_truncated_with_a_remainder() {
        let mut x = f("/t", "agent_session_transcript", "certain", 3, Scope::Deep);
        x.hit_lines = (1..=23).collect();
        let report = format_human_report(&[x], "/proj", STRICT_HIGH);
        assert!(
            report.contains(
                "\n      lines: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, \
                 14, 15, 16, 17, 18, 19, 20 (and 3 more; see --json)"
            ),
            "{report}"
        );
    }

    // --- human report ---

    #[test]
    fn an_empty_report_stops_after_the_no_keys_line() {
        assert_eq!(
            format_human_report(&[], "/proj", STRICT_HIGH),
            "0 LEAKs found (--strict high) — your agent can read 0 secrets \
             in this project (LEAK = Locally Exposed Agent Keys)\n\
             \n\
             0 certain · 0 likely · 0 possible\n\
             \n\
             --strict certain   0\n\
             --strict high      0\n\
             --strict paranoid  0\n\
             \n\
             No locally exposed agent keys found under default exclusions."
        );
    }

    /// `Project root:` appears only when something listed is project-scoped.
    #[test]
    fn project_root_is_omitted_for_a_deep_only_report() {
        let all = [f("/x", "inline", "certain", 1, Scope::Deep)];
        let report = format_human_report(&all, "/proj", STRICT_HIGH);
        assert!(!report.contains("Project root:"), "{report}");
        let mixed = [
            f("/x", "inline", "certain", 1, Scope::Project),
            f("/y", "inline", "certain", 1, Scope::Deep),
        ];
        assert!(format_human_report(&mixed, "/proj", STRICT_HIGH).contains("Project root: /proj"));
    }

    #[test]
    fn a_finding_without_names_says_filename_presence() {
        let all = [f(
            "/home/u/.ssh/id_rsa",
            "ssh_private_key",
            "certain",
            1,
            Scope::Deep,
        )];
        let report = format_human_report(&all, "/proj", STRICT_HIGH);
        assert!(
            report.contains("\n      names: (filename/presence)"),
            "{report}"
        );
    }

    /// The whole listing block for one finding, verbatim.
    #[test]
    fn a_listed_finding_renders_every_field() {
        let mut x = f("/proj/.env", "dotenv", "possible", 2, Scope::Project);
        x.secret_names = vec!["ALPHA".into(), "BETA".into()];
        x.importable = true;
        x.reasons = vec!["identifier".into(), "uuid".into()];
        x.reason = "assignment in .env".to_string();
        let report = format_human_report(&[x], "/proj", STRICT_PARANOID);
        assert!(
            report.contains(
                "  [1] /proj/.env\n      \
                 kind=dotenv  count=2  scope=project  confidence=possible  \
                 reasons=identifier,uuid\n      \
                 names: ALPHA, BETA\n      \
                 assignment in .env  [importable]"
            ),
            "{report}"
        );
    }

    #[test]
    fn a_transcript_finding_adds_its_own_line() {
        let all = [f(
            "/t",
            "agent_session_transcript",
            "certain",
            2,
            Scope::Deep,
        )];
        let report = format_human_report(&all, "/proj", STRICT_HIGH);
        assert!(
            report.contains(
                "2 LEAKs found in agent session transcripts \
                 (line-hits; advisory detection)"
            ),
            "{report}"
        );
        let one = [f(
            "/t",
            "agent_session_transcript",
            "certain",
            1,
            Scope::Deep,
        )];
        assert!(format_human_report(&one, "/proj", STRICT_HIGH).contains(
            "1 LEAK found in agent session transcripts \
                 (line-hits; advisory detection)"
        ));
    }

    /// A zero-count transcript finding is gated in but not listed, so the
    /// report falls through to the no-keys line.
    #[test]
    fn a_zero_count_transcript_finding_is_not_listed() {
        let all = [f(
            "/t",
            "agent_session_transcript",
            "certain",
            0,
            Scope::Deep,
        )];
        let report = format_human_report(&all, "/proj", STRICT_HIGH);
        assert!(
            report.ends_with("No locally exposed agent keys found under default exclusions."),
            "{report}"
        );
    }

    #[test]
    fn the_footer_lines_close_a_non_empty_report() {
        let all = [f("/proj/x", "inline", "certain", 1, Scope::Project)];
        let report = format_human_report(&all, "/proj", STRICT_HIGH);
        assert!(report.contains("\nValues are never shown.\n"), "{report}");
        assert!(
            report.ends_with(
                "Detection is advisory; false positives and false negatives \
                 are expected. Word-shaped passphrases appear under possible, \
                 not the default headline count."
            ),
            "{report}"
        );
    }

    // --- importable and the import hint ---

    #[test]
    fn importable_findings_need_a_positive_count() {
        let mut yes = f("/a/.env", "dotenv", "certain", 1, Scope::Project);
        yes.importable = true;
        let mut zero = f("/b/.env", "dotenv", "certain", 0, Scope::Project);
        zero.importable = true;
        let not = f("/c/.env", "dotenv", "certain", 4, Scope::Project);
        let all = [yes, zero, not];
        let kept = importable_findings(&all);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].path, "/a/.env");
    }

    #[test]
    fn the_import_hint_lists_dotenv_basenames_relative_to_the_root() {
        let mut a = f("/proj/.env", "dotenv", "certain", 1, Scope::Project);
        a.importable = true;
        let mut b = f(
            "/proj/sub/.env.local",
            "dotenv",
            "certain",
            2,
            Scope::Project,
        );
        b.importable = true;
        assert_eq!(
            format_import_next_line(&[a, b], "/proj"),
            Some("Next: in your own terminal, ka import .env sub/.env.local".to_string())
        );
    }

    /// Only dotenv names qualify, so a non-dotenv importable finding produces
    /// no hint at all.
    #[test]
    fn the_import_hint_skips_non_dotenv_names() {
        let mut a = f(
            "/proj/credentials.json",
            "credentials.json",
            "certain",
            1,
            Scope::Project,
        );
        a.importable = true;
        assert_eq!(format_import_next_line(&[a], "/proj"), None);
    }

    #[test]
    fn an_imported_leftover_is_not_a_dotenv_name() {
        let mut a = f(
            "/proj/.env.local.imported",
            "dotenv",
            "certain",
            1,
            Scope::Project,
        );
        a.importable = true;
        assert_eq!(format_import_next_line(&[a], "/proj"), None);
    }

    /// Outside the root, `relative_to` raises and Python falls back to the
    /// path as given.
    #[test]
    fn a_path_outside_the_root_is_shown_whole() {
        let mut a = f("/elsewhere/.env", "dotenv", "certain", 1, Scope::Project);
        a.importable = true;
        assert_eq!(
            format_import_next_line(&[a], "/proj"),
            Some("Next: in your own terminal, ka import /elsewhere/.env".to_string())
        );
    }

    // --- JSON ---

    #[test]
    fn json_for_no_findings() {
        assert_eq!(
            findings_to_json(&[], "/proj", STRICT_HIGH),
            "{\n  \"leak_count\": 0,\n  \"certain_count\": 0,\n  \
             \"likely_count\": 0,\n  \"possible_count\": 0,\n  \
             \"strict_certain\": 0,\n  \"strict_high\": 0,\n  \
             \"strict_paranoid\": 0,\n  \"transcript_line_hits\": 0,\n  \
             \"headline\": \"0 LEAKs found (--strict high) \\u2014 your agent \
             can read 0 secrets in this project (LEAK = Locally Exposed Agent \
             Keys)\",\n  \"strict\": \"high\",\n  \"project_root\": \
             \"/proj\",\n  \"findings\": [],\n  \"detection_note\": \
             \"Advisory heuristics; leak_count matches the --strict gate \
             (high). certain_count / likely_count / possible_count are \
             ungated. Per-finding confidence and reasons are always present. \
             Values are never included.\"\n}"
        );
    }

    /// The em dash in the headline is non-ASCII, and `ensure_ascii` escapes it,
    /// so `—` appears in the JSON and a literal em dash never does.
    #[test]
    fn json_escapes_the_headline_em_dash() {
        let out = findings_to_json(&[], "/proj", STRICT_HIGH);
        assert!(out.contains("\\u2014"), "{out}");
        assert!(!out.contains('—'), "{out}");
    }

    #[test]
    fn json_escapes_non_ascii_and_astral_and_quotes() {
        let mut x = f("/proj/a\"b\\c/.env", "dotenv", "certain", 1, Scope::Project);
        x.secret_names = vec!["КЛЮЧ".into(), "key\u{1F511}".into()];
        let out = findings_to_json(&[x], "/proj", STRICT_HIGH);
        // A quote and a backslash inside a path.
        assert!(out.contains(r#""path": "/proj/a\"b\\c/.env""#), "{out}");
        // Cyrillic, one escape per code point.
        assert!(out.contains("\"\\u041a\\u041b\\u042e\\u0427\""), "{out}");
        // U+1F511 as a UTF-16 surrogate pair.
        assert!(out.contains("\"key\\ud83d\\udd11\""), "{out}");
        // Never the raw characters.
        assert!(!out.contains('К'), "{out}");
        assert!(!out.contains('\u{1F511}'), "{out}");
    }

    #[test]
    fn json_escapes_control_characters_and_line_separators() {
        let mut x = f(
            "/p\u{0}\u{1}\u{7f}\u{2028}/.env",
            "dotenv",
            "certain",
            1,
            Scope::Project,
        );
        x.reason = "a\tb\nc".to_string();
        let out = findings_to_json(&[x], "/proj", STRICT_HIGH);
        // DEL is escaped too, being above `~`, and U+2028 like any
        // other non-ASCII code point.
        assert!(out.contains("\\u0000\\u0001\\u007f\\u2028"), "{out}");
        // Short forms survive for tab and newline.
        assert!(out.contains(r#""reason": "a\tb\nc""#), "{out}");
    }

    /// Empty collections stay inline as `[]` / `{}` even under `indent=2`, and
    /// a finding's keys follow dataclass field order rather than sorted order,
    /// because `sort_keys` is off at the call site.
    #[test]
    fn json_for_one_finding_matches_field_order_and_inline_empties() {
        let mut x = f("/proj/.env", "dotenv", "certain", 2, Scope::Project);
        x.secret_names = vec!["ALPHA".into()];
        x.importable = true;
        let out = findings_to_json(&[x], "/proj", STRICT_HIGH);
        assert!(
            out.contains(
                "  \"findings\": [\n    {\n      \"path\": \"/proj/.env\",\n      \
                 \"kind\": \"dotenv\",\n      \"secret_names\": [\n        \
                 \"ALPHA\"\n      ],\n      \"secret_count\": 2,\n      \
                 \"reason\": \"dotenv reason\",\n      \"importable\": true,\n      \
                 \"scope\": \"project\",\n      \"hit_lines\": [],\n      \
                 \"confidence\": \"certain\",\n      \"reasons\": [],\n      \
                 \"reason_counts\": {}\n    }\n  ],\n"
            ),
            "{out}"
        );
    }

    #[test]
    fn json_renders_hit_lines_and_reason_counts_when_present() {
        let mut x = f("/t", "agent_session_transcript", "possible", 2, Scope::Deep);
        x.hit_lines = vec![4, 9];
        x.reasons = vec!["uuid".into()];
        x.reason_counts = vec![("uuid".into(), 2)];
        let out = findings_to_json(&[x], "/proj", STRICT_PARANOID);
        assert!(
            out.contains("\"hit_lines\": [\n        4,\n        9\n      ],"),
            "{out}"
        );
        assert!(
            out.contains("\"reason_counts\": {\n        \"uuid\": 2\n      }"),
            "{out}"
        );
        assert!(out.contains("\"strict\": \"paranoid\""), "{out}");
    }

    #[test]
    fn json_reports_all_three_gate_totals_independently_of_strict() {
        let all = [
            f("/a", "dotenv", "certain", 3, Scope::Project),
            f("/b", "inline", "likely", 5, Scope::Project),
            f("/c", "inline", "possible", 7, Scope::Deep),
        ];
        let out = findings_to_json(&all, "/proj", STRICT_CERTAIN);
        assert!(out.contains("\"leak_count\": 3,"), "{out}");
        assert!(out.contains("\"strict_certain\": 3,"), "{out}");
        assert!(out.contains("\"strict_high\": 8,"), "{out}");
        assert!(out.contains("\"strict_paranoid\": 15,"), "{out}");
    }
}
