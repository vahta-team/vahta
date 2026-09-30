//! Counting and rendering findings. **Package C — unimplemented.**
//!
//! Ports, from `src/key_amnesia/scan.py`:
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

use crate::finding::Finding;

/// `certain_count`, `likely_count`, `possible_count` — a sum of
/// `secret_count`, as `leak_count` is.
pub fn tier_count(findings: &[Finding], confidence: &str) -> usize {
    let _ = (findings, confidence);
    unimplemented!("package C")
}

/// `transcript_line_hit_count`: certain+likely, transcripts only.
pub fn transcript_line_hit_count(findings: &[Finding]) -> usize {
    let _ = findings;
    unimplemented!("package C")
}

/// `headline`.
pub fn headline(findings: &[Finding], strict: &str) -> String {
    let _ = (findings, strict);
    unimplemented!("package C")
}

/// `_reason_bucket_counts`. Insertion-ordered like Python's dict, so a `Vec`
/// of pairs rather than a map.
pub fn reason_bucket_counts(findings: &[Finding]) -> Vec<(String, usize)> {
    let _ = findings;
    unimplemented!("package C")
}

/// `format_count_summary`: the always-printed three-count line.
pub fn format_count_summary(findings: &[Finding]) -> String {
    let _ = findings;
    unimplemented!("package C")
}

/// `format_gate_totals`: the always-printed per-gate totals.
pub fn format_gate_totals(findings: &[Finding]) -> String {
    let _ = findings;
    unimplemented!("package C")
}

/// `findings_to_json`. Emits the JSON text itself, since the crate has no
/// serialiser; key order and escaping must match `json.dumps`'s defaults for
/// the arguments Python passes.
pub fn findings_to_json(findings: &[Finding], strict: &str, scanned_root: Option<&str>) -> String {
    let _ = (findings, strict, scanned_root);
    unimplemented!("package C")
}

/// `format_human_report`.
pub fn format_human_report(findings: &[Finding], strict: &str) -> String {
    let _ = (findings, strict);
    unimplemented!("package C")
}

/// `importable_findings`.
pub fn importable_findings(findings: &[Finding]) -> Vec<&Finding> {
    let _ = findings;
    unimplemented!("package C")
}
