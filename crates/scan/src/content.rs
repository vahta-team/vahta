//! Reading a file and turning it into findings. **Package A — unimplemented.**
//!
//! Ports, from `src/key_amnesia/scan.py`:
//!   `_safe_read_text` (220), `_dotenv_finding` (233), `_json_key_names` (276),
//!   `scan_text_for_leaks` (290), `_inline_findings` (405),
//!   `_findings_for_path` (646),
//! plus `parse_dotenv` from `src/key_amnesia/dotenv_import.py:22`.
//!
//! Python is the specification, including where it is arguably wrong.

use crate::finding::{Finding, Scope};

/// `_safe_read_text`. `None` on an OS error, or when a NUL appears in the
/// first 4096 bytes. Decodes lossily — never fails on invalid UTF-8.
pub fn safe_read_text(path: &std::path::Path, limit: usize) -> Option<String> {
    let _ = (path, limit);
    unimplemented!("package A")
}

/// `parse_dotenv`, preserving insertion order, so a `Vec` and not a map.
pub fn parse_dotenv(text: &str) -> Vec<(String, String)> {
    let _ = text;
    unimplemented!("package A")
}

/// `_json_key_names`: top-level object keys, never values.
///
/// Must agree with `json.loads` on **validity**, not just on well-formed
/// input: Python returns `[]` for malformed JSON, for valid non-object JSON,
/// and for an unreadable file alike, so a lenient parser silently reports
/// keys where Python reports none.
pub fn json_key_names(path: &std::path::Path) -> Vec<String> {
    let _ = path;
    unimplemented!("package A")
}

/// `scan_text_for_leaks`: likely names plus an optional prefix kind.
pub fn scan_text_for_leaks(text: &str) -> (Vec<String>, Option<&'static str>) {
    let _ = text;
    unimplemented!("package A")
}

/// `_dotenv_finding`. Three shapes: no entries, entries but all empty, and
/// the ordinary case — only the last is `importable`.
pub fn dotenv_finding(path: &std::path::Path, scope: Scope) -> Option<Finding> {
    let _ = (path, scope);
    unimplemented!("package A")
}

/// `_inline_findings`: up to three findings from one text, one per tier.
pub fn inline_findings(
    path: &std::path::Path,
    text: &str,
    scope: Scope,
    kind: &str,
    high_reason: &str,
    possible_reason: &str,
) -> Vec<Finding> {
    let _ = (path, text, scope, kind, high_reason, possible_reason);
    unimplemented!("package A")
}

/// `_findings_for_path`: the whole per-file decision.
pub fn findings_for_path(path: &std::path::Path, scope: Scope) -> Vec<Finding> {
    let _ = (path, scope);
    unimplemented!("package A")
}
