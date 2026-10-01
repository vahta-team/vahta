//! One LEAK finding. Never carries secret *values*.

/// Confidence of a finding, ordered as `_CONF_ORDER` orders it.
///
/// A tier, not a score — the same distinction the detector makes. `Certain`
/// is a vendor prefix or a confirmed filename; `Likely` is an assignment or
/// UUID; `Possible` is a named weakening the hook still denies but the
/// default `leak_count` omits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Certain,
    Likely,
    Possible,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Certain => "certain",
            Confidence::Likely => "likely",
            Confidence::Possible => "possible",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "certain" => Some(Confidence::Certain),
            "likely" => Some(Confidence::Likely),
            "possible" => Some(Confidence::Possible),
            _ => None,
        }
    }

    /// `_CONF_ORDER`: certain 0, likely 1, possible 2.
    pub fn rank(self) -> u8 {
        match self {
            Confidence::Certain => 0,
            Confidence::Likely => 1,
            Confidence::Possible => 2,
        }
    }
}

/// Which sweep produced the finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Project,
    Deep,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Project => "project",
            Scope::Deep => "deep",
        }
    }
}

/// One finding.
///
/// Mirrors the Python dataclass field for field, including the ones the
/// project scan never sets, because the Python tests compare whole findings
/// and a missing field is a mismatch rather than an omission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub path: String,
    pub kind: String,
    /// Names only. The value they held is never recorded, anywhere.
    pub secret_names: Vec<String>,
    /// Signed, because Python's `max(f.secret_count, 0)` implies it can be
    /// negative and the guard is load-bearing.
    pub secret_count: i64,
    pub reason: String,
    pub importable: bool,
    pub scope: Scope,
    /// 1-based JSONL line numbers; agent transcripts only, so empty here.
    pub hit_lines: Vec<usize>,
    /// Empty string when the construction did not set one, as in Python.
    pub confidence: String,
    /// Named reason codes — `uuid`, `low-transition`, `identifier` — never values.
    pub reasons: Vec<String>,
    /// Counts per reason code, in insertion order, matching the Python dict.
    pub reason_counts: Vec<(String, usize)>,
}

impl Finding {
    pub fn new(path: impl Into<String>, kind: impl Into<String>, scope: Scope) -> Self {
        Finding {
            path: path.into(),
            kind: kind.into(),
            secret_names: Vec::new(),
            secret_count: 0,
            reason: String::new(),
            importable: false,
            scope,
            hit_lines: Vec::new(),
            confidence: String::new(),
            reasons: Vec::new(),
            reason_counts: Vec::new(),
        }
    }

    pub fn confidence_tier(&self) -> Option<Confidence> {
        Confidence::parse(&self.confidence)
    }
}

/// Which confidences a `--strict` level counts, matching `gated_confidences`.
pub fn gated_confidences(strict: &str) -> Vec<Confidence> {
    match strict {
        crate::STRICT_CERTAIN => vec![Confidence::Certain],
        crate::STRICT_PARANOID => {
            vec![Confidence::Certain, Confidence::Likely, Confidence::Possible]
        }
        // `high` is the default, and an unknown value falls here exactly as
        // the Python function does rather than raising.
        _ => vec![Confidence::Certain, Confidence::Likely],
    }
}

/// Secrets at or above the gate. The number a caller exits non-zero on.
///
/// A **sum of `secret_count`**, not a count of findings: one `.env` holding
/// four names is four LEAKs, and the headline says so. Python writes
/// `max(f.secret_count, 0)`, which is why the field is read as a signed value
/// here rather than trusted to be non-negative.
pub fn leak_count(findings: &[Finding], strict: &str) -> usize {
    let gate = gated_confidences(strict);
    findings
        .iter()
        .filter(|f| f.confidence_tier().is_some_and(|c| gate.contains(&c)))
        .map(|f| f.secret_count.max(0) as usize)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{STRICT_CERTAIN, STRICT_HIGH, STRICT_PARANOID};

    /// Distinct `secret_count`s on purpose: equal ones would let a count of
    /// findings pass for a sum of secrets, which is the bug this replaced.
    fn at(conf: &str, secret_count: i64) -> Finding {
        let mut f = Finding::new("p", "dotenv", Scope::Project);
        f.confidence = conf.to_string();
        f.secret_count = secret_count;
        f
    }

    #[test]
    fn strict_levels_gate_as_documented() {
        let all = [at("certain", 3), at("likely", 5), at("possible", 7)];
        assert_eq!(leak_count(&all, STRICT_CERTAIN), 3);
        assert_eq!(leak_count(&all, STRICT_HIGH), 8);
        assert_eq!(leak_count(&all, STRICT_PARANOID), 15);
    }

    #[test]
    fn an_unknown_strict_level_behaves_like_high() {
        let all = [at("certain", 3), at("likely", 5), at("possible", 7)];
        assert_eq!(leak_count(&all, "nonsense"), 8);
    }

    /// Python writes `max(f.secret_count, 0)`; a negative count contributes
    /// nothing rather than wrapping.
    #[test]
    fn a_negative_secret_count_contributes_nothing() {
        let all = [at("certain", -4), at("certain", 2)];
        assert_eq!(leak_count(&all, STRICT_CERTAIN), 2);
    }

    #[test]
    fn a_finding_without_a_confidence_is_never_counted() {
        let mut f = Finding::new("p", "dotenv", Scope::Project);
        f.secret_count = 9;
        assert_eq!(leak_count(&[f], STRICT_PARANOID), 0);
    }
}
