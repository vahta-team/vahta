//! What a scan of one text blob found. Never carries values.
//!
//! Ported from `key_amnesia.detect_py::HitSet` and `scan_text_hits`.
//! Insertion order is part of the contract: the Python original is backed by
//! dicts, which in CPython preserve insertion order, and the reported name and
//! reason lists are compared directly by the test suite.

use crate::classify::{Confidence, classify_value};
use crate::matchers::{
    FLAG_FORM_FIRE_TIERS, REASON_FLAG_FORM, classify_bearer_capture, find_prefix_kind,
    iter_assignments, iter_flag_values,
};

/// Assignment, flag-form, prefix and Bearer hits for one text blob.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HitSet {
    pub likely_names: Vec<String>,
    pub possible_names: Vec<String>,
    pub prefix: Option<&'static str>,
    pub bearer_likely: bool,
    pub bearer_possible: bool,
    pub likely_reasons: Vec<String>,
    pub possible_reasons: Vec<String>,
    pub likely_reason_counts: Vec<(String, usize)>,
    pub possible_reason_counts: Vec<(String, usize)>,
    /// Upper-cased names matched as `--flag <value>` rather than `name=<value>`.
    /// Phrasing only — the hit itself lives in the name lists.
    pub flag_names: Vec<String>,
    /// Reasons per name, parallel to `likely_names` / `possible_names`.
    ///
    /// The flat `*_reasons` lists above are deduplicated across names, which
    /// is what the Python dataclass reports — but a caller reconstructing that
    /// dataclass has to replay `record_assignment` name by name, and needs the
    /// reasons still attached to the name they came from.
    pub likely_reasons_by_name: Vec<Vec<String>>,
    pub possible_reasons_by_name: Vec<Vec<String>>,
    /// Upper-cased keys, parallel to the name lists. Needed by [`HitSet::merge`],
    /// which is keyed by name rather than positional.
    pub likely_keys: Vec<String>,
    pub possible_keys: Vec<String>,
}

/// `upper(name) -> (original name, reasons)`, in insertion order.
type ByName = Vec<(String, (String, Vec<String>))>;

fn lookup<'a>(store: &'a ByName, key: &str) -> Option<&'a (String, Vec<String>)> {
    store.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn remove(store: &mut ByName, key: &str) {
    store.retain(|(k, _)| k != key);
}

impl HitSet {
    fn rebuild(&mut self, likely: &ByName, possible: &ByName) {
        self.likely_names = likely.iter().map(|(_, (name, _))| name.clone()).collect();
        self.possible_names = possible.iter().map(|(_, (name, _))| name.clone()).collect();
        self.likely_reasons_by_name = likely.iter().map(|(_, (_, r))| r.clone()).collect();
        self.possible_reasons_by_name = possible.iter().map(|(_, (_, r))| r.clone()).collect();
        self.likely_keys = likely.iter().map(|(k, _)| k.clone()).collect();
        self.possible_keys = possible.iter().map(|(k, _)| k.clone()).collect();

        let (names, counts) = flatten_reasons(likely);
        self.likely_reasons = names;
        self.likely_reason_counts = counts;

        let (names, counts) = flatten_reasons(possible);
        self.possible_reasons = names;
        self.possible_reason_counts = counts;
    }
}

fn flatten_reasons(store: &ByName) -> (Vec<String>, Vec<(String, usize)>) {
    let mut order: Vec<String> = Vec::new();
    let mut counts: Vec<(String, usize)> = Vec::new();
    for (_, (_name, reasons)) in store {
        for reason in reasons {
            if reason.is_empty() {
                continue;
            }
            if !order.iter().any(|r| r == reason) {
                order.push(reason.clone());
            }
            match counts.iter_mut().find(|(r, _)| r == reason) {
                Some((_, n)) => *n += 1,
                None => counts.push((reason.clone(), 1)),
            }
        }
    }
    (order, counts)
}

/// Assignment and flag-form names, vendor prefix and Bearer.
///
/// Highest tier wins per name. A vendor prefix is certain; a Bearer whose
/// value is likely sets `bearer_likely`, an identifier-shaped one sets
/// `bearer_possible`, and neither is recorded when a prefix already matched.
/// Never returns values.
pub fn scan_text_hits(text: &str) -> HitSet {
    let mut hits = HitSet::default();
    if text.is_empty() {
        return hits;
    }

    hits.prefix = find_prefix_kind(text);
    let bearer_tier = classify_bearer_capture(text);
    if hits.prefix.is_none() {
        match bearer_tier {
            Confidence::Likely => hits.bearer_likely = true,
            Confidence::Possible => hits.bearer_possible = true,
            Confidence::None => {}
        }
    }

    // key -> (tier, original name, reasons), insertion-ordered.
    let mut chosen: Vec<(String, Confidence, String, Vec<String>)> = Vec::new();

    let mut record = |name: &str, tier: Confidence, reasons: Vec<String>| {
        let key = name.to_uppercase();
        match chosen.iter_mut().find(|(k, _, _, _)| *k == key) {
            None => chosen.push((key, tier, name.to_string(), reasons)),
            Some((_, prev_tier, prev_name, prev_reasons)) => {
                if *prev_tier == Confidence::Possible && tier == Confidence::Likely {
                    // Python replaces the whole entry, so the *later* spelling
                    // of the name wins when a possible hit is upgraded: a
                    // lower-case name then an upper-case one reports the
                    // upper-case one.
                    *prev_tier = tier;
                    *prev_name = name.to_string();
                    *prev_reasons = reasons;
                } else if *prev_tier == tier {
                    for reason in reasons {
                        if !reason.is_empty() && !prev_reasons.contains(&reason) {
                            prev_reasons.push(reason);
                        }
                    }
                }
            }
        }
    };

    for (name, value) in iter_assignments(text) {
        let (tier, reason) = classify_value(&value);
        if matches!(tier, Confidence::None) {
            continue;
        }
        let reasons = reason.map(|r| vec![r.to_string()]).unwrap_or_default();
        record(&name, tier, reasons);
    }

    for (name, value) in iter_flag_values(text) {
        let (tier, reason) = classify_value(&value);
        if !FLAG_FORM_FIRE_TIERS.contains(&tier) {
            continue;
        }
        let key = name.to_uppercase();
        if !hits.flag_names.contains(&key) {
            hits.flag_names.push(key);
        }
        let mut reasons = vec![REASON_FLAG_FORM.to_string()];
        if let Some(r) = reason {
            reasons.push(r.to_string());
        }
        record(&name, tier, reasons);
    }

    let mut likely: ByName = Vec::new();
    let mut possible: ByName = Vec::new();
    for (key, tier, name, reasons) in chosen {
        match tier {
            Confidence::Likely => {
                remove(&mut possible, &key);
                if lookup(&likely, &key).is_none() {
                    likely.push((key, (name, reasons)));
                }
            }
            Confidence::Possible => {
                if lookup(&likely, &key).is_none() && lookup(&possible, &key).is_none() {
                    possible.push((key, (name, reasons)));
                }
            }
            Confidence::None => {}
        }
    }
    hits.rebuild(&likely, &possible);
    hits
}

/// Phrase a name hit. Flag-form hits say so, so the deny message is actionable.
fn name_kind(name: &str, hits: &HitSet) -> String {
    if hits.flag_names.iter().any(|n| *n == name.to_uppercase()) {
        format!("--{name} flag value")
    } else {
        format!("{} assignment", name.to_uppercase())
    }
}

/// The single question the hook asks: what kind of secret is in here, if any?
pub fn find_secret_kind(text: &str) -> Option<String> {
    let hits = scan_text_hits(text);
    // Order is behaviour, not taste: a Bearer whose value is likely outranks
    // a likely *name*, and both outrank anything merely possible.
    if let Some(prefix) = hits.prefix {
        return Some(prefix.to_string());
    }
    if hits.bearer_likely {
        return Some("Bearer token".to_string());
    }
    if let Some(name) = hits.likely_names.first() {
        return Some(name_kind(name, &hits));
    }
    if hits.bearer_possible {
        return Some("Bearer token".to_string());
    }
    if let Some(name) = hits.possible_names.first() {
        return Some(name_kind(name, &hits));
    }
    None
}

/// `s.lstrip().startswith("{") or startswith("[")`
pub fn looks_like_json_container(s: &str) -> bool {
    let t = s.trim_start_matches(crate::primitives::is_python_space);
    t.starts_with('{') || t.starts_with('[')
}

impl HitSet {
    fn to_stores(&self) -> (ByName, ByName) {
        let likely = self
            .likely_keys
            .iter()
            .zip(self.likely_names.iter())
            .zip(self.likely_reasons_by_name.iter())
            .map(|((k, n), r)| (k.clone(), (n.clone(), r.clone())))
            .collect();
        let possible = self
            .possible_keys
            .iter()
            .zip(self.possible_names.iter())
            .zip(self.possible_reasons_by_name.iter())
            .map(|((k, n), r)| (k.clone(), (n.clone(), r.clone())))
            .collect();
        (likely, possible)
    }

    /// `HitSet.record_assignment`: highest tier wins per name, and a name
    /// already held at the same or a higher tier is left alone. Any tier other
    /// than `Likely` / `Possible` records nothing. Does not record values.
    pub fn record_assignment(&mut self, name: &str, tier: Confidence, reasons: &[String]) {
        let key = name.to_uppercase();
        let (mut likely, mut possible) = self.to_stores();
        match tier {
            Confidence::Likely => {
                if lookup(&likely, &key).is_some() {
                    return;
                }
                remove(&mut possible, &key);
                likely.push((key, (name.to_string(), reasons.to_vec())));
            }
            Confidence::Possible => {
                if lookup(&likely, &key).is_some() || lookup(&possible, &key).is_some() {
                    return;
                }
                possible.push((key, (name.to_string(), reasons.to_vec())));
            }
            _ => return,
        }
        self.rebuild(&likely, &possible);
    }

    /// Fold `extra` in, with the same rule the Python dataclass uses: a likely
    /// hit displaces a possible one for the same name, an existing likely hit
    /// is never replaced, the first vendor prefix wins, and the Bearer flags
    /// and flag names accumulate.
    pub fn merge(&mut self, extra: &HitSet) {
        let (mut likely, mut possible) = self.to_stores();
        let (extra_likely, extra_possible) = extra.to_stores();

        for (key, pair) in extra_likely {
            if lookup(&likely, &key).is_some() {
                continue;
            }
            remove(&mut possible, &key);
            likely.push((key, pair));
        }
        for (key, pair) in extra_possible {
            if lookup(&likely, &key).is_some() || lookup(&possible, &key).is_some() {
                continue;
            }
            possible.push((key, pair));
        }
        if self.prefix.is_none()
            && let Some(p) = extra.prefix
        {
            self.prefix = Some(p);
        }
        self.bearer_likely |= extra.bearer_likely;
        self.bearer_possible |= extra.bearer_possible;
        for key in &extra.flag_names {
            if !self.flag_names.iter().any(|n| n == key) {
                self.flag_names.push(key.clone());
            }
        }
        self.rebuild(&likely, &possible);
    }
}

/// Scan many texts and fold the results into one [`HitSet`].
///
/// The reason this exists is measured rather than aesthetic. Scanning agent
/// transcripts means calling the detector on thousands of *tiny* strings, and
/// crossing the Python boundary once per string costs more than the detection
/// saves: on a synthetic 879 KiB transcript tree the Rust path was 768 ms
/// against Python's 750 ms, i.e. slightly slower. Crossing once per file
/// instead moves the boundary to where the work is.
pub fn scan_texts<S: AsRef<str>>(texts: &[S]) -> HitSet {
    let mut acc = HitSet::default();
    for text in texts {
        let hits = scan_text_hits(text.as_ref());
        acc.merge(&hits);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assignment(name: &str, value: &str) -> String {
        format!("{name}={value}")
    }

    #[test]
    fn an_assignment_is_recorded_under_its_name() {
        let hits = scan_text_hits(&assignment("API_KEY", "aB3xQ9mK2pL7vN4wZ8"));
        assert_eq!(hits.likely_names, vec!["API_KEY"]);
        assert!(hits.flag_names.is_empty());
    }

    #[test]
    fn an_upgraded_hit_takes_the_later_spelling_of_the_name() {
        // Python: `chosen[key] = (tier, name, ...)` replaces the whole entry
        // when a possible hit is upgraded to likely.
        let name = ["tok", "en"].concat();
        let first = assignment(&name, "Frombuild");
        let second = format!("\"{}\": \"{}\"", name.to_uppercase(), "aB3xQ9mK2pL7vN4wZ8");
        let hits = scan_text_hits(&format!("{first}\n{second}"));
        assert_eq!(hits.likely_names, vec![name.to_uppercase()]);
        assert!(hits.possible_names.is_empty());
    }

    #[test]
    fn a_flag_form_hit_says_it_is_a_flag() {
        let text = format!("mysql --password {} -u root", "Zk9pL2xQ7mN4vB8w");
        let hits = scan_text_hits(&text);
        assert_eq!(hits.flag_names, vec!["PASSWORD"]);
        assert!(hits.likely_reasons.iter().any(|r| r == REASON_FLAG_FORM));
        assert_eq!(
            find_secret_kind(&text).as_deref(),
            Some("--password flag value")
        );
    }

    #[test]
    fn recommended_usage_stays_quiet() {
        assert_eq!(
            find_secret_kind("ka run --secret GOOGLE_API_KEY -- ./deploy.sh"),
            None
        );
        assert_eq!(
            find_secret_kind("vault login --token-file ./token.txt"),
            None
        );
        assert_eq!(
            find_secret_kind("mysql --password --host=db.internal.example.com"),
            None
        );
    }

    #[test]
    fn json_container_detection() {
        assert!(looks_like_json_container("  {\"a\": 1}"));
        assert!(looks_like_json_container("[1]"));
        assert!(!looks_like_json_container("a = 1"));
    }
}
