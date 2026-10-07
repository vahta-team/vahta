//! Where the secrets in a text are, for the hook to cut them out.
//!
//! [`crate::find_secret_kind`] answers "is there a secret here, and what kind";
//! this answers "where": the byte range of every value the same four matchers
//! find (vendor prefix, Bearer, assignment, flag form), with its kind and tier.
//! It is a new function beside the classifier, not a change to it, so the
//! Python parity contract is untouched.
//!
//! Two differences from the classifier, both on the side of finding more:
//! every Bearer capture is looked at (the classifier looks at the first), and
//! every occurrence of every vendor prefix (the classifier stops at the first
//! rule that matches). So when [`crate::find_secret_kind`] finds something,
//! there is at least one span, and on the test corpus the converse holds too.
//!
//! A span names a kind and a tier, never a value.

use std::ops::Range;

use crate::classify::{Confidence, classify_value};
use crate::matchers::{
    FLAG_FORM_FIRE_TIERS, find_bearer_spans, find_prefix_spans, iter_assignments_at,
    iter_flag_values_at,
};

/// One secret in a text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretSpan {
    /// Byte offsets into the text, on character boundaries.
    pub range: Range<usize>,
    /// What it is, as the hook says it: `OpenAI-style key`, `Bearer token`,
    /// `API_KEY assignment`, `--password flag value`.
    pub kind: String,
    /// `Likely` or `Possible`; never `None`.
    pub confidence: Confidence,
}

fn rank(c: Confidence) -> u8 {
    match c {
        Confidence::None => 0,
        Confidence::Possible => 1,
        Confidence::Likely => 2,
    }
}

/// A span before merging, with which matcher found it: when two overlap, the
/// higher tier names the merged span, and of equal tiers the more specific
/// matcher (a vendor prefix over an assignment that holds it).
struct Found {
    span: SecretSpan,
    matcher: u8,
}

/// Every secret in `text`, in order, overlapping finds merged into one span.
pub fn find_secret_spans(text: &str) -> Vec<SecretSpan> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut found: Vec<Found> = Vec::new();
    for (range, kind) in find_prefix_spans(text) {
        found.push(Found {
            span: SecretSpan {
                range,
                kind: kind.to_string(),
                // A vendor prefix is certain, which redacts like likely.
                confidence: Confidence::Likely,
            },
            matcher: 0,
        });
    }
    for (range, confidence) in find_bearer_spans(text) {
        found.push(Found {
            span: SecretSpan {
                range,
                kind: "Bearer token".to_string(),
                confidence,
            },
            matcher: 1,
        });
    }
    for (name, range) in iter_assignments_at(text) {
        let tier = classify_value(&text[range.clone()]).0;
        if tier == Confidence::None {
            continue;
        }
        found.push(Found {
            span: SecretSpan {
                range,
                kind: format!("{} assignment", name.to_uppercase()),
                confidence: tier,
            },
            matcher: 2,
        });
    }
    for (name, range) in iter_flag_values_at(text) {
        let tier = classify_value(&text[range.clone()]).0;
        if !FLAG_FORM_FIRE_TIERS.contains(&tier) {
            continue;
        }
        found.push(Found {
            span: SecretSpan {
                range,
                kind: format!("--{name} flag value"),
                confidence: tier,
            },
            matcher: 3,
        });
    }
    merge(found)
}

fn merge(mut found: Vec<Found>) -> Vec<SecretSpan> {
    found.sort_by_key(|f| (f.span.range.start, f.matcher));
    let mut out: Vec<Found> = Vec::new();
    for f in found {
        match out.last_mut() {
            Some(last) if f.span.range.start < last.span.range.end => {
                last.span.range.end = last.span.range.end.max(f.span.range.end);
                let better = rank(f.span.confidence) > rank(last.span.confidence)
                    || (rank(f.span.confidence) == rank(last.span.confidence)
                        && f.matcher < last.matcher);
                if better {
                    last.span.kind = f.span.kind;
                    last.span.confidence = f.span.confidence;
                    last.matcher = f.matcher;
                }
            }
            _ => out.push(f),
        }
    }
    out.into_iter().map(|f| f.span).collect()
}

/// `text` with every span at `min` or above replaced by
/// `***REDACTED(<kind>)***`. The hook uses `Likely`; the tests use this to
/// check that nothing likely is left.
pub fn redact_spans(text: &str, spans: &[SecretSpan], min: Confidence) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    for s in spans {
        if rank(s.confidence) < rank(min) || s.range.start < pos {
            continue;
        }
        out.push_str(&text[pos..s.range.start]);
        out.push_str("***REDACTED(");
        out.push_str(&s.kind);
        out.push_str(")***");
        pos = s.range.end;
    }
    out.push_str(&text[pos..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Values are built at run time, so no fixture here reads as a key to a
    // scanner, this crate's own hook included.
    fn openai() -> String {
        format!("sk-{}", "aB3xQ9mK2pL7vN4wZ8cD5eF")
    }

    fn likely_value() -> String {
        ["aB3xQ9mK", "2pL7vN4wZ8"].concat()
    }

    #[test]
    fn a_prefix_key_is_found_where_it_is() {
        let key = openai();
        let text = format!("export x; echo {key} done");
        let spans = find_secret_spans(&text);
        assert_eq!(spans.len(), 1);
        assert_eq!(&text[spans[0].range.clone()], key);
        assert_eq!(spans[0].kind, "OpenAI-style key");
        assert_eq!(spans[0].confidence, Confidence::Likely);
    }

    #[test]
    fn every_occurrence_is_found_not_only_the_first() {
        let key = openai();
        let gh = format!("ghp_{}", "Zx9Qw3Er7Ty1Ui5Op2As");
        let text = format!("{key}\n{gh}\nagain {key}");
        let spans = find_secret_spans(&text);
        let cut: Vec<&str> = spans.iter().map(|s| &text[s.range.clone()]).collect();
        assert_eq!(cut, [key.as_str(), gh.as_str(), key.as_str()]);
    }

    #[test]
    fn an_assignment_and_a_flag_cut_only_the_value() {
        let v = likely_value();
        let text = format!("API_KEY={v} and mysql --password {v} -u root");
        let spans = find_secret_spans(&text);
        assert_eq!(spans.len(), 2);
        assert!(spans.iter().all(|s| text[s.range.clone()] == v));
        assert_eq!(spans[0].kind, "API_KEY assignment");
        assert_eq!(spans[1].kind, "--password flag value");
    }

    #[test]
    fn a_bearer_is_cut_after_the_word_and_every_one_counts() {
        let v = likely_value();
        // The first capture is an identifier, the second a token: the
        // classifier looks only at the first, the spans at both.
        let text =
            format!("Authorization: Bearer getTokenFromCacheNow\nAuthorization: Bearer {v}xyz");
        let spans = find_secret_spans(&text);
        let last = spans.last().unwrap();
        assert_eq!(&text[last.range.clone()], format!("{v}xyz"));
        assert_eq!(last.confidence, Confidence::Likely);
    }

    #[test]
    fn overlapping_finds_merge_and_the_specific_kind_wins() {
        let key = openai();
        let text = format!("OPENAI_API_KEY={key}");
        let spans = find_secret_spans(&text);
        assert_eq!(spans.len(), 1);
        assert_eq!(&text[spans[0].range.clone()], key);
        assert_eq!(spans[0].kind, "OpenAI-style key");
    }

    #[test]
    fn positions_are_byte_offsets_in_text_that_is_not_ascii() {
        let key = openai();
        let v = likely_value();
        let text = format!("é Я ٣ token={v} — {key} ✓");
        for s in find_secret_spans(&text) {
            assert!(text.is_char_boundary(s.range.start) && text.is_char_boundary(s.range.end));
            let cut = &text[s.range.clone()];
            assert!(cut == v || cut == key, "{cut}");
        }
        assert_eq!(find_secret_spans(&text).len(), 2);
    }

    #[test]
    fn redacted_text_has_nothing_likely_left() {
        let key = openai();
        let v = likely_value();
        let text = format!("a {key} b API_KEY={v} c --token {v} d Bearer {v}");
        let spans = find_secret_spans(&text);
        let redacted = redact_spans(&text, &spans, Confidence::Likely);
        assert!(
            !redacted.contains(&key) && !redacted.contains(&v),
            "{redacted}"
        );
        assert!(
            find_secret_spans(&redacted)
                .iter()
                .all(|s| s.confidence != Confidence::Likely),
            "{redacted}"
        );
        assert!(redacted.contains("***REDACTED(OpenAI-style key)***"));
    }

    #[test]
    fn plain_text_has_no_spans() {
        assert!(find_secret_spans("").is_empty());
        assert!(find_secret_spans("cargo build --release && ls -la").is_empty());
        assert!(find_secret_spans("ka run --secret GOOGLE_API_KEY -- ./deploy.sh").is_empty());
    }
}
