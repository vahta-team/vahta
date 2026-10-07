//! Cutting secrets out of a tool's result before the model sees it.
//!
//! The result is kept in the shape the tool gave it (Claude wants that shape
//! back): every string in it is a *text*, numbered in pre-order, and a cut is
//! a byte range of one text with the label that replaces it,
//! `***REDACTED(<NAME or kind>)***`. Only likely finds are cut; a merely
//! possible one is left alone and counted.

use std::ops::Range;

use serde_json::Value;
use vahta_detect::{Confidence, find_secret_spans};

/// One value to cut: which text, where in it, and what to put instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cut {
    pub text: usize,
    pub range: Range<usize>,
    /// A secret's name when the daemon knew the value, else the detector's
    /// kind (`OpenAI-style key`).
    pub label: String,
}

/// Every string in `v`, in pre-order. Object keys are not texts: a key is the
/// tool's, not the data's.
pub fn texts_of(v: &Value) -> Vec<String> {
    fn collect(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) => out.push(s.clone()),
            Value::Array(items) => items.iter().for_each(|x| collect(x, out)),
            Value::Object(map) => map.values().for_each(|x| collect(x, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    collect(v, &mut out);
    out
}

/// Visit every string of `v` in the order [`texts_of`] numbers them. `v` is
/// no deeper than the harness's `OUTPUT_DEPTH`, so recursion is safe.
fn walk(v: &mut Value, f: &mut dyn FnMut(&mut String)) {
    match v {
        Value::String(s) => f(s),
        Value::Array(items) => items.iter_mut().for_each(|x| walk(x, f)),
        Value::Object(map) => map.values_mut().for_each(|x| walk(x, f)),
        _ => {}
    }
}

/// What the detector finds in `texts`: the likely values, to cut, and the
/// kinds of the merely possible ones, which are left in.
pub fn detector_cuts(texts: &[String]) -> (Vec<Cut>, Vec<String>) {
    let mut cuts = Vec::new();
    let mut possible = Vec::new();
    for (i, text) in texts.iter().enumerate() {
        for span in find_secret_spans(text) {
            match span.confidence {
                Confidence::Likely => cuts.push(Cut {
                    text: i,
                    range: span.range,
                    label: span.kind,
                }),
                _ => possible.push(span.kind),
            }
        }
    }
    (cuts, possible)
}

pub fn marker(label: &str) -> String {
    format!("***REDACTED({label})***")
}

/// `text` with `cuts` (ranges into it, in order, not overlapping) replaced by
/// their markers. A cut that is out of order, overlaps the one before or does
/// not sit on character boundaries is skipped: it can only come from a broken
/// daemon reply, and the detector's own cuts are applied from the hook's side
/// before anything else.
pub fn cut_text(text: &str, cuts: &[&Cut]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    for c in cuts {
        let Range { start, end } = c.range;
        if start < pos
            || end <= start
            || end > text.len()
            || !text.is_char_boundary(start)
            || !text.is_char_boundary(end)
        {
            continue;
        }
        out.push_str(&text[pos..start]);
        out.push_str(&marker(&c.label));
        pos = end;
    }
    out.push_str(&text[pos..]);
    out
}

/// `v` with every cut applied to its text, in place.
pub fn apply(v: &mut Value, cuts: &[Cut]) {
    let mut sorted: Vec<&Cut> = cuts.iter().collect();
    sorted.sort_by_key(|c| (c.text, c.range.start));
    let mut index = 0;
    walk(v, &mut |s| {
        let mine: Vec<&Cut> = sorted.iter().copied().filter(|c| c.text == index).collect();
        if !mine.is_empty() {
            *s = cut_text(s, &mine);
        }
        index += 1;
    });
}

/// The labels of `cuts`, each once, in order: `OpenAI-style key, DB_PASSWORD`.
pub fn labels(cuts: &[Cut]) -> String {
    let mut seen: Vec<&str> = Vec::new();
    for c in cuts {
        if !seen.contains(&c.label.as_str()) {
            seen.push(&c.label);
        }
    }
    seen.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key() -> String {
        ["sk-", "ant-", &"a".repeat(25)].concat()
    }

    #[test]
    fn strings_are_cut_where_they_are_and_the_shape_stays() {
        let k = key();
        let mut v = json!({
            "stdout": format!("found {k} here"),
            "stderr": "",
            "interrupted": false,
            "nested": [1, {"text": k.clone()}],
        });
        let texts = texts_of(&v);
        assert_eq!(texts.len(), 3);
        let (cuts, possible) = detector_cuts(&texts);
        assert_eq!(cuts.len(), 2);
        assert!(possible.is_empty());
        apply(&mut v, &cuts);
        assert_eq!(
            v["stdout"],
            "found ***REDACTED(Anthropic-style key)*** here"
        );
        assert_eq!(
            v["nested"][1]["text"],
            "***REDACTED(Anthropic-style key)***"
        );
        assert_eq!(v["interrupted"], false);
        assert_eq!(v["nested"][0], 1);
        assert!(!v.to_string().contains(&k));
        assert_eq!(labels(&cuts), "Anthropic-style key");
    }

    #[test]
    fn a_bad_cut_is_skipped_not_applied() {
        let text = "é abc";
        let bad = Cut {
            text: 0,
            range: 1..3,
            label: "X".into(),
        };
        let past = Cut {
            text: 0,
            range: 4..99,
            label: "X".into(),
        };
        assert_eq!(cut_text(text, &[&bad, &past]), text);
        let good = Cut {
            text: 0,
            range: 3..6,
            label: "N".into(),
        };
        assert_eq!(cut_text(text, &[&good]), "é ***REDACTED(N)***");
    }
}
