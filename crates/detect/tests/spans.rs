//! `find_secret_spans` against the classifier, over the shared test corpus.
//!
//! The corpus is the repository's own: the labelled scan corpus, the agent
//! transcripts and the hook fixtures, every line and every whole file, plus
//! likely values made at run time (as the corpus README asks, so no committed
//! file reads as a key). On all of it the two must agree on whether there is
//! a secret at all, every span must lie on character boundaries, and the text
//! with its likely spans cut must have nothing likely left.

use std::path::{Path, PathBuf};

use vahta_detect::{Confidence, find_secret_kind, find_secret_spans, redact_spans};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            files_under(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn corpus() -> Vec<String> {
    let mut files = Vec::new();
    for dir in [
        "tests/fixtures/scan_corpus",
        "tests/fixtures/agent_transcripts",
        "crates/harness/harnesses",
    ] {
        files_under(&repo().join(dir), &mut files);
    }
    let mut texts = Vec::new();
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        texts.extend(text.lines().map(str::to_string));
        texts.push(text);
    }
    assert!(texts.len() > 100, "the corpus was not found");
    // Likely shapes made at run time, in the forms the README lists.
    let v = ["aB3xQ9mK", "2pL7vN4wZ8", "cD5eF"].concat();
    for line in [
        format!("API_KEY={v}"),
        format!("export DB_PASSWORD='{v}'"),
        format!("{{\"token\": \"{v}\"}}"),
        format!("secret: {v}"),
        format!("[auth]\napi-key = \"{v}\""),
        format!("curl -H 'Authorization: Bearer {v}' https://example.invalid"),
        format!("mysql --password {v} -u root"),
        format!("sk-{v}"),
        format!("sk-ant-{v}"),
        format!("ghp_{v}"),
        format!("glpat-{v}"),
        format!("xoxb-{v}"),
        format!("AIza{v}"),
        format!("{}{}", "sk_li", format_args!("ve_{v}")),
        format!("npm_{v}"),
        "4f8a1c9e-2b7d-4e63-9a15-0c8bd3f7e214 is token=4f8a1c9e-2b7d-4e63-9a15-0c8bd3f7e214"
            .to_string(),
    ] {
        texts.push(line.clone());
        texts.push(format!("before é {line} after ✓"));
    }
    texts
}

#[test]
fn the_spans_agree_with_the_classifier_on_the_corpus() {
    for text in corpus() {
        let kind = find_secret_kind(&text);
        let spans = find_secret_spans(&text);
        assert_eq!(
            kind.is_some(),
            !spans.is_empty(),
            "classifier and spans disagree on a corpus text of {} bytes (kind {kind:?})",
            text.len()
        );
        for s in &spans {
            assert!(s.range.start < s.range.end);
            assert!(text.is_char_boundary(s.range.start) && text.is_char_boundary(s.range.end));
            assert_ne!(s.confidence, Confidence::None);
        }
        // In order and apart.
        for pair in spans.windows(2) {
            assert!(pair[0].range.end <= pair[1].range.start);
        }
        let redacted = redact_spans(&text, &spans, Confidence::Likely);
        assert!(
            find_secret_spans(&redacted)
                .iter()
                .all(|s| s.confidence != Confidence::Likely),
            "something likely is left after redaction in a corpus text of {} bytes",
            text.len()
        );
    }
}
