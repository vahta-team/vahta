//! A read of a file that holds a secret: the call is refused and the refusal
//! carries a redacted copy.
//!
//! Claude Code remembers a file it read, and after `/compact` it reads the
//! remembered files again from disk and puts them in the next request without
//! running any hook. Redacting the result of the Read is too late for that: the
//! file is on the list. A call the hook refused never makes the list, so the
//! hook reads the file itself, the window the call names, cuts what the
//! after-tool redaction would cut (the values Vahta holds, in every form the
//! daemon knows, and what the detector finds) and, if anything was cut, gives
//! the model the copy in the refusal.
//!
//! Text only: images, PDF and notebooks (the harness's own readers) and files
//! with a NUL byte are left to the other checks, as is a file too big to read
//! here. The copy is capped; past the cap the refusal is plain.

use std::path::Path;

use crate::daemon;
use crate::readguard::resolve;
use crate::redact::{self, Cut};

/// Claude Code's Read shows this many lines when the call gives no limit.
const DEFAULT_LINES: u64 = 2000;
/// The most text the refusal carries.
const MAX_COPY: usize = 64 * 1024;
/// A file bigger than this is not read by the hook.
const MAX_FILE: u64 = 32 * 1024 * 1024;
/// How much of the start of a file is looked at for a NUL byte.
const SNIFF: usize = 8000;
/// Files Claude Code reads with readers of its own.
const OTHER_READERS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "tif", "tiff", "pdf", "ipynb",
];

/// What the hook found in the window a Read names.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing to cut, or not a file this check reads.
    Clean,
    /// Something was cut: the copy, numbered as Read numbers lines, and what
    /// was cut.
    Copy {
        copy: String,
        cuts: Vec<Cut>,
        first: u64,
        last: u64,
        total: u64,
    },
    /// Something would be cut and the copy is over the cap.
    TooBig { cuts: Vec<Cut> },
}

/// The window of `given` that a Read with this `offset` and `limit` returns.
pub fn check(given: &str, cwd: Option<&str>, offset: Option<u64>, limit: Option<u64>) -> Outcome {
    if given.is_empty() {
        return Outcome::Clean;
    }
    let path = resolve(given, cwd);
    let reader = Path::new(given)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    if reader.is_some_and(|e| OTHER_READERS.contains(&e.as_str())) {
        return Outcome::Clean;
    }
    let Ok(meta) = std::fs::metadata(&path) else {
        return Outcome::Clean;
    };
    if !meta.is_file() || meta.len() > MAX_FILE {
        return Outcome::Clean;
    }
    let Ok(bytes) = std::fs::read(&path) else {
        return Outcome::Clean;
    };
    if bytes.iter().take(SNIFF).any(|b| *b == 0) {
        return Outcome::Clean;
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    let total = lines.len() as u64;
    let first = offset.unwrap_or(1).max(1);
    let count = limit.filter(|l| *l > 0).unwrap_or(DEFAULT_LINES);
    let start = usize::try_from(first - 1)
        .unwrap_or(usize::MAX)
        .min(lines.len());
    let end = usize::try_from(count)
        .map_or(lines.len(), |c| start.saturating_add(c))
        .min(lines.len());
    let window = lines[start..end].join("\n");
    let texts = vec![window.clone()];
    let (found, possible) = redact::detector_cuts(&texts);
    let asked = daemon::scan(daemon::Scan {
        cwd: cwd.unwrap_or_default().to_string(),
        tool: "Read".to_string(),
        texts,
        cuts: found.clone(),
        possible,
    });
    let cuts = match asked {
        Some(answer) => answer.cuts,
        None => found,
    };
    if cuts.is_empty() {
        return Outcome::Clean;
    }
    let refs: Vec<&Cut> = cuts.iter().filter(|c| c.text == 0).collect();
    let redacted = redact::cut_text(&window, &refs);
    let shown = redacted.split('\n').count();
    if shown as u64 > DEFAULT_LINES || redacted.len() > MAX_COPY {
        return Outcome::TooBig { cuts };
    }
    let mut copy = String::with_capacity(redacted.len() + shown * 7);
    for (i, line) in redacted.split('\n').enumerate() {
        if i > 0 {
            copy.push('\n');
        }
        copy.push_str(&format!("{:>6}\t{line}", start as u64 + i as u64 + 1));
    }
    Outcome::Copy {
        copy,
        cuts,
        first: start as u64 + 1,
        last: end as u64,
        total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> String {
        ["sk-", "ant-", &"a".repeat(25)].concat()
    }

    fn file(name: &str, body: &[u8]) -> (std::path::PathBuf, String) {
        let dir =
            std::env::temp_dir().join(format!("vahta-readcopy-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let p = dir.join(name);
        std::fs::write(&p, body).expect("write");
        let s = p.to_string_lossy().to_string();
        (dir, s)
    }

    #[test]
    fn a_found_value_is_cut_and_lines_are_numbered() {
        let body = format!("one\ntwo {}\nthree\n", key());
        let (dir, f) = file("a.txt", body.as_bytes());
        match check(&f, None, None, None) {
            Outcome::Copy {
                copy,
                first,
                last,
                total,
                ..
            } => {
                assert!(!copy.contains(&key()));
                assert!(copy.contains("     2\ttwo ***REDACTED("));
                assert_eq!((first, last, total), (1, 3, 3));
            }
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn offset_and_limit_pick_the_window() {
        let body = format!("one\ntwo {}\nthree\nfour\n", key());
        let (dir, f) = file("b.txt", body.as_bytes());
        assert_eq!(check(&f, None, Some(3), Some(5)), Outcome::Clean);
        assert_eq!(check(&f, None, Some(1), Some(1)), Outcome::Clean);
        match check(&f, None, Some(2), Some(2)) {
            Outcome::Copy {
                copy, first, last, ..
            } => {
                assert!(copy.starts_with("     2\ttwo "));
                assert!(copy.ends_with("     3\tthree"));
                assert_eq!((first, last), (2, 3));
            }
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_clean_a_binary_and_an_image_file_are_left_alone() {
        let (d1, clean) = file("c.txt", b"hello\n");
        assert_eq!(check(&clean, None, None, None), Outcome::Clean);
        let mut bin = vec![0u8, 1, 2];
        bin.extend_from_slice(key().as_bytes());
        let (d2, b) = file("d.bin", &bin);
        assert_eq!(check(&b, None, None, None), Outcome::Clean);
        let (d3, img) = file("e.png", key().as_bytes());
        assert_eq!(check(&img, None, None, None), Outcome::Clean);
        assert_eq!(check("/nonexistent/x", None, None, None), Outcome::Clean);
        for d in [d1, d2, d3] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    #[test]
    fn a_copy_over_the_cap_is_too_big() {
        let mut body = format!("{}\n", key());
        body.push_str(&"x".repeat(MAX_COPY + 10));
        let (dir, f) = file("f.txt", body.as_bytes());
        assert!(matches!(
            check(&f, None, None, None),
            Outcome::TooBig { .. }
        ));
        let _ = std::fs::remove_dir_all(dir);
    }
}
