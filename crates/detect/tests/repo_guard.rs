//! False-positive guard: the repository's own files, read as a hook would read
//! a Write of each of them, raise no blocking finding.
//!
//! Skipped: build output, `.git`, the rule data (which holds the regexes and a
//! few literals its rules match), and the Python key-amnesia tree (`src/`,
//! `tests/`), which A4 removes and whose test data holds PEM headers and
//! bearer values on purpose.
//!
//! Two kinds of hit are known and left out, so that the guard is about what
//! the new rules do: the older name and Bearer matchers fire on documentation
//! and test corpora that quote `token = ...` forms (they did before this
//! detector existed), and `structural.rs` holds the command lines its own
//! tests feed to the structural rules.

use std::path::{Path, PathBuf};

use vahta_detect::{Mode, detect};

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name();
        if p.is_dir() {
            let skip = name == "target"
                || name == ".git"
                || name == "node_modules"
                || p.ends_with("crates/rules/rules")
                || p.ends_with("../../legacy");
            if !skip {
                walk(&p, out);
            }
        } else {
            out.push(p);
        }
    }
}

#[test]
fn the_repository_raises_no_blocking_finding() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    walk(&root, &mut files);
    assert!(files.len() > 100, "found {} files", files.len());
    let mut bad = Vec::new();
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        let own_tests = f.ends_with("crates/detect/src/structural.rs");
        if let Some(found) = detect(&text).finding
            && found.mode == Mode::Block
            && !own_tests
            && !matches!(found.rule.as_str(), "vahta.assignment" | "vahta.bearer")
        {
            bad.push(format!(
                "{}: {} ({:?})",
                f.strip_prefix(&root).unwrap_or(&f).display(),
                found.rule,
                found.evasion
            ));
        }
    }
    assert!(bad.is_empty(), "blocking findings:\n{}", bad.join("\n"));
}
