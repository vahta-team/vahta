//! The rule data: it parses, every regex compiles within the size limit, every
//! sample behaves, every keyword is one the rule's own matches contain, and
//! the repository's own files raise no blocking hit.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use regex_syntax::hir::{Class, Hir, HirKind};
use vahta_rules::{MAX_SCAN_BYTES, Mode, rules, scan};

fn hits_rule(text: &str, id: &str) -> bool {
    scan(text).hits.iter().any(|h| h.rule().id == id)
}

#[test]
fn the_embedded_files_parse() {
    // The build script parses them; a file that does not fails the build.
    assert!(rules().len() > 100, "only {} rules", rules().len());
}

#[test]
fn ids_are_unique_and_prefixed_by_origin() {
    let mut seen = HashSet::new();
    for r in rules() {
        assert!(seen.insert(r.id), "duplicate id {}", r.id);
        assert!(
            ["gitleaks.", "betterleaks.", "veles.", "vahta."]
                .iter()
                .any(|p| r.id.starts_with(p)),
            "{}",
            r.id
        );
        assert!(
            !r.category.is_empty() && !r.description.is_empty(),
            "{}",
            r.id
        );
        assert!(
            r.category.starts_with("a ") || r.category.starts_with("an "),
            "category needs its article: {}",
            r.id
        );
    }
}

#[test]
fn every_rule_compiles_and_has_keywords() {
    for r in rules() {
        assert!(r.regex().is_some(), "{} does not compile", r.id);
        assert!(!r.keywords.is_empty(), "{} has no keywords", r.id);
        for k in r.keywords {
            assert!(
                k.len() >= 3 || k.contains(['_', '~', '-']),
                "{}: keyword {k:?} is too short",
                r.id
            );
            assert_eq!(*k, k.to_lowercase(), "{}: keyword not lowercase", r.id);
        }
        assert!(
            r.secret_group < r.regex().map_or(0, |re| re.captures_len()),
            "{}: secret_group out of range",
            r.id
        );
    }
}

#[test]
fn identifiers_that_are_no_secret_alone_only_observe() {
    let mode = |id: &str| rules().iter().find(|r| r.id == id).map(|r| r.mode);
    assert_eq!(mode("betterleaks.azure-tenant-id"), Some(Mode::Observe));
    assert_eq!(mode("gitleaks.adobe-client-id"), Some(Mode::Observe));
    assert_eq!(mode("gitleaks.github-pat"), Some(Mode::Block));
    assert_eq!(mode("gitleaks.private-key"), Some(Mode::Block));
}

#[test]
fn every_sample_behaves() {
    let mut checked = 0;
    for r in rules() {
        for t in r.tests {
            let text = t.text();
            assert_eq!(hits_rule(&text, r.id), t.hit, "{}: {:?}", r.id, t.parts);
            checked += 1;
        }
    }
    for s in vahta_rules::samples() {
        assert!(
            rules().iter().any(|r| r.id == s.rule),
            "unknown rule {}",
            s.rule
        );
        assert_eq!(
            hits_rule(&s.text(), s.rule),
            s.hit,
            "{}: {:?}",
            s.rule,
            s.parts
        );
        checked += 1;
    }
    assert!(checked >= 30, "only {checked} samples");
}

// --- the keyword prefilter against the regex ---------------------------------

/// A deterministic string the pattern matches: literals as they are, a class
/// by its first member, repetitions at their minimum, the first alternative.
fn sample_of(h: &Hir, out: &mut String) {
    match h.kind() {
        HirKind::Empty | HirKind::Look(_) => {}
        HirKind::Literal(l) => out.push_str(&String::from_utf8_lossy(&l.0)),
        HirKind::Class(Class::Unicode(u)) => {
            if let Some(r) = u.iter().next() {
                out.push(r.start());
            }
        }
        HirKind::Class(Class::Bytes(b)) => {
            if let Some(r) = b.iter().next() {
                out.push(r.start() as char);
            }
        }
        HirKind::Repetition(r) => {
            for _ in 0..r.min {
                sample_of(&r.sub, out);
            }
        }
        HirKind::Capture(c) => sample_of(&c.sub, out),
        HirKind::Concat(items) => items.iter().for_each(|i| sample_of(i, out)),
        HirKind::Alternation(alts) => {
            if let Some(a) = alts.first() {
                sample_of(a, out);
            }
        }
    }
}

#[test]
fn every_rule_s_keywords_occur_in_what_its_regex_matches() {
    // A gitleaks keyword is a context hint and need not occur in the match
    // (the Airtable token has "airtable" nearby, not in it); the keywords
    // derived from a regex must.
    for r in rules().iter().filter(|r| !r.id.starts_with("gitleaks.")) {
        let hir = regex_syntax::parse(r.regex).expect("parses");
        let mut s = String::new();
        sample_of(&hir, &mut s);
        let Some(re) = r.regex() else { continue };
        // Only samples the regex really matches say anything about the rule.
        if !re.is_match(&s) {
            continue;
        }
        let lower = s.to_lowercase();
        assert!(
            r.keywords.iter().any(|k| lower.contains(k)),
            "{}: a match of the regex holds none of {:?}",
            r.id,
            r.keywords
        );
    }
}

// --- false-positive guard: the repository's own files -----------------------

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name();
        if p.is_dir() {
            // The rule files hold the regexes (and a few literals) the rules
            // match, so they match themselves; tests/ and src/ are the legacy
            // Python ka, which A4 removes, with PEM headers and bearer values
            // in its test data.
            let own = p.ends_with("crates/rules/rules");
            let legacy = p.ends_with("tests") && p.parent().is_some_and(|d| d.ends_with("../.."))
                || p.ends_with("src/key_amnesia");
            if name == "target" || name == ".git" || name == "node_modules" || own || legacy {
                continue;
            }
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[test]
fn the_repository_raises_no_blocking_hit() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    walk(&root, &mut files);
    assert!(files.len() > 100, "found {} files", files.len());
    let mut bad = Vec::new();
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        if text.len() > MAX_SCAN_BYTES {
            continue;
        }
        for h in scan(&text).hits {
            if h.rule().mode == Mode::Block {
                bad.push(format!(
                    "{}: {} at {:?}",
                    f.strip_prefix(&root).unwrap_or(&f).display(),
                    h.rule().id,
                    h.range
                ));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "blocking hits on the repo:\n{}",
        bad.join("\n")
    );
}
