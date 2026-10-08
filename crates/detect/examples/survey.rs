//! Counts what `find_secret` finds, per rule, over every text file under a
//! directory, and times it: a false-positive survey for rule changes.
//!
//! ```text
//! cargo run --release -p vahta-detect --example survey -- ~/.cargo/registry/src
//! ```
//!
//! Prints counts and file names, never values.
use std::collections::BTreeMap;
use std::path::Path;
fn walk(d: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(d) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if e.file_name() != ".git" && e.file_name() != "target" {
                walk(&p, out)
            }
        } else {
            out.push(p)
        }
    }
}
fn main() {
    let root = std::env::args().nth(1).unwrap();
    let mut files = Vec::new();
    walk(Path::new(&root), &mut files);
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut examples: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let (mut n, mut bytes) = (0usize, 0usize);
    let t = std::time::Instant::now();
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        n += 1;
        bytes += text.len();
        if let Some(found) = vahta_detect::detect(&text).finding {
            let key = format!("{} {:?}", found.rule, found.evasion);
            *counts.entry(key.clone()).or_default() += 1;
            let e = examples.entry(key).or_default();
            if e.len() < 3 {
                e.push(f.display().to_string())
            }
        }
    }
    println!("{n} files, {} MB, {:?}", bytes / 1_000_000, t.elapsed());
    let mut v: Vec<_> = counts.into_iter().collect();
    v.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    for (k, c) in v {
        println!("{c:6} {k}   e.g. {:?}", examples[&k]);
    }
}
