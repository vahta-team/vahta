//! Walking a project tree.
//!
//! Ports, from `src/key_amnesia/scan_py.py` (the module `scan.py` now
//! dispatches to; the line numbers survived the move unchanged):
//!   `DEFAULT_EXCLUDE_DIR_NAMES` (44), `_SKIP_SUFFIXES` (70),
//!   `_should_skip_dir` (756), `iter_project_files` (763), `scan_project` (785).
//!
//! Walk order is observable: `iter_project_files` sorts directory names, and
//! `scan_project` sorts its output. Both orderings are part of the contract.
//!
//! Python is the specification, including where it is arguably wrong.

use crate::finding::{Finding, Scope};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// `DEFAULT_EXCLUDE_DIR_NAMES`. Directory basenames skipped by default (B4).
///
/// `.git` skips all git internals — git-*history* secret scanning is
/// intentionally out of scope. `.amnesia` is vault ciphertext, not
/// agent-readable plaintext, and is the one name refused at every setting.
pub const DEFAULT_EXCLUDE_DIR_NAMES: [&str; 19] = [
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".git",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "target",
    ".next",
    ".nuxt",
    "coverage",
    ".eggs",
    ".amnesia",
    ".hg",
    ".svn",
];

/// `_SKIP_SUFFIXES`. Filename suffixes that are build/cache artifacts even
/// when the parent directory isn't excluded.
pub const SKIP_SUFFIXES: [&str; 3] = [".pyc", ".pyo", ".egg-info"];

/// `_should_skip_dir`. Under `include_excluded` only `.amnesia` is refused —
/// vault storage is never walked at any setting.
///
/// The `.egg-info` test is `name.endswith(".egg-info")`, **not** a suffix
/// comparison, and the difference is observable: verified against the
/// interpreter, `".egg-info".endswith(".egg-info")` is `True` while
/// `Path(".egg-info").suffix` is `''` (pathlib gives a leading-dot name no
/// suffix). So a directory named exactly `.egg-info` is pruned by Python, and
/// `ends_with` is the port that keeps that true.
pub fn should_skip_dir(name: &str, include_excluded: bool) -> bool {
    if include_excluded {
        // Still never walk into .amnesia vault storage.
        return name == ".amnesia";
    }
    DEFAULT_EXCLUDE_DIR_NAMES.contains(&name) || name.ends_with(".egg-info")
}

/// `iter_project_files`. Returns a `Vec`, not an iterator: Python's generator
/// prunes `dirnames` in place, which has no direct Rust analogue, and the
/// caller consumes the whole list anyway.
///
/// # Order
///
/// Python does `os.walk(root, topdown=True, followlinks=False)` and assigns
/// `dirnames[:] = sorted(...)`, so exactly two things are guaranteed and both
/// are reproduced here:
///
/// 1. **Pre-order**: a directory's own files are yielded before any of its
///    subdirectories are descended into.
/// 2. **Sorted descent**: subdirectories are visited in sorted basename order.
///
/// `filenames` is *not* sorted by Python, so **file order within a single
/// directory is unspecified** — it is whatever `readdir` returned. That is
/// left unspecified here too rather than quietly imposing a sort, because
/// imposing one would make Rust disagree with Python on any tree where the
/// order is observable. In practice both sides iterate the same `readdir`
/// stream (`os.scandir` and `std::fs::read_dir`) and so agree on Linux.
///
/// # Symlinks
///
/// Python resolves the *root* but not each entry, and classifies entries with
/// `os.scandir`'s `entry.is_dir()`, which **follows** symlinks. So a symlink
/// to a directory lands in `dirnames`, is subject to pruning, and with
/// `followlinks=False` is never descended into — contributing no files at all.
/// `Path::is_dir()` is used below for the same reason: `file_type().is_dir()`
/// does *not* follow symlinks and would misclassify such a link as a file and
/// wrongly yield it. A symlink to a *file*, and a broken symlink, both land in
/// `filenames` and are yielded; `scan_project` is where a broken one is
/// dropped.
///
/// A directory that cannot be read is skipped silently, matching `os.walk`'s
/// default `onerror=None`, which swallows the `scandir` error and yields
/// nothing for that directory without aborting the walk.
pub fn project_files(root: &Path, include_excluded: bool) -> Vec<PathBuf> {
    // Python: `root = root.resolve()` then `if not root.is_dir(): return`.
    //
    // `canonicalize` is the analogue of `Path.resolve()` but not an exact one:
    // verified against the interpreter, `resolve()` is non-strict and returns
    // the dangling target for a broken symlink or a missing path, whereas
    // `canonicalize` fails with `NotFound`. That difference cannot change the
    // outcome here: where `canonicalize` fails, Python's `resolve()` succeeds
    // but the following `is_dir()` is then `False`, so both return nothing.
    let Ok(root) = dunce::canonicalize(root) else {
        return Vec::new();
    };
    if !root.is_dir() {
        return Vec::new();
    }

    let mut out: Vec<PathBuf> = Vec::new();
    // Explicit stack instead of recursion: a deep tree must not be able to
    // overflow the stack. Children are pushed in reverse sorted order so that
    // popping visits them in sorted order.
    let mut stack: Vec<PathBuf> = vec![root];

    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            // os.walk(onerror=None): unreadable directory, walk continues.
            continue;
        };

        let mut subdirs: Vec<(std::ffi::OsString, PathBuf)> = Vec::new();

        for entry in entries.flatten() {
            let path = entry.path();
            let raw_name = entry.file_name();

            // Follows symlinks, and is `false` on any error, exactly as
            // `os.scandir`'s `entry.is_dir()` does.
            if path.is_dir() {
                // `followlinks=False`. CPython's os.walk recurses only
                // `if followlinks or not islink(new_path)`, so a symlink to a
                // directory stays in `dirnames` — and is therefore never
                // yielded as a file — but is not descended into. A
                // non-descended directory contributes nothing, so dropping it
                // here is equivalent to keeping it in a list we never walk.
                // `file_type()` does not follow the link, unlike `is_dir()`
                // above, which is what makes the distinction possible at all.
                let is_symlink = entry.file_type().map(|ft| ft.is_symlink()).unwrap_or(false);
                // A non-UTF-8 basename is the one place the exclusion test can
                // drift from Python, which decodes with surrogateescape; the
                // lossy replacement only matters if the invalid bytes fall
                // inside a name that would otherwise match an exclusion.
                if !is_symlink && !should_skip_dir(&raw_name.to_string_lossy(), include_excluded) {
                    subdirs.push((raw_name, path));
                }
            } else {
                let name = raw_name.to_string_lossy();
                // `any(fname.endswith(suf) for suf in _SKIP_SUFFIXES)`.
                //
                // Deliberately *outside* the `include_excluded` branch, as in
                // Python: `include_excluded` re-includes excluded
                // *directories* but never re-includes a `.pyc`, `.pyo` or
                // `.egg-info` *file*. Verified on a real tree — under
                // `include_excluded` a `pkg.egg-info/` directory is walked
                // while a file named `weird.egg-info` beside it is still
                // dropped. Odd, and ported as-is.
                if SKIP_SUFFIXES.iter().any(|suf| name.ends_with(suf)) {
                    continue;
                }
                out.push(path);
            }
        }

        // `dirnames[:] = sorted(...)`. Sorting the raw basename keeps the
        // comparison byte-wise, which on Unix is the order Python's sorted()
        // gives for every basename that is valid UTF-8.
        subdirs.sort_by(|a, b| a.0.cmp(&b.0));
        for (_, path) in subdirs.into_iter().rev() {
            stack.push(path);
        }
    }

    out
}

/// `findings.sort(key=lambda f: (f.path, _CONF_ORDER.get(f.confidence, 9)))`.
///
/// An unrecognised or empty confidence ranks 9, i.e. after `possible`, and does
/// not raise. Python's sort is stable and so is `sort_by`. Shared by the
/// project scan and the deep scan, which end the same way.
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        let ka = (&a.path, a.confidence_tier().map_or(9u8, |c| c.rank()));
        let kb = (&b.path, b.confidence_tier().map_or(9u8, |c| c.rank()));
        ka.cmp(&kb)
    });
}

/// `scan_project`. Deduplicates by resolved path, drops empty-dotenv
/// findings, and sorts by `(path, confidence rank)`.
///
/// # Is walk order observable?
///
/// Yes, but only through the deduplication, never through the sort.
///
/// The sort key is `(f.path, rank)`. For findings from *distinct* files the
/// paths differ, so the sort fully determines the output and the order the
/// files were visited in is erased. Findings that tie on both path and rank
/// can only come from one call to `findings_for_path`, whose own order the
/// stable sort preserves — that is per-file order, not walk order.
///
/// What walk order does decide is *which* of two dedup-equivalent paths
/// survives. A symlink and its target resolve to one key, so only the
/// first-visited is scanned, and its finding carries the **unresolved** path
/// it was visited by. Whether that is `link.env` or `real.env` therefore
/// changes the output. When the pair sits in the *same* directory this is
/// unspecified in Python itself (unsorted `filenames`); when it spans
/// directories, sorted descent makes it deterministic and this port
/// reproduces it.
pub fn scan_project(root: &Path, include_excluded: bool) -> Vec<Finding> {
    scan_project_with_threads(root, include_excluded, crate::par::default_threads())
}

/// Files per worker below which another thread is not worth its spawn cost.
const MIN_FILES_PER_THREAD: usize = 32;

/// [`scan_project`] on `threads` worker threads. The output does not depend on
/// `threads`: the walk, the `is_file` test and the de-duplication stay
/// sequential and in walk order, only the per-file classification (read,
/// detect) runs in parallel, and its results are consumed in walk order.
/// `threads == 1` runs entirely on the calling thread.
pub fn scan_project_with_threads(
    root: &Path,
    include_excluded: bool,
    threads: usize,
) -> Vec<Finding> {
    // Python keys the set on `str(path)`. A `PathBuf` key is used instead
    // because `Path::display()` is lossy for a non-UTF-8 path and could make
    // two genuinely different paths collide, dropping a real finding; Python's
    // surrogateescape decoding round-trips and never collides. For every
    // UTF-8 path the two are the same set.
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut files: Vec<PathBuf> = Vec::new();

    for path in project_files(root, include_excluded) {
        // Python: `if not path.is_file(): continue` inside try/except OSError.
        // `Path::is_file()` already returns `false` rather than erroring on a
        // broken symlink or an unreadable parent, as Python's does.
        if !path.is_file() {
            continue;
        }

        // Python: `key = str(path.resolve())`, falling back to the
        // *unresolved* path on OSError, so a file whose resolution fails
        // still gets scanned, keyed by how it was reached.
        let key = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        if !seen.insert(key) {
            continue;
        }
        files.push(path);
    }

    let mut findings: Vec<Finding> = Vec::new();
    let threads = threads.min(files.len() / MIN_FILES_PER_THREAD).max(1);
    crate::par::ordered_map(
        &files,
        threads,
        threads * 16,
        u64::MAX,
        |_| 0,
        |_, path| crate::content::findings_for_path(path, Scope::Project),
        |_, found| {
            for finding in found {
                // An empty `.env` is not a leak: no names and nothing counted.
                if finding.kind == "dotenv"
                    && finding.secret_count == 0
                    && finding.secret_names.is_empty()
                {
                    continue;
                }
                findings.push(finding);
            }
            true
        },
    );

    sort_findings(&mut findings);
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    const SEP: char = std::path::MAIN_SEPARATOR;

    /// A real tree in a uniquely named temporary directory, removed on drop so
    /// a failing assertion still cleans up. `tempfile` is not a dependency and
    /// this crate stays dependency-free.
    struct Tree {
        root: PathBuf,
    }

    impl Tree {
        fn new(tag: &str) -> Tree {
            use std::sync::atomic::{AtomicU32, Ordering};
            static SEQ: AtomicU32 = AtomicU32::new(0);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let unique = format!(
                "vahta-walk-{}-{}-{}-{}",
                tag,
                std::process::id(),
                nanos,
                SEQ.fetch_add(1, Ordering::Relaxed)
            );
            let root = std::env::temp_dir().join(unique);
            std::fs::create_dir_all(&root).expect("create test root");
            Tree { root }
        }

        /// Create a file, making its parent directories as needed.
        fn file(&self, rel: &str) -> PathBuf {
            let p = self.root.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).expect("create parent");
            }
            std::fs::write(&p, b"placeholder\n").expect("write file");
            p
        }

        fn dir(&self, rel: &str) -> PathBuf {
            let p = self.root.join(rel);
            std::fs::create_dir_all(&p).expect("create dir");
            p
        }

        /// Paths relative to the root, `/`-separated, as the walker yielded
        /// them — order preserved, because order is what several tests check.
        fn walk(&self, include_excluded: bool) -> Vec<String> {
            let base = dunce::canonicalize(&self.root).expect("canonicalize root");
            project_files(&self.root, include_excluded)
                .into_iter()
                .map(|p| {
                    p.strip_prefix(&base)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .replace('\\', "/")
                })
                .collect()
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            // Restore any mode stripped by a test so removal can succeed.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(entries) = std::fs::read_dir(&self.root) {
                    for e in entries.flatten() {
                        let p = e.path();
                        if p.is_dir() {
                            let _ = std::fs::set_permissions(
                                &p,
                                std::fs::Permissions::from_mode(0o755),
                            );
                        }
                    }
                }
            }
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn position(list: &[String], needle: &str) -> usize {
        list.iter()
            .position(|s| s == needle)
            .unwrap_or_else(|| panic!("{needle} missing from {list:?}"))
    }

    // ---- should_skip_dir -------------------------------------------------

    #[test]
    fn default_exclusions_are_skipped() {
        for name in DEFAULT_EXCLUDE_DIR_NAMES {
            assert!(should_skip_dir(name, false), "{name} should be skipped");
        }
        assert!(!should_skip_dir("src", false));
        assert!(!should_skip_dir("tests", false));
        // Substrings and near-misses are not exclusions.
        assert!(!should_skip_dir("node_modules_old", false));
        assert!(!should_skip_dir("distribution", false));
        assert!(!should_skip_dir(".gitignore", false));
    }

    /// `endswith(".egg-info")`, not a pathlib suffix test: a directory named
    /// exactly `.egg-info` has no suffix in pathlib's model yet `endswith` is
    /// `True`, so it is pruned. Read out of the interpreter.
    #[test]
    fn egg_info_is_matched_by_endswith_not_by_suffix() {
        assert!(should_skip_dir("pkg.egg-info", false));
        assert!(should_skip_dir(".egg-info", false));
        assert!(should_skip_dir("a.b.egg-info", false));
        assert!(!should_skip_dir("egg-info", false));
        assert!(!should_skip_dir("pkg.egg-info.bak", false));
    }

    /// Under `include_excluded` the whole default list is re-included and only
    /// `.amnesia` stays refused.
    #[test]
    fn include_excluded_refuses_only_the_vault() {
        assert!(should_skip_dir(".amnesia", true));
        for name in DEFAULT_EXCLUDE_DIR_NAMES {
            if name == ".amnesia" {
                continue;
            }
            assert!(
                !should_skip_dir(name, true),
                "{name} should be walked under include_excluded"
            );
        }
        // The .egg-info rule is part of the default branch only.
        assert!(!should_skip_dir("pkg.egg-info", true));
        assert!(!should_skip_dir(".egg-info", true));
    }

    // ---- project_files: pruning -----------------------------------------

    #[test]
    fn excluded_directories_are_pruned_by_default() {
        let t = Tree::new("prune");
        t.file("keep.py");
        t.file("src/keep.py");
        for d in DEFAULT_EXCLUDE_DIR_NAMES {
            t.file(&format!("{d}/inside.py"));
        }
        t.file("pkg.egg-info/PKG-INFO");
        t.file(".egg-info/inside.py");

        let got = t.walk(false);
        assert_eq!(
            got.len(),
            2,
            "only the two kept files should survive: {got:?}"
        );
        assert!(got.contains(&"keep.py".to_string()));
        assert!(got.contains(&"src/keep.py".to_string()));
        for d in DEFAULT_EXCLUDE_DIR_NAMES {
            assert!(
                !got.contains(&format!("{d}/inside.py")),
                "{d} was walked but should have been pruned"
            );
        }
        assert!(!got.contains(&"pkg.egg-info/PKG-INFO".to_string()));
        assert!(!got.contains(&".egg-info/inside.py".to_string()));
    }

    /// Pruning is recursive: an excluded directory's *children* are never
    /// reached either, not merely its immediate files.
    #[test]
    fn pruning_stops_the_descent_entirely() {
        let t = Tree::new("deep");
        t.file("node_modules/pkg/lib/deep.py");
        t.file("ok/pkg/lib/deep.py");
        let got = t.walk(false);
        assert_eq!(got, vec!["ok/pkg/lib/deep.py".to_string()]);
    }

    #[test]
    fn include_excluded_walks_them_but_never_the_vault() {
        let t = Tree::new("inc");
        t.file("keep.py");
        t.file("node_modules/inside.py");
        t.file("target/inside.py");
        t.file("pkg.egg-info/PKG-INFO");
        t.file(".amnesia/inside.py");
        t.file(".amnesia/nested/deep.py");

        let got = t.walk(true);
        assert!(got.contains(&"node_modules/inside.py".to_string()));
        assert!(got.contains(&"target/inside.py".to_string()));
        assert!(got.contains(&"pkg.egg-info/PKG-INFO".to_string()));
        assert!(
            !got.contains(&".amnesia/inside.py".to_string()),
            "vault storage must never be walked: {got:?}"
        );
        assert!(!got.contains(&".amnesia/nested/deep.py".to_string()));
        assert_eq!(got.len(), 4, "{got:?}");
    }

    /// The odd branch: `include_excluded` re-includes excluded *directories*
    /// but the `_SKIP_SUFFIXES` filter on *files* is unconditional.
    #[test]
    fn skip_suffix_files_are_dropped_at_both_settings() {
        let t = Tree::new("suffix");
        t.file("keep.py");
        t.file("mod.pyc");
        t.file("mod.pyo");
        t.file("weird.egg-info");
        t.file("sub/mod.pyc");

        for include_excluded in [false, true] {
            let got = t.walk(include_excluded);
            assert_eq!(
                got,
                vec!["keep.py".to_string()],
                "include_excluded={include_excluded}"
            );
        }
    }

    // ---- project_files: order -------------------------------------------

    /// Sorted descent. The directories are *created* in an order unrelated to
    /// their sorted order, so a walker that used creation or readdir order
    /// would fail this.
    #[test]
    fn subdirectories_are_descended_in_sorted_order() {
        let t = Tree::new("order");
        for d in ["zsub", "msub", "asub", "Bsub"] {
            t.file(&format!("{d}/f.py"));
        }
        let got = t.walk(false);
        // Capital 'B' sorts before lowercase by code point, as Python sorts.
        let expected = vec![
            "Bsub/f.py".to_string(),
            "asub/f.py".to_string(),
            "msub/f.py".to_string(),
            "zsub/f.py".to_string(),
        ];
        assert_eq!(got, expected, "descent must be in sorted basename order");
    }

    /// Pre-order: `topdown=True` yields a directory's own files before it
    /// descends. Also checks a nested level keeps the same discipline.
    #[test]
    fn a_directorys_files_precede_its_subdirectories() {
        let t = Tree::new("preorder");
        t.file("root.py");
        t.file("mid/mid.py");
        t.file("mid/deeper/deep.py");
        let got = t.walk(false);
        assert_eq!(got.len(), 3, "{got:?}");
        assert!(
            position(&got, "root.py") < position(&got, "mid/mid.py"),
            "{got:?}"
        );
        assert!(
            position(&got, "mid/mid.py") < position(&got, "mid/deeper/deep.py"),
            "{got:?}"
        );
    }

    /// A whole subtree is finished before the next sibling starts, which is
    /// what depth-first means and is not implied by the two tests above.
    #[test]
    fn descent_is_depth_first_not_breadth_first() {
        let t = Tree::new("dfs");
        t.file("a/child/leaf.py");
        t.file("b/b.py");
        let got = t.walk(false);
        assert_eq!(
            got,
            vec!["a/child/leaf.py".to_string(), "b/b.py".to_string()],
            "a's subtree must complete before b"
        );
    }

    // ---- project_files: symlinks and errors ------------------------------

    /// `followlinks=False`: a symlink to a directory is classified as a
    /// directory (so it is never yielded as a file) and is not descended into,
    /// so it contributes nothing at all.
    #[test]
    #[cfg(unix)]
    fn a_symlinked_directory_is_neither_yielded_nor_descended() {
        let t = Tree::new("dirlink");
        let real = t.dir("real");
        std::fs::write(real.join("inner.py"), b"x\n").expect("write");
        std::os::unix::fs::symlink(&real, t.root.join("link_to_dir")).expect("symlink");

        let got = t.walk(false);
        assert_eq!(
            got,
            vec!["real/inner.py".to_string()],
            "the symlinked directory must contribute nothing: {got:?}"
        );
        assert!(!got.contains(&"link_to_dir".to_string()));
        assert!(!got.contains(&"link_to_dir/inner.py".to_string()));
    }

    /// A symlink to a file is an ordinary entry in `filenames` and is yielded,
    /// whether its target is inside the tree or outside it. Dedup happens
    /// later, in `scan_project`, not here.
    #[test]
    #[cfg(unix)]
    fn symlinks_to_files_are_yielded_including_one_pointing_outside() {
        let t = Tree::new("filelink");
        let target = t.file("real.py");
        let outside = Tree::new("filelink-out");
        let outside_target = outside.file("far.py");
        std::os::unix::fs::symlink(&target, t.root.join("link_inside.py")).expect("symlink");
        std::os::unix::fs::symlink(&outside_target, t.root.join("link_outside.py"))
            .expect("symlink");

        let mut got = t.walk(false);
        got.sort();
        assert_eq!(
            got,
            vec![
                "link_inside.py".to_string(),
                "link_outside.py".to_string(),
                "real.py".to_string(),
            ]
        );
    }

    /// A broken symlink lands in `filenames` (its `is_dir()` is false) and is
    /// yielded by the walker; dropping it is `scan_project`'s job.
    #[test]
    #[cfg(unix)]
    fn a_broken_symlink_is_yielded_by_the_walker() {
        let t = Tree::new("broken");
        std::os::unix::fs::symlink(t.root.join("nothing-here.py"), t.root.join("broken.py"))
            .expect("symlink");
        let got = t.walk(false);
        assert_eq!(got, vec!["broken.py".to_string()]);
        // And it is genuinely broken, so scan_project's is_file() gate drops it.
        assert!(!t.root.join("broken.py").is_file());
        // canonicalize fails where Python's non-strict resolve() would not;
        // unreachable in scan_project because is_file() already excluded it.
        assert!(std::fs::canonicalize(t.root.join("broken.py")).is_err());
    }

    /// `os.walk(onerror=None)` swallows the error: the unreadable directory
    /// yields nothing and the rest of the walk still happens.
    #[test]
    #[cfg(unix)]
    fn an_unreadable_directory_is_skipped_without_aborting_the_walk() {
        use std::os::unix::fs::PermissionsExt;
        let t = Tree::new("noperm");
        t.file("before.py");
        t.file("zzz_after/after.py");
        let locked = t.dir("locked");
        std::fs::write(locked.join("hidden.py"), b"x\n").expect("write");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");

        let got = t.walk(false);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).ok();

        assert!(!got.contains(&"locked/hidden.py".to_string()), "{got:?}");
        assert!(
            got.contains(&"before.py".to_string()),
            "walk aborted early: {got:?}"
        );
        assert!(
            got.contains(&"zzz_after/after.py".to_string()),
            "walk did not continue past the unreadable directory: {got:?}"
        );
        assert_eq!(got.len(), 2, "{got:?}");
    }

    // ---- project_files: root handling -----------------------------------

    #[test]
    fn a_missing_root_yields_nothing() {
        let t = Tree::new("missing");
        let absent = t.root.join("not-there");
        assert!(project_files(&absent, false).is_empty());
        assert!(project_files(&absent, true).is_empty());
    }

    /// `if not root.is_dir(): return` — a file as root yields nothing rather
    /// than yielding the file itself.
    #[test]
    fn a_file_as_root_yields_nothing() {
        let t = Tree::new("fileroot");
        let f = t.file("solo.py");
        assert!(project_files(&f, false).is_empty());
    }

    #[test]
    fn an_empty_root_yields_nothing() {
        let t = Tree::new("empty");
        assert!(project_files(&t.root, false).is_empty());
    }

    /// `root.resolve()` makes the yielded paths absolute even when the root
    /// given was relative or unnormalised. Both sides normalise the root
    /// before building any child path, which is why `str(Path(...))` and
    /// `Path::display()` disagreeing on `"a/"`, `"./a"` and `"a//b"`
    /// (verified: pathlib normalises all three, `display()` normalises none)
    /// cannot be observed through this function.
    #[test]
    fn yielded_paths_are_absolute_and_normalised() {
        let t = Tree::new("abs");
        t.file("f.py");
        t.dir("sub");
        let unnormalised = t.root.join("./sub/.."); // resolves back to root
        let got = project_files(&unnormalised, false);
        assert_eq!(got.len(), 1, "{got:?}");
        let p = &got[0];
        assert!(p.is_absolute(), "{p:?}");
        let s = p.to_string_lossy();
        assert!(!s.contains("/./"), "{s}");
        assert!(!s.contains(".."), "{s}");
        assert!(!s.contains("//"), "{s}");
        assert!(s.ends_with(&format!("{SEP}f.py")), "{s}");
    }

    /// A symlink *as the root* is resolved, because Python resolves the root,
    /// so the walk happens in the target and yields paths under it.
    #[test]
    #[cfg(unix)]
    fn a_symlinked_root_is_resolved_before_walking() {
        let t = Tree::new("rootlink");
        let real = t.dir("real");
        std::fs::write(real.join("inner.py"), b"x\n").expect("write");
        let link = t.root.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let got = project_files(&link, false);
        assert_eq!(got.len(), 1, "{got:?}");
        let s = got[0].to_string_lossy();
        assert!(s.ends_with("/real/inner.py"), "root not resolved: {s}");
    }

    // ---- scan_project ----------------------------------------------------
    //
    // Anything that reaches a real file needs `content::findings_for_path`,
    // which is package A. The cases below are the ones reachable without a
    // classification at all, so they hold whatever package A does; the

    #[test]
    fn scan_project_on_a_missing_root_yields_nothing() {
        let t = Tree::new("scan-missing");
        assert!(scan_project(&t.root.join("not-there"), false).is_empty());
    }

    /// The root is not a directory, so `project_files` is empty and
    /// `findings_for_path` is never called.
    #[test]
    fn scan_project_on_a_file_root_yields_nothing() {
        let t = Tree::new("scan-fileroot");
        let f = t.file("solo.py");
        assert!(scan_project(&f, false).is_empty());
    }

    #[test]
    fn scan_project_on_an_empty_directory_yields_nothing() {
        let t = Tree::new("scan-empty");
        assert!(scan_project(&t.root, false).is_empty());
    }

    /// A tree containing only pruned directories and skipped files reaches no
    /// file at all, so this too needs no classification.
    #[test]
    fn scan_project_yields_nothing_when_everything_is_pruned() {
        let t = Tree::new("scan-pruned");
        t.file("node_modules/inside.py");
        t.file(".git/config");
        t.file("mod.pyc");
        assert!(scan_project(&t.root, false).is_empty());
    }

    /// A tree whose only entry is a broken symlink: the walker yields it and
    /// the `is_file()` gate drops it, so `findings_for_path` is never reached.
    /// This is the one case that exercises `scan_project`'s own loop body
    /// against a non-empty walk without needing package A.
    #[test]
    #[cfg(unix)]
    fn scan_project_drops_a_broken_symlink_before_classifying() {
        let t = Tree::new("scan-broken");
        std::os::unix::fs::symlink(t.root.join("nothing-here.py"), t.root.join("broken.py"))
            .expect("symlink");
        assert_eq!(
            project_files(&t.root, false).len(),
            1,
            "walker must yield it"
        );
        // Would panic with unimplemented!("package A") if the gate let it past.
        assert!(scan_project(&t.root, false).is_empty());
    }

    /// Both names must be ones `filenames::is_dotenv_filename` accepts, or
    /// `findings_for_path` returns nothing and the test passes for the wrong
    /// reason: `real.env` is *not* a dotenv name, only `.env` and `.env.*` are.
    #[test]
    #[cfg(unix)]
    fn scan_project_deduplicates_a_symlink_against_its_target() {
        let t = Tree::new("scan-dedup");
        // One non-empty value, so the empty-dotenv filter does not drop it.
        let target = t.root.join(".env");
        std::fs::write(&target, b"A=b\n").expect("write");
        std::os::unix::fs::symlink(&target, t.root.join(".env.local")).expect("symlink");

        // Both are walked and both resolve to the same path, so exactly one
        // survives the dedup. *Which* one is unspecified in Python too: they
        // sit in one directory and `filenames` is not sorted.
        assert_eq!(
            project_files(&t.root, false).len(),
            2,
            "both names must reach the dedup for this to prove anything"
        );
        let got = scan_project(&t.root, false);
        assert_eq!(got.len(), 1, "{got:?}");
    }

    /// The `.env` files need a real `KEY=VALUE`, or the empty-dotenv filter
    /// drops both findings and the sort assertion passes on two empty vectors
    /// — proving nothing. The non-empty count assertion is what guards that.
    #[test]
    fn scan_project_sorts_by_path_then_confidence() {
        let t = Tree::new("scan-sort");
        // Created b-then-a so an unsorted output would come back in this order.
        t.dir("b");
        std::fs::write(t.root.join("b/.env"), b"B=1\n").expect("write");
        t.dir("a");
        std::fs::write(t.root.join("a/.env"), b"A=1\n").expect("write");

        let got = scan_project(&t.root, false);
        assert_eq!(got.len(), 2, "both dotenvs must survive: {got:?}");
        let paths: Vec<&str> = got.iter().map(|f| f.path.as_str()).collect();
        let mut sorted = paths.clone();
        sorted.sort_unstable();
        assert_eq!(paths, sorted, "output must be sorted by path");
        assert!(paths[0].ends_with(&format!("{SEP}a{SEP}.env")), "{paths:?}");
        assert!(paths[1].ends_with(&format!("{SEP}b{SEP}.env")), "{paths:?}");
    }

    #[test]
    fn scan_project_drops_an_empty_dotenv() {
        let t = Tree::new("scan-emptyenv");
        std::fs::write(t.root.join(".env"), b"\n# just a comment\n").expect("write");
        assert!(scan_project(&t.root, false).is_empty());
    }

    #[test]
    fn thread_count_does_not_change_the_project_scan() {
        let t = Tree::new("par");
        let name = ["API", "_KEY"].concat();
        for d in 0..12 {
            for f in 0..30 {
                let rel = format!("d{d}/e{}/f{f}.env", f % 3);
                let p = t.root.join(&rel);
                std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
                let body = match f % 4 {
                    0 => format!("{name}=aB3xQ9mK2pL7vN4wZ8{d}{f}\n"),
                    1 => String::new(),
                    2 => "# comment\n".repeat(f * 500),
                    _ => format!("{name}=short\nOTHER=1\n"),
                };
                std::fs::write(&p, body).expect("write");
            }
        }
        #[cfg(unix)]
        {
            let _ =
                std::os::unix::fs::symlink(t.root.join("d0/e0/f0.env"), t.root.join("d1/link.env"));
        }
        let base = scan_project_with_threads(&t.root, false, 1);
        assert!(base.len() > 50);
        for _ in 0..3 {
            for n in [2, 3, 8, 16, 64] {
                assert_eq!(
                    scan_project_with_threads(&t.root, false, n),
                    base,
                    "threads={n}"
                );
            }
        }
    }
}
