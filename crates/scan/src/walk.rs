//! Walking a project tree. **Package B — unimplemented.**
//!
//! Ports, from `src/key_amnesia/scan.py`:
//!   `DEFAULT_EXCLUDE_DIR_NAMES` (44), `_SKIP_SUFFIXES` (70),
//!   `_should_skip_dir` (756), `iter_project_files` (763), `scan_project` (785).
//!
//! Walk order is observable: `iter_project_files` sorts directory names, and
//! `scan_project` sorts its output. Both orderings are part of the contract.

use crate::finding::Finding;
use std::path::{Path, PathBuf};

/// `_should_skip_dir`. Under `include_excluded` only `.amnesia` is refused —
/// vault storage is never walked at any setting.
pub fn should_skip_dir(name: &str, include_excluded: bool) -> bool {
    let _ = (name, include_excluded);
    unimplemented!("package B")
}

/// `iter_project_files`. Returns a `Vec`, not an iterator: Python's generator
/// prunes `dirnames` in place, which has no direct Rust analogue, and the
/// caller consumes the whole list anyway.
pub fn project_files(root: &Path, include_excluded: bool) -> Vec<PathBuf> {
    let _ = (root, include_excluded);
    unimplemented!("package B")
}

/// `scan_project`. Deduplicates by resolved path, drops empty-dotenv
/// findings, and sorts by `(path, confidence rank)`.
pub fn scan_project(root: &Path, include_excluded: bool) -> Vec<Finding> {
    let _ = (root, include_excluded);
    unimplemented!("package B")
}
