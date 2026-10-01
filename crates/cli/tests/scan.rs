//! Drives the real `vahta` binary: exit codes, `--json`, and that no value
//! ever reaches the output.
//!
//! Credential-shaped fixtures are assembled at run time from pieces, so the
//! product's own hook never sees one written into this file.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT: AtomicU32 = AtomicU32::new(0);

struct Tree(PathBuf);

impl Tree {
    fn new() -> Tree {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("vahta-cli-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        Tree(dir)
    }
    fn write(&self, rel: &str, body: &str) {
        let p = self.0.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(p, body).expect("write fixture");
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn value() -> String {
    ["aB3xQ9", "mK2pL7", "vN4wZ8"].concat()
}

fn dotenv(tree: &Tree) {
    tree.write(".env", &format!("{}={}\n", "API_KEY", value()));
}

fn vahta(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vahta"))
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("run vahta")
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn a_clean_tree_exits_zero() {
    let t = Tree::new();
    t.write("README.md", "nothing here\n");
    let out = vahta(t.path(), &["scan"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stdout).contains("0 LEAKs found"));
}

#[test]
fn a_dotenv_exits_one_and_names_but_never_shows_the_value() {
    let t = Tree::new();
    dotenv(&t);
    let out = vahta(t.path(), &["scan"]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("API_KEY"));
    assert!(!stdout.contains(&value()));
    assert!(!text(&out.stderr).contains(&value()));
}

#[test]
fn json_is_the_documented_shape_and_hides_values() {
    let t = Tree::new();
    dotenv(&t);
    let out = vahta(t.path(), &["scan", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = text(&out.stdout);
    assert!(stdout.starts_with("{\n  \"leak_count\": 1,"));
    assert!(stdout.contains("\"strict\": \"high\""));
    assert!(stdout.contains("\"secret_names\": [\n        \"API_KEY\"\n      ]"));
    assert!(!stdout.contains(&value()));
    // The document and exactly one newline: no trailing blank line.
    assert!(stdout.ends_with("}\n") && !stdout.ends_with("\n\n"));
}

#[test]
fn path_argument_is_scanned_instead_of_the_cwd() {
    let t = Tree::new();
    dotenv(&t);
    let elsewhere = Tree::new();
    let out = vahta(elsewhere.path(), &["scan", t.path().to_str().expect("utf-8 temp path")]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn the_strict_gate_decides_the_exit_code() {
    // A bare identifier-shaped assignment is `possible`: paranoid gates it,
    // high does not.
    let t = Tree::new();
    t.write("notes.txt", &format!("{} = {}\n", "PASSWORD", "hunter7-correct-horse"));
    let high = vahta(t.path(), &["scan", "--strict", "high"]);
    let paranoid = vahta(t.path(), &["scan", "--strict=paranoid"]);
    assert_eq!(high.status.code(), Some(0));
    assert_eq!(paranoid.status.code(), Some(1));
}

#[test]
fn default_exclusions_apply_and_wide_lifts_them() {
    let t = Tree::new();
    t.write("node_modules/pkg/.env", &format!("{}={}\n", "API_KEY", value()));
    assert_eq!(vahta(t.path(), &["scan"]).status.code(), Some(0));
    assert_eq!(vahta(t.path(), &["scan", "--wide"]).status.code(), Some(1));
}

#[test]
fn deep_is_a_usage_error_that_says_where_to_go() {
    let t = Tree::new();
    let out = vahta(t.path(), &["scan", "--deep"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("only available in the Python `ka scan`"));
    assert!(out.stdout.is_empty());
}

#[test]
fn usage_errors_exit_two() {
    let t = Tree::new();
    for args in [
        vec!["scan", "--strict", "bogus"],
        vec!["scan", "--strict"],
        vec!["scan", "--nope"],
        vec!["scan", "a", "b"],
        vec!["scan", "--yes"],
        vec!["frobnicate"],
        vec![],
    ] {
        let out = vahta(t.path(), &args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
    let missing = vahta(t.path(), &["scan", "no-such-dir"]);
    assert_eq!(missing.status.code(), Some(2));
}

#[test]
fn help_exits_zero() {
    let t = Tree::new();
    assert_eq!(vahta(t.path(), &["scan", "--help"]).status.code(), Some(0));
    assert_eq!(vahta(t.path(), &["--help"]).status.code(), Some(0));
}
