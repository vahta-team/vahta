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
    let out = vahta(
        elsewhere.path(),
        &["scan", t.path().to_str().expect("utf-8 temp path")],
    );
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn the_strict_gate_decides_the_exit_code() {
    // A bare identifier-shaped assignment is `possible`: paranoid gates it,
    // high does not.
    let t = Tree::new();
    t.write(
        "notes.txt",
        &format!("{} = {}\n", "PASSWORD", "hunter7-correct-horse"),
    );
    let high = vahta(t.path(), &["scan", "--strict", "high"]);
    let paranoid = vahta(t.path(), &["scan", "--strict=paranoid"]);
    assert_eq!(high.status.code(), Some(0));
    assert_eq!(paranoid.status.code(), Some(1));
}

#[test]
fn default_exclusions_apply_and_wide_lifts_them() {
    let t = Tree::new();
    t.write(
        "node_modules/pkg/.env",
        &format!("{}={}\n", "API_KEY", value()),
    );
    assert_eq!(vahta(t.path(), &["scan"]).status.code(), Some(0));
    assert_eq!(vahta(t.path(), &["scan", "--wide"]).status.code(), Some(1));
}

/// `vahta` with a fake `$HOME`, so `--deep` never looks at the real one.
fn vahta_home(cwd: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vahta"))
        .current_dir(cwd)
        .env("HOME", home)
        .env_remove("APPDATA")
        .args(args)
        .output()
        .expect("run vahta")
}

fn assignment_line() -> String {
    format!(
        "{{\"text\": \"{}={}\"}}\n",
        ["API", "_KEY"].concat(),
        value()
    )
}

#[test]
fn deep_scans_the_home_directory_and_never_shows_a_value() {
    let project = Tree::new();
    project.write("README.md", "nothing here\n");
    let home = Tree::new();
    home.write(".npmrc", "registry=https://example.invalid/\n");
    home.write(
        ".claude/projects/p/s.jsonl",
        &format!("{{}}\n{}", assignment_line()),
    );
    let out = vahta_home(project.path(), home.path(), &["scan", "--deep", "--quiet"]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = text(&out.stdout);
    assert!(stdout.contains(".npmrc"), "{stdout}");
    assert!(stdout.contains("s.jsonl"), "{stdout}");
    assert!(stdout.contains("outside this project"), "{stdout}");
    assert!(!stdout.contains(&value()));
    assert!(!text(&out.stderr).contains(&value()));
    assert!(out.stderr.is_empty(), "--quiet silences progress");
}

#[test]
fn without_deep_the_home_directory_is_not_read() {
    let project = Tree::new();
    let home = Tree::new();
    home.write(".npmrc", "x\n");
    let out = vahta_home(project.path(), home.path(), &["scan"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(!text(&out.stdout).contains(".npmrc"));
}

#[test]
fn deep_progress_goes_to_stderr_and_names_no_content() {
    let project = Tree::new();
    let home = Tree::new();
    home.write(".claude/projects/p/s.jsonl", &assignment_line());
    let out = vahta_home(project.path(), home.path(), &["scan", "--deep", "--json"]);
    assert_eq!(text(&out.stderr), "agent transcripts 1/1\n");
    assert!(text(&out.stdout).trim_start().starts_with('{'));
}

#[test]
fn a_finding_already_seen_in_the_project_is_not_repeated_by_deep() {
    // The project *is* the home directory: every path is seen twice.
    let home = Tree::new();
    home.write(".npmrc", "x\n");
    let out = vahta_home(
        home.path(),
        home.path(),
        &["scan", "--deep", "--quiet", "--json"],
    );
    let stdout = text(&out.stdout);
    assert_eq!(stdout.matches("\"path\"").count(), 1, "{stdout}");
}

#[test]
fn a_clean_home_exits_zero() {
    let project = Tree::new();
    let home = Tree::new();
    let out = vahta_home(project.path(), home.path(), &["scan", "--deep", "--quiet"]);
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn deep_scans_hostile_lines_instead_of_stopping() {
    // Python aborts the whole scan on these; here they are lines like any
    // other, and a secret inside one is found, as is one elsewhere.
    let assignment = assignment_line();
    let assignment = assignment.trim_end();
    let quoted = format!("\"{}={}\"", ["API", "_KEY"].concat(), value());
    let deep = format!("{}{quoted}{}", "[".repeat(200_000), "]".repeat(200_000));
    let big = format!("[{}, {quoted}]", "9".repeat(5000));
    let project = Tree::new();
    let home = Tree::new();
    home.write(
        ".claude/projects/p/a.jsonl",
        &format!("{assignment}\n{deep}\n{big}\n"),
    );
    home.write(".claude/projects/p/b.jsonl", &format!("{deep}\n"));
    home.write(".claude/projects/p/c.jsonl", &format!("{big}\n"));
    home.write(
        ".claude/projects/p/d.jsonl",
        &format!("{}\n", "[".repeat(300_000)),
    );
    let out = vahta_home(
        project.path(),
        home.path(),
        &["scan", "--deep", "--quiet", "--json"],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    for file in ["a.jsonl", "b.jsonl", "c.jsonl"] {
        assert!(stdout.contains(file), "{file} missing from {stdout}");
    }
    assert!(!stdout.contains("d.jsonl"), "{stdout}");
    // Three lines in a.jsonl, one each in b and c.
    assert!(stdout.contains("\"transcript_line_hits\": 5"), "{stdout}");
    assert!(!stdout.contains(&value()));
}
