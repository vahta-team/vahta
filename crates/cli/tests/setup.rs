//! Drives the real `vahta setup`. Every run uses a temporary `HOME`, `PATH`,
//! `USERPROFILE` and `CODEX_HOME`, so the real agent configs are never read or
//! written. A copy of the `vahta` binary sits in `bin/` next to a stand-in
//! `vahta-hook`, which is where setup looks for the hook.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT: AtomicU32 = AtomicU32::new(0);
/// `.exe` on Windows: setup looks for `vahta-hook.exe` next to `vahta.exe`.
const EXE: &str = std::env::consts::EXE_SUFFIX;

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(with_hook: bool) -> Sandbox {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("vahta-setup-cli-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for d in ["bin", "home", "path"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        // A hard link when the file systems allow it: copying a binary and
        // running it from another thread's fork can fail with "text file busy".
        let exe = root.join(format!("bin/vahta{EXE}"));
        if fs::hard_link(env!("CARGO_BIN_EXE_vahta"), &exe).is_err() {
            fs::copy(env!("CARGO_BIN_EXE_vahta"), &exe).unwrap();
        }
        if with_hook {
            fs::write(root.join(format!("bin/vahta-hook{EXE}")), "#!/bin/sh\n").unwrap();
        }
        Sandbox(root)
    }
    fn home(&self) -> PathBuf {
        self.0.join("home")
    }
    /// The hook path as setup records it: canonical, with the platform's
    /// separators (a `bin/...` join would leave a `/` in a Windows path).
    fn hook(&self) -> PathBuf {
        let p = self.0.join("bin").join(format!("vahta-hook{EXE}"));
        dunce::canonicalize(&p).unwrap_or(p)
    }
    /// Make a harness "found" by its config directory.
    fn found(&self, dir: &str) {
        fs::create_dir_all(self.home().join(dir)).unwrap();
    }
    fn vahta(&self, args: &[&str]) -> Output {
        Command::new(self.0.join(format!("bin/vahta{EXE}")))
            .current_dir(&self.0)
            .args(args)
            .env_clear()
            .env("HOME", self.home())
            .env("USERPROFILE", self.home())
            .env("PATH", self.0.join("path"))
            .output()
            .expect("run vahta")
    }
    fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.home().join(rel)).unwrap()
    }
    fn exists(&self, rel: &str) -> bool {
        self.home().join(rel).exists()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

const CLAUDE: &str = ".claude/settings.json";

#[test]
fn bare_setup_prints_the_table_and_writes_nothing() {
    let s = Sandbox::new(true);
    s.found(".claude");
    let out = s.vahta(&["setup"]);
    assert_eq!(out.status.code(), Some(0));
    let o = text(&out.stdout);
    assert!(
        o.contains("harness") && o.contains("set up") && o.contains("config"),
        "{o}"
    );
    assert!(o.contains("Claude Code  yes"), "{o}");
    assert!(o.contains("Codex") && o.contains("not found"), "{o}");
    assert!(
        o.contains("vahta setup --all") && o.contains("--claude"),
        "{o}"
    );
    assert!(!s.exists(CLAUDE));
    assert!(text(&out.stderr).is_empty());
}

#[test]
fn a_harness_flag_refuses_when_not_found_and_force_overrides() {
    let s = Sandbox::new(true);
    let out = s.vahta(&["setup", "--codex"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("Codex not found"),
        "{}",
        text(&out.stderr)
    );
    assert!(!s.exists(".codex"));

    let out = s.vahta(&["setup", "--codex", "--force"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        s.read(".codex/hooks.json")
            .contains("--harness codex --event before_tool")
    );
}

#[test]
fn install_dry_run_status_and_uninstall() {
    let s = Sandbox::new(true);
    s.found(".claude");
    let before = r#"{"model": "opus", "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "key-amnesia-hook"}]}]}}"#;
    fs::write(s.home().join(CLAUDE), before).unwrap();

    let out = s.vahta(&["setup", "--claude", "--dry-run"]);
    assert_eq!(out.status.code(), Some(0));
    let o = text(&out.stdout);
    assert!(
        o.contains("--- ")
            && o.contains("+++ ")
            && o.contains("settings.json")
            && o.contains("+            \"command\""),
        "{o}"
    );
    assert_eq!(s.read(CLAUDE), before, "dry run writes nothing");
    assert!(!s.exists(".claude/settings.json.vahta-backup"));

    let out = s.vahta(&["setup", "--claude"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    // As it appears inside the JSON string: Windows backslashes are escaped.
    let hook = s.hook().display().to_string().replace('\\', "\\\\");
    assert!(s.read(CLAUDE).contains(&format!(
        "{hook} --harness claude --event before_tool --setup 1"
    )));
    assert_eq!(s.read(".claude/settings.json.vahta-backup"), before);
    let o = text(&s.vahta(&["setup"]).stdout);
    assert!(o.contains("Claude Code  yes    current"), "{o}");

    // Installing again changes nothing.
    let installed = s.read(CLAUDE);
    let out = s.vahta(&["setup", "--claude"]);
    assert!(text(&out.stdout).contains("already current"));
    assert_eq!(s.read(CLAUDE), installed);

    let out = s.vahta(&["setup", "--claude", "--uninstall", "--dry-run"]);
    assert!(
        text(&out.stdout).contains("-            \"command\""),
        "{}",
        text(&out.stdout)
    );
    assert_eq!(s.read(CLAUDE), installed);
    let out = s.vahta(&["setup", "--claude", "--uninstall"]);
    assert_eq!(out.status.code(), Some(0));
    let back: serde_like::Json = serde_like::parse(&s.read(CLAUDE));
    assert_eq!(back, serde_like::parse(before));
    assert!(text(&s.vahta(&["setup"]).stdout).contains("Claude Code  yes    none"));
}

/// The configs compared as JSON, without a JSON dependency in this test:
/// whitespace is stripped outside strings, which is enough for these fixtures.
mod serde_like {
    #[derive(PartialEq, Debug)]
    pub struct Json(String);
    pub fn parse(s: &str) -> Json {
        let (mut out, mut in_str, mut esc) = (String::new(), false, false);
        for c in s.chars() {
            if in_str {
                out.push(c);
                if esc {
                    esc = false
                } else if c == '\\' {
                    esc = true
                } else if c == '"' {
                    in_str = false
                }
            } else if !c.is_whitespace() {
                out.push(c);
                in_str = c == '"';
            }
        }
        Json(out)
    }
}

#[test]
fn all_acts_on_found_harnesses_and_lists_the_rest() {
    let s = Sandbox::new(true);
    s.found(".claude");
    s.found(".cursor");
    let out = s.vahta(&["setup", "--all"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let o = text(&out.stdout);
    assert!(o.contains("Codex: skipped, not found"), "{o}");
    assert!(s.exists(CLAUDE) && s.exists(".cursor/hooks.json"));
    assert!(!s.exists(".codex"));
    assert!(s.read(".cursor/hooks.json").contains("\"version\": 1"));

    // --all --uninstall acts on whatever has entries of ours, found or not.
    fs::remove_dir_all(s.home().join(".cursor")).ok();
    let out = s.vahta(&["setup", "--all", "--uninstall"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(!s.read(CLAUDE).contains("vahta-hook"));
}

#[test]
fn a_config_that_is_not_json_is_refused_and_nothing_is_written() {
    let s = Sandbox::new(true);
    s.found(".claude");
    s.found(".cursor");
    fs::write(s.home().join(CLAUDE), "{ not json").unwrap();
    let out = s.vahta(&["setup", "--all"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("not valid JSON"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(s.read(CLAUDE), "{ not json");
    assert!(!s.exists(".claude/settings.json.vahta-backup"));
    assert!(
        !s.exists(".cursor/hooks.json"),
        "the other harness is not written either"
    );
}

#[test]
fn a_missing_hook_binary_is_a_clear_error() {
    let s = Sandbox::new(false);
    s.found(".claude");
    let out = s.vahta(&["setup", "--claude"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("vahta-hook not found"),
        "{}",
        text(&out.stderr)
    );
    assert!(!s.exists(CLAUDE));
}

#[test]
fn usage_errors_exit_two() {
    let s = Sandbox::new(true);
    for args in [
        &["setup", "--all", "--claude"][..],
        &["setup", "--dry-run"],
        &["setup", "--bogus"],
        &["setup", "--all", "--force"],
    ] {
        let out = s.vahta(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
    assert_eq!(s.vahta(&["setup", "--help"]).status.code(), Some(0));
}

#[test]
fn the_stale_notice_goes_to_stderr_only_and_only_when_outdated() {
    let s = Sandbox::new(true);
    s.found(".claude");
    let scan = |s: &Sandbox| s.vahta(&["scan", "--json", "."]);

    // Nothing set up: silent.
    let out = scan(&s);
    assert!(text(&out.stderr).is_empty(), "{}", text(&out.stderr));

    // Current: silent.
    s.vahta(&["setup", "--claude"]);
    assert!(text(&scan(&s).stderr).is_empty());

    // Outdated: one line on stderr, none on stdout, which stays JSON.
    let cfg = s.home().join(CLAUDE);
    fs::write(
        &cfg,
        fs::read_to_string(&cfg)
            .unwrap()
            .replace("--setup 1", "--setup 0"),
    )
    .unwrap();
    let out = scan(&s);
    assert_eq!(
        text(&out.stderr),
        "vahta: setup for Claude Code is outdated; run `vahta setup --claude`\n"
    );
    let o = text(&out.stdout);
    assert!(
        o.trim_start().starts_with('{') && !o.contains("outdated"),
        "{o}"
    );

    // `setup` itself does not print it; its table says so.
    let out = s.vahta(&["setup"]);
    assert!(text(&out.stderr).is_empty());
    assert!(text(&out.stdout).contains("outdated"));

    // Fixed by running the suggested command.
    s.vahta(&["setup", "--claude"]);
    assert!(text(&scan(&s).stderr).is_empty());
}

#[test]
fn a_hook_path_that_no_longer_exists_is_flagged_in_the_table() {
    let s = Sandbox::new(true);
    s.found(".claude");
    s.vahta(&["setup", "--claude"]);
    fs::remove_file(s.hook()).unwrap();
    let o = text(&s.vahta(&["setup"]).stdout);
    assert!(o.contains("does not exist"), "{o}");
    // And on every other command: the harness now runs nothing.
    let out = s.vahta(&["scan", "--json", "."]);
    assert_eq!(
        text(&out.stderr),
        "vahta: the hook set up for Claude Code no longer exists; run `vahta setup --claude`\n"
    );
}

#[test]
fn codex_setup_says_to_trust_the_hooks_in_codex() {
    let s = Sandbox::new(true);
    s.found(".codex");
    let o = text(&s.vahta(&["setup", "--codex"]).stdout);
    assert!(o.contains("run /hooks and trust"), "{o}");
    // The table keeps saying it while the setup is there, and only for Codex.
    let o = text(&s.vahta(&["setup"]).stdout);
    assert!(o.contains("Codex: Codex skips new or changed hooks"), "{o}");
    assert!(!o.contains("Claude Code: Codex"), "{o}");
    // An uninstall does not ask for trust.
    assert!(!text(&s.vahta(&["setup", "--codex", "--uninstall"]).stdout).contains("run /hooks"));
}

#[test]
fn refresh_reinstalls_only_the_harnesses_that_have_ours() {
    let s = Sandbox::new(true);
    s.found(".claude");
    s.found(".cursor");
    s.vahta(&["setup", "--claude"]);
    assert!(!s.exists(".cursor/hooks.json"));

    // Outdated in Claude Code; Cursor is found but has nothing of ours.
    let cfg = s.home().join(CLAUDE);
    fs::write(
        &cfg,
        fs::read_to_string(&cfg)
            .unwrap()
            .replace("--setup 1", "--setup 0"),
    )
    .unwrap();
    let out = s.vahta(&["setup", "--refresh"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("Claude Code: installed"),
        "{}",
        text(&out.stdout)
    );
    assert!(s.read(CLAUDE).contains("--setup 1") && !s.read(CLAUDE).contains("--setup 0"));
    assert!(
        !s.exists(".cursor/hooks.json"),
        "a harness with none of ours is left alone"
    );
    assert!(text(&s.vahta(&["setup"]).stdout).contains("Claude Code  yes    current"));
}

#[test]
fn refresh_repoints_a_hook_path_that_points_elsewhere() {
    let s = Sandbox::new(true);
    s.found(".claude");
    s.vahta(&["setup", "--claude"]);
    let other = s.0.join("elsewhere");
    fs::create_dir_all(&other).unwrap();
    fs::write(other.join("vahta-hook"), "#!/bin/sh\n").unwrap();
    // As the paths appear inside the JSON: backslashes are escaped on Windows.
    let in_json = |p: &std::path::Path| {
        let quoted = serde_json::to_string(&p.display().to_string()).unwrap();
        quoted[1..quoted.len() - 1].to_string()
    };
    let (here, there) = (in_json(&s.hook()), in_json(&other.join("vahta-hook")));
    let cfg = s.home().join(CLAUDE);
    fs::write(
        &cfg,
        fs::read_to_string(&cfg).unwrap().replace(&here, &there),
    )
    .unwrap();
    assert!(text(&s.vahta(&["setup"]).stdout).contains("is not the vahta-hook next to this vahta"));

    let out = s.vahta(&["setup", "--refresh"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let after = s.read(CLAUDE);
    assert!(
        after.contains(&format!("{here} --harness claude")) && !after.contains(&there),
        "{after}"
    );
    assert!(!text(&s.vahta(&["setup"]).stdout).contains("is not the vahta-hook"));
}

#[test]
fn refresh_leaves_foreign_entries_alone() {
    let s = Sandbox::new(true);
    s.found(".claude");
    let before = r#"{"model": "opus", "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "key-amnesia-hook"}]}]}}"#;
    fs::write(s.home().join(CLAUDE), before).unwrap();
    // Only a foreign entry: that is not ours, so nothing is written.
    let out = s.vahta(&["setup", "--refresh"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(s.read(CLAUDE), before);

    s.vahta(&["setup", "--claude"]);
    s.vahta(&["setup", "--refresh"]);
    let back = s.read(CLAUDE);
    assert!(
        back.contains("key-amnesia-hook") && back.contains("\"model\": \"opus\""),
        "{back}"
    );
    s.vahta(&["setup", "--claude", "--uninstall"]);
    assert_eq!(
        serde_like::parse(&s.read(CLAUDE)),
        serde_like::parse(before)
    );
}

#[test]
fn refresh_does_nothing_when_nothing_is_set_up() {
    let s = Sandbox::new(true);
    s.found(".claude");
    let out = s.vahta(&["setup", "--refresh"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        text(&out.stdout).contains("nothing of ours is installed"),
        "{}",
        text(&out.stdout)
    );
    assert!(!s.exists(CLAUDE));
    // Not even when the hook binary is absent: there is nothing to repoint.
    let s = Sandbox::new(false);
    s.found(".claude");
    assert_eq!(s.vahta(&["setup", "--refresh"]).status.code(), Some(0));
}

#[test]
fn refresh_rejects_other_flags() {
    let s = Sandbox::new(true);
    s.found(".claude");
    for args in [
        &["setup", "--refresh", "--uninstall"][..],
        &["setup", "--refresh", "--all"],
        &["setup", "--refresh", "--claude"],
        &["setup", "--refresh", "--force"],
    ] {
        let out = s.vahta(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            text(&out.stderr).contains("--refresh goes with --dry-run only"),
            "{args:?}"
        );
    }
    assert!(!s.exists(CLAUDE));
}

#[test]
fn refresh_dry_run_writes_nothing() {
    let s = Sandbox::new(true);
    s.found(".claude");
    s.vahta(&["setup", "--claude"]);
    let cfg = s.home().join(CLAUDE);
    fs::write(
        &cfg,
        fs::read_to_string(&cfg)
            .unwrap()
            .replace("--setup 1", "--setup 0"),
    )
    .unwrap();
    let before = s.read(CLAUDE);
    let out = s.vahta(&["setup", "--refresh", "--dry-run"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("would change") && text(&out.stdout).contains("\n+++ "),
        "{}",
        text(&out.stdout)
    );
    assert_eq!(s.read(CLAUDE), before);
}

#[test]
fn the_stale_notice_suggests_refresh_when_several_harnesses_are_affected() {
    let s = Sandbox::new(true);
    s.found(".claude");
    s.found(".cursor");
    s.vahta(&["setup", "--all"]);
    for f in [CLAUDE, ".cursor/hooks.json"] {
        let cfg = s.home().join(f);
        fs::write(
            &cfg,
            fs::read_to_string(&cfg)
                .unwrap()
                .replace("--setup 1", "--setup 0"),
        )
        .unwrap();
    }
    let e = text(&s.vahta(&["scan", "--json", "."]).stderr);
    assert!(
        e.contains("Claude Code is outdated; run `vahta setup --refresh`"),
        "{e}"
    );
    assert!(
        e.contains("Cursor is outdated; run `vahta setup --refresh`"),
        "{e}"
    );
    // The hook gone: the same rule for the missing-hook notice.
    s.vahta(&["setup", "--refresh"]);
    fs::remove_file(s.hook()).unwrap();
    let e = text(&s.vahta(&["scan", "--json", "."]).stderr);
    assert!(
        e.contains("no longer exists; run `vahta setup --refresh`"),
        "{e}"
    );
}
