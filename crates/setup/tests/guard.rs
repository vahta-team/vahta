//! The watchdog's logic (`vahta_setup::guard`) against temporary homes: what
//! counts as tampering, pauses, putting things back, the autostart text and the
//! administrator-policy plans. Nothing here starts a process.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use vahta_harness::{Manifest, manifest};
use vahta_setup::guard::{self, Fix, Pause};
use vahta_setup::{Action, Env, Os, commit, plan};

static NEXT: AtomicU32 = AtomicU32::new(0);

struct Tree(PathBuf);

impl Tree {
    fn new() -> Tree {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("vahta-guard-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("home")).unwrap();
        fs::create_dir_all(dir.join("bin")).unwrap();
        fs::write(dir.join("bin/vahta-hook"), "#!/bin/sh\n").unwrap();
        Tree(dir)
    }
    fn env(&self, os: Os) -> Env {
        Env {
            home: self.0.join("home"),
            vars: BTreeMap::new(),
            path: Vec::new(),
            os,
            hook: self.0.join("bin/vahta-hook"),
        }
    }
    fn data(&self) -> PathBuf {
        self.0.join("data")
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn ms() -> Vec<Manifest> {
    vahta_harness::HARNESSES
        .iter()
        .map(|h| manifest(h).unwrap().unwrap())
        .collect()
}

fn install_all(t: &Tree) -> Vec<Manifest> {
    let env = t.env(Os::Linux);
    let ms = ms();
    for m in &ms {
        let p = plan(m, &env, Action::Install).unwrap();
        commit(&p).unwrap();
    }
    ms
}

fn names(t: &[guard::Tamper]) -> Vec<(String, Fix)> {
    t.iter().map(|t| (t.harness.clone(), t.fix)).collect()
}

#[test]
fn intact_hooks_are_not_tampering_and_are_remembered() {
    let t = Tree::new();
    let ms = install_all(&t);
    let mut expected = BTreeSet::new();
    let found = guard::check(&ms, &t.env(Os::Linux), &[], &mut expected, &[], 100);
    assert!(found.is_empty(), "{found:?}");
    assert_eq!(expected.len(), 3);
}

#[test]
fn removed_hooks_are_found_only_for_a_harness_that_had_them() {
    let t = Tree::new();
    let ms = install_all(&t);
    let env = t.env(Os::Linux);
    let mut expected = BTreeSet::new();
    guard::check(&ms, &env, &[], &mut expected, &[], 100);

    // Claude's removed by an agent; Cursor's file deleted; Codex untouched.
    let claude = vahta_setup::config_path(&ms[0], &env).unwrap();
    fs::write(&claude, "{\"model\":\"opus\"}").unwrap();
    let cursor = vahta_setup::config_path(&ms[2], &env).unwrap();
    fs::remove_file(&cursor).unwrap();
    let found = guard::check(&ms, &env, &[], &mut expected, &[], 100);
    assert_eq!(
        names(&found),
        vec![
            ("claude".to_string(), Fix::Reinstall),
            ("cursor".to_string(), Fix::Reinstall)
        ]
    );

    // A harness never set up is not asked about.
    let t2 = Tree::new();
    let mut none = BTreeSet::new();
    assert!(guard::check(&ms, &t2.env(Os::Linux), &[], &mut none, &[], 100).is_empty());
}

#[test]
fn some_entries_missing_counts_but_a_different_hook_path_does_not() {
    let t = Tree::new();
    let ms = install_all(&t);
    let env = t.env(Os::Linux);
    let mut expected = BTreeSet::new();
    let path = vahta_setup::config_path(&ms[0], &env).unwrap();
    let full = fs::read_to_string(&path).unwrap();

    // Another vahta-hook that exists, elsewhere: the person's own setup.
    let other = t.0.join("other/vahta-hook");
    fs::create_dir_all(other.parent().unwrap()).unwrap();
    fs::write(&other, "x").unwrap();
    fs::write(
        &path,
        full.replace(
            t.0.join("bin/vahta-hook").to_str().unwrap(),
            other.to_str().unwrap(),
        ),
    )
    .unwrap();
    assert!(guard::check(&ms, &env, &[], &mut expected, &[], 100).is_empty());

    // One event's entry removed.
    let mut doc: serde_json::Value = serde_json::from_str(&full).unwrap();
    doc["hooks"]
        .as_object_mut()
        .unwrap()
        .shift_remove("SessionStart");
    fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();
    let found = guard::check(&ms, &env, &[], &mut expected, &[], 100);
    assert_eq!(found.len(), 1);
    assert!(found[0].what.contains("removed"));
}

#[test]
fn disable_all_hooks_is_found_in_user_and_project_settings_and_cleared() {
    let t = Tree::new();
    let ms = install_all(&t);
    let env = t.env(Os::Linux);
    let mut expected = BTreeSet::new();
    guard::check(&ms, &env, &[], &mut expected, &[], 100);

    let project = t.0.join("proj");
    fs::create_dir_all(project.join(".claude")).unwrap();
    fs::write(
        project.join(".claude/settings.local.json"),
        "{\"disableAllHooks\": true, \"x\": 1}",
    )
    .unwrap();
    let user = vahta_setup::config_path(&ms[0], &env).unwrap();
    let text = fs::read_to_string(&user)
        .unwrap()
        .replacen('{', "{\"disableAllHooks\":true,", 1);
    fs::write(&user, text).unwrap();

    let found = guard::check(
        &ms,
        &env,
        std::slice::from_ref(&project),
        &mut expected,
        &[],
        100,
    );
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found.iter().all(|f| f.fix == Fix::ClearDisableAll));
    for f in &found {
        guard::restore(&ms, &env, f).unwrap();
    }
    assert!(
        !fs::read_to_string(&user)
            .unwrap()
            .contains("disableAllHooks")
    );
    let local = fs::read_to_string(project.join(".claude/settings.local.json")).unwrap();
    assert!(
        !local.contains("disableAllHooks") && local.contains("\"x\""),
        "{local}"
    );
    assert!(guard::check(&ms, &env, &[project], &mut expected, &[], 100).is_empty());
}

#[test]
fn codex_hooks_switched_off_in_config_toml_are_switched_back_on() {
    let t = Tree::new();
    let ms = install_all(&t);
    let env = t.env(Os::Linux);
    let toml = t.0.join("home/.codex/config.toml");
    fs::write(
        &toml,
        "model = \"x\"\n[features]\nhooks = false # off\nother = true\n",
    )
    .unwrap();
    let mut expected = BTreeSet::new();
    let found = guard::check(&ms, &env, &[], &mut expected, &[], 100);
    assert_eq!(
        names(&found),
        vec![("codex".to_string(), Fix::CodexHooksOn)]
    );
    guard::restore(&ms, &env, &found[0]).unwrap();
    assert_eq!(
        fs::read_to_string(&toml).unwrap(),
        "model = \"x\"\n[features]\nhooks = true\nother = true\n"
    );
    assert!(guard::toml_disables_hooks("[features]\nhooks=false\n"));
    assert!(!guard::toml_disables_hooks(
        "hooks = false\n[features]\nhooks = true\n"
    ));
}

#[test]
fn a_paused_harness_is_not_watched_and_restore_puts_the_entries_back() {
    let t = Tree::new();
    let ms = install_all(&t);
    let env = t.env(Os::Linux);
    let mut expected = BTreeSet::new();
    guard::check(&ms, &env, &[], &mut expected, &[], 100);
    assert!(guard::remove_entries(&ms[0], &env).unwrap());
    assert!(
        !guard::remove_entries(&ms[0], &env).unwrap(),
        "nothing left to take"
    );

    let pause = Pause {
        harness: "claude".into(),
        until: 200,
        reason: "r".into(),
    };
    assert!(
        guard::check(
            &ms,
            &env,
            &[],
            &mut expected,
            std::slice::from_ref(&pause),
            100
        )
        .is_empty()
    );
    // The time is up: it is tampering again, and restoring repairs it.
    let found = guard::check(&ms, &env, &[], &mut expected, &[pause], 200);
    assert_eq!(found.len(), 1);
    guard::restore(&ms, &env, &found[0]).unwrap();
    assert!(guard::has_entries(&ms[0], &env));
    assert!(!guard::add_entries(&ms[0], &env).unwrap(), "already there");
}

#[test]
fn pauses_and_projects_round_trip_through_the_data_directory() {
    let t = Tree::new();
    assert!(guard::read_pauses(&t.data()).is_empty());
    let p = Pause {
        harness: "claude".into(),
        until: 5,
        reason: "why".into(),
    };
    guard::write_pauses(&t.data(), std::slice::from_ref(&p)).unwrap();
    assert_eq!(guard::read_pauses(&t.data()), vec![p.clone()]);
    assert!(guard::paused(std::slice::from_ref(&p), "claude", 4));
    assert!(!guard::paused(&[p], "claude", 5));
    guard::write_pauses(&t.data(), &[]).unwrap();
    assert!(!guard::pause_file(&t.data()).exists());
    fs::write(guard::pause_file(&t.data()), "not json").unwrap();
    assert!(guard::read_pauses(&t.data()).is_empty());

    guard::note_project(&t.data(), &t.0.join("a"));
    guard::note_project(&t.data(), &t.0.join("a"));
    guard::note_project(&t.data(), &t.0.join("b"));
    assert_eq!(guard::read_projects(&t.data()).len(), 2);
}

struct Recorder(std::cell::RefCell<Vec<String>>, bool);

impl guard::Runner for Recorder {
    fn run(&self, argv: &[String]) -> bool {
        self.0.borrow_mut().push(argv.join(" "));
        self.1
    }
}

#[test]
fn autostart_is_text_per_os_and_the_commands_go_through_the_runner() {
    let t = Tree::new();
    let exe = PathBuf::from("/opt/vahta/bin/vahta");
    let linux = guard::autostart(&t.env(Os::Linux), &exe);
    let (path, unit) = linux.file.clone().unwrap();
    assert!(path.ends_with(".config/systemd/user/vahta-guard.service"));
    assert!(
        unit.contains("ExecStart=/opt/vahta/bin/vahta _guard"),
        "{unit}"
    );

    let mac = guard::autostart(&t.env(Os::Macos), &exe);
    let (path, plist) = mac.file.clone().unwrap();
    assert!(path.ends_with("Library/LaunchAgents/dev.vahta.guard.plist"));
    assert!(
        plist.contains("<string>_guard</string>") && plist.contains("RunAtLoad"),
        "{plist}"
    );

    let win = guard::autostart(&t.env(Os::Windows), &exe);
    assert!(win.file.is_none());
    assert!(
        win.enable[0]
            .join(" ")
            .contains(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")
    );

    // Nothing is written or run until asked; then the file and the commands.
    let run = Recorder(Default::default(), true);
    assert!(!path.exists());
    guard::enable_autostart(&linux, &run).unwrap();
    assert!(linux.file.as_ref().unwrap().0.is_file());
    assert_eq!(
        run.0.borrow().as_slice(),
        [
            "systemctl --user daemon-reload",
            "systemctl --user enable --now vahta-guard.service"
        ]
    );
    guard::disable_autostart(&linux, &run);
    assert!(!linux.file.as_ref().unwrap().0.exists());
    assert!(run.0.borrow().iter().any(|c| c.contains("disable --now")));
    // A failing command is an error naming it.
    let failing = Recorder(Default::default(), false);
    assert!(
        guard::enable_autostart(&linux, &failing)
            .unwrap_err()
            .contains("daemon-reload")
    );
}

#[test]
fn managed_plans_per_harness() {
    let t = Tree::new();
    let env = t.env(Os::Linux);
    let root = t.0.join("root");
    let ms = ms();

    let claude = guard::managed_plan(&ms[0], &env, Some(&root))
        .unwrap()
        .unwrap();
    assert_eq!(
        claude.path,
        root.join("etc/claude-code/managed-settings.json")
    );
    assert!(
        claude
            .text
            .contains("vahta-hook --harness claude --event before_tool")
    );
    assert!(!claude.current);
    guard::write_managed(&claude).unwrap();
    assert!(
        guard::managed_plan(&ms[0], &env, Some(&root))
            .unwrap()
            .unwrap()
            .current
    );

    // An existing managed file keeps what is in it.
    fs::write(&claude.path, "{\"permissions\":{\"allow\":[\"Bash(ls)\"]}}").unwrap();
    let merged = guard::managed_plan(&ms[0], &env, Some(&root))
        .unwrap()
        .unwrap();
    assert!(merged.text.contains("Bash(ls)") && merged.text.contains("vahta-hook"));

    // Codex: a whole file when absent, a block to add when it exists.
    let codex = guard::managed_plan(&ms[1], &env, Some(&root))
        .unwrap()
        .unwrap();
    assert!(!codex.append && codex.text.contains("hooks = true"));
    fs::create_dir_all(codex.path.parent().unwrap()).unwrap();
    fs::write(
        &codex.path,
        "allowed_approval_policies = [\"on-request\"]\n",
    )
    .unwrap();
    let appended = guard::managed_plan(&ms[1], &env, Some(&root))
        .unwrap()
        .unwrap();
    assert!(appended.append);
    guard::write_managed(&appended).unwrap();
    let file = fs::read_to_string(&codex.path).unwrap();
    assert!(
        file.starts_with("allowed_approval_policies")
            && file.contains("[[hooks.PreToolUse.hooks]]"),
        "{file}"
    );
    assert!(
        guard::managed_plan(&ms[1], &env, Some(&root))
            .unwrap()
            .unwrap()
            .current
    );

    // The command a person runs themselves.
    let cmd = guard::sudo_command(&claude);
    assert!(
        cmd.starts_with("sudo mkdir -p ")
            && cmd.contains("sudo tee ")
            && cmd.ends_with("VAHTA_EOF")
    );

    // Windows paths expand $ProgramData; unset means no path.
    let win = t.env(Os::Windows);
    assert!(
        guard::managed_plan(&ms[1], &win, Some(&root))
            .unwrap()
            .is_none()
    );
}
