//! The setup logic against temporary homes and the fixtures under
//! `crates/harness/harnesses/<h>/fixtures/setup/`: `<case>.before.json` is a
//! config, `<case>.after.json` what an install must turn it into.
//! `VAHTA_UPDATE_SNAPSHOTS=1` rewrites the `.after.json` files; review the diff.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;
use vahta_harness::{manifest, Manifest, HARNESSES};
use vahta_setup::{
    commit, detect, inspect, install_text, is_ours, plan, quote_word, uninstall_text, Action, Env,
    HookProblem, Os, Refusal, State,
};

const HOOK: &str = "/opt/vahta/bin/vahta-hook";

static NEXT: AtomicU32 = AtomicU32::new(0);

struct Tree(PathBuf);

impl Tree {
    fn new() -> Tree {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("vahta-setup-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        Tree(dir)
    }
    fn write(&self, rel: &str, body: &str) -> PathBuf {
        let p = self.0.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, body).unwrap();
        p
    }
    fn env(&self) -> Env {
        Env {
            home: self.0.join("home"),
            vars: BTreeMap::new(),
            path: vec![self.0.join("bin")],
            os: Os::Linux,
            hook: PathBuf::from(HOOK),
        }
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn m(h: &str) -> Manifest {
    manifest(h).unwrap().unwrap()
}

fn fixture(h: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../harness/harnesses")
        .join(h)
        .join("fixtures/setup")
        .join(name)
}

fn read_fixture(h: &str, name: &str) -> String {
    fs::read_to_string(fixture(h, name)).unwrap_or_else(|e| panic!("{h}/{name}: {e}"))
}

fn install(h: &str, before: Option<&str>) -> Result<String, Refusal> {
    install_text(before, &m(h), Os::Linux, HOOK)
}

fn json(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}

/// The harness's config file under a temp home.
fn config_in(t: &Tree, h: &str) -> PathBuf {
    vahta_setup::config_path(&m(h), &t.env()).unwrap()
}

/// The command strings of the entries at `hooks.<event>`, in order.
fn commands(doc: &str, event: &str) -> Vec<String> {
    let mut out = Vec::new();
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(o) => {
                if let Some(Value::String(c)) = o.get("command") {
                    out.push(c.clone());
                }
                o.values().for_each(|v| walk(v, out));
            }
            Value::Array(a) => a.iter().for_each(|v| walk(v, out)),
            _ => {}
        }
    }
    walk(&json(doc)["hooks"][event], &mut out);
    out
}

const CASES: [&str; 2] = ["foreign", "outdated"];

#[test]
fn install_matches_the_expected_fixtures() {
    let update = std::env::var_os("VAHTA_UPDATE_SNAPSHOTS").is_some();
    let mut cases: Vec<(&str, &str)> = Vec::new();
    for h in HARNESSES {
        for c in CASES {
            cases.push((h, c));
        }
    }
    cases.extend([("claude", "mixed"), ("codex", "mixed")]);
    for (h, case) in cases {
        let got = install(h, Some(&read_fixture(h, &format!("{case}.before.json")))).unwrap();
        let after = fixture(h, &format!("{case}.after.json"));
        if update {
            fs::write(&after, &got).unwrap();
        }
        assert_eq!(got, read_fixture(h, &format!("{case}.after.json")), "{h}/{case}");
    }
}

#[test]
fn install_into_a_missing_file_or_an_empty_object() {
    for h in HARNESSES {
        let from_missing = install(h, None).unwrap();
        let from_empty = install(h, Some("{}")).unwrap();
        assert_eq!(from_missing, from_empty, "{h}");
        let v = json(&from_missing);
        assert!(v["hooks"].is_object(), "{h}");
        assert_eq!(v["version"] == 1, h == "cursor", "{h}");
        assert!(from_missing.ends_with("}\n"));
        let n = m(h).events.len();
        let ours = from_missing.matches("vahta-hook --harness").count();
        assert_eq!(ours, n, "{h}: one entry per event");
    }
}

#[test]
fn two_installs_are_byte_identical() {
    for h in HARNESSES {
        for case in CASES {
            let once = install(h, Some(&read_fixture(h, &format!("{case}.before.json")))).unwrap();
            let twice = install(h, Some(&once)).unwrap();
            assert_eq!(once, twice, "{h}/{case}");
        }
    }
}

#[test]
fn foreign_entries_keep_their_order_and_ours_come_last() {
    let out = install("claude", Some(&read_fixture("claude", "foreign.before.json"))).unwrap();
    assert_eq!(
        commands(&out, "PreToolUse"),
        [
            "/home/u/.local/bin/key-amnesia-hook",
            "/usr/local/bin/audit-log --pre",
            "/opt/vahta/bin/vahta-hook --harness claude --event before_tool --setup 1",
            "/opt/vahta/bin/vahta-hook --harness claude --event before_read --setup 1",
        ]
    );
    // Top-level keys keep their order, new ones go after.
    let keys: Vec<_> = json(&out).as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, ["model", "permissions", "hooks", "env"]);
    let events: Vec<_> = json(&out)["hooks"].as_object().unwrap().keys().cloned().collect();
    assert_eq!(&events[..3], ["PreToolUse", "PostToolUse", "Notification"]);

    let out = install("cursor", Some(&read_fixture("cursor", "foreign.before.json"))).unwrap();
    assert_eq!(
        commands(&out, "preToolUse"),
        [
            "/home/u/.local/bin/key-amnesia-hook",
            "./hooks/validate-tool.sh",
            "/opt/vahta/bin/vahta-hook --harness cursor --event before_tool --setup 1",
        ]
    );
}

#[test]
fn reinstalling_over_an_outdated_entry_replaces_it() {
    for h in HARNESSES {
        let out = install(h, Some(&read_fixture(h, "outdated.before.json"))).unwrap();
        assert!(!out.contains("/old/place"), "{h}");
        assert!(!out.contains("--setup 0"), "{h}");
        let n = m(h).events.len();
        assert_eq!(out.matches("vahta-hook --harness").count(), n, "{h}: no duplicates");
    }
}

#[test]
fn a_mixed_group_loses_only_our_command() {
    for h in ["claude", "codex"] {
        let before = read_fixture(h, "mixed.before.json");
        let out = install(h, Some(&before)).unwrap();
        let cmds = commands(&out, "PreToolUse");
        assert_eq!(cmds[0], "/usr/local/bin/audit-log --pre");
        assert_eq!(cmds[1], "/home/u/.local/bin/key-amnesia-hook");
        // The mixed group is still one group with the two foreign commands.
        let group = &json(&out)["hooks"]["PreToolUse"][0]["hooks"];
        assert_eq!(group.as_array().unwrap().len(), 2, "{h}");
        let gone = uninstall_text(&out, &m(h), Os::Linux).unwrap().unwrap();
        assert_eq!(json(&gone)["hooks"]["PreToolUse"].as_array().unwrap().len(), 1, "{h}");
    }
}

#[test]
fn uninstall_restores_the_foreign_content() {
    for h in HARNESSES {
        let before = read_fixture(h, "foreign.before.json");
        let installed = install(h, Some(&before)).unwrap();
        let back = uninstall_text(&installed, &m(h), Os::Linux).unwrap().unwrap();
        assert_eq!(json(&back), json(&before), "{h}");
        assert!(!back.contains("vahta-hook"), "{h}");
    }
    // Into an empty file and back: the `hooks` object we made goes too.
    let back = uninstall_text(&install("claude", None).unwrap(), &m("claude"), Os::Linux)
        .unwrap()
        .unwrap();
    assert_eq!(json(&back), json("{}"));
    // Containers that were already empty stay.
    let before = r#"{"hooks": {"Stop": []}}"#;
    let back = uninstall_text(&install("claude", Some(before)).unwrap(), &m("claude"), Os::Linux)
        .unwrap()
        .unwrap();
    assert_eq!(json(&back), json(before));
}

#[test]
fn uninstall_with_nothing_of_ours_does_nothing() {
    for h in HARNESSES {
        let before = read_fixture(h, "foreign.before.json");
        assert_eq!(uninstall_text(&before, &m(h), Os::Linux).unwrap(), None, "{h}");
    }
    let t = Tree::new();
    let path = t.write("home/.claude/settings.json", &read_fixture("claude", "foreign.before.json"));
    let p = plan(&m("claude"), &t.env(), Action::Uninstall).unwrap();
    assert!(p.after.is_none());
    assert!(commit(&p).unwrap().is_none());
    assert!(!path.with_file_name("settings.json.vahta-backup").exists());
    // And with no file at all.
    let t = Tree::new();
    assert!(plan(&m("codex"), &t.env(), Action::Uninstall).unwrap().after.is_none());
}

#[test]
fn a_file_that_is_not_a_json_object_is_refused_and_left_alone() {
    for bad in ["{ not json", "", "[1, 2]", "\"text\"", "{} // comment"] {
        let t = Tree::new();
        let path = t.write("home/.claude/settings.json", bad);
        let err = plan(&m("claude"), &t.env(), Action::Install).unwrap_err();
        assert!(matches!(err, Refusal::InvalidJson(_) | Refusal::NotAnObject), "{bad:?}");
        assert_eq!(fs::read_to_string(&path).unwrap(), bad);
        assert!(!path.with_file_name("settings.json.vahta-backup").exists());
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1, "no temp file left");
    }
    // Shapes we cannot merge into are refused too.
    assert!(matches!(install("claude", Some(r#"{"hooks": []}"#)), Err(Refusal::Shape(_))));
    assert!(matches!(
        install("claude", Some(r#"{"hooks": {"PreToolUse": {}}}"#)),
        Err(Refusal::Shape(_))
    ));
    assert!(matches!(install("cursor", Some(r#"{"version": 2}"#)), Err(Refusal::Version { .. })));
}

#[test]
fn commit_backs_up_once_and_keeps_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let t = Tree::new();
    let before = read_fixture("claude", "foreign.before.json");
    let path = t.write("home/.claude/settings.json", &before);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let p = plan(&m("claude"), &t.env(), Action::Install).unwrap();
    let backup = commit(&p).unwrap().expect("backup made");
    assert_eq!(backup.file_name().unwrap(), "settings.json.vahta-backup");
    assert_eq!(fs::read_to_string(&backup).unwrap(), before);
    assert_eq!(fs::read_to_string(&path).unwrap(), p.after.clone().unwrap());
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 2, "no temp file left");

    // A second install has nothing to change, so nothing is written or backed up again.
    let again = plan(&m("claude"), &t.env(), Action::Install).unwrap();
    assert!(again.after.is_none());

    // Later writes keep the first backup: it is the file from before vahta.
    let u = plan(&m("claude"), &t.env(), Action::Uninstall).unwrap();
    assert!(commit(&u).unwrap().is_none(), "no second backup");
    assert_eq!(fs::read_to_string(&backup).unwrap(), before);
    assert_eq!(json(&fs::read_to_string(&path).unwrap()), json(&before));
}

#[test]
fn a_new_file_gets_no_backup_and_its_directory_is_created() {
    let t = Tree::new();
    let p = plan(&m("cursor"), &t.env(), Action::Install).unwrap();
    assert!(p.before.is_none());
    assert!(commit(&p).unwrap().is_none());
    let path = config_in(&t, "cursor");
    assert!(fs::read_to_string(&path).unwrap().contains("\"version\": 1"));
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
}

#[test]
fn a_symlinked_config_is_written_through() {
    use std::os::unix::fs::symlink;
    let t = Tree::new();
    let real = t.write("dotfiles/settings.json", "{}");
    fs::create_dir_all(t.0.join("home/.claude")).unwrap();
    let link = t.0.join("home/.claude/settings.json");
    symlink(&real, &link).unwrap();
    commit(&plan(&m("claude"), &t.env(), Action::Install).unwrap()).unwrap();
    assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
    assert!(fs::read_to_string(&real).unwrap().contains("vahta-hook"));
}

#[test]
fn detection_by_directory_binary_and_variable() {
    let t = Tree::new();
    let env = t.env();
    for h in HARNESSES {
        assert!(!detect(&m(h), &env).found, "{h}");
    }
    let d = detect(&m("claude"), &env);
    assert!(d.why.contains("no directory") && d.why.contains("no `claude` on PATH"), "{}", d.why);

    fs::create_dir_all(env.home.join(".claude")).unwrap();
    let d = detect(&m("claude"), &env);
    assert!(d.found && d.why.contains(".claude"));

    t.write("bin/cursor-agent", "");
    let d = detect(&m("cursor"), &env);
    assert!(d.found && d.why.contains("cursor-agent"));

    // $CODEX_HOME is a candidate, and decides where the config goes.
    let mut env = t.env();
    env.vars.insert("CODEX_HOME".into(), t.0.join("codex-home").to_string_lossy().into_owned());
    assert!(!detect(&m("codex"), &env).found);
    fs::create_dir_all(t.0.join("codex-home")).unwrap();
    assert!(detect(&m("codex"), &env).found);
    assert_eq!(
        vahta_setup::config_path(&m("codex"), &env).unwrap(),
        t.0.join("codex-home/hooks.json")
    );
    // Unset or empty falls back to ~/.codex.
    env.vars.insert("CODEX_HOME".into(), String::new());
    assert_eq!(
        vahta_setup::config_path(&m("codex"), &env).unwrap(),
        env.home.join(".codex/hooks.json")
    );
}

#[test]
fn status_none_current_outdated_and_hook_paths() {
    let t = Tree::new();
    let mut env = t.env();
    let hook = t.write("bin/vahta-hook", "");
    env.hook = hook.clone();
    let mf = m("claude");
    assert_eq!(inspect(&mf, &env).state, State::None);

    t.write("home/.claude/settings.json", &read_fixture("claude", "foreign.before.json"));
    assert_eq!(inspect(&mf, &env).state, State::None, "foreign entries are not ours");

    commit(&plan(&mf, &env, Action::Install).unwrap()).unwrap();
    let s = inspect(&mf, &env);
    assert_eq!(s.state, State::Current);
    assert!(s.problems.is_empty());

    // Content equality, not a number: a changed matcher is outdated at the same version.
    let path = config_in(&t, "claude");
    let text = fs::read_to_string(&path).unwrap();
    fs::write(&path, text.replace("Read|Grep", "Read")).unwrap();
    assert_eq!(inspect(&mf, &env).state, State::Outdated);
    // So is an old --setup number, and a missing entry.
    fs::write(&path, text.replace("--setup 1", "--setup 0")).unwrap();
    assert_eq!(inspect(&mf, &env).state, State::Outdated);
    let fewer = text.replacen("vahta-hook --harness claude --event prompt", "key-amnesia-hook --x", 1);
    fs::write(&path, fewer).unwrap();
    assert_eq!(inspect(&mf, &env).state, State::Outdated);

    // Installed path missing, or not the one next to this binary.
    fs::write(&path, &text).unwrap();
    fs::remove_file(&hook).unwrap();
    assert!(inspect(&mf, &env).problems.contains(&HookProblem::Missing(hook.to_string_lossy().into())));
    let other = t.write("elsewhere/vahta-hook", "");
    env.hook = other.clone();
    let s = inspect(&mf, &env);
    assert_eq!(s.state, State::Current, "the path is a problem, not staleness");
    // A path with spaces, quoted, is still the same setup.
    let spaced = t.write("with space/vahta-hook", "");
    env.hook = spaced;
    commit(&plan(&mf, &env, Action::Install).unwrap()).unwrap();
    assert_eq!(inspect(&mf, &env).state, State::Current);
    env.hook = other.clone();
    assert_eq!(inspect(&mf, &env).state, State::Current);
    fs::write(&path, &text).unwrap();
    assert!(s.problems.contains(&HookProblem::Elsewhere(hook.to_string_lossy().into())));

    // A broken file is reported, not guessed at.
    fs::write(&path, "{ nope").unwrap();
    assert!(matches!(inspect(&mf, &env).state, State::Unreadable(_)));
}

#[test]
fn which_commands_are_ours() {
    for c in [
        "/usr/bin/vahta-hook --harness claude",
        "vahta-hook",
        "'/home/a b/vahta-hook' --harness x",
        "\"C:\\Program Files\\Vahta\\vahta-hook.exe\" --harness x",
        "/x/vahta-hook.EXE",
        "  /x/vahta-hook",
    ] {
        assert!(is_ours(c, Os::Linux) || is_ours(c, Os::Windows), "{c}");
    }
    for c in [
        "/x/key-amnesia-hook",
        "/x/not-vahta-hook",
        "/x/vahta-hook-extra",
        "audit-log /x/vahta-hook",
        "echo vahta-hook",
        "",
    ] {
        assert!(!is_ours(c, Os::Linux), "{c}");
    }
    assert!(is_ours("\"C:\\Program Files\\Vahta\\vahta-hook.exe\" --a", Os::Windows));
    assert!(is_ours("C:\\Vahta\\vahta-hook.exe --a", Os::Windows));
}

#[test]
fn the_hook_path_is_quoted_when_it_needs_it() {
    assert_eq!(quote_word("/opt/v/vahta-hook", Os::Linux), "/opt/v/vahta-hook");
    assert_eq!(quote_word("/opt/my dir/vahta-hook", Os::Linux), "'/opt/my dir/vahta-hook'");
    assert_eq!(quote_word("/o'k/vahta-hook", Os::Linux), "'/o'\\''k/vahta-hook'");
    assert_eq!(quote_word("C:\\Vahta\\vahta-hook.exe", Os::Windows), "C:\\Vahta\\vahta-hook.exe");
    assert_eq!(
        quote_word("C:\\Program Files\\v\\vahta-hook.exe", Os::Windows),
        "\"C:\\Program Files\\v\\vahta-hook.exe\""
    );
    // And what we quote, we recognise and a status check can find again.
    let cmd = format!("{} --harness claude", quote_word("/opt/my dir/vahta-hook", Os::Linux));
    assert!(is_ours(&cmd, Os::Linux));
    let t = Tree::new();
    let mut env = t.env();
    env.hook = t.0.join("my dir/vahta-hook");
    fs::create_dir_all(env.hook.parent().unwrap()).unwrap();
    fs::write(&env.hook, "").unwrap();
    commit(&plan(&m("claude"), &env, Action::Install).unwrap()).unwrap();
    let s = inspect(&m("claude"), &env);
    assert_eq!(s.state, State::Current);
    assert!(s.problems.is_empty());
}

#[test]
fn the_diff_shows_a_change_and_nothing_for_none() {
    let d = vahta_setup::unified_diff(Path::new("/h/.claude/settings.json"), Some("{}\n"), "{\n  \"a\": 1\n}\n");
    assert!(d.contains("--- /h/.claude/settings.json") && d.contains("+  \"a\": 1"), "{d}");
    let d = vahta_setup::unified_diff(Path::new("/h/x.json"), None, "{}\n");
    assert!(d.contains("--- /dev/null") && d.contains("+{}"), "{d}");
}
