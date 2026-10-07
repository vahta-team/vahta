//! Drives the real `vahta` binary for `vahta list` and `vahta check`.
//!
//! Every run happens in a temp directory with `HOME`, `XDG_DATA_HOME` and
//! `VAHTA_DATA_DIR` all pointed inside it, so nothing reads or writes the real
//! home or the real local store. The vaults are made with the cheap test KDF
//! (a dev-dependency feature of this test crate only). Values are made up.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

use vahta_vault::project::Project;
use vahta_vault::store::LocalStore;
use vahta_vault::{KdfParams, Kind, Tier, Vault};

static NEXT: AtomicU32 = AtomicU32::new(0);
const PW: &[u8] = b"correct horse";

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Sandbox {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("vahta-cli-vault-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("project")).unwrap();
        fs::create_dir_all(root.join("home")).unwrap();
        Sandbox { root }
    }

    fn project(&self) -> PathBuf {
        self.root.join("project")
    }

    fn data(&self) -> PathBuf {
        self.root.join("data")
    }

    fn store(&self) -> LocalStore {
        LocalStore::new(self.data())
    }

    fn vault_path(&self) -> PathBuf {
        self.project().join(".vahta/vault.vht")
    }

    /// A project with a vault holding `items`, saved through this sandbox's store.
    fn with_vault(&self, items: &[(&str, &[u8], Kind, Tier)]) {
        Project::init(&self.project()).unwrap();
        let (mut v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
        for (n, val, k, t) in items {
            v.set(n, val, k.clone(), *t).unwrap();
        }
        v.save(&self.vault_path(), &self.store()).unwrap();
    }

    fn manifest(&self, text: &str) {
        fs::write(self.project().join("vahta.toml"), text).unwrap();
    }

    fn vahta(&self, cwd: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vahta"))
            .current_dir(cwd)
            .args(args)
            .env("HOME", self.root.join("home"))
            .env("XDG_DATA_HOME", self.data())
            .env("VAHTA_DATA_DIR", self.data())
            .output()
            .expect("run vahta")
    }

    fn run(&self, args: &[&str]) -> Output {
        self.vahta(&self.project(), args)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn items() -> Vec<(&'static str, &'static [u8], Kind, Tier)> {
    vec![
        ("ZETA", b"fake-one", Kind::Env, Tier::Session),
        (
            "ALPHA",
            b"fake-two",
            Kind::File {
                file_name: "alpha.pem".into(),
            },
            Tier::EachUse,
        ),
    ]
}

#[test]
fn list_without_a_project_says_so() {
    let s = Sandbox::new();
    let out = s.vahta(&s.root.join("home"), &["list"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("no Vahta project here (no .vahta/ in this directory or above)")
    );
}

#[test]
fn list_prints_sorted_names_kinds_and_tiers_and_never_a_value() {
    let s = Sandbox::new();
    s.with_vault(&items());
    let out = s.run(&["list"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = text(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(
        lines[0].starts_with("ALPHA")
            && lines[0].contains("file:alpha.pem")
            && lines[0].ends_with("each_use")
    );
    assert!(
        lines[1].starts_with("ZETA") && lines[1].contains("env") && lines[1].ends_with("session")
    );
    assert!(!stdout.contains("fake-") && !text(&out.stderr).contains("fake-"));
    // The saving machine pinned the vault: no "unverified" note.
    assert!(!text(&out.stderr).contains("unverified"));
}

#[test]
fn list_from_a_subdirectory_finds_the_project() {
    let s = Sandbox::new();
    s.with_vault(&items());
    let deep = s.project().join("src/deep");
    fs::create_dir_all(&deep).unwrap();
    let out = s.vahta(&deep, &["list"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stdout).contains("ZETA"));
}

#[test]
fn list_json_has_the_documented_shape() {
    let s = Sandbox::new();
    s.with_vault(&items());
    let out = s.run(&["list", "--json"]);
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["format"], 1);
    assert_eq!(v["verified"], true);
    assert_eq!(v["upgrade_pending"], false);
    assert_eq!(v["secrets"][0]["name"], "ALPHA");
    assert_eq!(v["secrets"][0]["kind"], "file");
    assert_eq!(v["secrets"][0]["file_name"], "alpha.pem");
    assert_eq!(v["secrets"][0]["tier"], "each_use");
    assert_eq!(v["secrets"][1]["kind"], "env");
    assert!(!text(&out.stdout).contains("fake-"));
}

#[test]
fn a_vault_this_machine_has_not_unlocked_is_reported_unverified() {
    let s = Sandbox::new();
    s.with_vault(&items());
    // A fresh store: as on a machine that just cloned the project.
    fs::remove_dir_all(s.data()).unwrap();
    let out = s.run(&["list"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        text(&out.stderr)
            .contains("unverified: this vault has not been unlocked on this machine yet")
    );
    let json = s.run(&["list", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(v["verified"], false);
}

#[test]
fn a_rolled_back_vault_is_a_hard_error() {
    let s = Sandbox::new();
    s.with_vault(&items());
    let old = fs::read(s.vault_path()).unwrap(); // generation 1
    let mut v = Vault::unlock_password(&s.vault_path(), PW, &s.store()).unwrap();
    v.set("NEW", b"fake-three", Kind::Env, Tier::Session)
        .unwrap();
    v.save(&s.vault_path(), &s.store()).unwrap(); // generation 2
    fs::write(s.vault_path(), old).unwrap();
    let out = s.run(&["list"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("rolled back"));
    assert!(text(&out.stdout).is_empty());
}

#[test]
fn a_tampered_vault_is_a_hard_error() {
    let s = Sandbox::new();
    s.with_vault(&items());
    let mut bytes = fs::read(s.vault_path()).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 1;
    fs::write(s.vault_path(), bytes).unwrap();
    let out = s.run(&["list"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stdout).is_empty());
    assert!(!text(&out.stderr).is_empty());
}

#[test]
fn a_swapped_owner_is_a_hard_error() {
    let s = Sandbox::new();
    s.with_vault(&items());
    // This machine remembers a different owner key for this vault id, as it
    // would after the file was replaced by one signed by someone else.
    let id = Vault::peek(&s.vault_path()).unwrap().vault_id;
    fs::remove_dir_all(s.data()).unwrap();
    s.store()
        .record(
            &id,
            &vahta_vault::store::StateKey::owner(&[1; 32]),
            &[9; 32],
            1,
        )
        .unwrap();
    let out = s.run(&["list"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stdout).is_empty());
    assert!(text(&out.stderr).contains("owner key differs"));
    s.manifest("[secrets.ZETA]\n");
    let out = s.run(&["check"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("owner key differs"));
}

#[test]
fn list_with_a_project_but_no_vault_yet() {
    let s = Sandbox::new();
    Project::init(&s.project()).unwrap();
    let out = s.run(&["list"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no vault yet"));
}

#[test]
fn check_without_a_vault_validates_the_contract_only() {
    let s = Sandbox::new();
    s.manifest("[secrets.API_TOKEN]\ndescription = \"x\"\n[secrets.OPTIONAL]\nrequired = false\n");
    let out = s.run(&["check"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("checked vahta.toml only")
            && stdout.contains("Required: 1")
            && stdout.contains("OK")
    );

    let json: serde_json::Value =
        serde_json::from_slice(&s.run(&["check", "--json"]).stdout).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["vault"], serde_json::Value::Null);
    assert_eq!(json["required"][0], "API_TOKEN");
    assert_eq!(json["missing"].as_array().unwrap().len(), 0);
}

#[test]
fn check_fails_on_a_malformed_manifest_without_a_vault() {
    let s = Sandbox::new();
    s.manifest("[secrets.API_TOKEN]\nrequried = false\n");
    let out = s.run(&["check"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("unknown key `requried`"));
    let json: serde_json::Value =
        serde_json::from_slice(&s.run(&["check", "--json"]).stdout).unwrap();
    assert_eq!(json["ok"], false);
    assert!(json["error"].as_str().unwrap().contains("requried"));
}

#[test]
fn check_reports_missing_required_names_and_exits_one() {
    let s = Sandbox::new();
    s.with_vault(&items());
    s.manifest(
        "[secrets.ZETA]\n[secrets.MISSING_ONE]\n[secrets.MISSING_TWO]\n[secrets.NICE_TO_HAVE]\nrequired = false\n",
    );
    let out = s.run(&["check"]);
    assert_eq!(out.status.code(), Some(1));
    let report = text(&out.stderr);
    assert!(report.contains("Required: 3") && report.contains("Present:  1"));
    assert!(report.contains("Missing:  MISSING_ONE, MISSING_TWO") && report.contains("FAIL"));
    assert!(report.contains("Optional absent (informational): NICE_TO_HAVE"));

    let json: serde_json::Value =
        serde_json::from_slice(&s.run(&["check", "--json"]).stdout).unwrap();
    assert_eq!(json["ok"], false);
    assert_eq!(json["present"][0], "ZETA");
    assert_eq!(json["missing"][1], "MISSING_TWO");
    assert_eq!(json["optional_absent"][0], "NICE_TO_HAVE");
    assert!(json["vault"].as_str().unwrap().ends_with("vault.vht"));
    assert!(!report.contains("fake-"));
}

#[test]
fn check_passes_when_every_required_name_is_present() {
    let s = Sandbox::new();
    s.with_vault(&items());
    s.manifest("[secrets.ZETA]\n[secrets.ALPHA]\n[secrets.GONE]\nrequired = false\n");
    let out = s.run(&["check"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("Missing:  (none)") && stdout.contains("OK"));
    assert!(stdout.contains("Optional absent (informational): GONE"));
}

#[test]
fn check_refuses_a_rolled_back_vault_too() {
    let s = Sandbox::new();
    s.with_vault(&items());
    s.manifest("[secrets.ZETA]\n");
    let old = fs::read(s.vault_path()).unwrap();
    let mut v = Vault::unlock_password(&s.vault_path(), PW, &s.store()).unwrap();
    v.set("NEW", b"fake-three", Kind::Env, Tier::Session)
        .unwrap();
    v.save(&s.vault_path(), &s.store()).unwrap();
    fs::write(s.vault_path(), old).unwrap();
    let out = s.run(&["check"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("rolled back"));
}

#[test]
fn check_without_any_project() {
    let s = Sandbox::new();
    let out = s.vahta(&s.root.join("home"), &["check"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no Vahta project here"));
}

#[test]
fn usage_errors_and_help() {
    let s = Sandbox::new();
    for cmd in ["list", "check"] {
        let bad = s.run(&[cmd, "--nope"]);
        assert_eq!(bad.status.code(), Some(2));
        let help = s.run(&[cmd, "--help"]);
        assert_eq!(help.status.code(), Some(0));
        assert!(text(&help.stdout).contains(&format!("usage: vahta {cmd}")));
    }
    let top = s.run(&["--help"]);
    assert!(text(&top.stdout).contains("list") && text(&top.stdout).contains("check"));
}

// --- classes and command rules ---------------------------------------------------

impl Sandbox {
    /// Give ZETA a class and approved rules, straight into the vault file.
    fn bind_zeta(&self, class: vahta_vault::Class, allow: &str) {
        use vahta_vault::rules::parse_rule;
        let mut v = Vault::unlock_password(&self.vault_path(), PW, &self.store()).unwrap();
        v.set_class("ZETA", Some(class)).unwrap();
        let rule = parse_rule(allow, true)
            .unwrap()
            .to_allow("/opt/fake/tool".to_string());
        v.set_bindings(
            "ZETA",
            Some(vahta_vault::Binding {
                name: "ZETA".into(),
                allow: vec![rule],
                deny: vec![],
            }),
        )
        .unwrap();
        v.save(&self.vault_path(), &self.store()).unwrap();
    }
}

#[test]
fn list_shows_the_class_and_whether_the_rules_are_approved() {
    let s = Sandbox::new();
    s.with_vault(&items());
    // Nothing known and nothing bound: the two columns are not there.
    let plain = text(&s.run(&["list"]).stdout);
    assert!(
        !plain.contains("any command") && !plain.contains("payment"),
        "{plain}"
    );
    let v: serde_json::Value = serde_json::from_slice(&s.run(&["list", "--json"]).stdout).unwrap();
    assert_eq!(v["secrets"][1]["class"], serde_json::Value::Null);
    assert_eq!(v["secrets"][1]["bound"], false);
    assert_eq!(v["secrets"][1]["rules_pending"], false);

    s.bind_zeta(vahta_vault::Class::Payment, "tool");
    let out = text(&s.run(&["list"]).stdout);
    let zeta = out.lines().find(|l| l.starts_with("ZETA")).unwrap();
    assert!(
        zeta.contains("payment") && zeta.trim_end().ends_with("bound"),
        "{out}"
    );
    let alpha = out.lines().find(|l| l.starts_with("ALPHA")).unwrap();
    assert!(alpha.trim_end().ends_with("any command"), "{out}");

    // The file says the same: in step.
    s.manifest("[secrets.ZETA]\nallow = [\"tool\"]\n");
    let out = text(&s.run(&["list"]).stdout);
    assert!(
        out.lines()
            .find(|l| l.starts_with("ZETA"))
            .unwrap()
            .trim_end()
            .ends_with("bound")
    );
    // The file proposes something else: shown, and flagged in the JSON.
    s.manifest("[secrets.ZETA]\nallow = [\"tool\", \"other\"]\n");
    let out = text(&s.run(&["list"]).stdout);
    assert!(out.contains("bound (toml differs)"), "{out}");
    let v: serde_json::Value = serde_json::from_slice(&s.run(&["list", "--json"]).stdout).unwrap();
    assert_eq!(v["secrets"][1]["class"], "payment");
    assert_eq!(v["secrets"][1]["bound"], true);
    assert_eq!(v["secrets"][1]["rules_pending"], true);
}

#[test]
fn check_reports_rules_the_vault_has_not_approved_and_unknown_groups() {
    let s = Sandbox::new();
    s.with_vault(&items());
    s.manifest("[secrets.ZETA]\n[secrets.ALPHA]\n");
    assert_eq!(s.run(&["check"]).status.code(), Some(0));

    // A proposal the vault does not have: exit 1, named, in JSON too.
    s.manifest("[secrets.ZETA]\nallow = [\"tool\"]\n[secrets.ALPHA]\n");
    let out = s.run(&["check"]);
    assert_eq!(out.status.code(), Some(1));
    let said = text(&out.stderr);
    assert!(
        said.contains("Rules not approved: ZETA") && said.contains("vahta bind"),
        "{said}"
    );
    let json = s.run(&["check", "--json"]);
    assert_eq!(json.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["rules_pending"][0], "ZETA");

    // Once approved, the check passes again.
    s.bind_zeta(vahta_vault::Class::Other, "tool");
    assert_eq!(s.run(&["check"]).status.code(), Some(0));

    // An unknown group, or a group in allow, is an error, never ignored.
    for bad in [
        "[secrets.ZETA]\ndeny = [\"@nope\"]\n",
        "[secrets.ZETA]\nallow = [\"@network\"]\n",
        "[secrets.ZETA]\nallow = [\"git 'push'\"]\n",
    ] {
        s.manifest(bad);
        let out = s.run(&["check"]);
        assert_eq!(out.status.code(), Some(1), "{bad}");
        assert!(!text(&out.stderr).is_empty());
    }
    // With no vault (CI) the file alone is validated, rules included.
    let ci = Sandbox::new();
    ci.manifest("[secrets.A]\nallow = [\"tool\"]\ndeny = [\"@network\"]\n");
    assert_eq!(ci.run(&["check"]).status.code(), Some(0));
    ci.manifest("[secrets.A]\ndeny = [\"@nope\"]\n");
    assert_eq!(ci.run(&["check"]).status.code(), Some(1));
}
