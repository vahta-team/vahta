//! Team members through the real `vahta` binary: an owner and members, each a
//! sandbox of its own (its own HOME, VAHTA_* directories and daemon), exchanging
//! files the way a chat would. The daemons are test builds and answer their
//! prompts from a script. Everything lives in temp directories; values and
//! passwords are made up.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use vahta_vault::store::LocalStore;
use vahta_vault::{Vault, member};

static NEXT: AtomicU32 = AtomicU32::new(0);
const OWNER_PW: &str = "correct horse";
const MEMBER_PW: &str = "member passphrase";

struct Person {
    root: PathBuf,
}

impl Person {
    fn new() -> Person {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("vahta-m-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for d in ["project", "home", "run", "data", "config", "files"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        Person { root }
    }

    fn project(&self) -> PathBuf {
        self.root.join("project")
    }

    fn file(&self, name: &str) -> PathBuf {
        self.root.join("files").join(name)
    }

    fn vault_path(&self) -> PathBuf {
        self.project().join(".vahta/vault.vht")
    }

    fn store(&self) -> LocalStore {
        LocalStore::new(self.root.join("data"))
    }

    fn command(&self, cwd: &Path) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vahta"));
        cmd.current_dir(cwd)
            .env("HOME", self.root.join("home"))
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env_remove("XDG_RUNTIME_DIR")
            .env("VAHTA_DATA_DIR", self.root.join("data"))
            .env("VAHTA_RUNTIME_DIR", self.root.join("run"))
            .env("VAHTA_CONFIG_DIR", self.root.join("config"))
            .env_remove("VAHTA_TEST_DAEMON_VERSION")
            .env_remove("VAHTA_TEST_IDLE_SECONDS")
            .env("VAHTA_TEST_SURFACE", self.root.join("script.jsonl"))
            .env("VAHTA_TEST_SURFACE_LOG", self.root.join("surface.log"))
            .env("VAHTA_TEST_MUTE_REFUSAL_ALARM", "1")
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY");
        cmd
    }

    /// Queue answers: `s:TEXT` is a typed secret, `t:TEXT` a line of text,
    /// `c:N` a choice.
    fn script(&self, answers: &[&str]) {
        let path = self.root.join("script.jsonl");
        let mut text = fs::read_to_string(&path).unwrap_or_default();
        for a in answers {
            let line = match a.split_once(':') {
                Some(("s", v)) => serde_json::json!({"secret": v}),
                Some(("t", v)) => serde_json::json!({"text": v}),
                Some(("c", v)) => serde_json::json!({"choose": v.parse::<u64>().unwrap()}),
                _ => panic!("bad script item {a}"),
            };
            text.push_str(&format!("{line}\n"));
        }
        fs::write(path, text).unwrap();
    }

    fn window_log(&self) -> Vec<Value> {
        fs::read_to_string(self.root.join("surface.log"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    fn asks(&self) -> usize {
        self.window_log()
            .iter()
            .filter(|e| e.get("ask").is_some())
            .count()
    }

    fn vahta(&self, args: &[&str]) -> Output {
        self.command(&self.project())
            .args(args)
            .output()
            .expect("run vahta")
    }

    /// Run and expect success.
    fn ok(&self, args: &[&str]) -> String {
        let out = self.vahta(args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{args:?}: {}",
            text(&out.stderr)
        );
        text(&out.stdout)
    }

    /// The owner's project: a vault holding `items`, each with an open rule set.
    fn owner_with(&self, items: &[(&str, &str)]) {
        // The recovery key is acknowledged with {"ack":true}, which `script`
        // has no shorthand for.
        let path = self.root.join("script.jsonl");
        fs::write(
            &path,
            format!("{{\"secret\":\"{OWNER_PW}\"}}\n{{\"ack\":true}}\n"),
        )
        .unwrap();
        self.ok(&["init"]);
        for (name, value) in items {
            self.script(&[&format!("s:{OWNER_PW}"), &format!("s:{value}"), "c:0"]);
            self.ok(&["add", name, "--tier", "session"]);
        }
        let mut vault = self.open_owner();
        for (name, _) in items {
            vault
                .set_bindings(
                    name,
                    Some(vahta_vault::RuleSet {
                        name: (*name).to_string(),
                        network: vahta_vault::Network::App,
                        ..Default::default()
                    }),
                )
                .unwrap();
        }
        vault.save(&self.vault_path(), &self.store()).unwrap();
        let _ = fs::remove_file(self.project().join("vahta.toml"));
    }

    fn open_owner(&self) -> Vault {
        Vault::unlock_password(&self.vault_path(), OWNER_PW.as_bytes(), &self.store()).unwrap()
    }

    /// `vahta id` for a member; returns the key and the words.
    fn make_identity(&self) -> (String, String) {
        self.script(&[&format!("s:{MEMBER_PW}")]);
        self.ok(&["id"]);
        self.show_identity()
    }

    fn show_identity(&self) -> (String, String) {
        let shown = self.ok(&["id", "--show"]);
        parse_identity(&shown)
    }

    /// The owner adds a member with the right words.
    fn add_member(&self, name: &str, role: &str, key: &str, words: &str) {
        self.script(&[&format!("t:{words}"), &format!("s:{OWNER_PW}")]);
        self.ok(&["members", "add", name, "--role", role, "--key", key]);
    }

    fn grant(&self, secret: &str, member: &str) {
        self.script(&["c:0", &format!("s:{OWNER_PW}")]);
        self.ok(&["grant", secret, member]);
    }

    /// The owner writes a package and returns the file.
    fn share(&self, member: &str, file: &str) -> PathBuf {
        let path = self.file(file);
        self.script(&[&format!("s:{OWNER_PW}")]);
        self.ok(&["share", member, "-o", path.to_str().unwrap()]);
        path
    }

    /// The member installs a package; the first time the owner's words are
    /// confirmed too.
    fn join(&self, file: &Path, first: bool) -> Output {
        if first {
            self.script(&[&format!("s:{MEMBER_PW}"), "c:0"]);
        } else {
            self.script(&[&format!("s:{MEMBER_PW}")]);
        }
        self.vahta(&["join", file.to_str().unwrap()])
    }

    fn run_len(&self, secret: &str) -> Output {
        self.script(&[&format!("s:{MEMBER_PW}")]);
        let var = secret.to_string();
        self.vahta(&[
            "run",
            "--secret",
            secret,
            "--",
            "sh",
            "-c",
            &format!("echo len=${{#{var}}}"),
        ])
    }
}

impl Drop for Person {
    fn drop(&mut self) {
        let _ = self
            .command(&self.root)
            .args(["daemon", "stop"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn parse_identity(shown: &str) -> (String, String) {
    let lines: Vec<&str> = shown.lines().map(str::trim).collect();
    let key = lines.iter().find(|l| l.starts_with("vh1")).unwrap();
    let at = lines
        .iter()
        .position(|l| l.contains("verification digits"))
        .unwrap();
    ((*key).to_string(), lines[at + 1].to_string())
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// An owner with ALPHA, BETA and GAMMA.
fn owner() -> Person {
    let o = Person::new();
    let v = |s: &str| format!("fake-{s}");
    o.owner_with(&[
        ("ALPHA", &v("alpha")),
        ("BETA", &v("beta")),
        ("GAMMA", &v("gamma")),
    ]);
    o
}

// --- Tests ------------------------------------------------------------------------------

#[test]
fn the_whole_path_from_the_owner_to_a_member_running_a_command() {
    let o = owner();
    let m = Person::new();
    let (key, words) = m.make_identity();
    assert!(key.starts_with("vh1"));
    assert_eq!(words.split(' ').count(), 6);
    // The identity is not made twice.
    let again = m.vahta(&["id"]);
    assert_eq!(again.status.code(), Some(3), "{}", text(&again.stderr));

    o.add_member("ann", "runner", &key, &words);
    let listed = o.ok(&["members", "list"]);
    assert!(listed.contains("ann") && listed.contains("runner") && listed.contains("active"));
    assert!(listed.contains("owner's digits:"));
    // The window showed the member, role and end date, never the words.
    let log = serde_json::to_string(&o.window_log()).unwrap();
    assert!(log.contains("Member: ann") && log.contains("Role: runner"));
    assert!(!log.contains(&words));

    o.grant("ALPHA", "ann");
    o.grant("BETA", "ann");
    let pkg = o.file("ann.vhp");
    o.script(&[&format!("s:{OWNER_PW}")]);
    let said = o.ok(&["share", "ann", "-o", pkg.to_str().unwrap()]);
    let owner_words = o.ok(&["members", "digits"]).trim().to_string();
    assert!(said.contains(&owner_words));

    // The package holds nothing of what ann does not hold, nor anyone else.
    let bytes = fs::read(&pkg).unwrap();
    for hidden in ["GAMMA", "fake-gamma", "fake-alpha"] {
        assert!(!contains(&bytes, hidden), "{hidden}");
    }
    let peek = Vault::peek_bytes(&bytes).unwrap();
    let names: Vec<&str> = peek.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["ALPHA", "BETA"]);
    assert_eq!(peek.recipient_count, 1);
    assert!(peek.package);
    // It is not a file the owner's password opens.
    assert!(Vault::unlock_password(&pkg, OWNER_PW.as_bytes(), &o.store()).is_err());
    // Writing over it is refused as well.
    assert!(
        member::file_info(&bytes).unwrap().package,
        "marked as a package"
    );

    // The member joins: the owner's words are shown and confirmed.
    let out = m.join(&pkg, true);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("joined as ann (runner)"));
    let log = serde_json::to_string(&m.window_log()).unwrap();
    assert!(log.contains(&owner_words));
    assert!(m.vault_path().is_file());

    let listed = m.ok(&["list"]);
    assert!(listed.contains("ALPHA") && listed.contains("BETA") && !listed.contains("GAMMA"));

    let out = m.run_len("ALPHA");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("len=10"),
        "{}",
        text(&out.stdout)
    );
    // A secret ann does not hold is not there (refused before any window).
    let out = m.vahta(&["run", "--secret", "GAMMA", "--", "true"]);
    assert_ne!(
        out.status.code(),
        Some(0),
        "{}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert!(!text(&out.stdout).contains("fake-"));
    // A wrong identity password does not run anything.
    m.script(&["s:nope", "s:nope", "s:nope"]);
    let out = m.vahta(&["run", "--secret", "ALPHA", "--", "true"]);
    assert_ne!(out.status.code(), Some(0));
}

#[test]
fn wrong_digits_refuse_the_member_and_write_nothing() {
    let o = owner();
    let m = Person::new();
    let (key, _) = m.make_identity();
    let before = fs::read(o.vault_path()).unwrap();
    let asks = o.asks();
    // Not this key's digits, whatever they are: letters, then a wrong code.
    o.script(&[
        "t:kabe lomi sefo ridu tave zonu",
        "t:0000 0000 0000 0000 0000 0000",
        "t:1234",
    ]);
    let out = o.vahta(&["members", "add", "ann", "--role", "runner", "--key", &key]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("refused") && text(&out.stderr).contains("do not match"));
    assert_eq!(fs::read(o.vault_path()).unwrap(), before);
    // Only the three word prompts; the password was never asked.
    assert_eq!(o.asks() - asks, 3);
    assert!(o.open_owner().recipients().is_empty());
    // A mistyped key string is refused before any window.
    let asks = o.asks();
    let out = o.vahta(&[
        "members",
        "add",
        "ann",
        "--role",
        "runner",
        "--key",
        &key[..key.len() - 3],
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(o.asks(), asks);
}

#[test]
fn a_package_for_another_identity_is_refused() {
    let o = owner();
    let (ann, mallory) = (Person::new(), Person::new());
    let (key, words) = ann.make_identity();
    mallory.make_identity();
    o.add_member("ann", "runner", &key, &words);
    o.grant("ALPHA", "ann");
    let pkg = o.share("ann", "ann.vhp");
    let asks = mallory.asks();
    let out = mallory.join(&pkg, true);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("not addressed to your identity"));
    assert!(!mallory.vault_path().exists());
    assert_eq!(mallory.asks(), asks, "refused before any password");
    // Someone with no identity at all is told to make one.
    let nobody = Person::new();
    let out = nobody.vahta(&["join", pkg.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("vahta id"));
}

#[test]
fn an_older_or_repeated_package_is_refused_and_a_newer_one_is_taken() {
    let o = owner();
    let m = Person::new();
    let (key, words) = m.make_identity();
    o.add_member("ann", "runner", &key, &words);
    o.grant("ALPHA", "ann");
    let old = o.share("ann", "old.vhp");
    assert_eq!(m.join(&old, true).status.code(), Some(0));
    o.grant("GAMMA", "ann");
    let new = o.share("ann", "new.vhp");
    let out = m.join(&new, false);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(m.ok(&["list"]).contains("GAMMA"));
    let installed = fs::read(m.vault_path()).unwrap();
    for stale in [&old, &new] {
        let out = m.join(stale, false);
        assert_eq!(out.status.code(), Some(1));
        assert!(text(&out.stderr).contains("not newer"));
        assert_eq!(fs::read(m.vault_path()).unwrap(), installed);
    }
}

#[test]
fn a_directory_with_a_vault_of_its_own_is_not_overwritten_by_a_join() {
    let o = owner();
    let m = Person::new();
    let (key, words) = m.make_identity();
    o.add_member("ann", "runner", &key, &words);
    o.grant("ALPHA", "ann");
    let pkg = o.share("ann", "ann.vhp");
    // The member also owns a vault in another project; joining there is refused.
    m.owner_with(&[("OWN", "fake-own")]);
    let before = fs::read(m.vault_path()).unwrap();
    let out = m.join(&pkg, true);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("vault of its own"));
    assert_eq!(fs::read(m.vault_path()).unwrap(), before);
}

#[test]
fn an_expired_membership_is_refused() {
    let o = owner();
    let m = Person::new();
    let (key, words) = m.make_identity();
    o.add_member("ann", "runner", &key, &words);
    o.grant("ALPHA", "ann");
    // The owner shortens it to a few seconds (the CLI's shortest is a minute).
    let mut v = o.open_owner();
    let id = v.recipients()[0].id;
    v.set_recipient_expiry(&id, Some(now() + 6)).unwrap();
    v.save(&o.vault_path(), &o.store()).unwrap();
    let pkg = o.share("ann", "ann.vhp");
    assert_eq!(m.join(&pkg, true).status.code(), Some(0));
    assert_eq!(m.run_len("ALPHA").status.code(), Some(0));
    std::thread::sleep(Duration::from_secs(7));
    let asks = m.asks();
    let out = m.run_len("ALPHA");
    assert_ne!(out.status.code(), Some(0));
    assert!(
        text(&out.stderr).contains("expired"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(m.asks(), asks, "refused before the password");
    // The owner is told too, and cannot share with an expired member.
    let listed = o.ok(&["members", "list"]);
    assert!(listed.contains("expired"));
    let out = o.vahta(&["share", "ann", "-o", o.file("again.vhp").to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(3));
    assert!(!o.file("again.vhp").exists());
}

#[test]
fn a_runner_cannot_add_or_reveal() {
    let o = owner();
    let m = Person::new();
    let (key, words) = m.make_identity();
    o.add_member("ann", "runner", &key, &words);
    o.grant("ALPHA", "ann");
    let pkg = o.share("ann", "ann.vhp");
    assert_eq!(m.join(&pkg, true).status.code(), Some(0));
    let asks = m.asks();
    for args in [
        vec!["add", "NEWONE"],
        vec!["reset", "ALPHA"],
        vec!["remove", "ALPHA"],
        vec!["reveal", "ALPHA"],
        vec!["copy", "ALPHA"],
        vec![
            "share",
            "--to",
            "owner",
            "ALPHA",
            "-o",
            m.file("x.vhp").to_str().unwrap(),
        ],
    ] {
        let out = m.vahta(&args);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{args:?}: {}",
            text(&out.stderr)
        );
        // `copy` looks for a clipboard tool first, which a test machine lacks.
        assert!(
            args[0] == "copy"
                || text(&out.stderr).contains("runner")
                || text(&out.stderr).contains("member"),
            "{args:?}: {}",
            text(&out.stderr)
        );
    }
    assert_eq!(m.asks(), asks, "none of them got as far as a password");
    assert!(!m.file("x.vhp").exists());
    // A member manages no one.
    let out = m.vahta(&["members", "add", "bob", "--role", "runner", "--key", &key]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("package"));
}

#[test]
fn an_editor_sends_a_secret_back_and_the_owner_imports_it_after_approving() {
    let o = owner();
    let m = Person::new();
    let (key, words) = m.make_identity();
    o.add_member("eve", "editor", &key, &words);
    o.grant("ALPHA", "eve");
    let pkg = o.share("eve", "eve.vhp");
    assert_eq!(m.join(&pkg, true).status.code(), Some(0));

    // The editor adds a secret of its own, in its package.
    let value = format!("fake-{}", "mine");
    m.script(&[&format!("s:{MEMBER_PW}"), &format!("s:{value}"), "c:0"]);
    let out = m.vahta(&["add", "MINE", "--tier", "session"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(m.ok(&["list"]).contains("MINE"));

    // Sending it: one secret, for the owner.
    let blob = m.file("mine.vhp");
    m.script(&[&format!("s:{MEMBER_PW}")]);
    m.ok(&[
        "share",
        "--to",
        "owner",
        "MINE",
        "-o",
        blob.to_str().unwrap(),
    ]);
    let bytes = fs::read(&blob).unwrap();
    assert!(!contains(&bytes, "ALPHA") && !contains(&bytes, &value));

    // The owner approves; the window names the secret and who sent it.
    o.script(&[&format!("s:{OWNER_PW}"), "c:0"]);
    let out = o.ok(&["join", blob.to_str().unwrap()]);
    assert!(out.contains("imported MINE from eve"), "{out}");
    let log = serde_json::to_string(&o.window_log()).unwrap();
    assert!(log.contains("Secret: MINE") && log.contains("From: eve (editor)"));
    assert!(!log.contains(&value));
    let v = o.open_owner();
    assert_eq!(v.get("MINE").unwrap().expose(), value.as_bytes());
    assert_eq!(v.held_by(&v.recipients()[0].id), ["ALPHA", "MINE"]);

    // Declining imports nothing; so does importing it a second time.
    let again = o.vahta(&["join", blob.to_str().unwrap()]);
    assert_eq!(again.status.code(), Some(1));
}

#[test]
fn declining_an_import_changes_nothing() {
    let o = owner();
    let m = Person::new();
    let (key, words) = m.make_identity();
    o.add_member("eve", "editor", &key, &words);
    o.grant("ALPHA", "eve");
    let pkg = o.share("eve", "eve.vhp");
    assert_eq!(m.join(&pkg, true).status.code(), Some(0));
    m.script(&[&format!("s:{MEMBER_PW}"), "s:fake-theirs", "c:0"]);
    m.ok(&["add", "THEIRS", "--tier", "session"]);
    let blob = m.file("t.vhp");
    m.script(&[&format!("s:{MEMBER_PW}")]);
    m.ok(&[
        "share",
        "--to",
        "owner",
        "THEIRS",
        "-o",
        blob.to_str().unwrap(),
    ]);
    let before = fs::read(o.vault_path()).unwrap();
    o.script(&[&format!("s:{OWNER_PW}"), "c:1"]);
    let out = o.vahta(&["join", blob.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(fs::read(o.vault_path()).unwrap(), before);
}

#[test]
fn removing_a_member_prints_the_secrets_to_rotate_and_revoke_re_keys() {
    let o = owner();
    let m = Person::new();
    let (key, words) = m.make_identity();
    o.add_member("ann", "runner", &key, &words);
    o.grant("ALPHA", "ann");
    o.grant("BETA", "ann");
    // Revoking one tells what to rotate.
    o.script(&[&format!("s:{OWNER_PW}")]);
    let out = o.ok(&["revoke", "BETA", "ann"]);
    assert!(out.contains("Rotate BETA"), "{out}");
    let listed = o.ok(&["members", "list", "--json"]);
    let doc: Value = serde_json::from_str(&listed).unwrap();
    assert_eq!(doc["members"][0]["secrets"], serde_json::json!(["ALPHA"]));
    o.script(&[&format!("s:{OWNER_PW}")]);
    let out = o.ok(&["members", "remove", "ann"]);
    assert!(
        out.contains("Rotate these") && out.contains("ALPHA"),
        "{out}"
    );
    assert!(!out.contains("BETA"));
    assert!(o.open_owner().recipients().is_empty());
    // The journal says who and what, never key material.
    let journal = fs::read_to_string(o.root.join("data/journal.jsonl")).unwrap();
    assert!(journal.contains("member_added") && journal.contains("member_removed"));
    assert!(!journal.contains(&key));
}

// --- Second iteration -----------------------------------------------------------------------

#[cfg(unix)]
/// The first program called `sh` on PATH, canonical, as the daemon resolves it.
fn sh_path() -> String {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|d| d.join("sh"))
        .find_map(|p| fs::canonicalize(p).ok())
        .expect("sh on PATH")
        .to_string_lossy()
        .into_owned()
}

#[test]
fn the_verification_digits_are_six_groups_and_typing_forgives_separators() {
    let o = owner();
    let (m1, m2, m3) = (Person::new(), Person::new(), Person::new());
    let (k1, d1) = m1.make_identity();
    let groups: Vec<&str> = d1.split(' ').collect();
    assert_eq!(groups.len(), 6);
    assert!(
        groups
            .iter()
            .all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_digit()))
    );
    // No separators at all.
    o.add_member("ann", "runner", &k1, &d1.replace(' ', ""));
    // Dashes and commas, a stray space.
    let (k2, d2) = m2.make_identity();
    o.add_member("bob", "runner", &k2, &format!(" {} ", d2.replace(' ', "-")));
    assert_eq!(o.open_owner().recipients().len(), 2);
    // One digit off is refused, as are the right digits for another key.
    let (k3, d3) = m3.make_identity();
    let mut off = d3.clone().into_bytes();
    off[0] = if off[0] == b'0' { b'1' } else { b'0' };
    let off = String::from_utf8(off).unwrap();
    o.script(&[&format!("t:{off}"), &format!("t:{d1}"), &format!("t:{d2}")]);
    let out = o.vahta(&["members", "add", "cy", "--role", "runner", "--key", &k3]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(o.open_owner().recipients().len(), 2);
    // The owner's side prints digits too, and a joining member sees them.
    let theirs = o.ok(&["members", "digits"]);
    assert_eq!(theirs.trim().split(' ').count(), 6);
    assert!(
        theirs
            .trim()
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b' ')
    );
}

#[cfg(unix)]
#[test]
fn a_rule_naming_a_place_in_the_owners_project_matches_in_the_members_project() {
    let o = owner();
    let m = Person::new();
    let (key, digits) = m.make_identity();
    o.add_member("ann", "runner", &key, &digits);
    o.grant("ALPHA", "ann");
    // The owner approved `sh <owner project>/lib/x.sh`.
    let root = fs::canonicalize(o.project()).unwrap();
    let script = root.join("lib/x.sh").to_string_lossy().into_owned();
    let rule = vahta_vault::rules::parse_rule(&format!("sh {script}"), true)
        .unwrap()
        .to_allow(sh_path());
    let mut v = o.open_owner();
    v.set_bindings(
        "ALPHA",
        Some(vahta_vault::RuleSet {
            name: "ALPHA".into(),
            allow: vec![rule],
            network: vahta_vault::Network::App,
            ..Default::default()
        }),
    )
    .unwrap();
    v.save(&o.vault_path(), &o.store()).unwrap();
    let pkg = o.share("ann", "ann.vhp");
    // The package says nothing of the owner's layout.
    let bytes = fs::read(&pkg).unwrap();
    assert!(!contains(&bytes, &root.to_string_lossy()));
    assert_eq!(m.join(&pkg, true).status.code(), Some(0));

    for name in ["x.sh", "y.sh"] {
        fs::create_dir_all(m.project().join("lib")).unwrap();
        fs::write(m.project().join("lib").join(name), "echo ran-it\n").unwrap();
    }
    let mine = |name: &str| {
        m.project()
            .join("lib")
            .join(name)
            .to_string_lossy()
            .into_owned()
    };
    m.script(&[&format!("s:{MEMBER_PW}")]);
    let out = m.vahta(&["run", "--secret", "ALPHA", "--", "sh", &mine("x.sh")]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("ran-it"));
    // Another script in the same folder is not what was approved.
    m.script(&[&format!("s:{MEMBER_PW}")]);
    let out = m.vahta(&["run", "--secret", "ALPHA", "--", "sh", &mine("y.sh")]);
    assert_ne!(out.status.code(), Some(0));
    assert!(!text(&out.stdout).contains("ran-it"));
    // Nor the owner's own path, which does not exist here.
    m.script(&[&format!("s:{MEMBER_PW}")]);
    let out = m.vahta(&["run", "--secret", "ALPHA", "--", "sh", &script]);
    assert_ne!(out.status.code(), Some(0));
}

#[cfg(unix)]
#[test]
fn share_warns_about_places_outside_the_project_by_secret_name() {
    let o = owner();
    let m = Person::new();
    let (key, digits) = m.make_identity();
    o.add_member("ann", "runner", &key, &digits);
    o.grant("ALPHA", "ann");
    let mut v = o.open_owner();
    let rule = vahta_vault::rules::parse_rule("sh", true)
        .unwrap()
        .to_allow(sh_path());
    v.set_bindings(
        "ALPHA",
        Some(vahta_vault::RuleSet {
            name: "ALPHA".into(),
            allow: vec![rule],
            network: vahta_vault::Network::App,
            ..Default::default()
        }),
    )
    .unwrap();
    v.save(&o.vault_path(), &o.store()).unwrap();
    o.script(&[&format!("s:{OWNER_PW}")]);
    let out = o.ok(&["share", "ann", "-o", o.file("w.vhp").to_str().unwrap()]);
    assert!(
        out.contains("warning") && out.contains("ALPHA:") && out.contains(&sh_path()),
        "{out}"
    );
}

#[test]
fn a_member_opens_a_session_that_never_outlasts_the_membership() {
    let o = owner();
    let m = Person::new();
    let (key, digits) = m.make_identity();
    o.add_member("ann", "runner", &key, &digits);
    o.grant("ALPHA", "ann");
    let mut v = o.open_owner();
    let id = v.recipients()[0].id;
    v.set_recipient_expiry(&id, Some(now() + 8)).unwrap();
    v.save(&o.vault_path(), &o.store()).unwrap();
    let pkg = o.share("ann", "ann.vhp");
    assert_eq!(m.join(&pkg, true).status.code(), Some(0));

    // An hour was asked for; the membership has seconds left.
    m.script(&[&format!("s:{MEMBER_PW}")]);
    let out = m.vahta(&["unlock", "--for", "1h", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    let left = doc["session"]["remaining_secs"].as_u64().unwrap();
    assert!(left <= 8, "{left}");
    assert_eq!(doc["session"]["names"], serde_json::json!(["ALPHA"]));
    let log = serde_json::to_string(&m.window_log()).unwrap();
    assert!(log.contains("membership ends"));

    // Inside the session no window and no password.
    let asks = m.asks();
    let out = m.vahta(&["run", "--secret", "ALPHA", "--", "true"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(m.asks(), asks);
    // A member still cannot reveal, even with a session.
    let out = m.vahta(&["reveal", "ALPHA"]);
    assert_eq!(out.status.code(), Some(1));

    std::thread::sleep(Duration::from_secs(9));
    let out = m.vahta(&["run", "--secret", "ALPHA", "--", "true"]);
    assert_ne!(out.status.code(), Some(0));
    assert!(
        m.ok(&["sessions", "--json"]).contains("\"sessions\":[]")
            || serde_json::from_str::<Value>(&m.ok(&["sessions", "--json"])).unwrap()["sessions"]
                .as_array()
                .unwrap()
                .is_empty()
    );
}

#[test]
fn after_the_owner_re_keys_a_member_follows_the_chain_when_the_digits_are_confirmed() {
    let o = owner();
    let m = Person::new();
    let (key, digits) = m.make_identity();
    o.add_member("ann", "runner", &key, &digits);
    o.grant("ALPHA", "ann");
    let first = o.share("ann", "first.vhp");
    assert_eq!(m.join(&first, true).status.code(), Some(0));

    // The owner lost a device and re-keys.
    let mut v = o.open_owner();
    let kek = v.password_kek(OWNER_PW.as_bytes()).unwrap();
    v.rekey(&kek, vahta_vault::RecoveryPlan::Replace, vec![])
        .unwrap();
    v.save(&o.vault_path(), &o.store()).unwrap();
    drop(v);
    o.grant("BETA", "ann");
    let second = o.share("ann", "second.vhp");
    let new_digits = o.ok(&["members", "digits"]).trim().to_string();

    // Declining leaves the installed package alone.
    let installed = fs::read(m.vault_path()).unwrap();
    m.script(&[&format!("s:{MEMBER_PW}"), "c:1"]);
    let out = m.vahta(&["join", second.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert_eq!(fs::read(m.vault_path()).unwrap(), installed);

    let out = m.join(&second, true);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let log = serde_json::to_string(&m.window_log()).unwrap();
    assert!(log.contains("owner's key changed") && log.contains(&new_digits));
    assert!(m.ok(&["list"]).contains("BETA"));
    assert_eq!(m.run_len("ALPHA").status.code(), Some(0));
    // The old package is old now.
    let out = m.join(&first, false);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("not newer"));
}

#[test]
fn an_editors_local_changes_do_not_block_the_owners_next_package() {
    let o = owner();
    let m = Person::new();
    let (key, digits) = m.make_identity();
    o.add_member("eve", "editor", &key, &digits);
    o.grant("ALPHA", "eve");
    let first = o.share("eve", "first.vhp");
    assert_eq!(m.join(&first, true).status.code(), Some(0));
    m.script(&[&format!("s:{MEMBER_PW}"), "s:fake-mine", "c:0"]);
    m.ok(&["add", "MINE", "--tier", "session"]);
    // One local save each: the two files' own generations are equal.
    o.grant("BETA", "eve");
    let second = o.share("eve", "second.vhp");
    let out = m.join(&second, false);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(m.ok(&["list"]).contains("BETA"));
    // The window warned that the local-only secret would be replaced.
    let log = serde_json::to_string(&m.window_log()).unwrap();
    assert!(log.contains("your current file has MINE"), "{log}");
    // An older package is still refused.
    let out = m.join(&first, false);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn an_editors_transfers_are_ordered_by_a_counter_not_a_clock() {
    let o = owner();
    let m = Person::new();
    let (key, digits) = m.make_identity();
    o.add_member("eve", "editor", &key, &digits);
    o.grant("ALPHA", "eve");
    let pkg = o.share("eve", "eve.vhp");
    assert_eq!(m.join(&pkg, true).status.code(), Some(0));
    m.script(&[&format!("s:{MEMBER_PW}"), "s:fake-v1", "c:0"]);
    m.ok(&["add", "MINE", "--tier", "session"]);
    let send = |file: &str| {
        let f = m.file(file);
        m.script(&[&format!("s:{MEMBER_PW}")]);
        m.ok(&["share", "--to", "owner", "MINE", "-o", f.to_str().unwrap()]);
        f
    };
    let (a, b) = (send("a.vhp"), send("b.vhp"));
    let import = |f: &Path| {
        o.script(&[&format!("s:{OWNER_PW}"), "c:0"]);
        o.vahta(&["join", f.to_str().unwrap()])
    };
    // The newer file first; the older one is then a replay.
    assert_eq!(import(&b).status.code(), Some(0));
    let out = import(&a);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("not newer"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(import(&b).status.code(), Some(1));
    // A later one is fine.
    let c = send("c.vhp");
    assert_eq!(import(&c).status.code(), Some(0));
}

#[test]
fn proposed_rules_are_shown_in_plain_words_and_applied_only_on_approval() {
    let o = owner();
    let m = Person::new();
    let (key, digits) = m.make_identity();
    o.add_member("eve", "editor", &key, &digits);
    o.grant("ALPHA", "eve");
    let pkg = o.share("eve", "eve.vhp");
    assert_eq!(m.join(&pkg, true).status.code(), Some(0));
    let mut names = Vec::new();
    for n in ["ONE", "TWO", "THREE"] {
        m.script(&[&format!("s:{MEMBER_PW}"), "s:fake-x", "c:0"]);
        m.ok(&["add", n, "--tier", "session"]);
        names.push(n);
    }
    let send = |name: &str| {
        let f = m.file(&format!("{name}.vhp"));
        m.script(&[&format!("s:{MEMBER_PW}")]);
        m.ok(&[
            "share",
            "--to",
            "owner",
            name,
            "-o",
            f.to_str().unwrap(),
            "--allow",
            "sh",
            "--net",
            "none",
        ]);
        f
    };
    // Approved: the owner's vault ends up with the rules, signed by the owner.
    o.script(&[&format!("s:{OWNER_PW}"), "c:0"]);
    let out = o.ok(&["join", send("ONE").to_str().unwrap()]);
    assert!(out.contains("rules it proposed are approved"), "{out}");
    let log = serde_json::to_string(&o.window_log()).unwrap();
    assert!(
        log.contains("PROPOSES")
            && log.contains("allow: sh")
            && log.contains("Import with these rules")
    );
    let v = o.open_owner();
    let b = v.bindings().iter().find(|b| b.name == "ONE").unwrap();
    assert_eq!(b.allow[0].text, "sh");
    assert_eq!(b.network, vahta_vault::Network::None);
    assert!(
        fs::read_to_string(o.project().join("vahta.toml"))
            .unwrap()
            .contains("ONE")
    );
    drop(v);

    // Imported without the rules: the secret has none.
    o.script(&[&format!("s:{OWNER_PW}"), "c:1"]);
    o.ok(&["join", send("TWO").to_str().unwrap()]);
    let v = o.open_owner();
    assert!(v.entries().iter().any(|e| e.name == "TWO"));
    assert!(v.bindings().iter().all(|b| b.name != "TWO"));
    drop(v);

    // Cancelled: nothing at all.
    o.script(&[&format!("s:{OWNER_PW}"), "c:2"]);
    let out = o.vahta(&["join", send("THREE").to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(4));
    let v = o.open_owner();
    assert!(v.entries().iter().all(|e| e.name != "THREE"));
    // The proposal is in the editor's signed file only as text.
    assert!(contains(&fs::read(m.file("THREE.vhp")).unwrap(), "sh"));
}

#[test]
fn proposed_rules_never_change_a_secret_the_owner_already_has() {
    let o = owner();
    let m = Person::new();
    let (key, digits) = m.make_identity();
    o.add_member("eve", "editor", &key, &digits);
    o.grant("ALPHA", "eve");
    let pkg = o.share("eve", "eve.vhp");
    assert_eq!(m.join(&pkg, true).status.code(), Some(0));
    let before = o.open_owner().bindings().to_vec();
    let f = m.file("alpha.vhp");
    m.script(&[&format!("s:{MEMBER_PW}")]);
    m.ok(&[
        "share",
        "--to",
        "owner",
        "ALPHA",
        "-o",
        f.to_str().unwrap(),
        "--allow",
        "sh",
    ]);
    // The window offers a plain import (no rules option) and says they are ignored.
    o.script(&[&format!("s:{OWNER_PW}"), "c:0"]);
    o.ok(&["join", f.to_str().unwrap()]);
    let log = serde_json::to_string(&o.window_log()).unwrap();
    assert!(log.contains("they are ignored"), "{log}");
    assert_eq!(o.open_owner().bindings(), before.as_slice());
}
