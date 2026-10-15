//! Using a vault from another project (`--vault DIR`, `vahta remote`,
//! `vahta bind --from`), against a real daemon in a sandbox with a scripted
//! prompt window and a temp HOME, like `daemon.rs`.
//!
//! The vault lives in `tools/` (the sandbox's "ai-tools" project); `app/` and
//! `other/` are the projects that call it. Every command runs with its own
//! directory as the working directory, so the daemon reads a real peer
//! directory from the kernel.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;
use vahta_ipc::client::Connector;
use vahta_ipc::paths::Paths;
use vahta_ipc::protocol::{ClientReply, ClientRequest, DurationSpec, RefusalKind};
use vahta_vault::store::LocalStore;
use vahta_vault::{Network, RuleSet, Vault};

static NEXT: AtomicU32 = AtomicU32::new(0);
const PW: &[u8] = b"correct horse";
const PW_ANSWER: &str = r#"{"secret":"correct horse"}"#;

struct Sandbox {
    root: PathBuf,
    tools: PathBuf,
    app: PathBuf,
    other: PathBuf,
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

impl Sandbox {
    fn new() -> Sandbox {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("vahta-r-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for d in ["tools", "app", "other", "home", "run", "data", "config"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        let root = fs::canonicalize(root).unwrap();
        let s = Sandbox {
            tools: root.join("tools"),
            app: root.join("app"),
            other: root.join("other"),
            root,
        };
        s.script(&[PW_ANSWER, r#"{"ack":true}"#]);
        let out = s.vahta(&s.tools, &["init"]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        for (name, value) in [("ZETA", "fake-one"), ("BETA", "fake-two")] {
            s.script(&[
                PW_ANSWER,
                &format!(r#"{{"secret":"{value}"}}"#),
                r#"{"choose":0}"#,
            ]);
            let out = s.vahta(&s.tools, &["add", name, "--tier", "session"]);
            assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        }
        // Any command may use them (no category), and the file `add` wrote goes.
        s.share(&["ZETA", "BETA"], &[], false);
        let _ = fs::remove_file(s.tools.join("vahta.toml"));
        s
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
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY");
        cmd
    }

    fn vahta(&self, cwd: &Path, args: &[&str]) -> Output {
        self.command(cwd).args(args).output().expect("run vahta")
    }

    /// `vahta run --vault tools --secret NAME -- printenv NAME` from `cwd`.
    fn run_remote(&self, cwd: &Path, name: &str) -> Output {
        let tools = self.tools.to_string_lossy().into_owned();
        self.vahta(
            cwd,
            &[
                "run", "--vault", &tools, "--secret", name, "--", "printenv", name,
            ],
        )
    }

    fn script(&self, answers: &[&str]) {
        let path = self.root.join("script.jsonl");
        let mut text = fs::read_to_string(&path).unwrap_or_default();
        for a in answers {
            text.push_str(a);
            text.push('\n');
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

    fn journal(&self) -> String {
        fs::read_to_string(self.root.join("data/journal.jsonl")).unwrap_or_default()
    }

    fn sessions(&self) -> Vec<Value> {
        let out = self.vahta(&self.tools, &["sessions", "--json"]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
        doc["sessions"].as_array().unwrap().clone()
    }

    fn vault_path(&self) -> PathBuf {
        self.tools.join(".vahta/vault.vht")
    }

    fn open_vault(&self) -> Vault {
        Vault::unlock_password(
            &self.vault_path(),
            PW,
            &LocalStore::new(self.root.join("data")),
        )
        .unwrap()
    }

    /// Give each of `names` an open rule set that may be used from the `from`
    /// projects, and turn the vault's remote switch to `remote`, straight into
    /// the vault (what the person's windows would do).
    fn share(&self, names: &[&str], from: &[&Path], remote: bool) {
        let mut vault = self.open_vault();
        for n in names {
            vault
                .set_bindings(
                    n,
                    Some(RuleSet {
                        name: (*n).to_string(),
                        network: Network::App,
                        from: from
                            .iter()
                            .map(|p| p.to_string_lossy().into_owned())
                            .collect(),
                        ..Default::default()
                    }),
                )
                .unwrap();
        }
        vault.set_remote(remote).unwrap();
        vault
            .save(&self.vault_path(), &LocalStore::new(self.root.join("data")))
            .unwrap();
    }

    fn connector(&self) -> Connector {
        Connector {
            paths: Paths {
                runtime: self.root.join("run"),
                data: self.root.join("data"),
                config: self.root.join("config"),
            },
            version: vahta_daemon::VERSION.to_string(),
            start: Some(vec![
                env!("CARGO_BIN_EXE_vahta").into(),
                "daemon".into(),
                "run".into(),
            ]),
        }
    }
}

impl Drop for Sandbox {
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

#[test]
fn with_the_switch_off_a_remote_request_fails_exactly_like_a_path_with_no_vault() {
    let s = Sandbox::new();
    // The secret names the caller, but the vault has not opted in.
    s.share(&["ZETA"], &[&s.app], false);
    let missing = s.root.join("nothing-here");
    let tools = s.tools.to_string_lossy().into_owned();
    let nothing = missing.to_string_lossy().into_owned();
    let asked = s.asks();
    for args in [
        vec!["run", "--secret", "ZETA", "--", "printenv", "ZETA"],
        vec![
            "http",
            "--secret",
            "ZETA",
            "-H",
            "X: {ZETA}",
            "https://h.example/",
        ],
        vec!["unlock", "--secret", "ZETA"],
        vec!["list"],
        vec!["check"],
    ] {
        let mut off = vec![args[0], "--vault", &tools];
        off.extend_from_slice(&args[1..]);
        let mut gone = vec![args[0], "--vault", &nothing];
        gone.extend_from_slice(&args[1..]);
        let a = s.vahta(&s.app, &off);
        let b = s.vahta(&s.app, &gone);
        assert_ne!(a.status.code(), Some(0), "{args:?}");
        assert_eq!(a.status.code(), b.status.code(), "{args:?}");
        assert_eq!(text(&a.stdout), text(&b.stdout), "{args:?}");
        assert_eq!(text(&a.stderr), text(&b.stderr), "{args:?}");
        assert!(
            text(&a.stderr).contains("no Vahta project here"),
            "{args:?}"
        );
        // No names, no counts.
        assert!(!text(&a.stdout).contains("ZETA") && !text(&a.stderr).contains("ZETA"));
    }
    assert_eq!(s.asks(), asked, "no window was opened for any of them");
    // At home it works as ever.
    s.script(&[PW_ANSWER]);
    let out = s.vahta(
        &s.tools,
        &["run", "--secret", "ZETA", "--", "printenv", "ZETA"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
}

#[test]
fn with_the_switch_on_and_the_secret_naming_the_caller_it_runs_and_both_ends_are_named() {
    let s = Sandbox::new();
    s.share(&["ZETA"], &[&s.app], true);
    s.script(&[PW_ANSWER]);
    let out = s.run_remote(&s.app, "ZETA");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "***REDACTED(ZETA)***\n");

    // The window names the vault and the calling project.
    let ask = s
        .window_log()
        .into_iter()
        .rev()
        .find(|e| e["ask"] == "password")
        .unwrap();
    let lines = ask["panel"]["lines"].to_string();
    assert!(
        lines.contains(&format!(
            "Vault: {} · used from {}",
            s.vault_path().display(),
            s.app.display()
        )),
        "{lines}"
    );
    // So does the journal.
    let journal = s.journal();
    let run = journal
        .lines()
        .find(|l| l.contains("\"event\":\"run\""))
        .unwrap();
    assert!(
        run.contains(&format!("\"used_from\":\"{}\"", s.app.display())),
        "{run}"
    );
    assert!(!journal.contains("fake-"));

    // The program ran in the caller's directory, not the vault's.
    s.script(&[PW_ANSWER]);
    let tools = s.tools.to_string_lossy().into_owned();
    let out = s.vahta(
        &s.app,
        &["run", "--vault", &tools, "--secret", "ZETA", "--", "pwd"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout).trim(), s.app.display().to_string());
}

#[test]
fn a_caller_the_secret_does_not_name_is_refused_and_a_subfolder_of_one_it_names_is_not() {
    let s = Sandbox::new();
    s.share(&["ZETA"], &[&s.app], true);
    let asked = s.asks();
    let out = s.run_remote(&s.other, "ZETA");
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    let err = text(&out.stderr);
    assert!(err.contains("no secret named ZETA"), "{err}");
    // A secret the vault does not have gets the very same answer.
    let nothing = s.run_remote(&s.other, "NOPE");
    assert_eq!(
        text(&nothing.stderr).replace("NOPE", "ZETA"),
        err,
        "an uncovered secret looks like one that does not exist"
    );
    assert_eq!(s.asks(), asked);

    // Below a named project is the project.
    let deep = s.app.join("src/bin");
    fs::create_dir_all(&deep).unwrap();
    s.script(&[PW_ANSWER]);
    let out = s.run_remote(&deep, "ZETA");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
}

#[test]
fn a_secret_with_no_from_list_is_refused_remotely_and_still_works_at_home() {
    let s = Sandbox::new();
    s.share(&["ZETA"], &[], true);
    let out = s.run_remote(&s.app, "ZETA");
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("no secret named ZETA"));
    // `list` from the other project shows nothing of it.
    let tools = s.tools.to_string_lossy().into_owned();
    let out = s.vahta(&s.app, &["list", "--vault", &tools]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!text(&out.stdout).contains("ZETA"), "{}", text(&out.stdout));
    // At home, as before.
    s.script(&[PW_ANSWER]);
    let out = s.vahta(
        &s.tools,
        &["run", "--secret", "ZETA", "--", "printenv", "ZETA"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    // And naming its own project with --vault needs no switch.
    s.share(&["ZETA"], &[], false);
    s.script(&[PW_ANSWER]);
    let out = s.run_remote(&s.tools, "ZETA");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
}

#[test]
fn list_from_another_project_shows_only_what_may_be_used_from_there() {
    let s = Sandbox::new();
    s.share(&["ZETA"], &[&s.app], true);
    s.share(&["BETA"], &[&s.other], true);
    let tools = s.tools.to_string_lossy().into_owned();
    let out = s.vahta(&s.app, &["list", "--vault", &tools, "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    let names: Vec<&str> = doc["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["ZETA"]);
}

#[test]
fn a_remote_session_covers_its_pair_and_not_a_third_project_nor_local_use() {
    let s = Sandbox::new();
    s.share(&["ZETA"], &[&s.app, &s.other], true);
    let tools = s.tools.to_string_lossy().into_owned();
    s.script(&[PW_ANSWER]);
    let out = s.vahta(&s.app, &["unlock", "--vault", &tools, "--secret", "ZETA"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let sessions = s.sessions();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["used_from"], s.app.display().to_string());
    // `vahta sessions` shows the pair.
    let listed = text(&s.vahta(&s.tools, &["sessions"]).stdout);
    assert!(
        listed.contains(&s.tools.display().to_string())
            && listed.contains(&s.app.display().to_string()),
        "{listed}"
    );

    // From the project it was opened for: no window.
    let asked = s.asks();
    let out = s.run_remote(&s.app, "ZETA");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.asks(), asked, "the session answered");
    assert_eq!(s.sessions()[0]["uses"], 1);

    // From a third project the vault also allows: not covered, so it asks.
    s.script(&[PW_ANSWER]);
    let out = s.run_remote(&s.other, "ZETA");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.asks(), asked + 1);
    // And local use is not covered either.
    s.script(&[PW_ANSWER]);
    let out = s.vahta(&s.tools, &["run", "--secret", "ZETA", "--", "true"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(s.asks(), asked + 2);
    assert_eq!(s.sessions()[0]["uses"], 1, "only the pair used it");
}

#[test]
fn turning_the_switch_off_ends_sessions_opened_from_other_projects() {
    let s = Sandbox::new();
    s.share(&["ZETA"], &[&s.app], true);
    let tools = s.tools.to_string_lossy().into_owned();
    s.script(&[PW_ANSWER]);
    assert_eq!(
        s.vahta(&s.app, &["unlock", "--vault", &tools])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(s.sessions().len(), 1);
    // The person turns it off in the vault's own project: a window and the password.
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&s.tools, &["remote", "off"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("now off"));
    assert!(s.sessions().is_empty());
    assert!(!s.open_vault().remote());
    assert!(s.journal().contains("remote_set"));
    // And it is off for real.
    let out = s.run_remote(&s.app, "ZETA");
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn remote_on_needs_the_window_and_the_password_and_plain_remote_only_reports() {
    let s = Sandbox::new();
    s.share(&["ZETA"], &[&s.app], false);
    let out = s.vahta(&s.tools, &["remote"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("remote use is off"));
    for answers in [
        vec![r#"{"choose":1}"#],
        vec![r#"{"cancel":true}"#],
        vec![r#"{"choose":0}"#, r#"{"cancel":true}"#],
    ] {
        s.script(&answers);
        let out = s.vahta(&s.tools, &["remote", "on"]);
        assert_eq!(
            out.status.code(),
            Some(4),
            "{answers:?}: {}",
            text(&out.stderr)
        );
        assert!(!s.open_vault().remote());
    }
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&s.tools, &["remote", "on"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(s.open_vault().remote());
    // The window said what it allows, in words, and named the secret's projects.
    let lines = s
        .window_log()
        .iter()
        .rev()
        .find(|e| e["ask"] == "choose")
        .unwrap()["panel"]["lines"]
        .to_string();
    assert!(
        lines.contains("ANOTHER project") && lines.contains("ZETA"),
        "{lines}"
    );
    assert!(lines.contains(&s.app.display().to_string()), "{lines}");
}

#[test]
fn a_client_that_claims_a_directory_it_is_not_in_is_refused_and_noted() {
    let s = Sandbox::new();
    s.share(&["ZETA"], &[&s.app], true);
    let mut conn = s.connector().connect().expect("connect");
    let asked = s.asks();
    let tools = s.tools.to_string_lossy().into_owned();
    // This test process runs in the cli crate's directory; it says it is in
    // `app/`, which the secret names, and asks for a run there.
    for claimed in [&s.app, &s.tools] {
        let reply = conn
            .request(&ClientRequest::Run {
                cwd: claimed.to_string_lossy().into_owned(),
                argv: vec!["printenv".into(), "ZETA".into()],
                env: vec![("PATH".into(), std::env::var("PATH").unwrap_or_default())],
                names: Some(vec!["ZETA".into()]),
                renames: vec![],
                label: None,
                ask: false,
                reason: None,
                vault: Some(tools.clone()),
            })
            .unwrap();
        let ClientReply::Refused(r) = reply else {
            panic!("a spoofed directory was served: {reply:?}");
        };
        assert_eq!(r.kind, RefusalKind::NotFromHere);
    }
    // Unlock and the hook's question are no different for a run in progress.
    let reply = conn
        .request(&ClientRequest::Unlock {
            cwd: s.app.to_string_lossy().into_owned(),
            names: None,
            duration: DurationSpec::Default {},
            label: None,
            vault: Some(tools),
        })
        .unwrap();
    assert!(matches!(reply, ClientReply::Refused(_)), "{reply:?}");
    assert_eq!(s.asks(), asked, "no window for a spoof");
    assert!(s.sessions().is_empty());
    let journal = s.journal();
    assert!(
        journal.contains("remote_refused") && journal.contains("suspicious"),
        "{journal}"
    );
}

#[test]
fn bind_from_and_vahta_toml_from_round_trip_and_check_compares_them() {
    let s = Sandbox::new();
    s.share(&["ZETA", "BETA"], &[], false);
    let app = s.app.to_string_lossy().into_owned();
    // The person (or an agent proposing) adds a project to an approved secret.
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&s.tools, &["bind", "ZETA", "--from", &app]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let lines = s
        .window_log()
        .iter()
        .rev()
        .find(|e| e["ask"] == "choose")
        .unwrap()["panel"]["lines"]
        .to_string();
    assert!(
        lines.contains("also usable from the projects") && lines.contains(&app),
        "{lines}"
    );
    let from_of = |name: &str| {
        s.open_vault()
            .bindings()
            .iter()
            .find(|b| b.name == name)
            .unwrap()
            .from
            .clone()
    };
    assert_eq!(from_of("ZETA"), vec![app.clone()]);
    let toml = fs::read_to_string(s.tools.join("vahta.toml")).unwrap();
    assert!(toml.contains(&format!("from = [\"{app}\"]")), "{toml}");

    // Both copies agree: check is clean.
    let out = s.vahta(&s.tools, &["check"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        text(&out.stdout),
        text(&out.stderr)
    );

    // A hand edit of the file's `from` is a proposal, and check says so.
    let other = s.other.to_string_lossy().into_owned();
    fs::write(
        s.tools.join("vahta.toml"),
        format!("[secrets.ZETA]\nfrom = [\"{app}\", \"{other}\"]\n[secrets.BETA]\n"),
    )
    .unwrap();
    let out = s.vahta(&s.tools, &["check"]);
    assert_eq!(out.status.code(), Some(1));
    let said = text(&out.stderr);
    assert!(
        said.contains("Rules not approved") && said.contains("ZETA"),
        "{said}"
    );
    // The edit changed nothing that is enforced.
    assert_eq!(from_of("ZETA"), vec![app.clone()]);
    // `bind` with no name approves the file, `from` included.
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&s.tools, &["bind"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(from_of("ZETA"), vec![app.clone(), other.clone()]);
    assert_eq!(s.vahta(&s.tools, &["check"]).status.code(), Some(0));

    // `--no-from` takes them away; a relative or missing project is refused
    // before any window.
    let asked = s.asks();
    for bad in ["relative/dir", "/no/such/project"] {
        let out = s.vahta(&s.tools, &["bind", "ZETA", "--from", bad]);
        assert_eq!(out.status.code(), Some(1), "{bad}: {}", text(&out.stderr));
    }
    assert_eq!(s.asks(), asked);
    s.script(&[r#"{"choose":0}"#, PW_ANSWER]);
    let out = s.vahta(&s.tools, &["bind", "ZETA", "--no-from"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        s.open_vault()
            .bindings()
            .iter()
            .find(|b| b.name == "ZETA")
            .unwrap()
            .from
            .is_empty()
    );
}

#[test]
fn the_hooks_question_is_allowed_only_where_the_run_would_be() {
    let s = Sandbox::new();
    s.share(&["ZETA"], &[&s.app], true);
    let mut conn = s.connector().connect().expect("connect");
    let tools = s.tools.to_string_lossy().into_owned();
    let path = std::env::var("PATH").ok();
    let mut ask = |cwd: &Path, vault: Option<&str>, name: &str| {
        conn.request(&ClientRequest::CheckRun {
            cwd: cwd.to_string_lossy().into_owned(),
            argv: vec!["printenv".into(), name.into()],
            names: vec![name.into()],
            path: path.clone(),
            vault: vault.map(str::to_string),
        })
        .unwrap()
    };
    assert_eq!(ask(&s.app, Some(&tools), "ZETA"), ClientReply::Allowed {});
    // A project the secret does not name, a secret that is not shared, no
    // vault at all: no opinion.
    assert_eq!(
        ask(&s.other, Some(&tools), "ZETA"),
        ClientReply::NoOpinion {}
    );
    assert_eq!(ask(&s.app, Some(&tools), "BETA"), ClientReply::NoOpinion {});
    assert_eq!(ask(&s.app, None, "ZETA"), ClientReply::NoOpinion {});
    // The switch off: no opinion, though the secret names the caller.
    s.share(&["ZETA"], &[&s.app], false);
    assert_eq!(ask(&s.app, Some(&tools), "ZETA"), ClientReply::NoOpinion {});
    // Asking is not an event.
    assert!(!s.journal().contains("\"event\":\"run\""));
}
