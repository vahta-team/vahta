//! The logic behind the hook watchdog (`vahta _guard`), `vahta hooks pause` and
//! `vahta setup --managed`, as pure functions over an explicit [`Env`] and
//! plain directories, so every case runs against a temporary tree.
//!
//! * **What is watched, and what counts as tampering** ([`check`]): a harness
//!   whose hooks were set up (remembered in `guard-state.json`) and whose
//!   config no longer holds all of our entries, or whose hook program is gone;
//!   `"disableAllHooks": true` in a Claude Code settings file (the user's, or a
//!   noted project's); `hooks = false` under `[features]` in Codex's
//!   `config.toml`. An entry that merely differs from what this binary would
//!   write is *not* tampering (an older or newer vahta may have written it),
//!   and neither is a hook path that points to another vahta-hook that exists.
//! * **Pauses** (`pause.json` in the data directory, which the hook already
//!   keeps agents out of): a harness with an unexpired pause is not watched.
//! * **Putting it back** ([`restore`]): the same plan and commit `vahta setup`
//!   uses, so the backup and the atomic write are reused.
//! * **Login autostart** ([`autostart`]): the unit, plist or registry value,
//!   and the commands that enable and disable it. The commands are run by the
//!   caller through a [`Runner`], so a test never reaches a service manager.
//! * **Administrator policy** ([`managed_plan`]).

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use vahta_harness::{ManagedFormat, Manifest};

use super::{
    Action, Entry, Env, Os, Placement, Plan, Refusal, State, commit, entries, event_kind, expand,
    installed, parse, plan_placed, quote_word, read_config, render,
};

/// The longest a pause may last.
pub const MAX_PAUSE_SECS: u64 = 8 * 3600;

/// The most project roots remembered for the watcher.
const MAX_PROJECTS: usize = 200;

// --- small files in the data directory ---------------------------------------------------

fn write_atomic(path: &Path, text: &str) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.tmp-{}", std::process::id()));
    let result = fs::write(&tmp, text).and_then(|()| fs::rename(&tmp, path));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// One pause: `harness` is not watched, and its hooks may be absent, until
/// `until` (seconds since the Unix epoch).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pause {
    pub harness: String,
    pub until: u64,
    pub reason: String,
}

pub fn pause_file(data: &Path) -> PathBuf {
    data.join("pause.json")
}

/// The pauses on record; an unreadable file is none.
pub fn read_pauses(data: &Path) -> Vec<Pause> {
    let Ok(text) = fs::read_to_string(pause_file(data)) else {
        return Vec::new();
    };
    let Ok(Value::Object(doc)) = serde_json::from_str::<Value>(&text) else {
        return Vec::new();
    };
    let Some(Value::Array(items)) = doc.get("pauses") else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|p| {
            Some(Pause {
                harness: p.get("harness")?.as_str()?.to_string(),
                until: p.get("until")?.as_u64()?,
                reason: p
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            })
        })
        .collect()
}

/// Replace the pauses on record. None left removes the file.
pub fn write_pauses(data: &Path, pauses: &[Pause]) -> io::Result<()> {
    if pauses.is_empty() {
        return match fs::remove_file(pause_file(data)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    let items: Vec<Value> = pauses
        .iter()
        .map(|p| {
            let mut o = Map::new();
            o.insert("harness".into(), p.harness.clone().into());
            o.insert("until".into(), p.until.into());
            o.insert("reason".into(), p.reason.clone().into());
            Value::Object(o)
        })
        .collect();
    let mut doc = Map::new();
    doc.insert("pauses".into(), Value::Array(items));
    write_atomic(&pause_file(data), &render(doc))
}

/// Whether `harness` has a pause that has not run out at `now`.
pub fn paused(pauses: &[Pause], harness: &str, now: u64) -> bool {
    pauses.iter().any(|p| p.harness == harness && p.until > now)
}

/// The harnesses whose hooks were set up, as the watcher last saw.
pub fn read_expected(data: &Path) -> BTreeSet<String> {
    let Ok(text) = fs::read_to_string(data.join("guard-state.json")) else {
        return BTreeSet::new();
    };
    let Ok(Value::Object(doc)) = serde_json::from_str::<Value>(&text) else {
        return BTreeSet::new();
    };
    match doc.get("expected") {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => BTreeSet::new(),
    }
}

pub fn write_expected(data: &Path, expected: &BTreeSet<String>) -> io::Result<()> {
    let mut doc = Map::new();
    doc.insert(
        "expected".into(),
        Value::Array(expected.iter().map(|s| Value::String(s.clone())).collect()),
    );
    write_atomic(&data.join("guard-state.json"), &render(doc))
}

/// Project roots the daemon has seen (`run` and `unlock`), whose Claude Code
/// settings the watcher also reads.
pub fn read_projects(data: &Path) -> Vec<PathBuf> {
    let Ok(text) = fs::read_to_string(data.join("projects.json")) else {
        return Vec::new();
    };
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(PathBuf::from))
            .collect(),
        _ => Vec::new(),
    }
}

/// Remember a project root. Cheap when it is already there.
pub fn note_project(data: &Path, root: &Path) {
    let mut roots = read_projects(data);
    if roots.iter().any(|r| r == root) {
        return;
    }
    roots.push(root.to_path_buf());
    if roots.len() > MAX_PROJECTS {
        roots.remove(0);
    }
    let items: Vec<Value> = roots
        .iter()
        .filter_map(|r| r.to_str().map(|s| Value::String(s.to_string())))
        .collect();
    let mut text = serde_json::to_string_pretty(&Value::Array(items)).unwrap_or_default();
    text.push('\n');
    let _ = write_atomic(&data.join("projects.json"), &text);
}

// --- what is watched -----------------------------------------------------------------------

/// The Claude Code settings files of a project root.
pub fn claude_project_files(root: &Path) -> [PathBuf; 2] {
    [
        root.join(".claude").join("settings.json"),
        root.join(".claude").join("settings.local.json"),
    ]
}

/// Codex's `config.toml`, next to its `hooks.json`.
fn codex_toml(m: &Manifest, env: &Env) -> Option<PathBuf> {
    if m.name != "codex" {
        return None;
    }
    super::config_path(m, env).map(|p| p.with_file_name("config.toml"))
}

/// Every file the watcher looks at, for the change signature.
pub fn watched_files(ms: &[Manifest], env: &Env, projects: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for m in ms {
        if let Some(p) = super::config_path(m, env) {
            out.push(p);
        }
        if let Some(p) = codex_toml(m, env) {
            out.push(p);
        }
    }
    for root in projects {
        out.extend(claude_project_files(root));
    }
    out
}

/// What the watcher found wrong, and how to put it right.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tamper {
    pub harness: String,
    pub title: String,
    pub file: PathBuf,
    pub what: String,
    pub fix: Fix,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fix {
    /// Install our entries again.
    Reinstall,
    /// Take `disableAllHooks` out of the file.
    ClearDisableAll,
    /// Turn Codex's hooks feature back on in `config.toml`.
    CodexHooksOn,
}

/// The `(event, --event kind)` of each of our commands in a config's text.
fn kinds_in(text: &str, m: &Manifest, env: &Env) -> Option<BTreeSet<(String, String)>> {
    let doc = parse(Some(text)).ok()?;
    Some(
        installed(&doc, m.config.shape, env.os)
            .into_iter()
            .filter_map(|(e, _)| Some((e.event.clone(), event_kind(&e.command, env.os)?)))
            .collect(),
    )
}

fn wanted_kinds(m: &Manifest, env: &Env) -> BTreeSet<(String, String)> {
    entries(m, "vahta-hook")
        .into_iter()
        .filter_map(|e| Some((e.event.clone(), event_kind(&e.command, env.os)?)))
        .collect()
}

/// Whether a JSON settings file has `"disableAllHooks": true` at its top level.
pub fn disables_all_hooks(text: &str) -> bool {
    matches!(
        serde_json::from_str::<Value>(text),
        Ok(Value::Object(o)) if o.get("disableAllHooks").is_some_and(|v| v.as_bool() == Some(true))
    )
}

/// Whether a Codex `config.toml` turns hooks off (`hooks = false` under
/// `[features]`). Read line by line: the file is not parsed as TOML.
pub fn toml_disables_hooks(text: &str) -> bool {
    let mut in_features = false;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            in_features = line == "[features]";
        } else if in_features
            && let Some((k, v)) = line.split_once('=')
            && k.trim() == "hooks"
            && v.trim() == "false"
        {
            return true;
        }
    }
    false
}

/// Look at every watched thing now. `expected` is the set of harnesses known
/// to have our hooks: a harness found with them is added, and one that has
/// lost them while in the set is tampering. A harness with an unexpired pause
/// is skipped.
pub fn check(
    ms: &[Manifest],
    env: &Env,
    projects: &[PathBuf],
    expected: &mut BTreeSet<String>,
    pauses: &[Pause],
    now: u64,
) -> Vec<Tamper> {
    let mut out = Vec::new();
    for m in ms {
        if paused(pauses, &m.name, now) {
            continue;
        }
        let Some(path) = super::config_path(m, env) else {
            continue;
        };
        let text = read_config(&path);
        let mut tamper = |what: String, file: &Path, fix: Fix| {
            out.push(Tamper {
                harness: m.name.clone(),
                title: m.title.clone(),
                file: file.to_path_buf(),
                what,
                fix,
            });
        };
        match &text {
            Ok(Some(t)) => match kinds_in(t, m, env) {
                Some(have) if !have.is_empty() => {
                    expected.insert(m.name.clone());
                    let missing = wanted_kinds(m, env).difference(&have).count();
                    if missing > 0 {
                        tamper(
                            format!("{missing} of Vahta's hook entries were removed"),
                            &path,
                            Fix::Reinstall,
                        );
                    } else if env.hook.is_file()
                        && super::inspect(m, env)
                            .problems
                            .iter()
                            .any(|p| matches!(p, super::HookProblem::Missing(_)))
                    {
                        tamper(
                            "the hook program Vahta's entries point to is gone".to_string(),
                            &path,
                            Fix::Reinstall,
                        );
                    }
                }
                Some(_) if expected.contains(&m.name) => tamper(
                    "Vahta's hooks were removed".to_string(),
                    &path,
                    Fix::Reinstall,
                ),
                None if expected.contains(&m.name) => tamper(
                    "the file was changed so that it can no longer be read".to_string(),
                    &path,
                    Fix::Reinstall,
                ),
                _ => {}
            },
            Ok(None) if expected.contains(&m.name) => tamper(
                "the file was deleted, and Vahta's hooks with it".to_string(),
                &path,
                Fix::Reinstall,
            ),
            _ => {}
        }
        if !expected.contains(&m.name) {
            continue;
        }
        if m.name == "claude" {
            let mut files = vec![path.clone()];
            for root in projects {
                files.extend(claude_project_files(root));
            }
            for f in files {
                if let Ok(Some(t)) = read_config(&f)
                    && disables_all_hooks(&t)
                {
                    out.push(Tamper {
                        harness: m.name.clone(),
                        title: m.title.clone(),
                        file: f,
                        what: "\"disableAllHooks\" was set to true, which turns every hook off"
                            .to_string(),
                        fix: Fix::ClearDisableAll,
                    });
                }
            }
        }
        if let Some(toml) = codex_toml(m, env)
            && let Ok(Some(t)) = read_config(&toml)
            && toml_disables_hooks(&t)
        {
            out.push(Tamper {
                harness: m.name.clone(),
                title: m.title.clone(),
                file: toml,
                what: "hooks were switched off under [features]".to_string(),
                fix: Fix::CodexHooksOn,
            });
        }
    }
    out
}

/// Put one thing right.
pub fn restore(ms: &[Manifest], env: &Env, t: &Tamper) -> Result<(), String> {
    let write = |after: String| -> Result<(), String> {
        let before = read_config(&t.file).map_err(|e| e.to_string())?;
        commit(&Plan {
            path: t.file.clone(),
            before,
            after: Some(after),
        })
        .map(|_| ())
        .map_err(|e| e.to_string())
    };
    match t.fix {
        Fix::Reinstall => {
            let m = ms
                .iter()
                .find(|m| m.name == t.harness)
                .ok_or("unknown harness")?;
            if !env.hook.is_file() {
                return Err(format!("{} does not exist", env.hook.display()));
            }
            let plan =
                plan_placed(m, env, Action::Install, Placement::Keep).map_err(|e| e.to_string())?;
            commit(&plan).map(|_| ()).map_err(|e| e.to_string())
        }
        Fix::ClearDisableAll => {
            let text = read_config(&t.file)
                .map_err(|e| e.to_string())?
                .ok_or("the file is gone")?;
            let mut doc = parse(Some(&text)).map_err(|e| e.to_string())?;
            doc.shift_remove("disableAllHooks");
            write(render(doc))
        }
        Fix::CodexHooksOn => {
            let text = read_config(&t.file)
                .map_err(|e| e.to_string())?
                .ok_or("the file is gone")?;
            let mut in_features = false;
            let mut out = String::new();
            for line in text.split_inclusive('\n') {
                let bare = line.split('#').next().unwrap_or("").trim();
                if bare.starts_with('[') {
                    in_features = bare == "[features]";
                }
                let flipped = in_features
                    && bare
                        .split_once('=')
                        .is_some_and(|(k, v)| k.trim() == "hooks" && v.trim() == "false");
                if flipped {
                    let nl = if line.ends_with('\n') { "\n" } else { "" };
                    out.push_str(&format!("hooks = true{nl}"));
                } else {
                    out.push_str(line);
                }
            }
            write(out)
        }
    }
}

/// Take our entries out of one harness's config, for a pause. `Ok(false)` when
/// there was nothing of ours to take.
pub fn remove_entries(m: &Manifest, env: &Env) -> Result<bool, String> {
    let plan = plan_placed(m, env, Action::Uninstall, Placement::Keep).map_err(|e| match e {
        Refusal::Io(e) => e.to_string(),
        other => other.to_string(),
    })?;
    if plan.after.is_none() {
        return Ok(false);
    }
    commit(&plan).map(|_| true).map_err(|e| e.to_string())
}

/// Put our entries into one harness's config, for a resume or the end of a
/// pause. `Ok(false)` when they were all there.
pub fn add_entries(m: &Manifest, env: &Env) -> Result<bool, String> {
    if !env.hook.is_file() {
        return Err(format!("{} does not exist", env.hook.display()));
    }
    let plan = plan_placed(m, env, Action::Install, Placement::Keep).map_err(|e| e.to_string())?;
    if plan.after.is_none() {
        return Ok(false);
    }
    commit(&plan).map(|_| true).map_err(|e| e.to_string())
}

/// Whether a harness has our entries now.
pub fn has_entries(m: &Manifest, env: &Env) -> bool {
    matches!(
        super::inspect(m, env).state,
        State::Current | State::Outdated
    )
}

// --- login autostart -----------------------------------------------------------------------------

/// What is run to enable or disable the autostart: a program and its arguments.
pub type Command = Vec<String>;

/// Runs the commands of an autostart. The real one starts processes; a test
/// records them.
pub trait Runner {
    fn run(&self, argv: &[String]) -> bool;
}

/// How the guard is started at login on this OS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Autostart {
    /// The file to write (a unit, a plist); none where it is a registry value.
    pub file: Option<(PathBuf, String)>,
    pub enable: Vec<Command>,
    pub disable: Vec<Command>,
}

pub const UNIT: &str = "vahta-guard.service";
pub const LAUNCHD_LABEL: &str = "dev.vahta.guard";
const RUN_VALUE: &str = "VahtaGuard";

/// The autostart for `exe` (the `vahta` that runs `_guard`).
pub fn autostart(env: &Env, exe: &Path) -> Autostart {
    let exe = exe.to_string_lossy();
    let cmd = |words: &[&str]| words.iter().map(|w| w.to_string()).collect::<Command>();
    match env.os {
        Os::Linux => {
            let base = match env.vars.get("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
                Some(x) => PathBuf::from(x),
                None => env.home.join(".config"),
            };
            let path = base.join("systemd").join("user").join(UNIT);
            let text = format!(
                "[Unit]\n\
                 Description=Vahta hook watchdog: watches the hook settings of coding agents (holds no keys, no network)\n\
                 \n\
                 [Service]\n\
                 ExecStart={} _guard\n\
                 Restart=on-failure\n\
                 RestartSec=10\n\
                 \n\
                 [Install]\n\
                 WantedBy=default.target\n",
                quote_word(&exe, env.os)
            );
            Autostart {
                file: Some((path, text)),
                enable: vec![
                    cmd(&["systemctl", "--user", "daemon-reload"]),
                    cmd(&["systemctl", "--user", "enable", "--now", UNIT]),
                ],
                disable: vec![
                    cmd(&["systemctl", "--user", "disable", "--now", UNIT]),
                    cmd(&["systemctl", "--user", "daemon-reload"]),
                ],
            }
        }
        Os::Macos => {
            let path = env
                .home
                .join("Library")
                .join("LaunchAgents")
                .join(format!("{LAUNCHD_LABEL}.plist"));
            let esc = |s: &str| {
                s.replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;")
            };
            let text = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                 <plist version=\"1.0\">\n<dict>\n\
                 \t<key>Label</key><string>{LAUNCHD_LABEL}</string>\n\
                 \t<key>ProgramArguments</key>\n\t<array><string>{}</string><string>_guard</string></array>\n\
                 \t<key>RunAtLoad</key><true/>\n\
                 \t<key>KeepAlive</key><true/>\n\
                 </dict>\n</plist>\n",
                esc(&exe)
            );
            let p = path.to_string_lossy().into_owned();
            Autostart {
                file: Some((path, text)),
                enable: vec![cmd(&["launchctl", "load", "-w", &p])],
                disable: vec![cmd(&["launchctl", "unload", "-w", &p])],
            }
        }
        Os::Windows => Autostart {
            file: None,
            enable: vec![cmd(&[
                "reg",
                "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                RUN_VALUE,
                "/t",
                "REG_SZ",
                "/d",
                &format!("\"{exe}\" _guard"),
                "/f",
            ])],
            disable: vec![cmd(&[
                "reg",
                "delete",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                RUN_VALUE,
                "/f",
            ])],
        },
    }
}

/// Whether the autostart is in place: its file exists, and on Windows
/// whatever `registered` says.
pub fn autostart_present(a: &Autostart) -> Option<bool> {
    a.file.as_ref().map(|(p, _)| p.is_file())
}

/// Write the autostart and enable it. The error says which step failed.
pub fn enable_autostart(a: &Autostart, runner: &dyn Runner) -> Result<(), String> {
    if let Some((path, text)) = &a.file {
        write_atomic(path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    for c in &a.enable {
        if !runner.run(c) {
            return Err(format!("`{}` did not succeed", c.join(" ")));
        }
    }
    Ok(())
}

/// Disable the autostart and remove its file. Best effort: a service that was
/// never enabled is fine.
pub fn disable_autostart(a: &Autostart, runner: &dyn Runner) {
    for c in &a.disable {
        let _ = runner.run(c);
    }
    if let Some((path, _)) = &a.file {
        let _ = fs::remove_file(path);
    }
}

// --- administrator policy -------------------------------------------------------------------------

/// The administrator-policy file for one harness, worked out.
#[derive(Debug, PartialEq, Eq)]
pub struct ManagedPlan {
    pub harness: String,
    pub title: String,
    pub path: PathBuf,
    /// What the file would hold (JSON harnesses: the whole file, merged with
    /// what is there; Codex: the whole file, or just the block to append).
    pub text: String,
    /// `text` is a block to add to a file that exists, not the whole file.
    pub append: bool,
    /// The file already says this.
    pub current: bool,
}

/// The managed path for `m`, under `root` when one is given (tests).
pub fn managed_path(m: &Manifest, env: &Env, root: Option<&Path>) -> Option<PathBuf> {
    let managed = m.config.managed.as_ref()?;
    let candidates = match env.os {
        Os::Linux => &managed.path.linux,
        Os::Macos => &managed.path.macos,
        Os::Windows => &managed.path.windows,
    };
    let path = candidates.iter().find_map(|t| expand(t, env))?;
    Some(match root {
        Some(root) => {
            let tail: PathBuf = path
                .components()
                .filter(|c| matches!(c, std::path::Component::Normal(_)))
                .collect();
            root.join(tail)
        }
        None => path,
    })
}

fn toml_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

/// Codex's `requirements.toml` hooks: the `[features]` pin that keeps a user
/// from switching hooks off, and one `[[hooks.<Event>]]` per entry.
fn codex_block(es: &[Entry]) -> String {
    let mut s = String::new();
    for e in es {
        s.push('\n');
        s.push_str(&format!("[[hooks.{}]]\n", e.event));
        if let Some(m) = &e.matcher {
            s.push_str(&format!("matcher = {}\n", toml_str(m)));
        }
        s.push_str(&format!("\n[[hooks.{}.hooks]]\n", e.event));
        s.push_str("type = \"command\"\n");
        s.push_str(&format!("command = {}\n", toml_str(&e.command)));
    }
    s
}

/// What `vahta setup --managed` would write for `m`. `None` when the harness
/// has no administrator policy or no path on this OS.
pub fn managed_plan(
    m: &Manifest,
    env: &Env,
    root: Option<&Path>,
) -> Result<Option<ManagedPlan>, Refusal> {
    let Some(managed) = &m.config.managed else {
        return Ok(None);
    };
    let Some(path) = managed_path(m, env, root) else {
        return Ok(None);
    };
    let hook = env.hook.to_str().ok_or(Refusal::HookPathNotUtf8)?;
    let program = quote_word(hook, env.os);
    let existing = match read_config(&path) {
        Ok(t) => t,
        // A file we cannot read (a permission) is treated as absent; the
        // write, or the printed command, says the rest.
        Err(Refusal::Io(_)) => None,
        Err(e) => return Err(e),
    };
    let (text, append, current) = match managed.format {
        ManagedFormat::JsonSettings => {
            let text = super::install_text(existing.as_deref(), m, env.os, &program)?;
            let current = existing.as_deref() == Some(text.as_str());
            (text, false, current)
        }
        ManagedFormat::TomlRequirements => {
            let block = codex_block(&entries(m, &program));
            match &existing {
                Some(t) if t.contains("vahta-hook") => (t.clone(), false, true),
                Some(_) => (
                    format!(
                        "\n# Vahta (vahta setup --managed): the hooks, and the feature pin that\n\
                         # keeps users from switching hooks off.\n\
                         # If [features] already exists in this file, put `hooks = true` there.\n\
                         [features]\nhooks = true\n{block}"
                    ),
                    true,
                    false,
                ),
                None => (
                    format!("# Vahta (vahta setup --managed)\n[features]\nhooks = true\n{block}"),
                    false,
                    false,
                ),
            }
        }
    };
    Ok(Some(ManagedPlan {
        harness: m.name.clone(),
        title: m.title.clone(),
        path,
        text,
        append,
        current,
    }))
}

/// Write a managed plan. `PermissionDenied` is the unprivileged case; the
/// caller prints the command instead.
pub fn write_managed(p: &ManagedPlan) -> io::Result<()> {
    if let Some(dir) = p.path.parent() {
        fs::create_dir_all(dir)?;
    }
    if p.append {
        use std::io::Write;
        let mut f = fs::OpenOptions::new().append(true).open(&p.path)?;
        f.write_all(p.text.as_bytes())
    } else {
        write_atomic(&p.path, &p.text)
    }
}

/// The shell command that writes a managed plan with administrator rights,
/// for a person to run. Unix only; on Windows the caller says to use an
/// administrator prompt.
pub fn sudo_command(p: &ManagedPlan) -> String {
    let path = quote_word(&p.path.to_string_lossy(), Os::Linux);
    let dir = p
        .path
        .parent()
        .map(|d| quote_word(&d.to_string_lossy(), Os::Linux))
        .unwrap_or_default();
    let tee = if p.append { "tee -a" } else { "tee" };
    format!(
        "sudo mkdir -p {dir} && sudo {tee} {path} >/dev/null <<'VAHTA_EOF'\n{}VAHTA_EOF",
        if p.text.ends_with('\n') {
            p.text.clone()
        } else {
            format!("{}\n", p.text)
        }
    )
}
