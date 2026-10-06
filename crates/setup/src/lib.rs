//! What `vahta setup` does, as pure logic over an explicit [`Env`].
//!
//! Nothing here reads the process environment: the home directory, variables,
//! `PATH`, the OS and the hook binary's path are all handed in, so every case
//! can be driven against a temporary directory. The only I/O is the config file
//! itself ([`plan`] reads it, [`commit`] writes it) and the existence checks of
//! detection.
//!
//! The rules, in one place:
//!
//! * A hook command is **ours** when its program's basename (unquoted, `.exe`
//!   stripped) is `vahta-hook`. Anything else, including key-amnesia's
//!   `key-amnesia-hook`, is foreign and is never touched or reordered.
//! * Install removes every entry of ours, then appends the fresh ones **last**
//!   in each event array (Claude's PostToolUse rewrites are last-registered-
//!   wins). So running it twice gives the same file.
//! * A config that exists but is not a JSON object is refused, never clobbered.
//! * "Current" is content equality with what this binary would write now, not a
//!   comparison of version numbers.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use vahta_harness::{Manifest, Shape};

/// The three operating systems the manifests have paths for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Linux,
    Macos,
    Windows,
}

impl Os {
    /// The OS this binary was built for.
    pub fn current() -> Os {
        if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::Macos
        } else {
            Os::Linux
        }
    }
}

/// Everything setup takes from its surroundings.
#[derive(Clone, Debug)]
pub struct Env {
    pub home: PathBuf,
    /// Environment variables that `$VAR` in a manifest may name.
    pub vars: BTreeMap<String, String>,
    /// The directories of `PATH`, in order.
    pub path: Vec<PathBuf>,
    pub os: Os,
    /// The `vahta-hook` binary setup would register (it need not exist).
    pub hook: PathBuf,
}

// --- paths and detection ------------------------------------------------------

/// `~`, `~/x`, `$VAR`, `$VAR/x` or a plain path. `None` when a variable is
/// unset or empty.
fn expand(template: &str, env: &Env) -> Option<PathBuf> {
    let join = |base: PathBuf, tail: &str| {
        let tail = tail.trim_start_matches('/');
        if tail.is_empty() {
            base
        } else {
            base.join(tail)
        }
    };
    if template == "~" || template.starts_with("~/") {
        return Some(join(env.home.clone(), &template[1..]));
    }
    if let Some(rest) = template.strip_prefix('$') {
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let (name, tail) = rest.split_at(end);
        let value = env.vars.get(name).filter(|v| !v.is_empty())?;
        return Some(join(PathBuf::from(value), tail));
    }
    Some(PathBuf::from(template))
}

/// The user-scope config file: the first candidate whose variables are set.
pub fn config_path(m: &Manifest, env: &Env) -> Option<PathBuf> {
    let candidates = match env.os {
        Os::Linux => &m.config.path.linux,
        Os::Macos => &m.config.path.macos,
        Os::Windows => &m.config.path.windows,
    };
    candidates.iter().find_map(|t| expand(t, env))
}

/// Whether the harness looks installed, and what said so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    pub found: bool,
    /// The rules that matched; when nothing matched, the rules that were tried.
    pub why: String,
}

fn on_path(name: &str, env: &Env) -> Option<PathBuf> {
    let names: Vec<String> = if env.os == Os::Windows {
        ["exe", "cmd", "bat", "com"]
            .iter()
            .map(|e| format!("{name}.{e}"))
            .collect()
    } else {
        vec![name.to_string()]
    };
    env.path
        .iter()
        .flat_map(|dir| names.iter().map(move |n| dir.join(n)))
        .find(|p| p.is_file())
}

pub fn detect(m: &Manifest, env: &Env) -> Detection {
    let mut hits = Vec::new();
    let mut tried = Vec::new();
    for t in &m.detect.dirs {
        match expand(t, env) {
            Some(p) if p.is_dir() => hits.push(format!("directory {}", p.display())),
            Some(p) => tried.push(format!("no directory {}", p.display())),
            None => {}
        }
    }
    for b in &m.detect.binaries {
        match on_path(b, env) {
            Some(p) => hits.push(format!("`{b}` on PATH ({})", p.display())),
            None => tried.push(format!("no `{b}` on PATH")),
        }
    }
    if hits.is_empty() {
        Detection {
            found: false,
            why: tried.join(", "),
        }
    } else {
        Detection {
            found: true,
            why: hits.join(", "),
        }
    }
}

// --- our command line ------------------------------------------------------------

/// Quote one path for a command line, only when it needs it.
pub fn quote_word(path: &str, os: Os) -> String {
    if os == Os::Windows {
        let plain = |c: char| c.is_ascii_alphanumeric() || "_./\\:@+=,-".contains(c);
        if path.chars().all(plain) {
            path.to_string()
        } else {
            format!("\"{path}\"")
        }
    } else {
        let plain = |c: char| c.is_ascii_alphanumeric() || "_./:@%+=,-".contains(c);
        if !path.is_empty() && path.chars().all(plain) {
            path.to_string()
        } else {
            format!("'{}'", path.replace('\'', "'\\''"))
        }
    }
}

/// The first word of a command line, unquoted. Backslash is an escape only off
/// Windows, where it is a path separator.
fn first_word(command: &str, os: Os) -> Option<String> {
    let mut out = String::new();
    let mut chars = command.trim_start().chars();
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        match (quote, c) {
            (None, c) if c.is_whitespace() => break,
            (None, '\'') | (None, '"') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') if os != Os::Windows => match chars.next() {
                Some(n @ ('"' | '\\')) => out.push(n),
                Some(n) => {
                    out.push('\\');
                    out.push(n);
                }
                None => out.push('\\'),
            },
            (None, '\\') if os != Os::Windows => out.extend(chars.next()),
            (_, c) => out.push(c),
        }
    }
    (!out.is_empty()).then_some(out)
}

fn is_ours_word(word: &str) -> bool {
    let base = word.rsplit(['/', '\\']).next().unwrap_or(word);
    let stem = match base.len().checked_sub(4) {
        Some(i) if base.is_char_boundary(i) && base[i..].eq_ignore_ascii_case(".exe") => &base[..i],
        _ => base,
    };
    stem == "vahta-hook"
}

/// A command with its program word cut off: what remains are our arguments.
fn arguments(command: &str, os: Os) -> String {
    let rest = command.trim_start();
    let mut quote: Option<char> = None;
    let mut chars = rest.char_indices();
    while let Some((i, c)) = chars.next() {
        match (quote, c) {
            (None, c) if c.is_whitespace() => return rest[i..].trim().to_string(),
            (None, '\'') | (None, '"') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (_, '\\') if os != Os::Windows && quote != Some('\'') => {
                chars.next();
            }
            _ => {}
        }
    }
    String::new()
}

/// The program of one of our commands, or `None` for a foreign command.
fn our_program(command: &str, os: Os) -> Option<String> {
    first_word(command, os).filter(|w| is_ours_word(w))
}

/// Whether a hook command belongs to us.
pub fn is_ours(command: &str, os: Os) -> bool {
    our_program(command, os).is_some()
}

// --- what we write ---------------------------------------------------------------------

/// One registration: the event, its matcher and the command.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    pub event: String,
    pub matcher: Option<String>,
    pub command: String,
}

/// The entries for a harness, one per `[[events]]` item. `program` is the hook
/// path already quoted for the command line.
fn entries(m: &Manifest, program: &str) -> Vec<Entry> {
    m.events
        .iter()
        .map(|e| Entry {
            event: e.name.clone(),
            matcher: e.matcher.clone(),
            command: format!(
                "{program} --harness {} --event {} --setup {}",
                m.name,
                e.kind.as_str(),
                m.setup_version
            ),
        })
        .collect()
}

fn entry_json(e: &Entry, shape: Shape) -> Value {
    let mut o = Map::new();
    match shape {
        Shape::Grouped => {
            if let Some(m) = &e.matcher {
                o.insert("matcher".into(), m.clone().into());
            }
            let mut h = Map::new();
            h.insert("type".into(), "command".into());
            h.insert("command".into(), e.command.clone().into());
            o.insert("hooks".into(), Value::Array(vec![Value::Object(h)]));
        }
        Shape::Flat => {
            o.insert("command".into(), e.command.clone().into());
            if let Some(m) = &e.matcher {
                o.insert("matcher".into(), m.clone().into());
            }
        }
    }
    Value::Object(o)
}

/// Why setup will not touch a file, or cannot proceed.
#[derive(Debug)]
pub enum Refusal {
    /// The file exists but is not valid JSON (or not UTF-8).
    InvalidJson(String),
    NotAnObject,
    /// A part of the file has a type we cannot merge into.
    Shape(String),
    /// The file's `version` is not the one the harness requires.
    Version {
        key: String,
        want: i64,
    },
    HookPathNotUtf8,
    NoConfigPath,
    Io(io::Error),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::InvalidJson(e) => write!(f, "is not valid JSON ({e}); fix or remove it first"),
            Refusal::NotAnObject => write!(f, "does not hold a JSON object at the top level"),
            Refusal::Shape(s) => write!(f, "{s}"),
            Refusal::Version { key, want } => {
                write!(
                    f,
                    "has a \"{key}\" other than {want}, which this setup does not know"
                )
            }
            Refusal::HookPathNotUtf8 => write!(f, "the hook path is not valid UTF-8"),
            Refusal::NoConfigPath => write!(f, "cannot work out where its config lives"),
            Refusal::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<io::Error> for Refusal {
    fn from(e: io::Error) -> Refusal {
        Refusal::Io(e)
    }
}

fn parse(text: Option<&str>) -> Result<Map<String, Value>, Refusal> {
    let Some(text) = text else {
        return Ok(Map::new());
    };
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(o)) => Ok(o),
        Ok(_) => Err(Refusal::NotAnObject),
        Err(e) => Err(Refusal::InvalidJson(e.to_string())),
    }
}

fn render(doc: Map<String, Value>) -> String {
    let mut s = serde_json::to_string_pretty(&Value::Object(doc)).unwrap_or_default();
    s.push('\n');
    s
}

fn command_of(v: &Value) -> Option<&str> {
    v.get("command").and_then(Value::as_str)
}

/// Remove every command of ours. Returns how many were removed and the events
/// whose array that emptied.
fn strip(
    doc: &mut Map<String, Value>,
    shape: Shape,
    os: Os,
) -> Result<(usize, Vec<String>), Refusal> {
    let Some(hooks) = doc.get_mut("hooks") else {
        return Ok((0, Vec::new()));
    };
    let Value::Object(hooks) = hooks else {
        return Err(Refusal::Shape("\"hooks\" is not an object".into()));
    };
    let mut removed = 0;
    let mut emptied = Vec::new();
    for (event, arr) in hooks.iter_mut() {
        // A foreign event of an odd type is none of our business.
        let Value::Array(arr) = arr else { continue };
        let mut here = 0;
        let mut kept = Vec::with_capacity(arr.len());
        for mut entry in std::mem::take(arr) {
            match shape {
                Shape::Flat => {
                    if command_of(&entry).is_some_and(|c| is_ours(c, os)) {
                        here += 1;
                        continue;
                    }
                }
                Shape::Grouped => {
                    if let Some(Value::Array(items)) = entry.get_mut("hooks") {
                        let before = items.len();
                        items.retain(|i| !command_of(i).is_some_and(|c| is_ours(c, os)));
                        let gone = before - items.len();
                        here += gone;
                        // A group we emptied goes; one that was empty already stays.
                        if gone > 0 && items.is_empty() {
                            continue;
                        }
                    }
                }
            }
            kept.push(entry);
        }
        *arr = kept;
        removed += here;
        if here > 0 && arr.is_empty() {
            emptied.push(event.clone());
        }
    }
    Ok((removed, emptied))
}

// --- deny rules ----------------------------------------------------------------------------

/// The list at the dotted `key`, if it is there. A part of the path that is not
/// an object, or a list that is not an array, is refused.
fn deny_list<'a>(
    doc: &'a mut Map<String, Value>,
    key: &str,
    create: bool,
) -> Result<Option<&'a mut Vec<Value>>, Refusal> {
    let mut parts: Vec<&str> = key.split('.').collect();
    let last = parts.pop().unwrap_or(key);
    let mut obj = doc;
    let mut at = String::new();
    for part in parts {
        if !at.is_empty() {
            at.push('.');
        }
        at.push_str(part);
        if !obj.contains_key(part) {
            if !create {
                return Ok(None);
            }
            obj.insert(part.to_string(), Value::Object(Map::new()));
        }
        match obj.get_mut(part) {
            Some(Value::Object(o)) => obj = o,
            _ => return Err(Refusal::Shape(format!("\"{at}\" is not an object"))),
        }
    }
    if !obj.contains_key(last) {
        if !create {
            return Ok(None);
        }
        obj.insert(last.to_string(), Value::Array(Vec::new()));
    }
    match obj.get_mut(last) {
        Some(Value::Array(a)) => Ok(Some(a)),
        _ => Err(Refusal::Shape(format!("\"{key}\" is not a list"))),
    }
}

/// Remove our deny rules. Returns how many were removed; a list (and an object
/// above it) that only that emptied is removed too.
fn strip_deny(doc: &mut Map<String, Value>, m: &Manifest) -> Result<usize, Refusal> {
    let Some(d) = &m.config.deny else {
        return Ok(0);
    };
    let Some(list) = deny_list(doc, &d.key, false)? else {
        return Ok(0);
    };
    let before = list.len();
    list.retain(|v| !v.as_str().is_some_and(|s| d.rules.iter().any(|r| r == s)));
    let removed = before - list.len();
    if removed > 0 && list.is_empty() {
        // `permissions.deny` -> remove `deny`, then `permissions` if empty.
        let parts: Vec<&str> = d.key.split('.').collect();
        for depth in (1..=parts.len()).rev() {
            let (path, leaf) = parts[..depth].split_at(depth - 1);
            let mut obj = &mut *doc;
            for p in path {
                match obj.get_mut(*p) {
                    Some(Value::Object(o)) => obj = o,
                    _ => return Ok(removed),
                }
            }
            let empty = match obj.get(leaf[0]) {
                Some(Value::Array(a)) => a.is_empty(),
                Some(Value::Object(o)) => o.is_empty(),
                _ => false,
            };
            if !empty {
                break;
            }
            obj.shift_remove(leaf[0]);
        }
    }
    Ok(removed)
}

/// Whether every deny rule of ours is in the config.
fn deny_present(doc: &mut Map<String, Value>, m: &Manifest) -> bool {
    let Some(d) = &m.config.deny else {
        return true;
    };
    match deny_list(doc, &d.key, false) {
        Ok(Some(list)) => d
            .rules
            .iter()
            .all(|r| list.iter().any(|v| v.as_str() == Some(r.as_str()))),
        _ => false,
    }
}

/// The config text after installing `program` into `before` (`None` = no file).
pub fn install_text(
    before: Option<&str>,
    m: &Manifest,
    os: Os,
    program: &str,
) -> Result<String, Refusal> {
    let mut doc = parse(before)?;
    if let Some(req) = &m.config.require {
        match doc.get(&req.key) {
            None => {
                doc.insert(req.key.clone(), req.value.into());
            }
            Some(v) if v.as_i64() == Some(req.value) => {}
            Some(_) => {
                return Err(Refusal::Version {
                    key: req.key.clone(),
                    want: req.value,
                });
            }
        }
    }
    strip(&mut doc, m.config.shape, os)?;
    if let Some(d) = &m.config.deny
        && let Some(list) = deny_list(&mut doc, &d.key, true)?
    {
        // Ours go last, once each; the person's own rules keep their place.
        list.retain(|v| !v.as_str().is_some_and(|s| d.rules.iter().any(|r| r == s)));
        list.extend(d.rules.iter().cloned().map(Value::String));
    }
    if !doc.contains_key("hooks") {
        doc.insert("hooks".into(), Value::Object(Map::new()));
    }
    let Some(Value::Object(hooks)) = doc.get_mut("hooks") else {
        return Err(Refusal::Shape("\"hooks\" is not an object".into()));
    };
    for e in entries(m, program) {
        let slot = hooks
            .entry(e.event.clone())
            .or_insert_with(|| Value::Array(Vec::new()));
        match slot {
            Value::Array(arr) => arr.push(entry_json(&e, m.config.shape)),
            _ => {
                return Err(Refusal::Shape(format!(
                    "\"hooks.{}\" is not an array",
                    e.event
                )));
            }
        }
    }
    Ok(render(doc))
}

/// The config text after removing our entries; `None` when none were there.
pub fn uninstall_text(before: &str, m: &Manifest, os: Os) -> Result<Option<String>, Refusal> {
    let mut doc = parse(Some(before))?;
    let (removed, emptied) = strip(&mut doc, m.config.shape, os)?;
    let removed = removed + strip_deny(&mut doc, m)?;
    if removed == 0 {
        return Ok(None);
    }
    if let Some(Value::Object(hooks)) = doc.get_mut("hooks") {
        for event in &emptied {
            hooks.shift_remove(event);
        }
        // Only when our removal emptied it: an `{}` that was there stays.
        if hooks.is_empty() {
            doc.shift_remove("hooks");
        }
    }
    Ok(Some(render(doc)))
}

/// The document an install into an empty config writes, with `{hook}` standing
/// for the hook path. This is what the CI snapshot pins.
pub fn fragment(m: &Manifest) -> Value {
    let text = install_text(None, m, Os::Linux, "{hook}").unwrap_or_default();
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

// --- plan and commit ------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Install,
    Uninstall,
}

/// A change to one file, worked out but not yet made.
#[derive(Debug)]
pub struct Plan {
    /// The file to write (a symlink is followed, so the link itself survives).
    pub path: PathBuf,
    /// The file's text now, `None` if it does not exist.
    pub before: Option<String>,
    /// The text to write; `None` means there is nothing to do.
    pub after: Option<String>,
}

fn read_config(path: &Path) -> Result<Option<String>, Refusal> {
    match fs::read(path) {
        Ok(b) => String::from_utf8(b)
            .map(Some)
            .map_err(|_| Refusal::InvalidJson("not valid UTF-8".into())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Refusal::Io(e)),
    }
}

pub fn plan(m: &Manifest, env: &Env, action: Action) -> Result<Plan, Refusal> {
    let path = config_path(m, env).ok_or(Refusal::NoConfigPath)?;
    let path = dunce::canonicalize(&path).unwrap_or(path);
    let before = read_config(&path)?;
    let after = match action {
        Action::Install => {
            let hook = env.hook.to_str().ok_or(Refusal::HookPathNotUtf8)?;
            let text = install_text(before.as_deref(), m, env.os, &quote_word(hook, env.os))?;
            (before.as_deref() != Some(text.as_str())).then_some(text)
        }
        Action::Uninstall => match &before {
            Some(b) => uninstall_text(b, m, env.os)?,
            None => None,
        },
    };
    Ok(Plan {
        path,
        before,
        after,
    })
}

/// Write a plan: back the old file up to `<file>.vahta-backup`, write a temp
/// file beside it, copy the permissions, rename. The backup is made once, from
/// the file as it was before vahta first wrote it, and never overwritten: a
/// later run would otherwise replace the person's original with our own
/// intermediate version. Returns the backup's path when one was made now.
pub fn commit(plan: &Plan) -> io::Result<Option<PathBuf>> {
    let Some(after) = &plan.after else {
        return Ok(None);
    };
    let name = plan
        .path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if let Some(dir) = plan.path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut backup = None;
    let b = plan.path.with_file_name(format!("{name}.vahta-backup"));
    if plan.before.is_some() && fs::symlink_metadata(&b).is_err() {
        fs::copy(&plan.path, &b)?;
        backup = Some(b);
    }
    let tmp = plan
        .path
        .with_file_name(format!(".{name}.vahta-tmp-{}", std::process::id()));
    let result = (|| {
        fs::write(&tmp, after)?;
        if plan.before.is_some() {
            fs::set_permissions(&tmp, fs::metadata(&plan.path)?.permissions())?;
        }
        fs::rename(&tmp, &plan.path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map(|()| backup)
}

/// A unified diff of one file's change, for `--dry-run`.
pub fn unified_diff(path: &Path, before: Option<&str>, after: &str) -> String {
    let shown = path.display().to_string();
    let old = if before.is_some() {
        shown.clone()
    } else {
        "/dev/null".to_string()
    };
    similar::TextDiff::from_lines(before.unwrap_or(""), after)
        .unified_diff()
        .context_radius(3)
        .header(&old, &shown)
        .to_string()
}

// --- status -----------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// No entry of ours in the file (or no file).
    None,
    /// Ours match what this binary would write now, up to the hook's path.
    Current,
    /// Ours are there but differ from what this binary would write.
    Outdated,
    /// The file cannot be read as a config; the reason.
    Unreadable(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookProblem {
    /// An installed command's program does not exist.
    Missing(String),
    /// An installed command points somewhere other than `Env::hook`.
    Elsewhere(String),
}

#[derive(Clone, Debug)]
pub struct Inspect {
    pub config_path: Option<PathBuf>,
    pub state: State,
    pub problems: Vec<HookProblem>,
}

#[derive(Clone, Debug)]
pub struct Status {
    pub name: String,
    pub title: String,
    pub detection: Detection,
    pub inspect: Inspect,
}

/// The installed entries of ours, with the program word of each.
fn installed(doc: &Map<String, Value>, shape: Shape, os: Os) -> Vec<(Entry, String)> {
    let mut out = Vec::new();
    let Some(Value::Object(hooks)) = doc.get("hooks") else {
        return out;
    };
    for (event, arr) in hooks {
        let Value::Array(arr) = arr else { continue };
        for entry in arr {
            let matcher = entry
                .get("matcher")
                .and_then(Value::as_str)
                .map(String::from);
            let commands: Vec<&Value> = match shape {
                Shape::Flat => vec![entry],
                Shape::Grouped => match entry.get("hooks") {
                    Some(Value::Array(items)) => items.iter().collect(),
                    _ => Vec::new(),
                },
            };
            for item in commands {
                if let Some(c) = command_of(item)
                    && let Some(word) = our_program(c, os)
                {
                    out.push((
                        Entry {
                            event: event.clone(),
                            matcher: matcher.clone(),
                            command: c.into(),
                        },
                        word,
                    ));
                }
            }
        }
    }
    out
}

/// Read the config and say what is set up. Reads one file; cheap enough to run
/// on every command.
pub fn inspect(m: &Manifest, env: &Env) -> Inspect {
    let config_path = config_path(m, env);
    let unreadable = |config_path, why: String| Inspect {
        config_path,
        state: State::Unreadable(why),
        problems: Vec::new(),
    };
    let Some(path) = &config_path else {
        return Inspect {
            config_path,
            state: State::None,
            problems: Vec::new(),
        };
    };
    let text = match read_config(path) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return Inspect {
                config_path,
                state: State::None,
                problems: Vec::new(),
            };
        }
        Err(e) => return unreadable(config_path, e.to_string()),
    };
    let mut doc = match parse(Some(&text)) {
        Ok(d) => d,
        Err(e) => return unreadable(config_path, e.to_string()),
    };
    let have = installed(&doc, m.config.shape, env.os);
    if have.is_empty() {
        return Inspect {
            config_path,
            state: State::None,
            problems: Vec::new(),
        };
    }
    // Compared without the program path: a dev build and an installed `vahta`
    // must agree on whether the setup is current. Where the hook lives is
    // reported separately, as a problem below.
    let args_only = |e: &Entry| Entry {
        command: arguments(&e.command, env.os),
        ..e.clone()
    };
    let mut want: Vec<Entry> = entries(m, "vahta-hook").iter().map(args_only).collect();
    let mut got: Vec<Entry> = have.iter().map(|(e, _)| args_only(e)).collect();
    want.sort();
    got.sort();
    let state = if want == got && deny_present(&mut doc, m) {
        State::Current
    } else {
        State::Outdated
    };

    let mut problems = Vec::new();
    let here = env.hook.to_string_lossy();
    for (_, word) in &have {
        let missing = HookProblem::Missing(word.clone());
        let elsewhere = HookProblem::Elsewhere(word.clone());
        if !Path::new(word).exists() && !problems.contains(&missing) {
            problems.push(missing);
        }
        if word.as_str() != here && !problems.contains(&elsewhere) {
            problems.push(elsewhere);
        }
    }
    Inspect {
        config_path,
        state,
        problems,
    }
}

pub fn status(m: &Manifest, env: &Env) -> Status {
    Status {
        name: m.name.clone(),
        title: m.title.clone(),
        detection: detect(m, env),
        inspect: inspect(m, env),
    }
}
