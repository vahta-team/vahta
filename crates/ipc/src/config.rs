//! `<config dir>/vahta/config.toml`: the few things a person may set.
//!
//! ```toml
//! session_minutes = 30     # how long `vahta unlock` lasts by default
//! lock_on_sleep = true     # end every session on suspend and screen lock
//! lock_sources = ["logind"]  # which triggers end sessions; unset means all
//! terminal = "kitty"       # the terminal the prompt window opens in (Linux)
//! idle_minutes = 10        # the daemon exits after this long with nothing to do
//! hook_output = "redact"   # or "observe": the hook only reports secrets in tool output
//! alarm = "warn"           # or "lock": what an agent that looks injected gets
//! hook_tool = "block"      # or "observe": the hook lets a secret in a tool call through and reports it
//! guard = "on"             # or "off": the hook watchdog (see docs/daemon.md); unset until asked
//! unlock = "last"          # the current unlock method: "last", "password" or "device:NAME"
//!
//! [unlock_vault]           # the same, for one vault (its id in hex), over the line above
//! 5f0c2d6a9e1b4c37a8d2e4f6b1c3a5d7 = "device:phone"
//! ```
//!
//! A missing file is the defaults. A file that does not parse, or carries a key
//! this build does not know, is an error: a typo in `lock_on_sleep` must not
//! quietly leave sessions open across a suspend.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub session_minutes: u64,
    pub lock_on_sleep: bool,
    /// Which lock sources (see `lock/`) may end sessions, by name. Unset means
    /// every source this build has; an empty list means none. A name this build
    /// does not know is journalled and ignored when the daemon starts, not an
    /// error here: the same file may serve builds with different sources.
    pub lock_sources: Option<Vec<String>>,
    /// A terminal command prefix, as ka's `terminal` key: the program and the
    /// flag that makes it run the rest of the command line (`alacritty -e`).
    /// Empty means detect one.
    pub terminal: String,
    pub idle_minutes: u64,
    pub hook_output: HookOutput,
    pub alarm: AlarmAction,
    pub hook_tool: HookTool,
    /// The person's answer about the hook watchdog; `None` until `vahta setup`
    /// has asked.
    pub guard: Option<Guard>,
    /// Which unlock method is tried first, for every vault without its own
    /// entry in `unlock_vault`. The master password is always the fallback.
    pub unlock: UnlockSetting,
    /// Per-vault override of `unlock`, keyed by the vault id in lowercase hex.
    pub unlock_vault: BTreeMap<String, UnlockSetting>,
}

/// The current unlock method. Orders the methods, never removes one: the
/// master password opens the vault whatever this says.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(try_from = "String")]
pub enum UnlockSetting {
    /// The method enrolled last (the default).
    #[default]
    Last,
    Password,
    /// A paired device, by name or by the start of its id.
    Device(String),
}

impl UnlockSetting {
    /// `last`, `password` or `device:<name or id>`.
    pub fn parse(text: &str) -> Option<UnlockSetting> {
        match text.trim() {
            "last" => Some(UnlockSetting::Last),
            "password" => Some(UnlockSetting::Password),
            t => {
                let name = t.strip_prefix("device:")?.trim();
                let ok = !name.is_empty()
                    && name.len() <= 64
                    && !name
                        .chars()
                        .any(|c| c.is_control() || c == '"' || c == '\\');
                ok.then(|| UnlockSetting::Device(name.to_string()))
            }
        }
    }

    pub fn as_text(&self) -> String {
        match self {
            UnlockSetting::Last => "last".into(),
            UnlockSetting::Password => "password".into(),
            UnlockSetting::Device(d) => format!("device:{d}"),
        }
    }
}

impl TryFrom<String> for UnlockSetting {
    type Error = String;

    fn try_from(text: String) -> Result<UnlockSetting, String> {
        UnlockSetting::parse(&text).ok_or_else(|| {
            format!("unlock must be \"last\", \"password\" or \"device:NAME\", not {text:?}")
        })
    }
}

impl Config {
    /// The setting for the vault whose id is `vault_id_hex`: its own entry,
    /// else the global one.
    pub fn unlock_for(&self, vault_id_hex: &str) -> &UnlockSetting {
        self.unlock_vault.get(vault_id_hex).unwrap_or(&self.unlock)
    }
}

/// Whether the hook watchdog runs, and starts at login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Guard {
    On,
    Off,
}

impl Guard {
    pub fn as_str(self) -> &'static str {
        match self {
            Guard::On => "on",
            Guard::Off => "off",
        }
    }
}

/// What the hook does with a secret in a tool's output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookOutput {
    /// Cut it out before the model sees it (the default).
    #[default]
    Redact,
    /// Change nothing: tell the person and the model, as before redaction,
    /// and have the daemon journal what was seen. For trying Vahta out, or for
    /// a harness whose other hooks also rewrite output.
    Observe,
}

/// What the hook does with a secret in a tool call, before the tool runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookTool {
    /// Refuse the call (the default).
    #[default]
    Block,
    /// Let the call through and tell the daemon what it carried. For trying
    /// Vahta out. A value hidden by base64, hex or joined pieces, and the
    /// commands and files Vahta guards for itself, are refused either way.
    Observe,
}

/// What the daemon does when an agent's behaviour scores past the injection
/// alarm's threshold (see the daemon's `alarm.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlarmAction {
    /// Ask the person in a window: lock every session, or ignore this agent
    /// session (the default). With no window to ask in, it locks.
    #[default]
    Warn,
    /// End every session at once, and tell the person.
    Lock,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            session_minutes: 30,
            lock_on_sleep: true,
            lock_sources: None,
            terminal: String::new(),
            idle_minutes: 10,
            hook_output: HookOutput::Redact,
            alarm: AlarmAction::Warn,
            hook_tool: HookTool::Block,
            guard: None,
            unlock: UnlockSetting::Last,
            unlock_vault: BTreeMap::new(),
        }
    }
}

/// Write `guard = "<g>"` into the config file, keeping everything else in it
/// (comments included): an existing `guard` line is replaced, else a line is
/// added. Atomic; creates the file and its directory if need be.
pub fn set_guard(path: &Path, g: Guard) -> std::io::Result<()> {
    let old = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    let line = format!("guard = \"{}\"", g.as_str());
    let mut out = String::new();
    let mut done = false;
    let mut top_level = true;
    for l in old.split_inclusive('\n') {
        let bare = l.trim_start();
        if bare.starts_with('[') {
            top_level = false;
        }
        let is_guard = top_level
            && bare
                .strip_prefix("guard")
                .is_some_and(|r| r.trim_start().starts_with('='));
        if is_guard && !done {
            out.push_str(&line);
            out.push('\n');
            done = true;
        } else if !is_guard {
            out.push_str(l);
        }
    }
    if !done {
        // Top-level keys must come before any table.
        let first_table = out
            .lines()
            .scan(0usize, |pos, l| {
                let at = *pos;
                *pos += l.len() + 1;
                Some((at, l))
            })
            .find(|(_, l)| l.trim_start().starts_with('['))
            .map(|(at, _)| at);
        match first_table {
            Some(at) => out.insert_str(at, &format!("{line}\n")),
            None => {
                if !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(&line);
                out.push('\n');
            }
        }
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&tmp, out)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Remove the `guard` line, so the next `vahta setup` asks again.
pub fn clear_guard(path: &Path) -> std::io::Result<()> {
    let old = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let mut top_level = true;
    let kept: String = old
        .split_inclusive('\n')
        .filter(|l| {
            let bare = l.trim_start();
            if bare.starts_with('[') {
                top_level = false;
            }
            !(top_level
                && bare
                    .strip_prefix("guard")
                    .is_some_and(|r| r.trim_start().starts_with('=')))
        })
        .collect();
    if kept == old {
        return Ok(());
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&tmp, kept)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

#[derive(Debug)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// The largest config read; a few lines of settings.
const MAX_CONFIG: u64 = 64 * 1024;

impl Config {
    /// Read the file at `path`; absent is the defaults.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let shown = path.display();
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(e) => return Err(ConfigError(format!("cannot read {shown}: {e}"))),
        };
        if meta.len() > MAX_CONFIG {
            return Err(ConfigError(format!("{shown} is too large")));
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError(format!("cannot read {shown}: {e}")))?;
        Config::parse(&text).map_err(|e| ConfigError(format!("{e} in {shown}")))
    }

    pub fn parse(text: &str) -> Result<Config, ConfigError> {
        let cfg: Config = toml::from_str(text)
            .map_err(|e| ConfigError(format!("invalid config ({})", e.message())))?;
        if cfg.session_minutes == 0 || cfg.session_minutes > 24 * 60 * 365 {
            return Err(ConfigError(
                "session_minutes must be between 1 and 525600".to_string(),
            ));
        }
        if cfg.idle_minutes == 0 || cfg.idle_minutes > 24 * 60 {
            return Err(ConfigError(
                "idle_minutes must be between 1 and 1440".to_string(),
            ));
        }
        if let Some(bad) = cfg
            .unlock_vault
            .keys()
            .find(|k| k.len() != 32 || !k.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        {
            return Err(ConfigError(format!(
                "unlock_vault: {bad:?} is not a vault id (32 lowercase hex characters)"
            )));
        }
        Ok(cfg)
    }
}

/// Set (`Some`) or remove (`None`) the unlock setting, keeping everything else
/// in the file, comments included. With `vault_id_hex` it is that vault's entry
/// in the `[unlock_vault]` table, else the top-level `unlock` line. Atomic;
/// creates the file and its directory if need be.
pub fn set_unlock(
    path: &Path,
    vault_id_hex: Option<&str>,
    setting: Option<&UnlockSetting>,
) -> std::io::Result<()> {
    let old = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    let out = match vault_id_hex {
        None => edit_top_level(&old, "unlock", setting.map(UnlockSetting::as_text)),
        Some(id) => edit_table_entry(
            &old,
            "unlock_vault",
            id,
            setting.map(UnlockSetting::as_text),
        ),
    };
    if out == old {
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&tmp, out)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

fn is_key_line(line: &str, key: &str) -> bool {
    line.trim_start()
        .strip_prefix(key)
        .is_some_and(|r| r.trim_start().starts_with('='))
}

/// `key = "value"` set or removed among the top-level lines of `text`.
fn edit_top_level(text: &str, key: &str, value: Option<String>) -> String {
    let line = value.map(|v| format!("{key} = \"{v}\"\n"));
    let mut out = String::new();
    let mut done = false;
    let mut top_level = true;
    for l in text.split_inclusive('\n') {
        if l.trim_start().starts_with('[') {
            top_level = false;
        }
        if top_level && is_key_line(l, key) {
            if let (Some(new), false) = (&line, done) {
                out.push_str(new);
                done = true;
            }
        } else {
            if !top_level && !done && line.is_some() {
                // Top-level keys come before the first table.
                out.push_str(line.as_deref().unwrap_or_default());
                done = true;
            }
            out.push_str(l);
        }
    }
    if !done && let Some(new) = &line {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(new);
    }
    out
}

/// `key = "value"` set or removed inside `[table]`. The table is added at the
/// end when there is none; it is left, empty, when its last entry goes.
fn edit_table_entry(text: &str, table: &str, key: &str, value: Option<String>) -> String {
    let line = value.map(|v| format!("{key} = \"{v}\"\n"));
    let header = format!("[{table}]");
    let mut out = String::new();
    let (mut inside, mut found_table, mut done) = (false, false, false);
    let flush = |out: &mut String, inside: bool, done: &mut bool| {
        if inside
            && !*done
            && let Some(new) = &line
        {
            if !out.ends_with('\n') && !out.is_empty() {
                out.push('\n');
            }
            out.push_str(new);
            *done = true;
        }
    };
    for l in text.split_inclusive('\n') {
        let bare = l.trim();
        if bare.starts_with('[') {
            flush(&mut out, inside, &mut done);
            inside = bare == header;
            found_table |= inside;
            out.push_str(l);
            if inside && !l.ends_with('\n') {
                out.push('\n');
            }
            continue;
        }
        if inside && is_key_line(l, key) {
            if let (Some(new), false) = (&line, done) {
                out.push_str(new);
                done = true;
            }
            continue;
        }
        out.push_str(l);
    }
    flush(&mut out, inside, &mut done);
    if !found_table && let Some(new) = &line {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&header);
        out.push('\n');
        out.push_str(new);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_overrides() {
        assert_eq!(Config::parse("").unwrap(), Config::default());
        let c = Config::parse("session_minutes = 5\nlock_on_sleep = false\nterminal = \"foot\"\n")
            .unwrap();
        assert_eq!(c.session_minutes, 5);
        assert!(!c.lock_on_sleep);
        assert_eq!(c.terminal, "foot");
        assert_eq!(c.idle_minutes, 10);
        assert_eq!(c.hook_output, HookOutput::Redact);
        let c = Config::parse("hook_output = \"observe\"\n").unwrap();
        assert_eq!(c.hook_output, HookOutput::Observe);
        assert_eq!(c.alarm, AlarmAction::Warn);
        let c = Config::parse("alarm = \"lock\"\n").unwrap();
        assert_eq!(c.alarm, AlarmAction::Lock);
        assert_eq!(c.hook_tool, HookTool::Block);
        let c = Config::parse("hook_tool = \"observe\"\n").unwrap();
        assert_eq!(c.hook_tool, HookTool::Observe);
    }

    #[test]
    fn the_unlock_setting_is_global_with_a_per_vault_override() {
        let c = Config::default();
        assert_eq!(*c.unlock_for("ab"), UnlockSetting::Last);
        let id = "5f0c2d6a9e1b4c37a8d2e4f6b1c3a5d7";
        let c = Config::parse(&format!(
            "unlock = \"password\"\n[unlock_vault]\n{id} = \"device:my phone\"\n"
        ))
        .unwrap();
        assert_eq!(*c.unlock_for(id), UnlockSetting::Device("my phone".into()));
        assert_eq!(*c.unlock_for("other"), UnlockSetting::Password);
        for bad in [
            "unlock = \"phone\"\n",
            "unlock = \"device:\"\n",
            "unlock = 3\n",
            "[unlock_vault]\nnot-hex = \"last\"\n",
            "[unlock_vault]\n5f0c2d6a9e1b4c37a8d2e4f6b1c3a5d7 = \"fast\"\n",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(
            UnlockSetting::parse("device:x").unwrap().as_text(),
            "device:x"
        );
    }

    #[test]
    fn set_unlock_edits_one_line_and_keeps_the_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("c/config.toml");
        let id = "5f0c2d6a9e1b4c37a8d2e4f6b1c3a5d7";
        set_unlock(&path, None, Some(&UnlockSetting::Password)).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "unlock = \"password\"\n"
        );
        std::fs::write(&path, "# mine\nterminal = \"foot\"\n[x]\na = 1\n").unwrap();
        set_unlock(&path, None, Some(&UnlockSetting::Last)).unwrap();
        set_unlock(
            &path,
            Some(id),
            Some(&UnlockSetting::Device("phone".into())),
        )
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text,
            format!(
                "# mine\nterminal = \"foot\"\nunlock = \"last\"\n[x]\na = 1\n\n[unlock_vault]\n{id} = \"device:phone\"\n"
            )
        );
        // The same edit in a file that parses as a whole.
        let plain = tmp.path().join("plain.toml");
        set_unlock(
            &plain,
            Some(id),
            Some(&UnlockSetting::Device("phone".into())),
        )
        .unwrap();
        assert_eq!(
            *Config::load(&plain).unwrap().unlock_for(id),
            UnlockSetting::Device("phone".into())
        );
        // Changing it again replaces the line; removing it removes it.
        set_unlock(&path, Some(id), Some(&UnlockSetting::Password)).unwrap();
        set_unlock(&path, None, Some(&UnlockSetting::Password)).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches(id).count(), 1);
        assert_eq!(text.matches("unlock = ").count(), 1);
        set_unlock(&path, Some(id), None).unwrap();
        set_unlock(&path, None, None).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(id) && !text.contains("unlock = "));
        assert!(text.contains("# mine") && text.contains("[x]"));
    }

    #[test]
    fn lock_sources_unset_named_or_empty() {
        assert_eq!(Config::parse("").unwrap().lock_sources, None);
        let c = Config::parse("lock_sources = [\"logind\", \"nope\"]\n").unwrap();
        assert_eq!(c.lock_sources, Some(vec!["logind".into(), "nope".into()]));
        let c = Config::parse("lock_sources = []\n").unwrap();
        assert_eq!(c.lock_sources, Some(Vec::new()));
        assert!(Config::parse("lock_sources = \"logind\"\n").is_err());
    }

    #[test]
    fn what_it_cannot_trust_is_refused() {
        for bad in [
            "lock_on_slepe = true\n",
            "session_minutes = \"soon\"\n",
            "session_minutes = 0\n",
            "idle_minutes = 0\n",
            "hook_output = \"off\"\n",
            "alarm = \"loud\"\n",
            "hook_tool = \"off\"\n",
            "= broken",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn guard_is_unset_until_asked_and_set_guard_keeps_the_rest() {
        assert_eq!(Config::parse("").unwrap().guard, None);
        assert_eq!(
            Config::parse("guard = \"on\"\n").unwrap().guard,
            Some(Guard::On)
        );
        assert!(Config::parse("guard = \"maybe\"\n").is_err());
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("c/config.toml");
        set_guard(&path, Guard::On).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "guard = \"on\"\n");
        std::fs::write(&path, "# mine\nterminal = \"foot\"\n[x]\na = 1\n").unwrap();
        set_guard(&path, Guard::Off).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "# mine\nterminal = \"foot\"\nguard = \"off\"\n[x]\na = 1\n"
        );
        set_guard(&path, Guard::On).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches("guard").count(), 1);
        assert!(text.contains("guard = \"on\""));
    }

    #[test]
    fn a_missing_file_is_the_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            Config::load(&tmp.path().join("config.toml")).unwrap(),
            Config::default()
        );
    }
}
