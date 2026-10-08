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
//! guard = "on"             # or "off": the hook watchdog (see docs/daemon.md); unset until asked
//! ```
//!
//! A missing file is the defaults. A file that does not parse, or carries a key
//! this build does not know, is an error: a typo in `lock_on_sleep` must not
//! quietly leave sessions open across a suspend.

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
    /// The person's answer about the hook watchdog; `None` until `vahta setup`
    /// has asked.
    pub guard: Option<Guard>,
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
            guard: None,
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
        Ok(cfg)
    }
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
