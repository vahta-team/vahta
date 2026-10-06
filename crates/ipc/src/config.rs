//! `<config dir>/vahta/config.toml`: the few things a person may set.
//!
//! ```toml
//! session_minutes = 30     # how long `vahta unlock` lasts by default
//! lock_on_sleep = true     # end every session on suspend and screen lock
//! terminal = "kitty"       # the terminal the prompt window opens in (Linux)
//! idle_minutes = 10        # the daemon exits after this long with nothing to do
//! hook_output = "redact"   # or "observe": the hook only reports secrets in tool output
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
    /// A terminal command prefix, as ka's `terminal` key: the program and the
    /// flag that makes it run the rest of the command line (`alacritty -e`).
    /// Empty means detect one.
    pub terminal: String,
    pub idle_minutes: u64,
    pub hook_output: HookOutput,
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

impl Default for Config {
    fn default() -> Config {
        Config {
            session_minutes: 30,
            lock_on_sleep: true,
            terminal: String::new(),
            idle_minutes: 10,
            hook_output: HookOutput::Redact,
        }
    }
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
    }

    #[test]
    fn what_it_cannot_trust_is_refused() {
        for bad in [
            "lock_on_slepe = true\n",
            "session_minutes = \"soon\"\n",
            "session_minutes = 0\n",
            "idle_minutes = 0\n",
            "hook_output = \"off\"\n",
            "= broken",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
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
