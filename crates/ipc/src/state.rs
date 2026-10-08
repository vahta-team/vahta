//! `<data dir>/state.json`: what Vahta remembers between runs about asking the
//! person to turn the hook watchdog on.
//!
//! `guard_declines` counts the times `vahta setup` was answered "no" (or run
//! with `--guard off`), `guard_reminded_at` is when a SessionStart notice last
//! reminded them. The reminder is weekly; after three declines, monthly.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::paths::Paths;

const WEEK: u64 = 7 * 24 * 3600;
const MONTH: u64 = 30 * 24 * 3600;

/// Declines after which the reminder slows to monthly.
pub const MANY_DECLINES: u32 = 3;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub guard_declines: u32,
    /// Seconds since the Unix epoch; 0 is never.
    pub guard_reminded_at: u64,
}

pub fn state_file(paths: &Paths) -> PathBuf {
    paths.data.join("state.json")
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl State {
    /// An unreadable or absent file is the empty state.
    pub fn load(path: &Path) -> State {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
        let text = serde_json::to_string_pretty(self).map_err(io::Error::other)?;
        std::fs::write(&tmp, text + "\n")?;
        std::fs::rename(&tmp, path).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
    }

    /// Whether a reminder is due at `now`.
    pub fn reminder_due(&self, now: u64) -> bool {
        let every = if self.guard_declines >= MANY_DECLINES {
            MONTH
        } else {
            WEEK
        };
        self.guard_reminded_at == 0 || now.saturating_sub(self.guard_reminded_at) >= every
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weekly_then_monthly_after_three_declines() {
        let mut s = State::default();
        assert!(s.reminder_due(1000));
        s.guard_reminded_at = 1000;
        assert!(!s.reminder_due(1000 + WEEK - 1));
        assert!(s.reminder_due(1000 + WEEK));
        s.guard_declines = 3;
        assert!(!s.reminder_due(1000 + WEEK));
        assert!(s.reminder_due(1000 + MONTH));
    }

    #[test]
    fn a_state_round_trips_and_garbage_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("d/state.json");
        assert_eq!(State::load(&p), State::default());
        let s = State {
            guard_declines: 2,
            guard_reminded_at: 5,
        };
        s.save(&p).unwrap();
        assert_eq!(State::load(&p), s);
        std::fs::write(&p, "{{{").unwrap();
        assert_eq!(State::load(&p), State::default());
    }
}
