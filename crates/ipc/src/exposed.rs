//! `<data dir>/exposed.json`: the secrets whose value the daemon found in an
//! agent's transcript on disk.
//!
//! A value in a transcript has left Vahta's hands for good: removing it from
//! the file (`vahta scrub --transcript`) does not un-send it to the model
//! provider, and a copy may sit in a backup or a synced folder. So the daemon
//! remembers it, and `vahta list` and `vahta check` say "rotate it" until the
//! secret's value is replaced (`vahta reset NAME`) or the secret is removed.
//!
//! Only a secret's name, its vault's id and the time are kept, never a value
//! and never where it was found. The daemon is the only writer; the commands
//! read. Written like `state.json`: a temp file in the same directory, then a
//! rename.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One secret found in a transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exposure {
    /// The vault's id, in hex, as the journal writes it.
    pub vault: String,
    pub name: String,
    /// When it was first found, seconds since the Unix epoch.
    pub at: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Exposed {
    pub exposed: Vec<Exposure>,
}

/// The file, in the data directory.
pub fn exposed_file(data: &Path) -> PathBuf {
    data.join("exposed.json")
}

impl Exposed {
    /// An unreadable or absent file is the empty list.
    pub fn load(path: &Path) -> Exposed {
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

    /// When `name` of `vault` was found in a transcript, if it was.
    pub fn when(&self, vault: &str, name: &str) -> Option<u64> {
        self.exposed
            .iter()
            .find(|e| e.vault == vault && e.name == name)
            .map(|e| e.at)
    }

    /// Record `name` of `vault` as exposed at `at`; the first time is kept.
    /// Whether the list changed.
    pub fn mark(&mut self, vault: &str, name: &str, at: u64) -> bool {
        if self.when(vault, name).is_some() {
            return false;
        }
        self.exposed.push(Exposure {
            vault: vault.to_string(),
            name: name.to_string(),
            at,
        });
        true
    }

    /// Forget `name` of `vault`: its value was replaced, or it is gone.
    /// Whether the list changed.
    pub fn clear(&mut self, vault: &str, name: &str) -> bool {
        let before = self.exposed.len();
        self.exposed
            .retain(|e| !(e.vault == vault && e.name == name));
        self.exposed.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_once_clears_and_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("d/exposed.json");
        let mut e = Exposed::load(&p);
        assert!(e.mark("ab", "TOKEN", 10));
        assert!(!e.mark("ab", "TOKEN", 20));
        assert_eq!(e.when("ab", "TOKEN"), Some(10));
        e.save(&p).unwrap();
        assert_eq!(Exposed::load(&p), e);
        assert!(!e.clear("cd", "TOKEN"));
        assert!(e.clear("ab", "TOKEN"));
        assert_eq!(e, Exposed::default());
        std::fs::write(&p, "{{{").unwrap();
        assert_eq!(Exposed::load(&p), Exposed::default());
    }
}
