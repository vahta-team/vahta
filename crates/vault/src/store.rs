//! What this machine remembers about each vault it has opened.
//!
//! Two facts per vault, kept outside the project (so a repo checkout or a
//! restored backup cannot rewrite them): the owner's signing key, pinned the
//! first time an unlock proves the key belongs to the vault, and the highest
//! generation seen. They turn "a file that verifies" into "the file this
//! machine has been using": a different owner key is [`Error::OwnerChanged`],
//! a lower generation is [`Error::RolledBack`].
//!
//! The root is a parameter so tests use a temp dir; the default is the
//! platform data directory plus `vahta`.

use std::fs;
use std::path::{Path, PathBuf};

use crate::{Error, hex_decode, hex_encode, write};

#[derive(Debug, Clone)]
pub struct LocalStore {
    root: PathBuf,
}

/// What the store holds for one vault.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    pub pinned_owner_sign_pk: Option<[u8; 32]>,
    pub max_generation: u64,
}

impl LocalStore {
    pub fn new(root: impl Into<PathBuf>) -> LocalStore {
        LocalStore { root: root.into() }
    }

    /// `<platform data dir>/vahta`, or `None` where there is no such directory.
    pub fn platform_default() -> Option<LocalStore> {
        dirs::data_dir().map(|d| LocalStore::new(d.join("vahta")))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn state_path(&self, vault_id: &[u8; 16]) -> PathBuf {
        self.root
            .join("vaults")
            .join(hex_encode(vault_id))
            .join("state")
    }

    /// The stored state; an absent file is an empty state. A file that is
    /// there but unreadable or malformed is an error, never "start over":
    /// forgetting the pin and the generation would switch the protection off.
    pub fn load(&self, vault_id: &[u8; 16]) -> Result<State, Error> {
        let path = self.state_path(vault_id);
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(State::default()),
            Err(_) => return Err(Error::Store("cannot read the state file")),
        };
        parse_state(&text).ok_or(Error::Store("the state file is malformed"))
    }

    /// Compare a file's owner key and generation with the stored state.
    pub fn check(
        &self,
        vault_id: &[u8; 16],
        owner_sign_pk: &[u8; 32],
        generation: u64,
    ) -> Result<crate::Verification, Error> {
        let state = self.load(vault_id)?;
        let pinned = match state.pinned_owner_sign_pk {
            Some(pk) if &pk != owner_sign_pk => return Err(Error::OwnerChanged),
            Some(_) => true,
            None => false,
        };
        if generation < state.max_generation {
            return Err(Error::RolledBack {
                found: generation,
                seen: state.max_generation,
            });
        }
        Ok(if pinned {
            crate::Verification::Pinned
        } else {
            crate::Verification::Unpinned
        })
    }

    /// Remember `generation` (never lowering the stored one) and pin the
    /// owner key if none is pinned yet. Callers pin only once something has
    /// proved the key: an unlock, or the owner's own save.
    pub fn record(
        &self,
        vault_id: &[u8; 16],
        owner_sign_pk: &[u8; 32],
        generation: u64,
    ) -> Result<(), Error> {
        let mut state = self.load(vault_id)?;
        match state.pinned_owner_sign_pk {
            Some(pk) if &pk != owner_sign_pk => return Err(Error::OwnerChanged),
            _ => state.pinned_owner_sign_pk = Some(*owner_sign_pk),
        }
        state.max_generation = state.max_generation.max(generation);
        let path = self.state_path(vault_id);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)
                .map_err(|_| Error::Store("cannot create the store directory"))?;
        }
        let text = format!(
            "pinned_owner_sign_pk = {}\nmax_generation = {}\n",
            hex_encode(&state.pinned_owner_sign_pk.unwrap_or([0; 32])),
            state.max_generation
        );
        write::write_atomic(&path, text.as_bytes())
    }
}

fn parse_state(text: &str) -> Option<State> {
    let mut pinned = None;
    let mut generation = None;
    for line in text.lines() {
        let (key, value) = line.split_once(" = ")?;
        match key {
            "pinned_owner_sign_pk" if pinned.is_none() => {
                let bytes: [u8; 32] = hex_decode(value)?.try_into().ok()?;
                pinned = Some(bytes);
            }
            "max_generation" if generation.is_none() => generation = Some(value.parse().ok()?),
            _ => return None,
        }
    }
    Some(State {
        pinned_owner_sign_pk: pinned,
        max_generation: generation?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_then_refuses_another_owner_and_a_lower_generation() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        let id = [1u8; 16];
        assert_eq!(
            store.check(&id, &[2; 32], 3).unwrap(),
            crate::Verification::Unpinned
        );
        store.record(&id, &[2; 32], 5).unwrap();
        assert_eq!(
            store.check(&id, &[2; 32], 5).unwrap(),
            crate::Verification::Pinned
        );
        assert!(matches!(
            store.check(&id, &[3; 32], 5),
            Err(Error::OwnerChanged)
        ));
        assert!(matches!(
            store.check(&id, &[2; 32], 3),
            Err(Error::RolledBack { found: 3, seen: 5 })
        ));
        // Recording never lowers the generation.
        store.record(&id, &[2; 32], 4).unwrap();
        assert_eq!(store.load(&id).unwrap().max_generation, 5);
    }

    #[test]
    fn a_damaged_state_file_is_an_error_not_a_reset() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        let id = [9u8; 16];
        store.record(&id, &[2; 32], 1).unwrap();
        fs::write(store.state_path(&id), "garbage").unwrap();
        assert!(matches!(store.load(&id), Err(Error::Store(_))));
    }
}
