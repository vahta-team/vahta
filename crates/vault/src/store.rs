//! What this machine remembers about each vault it has opened.
//!
//! Two facts per vault, kept outside the project (so a repo checkout or a
//! restored backup cannot rewrite them): the owner's signing key, pinned the
//! first time an unlock proves the key belongs to the vault, and the highest
//! generation seen. They turn "a file that verifies" into "the file this
//! machine has been using": a different owner key is [`Error::OwnerChanged`],
//! a lower generation is [`Error::RolledBack`].
//!
//! The state is authenticated. Each state file carries an HMAC-SHA256 over
//! `vault_id ‖ pinned key ‖ max_generation`, keyed from something only an
//! opener holds: the owner's is keyed from the vault key (`vahta/v1/store-mac`),
//! a recipient's from its own signing key (`vahta/v1/store-mac-recipient`). So
//! a file that has been edited, say to lower `max_generation` before a rollback,
//! is [`Error::StoreTampered`] at the next open, never silently reset. Owner and
//! recipient states are separate files (`state` and `state-<recipient id>`).
//! Peek has no key, so it reads the state to compare the pin and generation but
//! cannot check the MAC, and says so.
//!
//! The root is a parameter so tests use a temp dir; the default is the
//! platform data directory plus `vahta`.

use std::fs;
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, hex_decode, hex_encode, write};

const INFO_OWNER_MAC: &[u8] = b"vahta/v1/store-mac";
const INFO_RECIPIENT_MAC: &[u8] = b"vahta/v1/store-mac-recipient";

#[derive(Debug, Clone)]
pub struct LocalStore {
    root: PathBuf,
}

/// Which state file, and so which key, an opener uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateFile {
    Owner,
    Recipient([u8; 16]),
}

impl StateFile {
    fn file_name(&self) -> String {
        match self {
            StateFile::Owner => "state".to_string(),
            StateFile::Recipient(id) => format!("state-{}", hex_encode(id)),
        }
    }
}

/// The file an opener reads and writes, with the key that authenticates it.
pub struct StateKey {
    file: StateFile,
    mac_key: Zeroizing<[u8; 32]>,
}

impl StateKey {
    /// The owner's, from the vault key.
    pub fn owner(vk: &[u8; 32]) -> StateKey {
        StateKey {
            file: StateFile::Owner,
            mac_key: crate::crypto::hkdf(vk, INFO_OWNER_MAC),
        }
    }

    /// A recipient's, from its own signing key.
    pub fn recipient(id: [u8; 16], sign_sk: &[u8; 32]) -> StateKey {
        StateKey {
            file: StateFile::Recipient(id),
            mac_key: crate::crypto::hkdf(sign_sk, INFO_RECIPIENT_MAC),
        }
    }

    fn mac(&self, vault_id: &[u8; 16], pinned: &[u8; 32], generation: u64) -> Hmac<Sha256> {
        // HMAC accepts a key of any length, so this cannot fail.
        let mut m = Hmac::<Sha256>::new_from_slice(&*self.mac_key).expect("hmac key length");
        m.update(vault_id);
        m.update(pinned);
        m.update(&generation.to_le_bytes());
        m
    }
}

/// What the store holds for one vault in one state file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub pinned_owner_sign_pk: [u8; 32],
    pub max_generation: u64,
    mac: [u8; 32],
}

/// The outcome of an authenticated check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checked {
    /// There was no state for this vault here: this machine has not opened it
    /// as this opener before.
    pub first_open: bool,
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

    fn dir(&self, vault_id: &[u8; 16]) -> PathBuf {
        self.root.join("vaults").join(hex_encode(vault_id))
    }

    fn state_path(&self, vault_id: &[u8; 16], file: StateFile) -> PathBuf {
        self.dir(vault_id).join(file.file_name())
    }

    /// The stored state, with no MAC check; an absent file is `None`. A file
    /// that is there but unreadable or malformed is an error, never "start
    /// over": forgetting the pin and the generation would switch the protection
    /// off.
    pub fn load_unchecked(
        &self,
        vault_id: &[u8; 16],
        file: StateFile,
    ) -> Result<Option<State>, Error> {
        let path = self.state_path(vault_id, file);
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::Store("cannot read the state file")),
        };
        parse_state(&text)
            .map(Some)
            .ok_or(Error::Store("the state file is malformed"))
    }

    fn load_authenticated(
        &self,
        vault_id: &[u8; 16],
        key: &StateKey,
    ) -> Result<Option<State>, Error> {
        let Some(state) = self.load_unchecked(vault_id, key.file)? else {
            return Ok(None);
        };
        key.mac(vault_id, &state.pinned_owner_sign_pk, state.max_generation)
            .verify_slice(&state.mac)
            .map_err(|_| Error::StoreTampered)?;
        Ok(Some(state))
    }

    /// Check a file's owner key and generation against this opener's state,
    /// after authenticating the state. A state that fails its MAC is
    /// [`Error::StoreTampered`], whatever else it says.
    pub fn check(
        &self,
        vault_id: &[u8; 16],
        key: &StateKey,
        owner_sign_pk: &[u8; 32],
        generation: u64,
    ) -> Result<Checked, Error> {
        let Some(state) = self.load_authenticated(vault_id, key)? else {
            return Ok(Checked { first_open: true });
        };
        compare(&state, owner_sign_pk, generation)?;
        Ok(Checked { first_open: false })
    }

    /// The cheap, early half of the owner check: is the owner key in the file
    /// the one this machine pinned? It reads the state without its MAC, which is
    /// fine for this one question: a swapped owner key also changes the vault
    /// key, so the authenticated check after unlock could only say "tampered",
    /// and an edited pin can at worst make a good vault refuse. Everything else
    /// (generation, MAC) waits for the authenticated check.
    pub fn check_owner_pin(
        &self,
        vault_id: &[u8; 16],
        file: StateFile,
        owner_sign_pk: &[u8; 32],
    ) -> Result<(), Error> {
        match self.load_unchecked(vault_id, file)? {
            Some(s) if &s.pinned_owner_sign_pk != owner_sign_pk => Err(Error::OwnerChanged),
            _ => Ok(()),
        }
    }

    /// What a peek can say with no key: compare against every state file for
    /// this vault (the owner's and any recipient's) without checking MACs.
    /// `Ok(None)` means nothing on this machine remembers the vault.
    pub fn check_unauthenticated(
        &self,
        vault_id: &[u8; 16],
        owner_sign_pk: &[u8; 32],
        generation: u64,
    ) -> Result<Option<()>, Error> {
        let mut any = false;
        let dir = self.dir(vault_id);
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::Store("cannot read the store directory")),
        };
        for entry in entries {
            let entry = entry.map_err(|_| Error::Store("cannot read the store directory"))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let file = if name == "state" {
                StateFile::Owner
            } else if let Some(id) = name
                .strip_prefix("state-")
                .and_then(hex_decode)
                .and_then(|b| <[u8; 16]>::try_from(b).ok())
            {
                StateFile::Recipient(id)
            } else {
                continue;
            };
            if let Some(state) = self.load_unchecked(vault_id, file)? {
                compare(&state, owner_sign_pk, generation)?;
                any = true;
            }
        }
        Ok(any.then_some(()))
    }

    /// Remember `generation` (never lowering the stored one) and pin the owner
    /// key if none is pinned yet. Callers pin only once something has proved
    /// the key: an unlock, the owner's own save, or a recipient's first open.
    pub fn record(
        &self,
        vault_id: &[u8; 16],
        key: &StateKey,
        owner_sign_pk: &[u8; 32],
        generation: u64,
    ) -> Result<(), Error> {
        let existing = self.load_authenticated(vault_id, key)?;
        let max_generation = match &existing {
            Some(s) => {
                if &s.pinned_owner_sign_pk != owner_sign_pk {
                    return Err(Error::OwnerChanged);
                }
                s.max_generation.max(generation)
            }
            None => generation,
        };
        let mac = key
            .mac(vault_id, owner_sign_pk, max_generation)
            .finalize()
            .into_bytes();
        let text = format!(
            "pinned_owner_sign_pk = {}\nmax_generation = {}\nmac = {}\n",
            hex_encode(owner_sign_pk),
            max_generation,
            hex_encode(&mac)
        );
        let path = self.state_path(vault_id, key.file);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)
                .map_err(|_| Error::Store("cannot create the store directory"))?;
        }
        write::write_atomic(&path, text.as_bytes())
    }
}

fn compare(state: &State, owner_sign_pk: &[u8; 32], generation: u64) -> Result<(), Error> {
    if &state.pinned_owner_sign_pk != owner_sign_pk {
        return Err(Error::OwnerChanged);
    }
    if generation < state.max_generation {
        return Err(Error::RolledBack {
            found: generation,
            seen: state.max_generation,
        });
    }
    Ok(())
}

fn parse_state(text: &str) -> Option<State> {
    let (mut pinned, mut generation, mut mac) = (None, None, None);
    for line in text.lines() {
        let (key, value) = line.split_once(" = ")?;
        match key {
            "pinned_owner_sign_pk" if pinned.is_none() => {
                pinned = Some(<[u8; 32]>::try_from(hex_decode(value)?).ok()?);
            }
            "max_generation" if generation.is_none() => generation = Some(value.parse().ok()?),
            "mac" if mac.is_none() => {
                mac = Some(<[u8; 32]>::try_from(hex_decode(value)?).ok()?);
            }
            _ => return None,
        }
    }
    Some(State {
        pinned_owner_sign_pk: pinned?,
        max_generation: generation?,
        mac: mac?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner_key() -> StateKey {
        StateKey::owner(&[5; 32])
    }

    #[test]
    fn pins_then_refuses_another_owner_and_a_lower_generation() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        let (id, key) = ([1u8; 16], owner_key());
        assert!(store.check(&id, &key, &[2; 32], 3).unwrap().first_open);
        store.record(&id, &key, &[2; 32], 5).unwrap();
        assert!(!store.check(&id, &key, &[2; 32], 5).unwrap().first_open);
        assert!(matches!(
            store.check(&id, &key, &[3; 32], 5),
            Err(Error::OwnerChanged)
        ));
        assert!(matches!(
            store.check(&id, &key, &[2; 32], 3),
            Err(Error::RolledBack { found: 3, seen: 5 })
        ));
        // Recording never lowers the generation.
        store.record(&id, &key, &[2; 32], 4).unwrap();
        assert_eq!(
            store
                .load_unchecked(&id, StateFile::Owner)
                .unwrap()
                .unwrap()
                .max_generation,
            5
        );
    }

    #[test]
    fn a_damaged_or_edited_state_file_is_an_error_not_a_reset() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        let (id, key) = ([9u8; 16], owner_key());
        store.record(&id, &key, &[2; 32], 1).unwrap();
        let path = store.state_path(&id, StateFile::Owner);
        let good = fs::read_to_string(&path).unwrap();
        // Edited: well-formed, wrong MAC.
        fs::write(
            &path,
            good.replace("max_generation = 1", "max_generation = 7"),
        )
        .unwrap();
        assert!(matches!(
            store.check(&id, &key, &[2; 32], 1),
            Err(Error::StoreTampered)
        ));
        assert!(matches!(
            store.record(&id, &key, &[2; 32], 9),
            Err(Error::StoreTampered)
        ));
        // Another key cannot authenticate it either.
        fs::write(&path, &good).unwrap();
        assert!(matches!(
            store.check(&id, &StateKey::owner(&[6; 32]), &[2; 32], 1),
            Err(Error::StoreTampered)
        ));
        fs::write(&path, "garbage").unwrap();
        assert!(matches!(
            store.check(&id, &key, &[2; 32], 1),
            Err(Error::Store(_))
        ));
    }

    #[test]
    fn owner_and_recipient_states_are_separate_files() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        let (id, rid) = ([1u8; 16], [7u8; 16]);
        let rk = StateKey::recipient(rid, &[8; 32]);
        store.record(&id, &rk, &[2; 32], 3).unwrap();
        assert!(
            store
                .check(&id, &owner_key(), &[2; 32], 1)
                .unwrap()
                .first_open
        );
        assert!(!store.check(&id, &rk, &[2; 32], 3).unwrap().first_open);
        assert!(
            store
                .check_unauthenticated(&id, &[2; 32], 3)
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            store.check_unauthenticated(&id, &[2; 32], 2),
            Err(Error::RolledBack { .. })
        ));
        assert!(
            store
                .check_unauthenticated(&[3; 16], &[2; 32], 2)
                .unwrap()
                .is_none()
        );
    }
}
