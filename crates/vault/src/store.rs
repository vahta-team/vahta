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
//! The same file carries the **exposed marks**: the names of this vault's secrets
//! whose value was found in an agent's transcript (`vahta scrub --transcript`)
//! and that have not been replaced since. They are in the MAC, so an agent that
//! deletes a mark (or adds one) makes the next open [`Error::StoreTampered`]
//! instead of silently erasing "this key was exposed". A state with no marks has
//! exactly the MAC it had before marks existed. `vahta list` and `check` read the
//! marks like a peek reads the pin, without the MAC. An older `exposed.json` in
//! the root is moved into the state file of the vault it names the first time
//! that vault is opened with its key, and deleted when it is empty.
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

    /// The key of the state file `file`, from a MAC key kept earlier (a session
    /// keeps this instead of the vault key, which it has dropped).
    pub(crate) fn from_mac(file: StateFile, mac_key: [u8; 32]) -> StateKey {
        StateKey {
            file,
            mac_key: Zeroizing::new(mac_key),
        }
    }

    pub(crate) fn file(&self) -> StateFile {
        self.file
    }

    pub(crate) fn mac_key(&self) -> &[u8; 32] {
        &self.mac_key
    }

    /// A recipient's, from its own signing key.
    pub fn recipient(id: [u8; 16], sign_sk: &[u8; 32]) -> StateKey {
        StateKey {
            file: StateFile::Recipient(id),
            mac_key: crate::crypto::hkdf(sign_sk, INFO_RECIPIENT_MAC),
        }
    }

    fn mac(
        &self,
        vault_id: &[u8; 16],
        pinned: &[u8; 32],
        generation: u64,
        exposed: &[ExposedMark],
    ) -> Hmac<Sha256> {
        // HMAC accepts a key of any length, so this cannot fail.
        let mut m = Hmac::<Sha256>::new_from_slice(&*self.mac_key).expect("hmac key length");
        m.update(vault_id);
        m.update(pinned);
        m.update(&generation.to_le_bytes());
        // Nothing is added for no marks: a state from before marks verifies.
        let mut marks: Vec<&ExposedMark> = exposed.iter().collect();
        marks.sort_by(|a, b| a.name.cmp(&b.name));
        for mark in marks {
            m.update(b"exposed\0");
            m.update(mark.name.as_bytes());
            m.update(&[0]);
            m.update(&mark.at.to_le_bytes());
        }
        m
    }

    /// The text of a state file under this key.
    fn state_text(
        &self,
        vault_id: &[u8; 16],
        pinned: &[u8; 32],
        generation: u64,
        exposed: &[ExposedMark],
    ) -> String {
        let mut marks = exposed.to_vec();
        marks.sort_by(|a, b| a.name.cmp(&b.name));
        let mac = self
            .mac(vault_id, pinned, generation, &marks)
            .finalize()
            .into_bytes();
        let mut text = format!(
            "pinned_owner_sign_pk = {}\nmax_generation = {}\n",
            hex_encode(pinned),
            generation
        );
        for mark in &marks {
            text.push_str(&format!("exposed = {} {}\n", mark.name, mark.at));
        }
        text.push_str(&format!("mac = {}\n", hex_encode(&mac)));
        text
    }
}

/// A secret of the vault whose value was found in a transcript: its name and
/// when it was first found (seconds since the Unix epoch). Never the value, and
/// never where it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposedMark {
    pub name: String,
    pub at: u64,
}

/// What the store holds for one vault in one state file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub pinned_owner_sign_pk: [u8; 32],
    pub max_generation: u64,
    /// Sorted by name, one per name.
    pub exposed: Vec<ExposedMark>,
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
        key.mac(
            vault_id,
            &state.pinned_owner_sign_pk,
            state.max_generation,
            &state.exposed,
        )
        .verify_slice(&state.mac)
        .map_err(|_| Error::StoreTampered)?;
        Ok(Some(state))
    }

    /// This opener's state for the vault, after its MAC is checked; `None` if
    /// there is none.
    pub fn state(&self, vault_id: &[u8; 16], key: &StateKey) -> Result<Option<State>, Error> {
        self.load_authenticated(vault_id, key)
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

    /// Move this machine's owner state from `old` (the key of the vault before
    /// a re-key) to `new`: authenticate the existing state with `old`, then
    /// write one pinned to `new_owner_sign_pk` under `new`'s MAC. The old
    /// state must pin `old_owner_sign_pk`, and the generation never goes
    /// down. A machine with no state yet just records the new one.
    pub fn repin_owner(
        &self,
        vault_id: &[u8; 16],
        old: &StateKey,
        old_owner_sign_pk: &[u8; 32],
        new: &StateKey,
        new_owner_sign_pk: &[u8; 32],
        generation: u64,
    ) -> Result<(), Error> {
        let (seen, exposed) = match self.load_authenticated(vault_id, old)? {
            Some(s) => {
                if &s.pinned_owner_sign_pk != old_owner_sign_pk {
                    return Err(Error::OwnerChanged);
                }
                (s.max_generation, s.exposed)
            }
            None => (0, Vec::new()),
        };
        let max_generation = seen.max(generation);
        let text = new.state_text(vault_id, new_owner_sign_pk, max_generation, &exposed);
        write::write_atomic(&self.state_path(vault_id, new.file), text.as_bytes())
    }

    /// Move this machine's owner state to a new owner key that a successor
    /// chain vouches for. An owner's state is keyed from the vault key, and
    /// the vault key changed with the owner key, so the old state's MAC cannot
    /// be checked here; what is checked is that it pins `old_owner_sign_pk` and
    /// that `generation` is not below the highest it recorded. The caller has
    /// opened the file with the new vault key (`new`) and the person has
    /// confirmed; this writes the state under `new`'s MAC.
    pub fn adopt_owner(
        &self,
        vault_id: &[u8; 16],
        new: &StateKey,
        old_owner_sign_pk: &[u8; 32],
        new_owner_sign_pk: &[u8; 32],
        generation: u64,
    ) -> Result<(), Error> {
        let state = self
            .load_unchecked(vault_id, new.file)?
            .ok_or(Error::OwnerChanged)?;
        if &state.pinned_owner_sign_pk != old_owner_sign_pk {
            return Err(Error::OwnerChanged);
        }
        if generation < state.max_generation {
            return Err(Error::RolledBack {
                found: generation,
                seen: state.max_generation,
            });
        }
        // The marks are carried over: the person confirmed the owner, not that
        // the exposure is gone.
        let text = new.state_text(vault_id, new_owner_sign_pk, generation, &state.exposed);
        write::write_atomic(&self.state_path(vault_id, new.file), text.as_bytes())
    }

    /// The counter for the next transfer `recipient` sends to the owner of
    /// `vault_id`, and remember it. It is one above the last this machine gave
    /// out for that member; as a floor it is also the clock in seconds, so that a
    /// lost record (a reinstalled machine) cannot leave the member sending
    /// numbers the owner has long passed. The owner only ever compares counters
    /// with each other, never with a clock: a clock that is wrong only makes the
    /// numbers larger.
    pub fn next_transfer_counter(
        &self,
        vault_id: &[u8; 16],
        recipient: &[u8; 16],
    ) -> Result<u64, Error> {
        let path = self
            .dir(vault_id)
            .join(format!("transfer-{}", hex_encode(recipient)));
        let last = match fs::read_to_string(&path) {
            Ok(t) => t
                .trim()
                .parse::<u64>()
                .map_err(|_| Error::Store("the transfer counter file is malformed"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(_) => return Err(Error::Store("cannot read the transfer counter file")),
        };
        let next = last.saturating_add(1).max(crate::now());
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)
                .map_err(|_| Error::Store("cannot create the store directory"))?;
        }
        write::write_atomic(&path, format!("{next}\n").as_bytes())?;
        Ok(next)
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
        let mut exposed = existing.map(|s| s.exposed).unwrap_or_default();
        let migrated = self.legacy_exposed(vault_id);
        merge_marks(&mut exposed, &migrated);
        let text = key.state_text(vault_id, owner_sign_pk, max_generation, &exposed);
        let path = self.state_path(vault_id, key.file);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)
                .map_err(|_| Error::Store("cannot create the store directory"))?;
        }
        write::write_atomic(&path, text.as_bytes())?;
        // Only once the marks are safe in the state file is the old file cut.
        if !migrated.is_empty() {
            self.drop_legacy_exposed(vault_id);
        }
        Ok(())
    }

    /// This opener's exposed marks for the vault, after the state's MAC is
    /// checked. No state is no marks.
    pub fn exposed(&self, vault_id: &[u8; 16], key: &StateKey) -> Result<Vec<ExposedMark>, Error> {
        Ok(self
            .load_authenticated(vault_id, key)?
            .map(|s| s.exposed)
            .unwrap_or_default())
    }

    /// Record `names` as exposed at `at` (the first time of a name is kept).
    /// Whether the marks changed. A vault this opener has no state for cannot
    /// have anything recorded: it was never opened with its key.
    pub fn mark_exposed(
        &self,
        vault_id: &[u8; 16],
        key: &StateKey,
        names: &[String],
        at: u64,
    ) -> Result<bool, Error> {
        let Some(mut state) = self.load_authenticated(vault_id, key)? else {
            return Ok(false);
        };
        let before = state.exposed.len();
        let new: Vec<ExposedMark> = names
            .iter()
            .map(|name| ExposedMark {
                name: name.clone(),
                at,
            })
            .collect();
        merge_marks(&mut state.exposed, &new);
        if state.exposed.len() == before {
            return Ok(false);
        }
        self.write_marks(vault_id, key, &state)?;
        Ok(true)
    }

    /// Forget that `name` was exposed: its value was replaced, or it is gone.
    /// Whether the marks changed.
    pub fn clear_exposed(
        &self,
        vault_id: &[u8; 16],
        key: &StateKey,
        name: &str,
    ) -> Result<bool, Error> {
        let Some(mut state) = self.load_authenticated(vault_id, key)? else {
            return Ok(false);
        };
        let before = state.exposed.len();
        state.exposed.retain(|m| m.name != name);
        if state.exposed.len() == before {
            return Ok(false);
        }
        self.write_marks(vault_id, key, &state)?;
        Ok(true)
    }

    fn write_marks(&self, vault_id: &[u8; 16], key: &StateKey, state: &State) -> Result<(), Error> {
        let text = key.state_text(
            vault_id,
            &state.pinned_owner_sign_pk,
            state.max_generation,
            &state.exposed,
        );
        write::write_atomic(&self.state_path(vault_id, key.file), text.as_bytes())
    }

    /// The exposed marks of the vault as `vahta list` and `check` show them: every
    /// state file of the vault read without its MAC (a peek has no key), and an
    /// old `exposed.json` not yet moved. A tampered file is caught at the next
    /// open, not here; one that cannot be read has no marks to show.
    pub fn exposed_unchecked(&self, vault_id: &[u8; 16]) -> Vec<ExposedMark> {
        let mut out: Vec<ExposedMark> = Vec::new();
        if let Ok(entries) = fs::read_dir(self.dir(vault_id)) {
            for entry in entries.flatten() {
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
                if let Ok(Some(state)) = self.load_unchecked(vault_id, file) {
                    merge_marks(&mut out, &state.exposed);
                }
            }
        }
        merge_marks(&mut out, &self.legacy_exposed(vault_id));
        out
    }

    fn legacy_path(&self) -> PathBuf {
        self.root.join("exposed.json")
    }

    /// The marks of `vault_id` in an old `exposed.json`. An absent or unreadable
    /// file has none.
    fn legacy_exposed(&self, vault_id: &[u8; 16]) -> Vec<ExposedMark> {
        legacy_entries(&self.legacy_path())
            .into_iter()
            .filter(|(vault, _)| *vault == hex_encode(vault_id))
            .map(|(_, mark)| mark)
            .collect()
    }

    /// Take the marks of `vault_id` out of the old file, and the file itself when
    /// nothing is left. Best effort: what stays is migrated again, harmlessly.
    fn drop_legacy_exposed(&self, vault_id: &[u8; 16]) {
        let path = self.legacy_path();
        let id = hex_encode(vault_id);
        let rest: Vec<(String, ExposedMark)> = legacy_entries(&path)
            .into_iter()
            .filter(|(vault, _)| *vault != id)
            .collect();
        if rest.is_empty() {
            let _ = fs::remove_file(&path);
            return;
        }
        let items: Vec<String> = rest
            .iter()
            .map(|(vault, m)| {
                format!(
                    "    {{\"vault\": \"{vault}\", \"name\": \"{}\", \"at\": {}}}",
                    m.name, m.at
                )
            })
            .collect();
        let text = format!("{{\n  \"exposed\": [\n{}\n  ]\n}}\n", items.join(",\n"));
        let _ = write::write_atomic(&path, text.as_bytes());
    }
}

/// Add the marks of `new` that `marks` has no name for; the first time of a
/// name is kept. Sorted by name.
fn merge_marks(marks: &mut Vec<ExposedMark>, new: &[ExposedMark]) {
    for m in new {
        if !marks.iter().any(|x| x.name == m.name) {
            marks.push(m.clone());
        }
    }
    marks.sort_by(|a, b| a.name.cmp(&b.name));
}

/// `(vault id in hex, mark)` of every entry of an old `exposed.json`; a file
/// that is absent or not what it was written as has none. A name that is not a
/// valid secret name is skipped, so nothing odd is ever written to a state file.
fn legacy_entries(path: &Path) -> Vec<(String, ExposedMark)> {
    use vahta_json::Value;
    fn field<'a>(fields: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
        fields.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(parsed) = vahta_json::parse_bounded(&text, 8) else {
        return Vec::new();
    };
    let Value::Object(top) = &parsed else {
        return Vec::new();
    };
    let Some(Value::Array(items)) = field(top, "exposed") else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let Value::Object(f) = item else {
                return None;
            };
            let (Some(Value::Str(vault)), Some(Value::Str(name))) =
                (field(f, "vault"), field(f, "name"))
            else {
                return None;
            };
            let Some(Value::Int(at)) = field(f, "at") else {
                return None;
            };
            let at = at.parse::<u64>().ok()?;
            let hex_ok = vault.len() == 32 && vault.bytes().all(|b| b.is_ascii_hexdigit());
            (hex_ok && crate::valid_name(name)).then(|| {
                (
                    vault.to_ascii_lowercase(),
                    ExposedMark {
                        name: name.clone(),
                        at,
                    },
                )
            })
        })
        .collect()
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
    let mut exposed: Vec<ExposedMark> = Vec::new();
    for line in text.lines() {
        let (key, value) = line.split_once(" = ")?;
        match key {
            "exposed" => {
                let (name, at) = value.split_once(' ')?;
                if !crate::valid_name(name) || exposed.iter().any(|m| m.name == name) {
                    return None;
                }
                exposed.push(ExposedMark {
                    name: name.to_string(),
                    at: at.parse().ok()?,
                });
            }
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
        exposed,
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

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn exposed_marks_are_kept_in_the_authenticated_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        let (id, key) = ([4u8; 16], owner_key());
        // No state, nothing to attach marks to.
        assert!(!store.mark_exposed(&id, &key, &names(&["A"]), 10).unwrap());
        store.record(&id, &key, &[2; 32], 1).unwrap();
        assert!(
            store
                .mark_exposed(&id, &key, &names(&["B", "A"]), 10)
                .unwrap()
        );
        // The first time is kept, and a repeat changes nothing.
        assert!(!store.mark_exposed(&id, &key, &names(&["A"]), 99).unwrap());
        let marks = store.exposed(&id, &key).unwrap();
        assert_eq!(
            marks,
            [
                ExposedMark {
                    name: "A".into(),
                    at: 10
                },
                ExposedMark {
                    name: "B".into(),
                    at: 10
                }
            ]
        );
        // They survive a later record (an unlock, a save) and a re-pin.
        store.record(&id, &key, &[2; 32], 5).unwrap();
        assert_eq!(store.exposed(&id, &key).unwrap(), marks);
        let new = StateKey::owner(&[6; 32]);
        store
            .repin_owner(&id, &key, &[2; 32], &new, &[3; 32], 6)
            .unwrap();
        assert_eq!(store.exposed(&id, &new).unwrap(), marks);
        // A reader with no key sees them too.
        assert_eq!(store.exposed_unchecked(&id), marks);
        // Clearing one leaves the other.
        assert!(store.clear_exposed(&id, &new, "A").unwrap());
        assert!(!store.clear_exposed(&id, &new, "A").unwrap());
        assert_eq!(store.exposed(&id, &new).unwrap().len(), 1);
        assert_eq!(store.exposed_unchecked(&id)[0].name, "B");
    }

    #[test]
    fn deleting_adding_or_changing_a_mark_is_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        let (id, key) = ([8u8; 16], owner_key());
        store.record(&id, &key, &[2; 32], 1).unwrap();
        store.mark_exposed(&id, &key, &names(&["A"]), 10).unwrap();
        let path = store.state_path(&id, StateFile::Owner);
        let good = fs::read_to_string(&path).unwrap();
        assert!(good.contains("exposed = A 10\n"));
        for bad in [
            good.replace("exposed = A 10\n", ""),
            good.replace("exposed = A 10\n", "exposed = A 11\n"),
            good.replace("exposed = A 10\n", "exposed = Z 10\n"),
            good.replace("exposed = A 10\n", "exposed = A 10\nexposed = B 10\n"),
        ] {
            fs::write(&path, bad).unwrap();
            assert!(matches!(
                store.check(&id, &key, &[2; 32], 1),
                Err(Error::StoreTampered)
            ));
            assert!(matches!(
                store.mark_exposed(&id, &key, &names(&["C"]), 1),
                Err(Error::StoreTampered)
            ));
            assert!(matches!(
                store.clear_exposed(&id, &key, "A"),
                Err(Error::StoreTampered)
            ));
        }
        // Not a valid mark line: malformed, not a reset.
        for bad in [
            "exposed = a b 1\n",
            "exposed = A\n",
            "exposed = A x\n",
            "exposed = A 1\nexposed = A 2\n",
        ] {
            fs::write(&path, good.replace("exposed = A 10\n", bad)).unwrap();
            assert!(matches!(
                store.check(&id, &key, &[2; 32], 1),
                Err(Error::Store(_))
            ));
        }
        fs::write(&path, &good).unwrap();
        store.check(&id, &key, &[2; 32], 1).unwrap();
    }

    #[test]
    fn a_state_written_before_marks_existed_still_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        let (id, key) = ([2u8; 16], owner_key());
        // The old format: a MAC over id, pin and generation only.
        let mut m = Hmac::<Sha256>::new_from_slice(&*key.mac_key).unwrap();
        m.update(&id);
        m.update(&[7u8; 32]);
        m.update(&3u64.to_le_bytes());
        let text = format!(
            "pinned_owner_sign_pk = {}\nmax_generation = 3\nmac = {}\n",
            hex_encode(&[7u8; 32]),
            hex_encode(&m.finalize().into_bytes())
        );
        let path = store.state_path(&id, StateFile::Owner);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, text).unwrap();
        assert!(!store.check(&id, &key, &[7; 32], 3).unwrap().first_open);
        assert!(store.exposed(&id, &key).unwrap().is_empty());
    }

    #[test]
    fn an_old_exposed_json_is_moved_per_vault_and_removed_when_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path());
        let (a, b, key) = ([1u8; 16], [2u8; 16], owner_key());
        let legacy = dir.path().join("exposed.json");
        fs::write(
            &legacy,
            format!(
                r#"{{"exposed":[{{"vault":"{}","name":"A","at":10}},{{"vault":"{}","name":"B","at":20}},{{"vault":"{}","name":"bad name","at":1}},{{"vault":"zz","name":"C","at":1}}]}}"#,
                hex_encode(&a),
                hex_encode(&b),
                hex_encode(&a),
            ),
        )
        .unwrap();
        // Shown before any move.
        assert_eq!(store.exposed_unchecked(&a).len(), 1);
        store.record(&a, &key, &[2; 32], 1).unwrap();
        assert_eq!(store.exposed(&a, &key).unwrap()[0].name, "A");
        let rest = fs::read_to_string(&legacy).unwrap();
        assert!(
            rest.contains(&hex_encode(&b)) && !rest.contains("\"A\""),
            "{rest}"
        );
        assert_eq!(store.exposed_unchecked(&b)[0].at, 20);
        store.record(&b, &key, &[2; 32], 1).unwrap();
        assert!(!legacy.exists());
        assert_eq!(store.exposed(&b, &key).unwrap()[0].at, 20);
        // Garbage is no marks, and is left alone.
        fs::write(&legacy, "{{{").unwrap();
        assert!(store.exposed_unchecked(&a).len() == 1);
        store.record(&a, &key, &[2; 32], 2).unwrap();
        assert_eq!(fs::read_to_string(&legacy).unwrap(), "{{{");
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
