//! The operations on a vault: create, peek, unlock, edit, save.
//!
//! A [`Vault`] is either opened by its owner (password or recovery key), who
//! holds the vault key and can do everything, or by a recipient, who gets a
//! read-only view of the secrets it holds a wrap for. In v1 only the owner
//! writes: a new secret needs a wrap under a key derived from the vault key,
//! which a recipient does not have. The signature rules still accept an admin
//! or editor signer, because the format has to be able to carry them once a
//! cloud peer writes; here nothing produces one.
//!
//! `save` is the only way a vault reaches disk. It checks that the file is
//! still the one that was loaded, makes the one-time backup if this save is an
//! upgrade, bumps the generation, signs, writes atomically and tells the local
//! store. Hold a [`VaultLock`] around load, modify and save when more than one
//! process may write; `save_locked` takes the lock you already hold.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::{self, KEY_LEN, KdfParams};
use crate::format::current::{self, Actor, Entry, Kind, Recipient, RecipientKind, Role, Tier};
use crate::format::{self, CURRENT, Loaded, OwnerAccess};
use crate::store::LocalStore;
use crate::write::{VaultLock, write_atomic};
use crate::{Error, RecoveryKey, SecretValue, now, valid_name};

/// A recipient's private keys: one to open wraps, one to sign. Kept by the
/// recipient; the vault holds only the public halves.
pub struct RecipientSecret {
    enc_sk: Zeroizing<[u8; KEY_LEN]>,
    sign_sk: Zeroizing<[u8; KEY_LEN]>,
}

/// The public halves a recipient hands to the owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientPublic {
    pub enc_pk: [u8; KEY_LEN],
    pub sign_pk: [u8; KEY_LEN],
}

impl RecipientSecret {
    pub fn generate() -> Result<RecipientSecret, Error> {
        let (enc_sk, _) = crypto::enc_keypair_from_seed(&crypto::random::<KEY_LEN>()?);
        Ok(RecipientSecret {
            enc_sk,
            sign_sk: Zeroizing::new(crypto::random::<KEY_LEN>()?),
        })
    }

    pub fn from_parts(enc_sk: [u8; KEY_LEN], sign_sk: [u8; KEY_LEN]) -> RecipientSecret {
        RecipientSecret {
            enc_sk: Zeroizing::new(enc_sk),
            sign_sk: Zeroizing::new(sign_sk),
        }
    }

    pub fn enc_sk(&self) -> &[u8; KEY_LEN] {
        &self.enc_sk
    }

    pub fn sign_sk(&self) -> &[u8; KEY_LEN] {
        &self.sign_sk
    }

    pub fn public(&self) -> Result<RecipientPublic, Error> {
        Ok(RecipientPublic {
            enc_pk: crypto::enc_public_from_secret(&self.enc_sk)?,
            sign_pk: crypto::signing_key(&self.sign_sk)
                .verifying_key()
                .to_bytes(),
        })
    }
}

impl std::fmt::Debug for RecipientSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecipientSecret(<redacted>)")
    }
}

/// What a signature check against this machine's store says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// The owner key matches the one pinned here and the generation is not
    /// lower than any seen.
    Pinned,
    /// This machine has not unlocked the vault yet, so there is nothing to
    /// compare the owner key with. The file is self-consistent, nothing more.
    Unpinned,
}

/// What a vault file shows without a password. The file has been parsed and
/// its signatures verified; nothing has been compared with a store yet.
#[derive(Debug, Clone)]
pub struct Peek {
    pub vault_id: [u8; 16],
    pub format: u16,
    /// The file is in an older format; an owner unlock upgrades it.
    pub upgrade_pending: bool,
    pub generation: u64,
    pub updated: u64,
    pub owner_sign_pk: [u8; 32],
    pub signer: Actor,
    pub entries: Vec<Entry>,
    pub recipient_count: usize,
}

impl Peek {
    /// Compare with this machine's store: the pinned owner key and the highest
    /// generation seen.
    pub fn verified(&self, store: &LocalStore) -> Result<Verification, Error> {
        store.check(&self.vault_id, &self.owner_sign_pk, self.generation)
    }
}

enum Access {
    Owner(current::Unlocked),
    Recipient(current::RecipientView),
}

/// An opened vault.
pub struct Vault {
    access: Access,
    /// The generation of the file this was loaded from; 0 for a new vault.
    base_generation: u64,
    /// The format the file had before an upgrade; the first save backs it up.
    upgraded_from: Option<u16>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (role, count) = match &self.access {
            Access::Owner(u) => ("owner", u.model.index.len()),
            Access::Recipient(v) => ("recipient", v.values.len()),
        };
        f.debug_struct("Vault")
            .field("role", &role)
            .field("entries", &count)
            .field("generation", &self.base_generation)
            .finish_non_exhaustive()
    }
}

/// Read a vault file, refusing one over the size limit before reading it all.
pub fn read_file(path: &Path) -> Result<Vec<u8>, Error> {
    let io = |op, source| Error::Io {
        op,
        path: path.to_path_buf(),
        source,
    };
    let file = fs::File::open(path).map_err(|e| io("open", e))?;
    let mut bytes = Vec::new();
    // One byte past the limit is enough to know the file is too big.
    file.take(format::MAX_FILE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io("read", e))?;
    if bytes.len() > format::MAX_FILE {
        return Err(Error::TooLarge);
    }
    Ok(bytes)
}

fn peek_of(loaded: &Loaded) -> Peek {
    let m = loaded.model();
    Peek {
        vault_id: m.header.vault_id,
        format: loaded.format(),
        upgrade_pending: loaded.upgrade_pending(),
        generation: m.header.generation,
        updated: m.header.updated,
        owner_sign_pk: m.owner.sign_pk,
        signer: loaded.signer(),
        entries: m.index.clone(),
        recipient_count: m.recipients.len(),
    }
}

impl Vault {
    // --- Reading without a password -------------------------------------------

    /// Names, kinds, tiers and generation, after verifying the file's
    /// structure and signatures. Never upgrades, whatever the format.
    pub fn peek(path: &Path) -> Result<Peek, Error> {
        Vault::peek_bytes(&read_file(path)?)
    }

    pub fn peek_bytes(bytes: &[u8]) -> Result<Peek, Error> {
        Ok(peek_of(&format::decode(bytes)?))
    }

    // --- Creating -----------------------------------------------------------------

    /// A new, empty vault with a password slot and a recovery slot. The paper
    /// key is returned once and never stored. Nothing is written until `save`.
    pub fn create(pw: &[u8], kdf: KdfParams) -> Result<(Vault, RecoveryKey), Error> {
        let (unlocked, recovery) = current::create(CURRENT, pw, kdf, true)?;
        let vault = Vault {
            access: Access::Owner(unlocked),
            base_generation: 0,
            upgraded_from: None,
        };
        Ok((vault, recovery.ok_or(Error::Rng)?))
    }

    /// A vault in the pseudo-format 0, written to `path`, for upgrade tests.
    #[cfg(test)]
    pub(crate) fn write_v0_for_test(
        path: &Path,
        pw: &[u8],
        items: &[(&str, &[u8])],
    ) -> Result<(), Error> {
        let mut u = format::testing::create_v0(pw)?;
        for (n, (name, value)) in items.iter().enumerate() {
            let mut sid = crypto::random::<16>()?;
            sid[0] = n as u8;
            let sealed =
                current::seal_secret(u.fmt, &u.model.header.vault_id, sid, &u.vk, value, &[])?;
            u.model.secrets.push(sealed);
            u.model.index.push(Entry {
                secret_id: sid,
                name: (*name).to_string(),
                kind: Kind::Env,
                tier: Tier::Session,
                updated: now(),
                changed_by: Actor::Owner,
            });
        }
        u.model.header.generation = 1;
        let key = current::owner_keys(&u.vk).sign;
        write_atomic(
            path,
            &current::encode_as(0, &u.model, &key, Actor::Owner, &key)?,
        )
    }

    // --- Opening ---------------------------------------------------------------------

    fn load(path: &Path, store: &LocalStore) -> Result<Loaded, Error> {
        let loaded = format::decode(&read_file(path)?)?;
        // Cheap checks first: a different owner or an older file is refused
        // before the KDF runs.
        let m = loaded.model();
        store.check(&m.header.vault_id, &m.owner.sign_pk, m.header.generation)?;
        Ok(loaded)
    }

    fn open_owner(
        path: &Path,
        access: OwnerAccess<'_>,
        store: &LocalStore,
    ) -> Result<Vault, Error> {
        let loaded = Vault::load(path, store)?;
        let (unlocked, from) = format::unlock_owner(&loaded, access)?;
        // The unlock proved the vault key derives this owner key: pin it.
        store.record(
            &unlocked.model.header.vault_id,
            &unlocked.model.owner.sign_pk,
            unlocked.model.header.generation,
        )?;
        let base_generation = unlocked.model.header.generation;
        Ok(Vault {
            access: Access::Owner(unlocked),
            base_generation,
            upgraded_from: from,
        })
    }

    /// Unlock with the password. An older format is upgraded in memory; the
    /// next `save` writes it (after backing up the original).
    pub fn unlock_password(path: &Path, pw: &[u8], store: &LocalStore) -> Result<Vault, Error> {
        Vault::open_owner(path, OwnerAccess::Password(pw), store)
    }

    pub fn unlock_recovery(
        path: &Path,
        key: &RecoveryKey,
        store: &LocalStore,
    ) -> Result<Vault, Error> {
        Vault::open_owner(path, OwnerAccess::Recovery(key), store)
    }

    /// Open as a recipient: a read-only view of the secrets it holds a wrap
    /// for. The owner key is pinned on first open (trust on first use: a
    /// recipient cannot prove the owner's key the way an unlock does).
    pub fn open_as_recipient(
        path: &Path,
        recipient_id: &[u8; 16],
        keys: &RecipientSecret,
        store: &LocalStore,
    ) -> Result<Vault, Error> {
        let loaded = Vault::load(path, store)?;
        let view = format::unlock_recipient(&loaded, recipient_id, keys.enc_sk())?;
        store.record(
            &view.header.vault_id,
            &view.owner.sign_pk,
            view.header.generation,
        )?;
        let base_generation = view.header.generation;
        Ok(Vault {
            access: Access::Recipient(view),
            base_generation,
            upgraded_from: None,
        })
    }

    // --- Reading ------------------------------------------------------------------------

    pub fn vault_id(&self) -> [u8; 16] {
        match &self.access {
            Access::Owner(u) => u.model.header.vault_id,
            Access::Recipient(v) => v.header.vault_id,
        }
    }

    pub fn generation(&self) -> u64 {
        match &self.access {
            Access::Owner(u) => u.model.header.generation,
            Access::Recipient(v) => v.header.generation,
        }
    }

    /// Whether this was read from an older format and the next save will
    /// write it in the current one.
    pub fn upgrade_pending(&self) -> bool {
        self.upgraded_from.is_some()
    }

    /// The index: every name, kind and tier, for either kind of opening.
    pub fn entries(&self) -> &[Entry] {
        match &self.access {
            Access::Owner(u) => &u.model.index,
            Access::Recipient(v) => &v.entries,
        }
    }

    pub fn recipients(&self) -> &[Recipient] {
        match &self.access {
            Access::Owner(u) => &u.model.recipients,
            Access::Recipient(_) => &[],
        }
    }

    /// The value of `name`. A recipient gets only what it holds a wrap for.
    pub fn get(&self, name: &str) -> Result<SecretValue, Error> {
        match &self.access {
            Access::Owner(u) => {
                let (_, sealed) = find(&u.model, name)?;
                current::open_value(u.fmt, &u.model.header.vault_id, &u.vk, sealed)
            }
            Access::Recipient(v) => {
                if let Some((_, value)) = v.values.iter().find(|(n, _)| n == name) {
                    Ok(value.clone())
                } else if v.entries.iter().any(|e| e.name == name) {
                    Err(Error::NoAccess)
                } else {
                    Err(Error::not_found(name))
                }
            }
        }
    }

    // --- Editing secrets (owner) --------------------------------------------------------------

    fn owner(&mut self) -> Result<&mut current::Unlocked, Error> {
        match &mut self.access {
            Access::Owner(u) => Ok(u),
            Access::Recipient(_) => Err(Error::NotOwner),
        }
    }

    /// Add or replace a secret. Every change seals under a new DEK; existing
    /// grants of a replaced secret carry over.
    pub fn set(&mut self, name: &str, value: &[u8], kind: Kind, tier: Tier) -> Result<(), Error> {
        if !valid_name(name) {
            return Err(Error::InvalidName);
        }
        if let Kind::File { file_name } = &kind
            && !current::valid_file_name(file_name)
        {
            return Err(Error::InvalidFileName);
        }
        let u = self.owner()?;
        let vault_id = u.model.header.vault_id;
        match u.model.index.iter().position(|e| e.name == name) {
            Some(i) => {
                let holders = holder_ids(&u.model.secrets[i]);
                reseal(u, i, value, &holders)?;
                let e = &mut u.model.index[i];
                e.kind = kind;
                e.tier = tier;
                e.updated = now();
                e.changed_by = Actor::Owner;
            }
            None => {
                let sid = crypto::random::<16>()?;
                let sealed = current::seal_secret(u.fmt, &vault_id, sid, &u.vk, value, &[])?;
                u.model.secrets.push(sealed);
                u.model.index.push(Entry {
                    secret_id: sid,
                    name: name.to_string(),
                    kind,
                    tier,
                    updated: now(),
                    changed_by: Actor::Owner,
                });
            }
        }
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Result<(), Error> {
        let u = self.owner()?;
        let i = index_of(&u.model, name)?;
        let sid = u.model.index[i].secret_id;
        u.model.index.remove(i);
        u.model.secrets.retain(|s| s.secret_id != sid);
        Ok(())
    }

    pub fn set_tier(&mut self, name: &str, tier: Tier) -> Result<(), Error> {
        let u = self.owner()?;
        let i = index_of(&u.model, name)?;
        let e = &mut u.model.index[i];
        e.tier = tier;
        e.updated = now();
        e.changed_by = Actor::Owner;
        Ok(())
    }

    /// Add several secrets at once, refusing the whole batch if any name is
    /// already taken or invalid. Used by the ka import.
    pub fn import(&mut self, items: Vec<(String, SecretValue)>) -> Result<(), Error> {
        {
            let u = self.owner()?;
            for (i, (name, _)) in items.iter().enumerate() {
                if !valid_name(name) {
                    return Err(Error::InvalidName);
                }
                if u.model.index.iter().any(|e| &e.name == name)
                    || items[..i].iter().any(|(n, _)| n == name)
                {
                    return Err(Error::ImportCollision(crate::shown_name(name)));
                }
            }
        }
        for (name, value) in items {
            self.set(&name, value.expose(), Kind::Env, Tier::Session)?;
        }
        Ok(())
    }

    // --- Editing membership (owner) ---------------------------------------------------------------

    /// Add a recipient and return its id.
    pub fn add_recipient(
        &mut self,
        name: &str,
        kind: RecipientKind,
        role: Role,
        public: &RecipientPublic,
    ) -> Result<[u8; 16], Error> {
        let u = self.owner()?;
        if name.is_empty()
            || name.len() > 128
            || name.chars().any(char::is_control)
            || u.model.recipients.iter().any(|r| r.name == name)
        {
            return Err(Error::Corrupt("recipient name"));
        }
        let id = crypto::random::<16>()?;
        u.model.recipients.push(Recipient {
            id,
            name: name.to_string(),
            kind,
            role,
            enc_pk: public.enc_pk,
            sign_pk: public.sign_pk,
            added: now(),
        });
        Ok(id)
    }

    /// Remove a recipient and re-key every secret it held under a new DEK.
    /// Returns the names whose real values the recipient has seen and whose
    /// source (the API key, the password) should be rotated: re-keying cannot
    /// take back what was already read.
    pub fn remove_recipient(&mut self, id: &[u8; 16]) -> Result<Vec<String>, Error> {
        let u = self.owner()?;
        if !u.model.recipients.iter().any(|r| &r.id == id) {
            return Err(Error::UnknownRecipient);
        }
        let mut rotate = Vec::new();
        for i in 0..u.model.secrets.len() {
            let holders = holder_ids(&u.model.secrets[i]);
            if !holders.contains(id) {
                continue;
            }
            let kept: Vec<[u8; 16]> = holders.into_iter().filter(|h| h != id).collect();
            let value =
                current::open_value(u.fmt, &u.model.header.vault_id, &u.vk, &u.model.secrets[i])?;
            reseal(u, i, value.expose(), &kept)?;
            let sid = u.model.secrets[i].secret_id;
            if let Some(e) = u.model.index.iter().find(|e| e.secret_id == sid) {
                rotate.push(e.name.clone());
            }
        }
        u.model.recipients.retain(|r| &r.id != id);
        Ok(rotate)
    }

    /// Let `recipient` read `name`.
    pub fn grant(&mut self, name: &str, recipient: &[u8; 16]) -> Result<(), Error> {
        let u = self.owner()?;
        let i = index_of(&u.model, name)?;
        let r = u
            .model
            .recipients
            .iter()
            .find(|r| &r.id == recipient)
            .cloned()
            .ok_or(Error::UnknownRecipient)?;
        let sealed = &u.model.secrets[i];
        if sealed.wraps.iter().any(|w| &w.recipient_id == recipient) {
            return Ok(());
        }
        let dek = current::open_dek(u.fmt, &u.model.header.vault_id, &u.vk, sealed)?;
        let wrap = current::wrap_for(u.fmt, &u.model.header.vault_id, &sealed.secret_id, &dek, &r)?;
        u.model.secrets[i].wraps.push(wrap);
        Ok(())
    }

    /// Stop `recipient` reading `name` from now on, and re-key the secret so
    /// the wrap it was given opens nothing in the new file.
    pub fn revoke(&mut self, name: &str, recipient: &[u8; 16]) -> Result<(), Error> {
        let u = self.owner()?;
        let i = index_of(&u.model, name)?;
        let holders = holder_ids(&u.model.secrets[i]);
        if !holders.contains(recipient) {
            return Ok(());
        }
        let kept: Vec<[u8; 16]> = holders.into_iter().filter(|h| h != recipient).collect();
        let value =
            current::open_value(u.fmt, &u.model.header.vault_id, &u.vk, &u.model.secrets[i])?;
        reseal(u, i, value.expose(), &kept)
    }

    /// Replace the password slot. The recovery slot is untouched.
    pub fn change_password(&mut self, new_password: &[u8], kdf: KdfParams) -> Result<(), Error> {
        let u = self.owner()?;
        let slot =
            current::password_slot(u.fmt, &u.model.header.vault_id, &u.vk, new_password, kdf)?;
        match u
            .model
            .slots
            .iter_mut()
            .find(|s| matches!(s, current::Slot::Password { .. }))
        {
            Some(existing) => *existing = slot,
            None => u.model.slots.insert(0, slot),
        }
        Ok(())
    }

    // --- Writing -------------------------------------------------------------------------------------

    /// Take the lock, save, release.
    pub fn save(&mut self, path: &Path, store: &LocalStore) -> Result<(), Error> {
        let lock = VaultLock::acquire(path)?;
        self.save_locked(path, store, &lock)
    }

    /// Save while the caller holds `_lock` (taken with `VaultLock::acquire`
    /// on the same path). Refuses with [`Error::Conflict`] if the file is no
    /// longer the one this was loaded from.
    pub fn save_locked(
        &mut self,
        path: &Path,
        store: &LocalStore,
        _lock: &VaultLock,
    ) -> Result<(), Error> {
        let base = self.base_generation;
        let from = self.upgraded_from;
        let u = self.owner()?;

        let existing = match fs::read(path) {
            Ok(b) => Some(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(source) => {
                return Err(Error::Io {
                    op: "read",
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let on_disk = match &existing {
            Some(bytes) => {
                let loaded = format::decode(bytes)?;
                if loaded.model().header.vault_id != u.model.header.vault_id {
                    return Err(Error::Conflict);
                }
                loaded.model().header.generation
            }
            None => 0,
        };
        if on_disk != base {
            return Err(Error::Conflict);
        }

        // The first write in a new format keeps the original beside it, once.
        if let (Some(from), Some(bytes)) = (from, &existing) {
            write_backup(path, from, bytes)?;
        }

        let generation = base + 1;
        let (old_generation, old_updated) = (u.model.header.generation, u.model.header.updated);
        u.model.header.generation = generation;
        u.model.header.updated = now();
        let key = current::owner_keys(&u.vk).sign;
        let result = current::encode(&u.model, &key).and_then(|bytes| write_atomic(path, &bytes));
        if let Err(e) = result {
            u.model.header.generation = old_generation;
            u.model.header.updated = old_updated;
            return Err(e);
        }
        let (id, pk) = (u.model.header.vault_id, u.model.owner.sign_pk);
        self.base_generation = generation;
        self.upgraded_from = None;
        store.record(&id, &pk, generation)
    }
}

fn backup_path(path: &Path, from: u16) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault.vht".to_string());
    path.with_file_name(format!("{name}.v{from}-backup"))
}

/// Copy the original bytes to `<vault>.v<N>-backup`, never overwriting one.
fn write_backup(path: &Path, from: u16, bytes: &[u8]) -> Result<(), Error> {
    let target = backup_path(path, from);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(&target) {
        Ok(mut f) => f
            .write_all(bytes)
            .and_then(|()| f.sync_all())
            .map_err(|source| Error::Io {
                op: "write the backup",
                path: target,
                source,
            }),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(source) => Err(Error::Io {
            op: "create the backup",
            path: target,
            source,
        }),
    }
}

fn index_of(m: &current::Model, name: &str) -> Result<usize, Error> {
    m.index
        .iter()
        .position(|e| e.name == name)
        .ok_or_else(|| Error::not_found(name))
}

fn find<'a>(m: &'a current::Model, name: &str) -> Result<(&'a Entry, &'a current::Sealed), Error> {
    let entry = &m.index[index_of(m, name)?];
    let sealed = m
        .secrets
        .iter()
        .find(|s| s.secret_id == entry.secret_id)
        .ok_or(Error::Corrupt("index and secrets disagree"))?;
    Ok((entry, sealed))
}

fn holder_ids(sealed: &current::Sealed) -> Vec<[u8; 16]> {
    sealed.wraps.iter().map(|w| w.recipient_id).collect()
}

/// Seal `value` again under a fresh DEK, wrapped for the owner and for the
/// recipients in `holders` that still exist, replacing secret `i`.
fn reseal(
    u: &mut current::Unlocked,
    i: usize,
    value: &[u8],
    holders: &[[u8; 16]],
) -> Result<(), Error> {
    let recipients: Vec<&Recipient> = holders
        .iter()
        .filter_map(|h| u.model.recipients.iter().find(|r| &r.id == h))
        .collect();
    let sid = u.model.secrets[i].secret_id;
    let sealed = current::seal_secret(
        u.fmt,
        &u.model.header.vault_id,
        sid,
        &u.vk,
        value,
        &recipients,
    )?;
    u.model.secrets[i] = sealed;
    Ok(())
}

#[cfg(test)]
#[path = "vault_tests.rs"]
mod tests;
