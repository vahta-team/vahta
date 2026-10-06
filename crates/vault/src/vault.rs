//! The operations on a vault: create, peek, unlock, edit, save.
//!
//! A [`Vault`] is opened by its owner (password or recovery key), who holds the
//! vault key and can do everything, or by a recipient. A recipient with the
//! role Admin or Editor can write: a new secret is sealed for the owner from
//! the public key in the file, and for the writer itself; the file is signed by
//! that recipient. A Runner only reads. Membership has one more rule: an Admin
//! added by the owner may add and remove Editors and Runners; only the owner
//! adds or removes Admins. A recipient sees and edits only the secrets it holds
//! a wrap for, and leaves every other secret's bytes exactly as they were.
//!
//! `save` is the only way a vault reaches disk. It checks that the file is
//! still the one that was loaded, makes the one-time backup if this save is an
//! upgrade, bumps the generation, signs, writes atomically and tells the local
//! store. Hold a [`VaultLock`] around load, modify and save when more than one
//! process may write; `save_locked` takes the lock you already hold.
//!
//! An owner unlock of an older format upgrades the vault in memory. If the
//! upgrade needs the paper key (a step rewrites the recovery slot) and the
//! vault was opened with the password, the vault is open and readable but
//! *blocked*: every write, including `save`, refuses with
//! [`Error::UpgradeNeedsRecoveryKey`] until [`Vault::provide_recovery_key`].

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use crate::crypto::{self, KEY_LEN, KdfParams};
use crate::format::current::{self, Actor, Entry, Kind, Recipient, RecipientKind, Role, Tier};
use crate::format::upgrade::{self, AnyUnlocked};
use crate::format::{self, CURRENT, Loaded, OwnerAccess, OwnerState};
use crate::session::SessionKeys;
use crate::store::{LocalStore, StateFile, StateKey};
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

/// What a comparison with this machine's store says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// The owner key matches the one pinned here and the generation is not
    /// lower than any seen.
    Pinned,
    /// This machine has not opened the vault yet, so there is nothing to
    /// compare the owner key with. The file is self-consistent, nothing more.
    Unpinned,
}

/// [`Verification`] plus how far it can be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    pub status: Verification,
    /// Always false for a peek: the state's MAC needs a key, and a peek has
    /// none. An opener checks it.
    pub mac_checked: bool,
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
    /// generation seen. The state's MAC is not checked (a peek holds no key).
    pub fn verified(&self, store: &LocalStore) -> Result<Verified, Error> {
        let status = match store.check_unauthenticated(
            &self.vault_id,
            &self.owner_sign_pk,
            self.generation,
        )? {
            Some(()) => Verification::Pinned,
            None => Verification::Unpinned,
        };
        Ok(Verified {
            status,
            mac_checked: false,
        })
    }
}

/// A recipient's opening: the file's model and the keys to read and sign with.
struct RecipientAccess {
    fmt: u16,
    model: current::Model,
    me: Recipient,
    enc_sk: Zeroizing<[u8; KEY_LEN]>,
    sign_sk: Zeroizing<[u8; KEY_LEN]>,
}

// One per open vault, never in a collection: the size difference costs nothing.
#[allow(clippy::large_enum_variant)]
enum Access {
    Owner(current::Unlocked),
    /// Opened by the owner, but the upgrade to the current format is waiting
    /// for the paper key. Readable; nothing can be written.
    Blocked {
        old: AnyUnlocked,
        typed: Option<Zeroizing<Vec<u8>>>,
    },
    Recipient(RecipientAccess),
}

/// An opened vault.
pub struct Vault {
    access: Access,
    /// The generation of the file this was loaded from; 0 for a new vault.
    base_generation: u64,
    /// The format the file had before an upgrade; the first save backs it up.
    upgraded_from: Option<u16>,
    /// Which state file in the local store is this opener's, and its key.
    state_key: StateKey,
    first_open: bool,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let role = match &self.access {
            Access::Owner(_) => "owner",
            Access::Blocked { .. } => "owner (upgrade blocked)",
            Access::Recipient(_) => "recipient",
        };
        f.debug_struct("Vault")
            .field("role", &role)
            .field("entries", &self.model().index.len())
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

/// What an edit needs: the model to change, who is changing it and with which
/// keys. Built by [`Vault::writer`], which is where permission is decided.
struct Writer<'a> {
    model: &'a mut current::Model,
    fmt: u16,
    actor: Actor,
    /// `None` for the owner, who may do everything; else the writer's role.
    role: Option<Role>,
    /// Whether the writer was itself added by the owner (a delegated admin
    /// must have been, or its certificates would not verify).
    added_by_owner: bool,
    signer: SigningKey,
    /// The writer's private encryption key, to open the DEKs it holds.
    enc_sk: Zeroizing<[u8; KEY_LEN]>,
}

impl Writer<'_> {
    fn vault_id(&self) -> [u8; 16] {
        self.model.header.vault_id
    }

    /// The DEK of secret `i`, if this writer can open it. The owner always can.
    fn dek(&self, i: usize) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>, Error> {
        let sealed = &self.model.secrets[i];
        match self.actor {
            Actor::Owner => {
                current::open_dek(self.fmt, &self.vault_id(), &self.enc_sk, sealed).map(Some)
            }
            Actor::Recipient(id) => current::open_dek_as_recipient(
                self.fmt,
                &self.vault_id(),
                &self.enc_sk,
                &id,
                sealed,
            ),
        }
    }

    fn holders(&self, i: usize) -> Vec<[u8; 16]> {
        self.model.secrets[i]
            .wraps
            .iter()
            .map(|w| w.recipient_id)
            .collect()
    }

    /// Seal `value` again under a fresh DEK for the owner and for the
    /// recipients in `holders` that still exist, replacing secret `i`.
    fn reseal(&mut self, i: usize, value: &[u8], holders: &[[u8; 16]]) -> Result<(), Error> {
        let recipients: Vec<&Recipient> = holders
            .iter()
            .filter_map(|h| self.model.recipients.iter().find(|r| &r.id == h))
            .collect();
        let sid = self.model.secrets[i].secret_id;
        let sealed = current::seal_secret(
            self.fmt,
            &self.vault_id(),
            sid,
            &self.model.owner.enc_pk,
            value,
            &recipients,
        )?;
        self.model.secrets[i] = sealed;
        Ok(())
    }

    fn index_of(&self, name: &str) -> Result<usize, Error> {
        self.model
            .index
            .iter()
            .position(|e| e.name == name)
            .ok_or_else(|| Error::not_found(name))
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
        let state_key = StateKey::owner(&unlocked.vk);
        let vault = Vault {
            access: Access::Owner(unlocked),
            base_generation: 0,
            upgraded_from: None,
            state_key,
            first_open: true,
        };
        Ok((vault, recovery.ok_or(Error::Rng)?))
    }

    /// A vault in the pseudo-format 0, written to `path`, for upgrade tests.
    /// Returns its paper key.
    #[cfg(test)]
    pub(crate) fn write_v0_for_test(
        path: &Path,
        pw: &[u8],
        items: &[(&str, &[u8])],
    ) -> Result<RecoveryKey, Error> {
        let (mut u, key) = format::testing::create_v0(pw)?;
        for (n, (name, value)) in items.iter().enumerate() {
            let mut sid = crypto::random::<16>()?;
            sid[0] = n as u8;
            let sealed = current::seal_secret(
                u.fmt,
                &u.model.header.vault_id,
                sid,
                &u.model.owner.enc_pk,
                value,
                &[],
            )?;
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
        let signer = current::owner_keys(&u.vk).sign;
        write_atomic(
            path,
            &current::encode_as(0, &u.model, Actor::Owner, &signer)?,
        )?;
        Ok(key)
    }

    // --- Opening ---------------------------------------------------------------------

    fn open_owner(
        path: &Path,
        access: OwnerAccess<'_>,
        store: &LocalStore,
    ) -> Result<Vault, Error> {
        let loaded = format::decode(&read_file(path)?)?;
        let typed = match &access {
            OwnerAccess::Password(pw) => Some(Zeroizing::new(pw.to_vec())),
            OwnerAccess::Recovery(_) => None,
        };
        // A swapped owner is refused before the KDF runs.
        store.check_owner_pin(
            &loaded.model().header.vault_id,
            StateFile::Owner,
            &loaded.model().owner.sign_pk,
        )?;
        let open = format::unlock_owner(&loaded, access)?;
        let (access, vk) = match open.state {
            OwnerState::Current(u) => {
                let vk = u.vk.clone();
                (Access::Owner(u), vk)
            }
            OwnerState::Blocked(old) => {
                let vk = old.as_v1().vk.clone();
                (Access::Blocked { old, typed }, vk)
            }
        };
        let model = loaded.model();
        // The state is authenticated with a key only an unlock yields, so this
        // runs after the unlock: a tampered state is refused as tampered, not
        // mistaken for a rollback it may have been edited to cause.
        let state_key = StateKey::owner(&vk);
        let checked = store.check(
            &model.header.vault_id,
            &state_key,
            &model.owner.sign_pk,
            model.header.generation,
        )?;
        // The unlock proved the vault key derives this owner key: pin it.
        store.record(
            &model.header.vault_id,
            &state_key,
            &model.owner.sign_pk,
            model.header.generation,
        )?;
        Ok(Vault {
            access,
            base_generation: model.header.generation,
            upgraded_from: open.from,
            state_key,
            first_open: checked.first_open,
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

    /// Open as a recipient. An Admin or Editor of a current-format vault can
    /// write; a Runner, or any recipient of an older format, only reads. The
    /// owner key is pinned on first open (trust on first use: a recipient
    /// cannot prove the owner's key the way an unlock does), in this
    /// recipient's own state file.
    pub fn open_as_recipient(
        path: &Path,
        recipient_id: &[u8; 16],
        keys: &RecipientSecret,
        store: &LocalStore,
    ) -> Result<Vault, Error> {
        let loaded = format::decode(&read_file(path)?)?;
        let m = loaded.model();
        let state_key = StateKey::recipient(*recipient_id, keys.sign_sk());
        let checked = store.check(
            &m.header.vault_id,
            &state_key,
            &m.owner.sign_pk,
            m.header.generation,
        )?;
        let open = format::unlock_recipient(&loaded, recipient_id, keys.enc_sk())?;
        store.record(
            &open.model.header.vault_id,
            &state_key,
            &open.model.owner.sign_pk,
            open.model.header.generation,
        )?;
        let base_generation = open.model.header.generation;
        Ok(Vault {
            access: Access::Recipient(RecipientAccess {
                fmt: open.fmt,
                model: open.model,
                me: open.recipient,
                enc_sk: Zeroizing::new(*keys.enc_sk()),
                sign_sk: Zeroizing::new(*keys.sign_sk()),
            }),
            base_generation,
            upgraded_from: None,
            state_key,
            first_open: checked.first_open,
        })
    }

    // --- Reading ------------------------------------------------------------------------

    fn model(&self) -> &current::Model {
        match &self.access {
            Access::Owner(u) => &u.model,
            Access::Blocked { old, .. } => &old.as_v1().model,
            Access::Recipient(r) => &r.model,
        }
    }

    pub fn vault_id(&self) -> [u8; 16] {
        self.model().header.vault_id
    }

    pub fn generation(&self) -> u64 {
        self.model().header.generation
    }

    /// Whether this was read from an older format and the next save will
    /// write it in the current one.
    pub fn upgrade_pending(&self) -> bool {
        self.upgraded_from.is_some()
    }

    /// Whether the pending upgrade is waiting for the paper key. While true,
    /// reads work and every write refuses with
    /// [`Error::UpgradeNeedsRecoveryKey`].
    pub fn blocked_on_recovery_key(&self) -> bool {
        matches!(self.access, Access::Blocked { .. })
    }

    /// Whether this machine had no record of this vault for this opener until
    /// now. For the caller to say so; nothing here prompts.
    pub fn first_open_on_this_machine(&self) -> bool {
        self.first_open
    }

    /// The index: every name, kind and tier, for any kind of opening.
    pub fn entries(&self) -> &[Entry] {
        &self.model().index
    }

    pub fn recipients(&self) -> &[Recipient] {
        &self.model().recipients
    }

    /// The value of `name`. A recipient gets only what it holds a wrap for.
    pub fn get(&self, name: &str) -> Result<SecretValue, Error> {
        let m = self.model();
        let i = m
            .index
            .iter()
            .position(|e| e.name == name)
            .ok_or_else(|| Error::not_found(name))?;
        let sealed = &m.secrets[i];
        match &self.access {
            Access::Owner(u) => {
                let keys = current::owner_keys(&u.vk);
                current::open_value(u.fmt, &m.header.vault_id, &keys.enc_sk, sealed)
            }
            Access::Blocked { old, .. } => {
                let u = old.as_v1();
                let keys = current::owner_keys(&u.vk);
                current::open_value(u.fmt, &m.header.vault_id, &keys.enc_sk, sealed)
            }
            Access::Recipient(r) => {
                let dek = current::open_dek_as_recipient(
                    r.fmt,
                    &m.header.vault_id,
                    &r.enc_sk,
                    &r.me.id,
                    sealed,
                )?
                .ok_or(Error::NoAccess)?;
                current::value_with_dek(r.fmt, &m.header.vault_id, &dek, sealed)
            }
        }
    }

    /// What a session keeps instead of the vault: the data keys of `names`,
    /// the store's MAC key, and the owner key and generation as they are now.
    /// The caller then drops the vault and with it the vault key. Owner only,
    /// since only the owner holds a wrap for every secret; a name that is not
    /// in the vault is [`Error::NotFound`].
    pub fn session_keys(&self, names: &[String]) -> Result<SessionKeys, Error> {
        let (fmt, vk) = match &self.access {
            Access::Owner(u) => (u.fmt, &u.vk),
            Access::Blocked { old, .. } => (old.as_v1().fmt, &old.as_v1().vk),
            Access::Recipient(_) => return Err(Error::NotOwner),
        };
        let m = self.model();
        let owner = current::owner_keys(vk);
        let mut keys = Vec::with_capacity(names.len());
        for name in names {
            let i = m
                .index
                .iter()
                .position(|e| &e.name == name)
                .ok_or_else(|| Error::not_found(name))?;
            let dek = current::open_dek(fmt, &m.header.vault_id, &owner.enc_sk, &m.secrets[i])?;
            keys.push((name.clone(), m.index[i].secret_id, dek));
        }
        Ok(SessionKeys::new(
            m.header.vault_id,
            m.owner.sign_pk,
            m.header.generation,
            *self.state_key.mac_key(),
            keys,
        ))
    }

    // --- Writing: who may ---------------------------------------------------------------

    /// The editing context for this opening, or the reason there is none.
    fn writer(&mut self) -> Result<Writer<'_>, Error> {
        match &mut self.access {
            Access::Owner(u) => {
                let keys = current::owner_keys(&u.vk);
                Ok(Writer {
                    fmt: u.fmt,
                    model: &mut u.model,
                    actor: Actor::Owner,
                    role: None,
                    added_by_owner: true,
                    signer: keys.sign,
                    enc_sk: keys.enc_sk,
                })
            }
            Access::Blocked { .. } => Err(Error::UpgradeNeedsRecoveryKey),
            Access::Recipient(r) => {
                if r.me.role == Role::Runner || r.fmt != CURRENT {
                    return Err(Error::NotPermitted);
                }
                Ok(Writer {
                    fmt: r.fmt,
                    actor: Actor::Recipient(r.me.id),
                    role: Some(r.me.role),
                    added_by_owner: r.me.added_by == Actor::Owner,
                    signer: crypto::signing_key(&r.sign_sk),
                    enc_sk: r.enc_sk.clone(),
                    model: &mut r.model,
                })
            }
        }
    }

    // --- Editing secrets ------------------------------------------------------------------

    /// Add or replace a secret. Every change seals under a new DEK. A new
    /// secret is sealed for the owner and for the writer if it is a recipient;
    /// replacing one keeps its holders, and a recipient can only replace a
    /// secret it can read.
    pub fn set(&mut self, name: &str, value: &[u8], kind: Kind, tier: Tier) -> Result<(), Error> {
        if !valid_name(name) {
            return Err(Error::InvalidName);
        }
        if let Kind::File { file_name } = &kind
            && !current::valid_file_name(file_name)
        {
            return Err(Error::InvalidFileName);
        }
        let mut w = self.writer()?;
        match w.model.index.iter().position(|e| e.name == name) {
            Some(i) => {
                if w.dek(i)?.is_none() {
                    return Err(Error::NoAccess);
                }
                let holders = w.holders(i);
                w.reseal(i, value, &holders)?;
                let actor = w.actor;
                let e = &mut w.model.index[i];
                e.kind = kind;
                e.tier = tier;
                e.updated = now();
                e.changed_by = actor;
            }
            None => {
                let sid = crypto::random::<16>()?;
                let actor = w.actor;
                let mine: Vec<&Recipient> = match actor {
                    Actor::Owner => Vec::new(),
                    Actor::Recipient(id) => {
                        w.model.recipients.iter().filter(|r| r.id == id).collect()
                    }
                };
                let sealed = current::seal_secret(
                    w.fmt,
                    &w.vault_id(),
                    sid,
                    &w.model.owner.enc_pk,
                    value,
                    &mine,
                )?;
                w.model.secrets.push(sealed);
                w.model.index.push(Entry {
                    secret_id: sid,
                    name: name.to_string(),
                    kind,
                    tier,
                    updated: now(),
                    changed_by: actor,
                });
            }
        }
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Result<(), Error> {
        let w = self.writer()?;
        let i = w.index_of(name)?;
        w.model.index.remove(i);
        w.model.secrets.remove(i);
        Ok(())
    }

    pub fn set_tier(&mut self, name: &str, tier: Tier) -> Result<(), Error> {
        let w = self.writer()?;
        let i = w.index_of(name)?;
        let actor = w.actor;
        let e = &mut w.model.index[i];
        e.tier = tier;
        e.updated = now();
        e.changed_by = actor;
        Ok(())
    }

    /// Add several secrets at once, refusing the whole batch if any name is
    /// already taken or invalid. Used by the ka import.
    pub fn import(&mut self, items: Vec<(String, SecretValue)>) -> Result<(), Error> {
        {
            let w = self.writer()?;
            for (i, (name, _)) in items.iter().enumerate() {
                if !valid_name(name) {
                    return Err(Error::InvalidName);
                }
                if w.model.index.iter().any(|e| &e.name == name)
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

    // --- Editing membership ---------------------------------------------------------------------

    /// Add a recipient and return its id. The owner may add anyone; an Admin
    /// the owner added may add Editors and Runners; no one else adds.
    pub fn add_recipient(
        &mut self,
        name: &str,
        kind: RecipientKind,
        role: Role,
        public: &RecipientPublic,
    ) -> Result<[u8; 16], Error> {
        let w = self.writer()?;
        match w.role {
            None => {}
            Some(Role::Admin) if w.added_by_owner && role != Role::Admin => {}
            Some(_) => return Err(Error::NotPermitted),
        }
        if name.is_empty()
            || name.len() > 128
            || name.chars().any(char::is_control)
            || w.model.recipients.iter().any(|r| r.name == name)
        {
            return Err(Error::Corrupt("recipient name"));
        }
        let id = crypto::random::<16>()?;
        let mut entry = Recipient {
            id,
            name: name.to_string(),
            kind,
            role,
            enc_pk: public.enc_pk,
            sign_pk: public.sign_pk,
            added: now(),
            added_by: w.actor,
            cert: current::Sig([0; 64]),
        };
        entry.certify(&w.vault_id(), &w.signer);
        w.model.recipients.push(entry);
        Ok(id)
    }

    /// Remove a recipient and re-key every secret it held under a new DEK.
    /// Returns the names whose real values the recipient has seen and whose
    /// source (the API key, the password) should be rotated: re-keying cannot
    /// take back what was already read. A secret the writer cannot itself read
    /// (an Admin removing a member of a secret it does not hold) cannot be
    /// re-keyed: the recipient's wrap is dropped and the name is returned too.
    ///
    /// The owner may remove anyone; an Admin may remove Editors and Runners.
    /// When the owner removes an Admin, the members that Admin added are
    /// re-certified by the owner so they stay valid.
    pub fn remove_recipient(&mut self, id: &[u8; 16]) -> Result<Vec<String>, Error> {
        let mut w = self.writer()?;
        let target = w
            .model
            .recipients
            .iter()
            .find(|r| &r.id == id)
            .cloned()
            .ok_or(Error::UnknownRecipient)?;
        match w.role {
            None => {}
            Some(Role::Admin) if target.role != Role::Admin => {}
            Some(_) => return Err(Error::NotPermitted),
        }
        let mut rotate = Vec::new();
        for i in 0..w.model.secrets.len() {
            let holders = w.holders(i);
            if !holders.contains(id) {
                continue;
            }
            let kept: Vec<[u8; 16]> = holders.into_iter().filter(|h| h != id).collect();
            match w.dek(i)? {
                Some(dek) => {
                    let value =
                        current::value_with_dek(w.fmt, &w.vault_id(), &dek, &w.model.secrets[i])?;
                    w.reseal(i, value.expose(), &kept)?;
                }
                None => w.model.secrets[i].wraps.retain(|x| &x.recipient_id != id),
            }
            rotate.push(w.model.index[i].name.clone());
        }
        w.model.recipients.retain(|r| &r.id != id);
        if target.role == Role::Admin {
            let vault_id = w.vault_id();
            for r in w.model.recipients.iter_mut() {
                if r.added_by == Actor::Recipient(*id) {
                    r.added_by = Actor::Owner;
                    r.certify(&vault_id, &w.signer);
                }
            }
        }
        Ok(rotate)
    }

    /// Let `recipient` read `name`. The writer must be able to read it.
    pub fn grant(&mut self, name: &str, recipient: &[u8; 16]) -> Result<(), Error> {
        let w = self.writer()?;
        let i = w.index_of(name)?;
        let target = w
            .model
            .recipients
            .iter()
            .find(|r| &r.id == recipient)
            .cloned()
            .ok_or(Error::UnknownRecipient)?;
        if w.model.secrets[i]
            .wraps
            .iter()
            .any(|x| &x.recipient_id == recipient)
        {
            return Ok(());
        }
        let dek = w.dek(i)?.ok_or(Error::NoAccess)?;
        let wrap = current::wrap_for(
            w.fmt,
            &w.vault_id(),
            &w.model.secrets[i].secret_id,
            &dek,
            &target,
        )?;
        w.model.secrets[i].wraps.push(wrap);
        Ok(())
    }

    /// Stop `recipient` reading `name` from now on, and re-key the secret so
    /// the wrap it was given opens nothing in the new file. The writer must be
    /// able to read it.
    pub fn revoke(&mut self, name: &str, recipient: &[u8; 16]) -> Result<(), Error> {
        let mut w = self.writer()?;
        let i = w.index_of(name)?;
        let holders = w.holders(i);
        let dek = w.dek(i)?.ok_or(Error::NoAccess)?;
        if !holders.contains(recipient) {
            return Ok(());
        }
        let kept: Vec<[u8; 16]> = holders.into_iter().filter(|h| h != recipient).collect();
        let value = current::value_with_dek(w.fmt, &w.vault_id(), &dek, &w.model.secrets[i])?;
        w.reseal(i, value.expose(), &kept)
    }

    /// Replace the password slot. The recovery slot is untouched. Owner only.
    pub fn change_password(&mut self, new_password: &[u8], kdf: KdfParams) -> Result<(), Error> {
        let u = match &mut self.access {
            Access::Owner(u) => u,
            Access::Blocked { .. } => return Err(Error::UpgradeNeedsRecoveryKey),
            Access::Recipient(_) => return Err(Error::NotOwner),
        };
        let slot = current::password_slot(&u.model.header.vault_id, &u.vk, new_password, kdf)?;
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

    /// Finish an upgrade that was waiting for the paper key. The key must be
    /// the one that opens the vault's recovery slot, so a wrong one cannot
    /// replace it. Does nothing if the vault is not blocked.
    pub fn provide_recovery_key(&mut self, key: &RecoveryKey) -> Result<(), Error> {
        let Access::Blocked { old, typed } = &self.access else {
            return Ok(());
        };
        if !current::recovery_key_matches(&old.as_v1().model, key) {
            return Err(Error::Unlock);
        }
        let upgraded = upgrade::to_current(old, typed.as_ref().map(|t| t.as_slice()), Some(key))?;
        self.access = Access::Owner(upgraded);
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
    /// longer the one this was loaded from. Signed by the owner, or by the
    /// recipient that opened it (never a Runner). A recipient's save records the
    /// generation in its own state and never pins a different owner.
    pub fn save_locked(
        &mut self,
        path: &Path,
        store: &LocalStore,
        _lock: &VaultLock,
    ) -> Result<(), Error> {
        let base = self.base_generation;
        let from = self.upgraded_from;
        let w = self.writer()?;
        let (fmt, actor, signer) = (w.fmt, w.actor, w.signer.clone());
        let model = w.model;

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
                if loaded.model().header.vault_id != model.header.vault_id {
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
        let (old_generation, old_updated) = (model.header.generation, model.header.updated);
        model.header.generation = generation;
        model.header.updated = now();
        let result = current::encode_as(fmt, model, actor, &signer)
            .and_then(|bytes| write_atomic(path, &bytes));
        if let Err(e) = result {
            model.header.generation = old_generation;
            model.header.updated = old_updated;
            return Err(e);
        }
        let (id, pk) = (model.header.vault_id, model.owner.sign_pk);
        self.base_generation = generation;
        self.upgraded_from = None;
        store.record(&id, &self.state_key, &pk, generation)
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

#[cfg(test)]
#[path = "vault_tests.rs"]
mod tests;
