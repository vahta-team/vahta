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
use crate::format::current::{
    self, Actor, AgentRole, Class, Device, Entry, Kind, NewSlot, Recipient, RecipientKind, Role,
    RuleSet, SlotInfo, Tier, VaultKind,
};
use crate::format::upgrade::{self, AnyUnlocked};
use crate::format::{self, CURRENT, Loaded, OwnerAccess, OwnerState};
use crate::session::SessionKeys;
use crate::store::{Checked, LocalStore, StateFile, StateKey};
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
    /// Only from [`Peek::verified_for_unlock`]: this machine pinned an older
    /// owner key, and the file's successor chain leads from it to the file's
    /// owner. Nothing is established yet: the file is acceptable only if the
    /// person opens it here and confirms (see `Vault::unlock_password_accepting`).
    OwnerChangePending,
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
    /// The approved command rules, covered by the owner's signature.
    pub bindings: Vec<RuleSet>,
    pub recipient_count: usize,
    /// The key slots as the file lists them, with the public parameters each
    /// kind needs to derive its key-encryption key. No secret part.
    pub slots: Vec<SlotView>,
    /// The paired devices, covered by the owner's signature.
    pub devices: Vec<Device>,
    /// The owner successor chain (empty before format 3), oldest first.
    pub successors: Vec<current::Successor>,
    /// The person's opt-in to use from other projects (false before format 4).
    pub remote: bool,
    /// What the vault is for (`Project` before format 5).
    pub kind: VaultKind,
    /// A member's package, not a vault: it opens with the member's identity
    /// and has no owner password (see `member::is_package`).
    pub package: bool,
    /// The agent roles the person approved, covered by the owner's signature.
    pub roles: Vec<AgentRole>,
}

impl Peek {
    /// The vault as seen from another project (remote use): only the secrets
    /// whose `from` list covers `project`, with their rules. Any other name is
    /// simply not there.
    pub fn visible_from(mut self, project: &Path) -> Peek {
        self.bindings
            .retain(|b| crate::project::covers(&b.from, project));
        let names: Vec<&str> = self.bindings.iter().map(|b| b.name.as_str()).collect();
        self.entries.retain(|e| names.contains(&e.name.as_str()));
        // A role that names a secret not visible from here is not either.
        let entries = &self.entries;
        self.roles.retain(|r| {
            r.secrets
                .iter()
                .all(|s| entries.iter().any(|e| &e.name == s))
        });
        self
    }
}

/// A slot as a reader without a key sees it: its description and its public
/// parameters (a password slot's salt and cost, a device slot's ephemeral
/// public key). The wrapped vault key is not part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotView {
    pub info: SlotInfo,
    pub params: Vec<u8>,
}

impl Peek {
    /// [`Peek::verified`] for a caller that is about to unlock the vault and
    /// can ask the person about an owner re-key: a chain-linked owner change
    /// is [`Verification::OwnerChangePending`] instead of `OwnerChanged`. A
    /// caller that would act on what the peek shows, with no unlock, must use
    /// [`Peek::verified`]: an unconfirmed chain proves nothing about the rules
    /// and names in the file.
    pub fn verified_for_unlock(&self, store: &LocalStore) -> Result<Verified, Error> {
        match self.verified(store) {
            Err(Error::OwnerChanged) => {
                let pinned = store
                    .load_unchecked(&self.vault_id, StateFile::Owner)?
                    .ok_or(Error::OwnerChanged)?;
                let chain_leads_here =
                    current::path_from(&self.successors, &pinned.pinned_owner_sign_pk).is_some_and(
                        |p| {
                            p.last()
                                .is_some_and(|l| l.new_owner_sign_pub == self.owner_sign_pk)
                        },
                    );
                if !chain_leads_here {
                    return Err(Error::OwnerChanged);
                }
                if self.generation < pinned.max_generation {
                    return Err(Error::RolledBack {
                        found: self.generation,
                        seen: pinned.max_generation,
                    });
                }
                Ok(Verified {
                    status: Verification::OwnerChangePending,
                    mac_checked: false,
                })
            }
            other => other,
        }
    }

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

/// An owner key change this machine is being asked to accept: the file's
/// owner is not the one pinned here, but the file's successor chain leads from
/// the pinned key to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerKeyChange {
    pub vault_id: [u8; 16],
    /// When the last re-key in the chain was made (Unix seconds).
    pub changed_at: u64,
    /// The owner generation reached (see `Successor::generation`).
    pub owner_generation: u64,
    pub old_owner_sign_pk: [u8; 32],
    pub new_owner_sign_pk: [u8; 32],
}

/// The person's answer: `true` accepts the new owner key on this machine.
/// Called only after the vault has been opened here with the person's own
/// secret.
pub type Consent<'a> = &'a mut dyn FnMut(&OwnerKeyChange) -> bool;

/// The change that leads from `pinned` to the owner of `loaded`, if the file's
/// chain links them.
fn change_from(loaded: &Loaded, pinned: &[u8; 32]) -> Option<OwnerKeyChange> {
    let chain = loaded.successors();
    let path = current::path_from(&chain, pinned)?;
    let last = path.last()?;
    Some(OwnerKeyChange {
        vault_id: loaded.header().vault_id,
        changed_at: last.created_at,
        owner_generation: last.generation,
        old_owner_sign_pk: *pinned,
        new_owner_sign_pk: last.new_owner_sign_pub,
    })
}

/// What [`Vault::rekey`] does with the recovery slot.
pub enum RecoveryPlan<'a> {
    /// Wrap the new key under the same paper key, which must open the current
    /// recovery slot.
    Keep(&'a RecoveryKey),
    /// A new paper key; the old one stops working. It is returned once.
    Replace,
}

/// A slot [`Vault::rekey`] carries over: its description and the function that
/// wraps the new vault key for it (as for [`Vault::add_slot`]).
pub struct KeptSlot<'a> {
    pub new: NewSlot,
    #[allow(clippy::type_complexity)]
    pub wrap: Box<dyn FnOnce(&[u8; KEY_LEN], &[u8]) -> Result<Vec<u8>, Error> + 'a>,
}

/// What a re-key leaves for the caller.
pub struct RekeyOutcome {
    /// The new paper key, with `RecoveryPlan::Replace`. Show it once.
    pub recovery: Option<RecoveryKey>,
    /// The slots that were dropped (not password, not recovery, not kept).
    pub dropped: Vec<SlotInfo>,
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
        /// The older structure read as the current types, for reads.
        view: current::Model,
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
    /// Set by `rekey`: the store still holds the pin and MAC key of the old
    /// vault key, and the next save moves them (see `rekey`).
    repin: Option<Repin>,
}

/// What a re-keyed vault must tell the local store when it is saved.
struct Repin {
    old_state_key: StateKey,
    old_owner_sign_pk: [u8; 32],
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
    let header = loaded.header();
    Peek {
        vault_id: header.vault_id,
        format: loaded.format(),
        upgrade_pending: loaded.upgrade_pending(),
        generation: header.generation,
        updated: header.updated,
        owner_sign_pk: loaded.owner().sign_pk,
        signer: loaded.signer(),
        entries: loaded.index().to_vec(),
        bindings: loaded.rule_sets(),
        recipient_count: loaded.recipient_count(),
        slots: loaded
            .slots()
            .iter()
            .map(|s| SlotView {
                info: s.info(),
                params: s.params.clone(),
            })
            .collect(),
        devices: loaded.devices(),
        successors: loaded.successors(),
        remote: loaded.remote(),
        kind: loaded.kind(),
        package: loaded
            .current()
            .is_some_and(|d| crate::member::is_package(&d.model)),
        roles: loaded.roles(),
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
        Vault::create_with_kind(pw, kdf, VaultKind::Project)
    }

    /// [`Vault::create`] for a vault of `kind`. The kind is fixed here: there
    /// is no way to change it later, in memory or in the file.
    pub fn create_with_kind(
        pw: &[u8],
        kdf: KdfParams,
        kind: VaultKind,
    ) -> Result<(Vault, RecoveryKey), Error> {
        let (mut unlocked, recovery) = current::create(CURRENT, pw, kdf, true)?;
        unlocked.model.kind = kind;
        let state_key = StateKey::owner(&unlocked.vk);
        let vault = Vault {
            access: Access::Owner(unlocked),
            base_generation: 0,
            upgraded_from: None,
            state_key,
            first_open: true,
            repin: None,
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
        Vault::write_old_for_test(0, path, pw, items)
    }

    /// A vault in the real format 1, written to `path`, for upgrade tests.
    #[cfg(test)]
    pub(crate) fn write_v1_for_test(
        path: &Path,
        pw: &[u8],
        items: &[(&str, &[u8])],
    ) -> Result<RecoveryKey, Error> {
        Vault::write_old_for_test(1, path, pw, items)
    }

    #[cfg(test)]
    fn write_old_for_test(
        fmt: u16,
        path: &Path,
        pw: &[u8],
        items: &[(&str, &[u8])],
    ) -> Result<RecoveryKey, Error> {
        let (mut u, key) = format::v1::create(fmt, pw, KdfParams::TEST, true)?;
        let key = key.ok_or(Error::Rng)?;
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
                class: None,
            });
        }
        u.model.header.generation = 1;
        let signer = current::owner_keys(&u.vk).sign;
        write_atomic(
            path,
            &format::v1::encode_as(fmt, &u.model, Actor::Owner, &signer)?,
        )?;
        Ok(key)
    }

    // --- Opening ---------------------------------------------------------------------

    fn open_owner(
        path: &Path,
        access: OwnerAccess<'_>,
        store: &LocalStore,
        consent: Option<Consent<'_>>,
    ) -> Result<Vault, Error> {
        let loaded = format::decode(&read_file(path)?)?;
        // A member's package has no owner password: say what it is.
        if loaded
            .current()
            .is_some_and(|d| crate::member::is_package(&d.model))
        {
            return Err(Error::Package);
        }
        let typed = match &access {
            OwnerAccess::Password(pw) => Some(Zeroizing::new(pw.to_vec())),
            OwnerAccess::Recovery(_) | OwnerAccess::Slot(..) => None,
        };
        // A swapped owner is refused before the KDF runs, unless the file's
        // successor chain leads from the pinned key to this one and there is
        // someone to ask: then the unlock below decides.
        let mut pending: Option<OwnerKeyChange> = None;
        match store.check_owner_pin(
            &loaded.header().vault_id,
            StateFile::Owner,
            &loaded.owner().sign_pk,
        ) {
            Ok(()) => {}
            Err(Error::OwnerChanged) if consent.is_some() => {
                let state = store
                    .load_unchecked(&loaded.header().vault_id, StateFile::Owner)?
                    .ok_or(Error::OwnerChanged)?;
                let change =
                    change_from(&loaded, &state.pinned_owner_sign_pk).ok_or(Error::OwnerChanged)?;
                if loaded.header().generation < state.max_generation {
                    return Err(Error::RolledBack {
                        found: loaded.header().generation,
                        seen: state.max_generation,
                    });
                }
                pending = Some(change);
            }
            Err(e) => return Err(e),
        }
        let open = format::unlock_owner(&loaded, access)?;
        let (access, vk) = match open.state {
            OwnerState::Current(u) => {
                let vk = u.vk.clone();
                (Access::Owner(u), vk)
            }
            OwnerState::Blocked(old) => {
                let vk = old.as_v1().vk.clone();
                let view = current::Model::from_v1(&old.as_v1().model);
                (Access::Blocked { old, view, typed }, vk)
            }
        };
        let (header, owner) = (loaded.header(), loaded.owner());
        // The state is authenticated with a key only an unlock yields, so this
        // runs after the unlock: a tampered state is refused as tampered, not
        // mistaken for a rollback it may have been edited to cause.
        let state_key = StateKey::owner(&vk);
        let first_open = match (pending, consent) {
            (Some(change), Some(ask)) => {
                // The vault opened here with the person's own secret. Now the
                // person decides; no answer is a no.
                if !ask(&change) {
                    return Err(Error::OwnerChanged);
                }
                store.adopt_owner(
                    &header.vault_id,
                    &state_key,
                    &change.old_owner_sign_pk,
                    &owner.sign_pk,
                    header.generation,
                )?;
                false
            }
            _ => {
                store
                    .check(
                        &header.vault_id,
                        &state_key,
                        &owner.sign_pk,
                        header.generation,
                    )?
                    .first_open
            }
        };
        // The unlock proved the vault key derives this owner key: pin it.
        store.record(
            &header.vault_id,
            &state_key,
            &owner.sign_pk,
            header.generation,
        )?;
        Ok(Vault {
            access,
            base_generation: header.generation,
            upgraded_from: open.from,
            state_key,
            first_open,
            repin: None,
        })
    }

    /// Unlock with the password. An older format is upgraded in memory; the
    /// next `save` writes it (after backing up the original).
    pub fn unlock_password(path: &Path, pw: &[u8], store: &LocalStore) -> Result<Vault, Error> {
        Vault::open_owner(path, OwnerAccess::Password(pw), store, None)
    }

    /// [`Vault::unlock_password`] that can follow an owner re-key made on
    /// another machine: if this machine pinned an older owner key and the
    /// file's successor chain leads from it to the file's owner, then once the
    /// password has opened the vault `consent` is asked. A `true` re-pins the
    /// new key; `false` is [`Error::OwnerChanged`], as without a chain.
    pub fn unlock_password_accepting(
        path: &Path,
        pw: &[u8],
        store: &LocalStore,
        consent: Consent<'_>,
    ) -> Result<Vault, Error> {
        Vault::open_owner(path, OwnerAccess::Password(pw), store, Some(consent))
    }

    pub fn unlock_recovery(
        path: &Path,
        key: &RecoveryKey,
        store: &LocalStore,
    ) -> Result<Vault, Error> {
        Vault::open_owner(path, OwnerAccess::Recovery(key), store, None)
    }

    /// [`Vault::unlock_recovery`] with the owner-change consent of
    /// [`Vault::unlock_password_accepting`].
    pub fn unlock_recovery_accepting(
        path: &Path,
        key: &RecoveryKey,
        store: &LocalStore,
        consent: Consent<'_>,
    ) -> Result<Vault, Error> {
        Vault::open_owner(path, OwnerAccess::Recovery(key), store, Some(consent))
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
        Vault::open_as_recipient_with(path, recipient_id, keys, store, None)
    }

    /// [`Vault::open_as_recipient`] that can follow an owner re-key: when the
    /// owner key this recipient pinned is replaced by a chain-linked one, and
    /// the recipient's own keys open the file, `consent` decides whether to
    /// re-pin (as [`Vault::unlock_password_accepting`] does for an owner).
    pub fn open_as_recipient_accepting(
        path: &Path,
        recipient_id: &[u8; 16],
        keys: &RecipientSecret,
        store: &LocalStore,
        consent: Consent<'_>,
    ) -> Result<Vault, Error> {
        Vault::open_as_recipient_with(path, recipient_id, keys, store, Some(consent))
    }

    fn open_as_recipient_with(
        path: &Path,
        recipient_id: &[u8; 16],
        keys: &RecipientSecret,
        store: &LocalStore,
        consent: Option<Consent<'_>>,
    ) -> Result<Vault, Error> {
        let loaded = format::decode(&read_file(path)?)?;
        let (header, owner) = (loaded.header(), loaded.owner());
        // A member compares files by the generation the owner gave them, not
        // by its own file's, which its local saves move.
        let owner_generation = loaded.owner_generation();
        let state_key = StateKey::recipient(*recipient_id, keys.sign_sk());
        let mut moved: Option<OwnerKeyChange> = None;
        let checked = match store.check(
            &header.vault_id,
            &state_key,
            &owner.sign_pk,
            owner_generation,
        ) {
            Ok(c) => c,
            Err(Error::OwnerChanged) if consent.is_some() => {
                // This recipient's state is keyed by its own signing key, so it
                // can be authenticated here, unlike an owner's.
                let state = store
                    .state(&header.vault_id, &state_key)?
                    .ok_or(Error::OwnerChanged)?;
                let change =
                    change_from(&loaded, &state.pinned_owner_sign_pk).ok_or(Error::OwnerChanged)?;
                if owner_generation < state.max_generation {
                    return Err(Error::RolledBack {
                        found: owner_generation,
                        seen: state.max_generation,
                    });
                }
                moved = Some(change);
                Checked { first_open: false }
            }
            Err(e) => return Err(e),
        };
        let open = format::unlock_recipient(&loaded, recipient_id, keys.enc_sk())?;
        // The expiry is covered by the owner's certificate on the entry, so a
        // member cannot move it. It is enforced here, by the member's own
        // software: a member who patches this out still holds the keys.
        if open.recipient.expires_at.is_some_and(|t| now() >= t) {
            return Err(Error::MembershipExpired);
        }
        if let (Some(change), Some(ask)) = (moved, consent) {
            if !ask(&change) {
                return Err(Error::OwnerChanged);
            }
            store.repin_owner(
                &header.vault_id,
                &state_key,
                &change.old_owner_sign_pk,
                &state_key,
                &owner.sign_pk,
                owner_generation,
            )?;
        }
        store.record(
            &open.model.header.vault_id,
            &state_key,
            &open.model.owner.sign_pk,
            open.model.team.owner_generation,
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
            repin: None,
        })
    }

    // --- Reading ------------------------------------------------------------------------

    fn model(&self) -> &current::Model {
        match &self.access {
            Access::Owner(u) => &u.model,
            Access::Blocked { view, .. } => view,
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
            Access::Recipient(r) => return self.recipient_session_keys(r, names),
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
            self.state_key.file(),
            *self.state_key.mac_key(),
            None,
            keys,
        ))
    }

    /// [`Vault::session_keys`] for a member: the data keys of the secrets it
    /// holds a wrap for, the member's own state file and MAC key, and the end
    /// of its membership, after which the keys open nothing.
    fn recipient_session_keys(
        &self,
        r: &RecipientAccess,
        names: &[String],
    ) -> Result<SessionKeys, Error> {
        let m = &r.model;
        let mut keys = Vec::with_capacity(names.len());
        for name in names {
            let i = m
                .index
                .iter()
                .position(|e| &e.name == name)
                .ok_or_else(|| Error::not_found(name))?;
            let dek = current::open_dek_as_recipient(
                r.fmt,
                &m.header.vault_id,
                &r.enc_sk,
                &r.me.id,
                &m.secrets[i],
            )?
            .ok_or(Error::NoAccess)?;
            keys.push((name.clone(), m.index[i].secret_id, dek));
        }
        Ok(SessionKeys::new(
            m.header.vault_id,
            m.owner.sign_pk,
            m.team.owner_generation,
            self.state_key.file(),
            *self.state_key.mac_key(),
            r.me.expires_at,
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
                // A new value may be another kind of key; the caller sets the
                // class again from what it was given.
                e.class = None;
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
                    class: None,
                });
            }
        }
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Result<(), Error> {
        let w = self.writer()?;
        let i = w.index_of(name)?;
        let name = w.model.index[i].name.clone();
        w.model.index.remove(i);
        w.model.secrets.remove(i);
        w.model.bindings.retain(|b| b.name != name);
        for r in w.model.roles.iter_mut() {
            r.secrets.retain(|s| s != &name);
        }
        Ok(())
    }

    /// Record what `name` guards (or forget it with `None`).
    pub fn set_class(&mut self, name: &str, class: Option<Class>) -> Result<(), Error> {
        let w = self.writer()?;
        let i = w.index_of(name)?;
        if w.dek(i)?.is_none() {
            return Err(Error::NoAccess);
        }
        let actor = w.actor;
        let e = &mut w.model.index[i];
        e.class = class;
        e.updated = now();
        e.changed_by = actor;
        Ok(())
    }

    /// Replace the approved command rules of `name`, or remove them with
    /// `None`. A binding with no rules is the same as none. Goes through the
    /// writer like every edit, so it needs the opening to be able to sign.
    pub fn set_bindings(&mut self, name: &str, binding: Option<RuleSet>) -> Result<(), Error> {
        let w = self.writer()?;
        let i = w.index_of(name)?;
        if w.dek(i)?.is_none() {
            return Err(Error::NoAccess);
        }
        // Same checks a reader applies, so a bad rule set is refused here and
        // not by the next open, and before anything is changed.
        let new = match binding {
            Some(mut b) if !b.is_empty() => {
                b.name = name.to_string();
                current::check_binding_shapes(std::slice::from_ref(&b))?;
                // Harnesses belong to a connectors vault.
                if !b.harnesses.is_empty() && w.model.kind != VaultKind::Connectors {
                    return Err(Error::Invalid("harnesses"));
                }
                Some(b)
            }
            _ => None,
        };
        w.model.bindings.retain(|b| b.name != name);
        w.model.bindings.extend(new);
        let actor = w.actor;
        let e = &mut w.model.index[i];
        e.updated = now();
        e.changed_by = actor;
        Ok(())
    }

    /// Whether the person opted this vault in to use from projects other than
    /// its own.
    pub fn remote(&self) -> bool {
        self.model().remote
    }

    /// Turn the remote-use opt-in on or off. Signed like every edit.
    pub fn set_remote(&mut self, on: bool) -> Result<(), Error> {
        let w = self.writer()?;
        if w.actor != Actor::Owner {
            return Err(Error::NotPermitted);
        }
        w.model.remote = on;
        Ok(())
    }

    /// What the vault is for. Fixed when it is created.
    pub fn kind(&self) -> VaultKind {
        self.model().kind
    }

    /// The agent roles the person approved.
    pub fn roles(&self) -> &[AgentRole] {
        &self.model().roles
    }

    /// Add a role, or replace the one with the same name. Owner only, like
    /// every approval. The shape is checked as a reader would check it, and
    /// every secret it names must be in the vault; nothing changes on error.
    pub fn set_role(&mut self, role: AgentRole) -> Result<(), Error> {
        let w = self.writer()?;
        if w.actor != Actor::Owner {
            return Err(Error::NotPermitted);
        }
        current::check_role(&role)?;
        if let Some(missing) = role
            .secrets
            .iter()
            .find(|s| !w.model.index.iter().any(|e| &e.name == *s))
        {
            return Err(Error::not_found(missing));
        }
        let mut roles = w.model.roles.clone();
        match roles.iter_mut().find(|r| r.name == role.name) {
            Some(existing) => *existing = role,
            None => roles.push(role),
        }
        current::check_roles(&roles).map_err(|_| Error::Invalid("roles"))?;
        w.model.roles = roles;
        Ok(())
    }

    /// Remove the role called `name`. Owner only.
    pub fn remove_role(&mut self, name: &str) -> Result<(), Error> {
        let w = self.writer()?;
        if w.actor != Actor::Owner {
            return Err(Error::NotPermitted);
        }
        let before = w.model.roles.len();
        w.model.roles.retain(|r| r.name != name);
        if w.model.roles.len() == before {
            return Err(Error::not_found(name));
        }
        Ok(())
    }

    /// The approved command rules of every bound secret.
    pub fn bindings(&self) -> &[RuleSet] {
        &self.model().bindings
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
            expires_at: None,
            cert: current::Sig([0; 64]),
        };
        entry.certify(&w.vault_id(), &w.signer);
        w.model.recipients.push(entry);
        Ok(id)
    }

    /// Set when `id`'s membership ends, or clear it with `None`, and certify
    /// the entry again, since the certificate covers it. Allowed to whoever
    /// may add that member: the owner, or an Admin the owner added for an
    /// Editor or a Runner. The writer becomes the entry's issuer.
    pub fn set_recipient_expiry(
        &mut self,
        id: &[u8; 16],
        expires_at: Option<u64>,
    ) -> Result<(), Error> {
        let w = self.writer()?;
        let target_role = w
            .model
            .recipients
            .iter()
            .find(|r| &r.id == id)
            .map(|r| r.role)
            .ok_or(Error::UnknownRecipient)?;
        match w.role {
            None => {}
            Some(Role::Admin) if w.added_by_owner && target_role != Role::Admin => {}
            Some(_) => return Err(Error::NotPermitted),
        }
        let (vault_id, actor) = (w.vault_id(), w.actor);
        let entry = w
            .model
            .recipients
            .iter_mut()
            .find(|r| &r.id == id)
            .ok_or(Error::UnknownRecipient)?;
        entry.expires_at = expires_at;
        entry.added_by = actor;
        entry.certify(&vault_id, &w.signer);
        Ok(())
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
        w.model.team.counters.retain(|c| &c.recipient != id);
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
        let mut slot = current::password_slot(&u.model.header.vault_id, &u.vk, new_password, kdf)?;
        match u
            .model
            .slots
            .iter_mut()
            .find(|s| s.kind == current::SLOT_PASSWORD)
        {
            Some(existing) => {
                // A new password is not a new enrollment.
                slot.created_at = existing.created_at;
                *existing = slot;
            }
            None => u.model.slots.insert(0, slot),
        }
        Ok(())
    }

    // --- Slots and devices (owner only) -----------------------------------------------

    /// The owner's unlocked vault, or why this opening is not one.
    fn owner_mut(&mut self) -> Result<&mut current::Unlocked, Error> {
        match &mut self.access {
            Access::Owner(u) => Ok(u),
            Access::Blocked { .. } => Err(Error::UpgradeNeedsRecoveryKey),
            Access::Recipient(_) => Err(Error::NotOwner),
        }
    }

    /// Every slot, as metadata: kind, id, label, creation and expiry. Unknown
    /// kinds are listed like the rest. Nothing secret is returned.
    pub fn slots(&self) -> Vec<SlotInfo> {
        self.model().slots.iter().map(current::Slot::info).collect()
    }

    /// Add a slot of a kind other than password and recovery (those have
    /// [`Vault::change_password`] and the paper key). `wrap` is given the vault
    /// key and the slot's AAD and returns the slot's `ct`: build it with
    /// [`current::seal_vault_key`] under the key-encryption key the kind
    /// derives, so [`Vault::unlock_with_slot`] can open it with that key.
    /// Returns the slot's id. Refused at 16 slots, for a taken id or a bad
    /// label, parameters or size. Takes effect at the next `save`.
    pub fn add_slot(
        &mut self,
        new: NewSlot,
        wrap: impl FnOnce(&[u8; KEY_LEN], &[u8]) -> Result<Vec<u8>, Error>,
    ) -> Result<[u8; 16], Error> {
        let u = self.owner_mut()?;
        if matches!(new.kind, current::SLOT_PASSWORD | current::SLOT_RECOVERY) {
            return Err(Error::Invalid("slot kind"));
        }
        let slot = current::custom_slot(&u.model.header.vault_id, &u.vk, new, wrap)?;
        let mut slots = u.model.slots.clone();
        slots.push(slot.clone());
        current::check_slots(&slots).map_err(|_| Error::Invalid("slots"))?;
        u.model.slots = slots;
        Ok(slot.slot_id)
    }

    /// Remove a slot by id. The password and recovery slots stay: the first is
    /// replaced with `change_password`, and without them the owner could be
    /// left with no way in that does not depend on another device.
    pub fn remove_slot(&mut self, slot_id: &[u8; 16]) -> Result<(), Error> {
        let u = self.owner_mut()?;
        let i = u
            .model
            .slots
            .iter()
            .position(|s| &s.slot_id == slot_id)
            .ok_or(Error::UnknownSlot)?;
        if matches!(
            u.model.slots[i].kind,
            current::SLOT_PASSWORD | current::SLOT_RECOVERY
        ) {
            return Err(Error::Invalid("slot kind"));
        }
        u.model.slots.remove(i);
        Ok(())
    }

    /// Open a vault as its owner with a slot of any kind: `kek` is the
    /// key-encryption key the caller derived for slot `slot_id`. An older
    /// format has no such slots. An expired slot, an unknown id and a wrong key
    /// are all [`Error::Unlock`].
    pub fn unlock_with_slot(
        path: &Path,
        slot_id: &[u8; 16],
        kek: &[u8; KEY_LEN],
        store: &LocalStore,
    ) -> Result<Vault, Error> {
        Vault::open_owner(path, OwnerAccess::Slot(slot_id, kek), store, None)
    }

    /// [`Vault::unlock_with_slot`] with the owner-change consent of
    /// [`Vault::unlock_password_accepting`].
    pub fn unlock_with_slot_accepting(
        path: &Path,
        slot_id: &[u8; 16],
        kek: &[u8; KEY_LEN],
        store: &LocalStore,
        consent: Consent<'_>,
    ) -> Result<Vault, Error> {
        Vault::open_owner(path, OwnerAccess::Slot(slot_id, kek), store, Some(consent))
    }

    pub fn devices(&self) -> &[Device] {
        &self.model().devices
    }

    /// Record a paired device. The id and the name must be new.
    pub fn add_device(&mut self, device: Device) -> Result<(), Error> {
        let u = self.owner_mut()?;
        let mut devices = u.model.devices.clone();
        devices.push(device);
        current::check_devices(&devices).map_err(|_| Error::Invalid("device"))?;
        u.model.devices = devices;
        Ok(())
    }

    /// Replace the record with the same `device_id`.
    pub fn update_device(&mut self, device: Device) -> Result<(), Error> {
        let u = self.owner_mut()?;
        let mut devices = u.model.devices.clone();
        let slot = devices
            .iter_mut()
            .find(|d| d.device_id == device.device_id)
            .ok_or(Error::UnknownDevice)?;
        *slot = device;
        current::check_devices(&devices).map_err(|_| Error::Invalid("device"))?;
        u.model.devices = devices;
        Ok(())
    }

    /// Remove a device record. Its slot, if any, is removed separately with
    /// [`Vault::remove_slot`].
    pub fn remove_device(&mut self, device_id: &[u8; 16]) -> Result<(), Error> {
        let u = self.owner_mut()?;
        let before = u.model.devices.len();
        u.model.devices.retain(|d| &d.device_id != device_id);
        if u.model.devices.len() == before {
            return Err(Error::UnknownDevice);
        }
        Ok(())
    }

    /// The key-encryption key of the password slot for `pw`, if `pw` opens
    /// it: the one [`Vault::rekey`] wants. Costs one run of the password
    /// hash. Owner only.
    pub fn password_kek(&self, pw: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
        let u = match &self.access {
            Access::Owner(u) => u,
            Access::Blocked { .. } => return Err(Error::UpgradeNeedsRecoveryKey),
            Access::Recipient(_) => return Err(Error::NotOwner),
        };
        let slot = u
            .model
            .slots
            .iter()
            .find(|s| s.kind == current::SLOT_PASSWORD)
            .ok_or(Error::Unlock)?;
        let p = current::PasswordParams::decode(&slot.params).ok_or(Error::Unlock)?;
        let cost = KdfParams {
            m_kib: p.m_kib,
            t: p.t,
            p: p.p,
        };
        if !cost.meets(&crypto::kdf_floor()) {
            return Err(Error::KdfBelowFloor);
        }
        let kek = crypto::argon2id(pw, &p.salt, p.m_kib, p.t, p.p)?;
        slot.open(&u.model.header.vault_id, &kek)?;
        Ok(kek)
    }

    /// Replace the slot that has `new.slot_id` (which must be given) by a new
    /// one with the same id: remove and add in one step, so a failure leaves
    /// the old slot. A device slot is re-wrapped this way after each use.
    pub fn replace_slot(
        &mut self,
        new: NewSlot,
        wrap: impl FnOnce(&[u8; KEY_LEN], &[u8]) -> Result<Vec<u8>, Error>,
    ) -> Result<(), Error> {
        let u = self.owner_mut()?;
        let id = new.slot_id.ok_or(Error::Invalid("slot id"))?;
        if matches!(new.kind, current::SLOT_PASSWORD | current::SLOT_RECOVERY) {
            return Err(Error::Invalid("slot kind"));
        }
        let i = u
            .model
            .slots
            .iter()
            .position(|s| s.slot_id == id && s.kind == new.kind)
            .ok_or(Error::UnknownSlot)?;
        let mut slot = current::custom_slot(&u.model.header.vault_id, &u.vk, new, wrap)?;
        // Re-wrapping after a use is not a new enrollment.
        slot.created_at = u.model.slots[i].created_at;
        let mut slots = u.model.slots.clone();
        slots[i] = slot;
        current::check_slots(&slots).map_err(|_| Error::Invalid("slots"))?;
        u.model.slots = slots;
        Ok(())
    }

    /// Change the vault key. The vault is the same vault (same id, same
    /// names, same recipients, same rules and devices) under a new key, so
    /// that nothing that held the old key can open the next saved file.
    ///
    /// * A new vault key is drawn, and the owner's signing and encryption
    ///   keys, which derive from it, change with it.
    /// * Every secret is sealed again under a fresh data key, for the new
    ///   owner key and for the recipients that held it.
    /// * Recipients the owner added are certified again by the new owner key
    ///   (those an admin added keep the admin's certificate, which is still
    ///   good).
    /// * The password slot is wrapped again under `password_kek` (from
    ///   [`Vault::password_kek`]); the recovery slot under the same paper key
    ///   (`RecoveryPlan::Keep`) or under a new one (`RecoveryPlan::Replace`,
    ///   returned once in the outcome and never stored).
    /// * **Every other slot is dropped** unless the caller hands it back in
    ///   `keep`, wrapped for the new key. A device slot is kept by wrapping the
    ///   new key for the device again, which needs only the device's public
    ///   key.
    /// * The old owner key signs a successor record for the new one (kept in
    ///   the file's signed body, the last few). The local store's pin and MAC
    ///   key are moved to the new owner key by the next `save`
    ///   ([`LocalStore::repin_owner`]), so this machine does not report
    ///   `OwnerChanged`. Another machine that pinned the old key follows the
    ///   chain, but only after the person opens the file there with their own
    ///   secret and confirms ([`Vault::unlock_password_accepting`]); without
    ///   that, or without a chain that reaches it, it reports `OwnerChanged`.
    /// * A session opened before keeps keys that open nothing in the new file:
    ///   its reads fail with [`Error::SessionStale`].
    ///
    /// Takes effect at the next `save`. Nothing in the vault changes if it
    /// fails. Owner only.
    pub fn rekey(
        &mut self,
        password_kek: &[u8; KEY_LEN],
        recovery: RecoveryPlan<'_>,
        keep: Vec<KeptSlot<'_>>,
    ) -> Result<RekeyOutcome, Error> {
        let u = self.owner_mut()?;
        let vault_id = u.model.header.vault_id;
        let fmt = u.fmt;
        let old_keys = current::owner_keys(&u.vk);
        let old_state_key = StateKey::owner(&u.vk);
        let old_owner_sign_pk = u.model.owner.sign_pk;

        // The slots that must open before anything is touched.
        let old_pw = u
            .model
            .slots
            .iter()
            .find(|s| s.kind == current::SLOT_PASSWORD)
            .ok_or(Error::Invalid("no password slot"))?
            .clone();
        old_pw.open(&vault_id, password_kek)?;
        if let RecoveryPlan::Keep(key) = &recovery
            && !current::recovery_key_matches(&u.model, key)
        {
            return Err(Error::Unlock);
        }

        let new_vk = Zeroizing::new(crypto::random::<KEY_LEN>()?);
        let new_keys = current::owner_keys(&new_vk);
        let mut model = u.model.clone();

        // Secrets: a fresh data key each, wrapped for the new owner key.
        for i in 0..model.secrets.len() {
            let old = &model.secrets[i];
            let dek = current::open_dek(fmt, &vault_id, &old_keys.enc_sk, old)?;
            let value = current::value_with_dek(fmt, &vault_id, &dek, old)?;
            let holders: Vec<&Recipient> = model
                .recipients
                .iter()
                .filter(|r| old.wraps.iter().any(|w| w.recipient_id == r.id))
                .collect();
            let sealed = current::seal_secret(
                fmt,
                &vault_id,
                old.secret_id,
                &new_keys.enc_pk,
                value.expose(),
                &holders,
            )?;
            model.secrets[i] = sealed;
        }
        model.owner = current::Owner {
            sign_pk: new_keys.sign_pk,
            enc_pk: new_keys.enc_pk,
        };
        // The old owner key vouches for the new one, so a machine that pinned
        // the old key can follow (after the person confirms there).
        let epoch = model.successors.last().map_or(0, |s| s.generation) + 1;
        current::push_successor(
            &mut model.successors,
            current::Successor::sign(&vault_id, &old_keys.sign, new_keys.sign_pk, epoch, now()),
        );
        for r in model.recipients.iter_mut() {
            if r.added_by == Actor::Owner {
                r.certify(&vault_id, &new_keys.sign);
            }
        }

        // Slots.
        // A slot keeps the time it was enrolled: "the last enrolled method"
        // must survive a re-key.
        let enrolled = |id: &[u8; 16]| {
            u.model
                .slots
                .iter()
                .find(|s| &s.slot_id == id)
                .map(|s| s.created_at)
        };
        let mut slots = vec![current::Slot {
            created_at: old_pw.created_at,
            ..current::rewrap_slot(&vault_id, &old_pw, &new_vk, password_kek)?
        }];
        let mut new_recovery = None;
        match recovery {
            RecoveryPlan::Keep(key) => {
                if let Some(old) = model
                    .slots
                    .iter()
                    .find(|s| s.kind == current::SLOT_RECOVERY)
                {
                    let kek = current::recovery_kek(key);
                    slots.push(current::Slot {
                        created_at: old.created_at,
                        ..current::rewrap_slot(&vault_id, old, &new_vk, &kek)?
                    });
                }
            }
            RecoveryPlan::Replace => {
                let key = RecoveryKey::new(crypto::random::<32>()?);
                slots.push(current::recovery_slot(&vault_id, &new_vk, &key)?);
                new_recovery = Some(key);
            }
        }
        let mut kept_ids = Vec::new();
        for k in keep {
            if matches!(k.new.kind, current::SLOT_PASSWORD | current::SLOT_RECOVERY) {
                return Err(Error::Invalid("slot kind"));
            }
            let mut slot = current::custom_slot(&vault_id, &new_vk, k.new, k.wrap)?;
            if let Some(t) = enrolled(&slot.slot_id) {
                slot.created_at = t;
            }
            kept_ids.push(slot.slot_id);
            slots.push(slot);
        }
        let dropped: Vec<SlotInfo> = model
            .slots
            .iter()
            .filter(|s| {
                !matches!(s.kind, current::SLOT_PASSWORD | current::SLOT_RECOVERY)
                    && !kept_ids.contains(&s.slot_id)
            })
            .map(current::Slot::info)
            .collect();
        current::check_slots(&slots).map_err(|_| Error::Invalid("slots"))?;
        model.slots = slots;

        // Nothing failed: swap everything in.
        u.model = model;
        u.vk = new_vk;
        self.state_key = StateKey::owner(&u.vk);
        self.repin.get_or_insert(Repin {
            old_state_key,
            old_owner_sign_pk,
        });
        Ok(RekeyOutcome {
            recovery: new_recovery,
            dropped,
        })
    }

    /// Finish an upgrade that was waiting for the paper key. The key must be
    /// the one that opens the vault's recovery slot, so a wrong one cannot
    /// replace it. Does nothing if the vault is not blocked.
    pub fn provide_recovery_key(&mut self, key: &RecoveryKey) -> Result<(), Error> {
        let Access::Blocked { old, typed, .. } = &self.access else {
            return Ok(());
        };
        if !format::v1::recovery_key_matches(&old.as_v1().model, key) {
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
                if loaded.header().vault_id != model.header.vault_id {
                    return Err(Error::Conflict);
                }
                // A vault is never written over a member's package.
                if actor == Actor::Owner
                    && loaded
                        .current()
                        .is_some_and(|d| crate::member::is_package(&d.model))
                {
                    return Err(Error::Package);
                }
                loaded.header().generation
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
        // The owner's generation moves only when the owner saves: a member's
        // own save must not make the owner's next package look "not newer".
        let old_owner_generation = model.team.owner_generation;
        model.header.generation = generation;
        model.header.updated = now();
        if actor == Actor::Owner {
            model.team.owner_generation = generation;
        }
        let result = current::encode_as(fmt, model, actor, &signer)
            .and_then(|bytes| write_atomic(path, &bytes));
        if let Err(e) = result {
            model.header.generation = old_generation;
            model.header.updated = old_updated;
            model.team.owner_generation = old_owner_generation;
            return Err(e);
        }
        let (id, pk) = (model.header.vault_id, model.owner.sign_pk);
        // What this machine records is the owner's generation, which for the
        // owner is the file's.
        let tracked = model.team.owner_generation;
        self.base_generation = generation;
        self.upgraded_from = None;
        match self.repin.take() {
            Some(old) => store.repin_owner(
                &id,
                &old.old_state_key,
                &old.old_owner_sign_pk,
                &self.state_key,
                &pk,
                tracked,
            ),
            None => store.record(&id, &self.state_key, &pk, tracked),
        }
    }
}

fn backup_path(path: &Path, from: u16) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault.vht".to_string());
    path.with_file_name(format!("{name}.v{from}.bak"))
}

/// Copy the original bytes to `<vault>.v<N>.bak`, never overwriting one.
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

#[path = "vault_members.rs"]
mod members;
pub use members::{Transfer, TransferSender};

#[cfg(test)]
#[path = "vault_tests.rs"]
mod tests;
