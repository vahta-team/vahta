//! What opens the vault: the [`Unlocker`] trait, the two kinds the vault has
//! always had, and the [`Registry`] the daemon asks.
//!
//! The core never looks at a slot's kind. It hands the registry a vault path
//! and a [`UnlockCtx`] (how to ask the person for a password, how to reach a
//! device) and gets a vault back, or the reason none opened.

use std::path::Path;
use std::sync::Arc;

use vahta_vault::format::current;
use vahta_vault::store::LocalStore;
use vahta_vault::{Device, RecoveryKey, SLOT_PASSWORD, SLOT_RECOVERY, SlotInfo, SlotView, Vault};
use zeroize::Zeroizing;

use crate::device::{DeviceChannel, DeviceUnlocker};
use crate::error::AuthError;
use crate::factor::{Factor, Need};
use crate::request::Request;

/// How many wrong passwords one window accepts.
pub const MAX_TRIES: usize = 3;

/// A paired device and the way to reach it.
#[derive(Clone)]
pub struct LinkedDevice {
    pub record: Device,
    pub channel: Arc<dyn DeviceChannel>,
}

/// What an unlocker may ask of its surroundings.
pub trait UnlockCtx {
    /// What is being unlocked for; a device shows it to its person.
    fn request(&self) -> &Request;
    /// The vault password, asked of the person; `warning` is the line to show
    /// above a retry. `None` is the person cancelling.
    fn password(&mut self, warning: Option<&str>) -> Result<Option<Zeroizing<Vec<u8>>>, AuthError>;
    /// The recovery key, asked of the person; `None` is cancelling.
    fn recovery_key(&mut self) -> Result<Option<RecoveryKey>, AuthError>;
    /// The device whose slot id is `slot_id` (a device's slot shares its id),
    /// if it is known and has a way to be reached.
    fn device(&mut self, slot_id: &[u8; 16]) -> Option<LinkedDevice>;
}

/// How a vault was opened, for the journal and the person. No secret.
#[derive(Debug, Clone)]
pub struct UnlockedBy {
    pub kind: u16,
    pub slot_id: [u8; 16],
    pub label: String,
    pub factor: Factor,
    /// The device, when a device opened it.
    pub device_id: Option<[u8; 16]>,
    /// Whether the slot was written again with a new ephemeral key (a device
    /// slot is, after every use).
    pub rewrapped: bool,
}

/// One way to open the vault. Implementations are the only code that knows
/// what a slot of their kind holds.
pub trait Unlocker: Send + Sync {
    /// The slot kind number this opens.
    fn kind(&self) -> u16;
    fn label(&self) -> String;
    /// What opening with it proves.
    fn factor(&self) -> Factor;
    /// Lower goes first when several apply: a phone before a password prompt.
    fn priority(&self) -> u8 {
        50
    }
    /// Whether the ordinary unlock offers it. The recovery key is its own
    /// command.
    fn normal_flow(&self) -> bool {
        true
    }
    /// The key that opens `slot`, from `params` (the slot's public
    /// parameters) and whatever this kind needs from the person or a device.
    fn unwrap_kek(
        &self,
        slot: &SlotInfo,
        params: &[u8],
        ctx: &mut dyn UnlockCtx,
    ) -> Result<Zeroizing<[u8; 32]>, AuthError>;

    /// Open the vault at `path` with `slot`. The default derives the key and
    /// opens the slot; a kind whose vault format may still be old (password,
    /// recovery) overrides it to go through the upgrade path.
    fn open(
        &self,
        path: &Path,
        slot: &SlotView,
        ctx: &mut dyn UnlockCtx,
        store: &LocalStore,
    ) -> Result<(Vault, UnlockedBy), AuthError> {
        let kek = self.unwrap_kek(&slot.info, &slot.params, ctx)?;
        let vault = Vault::unlock_with_slot(path, &slot.info.slot_id, &kek, store)?;
        Ok((vault, self.by(slot, false, None)))
    }

    fn by(&self, slot: &SlotView, rewrapped: bool, device_id: Option<[u8; 16]>) -> UnlockedBy {
        UnlockedBy {
            kind: self.kind(),
            slot_id: slot.info.slot_id,
            label: slot.info.label.clone(),
            factor: self.factor(),
            device_id,
            rewrapped,
        }
    }
}

// --- Password ----------------------------------------------------------------------------

/// Kind 0: Argon2id of the typed password.
pub struct PasswordUnlocker;

impl Unlocker for PasswordUnlocker {
    fn kind(&self) -> u16 {
        SLOT_PASSWORD
    }

    fn label(&self) -> String {
        "master password".into()
    }

    fn factor(&self) -> Factor {
        Factor::Knowledge
    }

    fn priority(&self) -> u8 {
        100
    }

    fn unwrap_kek(
        &self,
        _slot: &SlotInfo,
        params: &[u8],
        ctx: &mut dyn UnlockCtx,
    ) -> Result<Zeroizing<[u8; 32]>, AuthError> {
        let p = current::PasswordParams::decode(params)
            .ok_or(AuthError::Vault(vahta_vault::Error::Unlock))?;
        let cost = vahta_vault::KdfParams {
            m_kib: p.m_kib,
            t: p.t,
            p: p.p,
        };
        if !cost.meets(&vahta_vault::crypto::kdf_floor()) {
            return Err(vahta_vault::Error::KdfBelowFloor.into());
        }
        let typed = ctx.password(None)?.ok_or(AuthError::Cancelled)?;
        Ok(vahta_vault::crypto::argon2id(
            &typed, &p.salt, p.m_kib, p.t, p.p,
        )?)
    }

    /// Asks up to [`MAX_TRIES`] times, and opens through `unlock_password`,
    /// which also carries an older file forward.
    fn open(
        &self,
        path: &Path,
        slot: &SlotView,
        ctx: &mut dyn UnlockCtx,
        store: &LocalStore,
    ) -> Result<(Vault, UnlockedBy), AuthError> {
        let mut warning: Option<String> = None;
        for _ in 0..MAX_TRIES {
            let typed = ctx
                .password(warning.take().as_deref())?
                .ok_or(AuthError::Cancelled)?;
            match Vault::unlock_password(path, &typed, store) {
                Ok(vault) => return Ok((vault, self.by(slot, false, None))),
                Err(vahta_vault::Error::Unlock) => {
                    warning = Some("Wrong password. Try again.".to_string());
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(AuthError::TooManyTries)
    }
}

// --- Recovery ------------------------------------------------------------------------------

/// Kind 1: the paper key.
pub struct RecoveryUnlocker;

impl Unlocker for RecoveryUnlocker {
    fn kind(&self) -> u16 {
        SLOT_RECOVERY
    }

    fn label(&self) -> String {
        "recovery key".into()
    }

    fn factor(&self) -> Factor {
        Factor::Knowledge
    }

    fn priority(&self) -> u8 {
        110
    }

    fn normal_flow(&self) -> bool {
        false
    }

    fn unwrap_kek(
        &self,
        _slot: &SlotInfo,
        _params: &[u8],
        ctx: &mut dyn UnlockCtx,
    ) -> Result<Zeroizing<[u8; 32]>, AuthError> {
        let key = ctx.recovery_key()?.ok_or(AuthError::Cancelled)?;
        Ok(current::recovery_kek(&key))
    }

    fn open(
        &self,
        path: &Path,
        slot: &SlotView,
        ctx: &mut dyn UnlockCtx,
        store: &LocalStore,
    ) -> Result<(Vault, UnlockedBy), AuthError> {
        let key = ctx.recovery_key()?.ok_or(AuthError::Cancelled)?;
        let vault = Vault::unlock_recovery(path, &key, store)?;
        Ok((vault, self.by(slot, false, None)))
    }
}

// --- The registry ------------------------------------------------------------------------------

/// The unlockers this build knows.
pub struct Registry {
    unlockers: Vec<Box<dyn Unlocker>>,
}

impl Registry {
    /// Password, recovery key, paired devices. The one place the daemon names
    /// the kinds.
    pub fn standard() -> Registry {
        Registry::with(vec![
            Box::new(PasswordUnlocker),
            Box::new(RecoveryUnlocker),
            Box::new(DeviceUnlocker),
        ])
    }

    pub fn with(mut unlockers: Vec<Box<dyn Unlocker>>) -> Registry {
        unlockers.sort_by_key(|u| u.priority());
        Registry { unlockers }
    }

    /// The unlocker for a slot kind.
    pub fn get(&self, kind: u16) -> Option<&dyn Unlocker> {
        self.unlockers
            .iter()
            .find(|u| u.kind() == kind)
            .map(|b| b.as_ref())
    }

    /// Open the vault at `path` the way `need` allows: each ordinary
    /// unlocker whose factor satisfies it, phone first, password last, for
    /// each live slot of its kind. An unlocker that is not available now
    /// (a phone out of reach, a refusal, a timeout) passes to the next; the
    /// person cancelling, or a wrong password three times, ends it.
    pub fn unlock(
        &self,
        path: &Path,
        store: &LocalStore,
        need: Need,
        ctx: &mut dyn UnlockCtx,
    ) -> Result<(Vault, UnlockedBy), AuthError> {
        let peek = Vault::peek(path)?;
        let mut last: Option<AuthError> = None;
        for unlocker in &self.unlockers {
            if !unlocker.normal_flow() || !need.satisfied_by(unlocker.factor()) {
                continue;
            }
            for slot in peek.slots.iter().filter(|s| s.info.kind == unlocker.kind()) {
                if slot.info.expires_at.is_some_and(|t| now() >= t) {
                    last = Some(AuthError::Refused(format!(
                        "access for \"{}\" has expired",
                        slot.info.label
                    )));
                    continue;
                }
                match unlocker.open(path, slot, ctx, store) {
                    Ok(opened) => return Ok(opened),
                    Err(
                        e @ (AuthError::Unavailable(_)
                        | AuthError::Timeout
                        | AuthError::Denied
                        | AuthError::Refused(_)
                        | AuthError::BadDecision(_)),
                    ) => last = Some(e),
                    Err(e) => return Err(e),
                }
            }
        }
        Err(last.unwrap_or_else(|| AuthError::Unavailable("no way to unlock this vault".into())))
    }

    /// Open with one named kind only (the recovery key, the password for
    /// device management), whatever `normal_flow` says.
    pub fn unlock_with(
        &self,
        kind: u16,
        path: &Path,
        store: &LocalStore,
        ctx: &mut dyn UnlockCtx,
    ) -> Result<(Vault, UnlockedBy), AuthError> {
        let unlocker = self
            .get(kind)
            .ok_or_else(|| AuthError::Unavailable("no such way to unlock".into()))?;
        let peek = Vault::peek(path)?;
        let slot = peek
            .slots
            .iter()
            .find(|s| s.info.kind == kind)
            .ok_or(AuthError::Vault(vahta_vault::Error::Unlock))?;
        unlocker.open(path, slot, ctx, store)
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
