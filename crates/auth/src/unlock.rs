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
use vahta_vault::{
    Device, OwnerKeyChange, Peek, RecoveryKey, SLOT_PASSWORD, SLOT_RECOVERY, SlotInfo, SlotView,
    Vault,
};
use zeroize::Zeroizing;

use crate::approve::Cancel;
use crate::device::{DeviceChannel, DeviceUnlocker, UnlockReply};
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
    /// Run `ask`, the call that waits on the device of `slot` for an unlock,
    /// while the person is told it is being waited on. A context with a window
    /// shows it and lets the person end the wait: it fires `cancel` and the
    /// ask returns, and the next method (the password) follows. The default
    /// just runs `ask`.
    fn ask_device(
        &mut self,
        _slot: &SlotInfo,
        cancel: &Cancel,
        ask: &(dyn Fn(&Cancel) -> Result<UnlockReply, AuthError> + Sync),
    ) -> Result<UnlockReply, AuthError> {
        ask(cancel)
    }
    /// An unlocker was tried and passed on (a device refused, answered wrongly,
    /// was out of reach). For the journal.
    fn attempt_failed(&mut self, _slot: &SlotInfo, _why: &AuthError) {}
    /// This machine pinned an older owner key of the vault, the file's
    /// successor chain leads from it to the file's owner, and the vault has
    /// just been opened here with the person's own secret. Ask the person
    /// whether to accept the new key; `false` (the default, and what no
    /// answer is) refuses it. See `Vault::unlock_password_accepting`.
    fn confirm_owner_change(&mut self, _change: &OwnerKeyChange) -> bool {
        false
    }
}

/// Which unlock method is tried first. The master password is always tried if
/// the first does not open the vault, so this orders the methods and never
/// narrows them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum UnlockPref {
    /// The method enrolled last (the newest slot among the ones in the normal
    /// flow; the password counts from when the vault was made). The default.
    #[default]
    Last,
    /// The master password.
    Password,
    /// A paired device, by name (any case) or by the start of its id (four
    /// hex characters or more). A name that matches no device with a slot in
    /// this vault is ignored: it is as if the setting were [`UnlockPref::Last`].
    Device(String),
}

impl UnlockPref {
    /// `last`, `password` or `device:<name or id>`.
    pub fn parse(text: &str) -> Option<UnlockPref> {
        match text.trim() {
            "last" => Some(UnlockPref::Last),
            "password" => Some(UnlockPref::Password),
            t => {
                let name = t.strip_prefix("device:")?.trim();
                (!name.is_empty()).then(|| UnlockPref::Device(name.to_string()))
            }
        }
    }

    pub fn as_text(&self) -> String {
        match self {
            UnlockPref::Last => "last".into(),
            UnlockPref::Password => "password".into(),
            UnlockPref::Device(d) => format!("device:{d}"),
        }
    }
}

/// The device of `peek` that `name` (a name in any case, or the start of an
/// id of four or more hex characters) points to, if it has a slot here.
pub fn find_device<'a>(peek: &'a Peek, name: &str) -> Option<&'a Device> {
    let lower = name.to_ascii_lowercase();
    let has_slot = |d: &&Device| {
        peek.slots
            .iter()
            .any(|s| s.info.slot_id == d.device_id && s.info.kind == vahta_vault::SLOT_DEVICE)
    };
    peek.devices
        .iter()
        .filter(has_slot)
        .find(|d| d.name.eq_ignore_ascii_case(name))
        .or_else(|| {
            if lower.len() < 4 {
                return None;
            }
            peek.devices
                .iter()
                .filter(has_slot)
                .find(|d| vahta_vault::hex_encode(&d.device_id).starts_with(&lower))
        })
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
        let vault =
            Vault::unlock_with_slot_accepting(path, &slot.info.slot_id, &kek, store, &mut |c| {
                ctx.confirm_owner_change(c)
            })?;
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
            let attempt = Vault::unlock_password_accepting(path, &typed, store, &mut |c| {
                ctx.confirm_owner_change(c)
            });
            match attempt {
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
        let vault = Vault::unlock_recovery_accepting(path, &key, store, &mut |c| {
            ctx.confirm_owner_change(c)
        })?;
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

    /// The methods in the order they are tried for this vault: every live slot
    /// of an ordinary unlocker whose factor satisfies `need`, the current one
    /// first and the rest by the unlockers' own priority (a phone before the
    /// password prompt). The password slot is in the list whenever `need`
    /// allows it, so it is always a fallback.
    ///
    /// The current one is, by `pref`: the newest enrolled (`Last`), the
    /// password, or the named device; a device that is not here is treated as
    /// `Last`. Ties in the enrollment time go to the slot written later.
    pub fn order(&self, peek: &Peek, need: Need, pref: &UnlockPref) -> Vec<SlotInfo> {
        // Candidates in the file's slot order, each with its priority.
        let mut all: Vec<(usize, u8, &SlotInfo)> = Vec::new();
        for unlocker in &self.unlockers {
            if !unlocker.normal_flow() || !need.satisfied_by(unlocker.factor()) {
                continue;
            }
            for (i, slot) in peek.slots.iter().enumerate() {
                if slot.info.kind == unlocker.kind() {
                    all.push((i, unlocker.priority(), &slot.info));
                }
            }
        }
        let first = match pref {
            UnlockPref::Password => all
                .iter()
                .find(|(_, _, s)| s.kind == SLOT_PASSWORD)
                .map(|(_, _, s)| s.slot_id),
            UnlockPref::Device(name) => find_device(peek, name)
                .and_then(|d| all.iter().find(|(_, _, s)| s.slot_id == d.device_id))
                .map(|(_, _, s)| s.slot_id),
            UnlockPref::Last => None,
        }
        .or_else(|| {
            // An expired slot does not count as the newest: it would be tried
            // first only to say no.
            all.iter()
                .filter(|(_, _, s)| s.expires_at.is_none_or(|t| now() < t))
                .max_by_key(|(i, _, s)| (s.created_at, *i))
                .map(|(_, _, s)| s.slot_id)
        });
        all.sort_by_key(|(i, prio, s)| (Some(s.slot_id) != first, *prio, *i));
        all.into_iter().map(|(_, _, s)| s.clone()).collect()
    }

    /// The slot [`Registry::order`] puts first.
    pub fn current(&self, peek: &Peek, need: Need, pref: &UnlockPref) -> Option<SlotInfo> {
        self.order(peek, need, pref).into_iter().next()
    }

    /// [`Registry::unlock_by`] with the default setting, the last enrolled
    /// method first.
    pub fn unlock(
        &self,
        path: &Path,
        store: &LocalStore,
        need: Need,
        ctx: &mut dyn UnlockCtx,
    ) -> Result<(Vault, UnlockedBy), AuthError> {
        self.unlock_by(path, store, need, &UnlockPref::Last, ctx)
    }

    /// Open the vault at `path` the way `need` allows, trying the methods in
    /// [`Registry::order`]. A method that is not available now (a phone out of
    /// reach, a timeout, an answer that does not verify, an expired slot)
    /// passes to the next; the person cancelling, a wrong password three times,
    /// or the person refusing on the device ([`AuthError::Denied`]) ends it: a
    /// no is an answer, and the password is not offered to override it. So with the phone current the
    /// phone is asked first and the password window follows if it fails; with
    /// the password current the phone is not asked unless the password path
    /// itself is out of reach.
    pub fn unlock_by(
        &self,
        path: &Path,
        store: &LocalStore,
        need: Need,
        pref: &UnlockPref,
        ctx: &mut dyn UnlockCtx,
    ) -> Result<(Vault, UnlockedBy), AuthError> {
        let peek = Vault::peek(path)?;
        let mut last: Option<AuthError> = None;
        for info in self.order(&peek, need, pref) {
            let Some(unlocker) = self.get(info.kind) else {
                continue;
            };
            let Some(slot) = peek.slots.iter().find(|s| s.info.slot_id == info.slot_id) else {
                continue;
            };
            if info.expires_at.is_some_and(|t| now() >= t) {
                last = Some(AuthError::Refused(format!(
                    "access for \"{}\" has expired",
                    info.label
                )));
                continue;
            }
            match unlocker.open(path, slot, ctx, store) {
                Ok(opened) => return Ok(opened),
                Err(
                    e @ (AuthError::Unavailable(_)
                    | AuthError::Timeout
                    | AuthError::Skipped
                    | AuthError::Refused(_)
                    | AuthError::BadDecision(_)),
                ) => {
                    ctx.attempt_failed(&slot.info, &e);
                    last = Some(e);
                }
                Err(AuthError::Denied) => {
                    ctx.attempt_failed(&slot.info, &AuthError::Denied);
                    return Err(AuthError::Denied);
                }
                Err(e) => return Err(e),
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
