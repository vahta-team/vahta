//! The frame every `vault.vht` has, and the dispatch from a file's format
//! number to the module that reads it.
//!
//! ```text
//! magic b"VAHTAVLT" (8) | format u16 LE | body_len u32 LE | body | signature section
//! ```
//!
//! The frame is the one part that never changes between formats, so it is
//! parsed here, before any format-specific code runs: size limit first, then
//! magic, then the format number. A number newer than this build is refused
//! before anything else is looked at, so a future file never gets as far as a
//! misleading "damaged" error.
//!
//! Each released format has its own frozen module (`v1.rs` to `v4.rs`). A file of an older
//! format is read by its own module and, on an owner unlock, carried forward by
//! the chain in `upgrade.rs` to [`current`]. A file of the current format needs
//! no chain. There is no way to write an older format: only the current module
//! has `encode`.

pub mod upgrade;
pub mod v1;
pub mod v2;
pub mod v3;
pub mod v4;

#[cfg(test)]
pub(crate) mod testing;

use crate::{Error, RecoveryKey};

/// The module of the format this build writes. The in-memory vault is made of
/// its types.
pub use v4 as current;

pub const MAGIC: &[u8; 8] = b"VAHTAVLT";
/// The format this build writes.
pub const CURRENT: u16 = current::FORMAT;
/// Files over this size are refused before parsing.
pub const MAX_FILE: usize = 16 * 1024 * 1024;
/// `magic (8) + format (2) + body_len (4)`.
pub const FRAME_HEAD: usize = 14;

/// A file cut into its parts. The slices borrow the file's bytes.
#[derive(Debug)]
pub struct Frame<'a> {
    pub format: u16,
    /// `magic` through the end of `body`: exactly what the signature covers.
    pub signed: &'a [u8],
    pub body: &'a [u8],
    pub sig: &'a [u8],
}

/// Which format a file carries, after the checks that need no format: size,
/// magic and a newer-than-supported number.
pub fn read_version(bytes: &[u8]) -> Result<u16, Error> {
    if bytes.len() > MAX_FILE {
        return Err(Error::TooLarge);
    }
    if bytes.len() < MAGIC.len() + 2 || &bytes[..MAGIC.len()] != MAGIC {
        return Err(Error::NotAVault);
    }
    let format = u16::from_le_bytes([bytes[8], bytes[9]]);
    if format > CURRENT {
        return Err(Error::NewerFormat {
            found: format,
            supported: CURRENT,
        });
    }
    if !is_known(format) {
        return Err(Error::NotAVault);
    }
    Ok(format)
}

/// Whether this build can read `format`. Format 0 never existed; under test it
/// is the pseudo-format that exercises the upgrade chain.
fn is_known(format: u16) -> bool {
    match format {
        1..=4 => true,
        #[cfg(test)]
        0 => true,
        _ => false,
    }
}

/// Cut `bytes` into frame parts, checking that `body_len` agrees with the
/// file's length.
pub fn split(bytes: &[u8]) -> Result<Frame<'_>, Error> {
    let format = read_version(bytes)?;
    if bytes.len() < FRAME_HEAD {
        return Err(Error::Corrupt("truncated"));
    }
    let body_len = u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) as usize;
    let body_end = FRAME_HEAD
        .checked_add(body_len)
        .ok_or(Error::Corrupt("body length"))?;
    // The signature section is not empty, so the body must end before the
    // file does.
    if body_end >= bytes.len() {
        return Err(Error::Corrupt("body length"));
    }
    Ok(Frame {
        format,
        signed: &bytes[..body_end],
        body: &bytes[FRAME_HEAD..body_end],
        sig: &bytes[body_end..],
    })
}

/// A file that parsed and verified, in whichever format it was written.
#[derive(Debug)]
pub enum Loaded {
    V1(v1::Decoded),
    V2(v2::Decoded),
    V3(v3::Decoded),
    V4(v4::Decoded),
    /// The test pseudo-format: the same layout as format 1 under another
    /// number, to prove the chain before a real second format exists.
    #[cfg(test)]
    V0(v1::Decoded),
}

/// Read, check and verify a file of any supported format. Never upgrades.
pub fn decode(bytes: &[u8]) -> Result<Loaded, Error> {
    let frame = split(bytes)?;
    match frame.format {
        1 => Ok(Loaded::V1(v1::decode(&frame)?)),
        2 => Ok(Loaded::V2(v2::decode(&frame)?)),
        3 => Ok(Loaded::V3(v3::decode(&frame)?)),
        4 => Ok(Loaded::V4(v4::decode(&frame)?)),
        #[cfg(test)]
        0 => Ok(Loaded::V0(v1::decode_as(&frame, 0)?)),
        _ => Err(Error::NotAVault),
    }
}

impl Loaded {
    pub fn format(&self) -> u16 {
        match self {
            Loaded::V1(_) => 1,
            Loaded::V2(_) => 2,
            Loaded::V3(_) => 3,
            Loaded::V4(_) => 4,
            #[cfg(test)]
            Loaded::V0(_) => 0,
        }
    }

    /// The header, which every format shares.
    pub fn header(&self) -> &v2::Header {
        match self {
            Loaded::V1(d) => &d.model.header,
            Loaded::V2(d) => &d.model.header,
            Loaded::V3(d) => &d.model.header,
            Loaded::V4(d) => &d.model.header,
            #[cfg(test)]
            Loaded::V0(d) => &d.model.header,
        }
    }

    pub fn owner(&self) -> &v2::Owner {
        match self {
            Loaded::V1(d) => &d.model.owner,
            Loaded::V2(d) => &d.model.owner,
            Loaded::V3(d) => &d.model.owner,
            Loaded::V4(d) => &d.model.owner,
            #[cfg(test)]
            Loaded::V0(d) => &d.model.owner,
        }
    }

    pub fn index(&self) -> &[v2::Entry] {
        match self {
            Loaded::V1(d) => &d.model.index,
            Loaded::V2(d) => &d.model.index,
            Loaded::V3(d) => &d.model.index,
            Loaded::V4(d) => &d.model.index,
            #[cfg(test)]
            Loaded::V0(d) => &d.model.index,
        }
    }

    pub fn recipient_count(&self) -> usize {
        match self {
            Loaded::V1(d) => d.model.recipients.len(),
            Loaded::V2(d) => d.model.recipients.len(),
            Loaded::V3(d) => d.model.recipients.len(),
            Loaded::V4(d) => d.model.recipients.len(),
            #[cfg(test)]
            Loaded::V0(d) => d.model.recipients.len(),
        }
    }

    /// The approved rules, in the current format's type (an older format's
    /// bindings read as rule sets with `Network::App`).
    pub fn rule_sets(&self) -> Vec<v4::RuleSet> {
        let up = |sets: &[v2::RuleSet]| sets.iter().map(v4::RuleSet::from_v2).collect();
        match self {
            Loaded::V4(d) => d.model.bindings.clone(),
            Loaded::V3(d) => up(&d.model.bindings),
            Loaded::V2(d) => up(&d.model.bindings),
            Loaded::V1(d) => up(&d
                .model
                .bindings
                .iter()
                .map(v2::RuleSet::from_v1)
                .collect::<Vec<_>>()),
            #[cfg(test)]
            Loaded::V0(d) => up(&d
                .model
                .bindings
                .iter()
                .map(v2::RuleSet::from_v1)
                .collect::<Vec<_>>()),
        }
    }

    /// The slots, in the current format's type (an older format's are shown
    /// with their bytes unchanged).
    pub fn slots(&self) -> Vec<v2::Slot> {
        let older = |d: &v1::Decoded| v2::Model::from_v1(&d.model).slots;
        match self {
            Loaded::V2(d) => d.model.slots.clone(),
            Loaded::V3(d) => d.model.slots.clone(),
            Loaded::V4(d) => d.model.slots.clone(),
            Loaded::V1(d) => older(d),
            #[cfg(test)]
            Loaded::V0(d) => older(d),
        }
    }

    /// The owner successor chain (a file older than format 3 has none).
    pub fn successors(&self) -> Vec<v3::Successor> {
        match self {
            Loaded::V3(d) => d.model.successors.clone(),
            Loaded::V4(d) => d.model.successors.clone(),
            _ => Vec::new(),
        }
    }

    /// The paired devices (an older format has none).
    pub fn devices(&self) -> Vec<v2::Device> {
        match self {
            Loaded::V2(d) => d.model.devices.clone(),
            Loaded::V3(d) => d.model.devices.clone(),
            Loaded::V4(d) => d.model.devices.clone(),
            _ => Vec::new(),
        }
    }

    pub fn signer(&self) -> v2::Actor {
        match self {
            Loaded::V1(d) => d.signer,
            Loaded::V2(d) => d.signer,
            Loaded::V3(d) => d.signer,
            Loaded::V4(d) => d.signer,
            #[cfg(test)]
            Loaded::V0(d) => d.signer,
        }
    }

    /// The file as the current format, when it is one.
    pub fn current(&self) -> Option<&v4::Decoded> {
        match self {
            Loaded::V4(d) => Some(d),
            _ => None,
        }
    }

    /// Whether the person has opted this vault in to use from other projects
    /// (off in every older format).
    pub fn remote(&self) -> bool {
        matches!(self, Loaded::V4(d) if d.model.remote)
    }

    pub fn upgrade_pending(&self) -> bool {
        self.format() != CURRENT
    }
}

/// How an owner proves itself.
#[derive(Clone, Copy)]
pub enum OwnerAccess<'a> {
    Password(&'a [u8]),
    Recovery(&'a RecoveryKey),
    /// A slot of any kind, by id, with the key-encryption key the caller
    /// derived for it. Only a current-format file has such slots.
    Slot(&'a [u8; 16], &'a [u8; 32]),
}

/// An owner-unlocked vault: in the current format, or still in an older one
/// because the upgrade is waiting for the paper key.
pub enum OwnerState {
    Current(current::Unlocked),
    /// Readable through its own format's module, but not savable: the chain
    /// has a step that rewrites the recovery slot and needs the paper key.
    Blocked(upgrade::AnyUnlocked),
}

pub struct OwnerOpen {
    pub state: OwnerState,
    /// The format the file had, when it was older than the current one.
    pub from: Option<u16>,
}

/// Unlock as the owner and carry the result forward to the current format. If
/// a step of the chain needs the recovery key and this unlock did not use it,
/// the result is [`OwnerState::Blocked`] rather than an error: the vault is
/// open and readable, and `upgrade::to_current` finishes the job once the key
/// is provided.
pub fn unlock_owner(loaded: &Loaded, access: OwnerAccess<'_>) -> Result<OwnerOpen, Error> {
    let unlocked = match (loaded, &access) {
        (Loaded::V4(d), _) => {
            let u = match access {
                OwnerAccess::Password(pw) => v4::unlock_password(d, pw)?,
                OwnerAccess::Recovery(k) => v4::unlock_recovery(d, k)?,
                OwnerAccess::Slot(id, kek) => v4::unlock_slot(d, id, kek)?,
            };
            return Ok(OwnerOpen {
                state: OwnerState::Current(u),
                from: None,
            });
        }
        // Formats 2 and 3 carry forward with no key needed beyond the unlock
        // itself.
        (Loaded::V3(d), _) => {
            let u = match access {
                OwnerAccess::Password(pw) => v3::unlock_password(d, pw)?,
                OwnerAccess::Recovery(k) => v3::unlock_recovery(d, k)?,
                OwnerAccess::Slot(id, kek) => v3::unlock_slot(d, id, kek)?,
            };
            return Ok(OwnerOpen {
                state: OwnerState::Current(upgrade::upgrade_v3_to_v4(&u)?),
                from: Some(3),
            });
        }
        (Loaded::V2(d), _) => {
            let u = match access {
                OwnerAccess::Password(pw) => v2::unlock_password(d, pw)?,
                OwnerAccess::Recovery(k) => v2::unlock_recovery(d, k)?,
                OwnerAccess::Slot(id, kek) => v2::unlock_slot(d, id, kek)?,
            };
            return Ok(OwnerOpen {
                state: OwnerState::Current(upgrade::upgrade_v3_to_v4(&upgrade::upgrade_v2_to_v3(
                    &u,
                )?)?),
                from: Some(2),
            });
        }
        (_, OwnerAccess::Slot(..)) => return Err(Error::Unlock),
        (Loaded::V1(d), OwnerAccess::Password(pw)) => {
            upgrade::AnyUnlocked::V1(v1::unlock_password(d, pw)?)
        }
        (Loaded::V1(d), OwnerAccess::Recovery(k)) => {
            upgrade::AnyUnlocked::V1(v1::unlock_recovery(d, k)?)
        }
        #[cfg(test)]
        (Loaded::V0(d), OwnerAccess::Password(pw)) => {
            upgrade::AnyUnlocked::V0(v1::unlock_password(d, pw)?)
        }
        #[cfg(test)]
        (Loaded::V0(d), OwnerAccess::Recovery(k)) => {
            upgrade::AnyUnlocked::V0(v1::unlock_recovery(d, k)?)
        }
    };
    let from = Some(loaded.format());
    let (typed, recovery) = match access {
        OwnerAccess::Password(pw) => (Some(pw), None),
        OwnerAccess::Recovery(k) => (None, Some(k)),
        OwnerAccess::Slot(..) => (None, None),
    };
    let state = match upgrade::to_current(&unlocked, typed, recovery) {
        Ok(u) => OwnerState::Current(u),
        Err(Error::UpgradeNeedsRecoveryKey) => OwnerState::Blocked(unlocked),
        Err(e) => return Err(e),
    };
    Ok(OwnerOpen { state, from })
}

/// A recipient's opening of the file: its entry and the file's model, in
/// whatever format the file has (an older one is shown as the current type).
/// A recipient never upgrades a file.
pub struct RecipientOpen {
    pub fmt: u16,
    pub model: current::Model,
    pub recipient: v2::Recipient,
}

pub fn unlock_recipient(
    loaded: &Loaded,
    recipient_id: &[u8; 16],
    enc_sk: &[u8; 32],
) -> Result<RecipientOpen, Error> {
    match loaded {
        Loaded::V4(d) => Ok(RecipientOpen {
            fmt: d.fmt,
            model: d.model.clone(),
            recipient: v4::check_recipient(d, recipient_id, enc_sk)?,
        }),
        Loaded::V3(d) => Ok(RecipientOpen {
            fmt: d.fmt,
            model: v4::Model::from_v3(&d.model),
            recipient: v3::check_recipient(d, recipient_id, enc_sk)?,
        }),
        Loaded::V2(d) => Ok(RecipientOpen {
            fmt: d.fmt,
            model: v4::Model::from_v2(&d.model),
            recipient: v2::check_recipient(d, recipient_id, enc_sk)?,
        }),
        Loaded::V1(d) => older_recipient(d, recipient_id, enc_sk),
        #[cfg(test)]
        Loaded::V0(d) => older_recipient(d, recipient_id, enc_sk),
    }
}

fn older_recipient(
    d: &v1::Decoded,
    recipient_id: &[u8; 16],
    enc_sk: &[u8; 32],
) -> Result<RecipientOpen, Error> {
    let recipient = v1::check_recipient(d, recipient_id, enc_sk)?;
    Ok(RecipientOpen {
        fmt: d.fmt,
        model: v4::Model::from_v1(&d.model),
        recipient,
    })
}
