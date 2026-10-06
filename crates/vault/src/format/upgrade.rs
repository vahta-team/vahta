//! The chain that carries an older format forward: `upgrade_vN_to_vN+1`, one
//! step per released format after the first.
//!
//! A step takes the older format's *unlocked* structure (vault key, every
//! field) and returns the next one, so it may re-encrypt, re-wrap or re-sign.
//! That is why only an owner unlock upgrades: it is the only access that holds
//! the vault key.
//!
//! Slots are independent of the file format (their AAD carries a slot version,
//! not the format number), so a step copies them verbatim unless the new format
//! changes that slot kind's own crypto. Two things a step may then need:
//!
//! * the typed password, for a change to the password slot. It is `Some` only
//!   when the vault was opened with the password;
//! * the paper key, for a change to the recovery slot, which only the paper key
//!   can make. When a step needs it and it was not given, `to_current` returns
//!   [`Error::UpgradeNeedsRecoveryKey`]; the caller keeps the vault open in its
//!   old format, readable, and refuses to save until the key is provided.
//!
//! With one released format the chain is empty and `to_current` is the
//! identity. It exists, dispatched and tested, so format 2 is one function
//! added here and not a rewrite. Under test, a pseudo-format 0 with the same
//! layout as format 1 is the first link, so the chain, the backup, the
//! generation continuity and the recovery-key rule are exercised for real.

use super::v1;
use crate::{Error, RecoveryKey};

/// An unlocked vault of any supported format.
#[derive(Clone)]
pub enum AnyUnlocked {
    V1(v1::Unlocked),
    #[cfg(test)]
    V0(v1::Unlocked),
}

impl AnyUnlocked {
    /// A read-only view for as long as the vault is not upgraded. Every format
    /// so far shares format 1's in-memory types; a format with its own would
    /// add an arm that converts what a reader needs.
    pub fn as_v1(&self) -> &v1::Unlocked {
        match self {
            AnyUnlocked::V1(u) => u,
            #[cfg(test)]
            AnyUnlocked::V0(u) => u,
        }
    }
}

/// Run the chain from whatever `unlocked` is to the current format.
#[cfg_attr(not(test), allow(unused_variables))]
pub fn to_current(
    unlocked: &AnyUnlocked,
    typed: Option<&[u8]>,
    recovery: Option<&RecoveryKey>,
) -> Result<v1::Unlocked, Error> {
    match unlocked {
        AnyUnlocked::V1(u) => Ok(u.clone()),
        #[cfg(test)]
        AnyUnlocked::V0(u) => to_current(
            &AnyUnlocked::V1(super::testing::upgrade_v0_to_v1(u, typed, recovery)?),
            typed,
            recovery,
        ),
    }
}
