//! The chain that carries an older format forward: `upgrade_vN_to_vN+1`, one
//! step per released format after the first.
//!
//! A step takes the older format's *unlocked* structure (vault key, every
//! field) and returns the next one, so it may re-encrypt, re-wrap or re-sign.
//! That is why only an owner unlock upgrades: it is the only access that holds
//! the vault key.
//!
//! A step also gets the typed secret when the vault was opened with the
//! password. A change that depends on it (a new KDF in the password slot)
//! needs it; when the vault was opened by recovery the step leaves that slot
//! as it was and it is redone on the next password unlock.
//!
//! With one released format the chain is empty and `to_current` is the
//! identity. It exists, dispatched and tested, so format 2 is one function
//! added here and not a rewrite. Under test, a pseudo-format 0 with the same
//! layout as format 1 but its own AAD number is the first link, so the chain,
//! the backup and the generation continuity are exercised for real.

use super::v1;
use crate::Error;

/// An unlocked vault of any supported format.
pub enum AnyUnlocked {
    V1(v1::Unlocked),
    #[cfg(test)]
    V0(v1::Unlocked),
}

#[cfg_attr(not(test), allow(unused_variables))]
/// Run the chain from whatever `unlocked` is to the current format.
pub fn to_current(unlocked: AnyUnlocked, typed: Option<&[u8]>) -> Result<v1::Unlocked, Error> {
    match unlocked {
        AnyUnlocked::V1(u) => Ok(u),
        #[cfg(test)]
        AnyUnlocked::V0(u) => to_current(
            AnyUnlocked::V1(super::testing::upgrade_v0_to_v1(u, typed)?),
            typed,
        ),
    }
}
