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
//! Format 4 to 5 adds the vault kind (`Project`), an empty role list, no expiry
//! on any member and no harnesses on any rule set, and re-seals the secrets
//! under the new number; it changes no slot either. A member's certificate
//! stays valid, because one with no expiry is signed as before.
//!
//! Format 3 to 4 adds the remote-use flag (off) and an empty `from` list to
//! every rule set, and re-seals the secrets under the new number; it changes no
//! slot either.
//!
//! Format 2 to 3 adds the (empty) successor chain and re-seals the secrets under
//! the new number; it changes no slot either.
//!
//! Format 1 to 2 changes no slot's crypto: the generic slot keeps the old
//! bytes and the old slot version, so it needs neither key. It re-seals every
//! secret (their AADs bind the format number) and turns bindings into rule sets.
//! Under test, a pseudo-format 0 with the same layout as format 1 is a link
//! before that, so the chain, the backup, the generation continuity and the
//! recovery-key rule are exercised for real.

use super::{v1, v2, v3, v4, v5};
use crate::{Error, RecoveryKey};

/// An unlocked vault of any supported format.
#[derive(Clone)]
pub enum AnyUnlocked {
    V1(v1::Unlocked),
    #[cfg(test)]
    V0(v1::Unlocked),
}

impl AnyUnlocked {
    /// The format 1 structure underneath, for as long as the vault is not
    /// upgraded.
    pub fn as_v1(&self) -> &v1::Unlocked {
        match self {
            AnyUnlocked::V1(u) => u,
            #[cfg(test)]
            AnyUnlocked::V0(u) => u,
        }
    }
}

/// Format 1 to 2: slots keep their bytes, bindings become rule sets (with
/// `Network::App`, no directories, no category), and every secret is re-sealed
/// under the new format number, for the owner and for each holder.
pub fn upgrade_v1_to_v2(old: &v1::Unlocked) -> Result<v2::Unlocked, Error> {
    let vault_id = old.model.header.vault_id;
    let keys = v1::owner_keys(&old.vk);
    let mut model = v2::Model::from_v1(&old.model);
    for sealed in &mut model.secrets {
        let value = v1::open_value(old.fmt, &vault_id, &keys.enc_sk, sealed)?;
        let holders: Vec<&v2::Recipient> = sealed
            .wraps
            .iter()
            .filter_map(|w| model.recipients.iter().find(|r| r.id == w.recipient_id))
            .collect();
        *sealed = v2::seal_secret(
            v2::FORMAT,
            &vault_id,
            sealed.secret_id,
            &model.owner.enc_pk,
            value.expose(),
            &holders,
        )?;
    }
    Ok(v2::Unlocked {
        fmt: v2::FORMAT,
        vk: old.vk.clone(),
        model,
    })
}

/// Format 2 to 3: the file gets an empty successor chain, and every secret is
/// re-sealed under the new format number, for the owner and for each holder.
pub fn upgrade_v2_to_v3(old: &v2::Unlocked) -> Result<v3::Unlocked, Error> {
    let vault_id = old.model.header.vault_id;
    let keys = v2::owner_keys(&old.vk);
    let mut model = v3::Model::from_v2(&old.model);
    for sealed in &mut model.secrets {
        let value = v2::open_value(old.fmt, &vault_id, &keys.enc_sk, sealed)?;
        let holders: Vec<&v2::Recipient> = sealed
            .wraps
            .iter()
            .filter_map(|w| model.recipients.iter().find(|r| r.id == w.recipient_id))
            .collect();
        *sealed = v3::seal_secret(
            v3::FORMAT,
            &vault_id,
            sealed.secret_id,
            &model.owner.enc_pk,
            value.expose(),
            &holders,
        )?;
    }
    Ok(v3::Unlocked {
        fmt: v3::FORMAT,
        vk: old.vk.clone(),
        model,
    })
}

/// Format 3 to 4: the vault gets the remote-use flag (off) and every rule set an
/// empty `from` list; every secret is re-sealed under the new format number,
/// for the owner and for each holder.
pub fn upgrade_v3_to_v4(old: &v3::Unlocked) -> Result<v4::Unlocked, Error> {
    let vault_id = old.model.header.vault_id;
    let keys = v3::owner_keys(&old.vk);
    let mut model = v4::Model::from_v3(&old.model);
    for sealed in &mut model.secrets {
        let value = v3::open_value(old.fmt, &vault_id, &keys.enc_sk, sealed)?;
        let holders: Vec<&v2::Recipient> = sealed
            .wraps
            .iter()
            .filter_map(|w| model.recipients.iter().find(|r| r.id == w.recipient_id))
            .collect();
        *sealed = v4::seal_secret(
            v4::FORMAT,
            &vault_id,
            sealed.secret_id,
            &model.owner.enc_pk,
            value.expose(),
            &holders,
        )?;
    }
    Ok(v4::Unlocked {
        fmt: v4::FORMAT,
        vk: old.vk.clone(),
        model,
    })
}

/// Format 4 to 5: the vault gets the kind `Project`, no roles, no member expiry
/// and no harnesses; every secret is re-sealed under the new format number, for
/// the owner and for each holder.
pub fn upgrade_v4_to_v5(old: &v4::Unlocked) -> Result<v5::Unlocked, Error> {
    let vault_id = old.model.header.vault_id;
    let keys = v4::owner_keys(&old.vk);
    let mut model = v5::Model::from_v4(&old.model);
    for sealed in &mut model.secrets {
        let value = v4::open_value(old.fmt, &vault_id, &keys.enc_sk, sealed)?;
        let holders: Vec<&v5::Recipient> = sealed
            .wraps
            .iter()
            .filter_map(|w| model.recipients.iter().find(|r| r.id == w.recipient_id))
            .collect();
        *sealed = v5::seal_secret(
            v5::FORMAT,
            &vault_id,
            sealed.secret_id,
            &model.owner.enc_pk,
            value.expose(),
            &holders,
        )?;
    }
    Ok(v5::Unlocked {
        fmt: v5::FORMAT,
        vk: old.vk.clone(),
        model,
    })
}

/// Run the chain from whatever `unlocked` is to the current format.
#[cfg_attr(not(test), allow(unused_variables))]
pub fn to_current(
    unlocked: &AnyUnlocked,
    typed: Option<&[u8]>,
    recovery: Option<&RecoveryKey>,
) -> Result<v5::Unlocked, Error> {
    match unlocked {
        AnyUnlocked::V1(u) => upgrade_v4_to_v5(&upgrade_v3_to_v4(&upgrade_v2_to_v3(
            &upgrade_v1_to_v2(u)?,
        )?)?),
        #[cfg(test)]
        AnyUnlocked::V0(u) => to_current(
            &AnyUnlocked::V1(super::testing::upgrade_v0_to_v1(u, typed, recovery)?),
            typed,
            recovery,
        ),
    }
}
