//! The pseudo-format that proves the upgrade chain before a real format 2
//! exists. Test builds only.
//!
//! "Format 0" is format 1's layout under another number. Every AEAD in a file
//! binds the number, so a format-0 file's secrets, wraps and password slot are
//! all sealed for 0 and cannot be read as 1. Upgrading therefore has real work
//! to do: open every secret under 0 and seal it again under 1, and redo the
//! password slot from the typed secret.
//!
//! What this cannot show, and a real format 2 must decide: a recovery slot is
//! sealed under a key only the paper key can make, so it cannot be redone at
//! an upgrade by password. Test format-0 vaults therefore have no recovery slot.

use super::v1::{self, Unlocked};
use crate::Error;
use crate::crypto::KdfParams;

/// Format 1's own function for building a vault, aimed at number 0.
pub(crate) fn create_v0(pw: &[u8]) -> Result<Unlocked, Error> {
    Ok(v1::create(0, pw, KdfParams::TEST, false)?.0)
}

/// `upgrade_v0_to_v1`: re-seal everything under the new number.
pub(crate) fn upgrade_v0_to_v1(old: Unlocked, typed: Option<&[u8]>) -> Result<Unlocked, Error> {
    let pw = typed.ok_or(Error::UpgradeNeedsPassword)?;
    let vault_id = old.model.header.vault_id;
    let mut model = old.model.clone();

    // The password slot: same KDF cost, new AAD.
    let Some(v1::Slot::Password { m_kib, t, p, .. }) = model.slots.first().cloned() else {
        return Err(Error::Corrupt("slots"));
    };
    model.slots = vec![v1::password_slot(
        v1::FORMAT,
        &vault_id,
        &old.vk,
        pw,
        KdfParams { m_kib, t, p },
    )?];

    // Every secret: open under 0, seal under 1, same holders.
    let recipients = model.recipients.clone();
    for sealed in &mut model.secrets {
        let value = v1::open_value(old.fmt, &vault_id, &old.vk, sealed)?;
        let holders: Vec<&v1::Recipient> = sealed
            .wraps
            .iter()
            .filter_map(|w| recipients.iter().find(|r| r.id == w.recipient_id))
            .collect();
        *sealed = v1::seal_secret(
            v1::FORMAT,
            &vault_id,
            sealed.secret_id,
            &old.vk,
            value.expose(),
            &holders,
        )?;
    }
    Ok(Unlocked {
        fmt: v1::FORMAT,
        vk: old.vk,
        model,
    })
}
