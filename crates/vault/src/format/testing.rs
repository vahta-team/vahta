//! The pseudo-format that proves the upgrade chain before a real format 2
//! exists. Test builds only.
//!
//! "Format 0" is format 1's layout under another number. Every secret and wrap
//! AEAD binds the number, so a format-0 file's secrets are sealed for 0 and
//! cannot be read as 1: upgrading has real work to do and re-seals them all.
//! Slots do not bind the format number, so the step copies them verbatim and
//! needs no key for that.
//!
//! To cover the other case, the step can be told (per thread, test only) that
//! "this format changes the recovery slot's crypto": it then rewrites that slot
//! and so needs the paper key, and without it returns
//! `UpgradeNeedsRecoveryKey`.

use std::cell::Cell;

use super::v1::{self, Unlocked};
use crate::crypto::KdfParams;
use crate::{Error, RecoveryKey};

thread_local! {
    static REWRITES_RECOVERY: Cell<bool> = const { Cell::new(false) };
}

/// Make the pseudo-step rewrite the recovery slot (and so need the paper key)
/// on this thread until the returned guard drops.
pub(crate) fn rewrite_recovery_slot() -> impl Drop {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            REWRITES_RECOVERY.with(|c| c.set(false));
        }
    }
    REWRITES_RECOVERY.with(|c| c.set(true));
    Reset
}

/// Format 1's own function for building a vault, aimed at number 0.
pub(crate) fn create_v0(pw: &[u8]) -> Result<(Unlocked, RecoveryKey), Error> {
    let (u, key) = v1::create(0, pw, KdfParams::TEST, true)?;
    Ok((u, key.ok_or(Error::Rng)?))
}

/// `upgrade_v0_to_v1`: re-seal every secret under the new number; copy the
/// slots, unless this format is pretending to change the recovery slot.
pub(crate) fn upgrade_v0_to_v1(
    old: &Unlocked,
    _typed: Option<&[u8]>,
    recovery: Option<&RecoveryKey>,
) -> Result<Unlocked, Error> {
    let vault_id = old.model.header.vault_id;
    let keys = v1::owner_keys(&old.vk);
    let mut model = old.model.clone();

    if REWRITES_RECOVERY.with(Cell::get)
        && let Some(i) = model
            .slots
            .iter()
            .position(|s| matches!(s, v1::Slot::Recovery { .. }))
    {
        let key = recovery.ok_or(Error::UpgradeNeedsRecoveryKey)?;
        model.slots[i] = v1::recovery_slot(&vault_id, &old.vk, key)?;
    }

    let recipients = model.recipients.clone();
    for sealed in &mut model.secrets {
        let value = v1::open_value(old.fmt, &vault_id, &keys.enc_sk, sealed)?;
        let holders: Vec<&v1::Recipient> = sealed
            .wraps
            .iter()
            .filter_map(|w| recipients.iter().find(|r| r.id == w.recipient_id))
            .collect();
        *sealed = v1::seal_secret(
            v1::FORMAT,
            &vault_id,
            sealed.secret_id,
            &model.owner.enc_pk,
            value.expose(),
            &holders,
        )?;
    }
    Ok(Unlocked {
        fmt: v1::FORMAT,
        vk: old.vk.clone(),
        model,
    })
}
