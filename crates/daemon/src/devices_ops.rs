//! `vahta devices ...` and `vahta recover`: the phones a vault has paired, and
//! getting back in when the password is lost.
//!
//! **Listing** needs no password: the device records are in the signed plain
//! part of the vault file. **Everything that changes a device** (pair, extend,
//! revoke, lost) needs the master password, typed in the window, and nothing
//! else: a paired phone can open the vault but cannot make itself last longer
//! or add another phone (`devices` is `password_only` in the factor policy).
//!
//! The journal records `device_paired`, `device_extended`, `device_revoked`,
//! `device_lost_rekey` and `rekey`, with the device's id and name and never a
//! key. `device_unlock` and `device_approve` are written where a device is used.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vahta_auth::{
    Action, AuthError, NewDevice, device_id_for, enroll_device, kept_device_slot, refresh_device,
};
use vahta_vault::{Device, RecoveryPlan, Vault, hex_encode};

use crate::authn;
use crate::journal::Entry;
use crate::ops::{
    Ctx, Flow, cancelled, error, find_vault, from_surface, from_vault, lines_for, refused,
};
use crate::protocol::{ClientReply, DeviceInfo, RefusalKind, Secret};
use crate::surface::Window;

/// The longest a device's access can be given at once.
pub const MAX_ACCESS_SECS: u64 = 365 * 86_400;
/// The shortest.
pub const MIN_ACCESS_SECS: u64 = 60;
/// How long the phone is waited for while pairing.
const PAIR_WAIT: Duration = Duration::from_secs(5 * 60);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn check_secs(secs: u64) -> Flow<()> {
    if !(MIN_ACCESS_SECS..=MAX_ACCESS_SECS).contains(&secs) {
        return Err(refused(
            RefusalKind::NothingToDo,
            "a device's access lasts from 1 minute to 365 days; nothing was changed",
        ));
    }
    Ok(())
}

/// The device the person means: its name, the start of its name, or the start
/// of its id in hex (at least four characters); only one device may match.
fn resolve(devices: &[Device], text: &str) -> Flow<Device> {
    let text = text.trim();
    let by_name: Vec<&Device> = devices
        .iter()
        .filter(|d| d.name.eq_ignore_ascii_case(text))
        .collect();
    if let [d] = by_name.as_slice() {
        return Ok((*d).clone());
    }
    let lower = text.to_ascii_lowercase();
    let by_prefix: Vec<&Device> = devices
        .iter()
        .filter(|d| d.name.to_ascii_lowercase().starts_with(&lower))
        .collect();
    if let [d] = by_prefix.as_slice() {
        return Ok((*d).clone());
    }
    let by_id: Vec<&Device> = devices
        .iter()
        .filter(|d| lower.len() >= 4 && hex_encode(&d.device_id).starts_with(&lower))
        .collect();
    match by_id.as_slice() {
        [d] => Ok((*d).clone()),
        [] => Err(refused(
            RefusalKind::UnknownName,
            format!("no paired device is called or starts with \"{text}\"; see `vahta devices`"),
        )),
        _ => Err(refused(
            RefusalKind::UnknownName,
            format!("\"{text}\" matches more than one device; give more of the id"),
        )),
    }
}

/// When the journal last saw `id` open the vault or approve something.
fn last_used(journal: &Path, id: &[u8; 16]) -> Option<u64> {
    let want = hex_encode(id);
    let text = std::fs::read_to_string(journal).ok()?;
    text.lines()
        .filter(|l| l.contains(&want))
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| {
            v["device"] == want.as_str()
                && matches!(
                    v["event"].as_str(),
                    Some("device_unlock" | "device_approve")
                )
                && v["result"] == "ok"
        })
        .filter_map(|v| v["time"].as_u64())
        .max()
}

// --- list -------------------------------------------------------------------------------------

pub(crate) fn list(ctx: &Ctx<'_>, cwd: &str) -> Flow<ClientReply> {
    let (_, vault_path) = find_vault(cwd)?;
    let peek = Vault::peek(&vault_path).map_err(from_vault)?;
    let journal = ctx.shared.options.paths.journal_file();
    let t = now();
    let devices = peek
        .devices
        .iter()
        .map(|d| DeviceInfo {
            id: hex_encode(&d.device_id),
            name: d.name.clone(),
            paired_at: d.paired_at,
            expires_at: d.expires_at,
            last_used: last_used(&journal, &d.device_id),
            state: if d.expires_at.is_some_and(|e| e <= t) {
                "expired".to_string()
            } else {
                "active".to_string()
            },
            transports: d.transports.clone(),
        })
        .collect();
    Ok(ClientReply::Devices { devices })
}

// --- pair ---------------------------------------------------------------------------------------

pub(crate) fn pair(ctx: &Ctx<'_>, cwd: &str, name: &str, secs: u64) -> Flow<ClientReply> {
    check_secs(secs)?;
    let (project, vault_path) = find_vault(cwd)?;
    let peek = Vault::peek(&vault_path).map_err(from_vault)?;
    if peek
        .devices
        .iter()
        .any(|d| d.name.eq_ignore_ascii_case(name))
    {
        return Err(refused(
            RefusalKind::Exists,
            format!("a device called {name} is already paired"),
        ));
    }
    let mut window = ctx.window("Pair a phone")?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!("Name: {name}"));
    lines.push(format!(
        "Its access lasts {}.",
        vahta_ipc::duration::human(secs)
    ));
    lines.push(
        "A phone is a way in, not a backup: keep the recovery key from when the vault was \
         made."
            .to_string(),
    );
    let panel = ctx.panel("Pair a phone", lines);
    let action = Action::Devices {
        what: format!("pair {name}"),
    };
    let vault = crate::ops::unlock_as(ctx, window.as_mut(), &vault_path, &panel, action)?;
    let new = ctx
        .shared
        .links
        .pair(name, PAIR_WAIT)
        .map_err(|e| match e {
            AuthError::Cancelled => cancelled(),
            other => error(other.to_string()),
        })?;
    record_pairing(ctx, window, &vault_path, vault, new, secs)
}

/// Record a phone that has just paired, with the vault already open: the entry
/// in the signed device list, its slot, and a save. What `vahta-link` calls
/// once the phone has proved its keys.
pub(crate) fn record_pairing(
    ctx: &Ctx<'_>,
    window: Box<dyn Window>,
    vault_path: &Path,
    mut vault: Vault,
    new: NewDevice,
    secs: u64,
) -> Flow<ClientReply> {
    let expires_at = now() + secs;
    let device = Device {
        device_id: device_id_for(&new.sign_pub, &new.ecdh_pub),
        name: new.name.clone(),
        sign_pub: new.sign_pub,
        ecdh_pub: new.ecdh_pub,
        paired_at: now(),
        expires_at: Some(expires_at),
        transports: new.transports,
    };
    let id = device.device_id;
    enroll_device(&mut vault, device, Some(expires_at)).map_err(|e| match e {
        AuthError::Vault(v) => from_vault(v),
        other => error(other.to_string()),
    })?;
    vault.save(vault_path, ctx.store()).map_err(from_vault)?;
    ctx.journal(
        Entry::new("device_paired")
            .vault(&vault.vault_id())
            .device(&id)
            .result("ok", Some(&format!("{}; until {expires_at}", new.name))),
    );
    window.close(Some("Phone paired."));
    Ok(ClientReply::Done {
        message: format!(
            "paired {} ({}); access lasts {}",
            new.name,
            &hex_encode(&id)[..8],
            vahta_ipc::duration::human(secs)
        ),
    })
}

// --- extend / revoke ----------------------------------------------------------------------------------

/// A device change in progress: the window, the vault's path, the device, the
/// open vault and the password that opened it.
struct Change {
    window: Box<dyn Window>,
    vault_path: std::path::PathBuf,
    device: Device,
    vault: Vault,
    typed: Option<zeroize::Zeroizing<Vec<u8>>>,
}

/// Open the window for a device change and unlock with the master password.
fn password_for(
    ctx: &Ctx<'_>,
    cwd: &str,
    id: &str,
    title: &str,
    what: &str,
    extra: Vec<String>,
) -> Flow<Change> {
    let (project, vault_path) = find_vault(cwd)?;
    let peek = Vault::peek(&vault_path).map_err(from_vault)?;
    let device = resolve(&peek.devices, id)?;
    let mut window = ctx.window(title)?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!(
        "Device: {} ({})",
        device.name,
        &hex_encode(&device.device_id)[..8]
    ));
    lines.extend(extra);
    let panel = ctx.panel(title, lines);
    let action = Action::Devices {
        what: format!("{what} {}", device.name),
    };
    let (vault, _, typed) =
        authn::unlock_keeping_password(ctx, window.as_mut(), &vault_path, &panel, action)?;
    // The device list may have changed while the window was open.
    let device = vault
        .devices()
        .iter()
        .find(|d| d.device_id == device.device_id)
        .cloned()
        .ok_or_else(|| error("that device is gone; nothing was done"))?;
    Ok(Change {
        window,
        vault_path,
        device,
        vault,
        typed,
    })
}

pub(crate) fn extend(ctx: &Ctx<'_>, cwd: &str, id: &str, secs: u64) -> Flow<ClientReply> {
    check_secs(secs)?;
    let extra = vec![format!(
        "Access will last {} from now.",
        vahta_ipc::duration::human(secs)
    )];
    let Change {
        window,
        vault_path,
        device,
        mut vault,
        ..
    } = password_for(ctx, cwd, id, "Extend a device's access", "extend", extra)?;
    let until = now() + secs;
    refresh_device(&mut vault, &device.device_id, Some(until)).map_err(|e| error(e.to_string()))?;
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    ctx.journal(
        Entry::new("device_extended")
            .vault(&vault.vault_id())
            .device(&device.device_id)
            .result("ok", Some(&format!("{}; until {until}", device.name))),
    );
    window.close(Some("Access extended."));
    Ok(ClientReply::Done {
        message: format!(
            "{} has access for {} from now",
            device.name,
            vahta_ipc::duration::human(secs)
        ),
    })
}

pub(crate) fn revoke(ctx: &Ctx<'_>, cwd: &str, id: &str) -> Flow<ClientReply> {
    let extra = vec!["The phone stops opening the vault from the next save.".to_string()];
    let Change {
        window,
        vault_path,
        device,
        mut vault,
        ..
    } = password_for(ctx, cwd, id, "Revoke a device", "revoke", extra)?;
    match vault.remove_slot(&device.device_id) {
        Ok(()) | Err(vahta_vault::Error::UnknownSlot) => {}
        Err(e) => return Err(from_vault(e)),
    }
    vault.remove_device(&device.device_id).map_err(from_vault)?;
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    ctx.journal(
        Entry::new("device_revoked")
            .vault(&vault.vault_id())
            .device(&device.device_id)
            .result("ok", Some(&device.name)),
    );
    window.close(Some("Device revoked."));
    Ok(ClientReply::Done {
        message: format!(
            "revoked {}. A copy of the vault file made before still opens with that phone; if the \
             phone was lost, use `vahta devices lost {}`",
            device.name, device.name
        ),
    })
}

// --- lost ------------------------------------------------------------------------------------------------

pub(crate) fn lost(ctx: &Ctx<'_>, cwd: &str, id: &str) -> Flow<ClientReply> {
    let extra = vec![
        "This removes the phone and changes the vault's key, so a copy of the file that the \
         phone could open is of no use to whoever has it going forward."
            .to_string(),
        "A new recovery key is made; the old one stops working. Other machines that use this \
         vault will refuse it until their record of it is cleared."
            .to_string(),
    ];
    let Change {
        mut window,
        vault_path,
        device,
        mut vault,
        typed,
    } = password_for(ctx, cwd, id, "A device is lost", "lost", extra)?;
    let typed = typed.ok_or_else(|| error("the password was not asked; nothing was done"))?;
    let kek = vault.password_kek(&typed).map_err(from_vault)?;
    drop(typed);

    // Every other device keeps working: its slot is wrapped for the new key
    // from its public key alone.
    let mut keep = Vec::new();
    for other in vault
        .devices()
        .iter()
        .filter(|d| d.device_id != device.device_id)
    {
        keep.push(kept_device_slot(other).map_err(|e| error(e.to_string()))?);
    }
    let kept = keep.len();
    vault.remove_device(&device.device_id).map_err(from_vault)?;
    let outcome = vault
        .rekey(&kek, RecoveryPlan::Replace, keep)
        .map_err(from_vault)?;
    drop(kek);
    let Some(new_key) = outcome.recovery else {
        return Err(error("no new recovery key was made; nothing was done"));
    };

    // Shown, and acknowledged, before anything is written: if the window dies
    // first the old file stays as it was.
    let mut panel = ctx.panel(
        "A new recovery key",
        vec![format!("Device removed: {}", device.name)],
    );
    panel.warning = Some(
        "Write this recovery key down and destroy the old one. It is shown only now.".to_string(),
    );
    if !window
        .show_recovery_key(&panel, &Secret::new(new_key.to_paper()))
        .map_err(from_surface)?
    {
        return Err(cancelled());
    }
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    let vault_id = vault.vault_id();

    // Sessions opened before hold keys of the old vault: end them.
    let ended = ctx
        .shared
        .sessions
        .lock()
        .map(|mut s| s.end_where(|s| s.vault_id == vault_id, "rekey"))
        .unwrap_or_default();
    let ended_n = ended.len();
    ctx.shared.record_ended(ended);

    ctx.journal(
        Entry::new("device_lost_rekey")
            .vault(&vault_id)
            .device(&device.device_id)
            .result("ok", Some(&device.name)),
    );
    ctx.journal(Entry::new("rekey").vault(&vault_id).result(
        "ok",
        Some(&format!(
            "{} other device(s) kept, {} slot(s) dropped, {ended_n} session(s) ended",
            kept,
            outcome.dropped.len()
        )),
    ));
    window.close(Some("The vault has a new key."));
    Ok(ClientReply::Done {
        message: format!(
            "{} removed and the vault re-keyed ({kept} other device(s) kept); the new recovery \
             key was shown once",
            device.name
        ),
    })
}

// --- recover ----------------------------------------------------------------------------------------------------

pub(crate) fn recover(ctx: &Ctx<'_>, cwd: &str) -> Flow<ClientReply> {
    let (project, vault_path) = find_vault(cwd)?;
    let mut window = ctx.window("Recover a vault")?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push(
        "Enter the recovery key written down when the vault was made, then choose a new \
         password."
            .to_string(),
    );
    let panel = ctx.panel("Recover a vault", lines);
    let mut vault = authn::unlock_with_recovery(ctx, window.as_mut(), &vault_path, &panel)?;
    let chosen = window
        .ask_password(&panel, "New vault password", true)
        .map_err(from_surface)?
        .ok_or_else(cancelled)?;
    if chosen.expose().is_empty() {
        return Err(error("the password cannot be empty; nothing was done"));
    }
    vault
        .change_password(chosen.expose().as_bytes(), ctx.shared.options.kdf)
        .map_err(from_vault)?;
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    ctx.journal(
        Entry::new("recover")
            .vault(&vault.vault_id())
            .result("ok", Some("new password set with the recovery key")),
    );
    window.close(Some("New password set."));
    Ok(ClientReply::Done {
        message: "the vault opens with the new password".to_string(),
    })
}
