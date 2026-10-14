//! Devices: the slot kind that a paired phone opens, the trait that reaches
//! the phone, and the approver that asks it.
//!
//! **The slot (kind 2).** At pairing the phone gives the computer two public
//! keys: one to verify its signatures (`sign_pub`), one for key agreement
//! (`ecdh_pub`), both P-256 and held in the phone's hardware keystore. To
//! enrol, the computer, with the vault open, makes an ephemeral key pair, does
//! ECDH of it with `ecdh_pub`, derives
//! `KEK = HKDF-SHA256(shared, "vahta/v2/device-kek" ‖ device_id ‖ params)` and
//! wraps the vault key under it. The slot's `params` hold the ephemeral public
//! key. To unlock, the computer sends that public key to the phone; the phone
//! (after its biometric check) does ECDH with its private key and returns the
//! shared secret over its encrypted channel, and the computer derives the same
//! KEK. **After every successful unlock the slot is written again with a new
//! ephemeral key**, so a shared secret captured once opens the file as it was
//! and no later one.
//!
//! The phone's answer to an unlock also carries a signed [`Decision`] on the
//! request, so one biometric prompt both approves and opens.
//!
//! **What this does not do.** The expiry of a device is enforced by the
//! daemon (it refuses an expired slot and an expired device record, and the
//! vault's own slot expiry is checked in code too). Cryptography alone does not
//! enforce it: a copy of the vault file, together with a phone that still holds
//! its key, opens that copy. Removing the slot and re-keying (`vahta devices
//! lost`) is what makes an old copy useless going forward.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use vahta_vault::store::LocalStore;
use vahta_vault::{Device, KeptSlot, NewSlot, SLOT_DEVICE, SlotView, Vault};
use zeroize::Zeroizing;

use crate::approve::{Approver, Cancel};
use crate::error::AuthError;
use crate::factor::Factor;
use crate::request::{Decision, Request};
use crate::unlock::{UnlockCtx, UnlockedBy, Unlocker};

const INFO_DEVICE_KEK: &[u8] = b"vahta/v2/device-kek";

/// A device's answer to an unlock request.
pub struct UnlockReply {
    /// The ECDH shared secret of the phone's private key and the request's
    /// ephemeral public key.
    pub shared: Zeroizing<[u8; 32]>,
    /// The phone's signed yes on the same [`Request`].
    pub decision: Decision,
}

/// A way to talk to one paired device. The transport (Bluetooth, Wi-Fi, a
/// relay) and the Noise session over it are the implementor's business; the
/// daemon trusts nothing but the signatures on what comes back.
pub trait DeviceChannel: Send + Sync {
    /// Whether the device looks reachable now. A guess; `unlock` and `approve`
    /// are the truth.
    fn reachable(&self) -> bool {
        true
    }

    /// Ask the device to do ECDH with `eph_pub` (SEC1) after the person
    /// approves `req` on it. Blocks until `req.expires_at`.
    fn unlock(&self, req: &Request, eph_pub: &[u8]) -> Result<UnlockReply, AuthError>;

    /// Ask the device to answer `req` (its `options`). The answer is a
    /// [`Decision`] the caller verifies.
    fn approve(&self, req: &Request) -> Result<Decision, AuthError>;

    /// [`DeviceChannel::approve`] that stops early when `cancel` fires (another
    /// approver answered first). A channel that waits on a real phone must
    /// override it, or the race for the first answer waits for the phone too.
    fn approve_cancellable(&self, req: &Request, _cancel: &Cancel) -> Result<Decision, AuthError> {
        self.approve(req)
    }
}

/// A device that has just paired: what the phone said about itself.
#[derive(Debug, Clone)]
pub struct NewDevice {
    pub name: String,
    pub sign_pub: Vec<u8>,
    pub ecdh_pub: Vec<u8>,
    pub transports: Vec<String>,
}

/// A device's id: the first 16 bytes of
/// `SHA-256("vahta/v1/device-id" ‖ sign_pub ‖ ecdh_pub)`. Derived from its keys,
/// so the phone and the computer agree on it without either choosing.
pub fn device_id_for(sign_pub: &[u8], ecdh_pub: &[u8]) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"vahta/v1/device-id");
    h.update(sign_pub);
    h.update(ecdh_pub);
    let full = h.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&full[..16]);
    id
}

/// The pairing code to show the person: what the phone scans or is given.
#[derive(Debug, Clone)]
pub struct PairingCode {
    /// The code as a Unicode-block QR, several lines.
    pub qr: String,
    /// The same code as one line of text, for a phone that cannot scan.
    pub text: String,
    /// Unix seconds after which the code is refused.
    pub expires_at: u64,
}

/// What a pairing needs from the caller.
pub struct PairContext<'a> {
    pub vault_id: [u8; 16],
    /// How long the phone is waited for.
    pub wait: Duration,
    /// Called once the code exists, before waiting; the caller puts it on
    /// screen.
    pub show: &'a (dyn Fn(PairingCode) + Sync),
    /// Fires when the person gave up (closed the window).
    pub cancel: &'a Cancel,
}

/// The daemon's view of everything that can reach devices (`vahta-link`
/// implements it).
pub trait DeviceLinks: Send + Sync {
    /// The channel to `device` of the vault `vault_id`, if some transport can
    /// reach it.
    fn channel(&self, vault_id: &[u8; 16], device: &Device) -> Option<Arc<dyn DeviceChannel>>;

    /// Pair a new device: build the pairing code, hand it to `ctx.show`, and
    /// wait for the phone. The caller records the result in the vault.
    fn pair(&self, name: &str, ctx: &PairContext<'_>) -> Result<NewDevice, AuthError>;

    /// A device was removed from the vault: forget what is kept for reaching
    /// it.
    fn forget(&self, _vault_id: &[u8; 16], _device_id: &[u8; 16]) {}
}

/// No device can be reached: the build without a transport.
pub struct NoLinks;

impl DeviceLinks for NoLinks {
    fn channel(&self, _vault_id: &[u8; 16], _device: &Device) -> Option<Arc<dyn DeviceChannel>> {
        None
    }

    fn pair(&self, _name: &str, _ctx: &PairContext<'_>) -> Result<NewDevice, AuthError> {
        Err(AuthError::Unavailable(
            "pairing a phone needs the phone link, which this build does not have".into(),
        ))
    }
}

// --- The slot ------------------------------------------------------------------------------

/// The key-encryption key of a device slot.
pub fn device_kek(shared: &[u8; 32], device_id: &[u8; 16], params: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut info = INFO_DEVICE_KEK.to_vec();
    info.extend_from_slice(device_id);
    info.extend_from_slice(params);
    vahta_vault::crypto::hkdf(shared, &info)
}

/// A new ephemeral key agreed with the device's `ecdh_pub`: the slot's
/// `params` (the ephemeral public key) and the key-encryption key.
fn fresh_kek(device: &Device) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), AuthError> {
    let theirs = PublicKey::from_sec1_bytes(&device.ecdh_pub)
        .map_err(|_| AuthError::Refused("the device's key is not a P-256 point".into()))?;
    let eph = EphemeralSecret::random(&mut rand_core::OsRng);
    let params = p256::EncodedPoint::from(eph.public_key())
        .as_bytes()
        .to_vec();
    let shared = eph.diffie_hellman(&theirs);
    let mut raw = Zeroizing::new([0u8; 32]);
    raw.copy_from_slice(shared.raw_secret_bytes().as_slice());
    let kek = device_kek(&raw, &device.device_id, &params);
    Ok((params, kek))
}

fn slot_for(device: &Device, expires_at: Option<u64>, params: Vec<u8>) -> NewSlot {
    NewSlot {
        kind: SLOT_DEVICE,
        slot_id: Some(device.device_id),
        label: device.name.clone(),
        expires_at,
        params,
    }
}

/// Record `device` in the open vault and give it a slot that opens the vault.
/// `expires_at` is when both stop being accepted. Nothing is saved.
pub fn enroll_device(
    vault: &mut Vault,
    device: Device,
    expires_at: Option<u64>,
) -> Result<(), AuthError> {
    let (params, kek) = fresh_kek(&device)?;
    vault.add_device(Device {
        expires_at,
        ..device.clone()
    })?;
    let added = vault.add_slot(slot_for(&device, expires_at, params), |vk, aad| {
        vahta_vault::seal_vault_key(&kek, aad, vk)
    });
    if let Err(e) = added {
        let _ = vault.remove_device(&device.device_id);
        return Err(e.into());
    }
    Ok(())
}

/// The slot of `device` for a [`Vault::rekey`], wrapped for the new vault key.
pub fn kept_device_slot(device: &Device) -> Result<KeptSlot<'static>, AuthError> {
    let (params, kek) = fresh_kek(device)?;
    Ok(KeptSlot {
        new: slot_for(device, device.expires_at, params),
        wrap: Box::new(move |vk, aad| vahta_vault::seal_vault_key(&kek, aad, vk)),
    })
}

/// Kind 2: a paired device.
pub struct DeviceUnlocker;

impl Unlocker for DeviceUnlocker {
    fn kind(&self) -> u16 {
        SLOT_DEVICE
    }

    fn label(&self) -> String {
        "paired device".into()
    }

    fn factor(&self) -> Factor {
        Factor::PossessionBiometric
    }

    fn priority(&self) -> u8 {
        10
    }

    fn unwrap_kek(
        &self,
        slot: &vahta_vault::SlotInfo,
        params: &[u8],
        ctx: &mut dyn UnlockCtx,
    ) -> Result<Zeroizing<[u8; 32]>, AuthError> {
        let linked = ctx
            .device(&slot.slot_id)
            .ok_or_else(|| AuthError::Unavailable(format!("{} is not in reach", slot.label)))?;
        let device = &linked.record;
        if device.expires_at.is_some_and(|t| now() >= t) {
            return Err(AuthError::Refused(format!(
                "access for \"{}\" has expired",
                device.name
            )));
        }
        if !linked.channel.reachable() {
            return Err(AuthError::Unavailable(format!(
                "{} is not in reach",
                device.name
            )));
        }
        let req = ctx.request().clone();
        let reply = linked.channel.unlock(&req, params)?;
        // The device must have seen and approved this very request.
        reply
            .decision
            .verify(&req, &device.device_id, &device.sign_pub)?;
        Ok(device_kek(&reply.shared, &device.device_id, params))
    }

    fn open(
        &self,
        path: &Path,
        slot: &SlotView,
        ctx: &mut dyn UnlockCtx,
        store: &LocalStore,
    ) -> Result<(Vault, UnlockedBy), AuthError> {
        let kek = self.unwrap_kek(&slot.info, &slot.params, ctx)?;
        let mut vault =
            Vault::unlock_with_slot_accepting(path, &slot.info.slot_id, &kek, store, &mut |c| {
                ctx.confirm_owner_change(c)
            })?;
        // Write the slot again with a new ephemeral key. A failure here (the
        // file changed under us) leaves the old slot, which still works; it is
        // reported, not fatal.
        let rewrapped = rewrap(&mut vault, path, store, &slot.info.slot_id).is_ok();
        let id = slot.info.slot_id;
        Ok((vault, self.by(slot, rewrapped, Some(id))))
    }
}

/// Give the device `device_id` access until `expires_at` (`None`: no end) and a
/// new slot with a fresh ephemeral key, under the same id. Updates the device
/// record and the slot together. Nothing is saved.
pub fn refresh_device(
    vault: &mut Vault,
    device_id: &[u8; 16],
    expires_at: Option<u64>,
) -> Result<(), AuthError> {
    let mut device = vault
        .devices()
        .iter()
        .find(|d| &d.device_id == device_id)
        .cloned()
        .ok_or(AuthError::Vault(vahta_vault::Error::UnknownDevice))?;
    device.expires_at = expires_at;
    let (params, kek) = fresh_kek(&device)?;
    vault.replace_slot(slot_for(&device, expires_at, params), |vk, aad| {
        vahta_vault::seal_vault_key(&kek, aad, vk)
    })?;
    vault.update_device(device)?;
    Ok(())
}

fn rewrap(
    vault: &mut Vault,
    path: &Path,
    store: &LocalStore,
    device_id: &[u8; 16],
) -> Result<(), AuthError> {
    let slot = vault
        .slots()
        .into_iter()
        .find(|s| &s.slot_id == device_id)
        .ok_or(AuthError::Vault(vahta_vault::Error::UnknownSlot))?;
    refresh_device(vault, device_id, slot.expires_at)?;
    vault.save(path, store)?;
    Ok(())
}

// --- The approver ----------------------------------------------------------------------------

/// A device that answers [`Request`]s.
pub struct DeviceApprover {
    pub record: Device,
    pub channel: Arc<dyn DeviceChannel>,
}

impl Approver for DeviceApprover {
    fn factor(&self) -> Factor {
        Factor::PossessionBiometric
    }

    fn label(&self) -> String {
        self.record.name.clone()
    }

    fn device_id(&self) -> Option<[u8; 16]> {
        Some(self.record.device_id)
    }

    fn available(&self) -> bool {
        !self.record.expires_at.is_some_and(|t| now() >= t) && self.channel.reachable()
    }

    fn decide(
        &self,
        req: &Request,
        _options: &[String],
        _timeout: Duration,
        cancel: &Cancel,
    ) -> Result<Option<usize>, AuthError> {
        match self.channel.approve_cancellable(req, cancel) {
            Ok(decision) => {
                decision.verify(req, &self.record.device_id, &self.record.sign_pub)?;
                Ok(Some(usize::from(decision.choice)))
            }
            Err(AuthError::Timeout | AuthError::Denied | AuthError::Cancelled) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
