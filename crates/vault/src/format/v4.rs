//! Format 4 of `vault.vht`: format 4 plus the remote-use flag and the
//! per-secret `from` list.
//!
//! Everything else is format 4's, re-exported here. What format 4 adds:
//!
//! * `remote` in the signed body: the person's opt-in that this vault may be
//!   used from a project other than its own. Off by default, and off after an
//!   upgrade from format 4.
//! * `from` in each [`RuleSet`]: the absolute project roots the secret may be
//!   used from, outside the vault's own project. Empty after an upgrade.
//!
//! Neither field is open-ended: the body is postcard, which has no room for a
//! field a build does not know, so an unknown field is refused at decode
//! (`Corrupt`), and a newer format number is refused before that.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::v2;
use super::v3;
pub use super::v3::*;
use super::{Frame, MAGIC};
use crate::crypto::{self, KEY_LEN, KdfParams};
use crate::{Error, RecoveryKey, hex_encode};

use super::v1::{self, exact};

/// This module's format number.
pub const FORMAT: u16 = 4;

/// How many project roots one secret's `from` list may hold.
pub const MAX_FROM: usize = 16;

// --- Rule sets ---------------------------------------------------------------------------

/// Format 3's rule set plus `from`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSet {
    pub name: String,
    pub category: Option<String>,
    pub downgraded_from: Option<String>,
    pub allow: Vec<ApprovedRule>,
    pub deny: Vec<ApprovedRule>,
    pub dirs: Vec<DirRule>,
    pub network: Network,
    /// Absolute, canonical project roots this secret may be used from outside
    /// the vault's own project. Empty: only inside it.
    pub from: Vec<String>,
}

impl RuleSet {
    /// A rule set that approves nothing is the same as none.
    pub fn is_empty(&self) -> bool {
        self.to_v2().is_empty() && self.from.is_empty()
    }

    /// What format 4 stored, in this format (`from` empty).
    pub fn from_v2(old: &v2::RuleSet) -> RuleSet {
        RuleSet {
            name: old.name.clone(),
            category: old.category.clone(),
            downgraded_from: old.downgraded_from.clone(),
            allow: old.allow.clone(),
            deny: old.deny.clone(),
            dirs: old.dirs.clone(),
            network: old.network.clone(),
            from: Vec::new(),
        }
    }

    /// The same rules without `from`, for the checks format 2 owns.
    pub fn to_v2(&self) -> v2::RuleSet {
        v2::RuleSet {
            name: self.name.clone(),
            category: self.category.clone(),
            downgraded_from: self.downgraded_from.clone(),
            allow: self.allow.clone(),
            deny: self.deny.clone(),
            dirs: self.dirs.clone(),
            network: self.network.clone(),
        }
    }
}

fn valid_from(p: &str) -> bool {
    !p.is_empty() && p.len() <= v2::MAX_PATH_LEN && v2::portable_absolute(p)
}

/// The shape checks of a reader, for rule sets a writer is about to store.
pub fn check_binding_shapes(sets: &[RuleSet]) -> Result<(), Error> {
    for b in sets {
        v2::check_binding_shapes(std::slice::from_ref(&b.to_v2()))?;
        if b.from.len() > MAX_FROM || !b.from.iter().all(|p| valid_from(p)) {
            return Err(Error::Corrupt("bindings"));
        }
    }
    Ok(())
}

/// Rule sets name secrets that exist, once each, and carry well-formed rules.
fn check_bindings(index: &[Entry], sets: &[RuleSet]) -> Result<(), Error> {
    let old: Vec<v2::RuleSet> = sets.iter().map(RuleSet::to_v2).collect();
    // `is_empty` of the v2 part would refuse a rule set that has only `from`;
    // that is the same as none, so it is refused here too.
    v2::check_bindings(index, &old)?;
    check_binding_shapes(sets)
}

// --- Body and model ---------------------------------------------------------------------

/// The wire body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    pub header: Header,
    pub slots: Vec<Slot>,
    pub owner: Owner,
    pub recipients: Vec<Recipient>,
    pub devices: Vec<Device>,
    pub index: Vec<Entry>,
    pub secrets: Vec<Sealed>,
    pub bindings: Vec<RuleSet>,
    pub successors: Vec<Successor>,
    /// The person's opt-in: usable from outside its own project.
    pub remote: bool,
}

/// The body with the recipient list parsed: what the rest of the crate edits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Model {
    pub header: Header,
    pub slots: Vec<Slot>,
    pub owner: Owner,
    pub recipients: Vec<Recipient>,
    pub devices: Vec<Device>,
    pub index: Vec<Entry>,
    pub secrets: Vec<Sealed>,
    pub bindings: Vec<RuleSet>,
    pub successors: Vec<Successor>,
    /// The person's opt-in: usable from outside its own project.
    pub remote: bool,
}

impl Model {
    /// A format 4 model's facts in this format: remote use off, no `from`.
    /// The sealed secrets are copied as they are (still sealed for format 4
    /// until `upgrade` re-seals them).
    pub fn from_v3(old: &v3::Model) -> Model {
        Model {
            header: old.header.clone(),
            slots: old.slots.clone(),
            owner: old.owner.clone(),
            recipients: old.recipients.clone(),
            devices: old.devices.clone(),
            index: old.index.clone(),
            secrets: old.secrets.clone(),
            bindings: old.bindings.iter().map(RuleSet::from_v2).collect(),
            successors: old.successors.clone(),
            remote: false,
        }
    }

    /// A format 2 model's facts in this format, with no successors.
    pub fn from_v2(old: &v2::Model) -> Model {
        Model::from_v3(&v3::Model::from_v2(old))
    }

    /// A format 1 model's facts in this format.
    pub fn from_v1(old: &v1::Model) -> Model {
        Model::from_v3(&v3::Model::from_v1(old))
    }
}

/// A file that parsed and whose signatures check, not yet unlocked.
#[derive(Debug, Clone)]
pub struct Decoded {
    pub fmt: u16,
    pub model: Model,
    pub signer: Actor,
}

/// A file opened with the vault key.
#[derive(Clone)]
pub struct Unlocked {
    pub fmt: u16,
    pub vk: Zeroizing<[u8; KEY_LEN]>,
    pub model: Model,
}

impl std::fmt::Debug for Unlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unlocked")
            .field("fmt", &self.fmt)
            .field("vault_id", &hex_encode(&self.model.header.vault_id))
            .field("secrets", &self.model.secrets.len())
            .finish_non_exhaustive()
    }
}

// --- Decode ---------------------------------------------------------------------------------

/// Parse and check a frame as format 4: structure, membership certificates,
/// the successor chain, signer permission and the file signature. No password
/// needed.
pub fn decode(frame: &Frame<'_>) -> Result<Decoded, Error> {
    let body: Body = exact(frame.body, "body")?;
    let sig_section: SigSection = exact(frame.sig, "signature section")?;

    check_slots(&body.slots)?;
    if body.index.len() > v1::MAX_ENTRIES || body.secrets.len() != body.index.len() {
        return Err(Error::Corrupt("index"));
    }
    v1::check_recipients(&body.header.vault_id, &body.owner, &body.recipients)?;
    v1::check_index(&body.index, &body.secrets, &body.recipients)?;
    check_devices(&body.devices)?;
    check_bindings(&body.index, &body.bindings)?;
    check_successors(&body.header.vault_id, &body.owner.sign_pk, &body.successors)?;

    let signer_pk = match sig_section.signer {
        Actor::Owner => body.owner.sign_pk,
        Actor::Recipient(id) => {
            let r = body
                .recipients
                .iter()
                .find(|r| r.id == id)
                .ok_or(Error::SignerNotAllowed)?;
            // A runner never signs a vault; admins and editors may.
            if r.role == Role::Runner {
                return Err(Error::SignerNotAllowed);
            }
            r.sign_pk
        }
    };
    if !crypto::verify(&signer_pk, frame.signed, &sig_section.sig.0) {
        return Err(Error::BadSignature);
    }

    Ok(Decoded {
        fmt: FORMAT,
        signer: sig_section.signer,
        model: Model {
            header: body.header,
            slots: body.slots,
            owner: body.owner,
            recipients: body.recipients,
            devices: body.devices,
            index: body.index,
            secrets: body.secrets,
            bindings: body.bindings,
            successors: body.successors,
            remote: body.remote,
        },
    })
}

// --- Creating and unlocking -------------------------------------------------------------------

/// A new, empty vault in `fmt`, with a password slot and, unless
/// `with_recovery` is false, a recovery slot and its paper key.
pub fn create(
    fmt: u16,
    pw: &[u8],
    kdf: KdfParams,
    with_recovery: bool,
) -> Result<(Unlocked, Option<RecoveryKey>), Error> {
    let (u, key) = v2::create(fmt, pw, kdf, with_recovery)?;
    Ok((
        Unlocked {
            fmt: u.fmt,
            vk: u.vk.clone(),
            model: Model::from_v3(&v3::Model::from_v2(&u.model)),
        },
        key,
    ))
}

fn finish_unlock(d: &Decoded, vk: Zeroizing<Vec<u8>>) -> Result<Unlocked, Error> {
    let vk: [u8; KEY_LEN] = vk.as_slice().try_into().map_err(|_| Error::Unlock)?;
    let vk = Zeroizing::new(vk);
    // The vault key must derive the owner key the file claims; otherwise the
    // file's owner is not who unlocked it.
    let keys = owner_keys(&vk);
    if keys.sign_pk != d.model.owner.sign_pk || keys.enc_pk != d.model.owner.enc_pk {
        return Err(Error::Corrupt("owner key"));
    }
    Ok(Unlocked {
        fmt: d.fmt,
        vk,
        model: d.model.clone(),
    })
}

/// Unlock with the password. The KDF floor is checked before any work. Slots
/// of other kinds, known or not, are not looked at.
pub fn unlock_password(d: &Decoded, pw: &[u8]) -> Result<Unlocked, Error> {
    let slot = d
        .model
        .slots
        .iter()
        .find(|s| s.kind == SLOT_PASSWORD)
        .ok_or(Error::Unlock)?;
    let p = PasswordParams::decode(&slot.params).ok_or(Error::Unlock)?;
    let cost = KdfParams {
        m_kib: p.m_kib,
        t: p.t,
        p: p.p,
    };
    if !cost.meets(&crypto::kdf_floor()) {
        return Err(Error::KdfBelowFloor);
    }
    let kek = crypto::argon2id(pw, &p.salt, p.m_kib, p.t, p.p)?;
    finish_unlock(d, slot.open(&d.model.header.vault_id, &kek)?)
}

/// Whether `key` opens the recovery slot of `model`.
pub fn recovery_key_matches(model: &Model, key: &RecoveryKey) -> bool {
    let Some(slot) = model.slots.iter().find(|s| s.kind == SLOT_RECOVERY) else {
        return false;
    };
    slot.open(&model.header.vault_id, &recovery_kek(key))
        .is_ok()
}

/// Unlock with the paper key.
pub fn unlock_recovery(d: &Decoded, key: &RecoveryKey) -> Result<Unlocked, Error> {
    let slot = d
        .model
        .slots
        .iter()
        .find(|s| s.kind == SLOT_RECOVERY)
        .ok_or(Error::Unlock)?;
    finish_unlock(d, slot.open(&d.model.header.vault_id, &recovery_kek(key))?)
}

/// Unlock with the slot `slot_id` and the key-encryption key the caller derived
/// for it. Works for any kind, because the key arrives ready; an expired slot
/// or one that `kek` does not open is [`Error::Unlock`].
pub fn unlock_slot(
    d: &Decoded,
    slot_id: &[u8; 16],
    kek: &[u8; KEY_LEN],
) -> Result<Unlocked, Error> {
    let slot = d
        .model
        .slots
        .iter()
        .find(|s| &s.slot_id == slot_id)
        .ok_or(Error::Unlock)?;
    finish_unlock(d, slot.open(&d.model.header.vault_id, kek)?)
}

/// What a recipient proves to open a vault: its id and the private key that
/// matches the public key listed for it. Every wrap it holds must open.
pub fn check_recipient(
    d: &Decoded,
    recipient_id: &[u8; 16],
    enc_sk: &[u8; KEY_LEN],
) -> Result<Recipient, Error> {
    let recipient = d
        .model
        .recipients
        .iter()
        .find(|r| &r.id == recipient_id)
        .ok_or(Error::Unlock)?;
    if crypto::enc_public_from_secret(enc_sk)? != recipient.enc_pk {
        return Err(Error::Unlock);
    }
    let vault_id = &d.model.header.vault_id;
    for sealed in &d.model.secrets {
        if let Some(dek) = open_dek_as_recipient(d.fmt, vault_id, enc_sk, recipient_id, sealed)? {
            value_with_dek(d.fmt, vault_id, &dek, sealed)?;
        }
    }
    Ok(recipient.clone())
}

// --- Encode ---------------------------------------------------------------------------------------

/// Encode `model` as a signed format-4 file, signed by the owner.
pub fn encode(model: &Model, owner_key: &SigningKey) -> Result<Vec<u8>, Error> {
    encode_as(FORMAT, model, Actor::Owner, owner_key)
}

/// Encode with an explicit format number and signer.
pub fn encode_as(
    fmt: u16,
    model: &Model,
    signer: Actor,
    signer_key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    let body = Body {
        header: model.header.clone(),
        slots: model.slots.clone(),
        owner: model.owner.clone(),
        recipients: model.recipients.clone(),
        devices: model.devices.clone(),
        index: model.index.clone(),
        secrets: model.secrets.clone(),
        bindings: model.bindings.clone(),
        successors: model.successors.clone(),
        remote: model.remote,
    };
    let body_bytes = postcard::to_allocvec(&body).map_err(|_| Error::Corrupt("encode"))?;
    let body_len = u32::try_from(body_bytes.len()).map_err(|_| Error::TooLarge)?;

    let mut out = Vec::with_capacity(body_bytes.len() + 128);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&fmt.to_le_bytes());
    out.extend_from_slice(&body_len.to_le_bytes());
    out.extend_from_slice(&body_bytes);
    let sig = Sig(crypto::sign(signer_key, &out));
    let section =
        postcard::to_allocvec(&SigSection { signer, sig }).map_err(|_| Error::Corrupt("encode"))?;
    out.extend_from_slice(&section);
    if out.len() > super::MAX_FILE {
        return Err(Error::TooLarge);
    }
    Ok(out)
}
