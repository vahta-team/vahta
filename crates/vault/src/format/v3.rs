//! Format 3 of `vault.vht`: format 2 plus the owner successor chain.
//!
//! The frame and everything else in the body are format 2's, re-exported
//! here; what format 3 adds is one list, `successors`, at the end of the
//! signed body.
//!
//! A re-key (`Vault::rekey`) changes the vault key, and with it the owner's
//! signing key. A second machine that pinned the old key used to refuse the
//! file for good (`OwnerChanged`): nothing in it showed that the old owner
//! had approved the new one. Now the re-key leaves a [`Successor`]: the old
//! owner key signs "this vault's owner is now that key, from owner generation
//! N". The last [`MAX_SUCCESSORS`] such records are kept, oldest first, each
//! one starting where the one before ended.
//!
//! The chain alone is not trusted. A key that leaked together with a stolen
//! phone could sign a successor for an attacker's key. So a machine that
//! follows a chain does so only after the vault has been opened *here* with
//! the person's own secret (password, recovery key or device) and the person
//! has confirmed in a window; see `Vault::unlock_password_accepting`.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::v2;
pub use super::v2::*;
use super::{Frame, MAGIC};
use crate::crypto::{self, KEY_LEN, KdfParams};
use crate::{Error, RecoveryKey, hex_encode};

use super::v1::{self, exact};

/// This module's format number.
pub const FORMAT: u16 = 3;

/// How many successor records a file keeps.
pub const MAX_SUCCESSORS: usize = 4;

const DOMAIN_SUCCESSOR: &[u8] = b"vahta/successor";

// --- The successor chain -------------------------------------------------------------

/// "The owner of this vault is now `new_owner_sign_pub`", signed by the key
/// that was the owner until now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Successor {
    pub old_owner_sign_pub: [u8; 32],
    pub new_owner_sign_pub: [u8; 32],
    /// The owner generation: 1 for the first re-key, then one more each time.
    /// Strictly increasing along the chain. (Not the file's generation, which
    /// is only known when the file is saved.)
    pub generation: u64,
    pub created_at: u64,
    pub signature_by_old: Sig,
}

fn successor_message(
    vault_id: &[u8; 16],
    old: &[u8; 32],
    new: &[u8; 32],
    generation: u64,
    created_at: u64,
) -> Vec<u8> {
    let mut m = DOMAIN_SUCCESSOR.to_vec();
    m.extend_from_slice(vault_id);
    m.extend_from_slice(old);
    m.extend_from_slice(new);
    m.extend_from_slice(&generation.to_le_bytes());
    m.extend_from_slice(&created_at.to_le_bytes());
    m
}

impl Successor {
    /// A record from the old owner key to `new_owner_sign_pub`.
    pub fn sign(
        vault_id: &[u8; 16],
        old_key: &SigningKey,
        new_owner_sign_pub: [u8; 32],
        generation: u64,
        created_at: u64,
    ) -> Successor {
        let old = old_key.verifying_key().to_bytes();
        let msg = successor_message(vault_id, &old, &new_owner_sign_pub, generation, created_at);
        Successor {
            old_owner_sign_pub: old,
            new_owner_sign_pub,
            generation,
            created_at,
            signature_by_old: Sig(crypto::sign(old_key, &msg)),
        }
    }

    /// Whether the old key signed exactly this record.
    pub fn verifies(&self, vault_id: &[u8; 16]) -> bool {
        let msg = successor_message(
            vault_id,
            &self.old_owner_sign_pub,
            &self.new_owner_sign_pub,
            self.generation,
            self.created_at,
        );
        crypto::verify(&self.old_owner_sign_pub, &msg, &self.signature_by_old.0)
    }
}

/// The chain is well formed and ends at `owner_sign_pk`: every record is
/// signed by its old key, each starts where the one before ended, the owner
/// generation rises, and there are at most [`MAX_SUCCESSORS`]. An empty chain
/// is fine.
pub fn check_successors(
    vault_id: &[u8; 16],
    owner_sign_pk: &[u8; 32],
    chain: &[Successor],
) -> Result<(), Error> {
    let bad = Error::Corrupt("successors");
    if chain.len() > MAX_SUCCESSORS {
        return Err(bad);
    }
    for (i, s) in chain.iter().enumerate() {
        if s.old_owner_sign_pub == s.new_owner_sign_pub || !s.verifies(vault_id) {
            return Err(bad);
        }
        if let Some(prev) = i.checked_sub(1).map(|j| &chain[j])
            && (prev.new_owner_sign_pub != s.old_owner_sign_pub || prev.generation >= s.generation)
        {
            return Err(bad);
        }
    }
    if chain
        .last()
        .is_some_and(|s| &s.new_owner_sign_pub != owner_sign_pk)
    {
        return Err(bad);
    }
    Ok(())
}

/// The records of `chain` that lead from the key `pinned` to the owner at the
/// end, if `pinned` is in it as an old key. `chain` must have passed
/// [`check_successors`].
pub fn path_from<'a>(chain: &'a [Successor], pinned: &[u8; 32]) -> Option<&'a [Successor]> {
    let at = chain.iter().position(|s| &s.old_owner_sign_pub == pinned)?;
    Some(&chain[at..])
}

/// Append `s`, dropping the oldest records beyond [`MAX_SUCCESSORS`].
pub fn push_successor(chain: &mut Vec<Successor>, s: Successor) {
    chain.push(s);
    while chain.len() > MAX_SUCCESSORS {
        chain.remove(0);
    }
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
}

impl Model {
    /// A format 2 model's facts in this format, with no successors. The
    /// sealed secrets are copied as they are (still sealed for format 2 until
    /// `upgrade` re-seals them).
    pub fn from_v2(old: &v2::Model) -> Model {
        Model {
            header: old.header.clone(),
            slots: old.slots.clone(),
            owner: old.owner.clone(),
            recipients: old.recipients.clone(),
            devices: old.devices.clone(),
            index: old.index.clone(),
            secrets: old.secrets.clone(),
            bindings: old.bindings.clone(),
            successors: Vec::new(),
        }
    }

    /// A format 1 model's facts in this format.
    pub fn from_v1(old: &v1::Model) -> Model {
        Model::from_v2(&v2::Model::from_v1(old))
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

/// Parse and check a frame as format 3: structure, membership certificates,
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
    v2::check_bindings(&body.index, &body.bindings)?;
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
            model: Model::from_v2(&u.model),
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

/// Encode `model` as a signed format-3 file, signed by the owner.
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
