//! Format 1 of `vault.vht`: its types, how it is read and checked, how it is
//! unlocked, and how it is written.
//!
//! This module is frozen the moment format 1 is released: a later format gets
//! its own copy and this one changes only for bug fixes. The in-memory
//! [`Model`] and [`Unlocked`] are the "current" types until a newer format
//! replaces them; `format::current` names whichever module that is.
//!
//! Layout, after the frame that `format/mod.rs` owns (`magic`, `format`,
//! `body_len`, `body`, signature section):
//!
//! * `body` is a postcard-encoded [`Body`]: header, key slots, owner keys, the
//!   owner-signed recipient list, the plaintext name index, the sealed
//!   secrets. Integers inside it are postcard varints.
//! * The signature section is a postcard-encoded [`SigSection`]. The signature
//!   covers the stored bytes from the magic through the end of the body, so
//!   nothing is re-encoded to verify it.
//!
//! A value is sealed in three layers: padded (`u32 length ‖ value ‖ zeros`, to
//! the next power of two, at least 64 bytes), encrypted under a random
//! per-secret key (the DEK) with XChaCha20-Poly1305, and the DEK is wrapped
//! once for the owner (under a key derived from the vault key) and once for
//! each granted recipient (HPKE). Every AEAD binds `magic ‖ format ‖ vault_id`
//! and then the slot kind or the secret id, so nothing can be moved to another
//! vault, another format or another secret.

use std::fmt;

use ed25519_dalek::SigningKey;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use super::{Frame, MAGIC};
use crate::crypto::{self, KEY_LEN, KdfParams, TAG_LEN};
use crate::{Error, RecoveryKey, SecretValue, hex_encode, valid_name};

/// This module's format number.
pub const FORMAT: u16 = 1;

const INFO_OWNER_SIGN: &[u8] = b"vahta/v1/owner-sign";
const INFO_OWNER_ENC: &[u8] = b"vahta/v1/owner-enc";
const INFO_DEK_WRAP: &[u8] = b"vahta/v1/dek-wrap";
const INFO_DEK_HPKE: &[u8] = b"vahta/v1/dek";
const INFO_RECOVERY: &[u8] = b"vahta/v1/recovery-kek";
const DOMAIN_RECIPIENTS: &[u8] = b"vahta/v1/recipients";

const SLOT_PASSWORD: u8 = 0;
const SLOT_RECOVERY: u8 = 1;

const MAX_ENTRIES: usize = 100_000;
const MAX_RECIPIENTS: usize = 4096;
const WRAPPED_KEY_LEN: usize = KEY_LEN + TAG_LEN;

/// An Ed25519 signature. `serde` has no impl for 64-byte arrays, so this
/// writes it as a 64-element tuple, which postcard stores as 64 raw bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sig(pub [u8; 64]);

impl fmt::Debug for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sig(..)")
    }
}

impl Serialize for Sig {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut t = s.serialize_tuple(64)?;
        for b in &self.0 {
            t.serialize_element(b)?;
        }
        t.end()
    }
}

impl<'de> Deserialize<'de> for Sig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Sig;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("64 bytes")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Sig, A::Error> {
                let mut out = [0u8; 64];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(Sig(out))
            }
        }
        d.deserialize_tuple(64, V)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub vault_id: [u8; 16],
    pub generation: u64,
    pub created: u64,
    pub updated: u64,
}

/// A way to recover the vault key. Each wraps the 32-byte vault key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Slot {
    /// The key-encryption key is Argon2id of the password.
    Password {
        salt: [u8; 16],
        m_kib: u32,
        t: u32,
        p: u32,
        nonce: [u8; 24],
        ct: Vec<u8>,
    },
    /// The key-encryption key is HKDF of a 32-byte random paper key. No
    /// Argon2: the key has full entropy.
    Recovery { nonce: [u8; 24], ct: Vec<u8> },
}

impl Slot {
    fn kind_byte(&self) -> u8 {
        match self {
            Slot::Password { .. } => SLOT_PASSWORD,
            Slot::Recovery { .. } => SLOT_RECOVERY,
        }
    }
}

/// The owner's public keys, both derived from the vault key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owner {
    pub sign_pk: [u8; 32],
    pub enc_pk: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecipientKind {
    Person,
    Device,
    Cloud,
}

/// What a recipient may do. The owner is not a recipient and changes
/// membership alone in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Admin,
    Editor,
    Runner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient {
    pub id: [u8; 16],
    pub name: String,
    pub kind: RecipientKind,
    pub role: Role,
    pub enc_pk: [u8; 32],
    pub sign_pk: [u8; 32],
    pub added: u64,
}

/// The recipient list as stored: its postcard bytes, kept verbatim so the
/// owner's signature is checked against exactly what was signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientBlock {
    pub list: Vec<u8>,
    pub sig: Sig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Env,
    /// To be injected as a file; `file_name` is a hint. Only stored for now.
    File {
        file_name: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    Session,
    EachUse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Actor {
    Owner,
    Recipient([u8; 16]),
}

/// One line of the plaintext, signed name index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub secret_id: [u8; 16],
    pub name: String,
    pub kind: Kind,
    pub tier: Tier,
    pub updated: u64,
    pub changed_by: Actor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapBlob {
    pub nonce: [u8; 24],
    pub ct: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientWrap {
    pub recipient_id: [u8; 16],
    pub enc: [u8; 32],
    pub ct: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub secret_id: [u8; 16],
    pub nonce: [u8; 24],
    pub ct: Vec<u8>,
    pub owner_wrap: WrapBlob,
    pub wraps: Vec<RecipientWrap>,
}

/// The wire body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    pub header: Header,
    pub slots: Vec<Slot>,
    pub owner: Owner,
    pub recipients: RecipientBlock,
    pub index: Vec<Entry>,
    pub secrets: Vec<Sealed>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigSection {
    pub signer: Actor,
    pub sig: Sig,
}

/// The body with the recipient list parsed: what the rest of the crate edits.
/// `secrets[i]` is the secret of `index[i]`; the reader enforces it and every
/// edit keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Model {
    pub header: Header,
    pub slots: Vec<Slot>,
    pub owner: Owner,
    pub recipients: Vec<Recipient>,
    pub index: Vec<Entry>,
    pub secrets: Vec<Sealed>,
}

/// A file that parsed and whose signatures check, not yet unlocked.
#[derive(Debug, Clone)]
pub struct Decoded {
    /// The format number the file carries (and its AADs were made with).
    pub fmt: u16,
    pub model: Model,
    pub signer: Actor,
}

/// A file opened with the vault key.
pub struct Unlocked {
    pub fmt: u16,
    pub vk: Zeroizing<[u8; KEY_LEN]>,
    pub model: Model,
}

impl fmt::Debug for Unlocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unlocked")
            .field("fmt", &self.fmt)
            .field("vault_id", &hex_encode(&self.model.header.vault_id))
            .field("secrets", &self.model.secrets.len())
            .finish_non_exhaustive()
    }
}

/// A recipient's read-only view: the index and the values it holds wraps for.
pub struct RecipientView {
    pub fmt: u16,
    pub header: Header,
    pub owner: Owner,
    pub recipient: Recipient,
    pub entries: Vec<Entry>,
    pub values: Vec<(String, SecretValue)>,
}

// --- AAD ---------------------------------------------------------------------

fn aad_prefix(fmt: u16, vault_id: &[u8; 16]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + 2 + 16 + 16);
    v.extend_from_slice(MAGIC);
    v.extend_from_slice(&fmt.to_le_bytes());
    v.extend_from_slice(vault_id);
    v
}

fn slot_aad(fmt: u16, vault_id: &[u8; 16], kind: u8) -> Vec<u8> {
    let mut v = aad_prefix(fmt, vault_id);
    v.push(kind);
    v
}

fn secret_aad(fmt: u16, vault_id: &[u8; 16], secret_id: &[u8; 16]) -> Vec<u8> {
    let mut v = aad_prefix(fmt, vault_id);
    v.extend_from_slice(secret_id);
    v
}

fn recipients_message(vault_id: &[u8; 16], list: &[u8]) -> Vec<u8> {
    let mut m = DOMAIN_RECIPIENTS.to_vec();
    m.extend_from_slice(vault_id);
    m.extend_from_slice(list);
    m
}

// --- Validation helpers --------------------------------------------------------

/// A plain file name: no separators, no NUL, not `.` or `..`.
pub fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', '\0'])
}

fn valid_recipient_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128 && !name.chars().any(char::is_control)
}

fn only<T>(items: &[T], f: impl Fn(&T) -> bool) -> bool {
    items.iter().filter(|i| f(i)).count() <= 1
}

fn exact<'a, T: Deserialize<'a>>(bytes: &'a [u8], what: &'static str) -> Result<T, Error> {
    match postcard::take_from_bytes::<T>(bytes) {
        Ok((value, [])) => Ok(value),
        _ => Err(Error::Corrupt(what)),
    }
}

// --- Decode and verify -----------------------------------------------------------

/// Parse and check a frame as format 1: structure, owner-signed recipient
/// list, signer permission and the file signature. No password needed.
pub fn decode(frame: &Frame<'_>) -> Result<Decoded, Error> {
    decode_as(frame, FORMAT)
}

/// [`decode`] for a file whose AADs and frame carry `fmt`. A format with the
/// same layout as format 1 (the test pseudo-format) reads through this.
pub(crate) fn decode_as(frame: &Frame<'_>, fmt: u16) -> Result<Decoded, Error> {
    let body: Body = exact(frame.body, "body")?;
    let sig_section: SigSection = exact(frame.sig, "signature section")?;

    check_slots(&body.slots)?;
    if body.index.len() > MAX_ENTRIES || body.secrets.len() != body.index.len() {
        return Err(Error::Corrupt("index"));
    }

    let vault_id = body.header.vault_id;
    let list_msg = recipients_message(&vault_id, &body.recipients.list);
    if !crypto::verify(&body.owner.sign_pk, &list_msg, &body.recipients.sig.0) {
        return Err(Error::BadSignature);
    }
    let recipients: Vec<Recipient> = exact(&body.recipients.list, "recipient list")?;
    check_recipients(&recipients)?;
    check_index(&body, &recipients)?;

    let signer_pk = match sig_section.signer {
        Actor::Owner => body.owner.sign_pk,
        Actor::Recipient(id) => {
            let r = recipients
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
        fmt,
        signer: sig_section.signer,
        model: Model {
            header: body.header,
            slots: body.slots,
            owner: body.owner,
            recipients,
            index: body.index,
            secrets: body.secrets,
        },
    })
}

fn check_slots(slots: &[Slot]) -> Result<(), Error> {
    if slots.is_empty()
        || slots.len() > 2
        || !only(slots, |s| s.kind_byte() == SLOT_PASSWORD)
        || !only(slots, |s| s.kind_byte() == SLOT_RECOVERY)
    {
        return Err(Error::Corrupt("slots"));
    }
    for slot in slots {
        match slot {
            Slot::Password {
                m_kib, t, p, ct, ..
            } => {
                let cost = KdfParams {
                    m_kib: *m_kib,
                    t: *t,
                    p: *p,
                };
                // A lower bound is the floor, checked at unlock. This is the
                // upper bound, so a hostile file cannot ask for ruin.
                if !crypto::KDF_CEILING.meets(&cost) || *m_kib == 0 || *t == 0 || *p == 0 {
                    return Err(Error::Corrupt("kdf parameters"));
                }
                if ct.len() != WRAPPED_KEY_LEN {
                    return Err(Error::Corrupt("slot"));
                }
            }
            Slot::Recovery { ct, .. } => {
                if ct.len() != WRAPPED_KEY_LEN {
                    return Err(Error::Corrupt("slot"));
                }
            }
        }
    }
    Ok(())
}

fn check_recipients(list: &[Recipient]) -> Result<(), Error> {
    if list.len() > MAX_RECIPIENTS {
        return Err(Error::Corrupt("recipients"));
    }
    for (i, r) in list.iter().enumerate() {
        if !valid_recipient_name(&r.name)
            || list[..i].iter().any(|o| o.id == r.id || o.name == r.name)
        {
            return Err(Error::Corrupt("recipients"));
        }
    }
    Ok(())
}

fn check_index(body: &Body, recipients: &[Recipient]) -> Result<(), Error> {
    for (i, e) in body.index.iter().enumerate() {
        if !valid_name(&e.name) {
            return Err(Error::Corrupt("name"));
        }
        if let Kind::File { file_name } = &e.kind
            && !valid_file_name(file_name)
        {
            return Err(Error::Corrupt("file name"));
        }
        if body.index[..i]
            .iter()
            .any(|o| o.name == e.name || o.secret_id == e.secret_id)
        {
            return Err(Error::Corrupt("duplicate name"));
        }
        // The secrets list is in index order, so an entry's secret is found by
        // position. Writers keep this; a file that breaks it is refused.
        let s = &body.secrets[i];
        if s.secret_id != e.secret_id {
            return Err(Error::Corrupt("index and secrets disagree"));
        }
        let body_len = s.ct.len().saturating_sub(TAG_LEN);
        if s.ct.len() < TAG_LEN
            || !body_len.is_power_of_two()
            || body_len < crypto::MIN_PADDED
            || body_len > crypto::padded_len(crypto::MAX_VALUE)
            || s.owner_wrap.ct.len() != WRAPPED_KEY_LEN
        {
            return Err(Error::Corrupt("secret"));
        }
        for (j, w) in s.wraps.iter().enumerate() {
            if w.ct.len() != WRAPPED_KEY_LEN
                || !recipients.iter().any(|r| r.id == w.recipient_id)
                || s.wraps[..j]
                    .iter()
                    .any(|o| o.recipient_id == w.recipient_id)
            {
                return Err(Error::Corrupt("wraps"));
            }
        }
    }
    Ok(())
}

// --- Keys -------------------------------------------------------------------------

pub struct OwnerKeys {
    pub sign: SigningKey,
    pub sign_pk: [u8; 32],
    pub enc_pk: [u8; 32],
}

/// Both owner key pairs, derived from the vault key.
pub fn owner_keys(vk: &[u8; KEY_LEN]) -> OwnerKeys {
    let sign = crypto::signing_key(&crypto::hkdf(vk, INFO_OWNER_SIGN));
    let (_, enc_pk) = crypto::enc_keypair_from_seed(&crypto::hkdf(vk, INFO_OWNER_ENC));
    OwnerKeys {
        sign_pk: sign.verifying_key().to_bytes(),
        sign,
        enc_pk,
    }
}

fn dek_wrap_key(vk: &[u8; KEY_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
    crypto::hkdf(vk, INFO_DEK_WRAP)
}

// --- Creating and unlocking ---------------------------------------------------------

/// A password slot wrapping `vk`.
pub fn password_slot(
    fmt: u16,
    vault_id: &[u8; 16],
    vk: &[u8; KEY_LEN],
    password: &[u8],
    kdf: KdfParams,
) -> Result<Slot, Error> {
    if !kdf.meets(&crypto::kdf_floor()) {
        return Err(Error::KdfBelowFloor);
    }
    let salt = crypto::random::<16>()?;
    let kek = crypto::argon2id(password, &salt, kdf.m_kib, kdf.t, kdf.p)?;
    let (nonce, ct) = crypto::seal(&kek, &slot_aad(fmt, vault_id, SLOT_PASSWORD), vk)?;
    Ok(Slot::Password {
        salt,
        m_kib: kdf.m_kib,
        t: kdf.t,
        p: kdf.p,
        nonce,
        ct,
    })
}

fn recovery_slot(
    fmt: u16,
    vault_id: &[u8; 16],
    vk: &[u8; KEY_LEN],
    key: &[u8; 32],
) -> Result<Slot, Error> {
    let kek = crypto::hkdf(key, INFO_RECOVERY);
    let (nonce, ct) = crypto::seal(&kek, &slot_aad(fmt, vault_id, SLOT_RECOVERY), vk)?;
    Ok(Slot::Recovery { nonce, ct })
}

/// A new, empty vault in `fmt`, with a password slot and, unless
/// `with_recovery` is false, a recovery slot and its paper key.
pub fn create(
    fmt: u16,
    password: &[u8],
    kdf: KdfParams,
    with_recovery: bool,
) -> Result<(Unlocked, Option<RecoveryKey>), Error> {
    let vk = Zeroizing::new(crypto::random::<KEY_LEN>()?);
    let vault_id = crypto::random::<16>()?;
    let mut slots = vec![password_slot(fmt, &vault_id, &vk, password, kdf)?];
    let recovery = if with_recovery {
        let key = RecoveryKey::new(crypto::random::<32>()?);
        slots.push(recovery_slot(fmt, &vault_id, &vk, key.bytes())?);
        Some(key)
    } else {
        None
    };
    let keys = owner_keys(&vk);
    let now = crate::now();
    Ok((
        Unlocked {
            fmt,
            vk,
            model: Model {
                header: Header {
                    vault_id,
                    generation: 0,
                    created: now,
                    updated: now,
                },
                slots,
                owner: Owner {
                    sign_pk: keys.sign_pk,
                    enc_pk: keys.enc_pk,
                },
                recipients: Vec::new(),
                index: Vec::new(),
                secrets: Vec::new(),
            },
        },
        recovery,
    ))
}

fn finish_unlock(d: &Decoded, vk: Zeroizing<Vec<u8>>) -> Result<Unlocked, Error> {
    let vk: [u8; KEY_LEN] = vk.as_slice().try_into().map_err(|_| Error::Unlock)?;
    let vk = Zeroizing::new(vk);
    // The vault key must derive the owner key the file claims; otherwise the
    // file's owner is not who unlocked it.
    if owner_keys(&vk).sign_pk != d.model.owner.sign_pk {
        return Err(Error::Corrupt("owner key"));
    }
    Ok(Unlocked {
        fmt: d.fmt,
        vk,
        model: d.model.clone(),
    })
}

/// Unlock with the password. The KDF floor is checked before any work.
pub fn unlock_password(d: &Decoded, password: &[u8]) -> Result<Unlocked, Error> {
    let Some(Slot::Password {
        salt,
        m_kib,
        t,
        p,
        nonce,
        ct,
    }) = d
        .model
        .slots
        .iter()
        .find(|s| s.kind_byte() == SLOT_PASSWORD)
    else {
        return Err(Error::Unlock);
    };
    let cost = KdfParams {
        m_kib: *m_kib,
        t: *t,
        p: *p,
    };
    if !cost.meets(&crypto::kdf_floor()) {
        return Err(Error::KdfBelowFloor);
    }
    let kek = crypto::argon2id(password, salt, *m_kib, *t, *p)?;
    let aad = slot_aad(d.fmt, &d.model.header.vault_id, SLOT_PASSWORD);
    finish_unlock(d, crypto::open(&kek, nonce, &aad, ct)?)
}

/// Unlock with the paper key.
pub fn unlock_recovery(d: &Decoded, key: &RecoveryKey) -> Result<Unlocked, Error> {
    let Some(Slot::Recovery { nonce, ct }) = d
        .model
        .slots
        .iter()
        .find(|s| s.kind_byte() == SLOT_RECOVERY)
    else {
        return Err(Error::Unlock);
    };
    let kek = crypto::hkdf(key.bytes(), INFO_RECOVERY);
    let aad = slot_aad(d.fmt, &d.model.header.vault_id, SLOT_RECOVERY);
    finish_unlock(d, crypto::open(&kek, nonce, &aad, ct)?)
}

/// Open as a recipient: only the secrets it holds a wrap for are decrypted.
pub fn unlock_recipient(
    d: &Decoded,
    recipient_id: &[u8; 16],
    enc_sk: &[u8; KEY_LEN],
) -> Result<RecipientView, Error> {
    let vault_id = &d.model.header.vault_id;
    let recipient = d
        .model
        .recipients
        .iter()
        .find(|r| &r.id == recipient_id)
        .ok_or(Error::Unlock)?;
    if crypto::enc_public_from_secret(enc_sk)? != recipient.enc_pk {
        return Err(Error::Unlock);
    }
    let mut values = Vec::new();
    for entry in &d.model.index {
        let Some(sealed) = d
            .model
            .secrets
            .iter()
            .find(|s| s.secret_id == entry.secret_id)
        else {
            return Err(Error::Corrupt("index and secrets disagree"));
        };
        let Some(wrap) = sealed
            .wraps
            .iter()
            .find(|w| &w.recipient_id == recipient_id)
        else {
            continue;
        };
        let aad = secret_aad(d.fmt, vault_id, &sealed.secret_id);
        let dek = crypto::hpke_open(enc_sk, &wrap.enc, INFO_DEK_HPKE, &aad, &wrap.ct)?;
        let dek: [u8; KEY_LEN] = dek.as_slice().try_into().map_err(|_| Error::Unlock)?;
        let value = open_with_dek(&Zeroizing::new(dek), &aad, sealed)?;
        values.push((entry.name.clone(), value));
    }
    Ok(RecipientView {
        fmt: d.fmt,
        header: d.model.header.clone(),
        owner: d.model.owner.clone(),
        recipient: recipient.clone(),
        entries: d.model.index.clone(),
        values,
    })
}

// --- Sealing and opening secrets ------------------------------------------------------

fn open_with_dek(dek: &[u8; KEY_LEN], aad: &[u8], sealed: &Sealed) -> Result<SecretValue, Error> {
    let plain = crypto::open(dek, &sealed.nonce, aad, &sealed.ct)?;
    Ok(SecretValue::from_zeroizing(crypto::unpad(&plain)?))
}

/// The DEK of `sealed`, opened with the vault key.
pub fn open_dek(
    fmt: u16,
    vault_id: &[u8; 16],
    vk: &[u8; KEY_LEN],
    sealed: &Sealed,
) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let aad = secret_aad(fmt, vault_id, &sealed.secret_id);
    let dek = crypto::open(
        &dek_wrap_key(vk),
        &sealed.owner_wrap.nonce,
        &aad,
        &sealed.owner_wrap.ct,
    )?;
    let dek: [u8; KEY_LEN] = dek.as_slice().try_into().map_err(|_| Error::Unlock)?;
    Ok(Zeroizing::new(dek))
}

/// The value of `sealed`, opened with the vault key.
pub fn open_value(
    fmt: u16,
    vault_id: &[u8; 16],
    vk: &[u8; KEY_LEN],
    sealed: &Sealed,
) -> Result<SecretValue, Error> {
    let dek = open_dek(fmt, vault_id, vk, sealed)?;
    open_with_dek(&dek, &secret_aad(fmt, vault_id, &sealed.secret_id), sealed)
}

/// Wrap `dek` for one recipient.
pub fn wrap_for(
    fmt: u16,
    vault_id: &[u8; 16],
    secret_id: &[u8; 16],
    dek: &[u8; KEY_LEN],
    recipient: &Recipient,
) -> Result<RecipientWrap, Error> {
    let aad = secret_aad(fmt, vault_id, secret_id);
    let (enc, ct) = crypto::hpke_seal(&recipient.enc_pk, INFO_DEK_HPKE, &aad, dek)?;
    Ok(RecipientWrap {
        recipient_id: recipient.id,
        enc,
        ct,
    })
}

/// Seal `value` under a fresh DEK, wrapped for the owner and for `holders`.
pub fn seal_secret(
    fmt: u16,
    vault_id: &[u8; 16],
    secret_id: [u8; 16],
    vk: &[u8; KEY_LEN],
    value: &[u8],
    holders: &[&Recipient],
) -> Result<Sealed, Error> {
    let dek = Zeroizing::new(crypto::random::<KEY_LEN>()?);
    let aad = secret_aad(fmt, vault_id, &secret_id);
    let padded = crypto::pad(value)?;
    let (nonce, ct) = crypto::seal(&dek, &aad, &padded)?;
    let (wnonce, wct) = crypto::seal(&dek_wrap_key(vk), &aad, &*dek)?;
    let wraps = holders
        .iter()
        .map(|r| wrap_for(fmt, vault_id, &secret_id, &dek, r))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Sealed {
        secret_id,
        nonce,
        ct,
        owner_wrap: WrapBlob {
            nonce: wnonce,
            ct: wct,
        },
        wraps,
    })
}

// --- Encode -----------------------------------------------------------------------------

/// Encode `model` as a signed format-1 file, signed by the owner.
pub fn encode(model: &Model, owner_key: &SigningKey) -> Result<Vec<u8>, Error> {
    encode_as(FORMAT, model, owner_key, Actor::Owner, owner_key)
}

/// Encode with an explicit format number and signer. The owner key always
/// signs the recipient list; `signer_key` signs the file. Only the owner signs
/// in normal use; the rest exists so tests can build files the verifier must
/// refuse.
pub fn encode_as(
    fmt: u16,
    model: &Model,
    owner_key: &SigningKey,
    signer: Actor,
    signer_key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    let list = postcard::to_allocvec(&model.recipients).map_err(|_| Error::Corrupt("encode"))?;
    let sig = Sig(crypto::sign(
        owner_key,
        &recipients_message(&model.header.vault_id, &list),
    ));
    let body = Body {
        header: model.header.clone(),
        slots: model.slots.clone(),
        owner: model.owner.clone(),
        recipients: RecipientBlock { list, sig },
        index: model.index.clone(),
        secrets: model.secrets.clone(),
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
