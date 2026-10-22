//! Format 2 of `vault.vht`: generic key slots, rule sets with directories and
//! network, and paired-device records.
//!
//! The frame is format 1's; the body is a postcard-encoded [`Body`]. What
//! changed from format 1:
//!
//! * **Slots are generic.** A [`Slot`] is a `kind` number, an id, a label and
//!   two opaque byte strings: `params` (what the kind needs to derive its
//!   key-encryption key) and `ct` (the vault key wrapped under it, as
//!   `nonce ‖ sealed`). Password (kind 0) and recovery (kind 1) are kinds
//!   whose parameters sit in `params`. A kind this build does not know is
//!   carried through reads and writes untouched and skipped when unlocking, so
//!   a slot added by a newer Vahta never makes the file unreadable. A slot's
//!   AAD binds `"vahta/slot" ‖ slot_version ‖ vault_id ‖ kind ‖ slot_id`; a slot
//!   carried over from format 1 has `slot_version` 1, whose AAD is format 1's
//!   (no id, kind as one byte), so its bytes stay valid without any key.
//! * **Rule sets** (the approved rules of one secret) also hold the
//!   directories and the network a command may use, stored for the sandbox.
//! * **Devices**: the public keys and metadata of each paired device, covered
//!   by the owner's signature. Device *slots* are ordinary slots.
//!
//! Everything format 1 and 2 share (header, owner, recipients, index entries,
//! sealed secrets, signatures, the secret and wrap crypto) is format 1's
//! definition, re-exported here; a format that changes one of them copies it.

use std::fmt;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::v1::{
    self, INFO_RECOVERY, MAX_ENTRIES, MAX_RULE_TEXT, WRAPPED_KEY_LEN, check_index,
    check_recipients, check_rules, exact, only, valid_recipient_name,
};
use super::{Frame, MAGIC};
use crate::crypto::{self, KEY_LEN, KdfParams, NONCE_LEN};
use crate::{Error, RecoveryKey, hex_encode};

pub use super::v1::{
    Actor, ApprovedRule, Class, Entry, Header, Kind, Owner, OwnerKeys, OwnerWrap, Program,
    Recipient, RecipientKind, RecipientWrap, Role, Sealed, Sig, SigSection, Tier, open_dek,
    open_dek_as_recipient, open_value, owner_keys, seal_secret, valid_file_name, value_with_dek,
    wrap_for,
};

/// This module's format number.
pub const FORMAT: u16 = 2;

const DOMAIN_SLOT: &[u8] = b"vahta/slot";
const INFO_LEGACY_SLOT_ID: &[u8] = b"vahta/v2/legacy-slot-id";

/// Slot kind numbers. The first two are format 1's kind bytes. A new kind is
/// added by giving it the next number here; an old build skips it.
pub const SLOT_PASSWORD: u16 = 0;
pub const SLOT_RECOVERY: u16 = 1;
/// A paired device: the vault key wrapped under an ECDH-derived key (see
/// `vahta-auth`). Opaque to this crate, which treats it as any other slot.
pub const SLOT_DEVICE: u16 = 2;

/// The slot crypto version written today.
pub const SLOT_VERSION: u16 = 2;
/// The version of a slot carried over from format 1.
const LEGACY_SLOT_VERSION: u16 = 1;

/// Most slots a vault may hold, of any kind.
pub const MAX_SLOTS: usize = 16;
pub const MAX_LABEL: usize = 128;
const MAX_SLOT_PARAMS: usize = 256;
const MAX_SLOT_CT: usize = 1024;
/// `nonce ‖ AEAD(vault key)`: what the password and recovery kinds store.
const SEALED_KEY_LEN: usize = NONCE_LEN + WRAPPED_KEY_LEN;
const PASSWORD_PARAMS_LEN: usize = 16 + 4 + 4 + 4;

pub const MAX_DEVICES: usize = 64;
const MAX_TRANSPORTS: usize = 8;
const MAX_TRANSPORT_LEN: usize = 32;

pub const MAX_DIRS: usize = 64;
pub const MAX_HOSTS: usize = 64;
pub(super) const MAX_PATH_LEN: usize = 4096;
const MAX_HOST_LEN: usize = 253;
const MAX_CATEGORY_LEN: usize = 64;

// --- Slots ---------------------------------------------------------------------

/// A way to recover the vault key. See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slot {
    pub kind: u16,
    pub slot_id: [u8; 16],
    pub slot_version: u16,
    pub label: String,
    pub created_at: u64,
    /// After this time the slot no longer unlocks. Nothing removes it.
    pub expires_at: Option<u64>,
    pub params: Vec<u8>,
    /// `nonce (24) ‖ XChaCha20-Poly1305(vault key)`.
    pub ct: Vec<u8>,
}

/// A slot without its secret parts: what listings show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotInfo {
    pub kind: u16,
    pub slot_id: [u8; 16],
    pub label: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

/// The caller's description of a slot to add. `slot_id` is random when `None`;
/// a caller that pairs a slot with another record (a device) may choose it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSlot {
    pub kind: u16,
    pub slot_id: Option<[u8; 16]>,
    pub label: String,
    pub expires_at: Option<u64>,
    pub params: Vec<u8>,
}

impl Slot {
    pub fn info(&self) -> SlotInfo {
        SlotInfo {
            kind: self.kind,
            slot_id: self.slot_id,
            label: self.label.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
        }
    }

    pub fn expired(&self) -> bool {
        self.expires_at.is_some_and(|t| crate::now() >= t)
    }

    /// The AAD this slot's `ct` is bound to.
    pub fn aad(&self, vault_id: &[u8; 16]) -> Vec<u8> {
        slot_aad(self.slot_version, vault_id, &self.slot_id, self.kind)
    }

    /// The vault key, if `kek` opens this slot and it has not expired.
    pub fn open(
        &self,
        vault_id: &[u8; 16],
        kek: &[u8; KEY_LEN],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if self.expired() {
            return Err(Error::Unlock);
        }
        open_vault_key(kek, &self.aad(vault_id), &self.ct)
    }
}

/// A slot's AAD. Version 1 is format 1's, which a carried-over slot was sealed
/// with; later versions also bind the slot's id and a two-byte kind.
pub fn slot_aad(version: u16, vault_id: &[u8; 16], slot_id: &[u8; 16], kind: u16) -> Vec<u8> {
    let mut v = DOMAIN_SLOT.to_vec();
    v.extend_from_slice(&version.to_le_bytes());
    v.extend_from_slice(vault_id);
    if version == LEGACY_SLOT_VERSION {
        v.push(kind as u8);
    } else {
        v.extend_from_slice(&kind.to_le_bytes());
        v.extend_from_slice(slot_id);
    }
    v
}

/// Wrap the vault key under `kek`: `nonce ‖ sealed`, the form `Slot::ct` has.
pub fn seal_vault_key(
    kek: &[u8; KEY_LEN],
    aad: &[u8],
    vault_key: &[u8; KEY_LEN],
) -> Result<Vec<u8>, Error> {
    let (nonce, ct) = crypto::seal(kek, aad, vault_key)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// The inverse of [`seal_vault_key`].
pub fn open_vault_key(
    kek: &[u8; KEY_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (nonce, sealed) = ct.split_at_checked(NONCE_LEN).ok_or(Error::Unlock)?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::Unlock)?;
    crypto::open(kek, &nonce, aad, sealed)
}

/// The password kind's parameters: `salt ‖ m_kib ‖ t ‖ p`, integers little endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordParams {
    pub salt: [u8; 16],
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl PasswordParams {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(PASSWORD_PARAMS_LEN);
        v.extend_from_slice(&self.salt);
        v.extend_from_slice(&self.m_kib.to_le_bytes());
        v.extend_from_slice(&self.t.to_le_bytes());
        v.extend_from_slice(&self.p.to_le_bytes());
        v
    }

    pub fn decode(bytes: &[u8]) -> Option<PasswordParams> {
        if bytes.len() != PASSWORD_PARAMS_LEN {
            return None;
        }
        let int = |at: usize| {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        Some(PasswordParams {
            salt: bytes[..16].try_into().ok()?,
            m_kib: int(16),
            t: int(20),
            p: int(24),
        })
    }

    fn cost(&self) -> KdfParams {
        KdfParams {
            m_kib: self.m_kib,
            t: self.t,
            p: self.p,
        }
    }
}

/// A password slot wrapping `vk`.
pub fn password_slot(
    vault_id: &[u8; 16],
    vk: &[u8; KEY_LEN],
    pw: &[u8],
    kdf: KdfParams,
) -> Result<Slot, Error> {
    if !kdf.meets(&crypto::kdf_floor()) {
        return Err(Error::KdfBelowFloor);
    }
    let params = PasswordParams {
        salt: crypto::random::<16>()?,
        m_kib: kdf.m_kib,
        t: kdf.t,
        p: kdf.p,
    };
    let slot_id = crypto::random::<16>()?;
    let kek = crypto::argon2id(pw, &params.salt, kdf.m_kib, kdf.t, kdf.p)?;
    let aad = slot_aad(SLOT_VERSION, vault_id, &slot_id, SLOT_PASSWORD);
    Ok(Slot {
        kind: SLOT_PASSWORD,
        slot_id,
        slot_version: SLOT_VERSION,
        label: "password".into(),
        created_at: crate::now(),
        expires_at: None,
        params: params.encode(),
        ct: seal_vault_key(&kek, &aad, vk)?,
    })
}

/// A recovery slot wrapping `vk` under the paper key.
pub fn recovery_slot(
    vault_id: &[u8; 16],
    vk: &[u8; KEY_LEN],
    key: &RecoveryKey,
) -> Result<Slot, Error> {
    let slot_id = crypto::random::<16>()?;
    let kek = crypto::hkdf(key.bytes(), INFO_RECOVERY);
    let aad = slot_aad(SLOT_VERSION, vault_id, &slot_id, SLOT_RECOVERY);
    Ok(Slot {
        kind: SLOT_RECOVERY,
        slot_id,
        slot_version: SLOT_VERSION,
        label: "recovery".into(),
        created_at: crate::now(),
        expires_at: None,
        params: Vec::new(),
        ct: seal_vault_key(&kek, &aad, vk)?,
    })
}

/// The key-encryption key of the recovery slot for the paper key `key`.
pub fn recovery_kek(key: &RecoveryKey) -> Zeroizing<[u8; KEY_LEN]> {
    crypto::hkdf(key.bytes(), INFO_RECOVERY)
}

/// `old` with `vk` wrapped under `kek`: the same id, kind, label, expiry and
/// parameters, a new nonce and ciphertext. What a re-key does to the slots it
/// keeps. The result is a current-version slot (the AAD binds its id and kind).
pub fn rewrap_slot(
    vault_id: &[u8; 16],
    old: &Slot,
    vk: &[u8; KEY_LEN],
    kek: &[u8; KEY_LEN],
) -> Result<Slot, Error> {
    let aad = slot_aad(SLOT_VERSION, vault_id, &old.slot_id, old.kind);
    Ok(Slot {
        slot_version: SLOT_VERSION,
        created_at: crate::now(),
        ct: seal_vault_key(kek, &aad, vk)?,
        ..old.clone()
    })
}

/// A slot of a kind the caller defines. `wrap` receives the vault key and the
/// slot's AAD and returns `ct` (use [`seal_vault_key`] under the kind's KEK).
pub fn custom_slot(
    vault_id: &[u8; 16],
    vk: &[u8; KEY_LEN],
    new: NewSlot,
    wrap: impl FnOnce(&[u8; KEY_LEN], &[u8]) -> Result<Vec<u8>, Error>,
) -> Result<Slot, Error> {
    let slot_id = match new.slot_id {
        Some(id) => id,
        None => crypto::random::<16>()?,
    };
    let aad = slot_aad(SLOT_VERSION, vault_id, &slot_id, new.kind);
    let slot = Slot {
        kind: new.kind,
        slot_id,
        slot_version: SLOT_VERSION,
        label: new.label,
        created_at: crate::now(),
        expires_at: new.expires_at,
        params: new.params,
        ct: wrap(vk, &aad)?,
    };
    check_slot_shape(&slot).map_err(|_| Error::Invalid("slot"))?;
    Ok(slot)
}

/// A format 1 slot, bytes kept. It gets a deterministic id so that every open
/// of the same old file agrees on it.
fn slot_from_v1(vault_id: &[u8; 16], created_at: u64, old: &v1::Slot) -> Slot {
    let (kind, label, params, nonce, ct) = match old {
        v1::Slot::Password {
            salt,
            m_kib,
            t,
            p,
            nonce,
            ct,
            ..
        } => (
            SLOT_PASSWORD,
            "password",
            PasswordParams {
                salt: *salt,
                m_kib: *m_kib,
                t: *t,
                p: *p,
            }
            .encode(),
            nonce,
            ct,
        ),
        v1::Slot::Recovery { nonce, ct, .. } => (SLOT_RECOVERY, "recovery", Vec::new(), nonce, ct),
    };
    let mut info = INFO_LEGACY_SLOT_ID.to_vec();
    info.push(kind as u8);
    let mut slot_id = [0u8; 16];
    slot_id.copy_from_slice(&crypto::hkdf(vault_id, &info)[..16]);
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(ct);
    Slot {
        kind,
        slot_id,
        slot_version: LEGACY_SLOT_VERSION,
        label: label.into(),
        created_at,
        expires_at: None,
        params,
        ct: sealed,
    }
}

fn valid_label(label: &str) -> bool {
    label.len() <= MAX_LABEL && !label.chars().any(char::is_control)
}

/// The checks every slot passes, whatever its kind; the known kinds also have
/// their own. An unknown kind is held to length limits only.
fn check_slot_shape(slot: &Slot) -> Result<(), Error> {
    if !valid_label(&slot.label)
        || slot.params.len() > MAX_SLOT_PARAMS
        || slot.ct.len() > MAX_SLOT_CT
    {
        return Err(Error::Corrupt("slots"));
    }
    match slot.kind {
        SLOT_PASSWORD => {
            let Some(p) = PasswordParams::decode(&slot.params) else {
                return Err(Error::Corrupt("slot"));
            };
            // A lower bound is the floor, checked at unlock. This is the upper
            // bound, so a hostile file cannot ask for ruin.
            if !crypto::KDF_CEILING.meets(&p.cost()) || p.m_kib == 0 || p.t == 0 || p.p == 0 {
                return Err(Error::Corrupt("kdf parameters"));
            }
        }
        SLOT_RECOVERY if !slot.params.is_empty() => return Err(Error::Corrupt("slot")),
        _ => {}
    }
    if matches!(slot.kind, SLOT_PASSWORD | SLOT_RECOVERY) {
        if slot.slot_version != LEGACY_SLOT_VERSION && slot.slot_version != SLOT_VERSION {
            return Err(Error::Corrupt("slot version"));
        }
        if slot.ct.len() != SEALED_KEY_LEN {
            return Err(Error::Corrupt("slot"));
        }
    }
    Ok(())
}

pub fn check_slots(slots: &[Slot]) -> Result<(), Error> {
    if slots.is_empty()
        || slots.len() > MAX_SLOTS
        || !only(slots, |s| s.kind == SLOT_PASSWORD)
        || !only(slots, |s| s.kind == SLOT_RECOVERY)
    {
        return Err(Error::Corrupt("slots"));
    }
    for (i, s) in slots.iter().enumerate() {
        if slots[..i].iter().any(|o| o.slot_id == s.slot_id) {
            return Err(Error::Corrupt("slots"));
        }
        check_slot_shape(s)?;
    }
    Ok(())
}

// --- Rule sets -------------------------------------------------------------------

/// A directory a command may use. `path` is canonical and absolute (what the
/// person approved); `text` is what they saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirRule {
    pub text: String,
    pub path: String,
    /// Read-write when true, read-only when false.
    pub write: bool,
}

/// A network destination. `host` is a lowercase DNS name or an IP literal;
/// `subdomains` extends it to every name beneath it; `port` `None` is any port.
/// `text` is what the person approved; it starts with [`PRIVATE_MARK`] when the
/// rule lets the name resolve to a loopback, private or link-local address
/// (the marker lives in the text so the signed format does not change).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRule {
    pub text: String,
    pub host: String,
    pub subdomains: bool,
    pub port: Option<u16>,
}

/// The prefix of a host rule that explicitly allows private resolution
/// (`private:db.internal.example:5432`).
pub const PRIVATE_MARK: &str = "private:";

impl HostRule {
    /// Whether the rule allows its name to resolve to a loopback, private,
    /// link-local or unspecified address. Without it such an answer is refused.
    pub fn allows_private(&self) -> bool {
        self.text.starts_with(PRIVATE_MARK)
    }
}

/// What a command may reach over the network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    /// Nothing is approved.
    #[default]
    None,
    /// Exactly these destinations.
    Hosts(Vec<HostRule>),
    /// Whatever the application does; Vahta does not narrow it. What a format 1
    /// binding becomes.
    App,
}

/// The approved rules of one secret: which commands may use it (`allow`,
/// `deny`), which directories and which network those commands get. The signed
/// copy is the one the daemon enforces; `vahta.toml` only proposes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSet {
    pub name: String,
    /// The profile it was built from (a short label), if any.
    pub category: Option<String>,
    /// The category it was lowered from when the person approved less than the
    /// profile offers.
    pub downgraded_from: Option<String>,
    pub allow: Vec<ApprovedRule>,
    pub deny: Vec<ApprovedRule>,
    pub dirs: Vec<DirRule>,
    pub network: Network,
}

impl RuleSet {
    /// A rule set that approves nothing is the same as none.
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty()
            && self.deny.is_empty()
            && self.dirs.is_empty()
            && self.network == Network::None
    }

    /// What format 1 stored, in this format.
    pub fn from_v1(old: &v1::Binding) -> RuleSet {
        RuleSet {
            name: old.name.clone(),
            category: None,
            downgraded_from: None,
            allow: old.allow.clone(),
            deny: old.deny.clone(),
            dirs: Vec::new(),
            network: Network::App,
        }
    }
}

fn valid_text(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_RULE_TEXT
}

fn valid_category(c: &str) -> bool {
    !c.is_empty() && c.len() <= MAX_CATEGORY_LEN && !c.chars().any(char::is_control)
}

/// Whether `p` is absolute in either convention: `/…`, `X:\…` or `X:/…`, or a
/// UNC path `\\server\share…`. Judged by the text alone, so a file decodes the
/// same on every OS.
pub fn portable_absolute(p: &str) -> bool {
    let b = p.as_bytes();
    if b.first() == Some(&b'/') {
        return true;
    }
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'/' | b'\\') {
        return true;
    }
    p.starts_with("\\\\") && p.len() > 2
}

fn valid_dir(d: &DirRule) -> bool {
    valid_text(&d.text)
        && d.path.len() <= MAX_PATH_LEN
        && !d.path.contains('\0')
        && (portable_absolute(&d.path) || crate::rules::is_project_path(&d.path))
        && !d.path.split(['/', '\\']).any(|c| c == "." || c == "..")
}

/// A lowercase DNS name (letters, digits, hyphens, dots; no empty label) or an
/// IPv4 literal. IPv6 literals are not stored in this format.
fn valid_host(host: &str) -> bool {
    host.len() <= MAX_HOST_LEN
        && !host.is_empty()
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn check_rule_set(b: &RuleSet) -> Result<(), Error> {
    check_rules(&b.allow, true)?;
    check_rules(&b.deny, false)?;
    let bad = Error::Corrupt("bindings");
    if b.category.as_deref().is_some_and(|c| !valid_category(c))
        || b.downgraded_from
            .as_deref()
            .is_some_and(|c| !valid_category(c))
        || b.dirs.len() > MAX_DIRS
        || !b.dirs.iter().all(valid_dir)
    {
        return Err(bad);
    }
    if let Network::Hosts(hosts) = &b.network
        && (hosts.is_empty()
            || hosts.len() > MAX_HOSTS
            || !hosts
                .iter()
                .all(|h| valid_text(&h.text) && valid_host(&h.host) && h.port != Some(0)))
    {
        return Err(bad);
    }
    Ok(())
}

/// The shape checks of a reader, for rule sets a writer is about to store.
pub fn check_binding_shapes(sets: &[RuleSet]) -> Result<(), Error> {
    sets.iter().try_for_each(check_rule_set)
}

/// Rule sets name secrets that exist, once each, and carry well-formed rules.
pub(super) fn check_bindings(index: &[Entry], sets: &[RuleSet]) -> Result<(), Error> {
    if sets.len() > MAX_ENTRIES {
        return Err(Error::Corrupt("bindings"));
    }
    for (i, b) in sets.iter().enumerate() {
        if !index.iter().any(|e| e.name == b.name)
            || sets[..i].iter().any(|o| o.name == b.name)
            || b.is_empty()
        {
            return Err(Error::Corrupt("bindings"));
        }
        check_rule_set(b)?;
    }
    Ok(())
}

// --- Devices -----------------------------------------------------------------------

/// A paired device. Keys are P-256 points in SEC1 form (33 or 65 bytes); this
/// format only stores and shape-checks them. A device's slot, if it has one, is
/// an ordinary slot; by convention it shares the device's id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub device_id: [u8; 16],
    pub name: String,
    pub sign_pub: Vec<u8>,
    pub ecdh_pub: Vec<u8>,
    pub paired_at: u64,
    pub expires_at: Option<u64>,
    /// How the device is reached (`"lan"`, `"relay"`, ...), short ASCII tokens.
    pub transports: Vec<String>,
}

fn valid_sec1(k: &[u8]) -> bool {
    matches!((k.len(), k.first()), (33, Some(2 | 3)) | (65, Some(4)))
}

/// One device's shape. Uniqueness among devices is [`check_devices`].
pub fn check_device(d: &Device) -> Result<(), Error> {
    let bad = Error::Corrupt("devices");
    if !valid_recipient_name(&d.name)
        || !valid_sec1(&d.sign_pub)
        || !valid_sec1(&d.ecdh_pub)
        || d.transports.len() > MAX_TRANSPORTS
        || !d.transports.iter().enumerate().all(|(i, t)| {
            !t.is_empty()
                && t.len() <= MAX_TRANSPORT_LEN
                && t.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && !d.transports[..i].contains(t)
        })
    {
        return Err(bad);
    }
    Ok(())
}

pub fn check_devices(devices: &[Device]) -> Result<(), Error> {
    if devices.len() > MAX_DEVICES {
        return Err(Error::Corrupt("devices"));
    }
    for (i, d) in devices.iter().enumerate() {
        check_device(d)?;
        if devices[..i]
            .iter()
            .any(|o| o.device_id == d.device_id || o.name == d.name)
        {
            return Err(Error::Corrupt("devices"));
        }
    }
    Ok(())
}

// --- Body and model ------------------------------------------------------------------

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
    pub devices: Vec<Device>,
    pub index: Vec<Entry>,
    pub secrets: Vec<Sealed>,
    pub bindings: Vec<RuleSet>,
}

impl Model {
    /// A format 1 model's facts in this format. The sealed secrets are copied
    /// as they are: they stay sealed for format 1 until `upgrade` re-seals them.
    pub fn from_v1(old: &v1::Model) -> Model {
        let id = &old.header.vault_id;
        Model {
            header: old.header.clone(),
            slots: old
                .slots
                .iter()
                .map(|s| slot_from_v1(id, old.header.created, s))
                .collect(),
            owner: old.owner.clone(),
            recipients: old.recipients.clone(),
            devices: Vec::new(),
            index: old.index.clone(),
            secrets: old.secrets.clone(),
            bindings: old.bindings.iter().map(RuleSet::from_v1).collect(),
        }
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

impl fmt::Debug for Unlocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unlocked")
            .field("fmt", &self.fmt)
            .field("vault_id", &hex_encode(&self.model.header.vault_id))
            .field("secrets", &self.model.secrets.len())
            .finish_non_exhaustive()
    }
}

// --- Decode ------------------------------------------------------------------------------

/// Parse and check a frame as format 2: structure, membership certificates,
/// signer permission and the file signature. No password needed.
pub fn decode(frame: &Frame<'_>) -> Result<Decoded, Error> {
    let body: Body = exact(frame.body, "body")?;
    let sig_section: SigSection = exact(frame.sig, "signature section")?;

    check_slots(&body.slots)?;
    if body.index.len() > MAX_ENTRIES || body.secrets.len() != body.index.len() {
        return Err(Error::Corrupt("index"));
    }
    check_recipients(&body.header.vault_id, &body.owner, &body.recipients)?;
    check_index(&body.index, &body.secrets, &body.recipients)?;
    check_devices(&body.devices)?;
    check_bindings(&body.index, &body.bindings)?;

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
        },
    })
}

// --- Creating and unlocking ------------------------------------------------------------------

/// A new, empty vault in `fmt`, with a password slot and, unless
/// `with_recovery` is false, a recovery slot and its paper key.
pub fn create(
    fmt: u16,
    pw: &[u8],
    kdf: KdfParams,
    with_recovery: bool,
) -> Result<(Unlocked, Option<RecoveryKey>), Error> {
    let vk = Zeroizing::new(crypto::random::<KEY_LEN>()?);
    let vault_id = crypto::random::<16>()?;
    let mut slots = vec![password_slot(&vault_id, &vk, pw, kdf)?];
    let recovery = if with_recovery {
        let key = RecoveryKey::new(crypto::random::<32>()?);
        slots.push(recovery_slot(&vault_id, &vk, &key)?);
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
                devices: Vec::new(),
                index: Vec::new(),
                secrets: Vec::new(),
                bindings: Vec::new(),
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
    if !p.cost().meets(&crypto::kdf_floor()) {
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
    let kek = crypto::hkdf(key.bytes(), INFO_RECOVERY);
    slot.open(&model.header.vault_id, &kek).is_ok()
}

/// Unlock with the paper key.
pub fn unlock_recovery(d: &Decoded, key: &RecoveryKey) -> Result<Unlocked, Error> {
    let slot = d
        .model
        .slots
        .iter()
        .find(|s| s.kind == SLOT_RECOVERY)
        .ok_or(Error::Unlock)?;
    let kek = crypto::hkdf(key.bytes(), INFO_RECOVERY);
    finish_unlock(d, slot.open(&d.model.header.vault_id, &kek)?)
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
/// matches the public key listed for it. Every wrap it holds must open, so a
/// swapped wrap is caught at open and not at first use.
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

// --- Encode -----------------------------------------------------------------------------------

/// Encode `model` as a signed format-2 file, signed by the owner.
pub fn encode(model: &Model, owner_key: &SigningKey) -> Result<Vec<u8>, Error> {
    encode_as(FORMAT, model, Actor::Owner, owner_key)
}

/// Encode with an explicit format number and signer. The owner or an admin or
/// editor recipient signs in normal use; the rest exists so tests can build
/// files the verifier must refuse.
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
