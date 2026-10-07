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
//!   recipient list (each entry carries its own certificate), the plaintext
//!   name index, the sealed secrets. Integers inside it are postcard varints.
//! * The signature section is a postcard-encoded [`SigSection`]. The signature
//!   covers the stored bytes from the magic through the end of the body, so
//!   nothing is re-encoded to verify it.
//!
//! A value is sealed in three layers: padded (`u32 length ‖ value ‖ zeros`, to
//! the next power of two, at least 64 bytes), encrypted under a random
//! per-secret key (the DEK) with XChaCha20-Poly1305, and the DEK is wrapped
//! once for the owner and once for each granted recipient, both by HPKE (the
//! owner's public key is in the file, so any writer can seal a new secret for
//! the owner). Secret and wrap AEADs bind `magic ‖ format ‖ vault_id ‖
//! secret_id`. Slots bind `"vahta/slot" ‖ slot_version ‖ vault_id ‖ kind`
//! instead and so do not depend on the file format.
//!
//! Membership is certified per member: each recipient entry carries `added_by`
//! and a signature of that actor over the entry. The owner may certify anyone;
//! an Admin that the owner added may certify Editors and Runners; delegation
//! goes no deeper.

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
const INFO_DEK_HPKE: &[u8] = b"vahta/v1/dek";
const INFO_RECOVERY: &[u8] = b"vahta/v1/recovery-kek";
const DOMAIN_MEMBER: &[u8] = b"vahta/v1/member";
const DOMAIN_SLOT: &[u8] = b"vahta/slot";

/// The version of the slot crypto written today. It changes only when a slot
/// kind's own crypto does, not with the file format.
pub const SLOT_VERSION: u16 = 1;

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

/// A way to recover the vault key. Each wraps the 32-byte vault key and
/// carries its own version, because a slot's crypto changes on its own
/// schedule, not the file format's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Slot {
    /// The key-encryption key is Argon2id of the password.
    Password {
        slot_version: u16,
        salt: [u8; 16],
        m_kib: u32,
        t: u32,
        p: u32,
        nonce: [u8; 24],
        ct: Vec<u8>,
    },
    /// The key-encryption key is HKDF of a 32-byte random paper key. No
    /// Argon2: the key has full entropy.
    Recovery {
        slot_version: u16,
        nonce: [u8; 24],
        ct: Vec<u8>,
    },
}

impl Slot {
    fn kind_byte(&self) -> u8 {
        match self {
            Slot::Password { .. } => SLOT_PASSWORD,
            Slot::Recovery { .. } => SLOT_RECOVERY,
        }
    }

    pub fn version(&self) -> u16 {
        match self {
            Slot::Password { slot_version, .. } | Slot::Recovery { slot_version, .. } => {
                *slot_version
            }
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

/// A member of the vault. `cert` is `added_by`'s signature over the entry
/// without it, so a membership change needs no one's signature but the issuer's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient {
    pub id: [u8; 16],
    pub name: String,
    pub kind: RecipientKind,
    pub role: Role,
    pub enc_pk: [u8; 32],
    pub sign_pk: [u8; 32],
    pub added: u64,
    pub added_by: Actor,
    pub cert: Sig,
}

/// What a certificate signs: the entry without `cert`.
#[derive(Serialize)]
struct RecipientCore<'a> {
    id: &'a [u8; 16],
    name: &'a str,
    kind: RecipientKind,
    role: Role,
    enc_pk: &'a [u8; 32],
    sign_pk: &'a [u8; 32],
    added: u64,
    added_by: Actor,
}

impl Recipient {
    /// `"vahta/v1/member" ‖ vault_id ‖ postcard(entry without cert)`.
    pub fn cert_message(&self, vault_id: &[u8; 16]) -> Vec<u8> {
        let core = RecipientCore {
            id: &self.id,
            name: &self.name,
            kind: self.kind,
            role: self.role,
            enc_pk: &self.enc_pk,
            sign_pk: &self.sign_pk,
            added: self.added,
            added_by: self.added_by,
        };
        let mut m = DOMAIN_MEMBER.to_vec();
        m.extend_from_slice(vault_id);
        // Serialising plain fixed-size data cannot fail.
        m.extend_from_slice(&postcard::to_allocvec(&core).unwrap_or_default());
        m
    }

    /// Sign this entry as `added_by` with `issuer_key`, filling in `cert`.
    pub fn certify(&mut self, vault_id: &[u8; 16], issuer_key: &SigningKey) {
        self.cert = Sig(crypto::sign(issuer_key, &self.cert_message(vault_id)));
    }
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

/// What a secret guards, judged from its typed value when it was added. It
/// steers advice only (an each-use suggestion); nothing is allowed or refused
/// because of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Class {
    Payment,
    Cloud,
    Other,
}

impl Class {
    pub fn as_str(self) -> &'static str {
        match self {
            Class::Payment => "payment",
            Class::Cloud => "cloud",
            Class::Other => "other",
        }
    }
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
    /// Set by add and reset from the typed value; `None` when unknown.
    pub class: Option<Class>,
}

/// The program of an approved rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Program {
    /// An `allow` rule: the canonical absolute path it resolved to when the
    /// person approved it. Checked against the resolved path at run.
    Path(String),
    /// A `deny` rule: a program file name, normalised (see `rules`).
    Name(String),
    /// A `deny` rule: a named group such as `@network`.
    Group(String),
}

/// One approved rule. `text` is what the person saw; `program` and `args` are
/// what is enforced; `args` is an argv prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedRule {
    pub text: String,
    pub program: Program,
    pub args: Vec<String>,
}

/// The approved command rules of one secret. The signed copy is the one the
/// daemon enforces; `vahta.toml` only proposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub name: String,
    pub allow: Vec<ApprovedRule>,
    pub deny: Vec<ApprovedRule>,
}

const MAX_RULES: usize = 64;
const MAX_RULE_ARGS: usize = 32;
const MAX_RULE_TEXT: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerWrap {
    pub enc: [u8; 32],
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
    pub owner_wrap: OwnerWrap,
    pub wraps: Vec<RecipientWrap>,
}

/// The wire body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    pub header: Header,
    pub slots: Vec<Slot>,
    pub owner: Owner,
    pub recipients: Vec<Recipient>,
    pub index: Vec<Entry>,
    pub secrets: Vec<Sealed>,
    pub bindings: Vec<Binding>,
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
    pub bindings: Vec<Binding>,
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

// --- AAD ---------------------------------------------------------------------

fn aad_prefix(fmt: u16, vault_id: &[u8; 16]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + 2 + 16 + 16);
    v.extend_from_slice(MAGIC);
    v.extend_from_slice(&fmt.to_le_bytes());
    v.extend_from_slice(vault_id);
    v
}

/// A slot's AAD: independent of the file format, so a format change can copy
/// slots verbatim.
fn slot_aad(slot_version: u16, vault_id: &[u8; 16], kind: u8) -> Vec<u8> {
    let mut v = DOMAIN_SLOT.to_vec();
    v.extend_from_slice(&slot_version.to_le_bytes());
    v.extend_from_slice(vault_id);
    v.push(kind);
    v
}

fn secret_aad(fmt: u16, vault_id: &[u8; 16], secret_id: &[u8; 16]) -> Vec<u8> {
    let mut v = aad_prefix(fmt, vault_id);
    v.extend_from_slice(secret_id);
    v
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

/// Parse and check a frame as format 1: structure, membership certificates,
/// signer permission and the file signature. No password needed.
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
    check_recipients(&body.header.vault_id, &body.owner, &body.recipients)?;
    check_index(&body, &body.recipients)?;
    check_bindings(&body)?;

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
        fmt,
        signer: sig_section.signer,
        model: Model {
            header: body.header,
            slots: body.slots,
            owner: body.owner,
            recipients: body.recipients,
            index: body.index,
            secrets: body.secrets,
            bindings: body.bindings,
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
        if slot.version() != SLOT_VERSION {
            return Err(Error::Corrupt("slot version"));
        }
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

/// Every member's certificate must verify, and every issuer must be allowed to
/// have issued it: the owner may certify anyone; an Admin the owner added may
/// certify Editors and Runners. Delegation is one level deep, so an admin added
/// by an admin certifies nobody and an admin cannot add an admin.
fn check_recipients(vault_id: &[u8; 16], owner: &Owner, list: &[Recipient]) -> Result<(), Error> {
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
    for r in list {
        let issuer_pk = match r.added_by {
            Actor::Owner => owner.sign_pk,
            Actor::Recipient(iid) => {
                let issuer = list
                    .iter()
                    .find(|o| o.id == iid)
                    .ok_or(Error::MembershipNotAllowed)?;
                if issuer.role != Role::Admin
                    || issuer.added_by != Actor::Owner
                    || r.role == Role::Admin
                {
                    return Err(Error::MembershipNotAllowed);
                }
                issuer.sign_pk
            }
        };
        if !crypto::verify(&issuer_pk, &r.cert_message(vault_id), &r.cert.0) {
            return Err(Error::BadSignature);
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

fn check_rules(rules: &[ApprovedRule], allow: bool) -> Result<(), Error> {
    if rules.len() > MAX_RULES {
        return Err(Error::Corrupt("bindings"));
    }
    for r in rules {
        let program_ok = match (&r.program, allow) {
            (Program::Path(p), true) => !p.is_empty(),
            (Program::Name(n), false) => !n.is_empty(),
            (Program::Group(g), false) => crate::rules::group_members(g).is_some(),
            _ => false,
        };
        let group_has_args = matches!(r.program, Program::Group(_)) && !r.args.is_empty();
        if !program_ok
            || group_has_args
            || r.text.is_empty()
            || r.text.len() > MAX_RULE_TEXT
            || r.args.len() > MAX_RULE_ARGS
            || r.args
                .iter()
                .any(|a| a.is_empty() || a.len() > MAX_RULE_TEXT)
        {
            return Err(Error::Corrupt("bindings"));
        }
    }
    Ok(())
}

/// The shape checks of a reader, for bindings a writer is about to store.
pub fn check_binding_shapes(bindings: &[Binding]) -> Result<(), Error> {
    for b in bindings {
        check_rules(&b.allow, true)?;
        check_rules(&b.deny, false)?;
    }
    Ok(())
}

/// Bindings name secrets that exist, once each, and carry well-formed rules.
fn check_bindings(body: &Body) -> Result<(), Error> {
    if body.bindings.len() > MAX_ENTRIES {
        return Err(Error::Corrupt("bindings"));
    }
    for (i, b) in body.bindings.iter().enumerate() {
        if !body.index.iter().any(|e| e.name == b.name)
            || body.bindings[..i].iter().any(|o| o.name == b.name)
            || (b.allow.is_empty() && b.deny.is_empty())
        {
            return Err(Error::Corrupt("bindings"));
        }
        check_rules(&b.allow, true)?;
        check_rules(&b.deny, false)?;
    }
    Ok(())
}

// --- Keys -------------------------------------------------------------------------

pub struct OwnerKeys {
    pub sign: SigningKey,
    pub sign_pk: [u8; 32],
    pub enc_sk: Zeroizing<[u8; KEY_LEN]>,
    pub enc_pk: [u8; 32],
}

/// Both owner key pairs, derived from the vault key.
pub fn owner_keys(vk: &[u8; KEY_LEN]) -> OwnerKeys {
    let sign = crypto::signing_key(&crypto::hkdf(vk, INFO_OWNER_SIGN));
    let (enc_sk, enc_pk) = crypto::enc_keypair_from_seed(&crypto::hkdf(vk, INFO_OWNER_ENC));
    OwnerKeys {
        sign_pk: sign.verifying_key().to_bytes(),
        sign,
        enc_sk,
        enc_pk,
    }
}

// --- Creating and unlocking ---------------------------------------------------------

/// A password slot wrapping `vk`. Slots are independent of the file format:
/// their AAD carries the slot's own version, so a format change copies them
/// verbatim.
pub fn password_slot(
    vault_id: &[u8; 16],
    vk: &[u8; KEY_LEN],
    pw: &[u8],
    kdf: KdfParams,
) -> Result<Slot, Error> {
    if !kdf.meets(&crypto::kdf_floor()) {
        return Err(Error::KdfBelowFloor);
    }
    let salt = crypto::random::<16>()?;
    let kek = crypto::argon2id(pw, &salt, kdf.m_kib, kdf.t, kdf.p)?;
    let aad = slot_aad(SLOT_VERSION, vault_id, SLOT_PASSWORD);
    let (nonce, ct) = crypto::seal(&kek, &aad, vk)?;
    Ok(Slot::Password {
        slot_version: SLOT_VERSION,
        salt,
        m_kib: kdf.m_kib,
        t: kdf.t,
        p: kdf.p,
        nonce,
        ct,
    })
}

/// A recovery slot wrapping `vk` under the paper key.
pub fn recovery_slot(
    vault_id: &[u8; 16],
    vk: &[u8; KEY_LEN],
    key: &RecoveryKey,
) -> Result<Slot, Error> {
    let kek = crypto::hkdf(key.bytes(), INFO_RECOVERY);
    let aad = slot_aad(SLOT_VERSION, vault_id, SLOT_RECOVERY);
    let (nonce, ct) = crypto::seal(&kek, &aad, vk)?;
    Ok(Slot::Recovery {
        slot_version: SLOT_VERSION,
        nonce,
        ct,
    })
}

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

/// Unlock with the password. The KDF floor is checked before any work.
pub fn unlock_password(d: &Decoded, pw: &[u8]) -> Result<Unlocked, Error> {
    let Some(Slot::Password {
        slot_version,
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
    let kek = crypto::argon2id(pw, salt, *m_kib, *t, *p)?;
    let aad = slot_aad(*slot_version, &d.model.header.vault_id, SLOT_PASSWORD);
    finish_unlock(d, crypto::open(&kek, nonce, &aad, ct)?)
}

/// Whether `key` opens the recovery slot of `model`.
pub fn recovery_key_matches(model: &Model, key: &RecoveryKey) -> bool {
    let Some(Slot::Recovery {
        slot_version,
        nonce,
        ct,
    }) = model.slots.iter().find(|s| s.kind_byte() == SLOT_RECOVERY)
    else {
        return false;
    };
    let kek = crypto::hkdf(key.bytes(), INFO_RECOVERY);
    let aad = slot_aad(*slot_version, &model.header.vault_id, SLOT_RECOVERY);
    crypto::open(&kek, nonce, &aad, ct).is_ok()
}

/// Unlock with the paper key.
pub fn unlock_recovery(d: &Decoded, key: &RecoveryKey) -> Result<Unlocked, Error> {
    let Some(Slot::Recovery {
        slot_version,
        nonce,
        ct,
    }) = d
        .model
        .slots
        .iter()
        .find(|s| s.kind_byte() == SLOT_RECOVERY)
    else {
        return Err(Error::Unlock);
    };
    let kek = crypto::hkdf(key.bytes(), INFO_RECOVERY);
    let aad = slot_aad(*slot_version, &d.model.header.vault_id, SLOT_RECOVERY);
    finish_unlock(d, crypto::open(&kek, nonce, &aad, ct)?)
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

// --- Sealing and opening secrets ------------------------------------------------------

fn hpke_open_dek(
    enc_sk: &[u8; KEY_LEN],
    enc: &[u8; KEY_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let dek = crypto::hpke_open(enc_sk, enc, INFO_DEK_HPKE, aad, ct)?;
    let dek: [u8; KEY_LEN] = dek.as_slice().try_into().map_err(|_| Error::Unlock)?;
    Ok(Zeroizing::new(dek))
}

/// The value of `sealed` under an already opened DEK.
pub fn value_with_dek(
    fmt: u16,
    vault_id: &[u8; 16],
    dek: &[u8; KEY_LEN],
    sealed: &Sealed,
) -> Result<SecretValue, Error> {
    let aad = secret_aad(fmt, vault_id, &sealed.secret_id);
    let plain = crypto::open(dek, &sealed.nonce, &aad, &sealed.ct)?;
    Ok(SecretValue::from_zeroizing(crypto::unpad(&plain)?))
}

/// The DEK of `sealed`, opened with the owner's private encryption key.
pub fn open_dek(
    fmt: u16,
    vault_id: &[u8; 16],
    owner_enc_sk: &[u8; KEY_LEN],
    sealed: &Sealed,
) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let aad = secret_aad(fmt, vault_id, &sealed.secret_id);
    hpke_open_dek(
        owner_enc_sk,
        &sealed.owner_wrap.enc,
        &aad,
        &sealed.owner_wrap.ct,
    )
}

/// The DEK of `sealed` as a recipient: `None` when it holds no wrap.
pub fn open_dek_as_recipient(
    fmt: u16,
    vault_id: &[u8; 16],
    enc_sk: &[u8; KEY_LEN],
    recipient_id: &[u8; 16],
    sealed: &Sealed,
) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>, Error> {
    let Some(w) = sealed
        .wraps
        .iter()
        .find(|w| &w.recipient_id == recipient_id)
    else {
        return Ok(None);
    };
    let aad = secret_aad(fmt, vault_id, &sealed.secret_id);
    hpke_open_dek(enc_sk, &w.enc, &aad, &w.ct).map(Some)
}

/// The value of `sealed`, opened with the owner's private encryption key.
pub fn open_value(
    fmt: u16,
    vault_id: &[u8; 16],
    owner_enc_sk: &[u8; KEY_LEN],
    sealed: &Sealed,
) -> Result<SecretValue, Error> {
    let dek = open_dek(fmt, vault_id, owner_enc_sk, sealed)?;
    value_with_dek(fmt, vault_id, &dek, sealed)
}

/// Wrap `dek` for one recipient.
pub fn wrap_for(
    fmt: u16,
    vault_id: &[u8; 16],
    sid: &[u8; 16],
    dek: &[u8; KEY_LEN],
    recipient: &Recipient,
) -> Result<RecipientWrap, Error> {
    let aad = secret_aad(fmt, vault_id, sid);
    let (enc, ct) = crypto::hpke_seal(&recipient.enc_pk, INFO_DEK_HPKE, &aad, dek)?;
    Ok(RecipientWrap {
        recipient_id: recipient.id,
        enc,
        ct,
    })
}

/// Seal `value` under a fresh DEK, wrapped for the owner (from the public
/// file alone, so any writer can do it) and for `holders`.
pub fn seal_secret(
    fmt: u16,
    vault_id: &[u8; 16],
    sid: [u8; 16],
    owner_enc_pk: &[u8; KEY_LEN],
    value: &[u8],
    holders: &[&Recipient],
) -> Result<Sealed, Error> {
    let dek = Zeroizing::new(crypto::random::<KEY_LEN>()?);
    let aad = secret_aad(fmt, vault_id, &sid);
    let padded = crypto::pad(value)?;
    let (nonce, ct) = crypto::seal(&dek, &aad, &padded)?;
    let (enc, wct) = crypto::hpke_seal(owner_enc_pk, INFO_DEK_HPKE, &aad, &*dek)?;
    let wraps = holders
        .iter()
        .map(|r| wrap_for(fmt, vault_id, &sid, &dek, r))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Sealed {
        secret_id: sid,
        nonce,
        ct,
        owner_wrap: OwnerWrap { enc, ct: wct },
        wraps,
    })
}

// --- Encode -----------------------------------------------------------------------------

/// Encode `model` as a signed format-1 file, signed by the owner.
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
