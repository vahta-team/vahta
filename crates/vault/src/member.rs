//! Team members: the public key a person gives to the owner, the words that
//! prove it arrived unchanged, the package the owner sends back and the single
//! secret an editor sends to the owner.
//!
//! **The key string.** `vh1` followed by the lowercase base32 (no padding) of
//! `enc_pk ‖ sign_pk ‖ checksum`, where the checksum is the first four bytes of
//! SHA-256 over `"vahta/v1/member-key-check" ‖ enc_pk ‖ sign_pk`. It catches a
//! mistyped or cut-off string; it is not a defence against an attacker, who
//! can compute it. The words are.
//!
//! **The verification words.** Six words derived from SHA-256 over
//! `"vahta/v1/member-words" ‖ enc_pk ‖ sign_pk`: 72 bits, twelve per word. The
//! person who owns the key reads them to the owner over another channel, and
//! the owner types them in. Someone who swaps the key string in the chat has to
//! find another key pair with the same 72 bits, which is out of reach. The
//! repository has no word list (the paper key is hex), so a word is two
//! syllables, each a consonant and a vowel from 16 and 4 (64 syllables, 4096
//! words), chosen to be easy to say and to spell.
//!
//! **The package** ([`build_package`]) is a format-5 vault file the owner signs
//! and that holds one member's recipient entry and nothing about anyone else:
//! only the secrets that member holds a wrap for, their index entries, rules and
//! wraps; no other member, no devices, no roles. The format requires a key
//! slot, so the file carries one placeholder: a password slot whose sealed key
//! is all zeros. It can never open (an AEAD tag of zeros does not verify), it
//! has no secret, and it is the marker by which a package is told from a vault
//! ([`is_package`]): an owner's unlock refuses a file that has it, and the
//! owner's writes refuse to replace one.
//!
//! **The transfer** ([`Transfer`]) is how an editor sends one secret to the
//! owner: the secret as the editor's copy of the vault already holds it (sealed
//! under its own key, which is wrapped for the owner's public key), plus its
//! name, kind and tier, signed by the editor.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{self, KEY_LEN};
use crate::format::current::{
    self, Actor, Entry, Kind, Model, PasswordParams, Recipient, SLOT_PASSWORD, Sealed, Slot, Tier,
};
use crate::vault::RecipientPublic;
use crate::{Error, hex_encode, valid_name};

const DOMAIN_KEY_CHECK: &[u8] = b"vahta/v1/member-key-check";
const DOMAIN_WORDS: &[u8] = b"vahta/v1/member-words";
const DOMAIN_FINGERPRINT: &[u8] = b"vahta/v1/member-fingerprint";
const DOMAIN_TRANSFER: &[u8] = b"vahta/v1/transfer";

/// What a key string starts with.
pub const KEY_PREFIX: &str = "vh1";
/// How many words are read out.
pub const WORD_COUNT: usize = 6;

/// The label of the placeholder slot of a package.
pub const PACKAGE_SLOT_LABEL: &str = "vahta/package";

// --- Base32 ---------------------------------------------------------------------------------

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn b32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// The inverse of [`b32_encode`], strictly: lowercase alphabet only, and the
/// unused bits of the last character must be zero.
fn b32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let v = B32.iter().position(|x| *x == c)? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (acc == 0).then_some(out)
}

// --- Key string, fingerprint and words -----------------------------------------------------

fn digest(domain: &[u8], public: &RecipientPublic) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(public.enc_pk);
    h.update(public.sign_pk);
    h.finalize().into()
}

/// `vh1…`: the public keys with a checksum, to paste into a chat.
pub fn public_key_string(public: &RecipientPublic) -> String {
    let mut raw = Vec::with_capacity(2 * KEY_LEN + 4);
    raw.extend_from_slice(&public.enc_pk);
    raw.extend_from_slice(&public.sign_pk);
    raw.extend_from_slice(&digest(DOMAIN_KEY_CHECK, public)[..4]);
    format!("{KEY_PREFIX}{}", b32_encode(&raw))
}

/// The inverse of [`public_key_string`]. Surrounding whitespace and capitals
/// (a chat app may add either) are forgiven; a bad checksum, a wrong length or
/// any other character is [`Error::Invalid`].
pub fn parse_public_key(text: &str) -> Result<RecipientPublic, Error> {
    let bad = || Error::Invalid("not a Vahta member key (check that all of it was copied)");
    let lower = text.trim().to_ascii_lowercase();
    let body = lower.strip_prefix(KEY_PREFIX).ok_or_else(bad)?;
    let raw = b32_decode(body).ok_or_else(bad)?;
    if raw.len() != 2 * KEY_LEN + 4 {
        return Err(bad());
    }
    let public = RecipientPublic {
        enc_pk: raw[..KEY_LEN].try_into().map_err(|_| bad())?,
        sign_pk: raw[KEY_LEN..2 * KEY_LEN].try_into().map_err(|_| bad())?,
    };
    if digest(DOMAIN_KEY_CHECK, &public)[..4] != raw[2 * KEY_LEN..] {
        return Err(bad());
    }
    Ok(public)
}

/// A short name for the key, for windows and the journal: twelve hex digits.
pub fn fingerprint(public: &RecipientPublic) -> String {
    hex_encode(&digest(DOMAIN_FINGERPRINT, public)[..6])
}

const CONSONANTS: &[u8; 16] = b"bdfghklmnprstvwz";
const VOWELS: &[u8; 4] = b"aeio";

fn syllable(i: u16) -> [char; 2] {
    [
        CONSONANTS[usize::from(i >> 2) & 15] as char,
        VOWELS[usize::from(i & 3)] as char,
    ]
}

/// The six words of `public`, in order.
pub fn verification_words(public: &RecipientPublic) -> [String; WORD_COUNT] {
    let hash = digest(DOMAIN_WORDS, public);
    let mut bits = 0u32;
    let mut acc = 0u32;
    let mut bytes = hash.iter();
    std::array::from_fn(|_| {
        while bits < 12 {
            acc = (acc << 8) | u32::from(*bytes.next().unwrap_or(&0));
            bits += 8;
        }
        bits -= 12;
        let w = ((acc >> bits) & 0xfff) as u16;
        acc &= (1 << bits) - 1;
        let (a, b) = (syllable(w >> 6), syllable(w & 63));
        [a[0], a[1], b[0], b[1]].iter().collect()
    })
}

/// The words as one line, `kabe lomi ...`.
pub fn words_line(public: &RecipientPublic) -> String {
    verification_words(public).join(" ")
}

/// Whether `typed` is the six words of `public`: case and the separators
/// (spaces, commas, hyphens) are forgiven, a different word is not.
pub fn words_match(public: &RecipientPublic, typed: &str) -> bool {
    let got: Vec<String> = typed
        .split(|c: char| c.is_whitespace() || c == ',' || c == '-')
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect();
    got == verification_words(public)
}

// --- Packages -------------------------------------------------------------------------------

/// What a package is.
pub(crate) fn package_slot() -> Slot {
    Slot {
        kind: SLOT_PASSWORD,
        slot_id: [0; 16],
        slot_version: current::SLOT_VERSION,
        label: PACKAGE_SLOT_LABEL.to_string(),
        created_at: 0,
        expires_at: None,
        // The cheapest cost a reader accepts; nothing is derived from it.
        params: PasswordParams {
            salt: [0; 16],
            m_kib: 8,
            t: 1,
            p: 1,
        }
        .encode(),
        // `nonce (24) ‖ sealed key (32 + 16)`, all zeros.
        ct: vec![0; 24 + 32 + 16],
    }
}

/// Whether `model` is a member package rather than a vault: one placeholder
/// slot with an all-zero sealed key, and one member.
pub fn is_package(model: &Model) -> bool {
    matches!(model.slots.as_slice(), [s]
        if s.kind == SLOT_PASSWORD
            && s.label == PACKAGE_SLOT_LABEL
            && s.ct.iter().all(|b| *b == 0))
        && model.recipients.len() == 1
}

/// The file `owner_key` signs for `recipient_id`: see the module
/// documentation. The member's entry is certified again by the owner, so a
/// member an Admin added still verifies without the Admin's entry.
pub(crate) fn build_package(
    model: &Model,
    recipient_id: &[u8; 16],
    owner_key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    if is_package(model) {
        return Err(Error::Package);
    }
    let vault_id = model.header.vault_id;
    let mut member: Recipient = model
        .recipients
        .iter()
        .find(|r| &r.id == recipient_id)
        .cloned()
        .ok_or(Error::UnknownRecipient)?;
    member.added_by = Actor::Owner;
    member.certify(&vault_id, owner_key);

    let mut index = Vec::new();
    let mut secrets = Vec::new();
    for (entry, sealed) in model.index.iter().zip(&model.secrets) {
        let Some(wrap) = sealed
            .wraps
            .iter()
            .find(|w| &w.recipient_id == recipient_id)
        else {
            continue;
        };
        let mut entry: Entry = entry.clone();
        // Another member's id is not this member's business.
        if matches!(entry.changed_by, Actor::Recipient(id) if &id != recipient_id) {
            entry.changed_by = Actor::Owner;
        }
        index.push(entry);
        secrets.push(Sealed {
            wraps: vec![wrap.clone()],
            ..sealed.clone()
        });
    }
    let bindings = model
        .bindings
        .iter()
        .filter(|b| index.iter().any(|e| e.name == b.name))
        .cloned()
        .collect();
    let package = Model {
        header: model.header.clone(),
        slots: vec![package_slot()],
        owner: model.owner.clone(),
        recipients: vec![member],
        devices: Vec::new(),
        index,
        secrets,
        bindings,
        successors: model.successors.clone(),
        remote: false,
        kind: model.kind,
        roles: Vec::new(),
    };
    let bytes = current::encode(&package, owner_key)?;
    // What leaves here must be what a reader accepts as a package.
    match crate::format::decode(&bytes)?.current() {
        Some(d) if is_package(&d.model) => Ok(bytes),
        _ => Err(Error::Corrupt("package")),
    }
}

/// What can be read from a vault file or a package without a key.
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub vault_id: [u8; 16],
    pub generation: u64,
    pub owner: RecipientPublic,
    /// Whether this is a member package (see [`is_package`]).
    pub package: bool,
    /// Whether the owner signed it.
    pub signed_by_owner: bool,
    /// The members the file lists: all of them in a vault, the one in a
    /// package. Empty for a file older than format 5.
    pub recipients: Vec<Recipient>,
    /// For each member (by id), the names of the secrets it holds a wrap for.
    pub holdings: Vec<([u8; 16], Vec<String>)>,
}

/// Read, verify and describe `bytes`.
pub fn file_info(bytes: &[u8]) -> Result<FileInfo, Error> {
    let loaded = crate::format::decode(bytes)?;
    let owner = loaded.owner();
    let (package, recipients, holdings) = match loaded.current() {
        Some(d) => (
            is_package(&d.model),
            d.model.recipients.clone(),
            d.model
                .recipients
                .iter()
                .map(|r| {
                    let held = d
                        .model
                        .index
                        .iter()
                        .zip(&d.model.secrets)
                        .filter(|(_, s)| s.wraps.iter().any(|w| w.recipient_id == r.id))
                        .map(|(e, _)| e.name.clone())
                        .collect();
                    (r.id, held)
                })
                .collect(),
        ),
        None => (false, Vec::new(), Vec::new()),
    };
    Ok(FileInfo {
        vault_id: loaded.header().vault_id,
        generation: loaded.header().generation,
        owner: RecipientPublic {
            enc_pk: owner.enc_pk,
            sign_pk: owner.sign_pk,
        },
        package,
        signed_by_owner: loaded.signer() == Actor::Owner,
        recipients,
        holdings,
    })
}

impl FileInfo {
    /// The names `recipient_id` holds.
    pub fn held_by(&self, recipient_id: &[u8; 16]) -> &[String] {
        self.holdings
            .iter()
            .find(|(id, _)| id == recipient_id)
            .map_or(&[], |(_, names)| names.as_slice())
    }

    /// The entry whose public keys are `public`, if the file lists one.
    pub fn member_with(&self, public: &RecipientPublic) -> Option<&Recipient> {
        self.recipients
            .iter()
            .find(|r| r.enc_pk == public.enc_pk && r.sign_pk == public.sign_pk)
    }
}

// --- Transfer ---------------------------------------------------------------------------------

const TRANSFER_MAGIC: &[u8; 8] = b"VAHTAXFR";
const TRANSFER_VERSION: u16 = 1;
const MAX_TRANSFER: usize = 3 << 20;

/// Whether `bytes` start like a transfer file.
pub fn is_transfer(bytes: &[u8]) -> bool {
    bytes.starts_with(TRANSFER_MAGIC)
}

#[derive(Serialize, Deserialize)]
pub(crate) struct TransferBody {
    pub vault_id: [u8; 16],
    pub from: [u8; 16],
    pub name: String,
    pub kind: Kind,
    pub tier: Tier,
    /// When the editor last changed the secret; an older transfer than the
    /// owner's copy is refused.
    pub updated: u64,
    pub fmt: u16,
    pub sealed: Sealed,
}

pub(crate) fn encode_transfer(body: &TransferBody, signer: &SigningKey) -> Result<Vec<u8>, Error> {
    let body = postcard::to_allocvec(body).map_err(|_| Error::Corrupt("transfer"))?;
    let len = u32::try_from(body.len()).map_err(|_| Error::TooLarge)?;
    let mut out = Vec::with_capacity(body.len() + 80);
    out.extend_from_slice(TRANSFER_MAGIC);
    out.extend_from_slice(&TRANSFER_VERSION.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&body);
    let sig = crypto::sign(signer, &transfer_message(&out));
    out.extend_from_slice(&sig);
    if out.len() > MAX_TRANSFER {
        return Err(Error::TooLarge);
    }
    Ok(out)
}

fn transfer_message(framed: &[u8]) -> Vec<u8> {
    let mut m = DOMAIN_TRANSFER.to_vec();
    m.extend_from_slice(framed);
    m
}

/// Parse a transfer and hand back its body and a check of the signature
/// against `sign_pk_of(from)`, which the caller looks up in the vault.
pub(crate) fn decode_transfer(
    bytes: &[u8],
    sign_pk_of: impl FnOnce(&[u8; 16]) -> Option<[u8; 32]>,
) -> Result<TransferBody, Error> {
    if bytes.len() > MAX_TRANSFER {
        return Err(Error::TooLarge);
    }
    if !is_transfer(bytes) {
        return Err(Error::NotAVault);
    }
    let corrupt = || Error::Corrupt("transfer");
    let head = bytes.get(8..14).ok_or_else(corrupt)?;
    if u16::from_le_bytes([head[0], head[1]]) != TRANSFER_VERSION {
        return Err(corrupt());
    }
    let len = u32::from_le_bytes([head[2], head[3], head[4], head[5]]) as usize;
    let end = 14usize.checked_add(len).ok_or_else(corrupt)?;
    if bytes.len() != end + 64 {
        return Err(corrupt());
    }
    let body: TransferBody = postcard::from_bytes(&bytes[14..end]).map_err(|_| corrupt())?;
    let sig: [u8; 64] = bytes[end..].try_into().map_err(|_| corrupt())?;
    let pk = sign_pk_of(&body.from).ok_or(Error::SignerNotAllowed)?;
    if !crypto::verify(&pk, &transfer_message(&bytes[..end]), &sig) {
        return Err(Error::BadSignature);
    }
    if !valid_name(&body.name) {
        return Err(Error::InvalidName);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public(a: u8, b: u8) -> RecipientPublic {
        RecipientPublic {
            enc_pk: [a; 32],
            sign_pk: [b; 32],
        }
    }

    #[test]
    fn base32_round_trips_and_is_strict() {
        for len in 0..40usize {
            let bytes: Vec<u8> = (0..len as u8).map(|b| b.wrapping_mul(37)).collect();
            assert_eq!(b32_decode(&b32_encode(&bytes)).unwrap(), bytes);
        }
        assert!(b32_decode("A").is_none());
        assert!(b32_decode("b").is_none(), "non-zero spare bits");
        assert!(b32_decode("a1").is_none());
    }

    #[test]
    fn a_key_string_round_trips_and_a_flipped_character_is_refused() {
        let p = public(3, 9);
        let s = public_key_string(&p);
        assert!(s.starts_with("vh1") && s == s.to_lowercase());
        assert_eq!(parse_public_key(&s).unwrap(), p);
        assert_eq!(
            parse_public_key(&format!("  {}\n", s.to_uppercase())).unwrap(),
            p
        );
        let mut chars: Vec<char> = s.chars().collect();
        let i = 20;
        chars[i] = if chars[i] == 'a' { 'b' } else { 'a' };
        let bad: String = chars.into_iter().collect();
        assert!(parse_public_key(&bad).is_err());
        assert!(parse_public_key(&s[..s.len() - 1]).is_err());
        assert!(parse_public_key("vh2aaaa").is_err());
        assert!(parse_public_key("").is_err());
    }

    #[test]
    fn the_words_depend_on_both_keys_and_are_stable() {
        let a = verification_words(&public(1, 2));
        assert_eq!(a, verification_words(&public(1, 2)));
        assert_ne!(a, verification_words(&public(1, 3)));
        assert_ne!(a, verification_words(&public(2, 2)));
        for w in &a {
            assert_eq!(w.len(), 4);
        }
        let line = words_line(&public(1, 2));
        assert!(words_match(&public(1, 2), &line));
        assert!(words_match(
            &public(1, 2),
            &line.to_uppercase().replace(' ', ",  ")
        ));
        assert!(!words_match(&public(1, 2), &words_line(&public(1, 3))));
        let fewer: Vec<&str> = line.split(' ').take(5).collect();
        assert!(!words_match(&public(1, 2), &fewer.join(" ")));
        assert!(!words_match(&public(1, 2), ""));
    }
}
