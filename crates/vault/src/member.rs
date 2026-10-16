//! Team members: the public key a person gives to the owner, the digits that
//! prove it arrived unchanged, the package the owner sends back and the single
//! secret an editor sends to the owner.
//!
//! **The key string.** `vh1` followed by the lowercase base32 (no padding) of
//! `enc_pk ‖ sign_pk ‖ checksum`, where the checksum is the first four bytes of
//! SHA-256 over `"vahta/v1/member-key-check" ‖ enc_pk ‖ sign_pk`. It catches a
//! mistyped or cut-off string; it is not a defence against an attacker, who
//! can compute it. The digits are.
//!
//! **The verification digits.** Six groups of four decimal digits derived from
//! SHA-256 over `"vahta/v1/member-digits" ‖ enc_pk ‖ sign_pk`: the first 128 bits
//! of the hash, modulo 10^24, which is about 79 bits. The person who owns the
//! key reads them to the owner over another channel, and the owner types them
//! in. Someone who swaps the key string in the chat has to find another key
//! pair with the same 79 bits, which is out of reach. Digits, not words, because
//! they are language-neutral: everyone reads `4821 3905` aloud in their own
//! language, and there is no word list to translate or to mishear. Typing
//! accepts any separators (or none).
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
//! name, kind and tier, signed by the editor. It also carries a **counter**, one
//! more than the editor's last, which the owner records in the signed vault: an
//! old transfer cannot be replayed, and no clock is involved. For a secret the
//! owner does not have yet, the editor may **propose rules** as text
//! ([`ProposedRules`]); they mean nothing until the owner reads them in the
//! import window and approves, and are then built and signed by the owner like
//! any other approval.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{self, KEY_LEN};
use std::path::Path;

use crate::format::current::{
    self, Actor, Entry, Kind, Model, PasswordParams, Recipient, SLOT_PASSWORD, Sealed, Slot, Team,
    Tier,
};
use crate::vault::RecipientPublic;
use crate::{Error, hex_encode, valid_name};

const DOMAIN_KEY_CHECK: &[u8] = b"vahta/v1/member-key-check";
const DOMAIN_DIGITS: &[u8] = b"vahta/v1/member-digits";
const DOMAIN_FINGERPRINT: &[u8] = b"vahta/v1/member-fingerprint";
const DOMAIN_TRANSFER: &[u8] = b"vahta/v1/transfer";

/// What a key string starts with.
pub const KEY_PREFIX: &str = "vh1";
/// How many groups of digits are read out.
pub const GROUP_COUNT: usize = 6;
/// How many digits one group has.
const GROUP_DIGITS: usize = 4;

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

/// The six groups of `public`, in order, each four digits.
pub fn verification_digits(public: &RecipientPublic) -> [String; GROUP_COUNT] {
    let hash = digest(DOMAIN_DIGITS, public);
    let mut head = [0u8; 16];
    head.copy_from_slice(&hash[..16]);
    // 128 bits reduced to 24 digits; the bias of the reduction is below 2^-40.
    let mut n = u128::from_be_bytes(head) % 10u128.pow((GROUP_COUNT * GROUP_DIGITS) as u32);
    let mut groups = [0u32; GROUP_COUNT];
    for g in groups.iter_mut().rev() {
        *g = (n % 10u128.pow(GROUP_DIGITS as u32)) as u32;
        n /= 10u128.pow(GROUP_DIGITS as u32);
    }
    groups.map(|g| format!("{g:0width$}", width = GROUP_DIGITS))
}

/// The digits as one line, `4821 3905 ...`.
pub fn digits_line(public: &RecipientPublic) -> String {
    verification_digits(public).join(" ")
}

/// The value of a decimal digit in the scripts people are likely to type: ASCII,
/// Arabic-Indic, Devanagari, Bengali, Thai and full-width digits.
fn digit_value(c: char) -> Option<u32> {
    const ZEROS: [u32; 7] = [0x30, 0x660, 0x6F0, 0x966, 0x9E6, 0xE50, 0xFF10];
    let code = c as u32;
    ZEROS
        .iter()
        .find_map(|z| code.checked_sub(*z).filter(|d| *d < 10))
}

/// Whether `typed` is the digits of `public`. Spaces and any other punctuation
/// between (or inside) the groups are ignored, so `4821 3905`, `4821-3905` and
/// `48213905` are the same; a letter, a missing digit or a wrong one is not.
pub fn digits_match(public: &RecipientPublic, typed: &str) -> bool {
    let mut got = String::new();
    for c in typed.chars() {
        match digit_value(c) {
            Some(d) => got.push(char::from_digit(d, 10).unwrap_or('?')),
            None if c.is_alphanumeric() => return false,
            None => {}
        }
    }
    got == verification_digits(public).concat()
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
///
/// The rules in it are the owner's approved ones with every place inside the
/// project (one of `roots`) in the project-relative form, so a vault from
/// before that form still works on the member's machine; the folders the secret
/// may be used from (the owner's own layout, and no use to a member) are left
/// out.
pub(crate) fn build_package(
    model: &Model,
    recipient_id: &[u8; 16],
    owner_key: &SigningKey,
    roots: &[&Path],
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
        .filter_map(|mut b| {
            crate::rules::relativize(&mut b, roots);
            b.from.clear();
            (!b.is_empty()).then_some(b)
        })
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
        team: Team {
            owner_generation: model.team.owner_generation,
            counters: Vec::new(),
        },
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
    /// The file's own generation (an editor's local saves move it).
    pub generation: u64,
    /// The generation as the owner saved the file: what packages are compared
    /// by.
    pub owner_generation: u64,
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
    /// The owner successor chain the file carries, oldest first.
    pub successors: Vec<current::Successor>,
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
        owner_generation: loaded.owner_generation(),
        owner: RecipientPublic {
            enc_pk: owner.enc_pk,
            sign_pk: owner.sign_pk,
        },
        package,
        signed_by_owner: loaded.signer() == Actor::Owner,
        recipients,
        holdings,
        successors: loaded.successors(),
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

    /// The records of the file's successor chain that lead from the owner key
    /// `pinned` to this file's owner, if it is an earlier owner of this vault
    /// (the chain's signatures were checked when the file was read). Empty
    /// `None` when `pinned` is not in the chain.
    pub fn successors_from(&self, pinned: &[u8; 32]) -> Option<&[current::Successor]> {
        current::path_from(&self.successors, pinned).filter(|p| {
            p.last()
                .is_some_and(|l| l.new_owner_sign_pub == self.owner.sign_pk)
        })
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
const TRANSFER_VERSION: u16 = 2;
const MAX_TRANSFER: usize = 3 << 20;

/// Whether `bytes` start like a transfer file.
pub fn is_transfer(bytes: &[u8]) -> bool {
    bytes.starts_with(TRANSFER_MAGIC)
}

/// How many rules, folders and hosts a proposal may name, and how long each is.
const MAX_PROPOSED: usize = 64;
const MAX_PROPOSED_TEXT: usize = 512;

/// The rules an editor proposes for a secret it sends, as the text it would
/// give `vahta bind`. Text, not resolved rules: the programs are found on the
/// owner's machine when the owner approves, and the owner reads the result
/// before anything is stored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedRules {
    pub category: Option<String>,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub dirs: Vec<String>,
    /// `none`, `app` or `hosts:H[,H...]`.
    pub net: Option<String>,
}

impl ProposedRules {
    /// Whether it proposes nothing.
    pub fn is_empty(&self) -> bool {
        self.category.is_none()
            && self.allow.is_empty()
            && self.deny.is_empty()
            && self.dirs.is_empty()
            && self.net.is_none()
    }

    /// Few items, each of a sensible length and free of control characters.
    pub fn is_well_formed(&self) -> bool {
        let text_ok = |t: &String| {
            !t.is_empty() && t.len() <= MAX_PROPOSED_TEXT && !t.chars().any(char::is_control)
        };
        [&self.allow, &self.deny, &self.dirs]
            .iter()
            .all(|l| l.len() <= MAX_PROPOSED && l.iter().all(text_ok))
            && self.category.iter().all(text_ok)
            && self.net.iter().all(text_ok)
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct TransferBody {
    pub vault_id: [u8; 16],
    pub from: [u8; 16],
    pub name: String,
    pub kind: Kind,
    pub tier: Tier,
    /// The sender's counter for this transfer: above every earlier one it
    /// made, and above the highest the owner has accepted from it.
    pub counter: u64,
    pub fmt: u16,
    pub sealed: Sealed,
    pub proposed: Option<ProposedRules>,
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
    if body
        .proposed
        .as_ref()
        .is_some_and(|p| p.is_empty() || !p.is_well_formed())
    {
        return Err(corrupt());
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
    fn the_digits_depend_on_both_keys_and_are_stable() {
        let a = verification_digits(&public(1, 2));
        assert_eq!(a, verification_digits(&public(1, 2)));
        assert_ne!(a, verification_digits(&public(1, 3)));
        assert_ne!(a, verification_digits(&public(2, 2)));
        assert_eq!(a.len(), 6);
        for g in &a {
            assert!(g.len() == 4 && g.bytes().all(|b| b.is_ascii_digit()), "{g}");
        }
        let line = digits_line(&public(1, 2));
        assert_eq!(line.len(), 6 * 4 + 5);
        let p = public(1, 2);
        // Spaces, none at all, other separators and other scripts' digits.
        assert!(digits_match(&p, &line));
        assert!(digits_match(&p, &line.replace(' ', "")));
        assert!(digits_match(
            &p,
            &format!("  {}\n", line.replace(' ', " - "))
        ));
        assert!(digits_match(&p, &line.replace(' ', ",")));
        let arabic: String = line
            .chars()
            .map(|c| {
                c.to_digit(10)
                    .map_or(c, |d| char::from_u32(0x660 + d).unwrap())
            })
            .collect();
        assert!(digits_match(&p, &arabic));
        // A different key, a changed or missing digit, a letter, nothing.
        assert!(!digits_match(&p, &digits_line(&public(1, 3))));
        assert!(!digits_match(&p, &line[..line.len() - 1]));
        let mut off = line.clone().into_bytes();
        let last = off.len() - 1;
        off[last] = if off[last] == b'0' { b'1' } else { b'0' };
        assert!(!digits_match(&p, &String::from_utf8(off).unwrap()));
        assert!(!digits_match(&p, &format!("{line}0")));
        assert!(!digits_match(
            &p,
            &line.replacen(|c: char| c.is_ascii_digit(), "o", 1)
        ));
        assert!(!digits_match(&p, ""));
    }

    #[test]
    fn the_digits_use_the_whole_range_and_the_bits_are_spread() {
        // 24 digits, leading zeros kept, and many keys give many different codes.
        let mut seen = std::collections::HashSet::new();
        for a in 0..=255u8 {
            let d = verification_digits(&public(a, 7)).concat();
            assert_eq!(d.len(), 24);
            seen.insert(d);
        }
        assert_eq!(seen.len(), 256);
    }

    #[test]
    fn proposed_rules_are_bounded() {
        let ok = ProposedRules {
            allow: vec!["git push".into()],
            ..ProposedRules::default()
        };
        assert!(ok.is_well_formed() && !ok.is_empty());
        assert!(ProposedRules::default().is_empty());
        let long = ProposedRules {
            allow: vec!["a".repeat(MAX_PROPOSED_TEXT + 1)],
            ..ok.clone()
        };
        let many = ProposedRules {
            allow: vec!["a".into(); MAX_PROPOSED + 1],
            ..ok.clone()
        };
        let control = ProposedRules {
            net: Some("none\u{7}".into()),
            ..ok
        };
        for bad in [long, many, control] {
            assert!(!bad.is_well_formed());
        }
    }
}
