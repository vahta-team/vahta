//! Format 5 of `vault.vht`: format 4 plus the vault kind, agent roles, member
//! expiry and the harnesses of a rule set.
//!
//! Everything else is format 4's, re-exported here. What format 5 adds:
//!
//! * `kind` in the signed body: a `Project` vault (every vault until now) or a
//!   `Connectors` vault, which holds the person's own connections and is
//!   bound to harnesses rather than to a project. Fixed when the vault is
//!   created; an older file reads as `Project`.
//! * `roles`: named, person-approved sets of secrets and limits an agent may
//!   be given. Empty after an upgrade.
//! * `expires_at` on every [`Recipient`], covered by its membership
//!   certificate. `None` after an upgrade.
//! * `harnesses` in each [`RuleSet`]: which agent harnesses a secret of a
//!   `Connectors` vault is bound to. Empty after an upgrade, and always empty
//!   in a `Project` vault.
//!
//! None of these is open-ended: the body is postcard, which has no room for a
//! field a build does not know, so an unknown field is refused at decode
//! (`Corrupt`), and a newer format number is refused before that.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::v2;
use super::v3;
use super::v4;
pub use super::v4::*;
use super::{Frame, MAGIC};
use crate::crypto::{self, KEY_LEN, KdfParams};
use crate::{Error, RecoveryKey, hex_encode, valid_name};

use super::v1::{self, exact, valid_recipient_name};

/// This module's format number.
pub const FORMAT: u16 = 5;

/// How many roles one vault may hold.
pub const MAX_ROLES: usize = 64;
/// How many secrets one role may name.
pub const MAX_ROLE_SECRETS: usize = 64;
/// The harnesses a rule set of a `Connectors` vault may be bound to.
pub const HARNESSES: [&str; 3] = ["claude", "codex", "cursor"];

/// Domain of a certificate that covers an expiry. A member with no expiry is
/// certified exactly as in format 1, so the certificates of an older file stay
/// good without anyone re-signing them.
const DOMAIN_MEMBER_EXPIRY: &[u8] = b"vahta/v5/member";

// --- Kind -----------------------------------------------------------------------------------

/// What a vault is for. Fixed at creation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultKind {
    /// The secrets of one project.
    #[default]
    Project,
    /// The person's own connections, bound to harnesses.
    Connectors,
}

// --- Members --------------------------------------------------------------------------------

/// Format 1's member plus `expires_at`: when the membership ends, if it does.
/// The certificate covers it, so it cannot be changed without the issuer.
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
    pub expires_at: Option<u64>,
    pub cert: Sig,
}

/// What a certificate over an expiry signs: the entry without `cert`.
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
    expires_at: u64,
}

impl Recipient {
    /// What formats 1 to 4 stored, in this format (no expiry; the certificate
    /// is the one it had).
    pub fn from_v1(old: &v1::Recipient) -> Recipient {
        Recipient {
            id: old.id,
            name: old.name.clone(),
            kind: old.kind,
            role: old.role,
            enc_pk: old.enc_pk,
            sign_pk: old.sign_pk,
            added: old.added,
            added_by: old.added_by,
            expires_at: None,
            cert: old.cert,
        }
    }

    /// The same member as format 1 knew it, without the expiry.
    pub fn to_v1(&self) -> v1::Recipient {
        v1::Recipient {
            id: self.id,
            name: self.name.clone(),
            kind: self.kind,
            role: self.role,
            enc_pk: self.enc_pk,
            sign_pk: self.sign_pk,
            added: self.added,
            added_by: self.added_by,
            cert: self.cert,
        }
    }

    /// Without an expiry, format 1's message. With one,
    /// `"vahta/v5/member" ‖ vault_id ‖ postcard(entry without cert)`.
    pub fn cert_message(&self, vault_id: &[u8; 16]) -> Vec<u8> {
        let Some(expires_at) = self.expires_at else {
            return self.to_v1().cert_message(vault_id);
        };
        let core = RecipientCore {
            id: &self.id,
            name: &self.name,
            kind: self.kind,
            role: self.role,
            enc_pk: &self.enc_pk,
            sign_pk: &self.sign_pk,
            added: self.added,
            added_by: self.added_by,
            expires_at,
        };
        let mut m = DOMAIN_MEMBER_EXPIRY.to_vec();
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

/// Every member's certificate must verify, and every issuer must be allowed to
/// have issued it: the owner may certify anyone; an Admin the owner added may
/// certify Editors and Runners (format 1's rule, over this format's entries).
fn check_recipients(vault_id: &[u8; 16], owner: &Owner, list: &[Recipient]) -> Result<(), Error> {
    if list.len() > v1::MAX_RECIPIENTS {
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

// --- Rule sets ---------------------------------------------------------------------------

/// Format 4's rule set plus `harnesses`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSet {
    pub name: String,
    pub category: Option<String>,
    pub downgraded_from: Option<String>,
    pub allow: Vec<ApprovedRule>,
    pub deny: Vec<ApprovedRule>,
    pub dirs: Vec<DirRule>,
    pub network: Network,
    pub from: Vec<String>,
    /// The harnesses (`claude`, `codex`, `cursor`) this secret is bound to.
    /// Only a `Connectors` vault has any.
    pub harnesses: Vec<String>,
}

impl RuleSet {
    /// A rule set that approves nothing is the same as none.
    pub fn is_empty(&self) -> bool {
        self.to_v4().is_empty() && self.harnesses.is_empty()
    }

    /// What format 4 stored, in this format (`harnesses` empty).
    pub fn from_v4(old: &v4::RuleSet) -> RuleSet {
        RuleSet {
            name: old.name.clone(),
            category: old.category.clone(),
            downgraded_from: old.downgraded_from.clone(),
            allow: old.allow.clone(),
            deny: old.deny.clone(),
            dirs: old.dirs.clone(),
            network: old.network.clone(),
            from: old.from.clone(),
            harnesses: Vec::new(),
        }
    }

    /// What format 2 stored, in this format.
    pub fn from_v2(old: &v2::RuleSet) -> RuleSet {
        RuleSet::from_v4(&v4::RuleSet::from_v2(old))
    }

    /// The same rules without `harnesses`, for the checks format 4 owns.
    pub fn to_v4(&self) -> v4::RuleSet {
        v4::RuleSet {
            name: self.name.clone(),
            category: self.category.clone(),
            downgraded_from: self.downgraded_from.clone(),
            allow: self.allow.clone(),
            deny: self.deny.clone(),
            dirs: self.dirs.clone(),
            network: self.network.clone(),
            from: self.from.clone(),
        }
    }
}

/// Whether `harnesses` are known names, each once.
pub fn valid_harnesses(harnesses: &[String]) -> bool {
    harnesses.len() <= HARNESSES.len()
        && harnesses
            .iter()
            .enumerate()
            .all(|(i, h)| HARNESSES.contains(&h.as_str()) && !harnesses[..i].iter().any(|o| o == h))
}

/// The shape checks of a reader, for rule sets a writer is about to store.
pub fn check_binding_shapes(sets: &[RuleSet]) -> Result<(), Error> {
    for b in sets {
        v4::check_binding_shapes(std::slice::from_ref(&b.to_v4()))?;
        if !valid_harnesses(&b.harnesses) {
            return Err(Error::Corrupt("bindings"));
        }
    }
    Ok(())
}

/// Rule sets name secrets that exist, once each, and carry well-formed rules;
/// only a `Connectors` vault binds harnesses.
fn check_bindings(kind: VaultKind, index: &[Entry], sets: &[RuleSet]) -> Result<(), Error> {
    if sets.len() > v1::MAX_ENTRIES {
        return Err(Error::Corrupt("bindings"));
    }
    for (i, b) in sets.iter().enumerate() {
        if !index.iter().any(|e| e.name == b.name)
            || sets[..i].iter().any(|o| o.name == b.name)
            || b.is_empty()
            || (kind != VaultKind::Connectors && !b.harnesses.is_empty())
        {
            return Err(Error::Corrupt("bindings"));
        }
    }
    check_binding_shapes(sets)
}

// --- Agent roles ---------------------------------------------------------------------------

/// What an agent in a role may ask a secret to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// Run a command with the secret in its environment.
    Run,
    /// Make an HTTP request with the secret.
    Http,
}

/// A named grant the person approved for an agent: which secrets, under which
/// rules and limits. The signed copy is the one that counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRole {
    /// Shaped like a secret name.
    pub name: String,
    /// Names of secrets of this vault.
    pub secrets: Vec<String>,
    pub allow: Vec<ApprovedRule>,
    pub deny: Vec<ApprovedRule>,
    /// `None`: the role says nothing about the network.
    pub network: Option<Network>,
    pub dirs: Vec<DirRule>,
    /// How long one grant lasts, in seconds, at most.
    pub max_for_secs: Option<u64>,
    /// How many uses one grant gives, at most.
    pub max_uses: Option<u32>,
    pub actions: Vec<Action>,
    /// Ask the person before every use.
    pub ask_each_use: bool,
    /// When the person approved this role (seconds since the epoch).
    pub approved_at: u64,
}

/// One role's shape. Uniqueness among roles is [`check_roles`].
pub fn check_role(r: &AgentRole) -> Result<(), Error> {
    let bad = || Error::Corrupt("roles");
    if !valid_name(&r.name)
        || r.secrets.len() > MAX_ROLE_SECRETS
        || !r
            .secrets
            .iter()
            .enumerate()
            .all(|(i, s)| valid_name(s) && !r.secrets[..i].iter().any(|o| o == s))
        || r.max_for_secs == Some(0)
        || r.max_uses == Some(0)
        || r.actions.len() > 2
        || (r.actions.len() == 2 && r.actions[0] == r.actions[1])
    {
        return Err(bad());
    }
    // The rules, directories and network are held to the limits of a rule
    // set's: the same checks, on a rule set made of them.
    v2::check_binding_shapes(&[v2::RuleSet {
        name: r.name.clone(),
        allow: r.allow.clone(),
        deny: r.deny.clone(),
        dirs: r.dirs.clone(),
        network: r.network.clone().unwrap_or_default(),
        ..v2::RuleSet::default()
    }])
    .map_err(|_| bad())
}

/// Roles are few, well formed and named once each.
pub fn check_roles(roles: &[AgentRole]) -> Result<(), Error> {
    if roles.len() > MAX_ROLES {
        return Err(Error::Corrupt("roles"));
    }
    for (i, r) in roles.iter().enumerate() {
        if roles[..i].iter().any(|o| o.name == r.name) {
            return Err(Error::Corrupt("roles"));
        }
        check_role(r)?;
    }
    Ok(())
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
    pub kind: VaultKind,
    pub roles: Vec<AgentRole>,
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
    pub kind: VaultKind,
    pub roles: Vec<AgentRole>,
}

impl Model {
    /// A format 4 model's facts in this format: kind `Project`, no roles, no
    /// expiries, no harnesses. The sealed secrets are copied as they are
    /// (still sealed for format 4 until `upgrade` re-seals them).
    pub fn from_v4(old: &v4::Model) -> Model {
        Model {
            header: old.header.clone(),
            slots: old.slots.clone(),
            owner: old.owner.clone(),
            recipients: old.recipients.iter().map(Recipient::from_v1).collect(),
            devices: old.devices.clone(),
            index: old.index.clone(),
            secrets: old.secrets.clone(),
            bindings: old.bindings.iter().map(RuleSet::from_v4).collect(),
            successors: old.successors.clone(),
            remote: old.remote,
            kind: VaultKind::Project,
            roles: Vec::new(),
        }
    }

    /// A format 3 model's facts in this format.
    pub fn from_v3(old: &v3::Model) -> Model {
        Model::from_v4(&v4::Model::from_v3(old))
    }

    /// A format 2 model's facts in this format, with no successors.
    pub fn from_v2(old: &v2::Model) -> Model {
        Model::from_v4(&v4::Model::from_v2(old))
    }

    /// A format 1 model's facts in this format.
    pub fn from_v1(old: &v1::Model) -> Model {
        Model::from_v4(&v4::Model::from_v1(old))
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

// --- Sealing ------------------------------------------------------------------------------------

/// Wrap `dek` for one recipient.
pub fn wrap_for(
    fmt: u16,
    vault_id: &[u8; 16],
    sid: &[u8; 16],
    dek: &[u8; KEY_LEN],
    recipient: &Recipient,
) -> Result<RecipientWrap, Error> {
    v1::wrap_for(fmt, vault_id, sid, dek, &recipient.to_v1())
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
    // Wrapping looks at an id and a public key only.
    let old: Vec<v1::Recipient> = holders.iter().map(|r| r.to_v1()).collect();
    let refs: Vec<&v1::Recipient> = old.iter().collect();
    v1::seal_secret(fmt, vault_id, sid, owner_enc_pk, value, &refs)
}

// --- Decode ---------------------------------------------------------------------------------

/// Parse and check a frame as format 5: structure, membership certificates,
/// the successor chain, signer permission and the file signature. No password
/// needed.
pub fn decode(frame: &Frame<'_>) -> Result<Decoded, Error> {
    let body: Body = exact(frame.body, "body")?;
    let sig_section: SigSection = exact(frame.sig, "signature section")?;

    check_slots(&body.slots)?;
    if body.index.len() > v1::MAX_ENTRIES || body.secrets.len() != body.index.len() {
        return Err(Error::Corrupt("index"));
    }
    check_recipients(&body.header.vault_id, &body.owner, &body.recipients)?;
    // Only the recipients' ids matter to the index.
    let old: Vec<v1::Recipient> = body.recipients.iter().map(Recipient::to_v1).collect();
    v1::check_index(&body.index, &body.secrets, &old)?;
    check_devices(&body.devices)?;
    check_bindings(body.kind, &body.index, &body.bindings)?;
    check_roles(&body.roles)?;
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
            kind: body.kind,
            roles: body.roles,
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

/// Encode `model` as a signed format-5 file, signed by the owner.
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
        kind: model.kind,
        roles: model.roles.clone(),
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
