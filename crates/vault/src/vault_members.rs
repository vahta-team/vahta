//! The team-member operations of [`Vault`]: packages for members, the held
//! secrets of a member, and the single-secret transfer from an editor to the
//! owner. See `member.rs` for the formats.

use super::*;
use crate::format::current::Sealed;
use crate::member::{self, TransferBody};

/// Who sent a transfer: a member of the vault, by id and name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferSender {
    pub id: [u8; 16],
    pub name: String,
}

/// A secret an editor sent, opened by the owner and checked, not yet applied.
pub struct Transfer {
    pub name: String,
    pub kind: Kind,
    pub tier: Tier,
    pub from: TransferSender,
    /// When the editor last changed it (the editor's clock).
    pub updated: u64,
    /// The vault already has a secret of this name, which this would replace.
    pub replaces: bool,
    value: SecretValue,
}

impl Transfer {
    pub fn value(&self) -> &SecretValue {
        &self.value
    }
}

impl std::fmt::Debug for Transfer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transfer")
            .field("name", &self.name)
            .field("from", &self.from.name)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// The file to send `recipient_id`: owner-signed, holding that member's
    /// entry and only the secrets they hold. Owner only. It reflects the vault
    /// as it is in memory, so save first. See `member::build_package`.
    pub fn package_for(&self, recipient_id: &[u8; 16]) -> Result<Vec<u8>, Error> {
        match &self.access {
            Access::Owner(u) => {
                member::build_package(&u.model, recipient_id, &current::owner_keys(&u.vk).sign)
            }
            Access::Blocked { .. } => Err(Error::UpgradeNeedsRecoveryKey),
            Access::Recipient(_) => Err(Error::NotOwner),
        }
    }

    /// The names of the secrets `recipient_id` holds a wrap for.
    pub fn held_by(&self, recipient_id: &[u8; 16]) -> Vec<String> {
        let m = self.model();
        m.index
            .iter()
            .zip(&m.secrets)
            .filter(|(_, s)| s.wraps.iter().any(|w| &w.recipient_id == recipient_id))
            .map(|(e, _)| e.name.clone())
            .collect()
    }

    /// This opener's own membership entry, when it opened as a recipient.
    pub fn membership(&self) -> Option<&Recipient> {
        match &self.access {
            Access::Recipient(r) => Some(&r.me),
            _ => None,
        }
    }

    /// One secret for the owner: the sealed secret as this vault holds it
    /// (its key is wrapped for the owner's public key), with its name, kind
    /// and tier, signed by this member. An Admin or Editor only, and only a
    /// secret it can read.
    pub fn make_transfer(&self, name: &str) -> Result<Vec<u8>, Error> {
        let Access::Recipient(r) = &self.access else {
            return Err(Error::Invalid("only a member sends a secret to the owner"));
        };
        if r.me.role == Role::Runner || r.fmt != CURRENT {
            return Err(Error::NotPermitted);
        }
        let i = r
            .model
            .index
            .iter()
            .position(|e| e.name == name)
            .ok_or_else(|| Error::not_found(name))?;
        let sealed = &r.model.secrets[i];
        // It must be one this member can open, or it has no business sending it.
        current::open_dek_as_recipient(
            r.fmt,
            &r.model.header.vault_id,
            &r.enc_sk,
            &r.me.id,
            sealed,
        )?
        .ok_or(Error::NoAccess)?;
        let entry = &r.model.index[i];
        member::encode_transfer(
            &TransferBody {
                vault_id: r.model.header.vault_id,
                from: r.me.id,
                name: entry.name.clone(),
                kind: entry.kind.clone(),
                tier: entry.tier,
                updated: entry.updated,
                fmt: r.fmt,
                sealed: Sealed {
                    wraps: Vec::new(),
                    ..sealed.clone()
                },
            },
            &crypto::signing_key(&r.sign_sk),
        )
    }

    /// Open and check a transfer: it is for this vault, an Admin or Editor of
    /// it signed it and has not expired, the secret opens with the owner key,
    /// and it is newer than the owner's copy. Owner only. Nothing changes
    /// until [`Vault::apply_transfer`].
    pub fn read_transfer(&self, bytes: &[u8]) -> Result<Transfer, Error> {
        let Access::Owner(u) = &self.access else {
            return Err(Error::NotOwner);
        };
        let body = member::decode_transfer(bytes, |id| {
            u.model
                .recipients
                .iter()
                .find(|r| &r.id == id)
                .map(|r| r.sign_pk)
        })?;
        if body.vault_id != u.model.header.vault_id || body.fmt != u.fmt {
            return Err(Error::Invalid("this transfer is for another vault"));
        }
        let sender = u
            .model
            .recipients
            .iter()
            .find(|r| r.id == body.from)
            .ok_or(Error::SignerNotAllowed)?;
        if sender.role == Role::Runner {
            return Err(Error::NotPermitted);
        }
        if sender.expires_at.is_some_and(|t| now() >= t) {
            return Err(Error::MembershipExpired);
        }
        let existing = u.model.index.iter().find(|e| e.name == body.name);
        if existing.is_some_and(|e| e.updated >= body.updated) {
            return Err(Error::Invalid(
                "this transfer is not newer than the secret already in the vault",
            ));
        }
        let keys = current::owner_keys(&u.vk);
        let value = current::open_value(u.fmt, &body.vault_id, &keys.enc_sk, &body.sealed)?;
        Ok(Transfer {
            name: body.name,
            kind: body.kind,
            tier: body.tier,
            from: TransferSender {
                id: sender.id,
                name: sender.name.clone(),
            },
            updated: body.updated,
            replaces: existing.is_some(),
            value,
        })
    }

    /// Store a checked transfer. A secret the vault already has keeps its kind
    /// and tier (the sender changes the value, not the policy); a new one has
    /// no approved rules, which are the owner's to give, and the sender keeps
    /// access to it.
    pub fn apply_transfer(&mut self, t: &Transfer) -> Result<(), Error> {
        let (kind, tier) = match self.entries().iter().find(|e| e.name == t.name) {
            Some(e) => (e.kind.clone(), e.tier),
            None => (t.kind.clone(), t.tier),
        };
        self.set(&t.name, t.value.expose(), kind, tier)?;
        self.grant(&t.name, &t.from.id)
    }
}
