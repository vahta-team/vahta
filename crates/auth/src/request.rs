//! What is being asked of the person, as a structure, and the answer bound to
//! it.
//!
//! A phone draws its own screen from a [`Request`]; it never shows text the
//! computer composed. The [`Decision`] it sends back carries the hash of the
//! request and a signature over that hash and the choice, made with the key
//! it generated at pairing. The daemon accepts it only for the request it
//! sent, before the request expires, from the device the vault lists.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AuthError;

const DOMAIN_REQUEST: &[u8] = b"vahta/v1/request";
const DOMAIN_DECISION: &[u8] = b"vahta/v1/decision";

/// What is being done. Names, never values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Unlock {
        names: Vec<String>,
        /// `None`: until revoked.
        duration_secs: Option<u64>,
    },
    RunEachUse {
        names: Vec<String>,
        command: String,
    },
    RunAsk {
        names: Vec<String>,
        command: String,
        reason: Option<String>,
    },
    Bind {
        names: Vec<String>,
    },
    Add {
        name: String,
    },
    Reset {
        name: String,
    },
    Remove {
        name: String,
    },
    Reveal {
        name: String,
    },
    Copy {
        name: String,
    },
    Import {
        source: String,
    },
    SetTier {
        name: String,
    },
    HooksPause {
        secs: u64,
    },
    AlarmLock,
    Extend {
        session: String,
        secs: u64,
    },
    GuardChoice {
        what: String,
    },
    OutputAllow,
    /// Managing devices: extend, revoke, lost, pair.
    Devices {
        what: String,
    },
    Recover,
    Other {
        what: String,
    },
}

impl Action {
    /// The row of `policy/factors.toml` for this action.
    pub fn key(&self) -> &'static str {
        match self {
            Action::Unlock { .. } => "unlock",
            Action::RunEachUse { .. } => "run_each_use",
            Action::RunAsk { .. } => "run_ask",
            Action::Bind { .. } => "bind",
            Action::Add { .. } => "add",
            Action::Reset { .. } => "reset",
            Action::Remove { .. } => "remove",
            Action::Reveal { .. } => "reveal",
            Action::Copy { .. } => "copy",
            Action::Import { .. } => "import",
            Action::SetTier { .. } => "set_tier",
            Action::HooksPause { .. } => "hooks_pause",
            Action::AlarmLock => "alarm_lock",
            Action::Extend { .. } => "extend",
            Action::GuardChoice { .. } => "guard_choice",
            Action::OutputAllow => "output_allow",
            Action::Devices { .. } => "devices",
            Action::Recover => "recover",
            Action::Other { .. } => "other",
        }
    }
}

impl Action {
    /// The secret names it touches.
    pub fn names(&self) -> Vec<String> {
        match self {
            Action::Unlock { names, .. }
            | Action::RunEachUse { names, .. }
            | Action::RunAsk { names, .. }
            | Action::Bind { names } => names.clone(),
            Action::Add { name }
            | Action::Reset { name }
            | Action::Remove { name }
            | Action::Reveal { name }
            | Action::Copy { name }
            | Action::SetTier { name } => vec![name.clone()],
            _ => Vec::new(),
        }
    }
}

/// A request for the person's yes. Canonical: its bytes are `postcard` of
/// this struct, and [`Request::hash`] is over those bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub action: Action,
    pub project: String,
    pub vault_id: [u8; 16],
    /// The strictest category of the secrets involved, when there is one.
    pub category: Option<String>,
    /// What the agent said it is for. Unverified; the phone marks it so.
    pub agent_label: Option<String>,
    /// The choices the person can make, as text; a [`Decision`]'s `choice`
    /// indexes them. Part of the hash, so a choice cannot be moved onto a
    /// different option list.
    pub options: Vec<String>,
    pub nonce: [u8; 16],
    /// Unix seconds after which no answer to this request is accepted.
    pub expires_at: u64,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Request {
    /// A request with a fresh nonce that expires `valid_for` from now.
    pub fn new(
        action: Action,
        project: &str,
        vault_id: [u8; 16],
        valid_for: std::time::Duration,
    ) -> Result<Request, AuthError> {
        Ok(Request {
            action,
            project: project.to_string(),
            vault_id,
            category: None,
            agent_label: None,
            options: Vec::new(),
            nonce: vahta_vault::crypto::random::<16>()
                .map_err(|_| AuthError::Unavailable("the system random generator failed".into()))?,
            expires_at: now() + valid_for.as_secs().max(1),
        })
    }

    pub fn with_options(mut self, options: &[String]) -> Request {
        self.options = options.to_vec();
        self
    }

    pub fn with_category(mut self, category: Option<String>) -> Request {
        self.category = category;
        self
    }

    pub fn with_label(mut self, label: Option<String>) -> Request {
        self.agent_label = label;
        self
    }

    /// The canonical bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Plain data: encoding cannot fail.
        postcard::to_allocvec(self).unwrap_or_default()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Request> {
        postcard::from_bytes(bytes).ok()
    }

    /// `SHA-256("vahta/v1/request" ‖ canonical bytes)`.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN_REQUEST);
        h.update(self.to_bytes());
        h.finalize().into()
    }

    pub fn expired(&self) -> bool {
        now() >= self.expires_at
    }
}

/// A device's answer to a [`Request`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub request_hash: [u8; 32],
    /// An index into the request's `options` (0 for a plain "yes" to an
    /// unlock, which has one option).
    pub choice: u8,
    pub device_id: [u8; 16],
    /// ECDSA P-256, 64 bytes, over [`Decision::message`].
    pub signature: Vec<u8>,
}

impl Decision {
    /// `"vahta/v1/decision" ‖ request hash ‖ choice ‖ device id`.
    pub fn message(request_hash: &[u8; 32], choice: u8, device_id: &[u8; 16]) -> Vec<u8> {
        let mut m = DOMAIN_DECISION.to_vec();
        m.extend_from_slice(request_hash);
        m.push(choice);
        m.extend_from_slice(device_id);
        m
    }

    /// What a device does: sign `choice` for `req`.
    pub fn sign(req: &Request, choice: u8, device_id: [u8; 16], key: &SigningKey) -> Decision {
        let request_hash = req.hash();
        let sig: Signature = key.sign(&Decision::message(&request_hash, choice, &device_id));
        Decision {
            request_hash,
            choice,
            device_id,
            signature: sig.to_bytes().to_vec(),
        }
    }

    /// Whether this is `device_id`'s answer to `req`, in time: the hash is the
    /// request's, the request has not expired, the choice is one of its
    /// options (or 0 when it has none), and the signature verifies under
    /// `sign_pub` (SEC1).
    pub fn verify(
        &self,
        req: &Request,
        device_id: &[u8; 16],
        sign_pub: &[u8],
    ) -> Result<(), AuthError> {
        if &self.device_id != device_id {
            return Err(AuthError::BadDecision("another device"));
        }
        if self.request_hash != req.hash() {
            return Err(AuthError::BadDecision("another request"));
        }
        if req.expired() {
            return Err(AuthError::BadDecision("too late"));
        }
        let options = req.options.len().max(1);
        if usize::from(self.choice) >= options {
            return Err(AuthError::BadDecision("no such choice"));
        }
        let key = VerifyingKey::from_sec1_bytes(sign_pub)
            .map_err(|_| AuthError::BadDecision("bad device key"))?;
        let sig = Signature::from_slice(&self.signature)
            .map_err(|_| AuthError::BadDecision("bad signature"))?;
        key.verify(
            &Decision::message(&self.request_hash, self.choice, &self.device_id),
            &sig,
        )
        .map_err(|_| AuthError::BadDecision("signature"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn key() -> (SigningKey, Vec<u8>) {
        let k = SigningKey::random(&mut rand_core::OsRng);
        let pubkey = k
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        (k, pubkey)
    }

    fn req() -> Request {
        Request::new(
            Action::RunEachUse {
                names: vec!["A".into()],
                command: "deploy".into(),
            },
            "/p",
            [1; 16],
            Duration::from_secs(60),
        )
        .unwrap()
        .with_options(&["Allow".to_string(), "Deny".to_string()])
    }

    #[test]
    fn a_decision_verifies_only_for_its_request_device_and_key() {
        let (sk, pk) = key();
        let r = req();
        let d = Decision::sign(&r, 1, [7; 16], &sk);
        d.verify(&r, &[7; 16], &pk).unwrap();
        // Another request, even a similar one (a new nonce): a replay.
        let again = req();
        assert!(d.verify(&again, &[7; 16], &pk).is_err());
        // Another device id, another key, another choice, a cut signature.
        assert!(d.verify(&r, &[8; 16], &pk).is_err());
        let (_, other_pk) = key();
        assert!(d.verify(&r, &[7; 16], &other_pk).is_err());
        let mut moved = d.clone();
        moved.choice = 0;
        assert!(moved.verify(&r, &[7; 16], &pk).is_err());
        let mut cut = d.clone();
        cut.signature.truncate(10);
        assert!(cut.verify(&r, &[7; 16], &pk).is_err());
        // A choice outside the options is refused even if signed.
        let wild = Decision::sign(&r, 9, [7; 16], &sk);
        assert!(wild.verify(&r, &[7; 16], &pk).is_err());
    }

    #[test]
    fn an_expired_request_takes_no_answer() {
        let (sk, pk) = key();
        let mut r = req();
        r.expires_at = 1;
        let d = Decision::sign(&r, 0, [7; 16], &sk);
        assert!(matches!(
            d.verify(&r, &[7; 16], &pk),
            Err(AuthError::BadDecision("too late"))
        ));
    }

    #[test]
    fn the_hash_covers_every_field_and_round_trips() {
        let r = req();
        assert_eq!(Request::from_bytes(&r.to_bytes()).unwrap(), r);
        let mut o = r.clone();
        o.options[1] = "Maybe".into();
        assert_ne!(o.hash(), r.hash());
        let mut o = r.clone();
        o.project = "/q".into();
        assert_ne!(o.hash(), r.hash());
        let mut o = r.clone();
        o.agent_label = Some("x".into());
        assert_ne!(o.hash(), r.hash());
        assert_eq!(r.action.key(), "run_each_use");
    }
}
