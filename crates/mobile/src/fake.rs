//! A software phone for tests (the `fake-phone` feature; the app never
//! enables it). It does what the Kotlin side does, through this crate's own
//! API and nothing else: `PairingSession` and `LinkSession` for the protocol,
//! `request_summary` and `decision_message` for the request, a P-256 key that
//! signs DER (as Android's `Signature` does) and a P-256 key that does ECDH
//! (as the Keystore's `KeyAgreement` does). So a test that drives a daemon
//! with it exercises the same helper calls the real app must make.
//!
//! What it does when asked is scripted: approve an option, deny, or ignore
//! (hold the question until the desktop gives up and hangs up).

use std::collections::VecDeque;
use std::sync::Mutex;

use p256::SecretKey;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use vahta_link::Pipe;

use crate::{
    LinkEvent, LinkSession, PairedDesktop, PairingSession, RequestView, StaticKey,
    decision_message, device_id, generate_static_key, request_summary, sec1_from_spki,
    signature_from_der,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behavior {
    /// The person approves, choosing this option (0 for an unlock).
    Approve(u8),
    Deny,
    /// No answer.
    Ignore,
}

/// A question the phone was asked.
#[derive(Debug, Clone)]
pub struct Asked {
    /// `approve` or `unlock`.
    pub kind: String,
    pub view: RequestView,
}

pub struct FakePhone {
    pub name: String,
    key: StaticKey,
    sign: SigningKey,
    ecdh: SecretKey,
    behaviors: Mutex<VecDeque<Behavior>>,
    asked: Mutex<Vec<Asked>>,
    desktop: Mutex<Option<PairedDesktop>>,
}

/// What Android's `PublicKey.getEncoded()` gives for a P-256 key.
fn spki(sec1: &[u8]) -> Vec<u8> {
    let mut v = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    v.extend_from_slice(sec1);
    v
}

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

impl FakePhone {
    pub fn new(name: &str) -> FakePhone {
        FakePhone {
            name: name.to_string(),
            key: generate_static_key().expect("system randomness"),
            sign: SigningKey::random(&mut rand_core::OsRng),
            ecdh: SecretKey::random(&mut rand_core::OsRng),
            behaviors: Mutex::new(VecDeque::new()),
            asked: Mutex::new(Vec::new()),
            desktop: Mutex::new(None),
        }
    }

    /// What it does for its next question.
    pub fn queue(&self, b: Behavior) {
        if let Ok(mut q) = self.behaviors.lock() {
            q.push_back(b);
        }
    }

    /// The questions it has been asked, in order.
    pub fn asked(&self) -> Vec<Asked> {
        self.asked.lock().map(|a| a.clone()).unwrap_or_default()
    }

    /// Its Keystore public keys in the form `PairingSession::start` takes.
    fn public_keys(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        let sign = self.sign.verifying_key().to_encoded_point(false);
        let ecdh = p256::EncodedPoint::from(self.ecdh.public_key());
        Ok((
            sec1_from_spki(spki(sign.as_bytes()))?,
            sec1_from_spki(spki(ecdh.as_bytes()))?,
        ))
    }

    pub fn device_id(&self) -> Result<Vec<u8>, String> {
        let (sign, ecdh) = self.public_keys()?;
        Ok(device_id(sign, ecdh))
    }

    /// The static key it advertises under (for a memory transport listener).
    pub fn static_pub(&self) -> Vec<u8> {
        self.key.public.clone()
    }

    /// Serves one pairing connection from the scanned `qr` string.
    pub fn pair_over(&self, mut pipe: Box<dyn Pipe>, qr: &str, now: u64) -> Result<(), String> {
        let (sign_pub, ecdh_pub) = self.public_keys()?;
        let mut session = PairingSession::start(
            qr.to_string(),
            self.key.clone(),
            self.name.clone(),
            sign_pub,
            ecdh_pub,
            now,
        )?;
        while !session.is_done() {
            let frame = pipe.recv().map_err(err)?;
            for out in session.handle_frame(frame)? {
                pipe.send(&out).map_err(err)?;
            }
        }
        *self.desktop.lock().map_err(err)? = session.result();
        Ok(())
    }

    /// Serves one session connection until the desktop hangs up.
    pub fn serve(&self, mut pipe: Box<dyn Pipe>) -> Result<(), String> {
        let desktop = self
            .desktop
            .lock()
            .map_err(err)?
            .clone()
            .ok_or("not paired")?;
        let mut link = LinkSession::start(
            self.key.clone(),
            desktop.desktop_static_pub,
            desktop.vault_id,
        )?;
        let id = self.device_id()?;
        loop {
            let frame = match pipe.recv() {
                Ok(f) => f,
                Err(vahta_link::LinkError::Closed) => return Ok(()),
                Err(e) => return Err(err(e)),
            };
            let out = link.handle_frame(frame)?;
            for f in &out.frames {
                pipe.send(f).map_err(err)?;
            }
            let (kind, request) = match &out.event {
                LinkEvent::Approve(a) => ("approve", a.request.clone()),
                LinkEvent::Unlock { request, .. } => ("unlock", request.clone()),
                _ => continue,
            };
            if let Ok(mut asked) = self.asked.lock() {
                asked.push(Asked {
                    kind: kind.to_string(),
                    view: request_summary(request.clone())?,
                });
            }
            let behavior = self
                .behaviors
                .lock()
                .map_err(err)?
                .pop_front()
                .unwrap_or(Behavior::Ignore);
            let frames = match (behavior, &out.event) {
                (Behavior::Ignore, _) => continue,
                (Behavior::Deny, LinkEvent::Approve(a)) => {
                    link.reply_decision(a.request_hash.clone(), false, 0, vec![])?
                }
                (Behavior::Deny, _) => link.reply_unlock_denied()?,
                (Behavior::Approve(option), LinkEvent::Approve(a)) => {
                    let signature = self.sign_decision(&request, option, &id)?;
                    link.reply_decision(a.request_hash.clone(), true, option, signature)?
                }
                (Behavior::Approve(_), LinkEvent::Unlock { eph_pub, .. }) => {
                    let signature = self.sign_decision(&request, 0, &id)?;
                    link.reply_unlock_ok(self.ecdh_with(eph_pub)?, signature)?
                }
                _ => continue,
            };
            for f in &frames {
                pipe.send(f).map_err(err)?;
            }
        }
    }

    /// Keystore signing: SHA256withECDSA over the helper's bytes, DER, then
    /// the helper turns it into r then s.
    fn sign_decision(&self, request: &[u8], option: u8, id: &[u8]) -> Result<Vec<u8>, String> {
        let message = decision_message(request.to_vec(), option, id.to_vec())?;
        let sig: p256::ecdsa::Signature = self.sign.sign(&message);
        signature_from_der(sig.to_der().as_bytes().to_vec())
    }

    /// Keystore key agreement with the desktop's ephemeral key.
    fn ecdh_with(&self, eph_pub: &[u8]) -> Result<Vec<u8>, String> {
        let theirs = p256::PublicKey::from_sec1_bytes(eph_pub).map_err(err)?;
        let shared = p256::ecdh::diffie_hellman(self.ecdh.to_nonzero_scalar(), theirs.as_affine());
        Ok(shared.raw_secret_bytes().to_vec())
    }
}
