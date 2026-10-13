//! The phone side of the Vahta link protocol, shaped to be wrapped by
//! flutter_rust_bridge: plain structs, `Vec<u8>`, `String`, no traits and no
//! callbacks across the boundary.
//!
//! The crate does no I/O and holds no keys. The app owns the Bluetooth GATT
//! server and the TCP/mDNS listener (Kotlin), hands every frame it receives to
//! `handle_frame`, and sends the frames that come back. Android Keystore work
//! (the P-256 signing key, the ECDH key, biometrics) stays on the Kotlin side:
//! public keys go in as bytes when pairing; signatures and ECDH results come
//! back in as bytes from the app.
//!
//! Errors are `String`s: the bridge turns them into exceptions.

use vahta_link::channel::{Channel, Handshake, Keypair, Partial};
use vahta_link::messages::{Choice, Decision, UnlockResponse};
use vahta_link::pairing::PairResponder;
use vahta_link::{Message, PairAccept, PairOffer};

fn e(err: vahta_link::LinkError) -> String {
    err.to_string()
}

fn arr<const N: usize>(b: &[u8], what: &str) -> Result<[u8; N], String> {
    b.try_into()
        .map_err(|_| format!("{what} must be {N} bytes"))
}

/// The phone's X25519 channel key. The app stores it (in encrypted storage).
#[derive(Debug, Clone)]
pub struct StaticKey {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

impl StaticKey {
    fn to_keypair(&self) -> Result<Keypair, String> {
        Keypair::from_parts(&self.public, &self.private).map_err(e)
    }
}

pub fn generate_static_key() -> Result<StaticKey, String> {
    let k = Keypair::generate().map_err(e)?;
    Ok(StaticKey {
        public: k.public.to_vec(),
        private: k.private.to_vec(),
    })
}

/// What a scanned QR code says, for the confirmation screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedOffer {
    pub desktop_name: String,
    pub desktop_static_pub: Vec<u8>,
    pub vault_id: Vec<u8>,
    pub expires_at: u64,
}

/// Parses and checks a scanned `vahta-pair:` string. `now` is Unix seconds.
pub fn parse_offer(qr: String, now: u64) -> Result<ScannedOffer, String> {
    let o = PairOffer::from_qr_string(&qr).map_err(e)?;
    o.check_fresh(now).map_err(e)?;
    Ok(ScannedOffer {
        desktop_name: o.desktop_name.clone(),
        desktop_static_pub: o.desktop_static_pub.to_vec(),
        vault_id: o.vault_id.to_vec(),
        expires_at: o.expires_at,
    })
}

/// Who the phone paired with; the app stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedDesktop {
    pub desktop_name: String,
    pub desktop_static_pub: Vec<u8>,
    pub vault_id: Vec<u8>,
}

/// Pairing in progress. The desktop connects to the phone's GATT server (or
/// TCP listener); every frame it sends goes to `handle_frame`.
pub struct PairingSession {
    inner: PairResponder,
}

impl PairingSession {
    /// `sign_pub` and `ecdh_pub` are the Keystore public keys, SEC1 P-256.
    pub fn start(
        qr: String,
        key: StaticKey,
        phone_name: String,
        sign_pub: Vec<u8>,
        ecdh_pub: Vec<u8>,
        now: u64,
    ) -> Result<PairingSession, String> {
        let offer = PairOffer::from_qr_string(&qr).map_err(e)?;
        let accept = PairAccept {
            phone_name,
            phone_static_pub: [0; 32],
            sign_pub,
            ecdh_pub,
        };
        let inner = PairResponder::new(offer, &key.to_keypair()?, accept, now).map_err(e)?;
        Ok(PairingSession { inner })
    }

    /// Feeds one received frame; returns frames to send back, in order.
    pub fn handle_frame(&mut self, frame: Vec<u8>) -> Result<Vec<Vec<u8>>, String> {
        self.inner.on_frame(&frame).map_err(e)
    }

    pub fn is_done(&self) -> bool {
        self.inner.is_done()
    }

    /// Set once done.
    pub fn result(&self) -> Option<PairedDesktop> {
        self.inner.result().map(|p| PairedDesktop {
            desktop_name: p.desktop_name,
            desktop_static_pub: p.desktop_static_pub.to_vec(),
            vault_id: p.vault_id.to_vec(),
        })
    }
}

/// A request the desktop wants approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// The structured request, opaque to this crate.
    pub request: Vec<u8>,
    pub request_hash: Vec<u8>,
    pub nonce: Vec<u8>,
    pub expires_at: u64,
}

/// What a received frame turned into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkEvent {
    /// Nothing for the app yet (handshake step, or a fragment of a message).
    None,
    Approve(ApprovalRequest),
    /// The desktop asks the phone to do the Keystore ECDH with `eph_pub`.
    Unlock {
        slot_id: Vec<u8>,
        eph_pub: Vec<u8>,
    },
    /// Already answered by the session; reported for the UI's liveness.
    Ping,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkOutput {
    /// Frames to send, in order.
    pub frames: Vec<Vec<u8>>,
    pub event: LinkEvent,
}

enum Stage {
    Handshake(Box<Handshake>),
    Open(Box<Channel>),
    Dead,
}

/// A pinned session (`Noise_KK`) with the paired desktop.
pub struct LinkSession {
    stage: Stage,
    partial: Partial,
}

impl LinkSession {
    pub fn start(
        key: StaticKey,
        desktop_static_pub: Vec<u8>,
        vault_id: Vec<u8>,
    ) -> Result<LinkSession, String> {
        let hs = Handshake::session_responder(
            &key.to_keypair()?,
            &arr(&desktop_static_pub, "desktop key")?,
            &arr(&vault_id, "vault id")?,
        )
        .map_err(e)?;
        Ok(LinkSession {
            stage: Stage::Handshake(Box::new(hs)),
            partial: Partial::default(),
        })
    }

    pub fn is_established(&self) -> bool {
        matches!(self.stage, Stage::Open(_))
    }

    /// Feeds one received frame. Any error ends the session: drop it and wait
    /// for the desktop to connect again.
    pub fn handle_frame(&mut self, frame: Vec<u8>) -> Result<LinkOutput, String> {
        let r = self.step(&frame);
        if r.is_err() {
            self.stage = Stage::Dead;
        }
        r
    }

    fn step(&mut self, frame: &[u8]) -> Result<LinkOutput, String> {
        match std::mem::replace(&mut self.stage, Stage::Dead) {
            Stage::Handshake(mut hs) => {
                hs.read(frame).map_err(e)?;
                let mut frames = Vec::new();
                while !hs.is_finished() && hs.is_my_turn() {
                    frames.push(hs.write().map_err(e)?);
                }
                self.stage = if hs.is_finished() {
                    Stage::Open(Box::new(hs.finish().map_err(e)?))
                } else {
                    Stage::Handshake(hs)
                };
                Ok(LinkOutput {
                    frames,
                    event: LinkEvent::None,
                })
            }
            Stage::Open(mut ch) => {
                let msg = ch.open_message(&mut self.partial, frame).map_err(e)?;
                let mut frames = Vec::new();
                let event = match msg {
                    None => LinkEvent::None,
                    Some(Message::Ping(n)) => {
                        frames = ch.seal_message(&Message::Pong(n)).map_err(e)?;
                        LinkEvent::Ping
                    }
                    Some(Message::ApproveRequest(r)) => LinkEvent::Approve(ApprovalRequest {
                        request: r.request,
                        request_hash: r.request_hash.to_vec(),
                        nonce: r.nonce.to_vec(),
                        expires_at: r.expires_at,
                    }),
                    Some(Message::UnlockRequest(u)) => LinkEvent::Unlock {
                        slot_id: u.slot_id,
                        eph_pub: u.eph_pub,
                    },
                    Some(_) => return Err("unexpected message from the desktop".into()),
                };
                self.stage = Stage::Open(ch);
                Ok(LinkOutput { frames, event })
            }
            Stage::Dead => Err("session is over".into()),
        }
    }

    fn seal(&mut self, m: Message) -> Result<Vec<Vec<u8>>, String> {
        match &mut self.stage {
            Stage::Open(ch) => ch.seal_message(&m).map_err(e),
            _ => Err("session is not established".into()),
        }
    }

    /// Answers an approval. `signature` is the Keystore's, over whatever the
    /// app and the desktop agreed to sign; empty for a deny.
    pub fn reply_decision(
        &mut self,
        request_hash: Vec<u8>,
        approve: bool,
        signature: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, String> {
        self.seal(Message::Decision(Decision {
            request_hash: arr(&request_hash, "request hash")?,
            choice: if approve {
                Choice::Approve
            } else {
                Choice::Deny
            },
            signature,
        }))
    }

    /// Answers an unlock request with the Keystore's ECDH output.
    pub fn reply_unlock_ok(&mut self, ecdh_result: Vec<u8>) -> Result<Vec<Vec<u8>>, String> {
        self.seal(Message::UnlockResponse(UnlockResponse::SharedSecret(
            ecdh_result,
        )))
    }

    /// Declines an unlock request (biometrics failed, slot unknown).
    pub fn reply_unlock_error(&mut self, reason: String) -> Result<Vec<Vec<u8>>, String> {
        self.seal(Message::UnlockResponse(UnlockResponse::Error(reason)))
    }
}

/// Cuts a frame into BLE notification chunks (`chunk_len` is MTU minus 3).
pub fn ble_chunks(frame: Vec<u8>, chunk_len: u32) -> Result<Vec<Vec<u8>>, String> {
    vahta_link::ble_frame::chunk_frame(&frame, chunk_len as usize).map_err(e)
}

/// Puts BLE chunks (from GATT writes) back into frames.
#[derive(Default)]
pub struct BleReassembler {
    inner: vahta_link::ble_frame::Reassembler,
}

impl BleReassembler {
    pub fn new() -> BleReassembler {
        BleReassembler::default()
    }

    pub fn push(&mut self, chunk: Vec<u8>) -> Vec<Vec<u8>> {
        self.inner.push(&chunk)
    }
}
