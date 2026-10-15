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

#[cfg(feature = "fake-phone")]
pub mod fake;

use vahta_auth::{Action, Request};
use vahta_link::channel::{Channel, Handshake, Keypair, Partial};
use vahta_link::messages::{
    Choice, Decision, UnlockResponse, ble_service_data, device_tag as link_device_tag, pairing_tag,
    tag_hex,
};
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
    /// The desktop asks the phone to approve `request` and, once the person
    /// has, to do the Keystore ECDH with `eph_pub`. Answer with
    /// `reply_unlock_ok` (shared secret plus the signature of the decision on
    /// `request`, option 0), `reply_unlock_denied` or `reply_unlock_error`.
    Unlock {
        slot_id: Vec<u8>,
        eph_pub: Vec<u8>,
        /// The structured request, as for `Approve`; pass it to
        /// `request_summary` and `decision_message`.
        request: Vec<u8>,
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
                    Some(Message::ApproveRequest(r)) => {
                        // What the person will be shown must be what the
                        // envelope says: refuse a request that does not parse
                        // or whose nonce and expiry differ from the envelope.
                        let req = parse_request(&r.request)?;
                        if req.nonce != r.nonce || req.expires_at != r.expires_at {
                            return Err("the request does not match its envelope".into());
                        }
                        LinkEvent::Approve(ApprovalRequest {
                            request: r.request,
                            request_hash: r.request_hash.to_vec(),
                            nonce: r.nonce.to_vec(),
                            expires_at: r.expires_at,
                        })
                    }
                    Some(Message::UnlockRequest(u)) => {
                        parse_request(&u.request)?;
                        LinkEvent::Unlock {
                            slot_id: u.slot_id,
                            eph_pub: u.eph_pub,
                            request: u.request,
                        }
                    }
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

    /// Answers an approval. `request_hash` is the event's; `option` is the
    /// index the person chose among the request's options and `signature` the
    /// 64-byte (r then s) Keystore signature over
    /// `decision_message(request, option, device_id)`. For a deny, `approve`
    /// is false and both are ignored.
    pub fn reply_decision(
        &mut self,
        request_hash: Vec<u8>,
        approve: bool,
        option: u8,
        signature: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, String> {
        let (option, signature) = if approve {
            arr::<64>(&signature, "the signature")?;
            (option, signature)
        } else {
            (0, Vec::new())
        };
        self.seal(Message::Decision(Decision {
            request_hash: arr(&request_hash, "request hash")?,
            choice: if approve {
                Choice::Approve
            } else {
                Choice::Deny
            },
            option,
            signature,
        }))
    }

    /// Answers an unlock request: `ecdh_result` is the Keystore's 32-byte ECDH
    /// output with the event's `eph_pub`; `signature` is the 64-byte (r then
    /// s) signature over `decision_message(request, 0, device_id)`. Both come
    /// from one biometric prompt.
    pub fn reply_unlock_ok(
        &mut self,
        ecdh_result: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, String> {
        arr::<32>(&ecdh_result, "the ECDH result")?;
        arr::<64>(&signature, "the signature")?;
        self.seal(Message::UnlockResponse(UnlockResponse::Approved {
            shared: ecdh_result,
            signature,
        }))
    }

    /// The person said no to an unlock.
    pub fn reply_unlock_denied(&mut self) -> Result<Vec<Vec<u8>>, String> {
        self.seal(Message::UnlockResponse(UnlockResponse::Denied))
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

// --- Helpers for the Kotlin side --------------------------------------------------------------
//
// Kotlin only signs bytes and does ECDH. Everything about what is signed, how
// a request is read and what is advertised lives here.

fn parse_request(bytes: &[u8]) -> Result<Request, String> {
    Request::from_bytes(bytes).ok_or_else(|| "not a Vahta request".to_string())
}

/// The exact bytes the phone's Keystore signing key signs to answer
/// `request` with option `choice`: `"vahta/v1/decision" || request hash ||
/// choice || device_id` (the desktop's `Decision::sign` signs the same bytes:
/// both call `Request::decision_message`). Sign them with `SHA256withECDSA`
/// and give the result to `signature_from_der`. Refuses a `choice` the
/// request does not offer.
pub fn decision_message(
    request: Vec<u8>,
    choice: u8,
    device_id: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let req = parse_request(&request)?;
    if usize::from(choice) >= req.options.len().max(1) {
        return Err("the request has no such option".into());
    }
    Ok(req.decision_message(choice, &arr(&device_id, "device id")?))
}

/// A device's id from its two public keys (SEC1): the first 16 bytes of
/// `SHA-256("vahta/v1/device-id" || sign_pub || ecdh_pub)`. The desktop
/// derives the same id when pairing.
pub fn device_id(sign_pub: Vec<u8>, ecdh_pub: Vec<u8>) -> Vec<u8> {
    vahta_auth::device_id_for(&sign_pub, &ecdh_pub).to_vec()
}

/// Android's `Signature` (SHA256withECDSA) gives an ASN.1 DER signature; the
/// desktop wants the 64 bytes r then s. Rejects anything that is not one
/// valid DER signature.
pub fn signature_from_der(der: Vec<u8>) -> Result<Vec<u8>, String> {
    let sig = p256::ecdsa::Signature::from_der(&der).map_err(|_| "not a DER signature")?;
    Ok(sig.to_bytes().to_vec())
}

/// The SEC1 uncompressed point (65 bytes) inside the X.509
/// SubjectPublicKeyInfo that Android's `PublicKey.getEncoded()` gives for a
/// P-256 key. This is the form `PairingSession::start` wants for `sign_pub`
/// and `ecdh_pub`. Rejects any other curve or a point not on the curve.
pub fn sec1_from_spki(spki: Vec<u8>) -> Result<Vec<u8>, String> {
    // SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING 04 || x || y }
    const PREFIX: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    let point = spki
        .strip_prefix(&PREFIX)
        .filter(|p| p.len() == 65)
        .ok_or("not a P-256 public key")?;
    p256::PublicKey::from_sec1_bytes(point).map_err(|_| "not a point on P-256")?;
    Ok(point.to_vec())
}

/// The 8-byte tag a paired phone advertises: the first 8 bytes of
/// SHA-256(its static Noise public key). Same bytes as the mDNS instance name
/// in hex.
pub fn device_tag(static_pub: Vec<u8>) -> Result<Vec<u8>, String> {
    Ok(link_device_tag(&arr(&static_pub, "static key")?).to_vec())
}

/// What a phone advertises and how, so the desktop can find it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advert {
    /// Advertise the service `service_uuid` in the advertising packet, and
    /// `service_data` as service data under the same UUID in the scan
    /// response.
    pub service_uuid: String,
    pub service_data: Vec<u8>,
    /// The mDNS instance name for a `_vahta._tcp` registration of the LAN
    /// listener.
    pub lan_instance: String,
    /// The GATT characteristic the desktop writes frames to.
    pub write_characteristic: String,
    /// The GATT characteristic the phone notifies frames on.
    pub notify_characteristic: String,
}

fn advert(pairing: bool, tag: [u8; 8]) -> Advert {
    Advert {
        service_uuid: vahta_link::ble_frame::SERVICE_UUID.to_string(),
        service_data: ble_service_data(pairing, &tag),
        lan_instance: tag_hex(&tag),
        write_characteristic: vahta_link::ble_frame::WRITE_CHAR_UUID.to_string(),
        notify_characteristic: vahta_link::ble_frame::NOTIFY_CHAR_UUID.to_string(),
    }
}

/// The advertisement while waiting to be paired, from the scanned QR string
/// (the tag derives from the offer's one-time secret).
pub fn pairing_advert(qr: String) -> Result<Advert, String> {
    let offer = PairOffer::from_qr_string(&qr).map_err(e)?;
    Ok(advert(true, pairing_tag(&offer.psk)))
}

/// The advertisement of a paired phone.
pub fn session_advert(static_pub: Vec<u8>) -> Result<Advert, String> {
    Ok(advert(
        false,
        link_device_tag(&arr(&static_pub, "static key")?),
    ))
}

/// An approval request drawn for the person. Every string came from the
/// computer (names, project, command) or from the agent (`agent_label`,
/// which nobody verified); show the label marked as unverified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestView {
    /// What is being done: `unlock`, `run_each_use`, `run_ask`, `bind`,
    /// `http`, `add`, `reset`, `remove`, `reveal`, `copy`, `import`,
    /// `set_tier`, `hooks_pause`, `alarm_lock`, `extend`, `guard_choice`,
    /// `output_allow`, `devices`, `recover`, `other`.
    pub kind: String,
    /// The secret names it touches (never values).
    pub names: Vec<String>,
    pub project: String,
    /// The command, for `run_each_use` and `run_ask`.
    pub command: Option<String>,
    /// The host, for `http`.
    pub host: Option<String>,
    /// The reason the agent gave, for `run_ask` (unverified like the label).
    pub reason: Option<String>,
    /// The one text parameter of the other kinds: the import source, the
    /// session to extend, what is being chosen or managed.
    pub detail: Option<String>,
    /// A time in seconds: how long an unlock lasts (absent: until revoked),
    /// the pause for `hooks_pause`, the extension for `extend`.
    pub seconds: Option<u64>,
    /// The strictest category of the secrets involved.
    pub category: Option<String>,
    /// What the agent said it is for. Not verified.
    pub agent_label: Option<String>,
    /// Always false: a label comes from the agent. Present so the UI cannot
    /// forget to mark it.
    pub agent_label_verified: bool,
    /// The choices; the one tapped is the `option` of the reply.
    pub options: Vec<String>,
    pub expires_at: u64,
    pub nonce: Vec<u8>,
    pub vault_id: Vec<u8>,
}

/// Reads the request bytes of an `Approve` or `Unlock` event into what the
/// approval screen shows.
pub fn request_summary(request: Vec<u8>) -> Result<RequestView, String> {
    let req = parse_request(&request)?;
    let (mut command, mut host, mut reason, mut detail, mut seconds) =
        (None, None, None, None, None);
    match &req.action {
        Action::Unlock { duration_secs, .. } => seconds = *duration_secs,
        Action::RunEachUse { command: c, .. } => command = Some(c.clone()),
        Action::RunAsk {
            command: c,
            reason: r,
            ..
        } => {
            command = Some(c.clone());
            reason = r.clone();
        }
        Action::Http { host: h, .. } => host = Some(h.clone()),
        Action::Import { source } => detail = Some(source.clone()),
        Action::HooksPause { secs } => seconds = Some(*secs),
        Action::Extend { session, secs } => {
            detail = Some(session.clone());
            seconds = Some(*secs);
        }
        Action::GuardChoice { what } | Action::Devices { what } | Action::Other { what } => {
            detail = Some(what.clone());
        }
        Action::Remote { on } => {
            detail = Some(if *on {
                "let other projects use this vault".to_string()
            } else {
                "stop other projects using this vault".to_string()
            });
        }
        _ => {}
    }
    Ok(RequestView {
        kind: req.action.key().to_string(),
        names: req.action.names(),
        project: req.project.clone(),
        command,
        host,
        reason,
        detail,
        seconds,
        category: req.category.clone(),
        agent_label: req.agent_label.clone(),
        agent_label_verified: false,
        options: req.options.clone(),
        expires_at: req.expires_at,
        nonce: req.nonce.to_vec(),
        vault_id: req.vault_id.to_vec(),
    })
}
