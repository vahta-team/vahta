//! The message set: plain data, postcard on the wire, strict on the way in.
//! Nothing here decides anything about signatures or secrets; it carries
//! bytes. The structured approval request is defined elsewhere and travels as
//! opaque bytes plus its hash.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{LinkError, Result};

/// The wire version. A peer that sees another number refuses the message.
pub const VERSION: u8 = 1;

/// Most bytes in one encoded message (a bound on what a peer can make us hold).
pub const MAX_MESSAGE: usize = 1 << 20;

const OFFER_PREFIX: &str = "vahta-pair:";
const MAX_NAME: usize = 64;

fn bad(what: &str) -> LinkError {
    LinkError::Protocol(what.to_string())
}

/// Length of the tag a phone advertises so the desktop can tell it from other
/// Vahta phones.
pub const TAG_LEN: usize = 8;

/// The tag of a paired phone: the first 8 bytes of SHA-256 of its static
/// Noise public key. It is the BLE advertisement tag and, in hex, the mDNS
/// instance name. It names a device without carrying its key.
pub fn device_tag(phone_static_pub: &[u8; 32]) -> [u8; TAG_LEN] {
    let h = sha256(phone_static_pub);
    let mut t = [0u8; TAG_LEN];
    t.copy_from_slice(&h[..TAG_LEN]);
    t
}

/// The tag a phone advertises while it waits to be paired: the first 8 bytes
/// of `SHA-256("vahta/v1/pair-tag" || psk)`. Only someone who has seen the QR
/// code can compute it, and it reveals nothing of the PSK.
pub fn pairing_tag(psk: &[u8; 32]) -> [u8; TAG_LEN] {
    let mut h = Sha256::new();
    h.update(b"vahta/v1/pair-tag");
    h.update(psk);
    let h: [u8; 32] = h.finalize().into();
    let mut t = [0u8; TAG_LEN];
    t.copy_from_slice(&h[..TAG_LEN]);
    t
}

/// A tag as the lowercase hex used for the mDNS instance name.
pub fn tag_hex(tag: &[u8; TAG_LEN]) -> String {
    tag.iter().map(|b| format!("{b:02x}")).collect()
}

/// The BLE service data a phone advertises under the Vahta service UUID:
/// `[1 (format), kind (1 session, 2 pairing), tag (8 bytes)]`.
pub fn ble_service_data(pairing: bool, tag: &[u8; TAG_LEN]) -> Vec<u8> {
    let mut v = vec![1, if pairing { 2 } else { 1 }];
    v.extend_from_slice(tag);
    v
}

/// Reads [`ble_service_data`]: `(is pairing, tag)`. `None` for anything else
/// (another format version is ignored, not guessed at).
pub fn parse_ble_service_data(data: &[u8]) -> Option<(bool, [u8; TAG_LEN])> {
    let [1, kind @ (1 | 2), tag @ ..] = data else {
        return None;
    };
    Some((*kind == 2, tag.try_into().ok()?))
}

/// What the desktop shows as a QR code. The PSK is the one-time secret that
/// proves the phone saw the screen; it never travels over a transport.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairOffer {
    pub v: u8,
    pub desktop_static_pub: [u8; 32],
    pub psk: [u8; 32],
    pub vault_id: [u8; 16],
    pub desktop_name: String,
    /// Unix seconds.
    pub expires_at: u64,
}

impl Drop for PairOffer {
    fn drop(&mut self) {
        self.psk.zeroize();
    }
}

impl std::fmt::Debug for PairOffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairOffer")
            .field("desktop_name", &self.desktop_name)
            .field("expires_at", &self.expires_at)
            .field("psk", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl PairOffer {
    /// A fresh offer with a random PSK, good for `ttl_secs` from `now`.
    pub fn new(
        desktop_static_pub: [u8; 32],
        vault_id: [u8; 16],
        desktop_name: &str,
        now: u64,
        ttl_secs: u64,
    ) -> Result<Self> {
        let mut psk = [0u8; 32];
        crate::random_bytes(&mut psk)?;
        let offer = Self {
            v: VERSION,
            desktop_static_pub,
            psk,
            vault_id,
            desktop_name: desktop_name.to_string(),
            expires_at: now.saturating_add(ttl_secs),
        };
        offer.validate()?;
        Ok(offer)
    }

    fn validate(&self) -> Result<()> {
        if self.v != VERSION {
            return Err(LinkError::OfferInvalid(format!("version {}", self.v)));
        }
        if self.desktop_name.len() > MAX_NAME {
            return Err(LinkError::OfferInvalid("name too long".into()));
        }
        Ok(())
    }

    /// Refuses an offer that is past its time.
    pub fn check_fresh(&self, now: u64) -> Result<()> {
        self.validate()?;
        if now > self.expires_at {
            return Err(LinkError::OfferExpired);
        }
        Ok(())
    }

    /// `vahta-pair:` plus base64url (no padding) of the postcard bytes.
    pub fn to_qr_string(&self) -> String {
        let bytes = postcard::to_allocvec(self).expect("offer encodes");
        format!("{OFFER_PREFIX}{}", b64_encode(&bytes))
    }

    pub fn from_qr_string(s: &str) -> Result<Self> {
        let body = s
            .trim()
            .strip_prefix(OFFER_PREFIX)
            .ok_or_else(|| LinkError::OfferInvalid("not a Vahta pairing code".into()))?;
        let bytes = b64_decode(body).ok_or_else(|| LinkError::OfferInvalid("bad base64".into()))?;
        let offer: Self =
            decode_exact(&bytes).map_err(|e| LinkError::OfferInvalid(e.to_string()))?;
        offer.validate()?;
        Ok(offer)
    }
}

/// The phone's answer: its name, its channel key and the two P-256 public keys
/// (SEC1 bytes) its Keystore holds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairAccept {
    pub phone_name: String,
    pub phone_static_pub: [u8; 32],
    pub sign_pub: Vec<u8>,
    pub ecdh_pub: Vec<u8>,
}

/// Whether `b` has the shape of a SEC1 P-256 point (uncompressed or compressed).
pub fn looks_like_sec1_p256(b: &[u8]) -> bool {
    (b.len() == 65 && b[0] == 4) || (b.len() == 33 && (b[0] == 2 || b[0] == 3))
}

impl PairAccept {
    fn validate(&self) -> Result<()> {
        if self.phone_name.len() > MAX_NAME {
            return Err(bad("phone name too long"));
        }
        if !looks_like_sec1_p256(&self.sign_pub) || !looks_like_sec1_p256(&self.ecdh_pub) {
            return Err(bad("public key is not SEC1 P-256"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApproveRequest {
    /// The structured request, opaque here.
    pub request: Vec<u8>,
    /// SHA-256 of `request`; what a `Decision` answers.
    pub request_hash: [u8; 32],
    pub nonce: [u8; 16],
    pub expires_at: u64,
}

impl ApproveRequest {
    pub fn new(request: Vec<u8>, nonce: [u8; 16], expires_at: u64) -> Self {
        let request_hash = sha256(&request);
        Self {
            request,
            request_hash,
            nonce,
            expires_at,
        }
    }

    fn validate(&self) -> Result<()> {
        if sha256(&self.request) != self.request_hash {
            return Err(bad("request hash does not match the request"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Choice {
    Approve,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    /// SHA-256 of the `ApproveRequest::request` bytes (the link-level hash,
    /// not the domain-separated one the signature covers).
    pub request_hash: [u8; 32],
    pub choice: Choice,
    /// Which of the request's options was chosen (what the signature covers);
    /// 0 on a deny.
    pub option: u8,
    /// Made by the phone's Keystore key, 64 bytes (r then s); opaque here.
    /// Empty on a deny.
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnlockRequest {
    pub slot_id: Vec<u8>,
    /// The desktop's ephemeral P-256 public key (SEC1).
    pub eph_pub: Vec<u8>,
    /// The structured request the person is asked to approve with the unlock
    /// (opaque here), so one biometric prompt both approves and opens.
    pub request: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum UnlockResponse {
    /// The person approved: the ECDH result of the phone's Keystore key with
    /// `eph_pub`, and the signature of the decision (option 0) on `request`.
    Approved {
        shared: Vec<u8>,
        signature: Vec<u8>,
    },
    /// The person said no.
    Denied,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Message {
    PairAccept(PairAccept),
    PairAck,
    ApproveRequest(ApproveRequest),
    Decision(Decision),
    UnlockRequest(UnlockRequest),
    UnlockResponse(UnlockResponse),
    Ping(u64),
    Pong(u64),
}

impl Message {
    /// `[VERSION]` then postcard.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION];
        out.extend(postcard::to_allocvec(self).expect("message encodes"));
        out
    }

    /// Strict: the version must match, the bytes must be exactly one message
    /// (nothing left over), and the contents must have the right shape.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_MESSAGE {
            return Err(bad("message too large"));
        }
        let (&v, rest) = bytes.split_first().ok_or_else(|| bad("empty message"))?;
        if v != VERSION {
            return Err(bad("unsupported message version"));
        }
        let msg: Message = decode_exact(rest)?;
        match &msg {
            Message::PairAccept(a) => a.validate()?,
            Message::ApproveRequest(r) => r.validate()?,
            Message::UnlockRequest(u)
                if u.slot_id.len() > 64
                    || !looks_like_sec1_p256(&u.eph_pub)
                    || u.request.is_empty() =>
            {
                return Err(bad("malformed unlock request"));
            }
            Message::Decision(d) if d.choice == Choice::Approve && d.signature.len() != 64 => {
                return Err(bad("malformed decision"));
            }
            Message::UnlockResponse(UnlockResponse::Approved { shared, signature })
                if shared.len() != 32 || signature.len() != 64 =>
            {
                return Err(bad("malformed unlock response"));
            }
            _ => {}
        }
        Ok(msg)
    }
}

fn decode_exact<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let (v, rest) = postcard::take_from_bytes::<T>(bytes).map_err(|e| bad(&e.to_string()))?;
    if !rest.is_empty() {
        return Err(bad("trailing bytes"));
    }
    Ok(v)
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..=c.len() {
            out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for ch in s.bytes() {
        let v = B64.iter().position(|&c| c == ch)? as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Canonical only: a 1-char tail is impossible and leftover bits must be 0.
    if s.len() % 4 == 1 || acc != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> PairOffer {
        PairOffer::new([7; 32], [9; 16], "laptop", 1000, 120).unwrap()
    }

    #[test]
    fn b64_round_trips_all_tail_lengths() {
        for n in 0..40 {
            let data: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(b64_decode(&b64_encode(&data)).unwrap(), data, "len {n}");
        }
        assert_eq!(b64_encode(&[0xfb, 0xff]), "-_8");
        assert!(b64_decode("A").is_none());
        assert!(b64_decode("a=").is_none());
        assert!(b64_decode("AB").is_none(), "non-canonical trailing bits");
    }

    #[test]
    fn offer_round_trips_through_the_qr_string() {
        let o = offer();
        let s = o.to_qr_string();
        assert!(s.starts_with("vahta-pair:"));
        assert!(s.len() < 200, "stays QR-friendly: {}", s.len());
        assert_eq!(PairOffer::from_qr_string(&s).unwrap(), o);
        assert!(PairOffer::from_qr_string("vahta-pair:").is_err());
        assert!(PairOffer::from_qr_string("other:AAAA").is_err());
        assert!(!format!("{o:?}").contains("psk: ["));
    }

    #[test]
    fn offer_expiry() {
        let o = offer();
        assert!(o.check_fresh(1120).is_ok());
        assert!(matches!(o.check_fresh(1121), Err(LinkError::OfferExpired)));
    }

    #[test]
    fn offer_with_wrong_version_or_trailing_bytes_is_refused() {
        let mut o = offer();
        o.v = 2;
        let s = o.to_qr_string();
        assert!(PairOffer::from_qr_string(&s).is_err());
        let o = offer();
        let mut bytes = postcard::to_allocvec(&o).unwrap();
        bytes.push(0);
        let s = format!("vahta-pair:{}", b64_encode(&bytes));
        assert!(PairOffer::from_qr_string(&s).is_err());
    }

    #[test]
    fn messages_round_trip() {
        let msgs = vec![
            Message::Ping(5),
            Message::PairAck,
            Message::ApproveRequest(ApproveRequest::new(b"run curl".to_vec(), [1; 16], 99)),
            Message::Decision(Decision {
                request_hash: [3; 32],
                choice: Choice::Approve,
                option: 1,
                signature: vec![1; 64],
            }),
            Message::Decision(Decision {
                request_hash: [3; 32],
                choice: Choice::Deny,
                option: 0,
                signature: vec![],
            }),
            Message::UnlockRequest(UnlockRequest {
                slot_id: vec![1; 16],
                eph_pub: [&[4u8][..], &[1; 64]].concat(),
                request: b"req".to_vec(),
            }),
            Message::UnlockResponse(UnlockResponse::Approved {
                shared: vec![5; 32],
                signature: vec![6; 64],
            }),
            Message::UnlockResponse(UnlockResponse::Denied),
            Message::UnlockResponse(UnlockResponse::Error("no".into())),
        ];
        for m in msgs {
            assert_eq!(Message::decode(&m.encode()).unwrap(), m);
        }
    }

    #[test]
    fn strict_decoding() {
        let m = Message::Ping(1).encode();
        let mut long = m.clone();
        long.push(0);
        assert!(Message::decode(&long).is_err(), "trailing byte");
        let mut v2 = m.clone();
        v2[0] = 2;
        assert!(Message::decode(&v2).is_err(), "version");
        assert!(Message::decode(&[]).is_err());
        assert!(Message::decode(&[VERSION, 200]).is_err(), "unknown variant");
        let mut r = ApproveRequest::new(b"x".to_vec(), [0; 16], 1);
        r.request_hash[0] ^= 1;
        assert!(Message::decode(&Message::ApproveRequest(r).encode()).is_err());
        let bad_key = Message::PairAccept(PairAccept {
            phone_name: "p".into(),
            phone_static_pub: [0; 32],
            sign_pub: vec![1; 10],
            ecdh_pub: vec![4; 65],
        });
        assert!(Message::decode(&bad_key.encode()).is_err());
        let short_sig = Message::Decision(Decision {
            request_hash: [0; 32],
            choice: Choice::Approve,
            option: 0,
            signature: vec![1; 10],
        });
        assert!(Message::decode(&short_sig.encode()).is_err());
        let short_shared = Message::UnlockResponse(UnlockResponse::Approved {
            shared: vec![1; 31],
            signature: vec![1; 64],
        });
        assert!(Message::decode(&short_shared.encode()).is_err());
    }
}
