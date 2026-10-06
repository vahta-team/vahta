//! Thin wrappers over the RustCrypto primitives the format uses.
//!
//! The rest of the crate never names `argon2`, `chacha20poly1305`, `hpke` or
//! `ed25519_dalek` directly, so a primitive can be swapped in one file and the
//! algorithms of format 1 are visible in one place: Argon2id for the password,
//! HKDF-SHA256 for derivations, XChaCha20-Poly1305 for every symmetric
//! encryption, HPKE (RFC 9180, base mode, DHKEM X25519 / HKDF-SHA256 /
//! ChaCha20-Poly1305) for wraps to recipients and Ed25519 for signatures.
//!
//! Nothing here logs or formats a key or a value, and every failure is an
//! [`Error`] that says what step failed, never what it was holding.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hpke::aead::ChaCha20Poly1305 as HpkeAead;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use rand_core::{CryptoRng, OsRng, RngCore, TryRngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::Error;

type Kem = X25519HkdfSha256;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
/// The smallest padded plaintext of a secret, in bytes.
pub const MIN_PADDED: usize = 64;
/// The largest value a secret may hold. Large enough for a certificate or a
/// service-account file, small enough that padding to a power of two stays
/// well inside the 16 MiB file limit.
pub const MAX_VALUE: usize = 1 << 20;

/// Argon2id cost: memory in KiB, passes, lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// What a vault is created with: 1 GiB, four passes, one lane.
    pub const PRODUCTION: KdfParams = KdfParams {
        m_kib: 1_048_576,
        t: 4,
        p: 1,
    };

    /// A cost small enough for tests. Not available in a shipped build.
    #[cfg(any(test, feature = "test-kdf"))]
    pub const TEST: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };

    /// Whether `self` is at least as expensive as `floor` in every part.
    pub fn meets(&self, floor: &KdfParams) -> bool {
        self.m_kib >= floor.m_kib && self.t >= floor.t && self.p >= floor.p
    }
}

/// The cheapest cost this build accepts, on create and on unlock. A release
/// build has only the production floor; the test build lowers it so a unit
/// test does not need a gigabyte, and the floor itself is tested through
/// [`KdfParams::meets`] against [`KdfParams::PRODUCTION`].
pub fn kdf_floor() -> KdfParams {
    #[cfg(any(test, feature = "test-kdf"))]
    {
        KdfParams {
            m_kib: 8,
            t: 1,
            p: 1,
        }
    }
    #[cfg(not(any(test, feature = "test-kdf")))]
    {
        KdfParams::PRODUCTION
    }
}

/// The most a file may ask a reader to spend, so a hostile file cannot make
/// an unlock allocate without bound.
pub const KDF_CEILING: KdfParams = KdfParams {
    m_kib: 4 * 1_048_576,
    t: 32,
    p: 16,
};

/// Random bytes drawn up front, so that a primitive that wants an `RngCore`
/// (HPKE's ephemeral key) can be fed from the system generator while a failure
/// of that generator is still an `Error` here and never a panic there.
struct Pool {
    bytes: Zeroizing<[u8; 128]>,
    pos: usize,
}

impl Pool {
    fn new() -> Result<Pool, Error> {
        Ok(Pool {
            bytes: Zeroizing::new(random::<128>()?),
            pos: 0,
        })
    }
}

impl RngCore for Pool {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        // HPKE X25519 asks for 32 bytes once. If a primitive ever asks for
        // more than the pool holds, stopping is safer than reusing bytes.
        let end = self.pos + dst.len();
        assert!(end <= self.bytes.len(), "random pool exhausted");
        dst.copy_from_slice(&self.bytes[self.pos..end]);
        self.pos = end;
    }
}

impl CryptoRng for Pool {}

pub fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    OsRng.try_fill_bytes(&mut out).map_err(|_| Error::Rng)?;
    Ok(out)
}

/// Argon2id v0x13 of `password` under `salt`, as a 32-byte key.
pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let params = Params::new(m_kib, t, p, Some(KEY_LEN)).map_err(|_| Error::Corrupt("kdf"))?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, &mut *out)
        .map_err(|_| Error::Corrupt("kdf"))?;
    Ok(out)
}

/// HKDF-SHA256 with no salt: `ikm` is already full-entropy key material.
pub fn hkdf(ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    // A 32-byte output is far below the 255 * 32 limit, so this cannot fail.
    let _ = Hkdf::<Sha256>::new(None, ikm).expand(info, &mut *out);
    out
}

/// XChaCha20-Poly1305 under `key` with a fresh random nonce.
pub fn seal(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), Error> {
    let nonce = random::<NONCE_LEN>()?;
    let ct = XChaCha20Poly1305::new(key.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Corrupt("encrypt"))?;
    Ok((nonce, ct))
}

/// The inverse of [`seal`]. A wrong key, a wrong AAD and a changed byte are
/// the same failure on purpose.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Unlock)
}

/// The padded length of a plaintext of `len` value bytes: the 4-byte length
/// prefix and the value, rounded up to the next power of two, at least 64.
pub fn padded_len(len: usize) -> usize {
    (len + 4).next_power_of_two().max(MIN_PADDED)
}

/// `u32 length ‖ value ‖ zeros`, so the ciphertext length says only which
/// power of two the value fits in.
pub fn pad(value: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if value.len() > MAX_VALUE {
        return Err(Error::ValueTooLarge);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(padded_len(value.len())));
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
    out.resize(padded_len(value.len()), 0);
    Ok(out)
}

/// Undo [`pad`], strictly: the length must be one `pad` would have produced
/// for that value, and every padding byte must be zero.
pub fn unpad(plain: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let corrupt = Error::Corrupt("secret padding");
    let Some((head, rest)) = plain.split_first_chunk::<4>() else {
        return Err(corrupt);
    };
    let len = u32::from_le_bytes(*head) as usize;
    if len > rest.len() || len > MAX_VALUE || padded_len(len) != plain.len() {
        return Err(corrupt);
    }
    if rest[len..].iter().any(|&b| b != 0) {
        return Err(corrupt);
    }
    Ok(Zeroizing::new(rest[..len].to_vec()))
}

/// An X25519 key pair for HPKE, derived deterministically from 32 bytes.
pub fn enc_keypair_from_seed(seed: &[u8; KEY_LEN]) -> (Zeroizing<[u8; KEY_LEN]>, [u8; KEY_LEN]) {
    let (sk, pk) = Kem::derive_keypair(seed);
    (
        Zeroizing::new(to_array(&sk.to_bytes())),
        to_array(&pk.to_bytes()),
    )
}

/// The public half of an X25519 private key.
pub fn enc_public_from_secret(sk: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN], Error> {
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(sk).map_err(|_| Error::Unlock)?;
    Ok(to_array(&Kem::sk_to_pk(&sk).to_bytes()))
}

fn to_array(bytes: &[u8]) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(bytes);
    out
}

/// HPKE base mode to `recipient_pk`. Returns the encapsulated key and the
/// ciphertext (with its tag).
pub fn hpke_seal(
    recipient_pk: &[u8; KEY_LEN],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<([u8; KEY_LEN], Vec<u8>), Error> {
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(recipient_pk)
        .map_err(|_| Error::Corrupt("recipient key"))?;
    let (enc, ct) = hpke::single_shot_seal::<HpkeAead, HkdfSha256, Kem, _>(
        &OpModeS::Base,
        &pk,
        info,
        plaintext,
        aad,
        &mut Pool::new()?,
    )
    .map_err(|_| Error::Corrupt("recipient key"))?;
    Ok((to_array(&enc.to_bytes()), ct))
}

/// The inverse of [`hpke_seal`], with the recipient's private key.
pub fn hpke_open(
    recipient_sk: &[u8; KEY_LEN],
    enc: &[u8; KEY_LEN],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(recipient_sk).map_err(|_| Error::Unlock)?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(enc).map_err(|_| Error::Unlock)?;
    hpke::single_shot_open::<HpkeAead, HkdfSha256, Kem>(
        &OpModeR::Base,
        &sk,
        &encapped,
        info,
        ct,
        aad,
    )
    .map(Zeroizing::new)
    .map_err(|_| Error::Unlock)
}

/// An Ed25519 signing key from a 32-byte seed.
pub fn signing_key(seed: &[u8; KEY_LEN]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

pub fn sign(key: &SigningKey, message: &[u8]) -> [u8; 64] {
    key.sign(message).to_bytes()
}

/// Strict Ed25519 verification: a malformed key or signature is a failure,
/// not a panic and not a pass.
pub fn verify(pk: &[u8; KEY_LEN], message: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(pk) else {
        return false;
    };
    key.verify_strict(message, &Signature::from_bytes(sig))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_edges() {
        // 4 bytes of length prefix: 60 fills 64 exactly, 61 spills to 128.
        assert_eq!(padded_len(0), 64);
        assert_eq!(padded_len(60), 64);
        assert_eq!(padded_len(61), 128);
        assert_eq!(padded_len(64), 128);
        assert_eq!(padded_len(65), 128);
        for len in [0usize, 1, 10, 50, 59, 60, 61, 64, 65, 1000] {
            let value = vec![7u8; len];
            let padded = pad(&value).unwrap();
            assert_eq!(padded.len(), padded_len(len));
            assert_eq!(&**unpad(&padded).unwrap(), &value[..]);
        }
    }

    #[test]
    fn unpad_rejects_a_dirty_or_short_buffer() {
        let mut p = pad(b"fake-one").unwrap().to_vec();
        *p.last_mut().unwrap() = 1;
        assert!(unpad(&p).is_err());
        assert!(unpad(&[1, 2]).is_err());
        let mut long = 1000u32.to_le_bytes().to_vec();
        long.resize(64, 0);
        assert!(unpad(&long).is_err());
    }

    #[test]
    fn the_production_floor_is_a_gibibyte_four_passes() {
        let weak = KdfParams {
            m_kib: 1_048_575,
            ..KdfParams::PRODUCTION
        };
        assert!(KdfParams::PRODUCTION.meets(&KdfParams::PRODUCTION));
        assert!(!weak.meets(&KdfParams::PRODUCTION));
        assert!(
            !KdfParams {
                t: 3,
                ..KdfParams::PRODUCTION
            }
            .meets(&KdfParams::PRODUCTION)
        );
    }

    #[test]
    fn seal_open_round_trip_and_aad_binding() {
        let key = random::<32>().unwrap();
        let (nonce, ct) = seal(&key, b"aad", b"fake-one").unwrap();
        assert_eq!(&**open(&key, &nonce, b"aad", &ct).unwrap(), b"fake-one");
        assert!(open(&key, &nonce, b"other", &ct).is_err());
    }

    #[test]
    fn hpke_round_trip() {
        let seed = random::<32>().unwrap();
        let (sk, pk) = enc_keypair_from_seed(&seed);
        let (enc, ct) = hpke_seal(&pk, b"info", b"aad", b"fake-one").unwrap();
        assert_eq!(
            &**hpke_open(&sk, &enc, b"info", b"aad", &ct).unwrap(),
            b"fake-one"
        );
        assert!(hpke_open(&sk, &enc, b"info", b"nope", &ct).is_err());
    }
}
