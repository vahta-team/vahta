//! Import of ka vaults (KAM1 and KAM2), values only.
//!
//! This is the entry below format 1, not part of the upgrade chain: ka's files
//! are read here and their values land in a new vault through the ordinary
//! `Vault::import`. Roles, members and ACLs are not carried over.
//!
//! Layout (`<4sB16sQQ`, little endian): magic `KAM1` or `KAM2`, version byte
//! (1), a 16-byte salt, `opslimit`, `memlimit`; then a PyNaCl `SecretBox`
//! blob, nonce (24) then MAC and ciphertext. The key is libsodium's
//! `crypto_pwhash` Argon2id v1.3 with `t = opslimit`, `m = memlimit / 1024`
//! KiB and one lane. The plaintext is JSON, parsed with `vahta-json` because
//! the file is untrusted.
//!
//! * KAM1: `secrets` maps a name to its value.
//! * KAM2: `kam2.admin_box_sk` is a hex X25519 key and `secrets[name]` is
//!   `{ciphertext, wraps}`; the wrap for `kam2.admin_box_pk`, else any wrap,
//!   is a sealed box holding the data key, and the data key opens
//!   `ciphertext` (another `SecretBox`). The admin key is inside the password's
//!   box, so the password is enough.
//!
//! Errors name the problem, never a value.

use std::path::Path;

use crypto_box::SecretKey;
use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::{Nonce, XSalsa20Poly1305};
use vahta_json::Value;
use zeroize::Zeroizing;

use crate::{Error, SecretValue, crypto, hex_decode};

const HEADER_LEN: usize = 4 + 1 + 16 + 8 + 8;
const MAX_FILE: u64 = 16 * 1024 * 1024;
const NONCE: usize = 24;

fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn as_str(v: &Value) -> Option<&str> {
    match v {
        Value::Str(s) => Some(s),
        _ => None,
    }
}

fn secretbox_open(key: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if blob.len() < NONCE + 16 || key.len() != 32 {
        return Err(Error::Ka("the encrypted payload is too short"));
    }
    let cipher = XSalsa20Poly1305::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(&blob[..NONCE]), &blob[NONCE..])
        .map(Zeroizing::new)
        .map_err(|_| Error::Unlock)
}

/// Read the secrets of a ka vault with its password.
pub fn import_ka(path: &Path, pw: &[u8]) -> Result<Vec<(String, SecretValue)>, Error> {
    let io = |op, source| Error::Io {
        op,
        path: path.to_path_buf(),
        source,
    };
    let len = std::fs::metadata(path).map_err(|e| io("open", e))?.len();
    if len > MAX_FILE {
        return Err(Error::TooLarge);
    }
    let data = std::fs::read(path).map_err(|e| io("read", e))?;
    if data.len() < HEADER_LEN {
        return Err(Error::Ka("the file is too short"));
    }
    let magic = &data[..4];
    let kam2 = match magic {
        b"KAM1" => false,
        b"KAM2" => true,
        _ => return Err(Error::Ka("not a ka vault")),
    };
    if data[4] != 1 {
        return Err(Error::Ka("unsupported ka vault version"));
    }
    let salt = &data[5..21];
    let (mut ops, mut mem) = ([0u8; 8], [0u8; 8]);
    ops.copy_from_slice(&data[21..29]);
    mem.copy_from_slice(&data[29..37]);
    let (opslimit, memlimit) = (u64::from_le_bytes(ops), u64::from_le_bytes(mem));
    // A hostile header must not make this allocate or spin without bound.
    let m_kib = u32::try_from(memlimit / 1024).map_err(|_| Error::Ka("unreasonable KDF cost"))?;
    let t = u32::try_from(opslimit).map_err(|_| Error::Ka("unreasonable KDF cost"))?;
    if m_kib == 0 || t == 0 || m_kib > crypto::KDF_CEILING.m_kib || t > crypto::KDF_CEILING.t {
        return Err(Error::Ka("unreasonable KDF cost"));
    }

    let key = crypto::argon2id(pw, salt, m_kib, t, 1)?;
    let plain = secretbox_open(&*key, &data[HEADER_LEN..])?;
    let text = std::str::from_utf8(&plain).map_err(|_| Error::Ka("the payload is not UTF-8"))?;
    let payload = vahta_json::parse_bounded(text, 64)
        .map_err(|_| Error::Ka("the payload is not valid JSON"))?;
    let Some(Value::Object(secrets)) = get(&payload, "secrets") else {
        return Err(Error::Ka("the payload has no secrets"));
    };

    let mut out = Vec::with_capacity(secrets.len());
    if !kam2 {
        for (name, value) in secrets {
            let Value::Str(value) = value else {
                return Err(Error::Ka("a secret is not a string"));
            };
            out.push((name.clone(), SecretValue::new(value.as_bytes().to_vec())));
        }
        return Ok(out);
    }

    let meta = get(&payload, "kam2").ok_or(Error::Ka("the payload has no kam2 section"))?;
    let admin_sk = get(meta, "admin_box_sk")
        .and_then(as_str)
        .and_then(hex_decode)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .map(Zeroizing::new)
        .ok_or(Error::Ka("the admin key is missing or malformed"))?;
    let admin_pk = get(meta, "admin_box_pk").and_then(as_str);
    let sk = SecretKey::from_bytes(*admin_sk);
    for (name, entry) in secrets {
        let Some(Value::Object(wraps)) = get(entry, "wraps") else {
            return Err(Error::Ka("a secret has no wraps"));
        };
        let ciphertext = get(entry, "ciphertext")
            .and_then(as_str)
            .and_then(hex_decode)
            .ok_or(Error::Ka("a secret has no ciphertext"))?;
        // The wrap for the admin key first, then any wrap that opens.
        let preferred = admin_pk.and_then(|pk| wraps.iter().find(|(id, _)| id == pk));
        let candidates = preferred
            .into_iter()
            .chain(wraps.iter().filter(|(id, _)| Some(id.as_str()) != admin_pk));
        let mut data_key = None;
        for (_, wrap) in candidates {
            let Some(bytes) = as_str(wrap).and_then(hex_decode) else {
                continue;
            };
            if let Ok(k) = sk.unseal(&bytes) {
                data_key = Some(Zeroizing::new(k));
                break;
            }
        }
        let data_key = data_key.ok_or(Error::Ka("no wrap of a secret opens"))?;
        let value = secretbox_open(&data_key, &ciphertext)?;
        out.push((name.clone(), SecretValue::from_zeroizing(value)));
    }
    Ok(out)
}
