//! A person's own key on their own machine: `identity.vht`.
//!
//! It holds a [`RecipientSecret`] sealed under the person's password, with the
//! public half beside it in the clear so that `vahta id --show` needs no
//! password. Layout (all integers little endian, the file is exactly this long):
//!
//! ```text
//! magic b"VAHTAIDN" (8) | version u16 (=1) | m_kib u32 | t u32 | p u32
//! | salt (16) | enc_pk (32) | sign_pk (32)          <- the header, 102 bytes
//! | nonce (24) | XChaCha20-Poly1305(enc_sk ‖ sign_sk) (64 + 16)
//! ```
//!
//! The key-encryption key is `HKDF(Argon2id(password, salt, m, t, p),
//! "vahta/id/v1/kek")` and the AAD is `"vahta/id/v1" ‖ header`, so the clear
//! public half is authenticated by the sealed part: a file whose public half
//! was edited does not open. A password that opens it also has to derive the
//! public half the header states. Argon2id costs are held to the same floor and
//! ceiling as the vault's password slot.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use zeroize::Zeroizing;

use crate::Error;
use crate::crypto::{self, KEY_LEN, KdfParams, NONCE_LEN, TAG_LEN};
use crate::vault::{RecipientPublic, RecipientSecret};

const MAGIC: &[u8; 8] = b"VAHTAIDN";
const VERSION: u16 = 1;
const DOMAIN_AAD: &[u8] = b"vahta/id/v1";
const INFO_KEK: &[u8] = b"vahta/id/v1/kek";
const HEADER_LEN: usize = 8 + 2 + 12 + 16 + 2 * KEY_LEN;
const FILE_LEN: usize = HEADER_LEN + NONCE_LEN + 2 * KEY_LEN + TAG_LEN;

struct Header {
    cost: KdfParams,
    salt: [u8; 16],
    public: RecipientPublic,
}

fn parse(bytes: &[u8]) -> Result<Header, Error> {
    let bad = || Error::Corrupt("identity file");
    if bytes.len() != FILE_LEN || &bytes[..8] != MAGIC {
        return Err(bad());
    }
    if u16::from_le_bytes([bytes[8], bytes[9]]) != VERSION {
        return Err(Error::Corrupt("identity file version"));
    }
    let int =
        |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    let cost = KdfParams {
        m_kib: int(10),
        t: int(14),
        p: int(18),
    };
    if !crypto::KDF_CEILING.meets(&cost) || cost.m_kib == 0 || cost.t == 0 || cost.p == 0 {
        return Err(Error::Corrupt("identity kdf parameters"));
    }
    Ok(Header {
        cost,
        salt: bytes[22..38].try_into().map_err(|_| bad())?,
        public: RecipientPublic {
            enc_pk: bytes[38..70].try_into().map_err(|_| bad())?,
            sign_pk: bytes[70..102].try_into().map_err(|_| bad())?,
        },
    })
}

fn kek(pw: &[u8], h: &Header) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let raw = crypto::argon2id(pw, &h.salt, h.cost.m_kib, h.cost.t, h.cost.p)?;
    Ok(crypto::hkdf(&*raw, INFO_KEK))
}

fn aad(header: &[u8]) -> Vec<u8> {
    let mut a = DOMAIN_AAD.to_vec();
    a.extend_from_slice(header);
    a
}

/// Whether an identity file is there.
pub fn exists(path: &Path) -> bool {
    path.is_file()
}

/// Make a new identity at `path`, sealed with `pw`, and return its public
/// half. Refuses to replace a file: losing an identity loses every membership
/// it holds.
pub fn create(path: &Path, pw: &[u8], kdf: KdfParams) -> Result<RecipientPublic, Error> {
    if !kdf.meets(&crypto::kdf_floor()) {
        return Err(Error::KdfBelowFloor);
    }
    let keys = RecipientSecret::generate()?;
    let public = keys.public()?;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&VERSION.to_le_bytes());
    for n in [kdf.m_kib, kdf.t, kdf.p] {
        header.extend_from_slice(&n.to_le_bytes());
    }
    header.extend_from_slice(&crypto::random::<16>()?);
    header.extend_from_slice(&public.enc_pk);
    header.extend_from_slice(&public.sign_pk);
    let key = kek(
        pw,
        &Header {
            cost: kdf,
            salt: header[22..38].try_into().map_err(|_| Error::Rng)?,
            public,
        },
    )?;
    let mut plain = Zeroizing::new(Vec::with_capacity(2 * KEY_LEN));
    plain.extend_from_slice(keys.enc_sk());
    plain.extend_from_slice(keys.sign_sk());
    let (nonce, ct) = crypto::seal(&key, &aad(&header), &plain)?;
    let mut file = header;
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&ct);

    let io = |op, source| Error::Io {
        op,
        path: path.to_path_buf(),
        source,
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| io("create the directory of", e))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(path).map_err(|e| io("create", e))?;
    f.write_all(&file)
        .and_then(|()| f.sync_all())
        .map_err(|e| io("write", e))?;
    Ok(public)
}

fn read(path: &Path) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|source| Error::Io {
        op: "read",
        path: path.to_path_buf(),
        source,
    })
}

/// The public half, with no password. The file is parsed but nothing here
/// proves the public half belongs to the sealed one; [`open`] does.
pub fn read_public(path: &Path) -> Result<RecipientPublic, Error> {
    Ok(parse(&read(path)?)?.public)
}

/// Open the identity with its password. A wrong password is
/// [`Error::Unlock`].
pub fn open(path: &Path, pw: &[u8]) -> Result<RecipientSecret, Error> {
    let bytes = read(path)?;
    let header = parse(&bytes)?;
    if !header.cost.meets(&crypto::kdf_floor()) {
        return Err(Error::KdfBelowFloor);
    }
    let key = kek(pw, &header)?;
    let nonce: [u8; NONCE_LEN] = bytes[HEADER_LEN..HEADER_LEN + NONCE_LEN]
        .try_into()
        .map_err(|_| Error::Corrupt("identity file"))?;
    let plain = crypto::open(
        &key,
        &nonce,
        &aad(&bytes[..HEADER_LEN]),
        &bytes[HEADER_LEN + NONCE_LEN..],
    )?;
    let enc: [u8; KEY_LEN] = plain[..KEY_LEN]
        .try_into()
        .map_err(|_| Error::Corrupt("identity file"))?;
    let sign: [u8; KEY_LEN] = plain[KEY_LEN..]
        .try_into()
        .map_err(|_| Error::Corrupt("identity file"))?;
    let keys = RecipientSecret::from_parts(enc, sign);
    if keys.public()? != header.public {
        return Err(Error::Corrupt("identity file"));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_show_open_and_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub/identity.vht");
        let public = create(&p, b"pw one", KdfParams::TEST).unwrap();
        assert_eq!(read_public(&p).unwrap(), public);
        assert_eq!(open(&p, b"pw one").unwrap().public().unwrap(), public);
        assert!(matches!(open(&p, b"pw two"), Err(Error::Unlock)));
        assert!(matches!(
            create(&p, b"again", KdfParams::TEST),
            Err(Error::Io { .. })
        ));
        assert_eq!(std::fs::read(&p).unwrap().len(), FILE_LEN);
    }

    #[test]
    fn an_edited_public_half_or_cost_does_not_open() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("identity.vht");
        create(&p, b"pw", KdfParams::TEST).unwrap();
        let good = std::fs::read(&p).unwrap();
        for at in [40usize, 80, 25, 12] {
            let mut bad = good.clone();
            bad[at] ^= 1;
            std::fs::write(&p, &bad).unwrap();
            assert!(open(&p, b"pw").is_err(), "byte {at}");
        }
        std::fs::write(&p, &good[..good.len() - 1]).unwrap();
        assert!(matches!(read_public(&p), Err(Error::Corrupt(_))));
    }
}
