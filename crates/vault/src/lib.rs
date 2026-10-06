//! The Vahta vault as a library: `vault.vht` format 1, the crypto under it, the
//! local store that remembers what this machine has seen, project discovery,
//! the `vahta.toml` contract and the import of ka's KAM1/KAM2 vaults.
//!
//! The vault is a file with one owner. Everything about it is stored so that it
//! can be checked without a password (the name index is plaintext and signed)
//! and nothing about a value can be learned without a key (values are padded,
//! sealed under a per-secret key, and that key is wrapped separately for the
//! owner and for each recipient). Writes belong to the daemon, which is the
//! vault's only owner; this crate has them as library functions and the CLI
//! uses only the read-only ones.
//!
//! No error message, `Debug` output or log line in this crate contains a
//! value. A secret *name* may appear, a value never.

pub mod crypto;
pub mod format;
pub mod ka;
pub mod manifest;
pub mod project;
pub mod session;
pub mod store;
mod vault;
pub mod write;

use std::fmt;
use std::path::PathBuf;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub use crypto::KdfParams;
pub use format::current::{Actor, Entry, Kind, Recipient, RecipientKind, Role, Tier};
pub use session::SessionKeys;
pub use vault::{Peek, RecipientSecret, Vault, Verification};

/// Names are env-var-like and short. Checked on every write and every read of
/// a file, so no vault can carry a name the project contract cannot spell.
pub const MAX_NAME_LEN: usize = 128;

/// Whether `name` matches `[A-Za-z_][A-Za-z0-9_]*`, at most 128 characters.
pub fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_alphabetic() || b == b'_' => {}
        _ => return false,
    }
    name.len() <= MAX_NAME_LEN && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Why a vault operation did not happen. Never carries a value.
#[derive(Debug)]
pub enum Error {
    /// A file system step failed.
    Io {
        op: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    /// Not a Vahta vault: wrong magic, too short, or a format number this
    /// build has never heard of.
    NotAVault,
    /// Over the 16 MiB limit, refused before any parsing.
    TooLarge,
    /// Written by a newer Vahta.
    NewerFormat {
        found: u16,
        supported: u16,
    },
    /// Structurally wrong: a length, a section, a duplicate, a bad name.
    Corrupt(&'static str),
    /// A signature does not verify.
    BadSignature,
    /// A signature verifies but its signer may not sign.
    SignerNotAllowed,
    /// Wrong password, wrong key, or damaged ciphertext. Deliberately one
    /// error for all three.
    Unlock,
    /// The password slot asks for less work than the floor.
    KdfBelowFloor,
    /// The owner key is not the one this machine pinned for this vault.
    OwnerChanged,
    /// The file's generation is below one this machine has already seen.
    RolledBack {
        found: u64,
        seen: u64,
    },
    /// The file changed on disk since this vault was loaded.
    Conflict,
    /// The operation needs the owner and this vault was opened as a recipient.
    NotOwner,
    NotFound(String),
    InvalidName,
    InvalidFileName,
    ValueTooLarge,
    UnknownRecipient,
    /// A recipient asked for a secret it holds no wrap for.
    NoAccess,
    /// The local store could not be read or written.
    Store(&'static str),
    /// The system random generator failed.
    Rng,
    /// The vault already holds a secret this import would replace.
    ImportCollision(String),
    /// A ka vault that cannot be read; says which part, never a value.
    Ka(&'static str),
    /// `vahta.toml` is malformed.
    Manifest(String),
    /// An upgrade step rewrites the recovery slot and the paper key has not
    /// been given: the vault reads, but cannot be saved until
    /// `Vault::provide_recovery_key`.
    UpgradeNeedsRecoveryKey,
    /// A membership certificate is valid but its issuer may not have issued it
    /// (an admin adding an admin, an admin added by an admin adding anyone).
    MembershipNotAllowed,
    /// The opener's role does not allow this (a runner writing, an editor
    /// changing membership).
    NotPermitted,
    /// The local store's state file does not pass its MAC: edited, or not
    /// written by this opener. Never reset silently.
    StoreTampered,
    /// A session's read found the vault changed since the session was opened:
    /// a secret re-sealed, removed or moved to another tier, or the file
    /// replaced. The session's keys no longer open it.
    SessionStale,
}

impl Error {
    /// `NotFound` for a name the caller supplied. A name that is not even
    /// shaped like one (a value pasted in the wrong place, say) is not echoed.
    pub fn not_found(name: &str) -> Error {
        Error::NotFound(shown_name(name))
    }
}

/// A name safe to put in a message: itself if it is a valid name, else a
/// placeholder, so a mistyped value never ends up in an error.
pub(crate) fn shown_name(name: &str) -> String {
    if valid_name(name) {
        name.to_string()
    } else {
        "<not a valid name>".to_string()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io { op, path, source } => write!(f, "cannot {op} {}: {source}", path.display()),
            Error::NotAVault => f.write_str("not a Vahta vault"),
            Error::TooLarge => f.write_str("the vault file is over the 16 MiB limit"),
            Error::NewerFormat { .. } => {
                f.write_str("this vault was written by a newer Vahta; update Vahta")
            }
            Error::Corrupt(what) => write!(f, "the vault is damaged ({what})"),
            Error::BadSignature => f.write_str("the vault's signature does not verify"),
            Error::SignerNotAllowed => f.write_str("the vault was signed by someone who may not sign"),
            Error::Unlock => f.write_str("could not unlock the vault (wrong password or key, or a damaged file)"),
            Error::KdfBelowFloor => {
                f.write_str("the vault's password hashing is weaker than this build accepts")
            }
            Error::OwnerChanged => f.write_str(
                "the vault's owner key differs from the one this machine saw before; refusing it",
            ),
            Error::RolledBack { .. } => f.write_str(
                "the vault is older than one this machine has already seen (rolled back); refusing it",
            ),
            Error::Conflict => f.write_str("the vault changed on disk since it was loaded"),
            Error::NotOwner => f.write_str("only the vault's owner can do that"),
            Error::NotFound(name) => write!(f, "no secret named {name}"),
            Error::InvalidName => f.write_str("names are letters, digits and underscores, not starting with a digit, up to 128 characters"),
            Error::InvalidFileName => f.write_str("a file name hint is a plain file name"),
            Error::ValueTooLarge => f.write_str("the value is over the 1 MiB limit"),
            Error::UnknownRecipient => f.write_str("no such recipient"),
            Error::NoAccess => f.write_str("this recipient holds no wrap for that secret"),
            Error::Store(what) => write!(f, "the local store is unusable ({what})"),
            Error::Rng => f.write_str("the system random generator failed"),
            Error::ImportCollision(name) => write!(f, "the vault already has a secret named {name}"),
            Error::Ka(what) => write!(f, "cannot read the ka vault ({what})"),
            Error::Manifest(msg) => f.write_str(msg),
            Error::UpgradeNeedsRecoveryKey => f.write_str(
                "this vault's upgrade needs the recovery key; give it before saving",
            ),
            Error::MembershipNotAllowed => {
                f.write_str("a member was added by someone who may not add that member")
            }
            Error::NotPermitted => f.write_str("this recipient's role does not allow that"),
            Error::StoreTampered => f.write_str(
                "this machine's record of the vault failed its integrity check; refusing to reset it",
            ),
            Error::SessionStale => f.write_str(
                "changed since this session was opened; unlock again",
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// A secret's bytes. Zeroed on drop, redacted in `Debug`, no `Display`.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretValue(Zeroizing::new(bytes))
    }

    pub(crate) fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        SecretValue(bytes)
    }

    /// The only way to the bytes, named so a reader of the code sees it.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Clone for SecretValue {
    fn clone(&self) -> Self {
        SecretValue::new(self.0.to_vec())
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

impl PartialEq for SecretValue {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len() && bool::from(self.0.ct_eq(&other.0))
    }
}

/// The paper key: 32 random bytes that open the vault without the password.
/// Shown once, at creation.
pub struct RecoveryKey(Zeroizing<[u8; 32]>);

impl RecoveryKey {
    pub(crate) fn new(bytes: [u8; 32]) -> Self {
        RecoveryKey(Zeroizing::new(bytes))
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex in groups of eight, for writing on paper.
    pub fn to_paper(&self) -> String {
        let hex = hex_encode(&*self.0);
        let groups: Vec<&str> = (0..hex.len()).step_by(8).map(|i| &hex[i..i + 8]).collect();
        groups.join("-")
    }

    /// The inverse of [`RecoveryKey::to_paper`]; dashes and spaces are ignored.
    pub fn from_paper(text: &str) -> Option<RecoveryKey> {
        let compact: String = text
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        let bytes = hex_decode(&compact)?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(RecoveryKey::new(arr))
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey(<redacted>)")
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    bytes
        .chunks(2)
        .map(|p| Some(nibble(p[0])? << 4 | nibble(p[1])?))
        .collect()
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
