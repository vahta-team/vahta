"""Argon2id KDF + SecretBox + PyNaCl SealedBox/Box/Sign helpers."""

from __future__ import annotations

import nacl.pwhash
import nacl.public
import nacl.secret
import nacl.signing
import nacl.utils
from nacl.exceptions import BadSignatureError, CryptoError

# Locked to SENSITIVE only — never dial down.
OPSLIMIT = nacl.pwhash.argon2id.OPSLIMIT_SENSITIVE
MEMLIMIT = nacl.pwhash.argon2id.MEMLIMIT_SENSITIVE

KEY_SIZE = nacl.secret.SecretBox.KEY_SIZE
SALT_SIZE = nacl.pwhash.argon2id.SALTBYTES
BOX_PK_SIZE = 32
BOX_SK_SIZE = 32
SIGN_PK_SIZE = 32
SIGN_SK_SEED_SIZE = 32
SIGN_SIG_SIZE = 64


class CryptoError_(Exception):
    """Raised when decryption or authentication fails."""


def generate_salt() -> bytes:
    return nacl.utils.random(SALT_SIZE)


def generate_secret_key() -> bytes:
    """Random SecretBox key (also used as a per-secret data key)."""
    return nacl.utils.random(KEY_SIZE)


def derive_key(
    password: bytes,
    salt: bytes,
    opslimit: int = OPSLIMIT,
    memlimit: int = MEMLIMIT,
) -> bytes:
    """Derive a SecretBox key via Argon2id.

    opslimit/memlimit default to SENSITIVE. Callers must not pass weaker values
    for new vaults; load_vault may read stored params for compatibility with the
    on-disk header, but save_vault always writes SENSITIVE.
    """
    return nacl.pwhash.argon2id.kdf(
        KEY_SIZE,
        password,
        salt,
        opslimit=opslimit,
        memlimit=memlimit,
    )


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    box = nacl.secret.SecretBox(key)
    return box.encrypt(plaintext)


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    box = nacl.secret.SecretBox(key)
    try:
        return box.decrypt(ciphertext)
    except CryptoError as e:
        raise CryptoError_("Decryption failed (wrong password or tampered data)") from e


# --- X25519 SealedBox / Box (KAM2 per-recipient wraps) ---


def generate_box_keypair() -> tuple[bytes, bytes]:
    """Return `(private_key_bytes, public_key_bytes)` for X25519 SealedBox/Box."""
    sk = nacl.public.PrivateKey.generate()
    return bytes(sk), bytes(sk.public_key)


def sealed_box_seal(recipient_pk: bytes, plaintext: bytes) -> bytes:
    """Anonymous SealedBox: only the recipient's sk can open."""
    pk = nacl.public.PublicKey(recipient_pk)
    return nacl.public.SealedBox(pk).encrypt(plaintext)


def sealed_box_open(recipient_sk: bytes, ciphertext: bytes) -> bytes:
    sk = nacl.public.PrivateKey(recipient_sk)
    try:
        return nacl.public.SealedBox(sk).decrypt(ciphertext)
    except CryptoError as e:
        raise CryptoError_("SealedBox open failed") from e


def box_encrypt(sender_sk: bytes, recipient_pk: bytes, plaintext: bytes) -> bytes:
    """Authenticated Box (sender sk + recipient pk)."""
    box = nacl.public.Box(
        nacl.public.PrivateKey(sender_sk),
        nacl.public.PublicKey(recipient_pk),
    )
    return box.encrypt(plaintext)


def box_decrypt(recipient_sk: bytes, sender_pk: bytes, ciphertext: bytes) -> bytes:
    box = nacl.public.Box(
        nacl.public.PrivateKey(recipient_sk),
        nacl.public.PublicKey(sender_pk),
    )
    try:
        return box.decrypt(ciphertext)
    except CryptoError as e:
        raise CryptoError_("Box decrypt failed") from e


# --- Ed25519 signatures (KAM2 tamper-evident member/ACL metadata) ---


def generate_signing_keypair() -> tuple[bytes, bytes]:
    """Return `(seed_32, verify_key_32)` for Ed25519."""
    sk = nacl.signing.SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


def sign(seed: bytes, message: bytes) -> bytes:
    return bytes(nacl.signing.SigningKey(seed).sign(message).signature)


def verify(verify_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        nacl.signing.VerifyKey(verify_key).verify(message, signature)
        return True
    except BadSignatureError:
        return False
