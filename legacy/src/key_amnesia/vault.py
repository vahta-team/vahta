"""Vault binary layout, load/save, and names sidecar.

Supports:
- **KAM1** — whole-vault Argon2id + SecretBox (default until roles are enabled)
- **KAM2** — same outer AEAD; inner payload uses per-secret data keys +
  SealedBox wraps and signed member/ACL metadata (see DESIGN.md § KAM2)
"""

from __future__ import annotations

import hashlib
import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from key_amnesia import crypto
from key_amnesia import theme
from key_amnesia.paths import names_path, vault_path

MAGIC_KAM1 = b"KAM1"
MAGIC_KAM2 = b"KAM2"
# Back-compat aliases used by older tests / callers.
MAGIC = MAGIC_KAM1
VERSION_KAM1 = 1
VERSION_KAM2 = 1
VERSION = VERSION_KAM1
HEADER_FMT = "<4sB16sQQ"  # magic, version, salt, opslimit, memlimit
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# Obsolete browser-fill payload keys, removed in 0.3.0. Dropped on load/save
# so old vaults migrate forward automatically; see _normalize_payload.
_OBSOLETE_FILL_KEYS = ("logins", "browser_associations", "database_id")


class VaultError(Exception):
    """Vault I/O or format error."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def empty_payload() -> dict[str, Any]:
    now = _utc_now_iso()
    return {
        "secrets": {},
        "created_at": now,
        "updated_at": now,
    }


def detect_vault_magic(path: Path | str) -> bytes | None:
    """Return the 4-byte magic of a vault file, or None if unreadable/too short."""
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError:
        return None
    if len(data) < 4:
        return None
    return data[:4]


def _normalize_payload(payload: dict[str, Any], *, warn: bool = True) -> dict[str, Any]:
    """Drop obsolete browser-fill keys (removed in 0.3.0) before use.

    Prints a one-time informational notice only when there was a non-empty
    ``logins`` list to actually lose; empty/absent obsolete keys are dropped
    silently. Callers that immediately re-save the payload (e.g. ``load_vault``
    followed by a mutation + ``save_vault``) should only warn once — pass
    ``warn=False`` on the save-side normalization.
    """
    if any(key in payload for key in _OBSOLETE_FILL_KEYS):
        logins = payload.get("logins")
        if warn and isinstance(logins, list) and logins:
            theme.info(
                "Removed obsolete login associations - browser-fill was "
                "removed in 0.3.0."
            )
        for key in _OBSOLETE_FILL_KEYS:
            payload.pop(key, None)
    return payload


def _read_header(data: bytes) -> tuple[bytes, int, bytes, int, int, bytes]:
    """Parse the fixed header.

    Returns (magic, version, salt, opslimit, memlimit, ciphertext blob).
    """
    if len(data) < HEADER_SIZE:
        raise VaultError("Vault file too short")
    magic, version, salt, opslimit, memlimit = struct.unpack(
        HEADER_FMT, data[:HEADER_SIZE]
    )
    if magic not in (MAGIC_KAM1, MAGIC_KAM2):
        raise VaultError("Invalid vault magic")
    if magic == MAGIC_KAM1 and version != VERSION_KAM1:
        raise VaultError(f"Unsupported KAM1 version: {version}")
    if magic == MAGIC_KAM2 and version != VERSION_KAM2:
        raise VaultError(f"Unsupported KAM2 version: {version}")
    return magic, version, salt, opslimit, memlimit, data[HEADER_SIZE:]


def _decrypt_outer(key: bytes, blob: bytes) -> dict[str, Any]:
    try:
        plaintext = crypto.decrypt(key, blob)
    except crypto.CryptoError_ as e:
        raise VaultError(str(e)) from e
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise VaultError("Vault payload is corrupt") from e
    if not isinstance(payload, dict):
        raise VaultError("Vault payload is not an object")
    return payload


def _payload_from_inner(magic: bytes, inner: dict[str, Any], *, warn: bool) -> dict[str, Any]:
    """Normalize an outer-decrypted JSON object into the in-memory payload.

    KAM1: secrets are plaintext strings.
    KAM2: secrets are ciphertext+wraps; decode to plaintext using admin_box_sk
    (present inside the password AEAD).
    """
    if magic == MAGIC_KAM2 or inner.get("format") == "KAM2":
        from key_amnesia.roles import decode_wrapped_secrets_after_load

        try:
            payload = decode_wrapped_secrets_after_load(inner)
        except VaultError:
            raise
        except Exception as e:
            raise VaultError(f"KAM2 decode failed: {e}") from e
        return _normalize_payload(payload, warn=warn)

    if "secrets" not in inner:
        raise VaultError("Vault payload missing secrets")
    return _normalize_payload(inner, warn=warn)


def load_vault_with_key(path: Path | str | None, password: str) -> tuple[dict[str, Any], bytes]:
    """Decrypt the vault and return `(payload, derived_key)`.

    Runs Argon2id exactly once. Callers that need to hold onto the derived
    SecretBox key for a later no-KDF re-open (e.g. the guard's stale-secrets
    reload — see `load_vault_with_retained_key`) should use this instead of
    `load_vault` to avoid deriving the key twice.

    Returned payload always exposes ``secrets`` as plaintext name→value for
    password holders (KAM2 unwraps via admin_box_sk inside the outer AEAD).
    """
    p = Path(path) if path is not None else vault_path()
    if not p.exists():
        raise VaultError(f"Vault not found: {p}")
    data = p.read_bytes()
    magic, _version, salt, opslimit, memlimit, blob = _read_header(data)
    key = crypto.derive_key(
        password.encode("utf-8"),
        salt,
        opslimit=opslimit,
        memlimit=memlimit,
    )
    inner = _decrypt_outer(key, blob)
    payload = _payload_from_inner(magic, inner, warn=True)
    return payload, key


def load_vault(path: Path | str | None, password: str) -> dict[str, Any]:
    """Decrypt and return the vault JSON payload."""
    payload, _key = load_vault_with_key(path, password)
    return payload


def load_vault_with_retained_key(path: Path | str | None, key: bytes) -> dict[str, Any]:
    """Decrypt the vault using an already-derived SecretBox key — no Argon2id.

    Used by the guard's stale-secrets reload: the guard retains the derived
    key from the `ka unlock` password prompt and re-opens the vault file
    whenever its content changes, without re-running the deliberately-slow
    Argon2id KDF and without ever seeing the password again.
    """
    p = Path(path) if path is not None else vault_path()
    if not p.exists():
        raise VaultError(f"Vault not found: {p}")
    data = p.read_bytes()
    magic, _version, _salt, _opslimit, _memlimit, blob = _read_header(data)
    inner = _decrypt_outer(key, blob)
    return _payload_from_inner(magic, inner, warn=True)


def vault_fingerprint(path: Path | str | None = None) -> str | None:
    """Cheap content fingerprint (size + mtime + hash) of the vault file.

    Used to detect a `ka set`/`ka remove` write from another process without
    re-decrypting on every request. Returns `None` if the file can't
    currently be read (missing, or caught mid-write) so callers can treat
    "no fingerprint" as "nothing to compare yet" rather than crashing.
    """
    p = Path(path) if path is not None else vault_path()
    try:
        st = p.stat()
        data = p.read_bytes()
    except OSError:
        return None
    digest = hashlib.sha256(data).hexdigest()
    return f"{st.st_size}:{st.st_mtime_ns}:{digest}"


def save_vault(
    path: Path | str | None,
    password: str,
    payload: dict[str, Any],
    *,
    salt: bytes | None = None,
) -> None:
    """Encrypt and write the vault. Always uses OPSLIMIT/MEMLIMIT_SENSITIVE.

    If ``payload`` carries ``kam2`` metadata, writes **KAM2** (per-secret wraps).
    Otherwise writes **KAM1**. Users who never enable roles stay on KAM1.
    """
    p = Path(path) if path is not None else vault_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    if salt is None:
        # Preserve salt if vault already exists (same password re-encrypt).
        if p.exists() and len(p.read_bytes()) >= HEADER_SIZE:
            existing = p.read_bytes()
            _, _, salt, _, _ = struct.unpack(HEADER_FMT, existing[:HEADER_SIZE])
        else:
            salt = crypto.generate_salt()
    opslimit = crypto.OPSLIMIT
    memlimit = crypto.MEMLIMIT
    key = crypto.derive_key(
        password.encode("utf-8"),
        salt,
        opslimit=opslimit,
        memlimit=memlimit,
    )
    # Silent here: load_vault already surfaced the migration notice (if any)
    # on the read side of a load-then-save round trip.
    body = _normalize_payload(dict(payload), warn=False)
    if "created_at" not in body:
        body["created_at"] = _utc_now_iso()
    body["updated_at"] = _utc_now_iso()
    if "secrets" not in body:
        body["secrets"] = {}

    if isinstance(body.get("kam2"), dict):
        from key_amnesia.roles import encode_wrapped_secrets_for_save

        inner = encode_wrapped_secrets_for_save(body)
        magic = MAGIC_KAM2
        version = VERSION_KAM2
        secret_names = sorted(body["secrets"].keys())
    else:
        # Strip any accidental kam2-only keys for a clean KAM1 write.
        body.pop("kam2", None)
        body.pop("format", None)
        inner = {
            "secrets": body["secrets"],
            "created_at": body["created_at"],
            "updated_at": body["updated_at"],
        }
        magic = MAGIC_KAM1
        version = VERSION_KAM1
        secret_names = sorted(body["secrets"].keys())

    plaintext = json.dumps(inner, separators=(",", ":"), sort_keys=True).encode("utf-8")
    blob = crypto.encrypt(key, plaintext)
    header = struct.pack(HEADER_FMT, magic, version, salt, opslimit, memlimit)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_bytes(header + blob)
    tmp.replace(p)
    # Keep names sidecar in sync with encrypted secrets keys.
    write_names(secret_names, names_path_for_vault(p))


def names_path_for_vault(vault: Path) -> Path:
    return vault.with_name(vault.stem + ".names.json")


def read_names(path: Path | None = None) -> list[str]:
    p = path or names_path()
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    names = data.get("names", []) if isinstance(data, dict) else []
    if not isinstance(names, list):
        return []
    return [str(n) for n in names]


def write_names(names: list[str], path: Path | None = None) -> None:
    p = path or names_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {"names": sorted(set(names))}
    p.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def update_names_after_mutation(secrets: dict[str, str], vault: Path | None = None) -> None:
    vp = vault or vault_path()
    write_names(sorted(secrets.keys()), names_path_for_vault(vp))
