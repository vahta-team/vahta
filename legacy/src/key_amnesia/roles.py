"""KAM2 roles, identity, ACL, migration, and export (PyNaCl only).

Policy vs cryptography (read every call site with this in mind):

| Capability | Class |
|---|---|
| Per-secret data-key wrap / SealedBox export | **Cryptographic** |
| Admin Ed25519 signature over members+ACL | **Cryptographic, detection only** (tamper-evident) |
| runner: `run` yes, `reveal`/`copy` no | **Policy** vs a determined human with the master password; **effective** vs an agent using a runner identity |
"""

from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from key_amnesia import crypto
from key_amnesia.paths import data_dir
from key_amnesia.vault import (
    MAGIC_KAM1,
    MAGIC_KAM2,
    VERSION_KAM2,
    VaultError,
    detect_vault_magic,
    load_vault,
    save_vault,
)

ROLES = frozenset({"admin", "writer", "runner"})

# Export file magic (recipient-only ciphertext bundle).
MAGIC_KAMX = b"KAMX"
VERSION_KAMX = 1
KAMX_HEADER_FMT = "<4sB32s"  # magic, version, recipient box pk
KAMX_HEADER_SIZE = struct.calcsize(KAMX_HEADER_FMT)

ConfirmFn = Callable[[str], bool]


class RolesError(Exception):
    """Roles / identity / export error."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def identity_path() -> Path:
    return data_dir() / "identity.json"


def create_identity(*, label: str = "") -> dict[str, Any]:
    """Generate a local X25519 identity and write it to identity.json."""
    sk, pk = crypto.generate_box_keypair()
    record = {
        "label": label or "",
        "box_sk": sk.hex(),
        "box_pk": pk.hex(),
        "created_at": _utc_now_iso(),
    }
    path = identity_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return record


def load_identity() -> dict[str, Any] | None:
    path = identity_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or "box_sk" not in data or "box_pk" not in data:
        return None
    return data


def member_id_from_pubkey(box_pk_hex: str) -> str:
    """Stable member id = lowercase hex of the X25519 public key."""
    raw = bytes.fromhex(box_pk_hex.strip().lower())
    if len(raw) != crypto.BOX_PK_SIZE:
        raise RolesError(f"box pubkey must be {crypto.BOX_PK_SIZE} bytes")
    return raw.hex()


def canonical_acl_bytes(members: dict[str, Any], acl: dict[str, Any]) -> bytes:
    """Canonical encoding for the admin signature (implementation-independent).

    JSON object with sorted keys at every level; members keyed by member id;
    acl values are sorted lists of member ids. Separators are compact.
    """
    body = {
        "acl": {k: sorted(acl[k]) for k in sorted(acl)},
        "members": {
            mid: {
                "box_pk": members[mid]["box_pk"],
                "name": members[mid]["name"],
                "role": members[mid]["role"],
            }
            for mid in sorted(members)
        },
    }
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sign_acl(admin_signing_sk: bytes, members: dict[str, Any], acl: dict[str, Any]) -> str:
    sig = crypto.sign(admin_signing_sk, canonical_acl_bytes(members, acl))
    return sig.hex()


def verify_acl_signature(payload: dict[str, Any]) -> bool:
    kam2 = payload.get("kam2")
    if not isinstance(kam2, dict):
        return False
    pk_hex = kam2.get("admin_signing_pk")
    sig_hex = kam2.get("acl_signature")
    members = kam2.get("members") or {}
    acl = kam2.get("acl") or {}
    if not pk_hex or not sig_hex:
        return False
    try:
        return crypto.verify(
            bytes.fromhex(pk_hex),
            canonical_acl_bytes(members, acl),
            bytes.fromhex(sig_hex),
        )
    except (ValueError, TypeError):
        return False


def is_kam2_payload(payload: dict[str, Any]) -> bool:
    return isinstance(payload.get("kam2"), dict)


def role_for_identity(payload: dict[str, Any], identity: dict[str, Any] | None) -> str | None:
    """Return the vault role for the local identity, or None if not a member.

    When the vault is still KAM1 (no roles), returns None — password holder
    has full access (no role restrictions).
    """
    if not identity or not is_kam2_payload(payload):
        return None
    mid = member_id_from_pubkey(str(identity["box_pk"]))
    member = (payload.get("kam2") or {}).get("members", {}).get(mid)
    if not isinstance(member, dict):
        return None
    role = member.get("role")
    return str(role) if role in ROLES else None


def policy_allows(action: str, role: str | None) -> bool:
    """CLI policy gate by role. ``role is None`` = no roles / not a member → allow.

    Classification: **policy** (not cryptography). A human with the master
    password can still decrypt the outer AEAD; this gate is **effective**
    against an agent operating under a runner identity.
    """
    if role is None:
        return True
    if role == "admin":
        return True
    if role == "writer":
        return action not in {"member_add", "member_remove", "member_set_role", "passwd"}
    if role == "runner":
        # reveal/copy/set/remove/member_* denied — policy vs human; effective vs agent
        return action in {"run", "list", "status", "unlock", "lock"}
    return False


def deny_reason(action: str, role: str) -> str:
    return (
        f"Denied by role policy: identity role is '{role}', which cannot '{action}'. "
        f"(Policy vs human with master password; effective vs agent.)"
    )


def kam1_backup_path(vault: Path) -> Path:
    return vault.with_name(vault.name + ".kam1.bak")


def migrate_kam1_to_kam2(
    vault: Path,
    password: str,
    *,
    confirm: ConfirmFn | None = None,
    announce: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Enable-triggered KAM1→KAM2 upgrade with confirmed, verified backup.

    1. Announce + require confirmation (never silent).
    2. Write ``vault.bin.kam1.bak``.
    3. Re-open and decrypt the backup successfully.
    4. Only then rewrite the live vault as KAM2.
    """
    if detect_vault_magic(vault) == MAGIC_KAM2:
        return load_vault(vault, password)

    bak = kam1_backup_path(vault)
    msg = (
        f"Enabling roles upgrades this vault from KAM1 to KAM2.\n"
        f"A backup will be written to: {bak}\n"
        f"The backup will be verified (decrypt) before the live vault is modified.\n"
        f"Users who never enable roles stay on KAM1.\n"
        f"Proceed?"
    )
    if announce:
        announce(msg)
    if confirm is None:
        raise RolesError("Roles enable requires an explicit confirm= callback")
    if not confirm(msg):
        raise RolesError("Roles enable cancelled — vault left on KAM1")

    # Snapshot live bytes, write backup, verify decrypt.
    live_bytes = vault.read_bytes()
    if not live_bytes.startswith(MAGIC_KAM1):
        raise RolesError("Expected a KAM1 vault for migration")
    bak.write_bytes(live_bytes)
    try:
        kam1_payload = load_vault(bak, password)
    except VaultError as e:
        raise RolesError(
            f"Backup verification failed — live vault NOT modified: {e}"
        ) from e

    # Build KAM2 payload: admin keypairs + plaintext secrets (re-wrapped on save).
    box_sk, box_pk = crypto.generate_box_keypair()
    sign_sk, sign_pk = crypto.generate_signing_keypair()
    admin_id = box_pk.hex()
    members = {
        admin_id: {
            "name": "admin",
            "role": "admin",
            "box_pk": box_pk.hex(),
            "added_at": _utc_now_iso(),
        }
    }
    secrets = dict(kam1_payload.get("secrets") or {})
    acl = {name: [admin_id] for name in secrets}

    payload: dict[str, Any] = {
        "secrets": secrets,
        "created_at": kam1_payload.get("created_at") or _utc_now_iso(),
        "updated_at": _utc_now_iso(),
        "kam2": {
            "members": members,
            "acl": acl,
            "admin_signing_pk": sign_pk.hex(),
            "admin_signing_sk": sign_sk.hex(),
            "admin_box_sk": box_sk.hex(),
            "admin_box_pk": box_pk.hex(),
            "acl_signature": sign_acl(sign_sk, members, acl),
        },
    }
    save_vault(vault, password, payload)
    # Sanity: live file must now be KAM2 and decrypt.
    if detect_vault_magic(vault) != MAGIC_KAM2:
        raise RolesError("Migration failed: live vault is not KAM2 after save")
    loaded = load_vault(vault, password)
    if loaded.get("secrets") != secrets:
        raise RolesError("Migration failed: secret round-trip mismatch")
    return loaded


def add_member(
    payload: dict[str, Any],
    *,
    name: str,
    box_pk_hex: str,
    role: str,
) -> dict[str, Any]:
    if role not in ROLES:
        raise RolesError(f"Invalid role '{role}'; must be one of {sorted(ROLES)}")
    if not is_kam2_payload(payload):
        raise RolesError("Vault is not KAM2 — enable roles first")
    mid = member_id_from_pubkey(box_pk_hex)
    kam2 = payload["kam2"]
    members: dict[str, Any] = dict(kam2.get("members") or {})
    if mid in members:
        raise RolesError(f"Member already present: {name or mid}")
    for existing in members.values():
        if existing.get("name") == name:
            raise RolesError(f"Member name already used: {name}")
    members[mid] = {
        "name": name,
        "role": role,
        "box_pk": mid,  # normalized hex
        "added_at": _utc_now_iso(),
    }
    kam2["members"] = members
    _resign(payload)
    return payload


def remove_member(payload: dict[str, Any], name: str) -> tuple[dict[str, Any], str]:
    """Remove a member by name. Returns (payload, warning about rotation)."""
    if not is_kam2_payload(payload):
        raise RolesError("Vault is not KAM2")
    kam2 = payload["kam2"]
    members: dict[str, Any] = dict(kam2.get("members") or {})
    mid = None
    for k, v in members.items():
        if v.get("name") == name:
            mid = k
            break
    if mid is None:
        raise RolesError(f"Unknown member: {name}")
    if members[mid].get("role") == "admin" and _admin_count(members) <= 1:
        raise RolesError("Cannot remove the last admin")
    del members[mid]
    acl = {s: [m for m in ms if m != mid] for s, ms in (kam2.get("acl") or {}).items()}
    kam2["members"] = members
    kam2["acl"] = acl
    _resign(payload)
    warning = (
        f"Removed member '{name}'. Rotate any secrets they could unwrap "
        f"(cryptographic wraps for their pubkey remain until you re-save / rotate)."
    )
    return payload, warning


def grant_secret(payload: dict[str, Any], secret_name: str, member_name: str) -> dict[str, Any]:
    if not is_kam2_payload(payload):
        raise RolesError("Vault is not KAM2")
    if secret_name not in (payload.get("secrets") or {}):
        raise RolesError(f"Unknown secret: {secret_name}")
    mid = _member_id_by_name(payload, member_name)
    kam2 = payload["kam2"]
    acl = dict(kam2.get("acl") or {})
    holders = list(acl.get(secret_name) or [])
    if mid not in holders:
        holders.append(mid)
    acl[secret_name] = holders
    kam2["acl"] = acl
    _resign(payload)
    return payload


def revoke_secret(payload: dict[str, Any], secret_name: str, member_name: str) -> dict[str, Any]:
    if not is_kam2_payload(payload):
        raise RolesError("Vault is not KAM2")
    mid = _member_id_by_name(payload, member_name)
    kam2 = payload["kam2"]
    acl = dict(kam2.get("acl") or {})
    holders = [m for m in (acl.get(secret_name) or []) if m != mid]
    acl[secret_name] = holders
    kam2["acl"] = acl
    _resign(payload)
    return payload


def find_member_by_name(payload: dict[str, Any], name: str) -> tuple[str, dict[str, Any]]:
    return _member_id_by_name(payload, name), (payload["kam2"]["members"][_member_id_by_name(payload, name)])


def _member_id_by_name(payload: dict[str, Any], name: str) -> str:
    members = (payload.get("kam2") or {}).get("members") or {}
    for mid, info in members.items():
        if info.get("name") == name:
            return mid
    raise RolesError(f"Unknown member: {name}")


def _admin_count(members: dict[str, Any]) -> int:
    return sum(1 for m in members.values() if m.get("role") == "admin")


def _resign(payload: dict[str, Any]) -> None:
    kam2 = payload["kam2"]
    sk_hex = kam2.get("admin_signing_sk")
    if not sk_hex:
        raise RolesError("Missing admin signing key in vault payload")
    kam2["acl_signature"] = sign_acl(
        bytes.fromhex(sk_hex),
        kam2.get("members") or {},
        kam2.get("acl") or {},
    )


def build_export_blob(payload: dict[str, Any], member_name: str) -> bytes:
    """Build a KAMX export: only secrets ACL'd to ``member_name``, wrapped for them.

    Cryptographic: recipient opens with their X25519 sk via SealedBox.
    """
    if not is_kam2_payload(payload):
        raise RolesError("Vault is not KAM2 — enable roles before export")
    mid = _member_id_by_name(payload, member_name)
    member = payload["kam2"]["members"][mid]
    recipient_pk = bytes.fromhex(member["box_pk"])
    acl = payload["kam2"].get("acl") or {}
    secrets_plain = payload.get("secrets") or {}

    export_secrets: dict[str, Any] = {}
    for name, holders in acl.items():
        if mid not in holders:
            continue
        if name not in secrets_plain:
            continue
        data_key = crypto.generate_secret_key()
        ct = crypto.encrypt(data_key, str(secrets_plain[name]).encode("utf-8"))
        wrap = crypto.sealed_box_seal(recipient_pk, data_key)
        export_secrets[name] = {
            "ciphertext": ct.hex(),
            "wrap": wrap.hex(),
        }

    bundle = {
        "format": "KAMX",
        "version": VERSION_KAMX,
        "member_id": mid,
        "member_name": member_name,
        "exported_at": _utc_now_iso(),
        "secrets": export_secrets,
    }
    # Seal the whole JSON bundle to the recipient (defence in depth on top of
    # per-secret wraps — still only openable by their sk).
    sealed = crypto.sealed_box_seal(
        recipient_pk,
        json.dumps(bundle, separators=(",", ":"), sort_keys=True).encode("utf-8"),
    )
    header = struct.pack(KAMX_HEADER_FMT, MAGIC_KAMX, VERSION_KAMX, recipient_pk)
    return header + sealed


def open_export_blob(blob: bytes, recipient_sk: bytes) -> dict[str, Any]:
    """Open a KAMX export with the recipient's private key; return plaintext secrets."""
    if len(blob) < KAMX_HEADER_SIZE:
        raise RolesError("Export file too short")
    magic, version, recipient_pk = struct.unpack(KAMX_HEADER_FMT, blob[:KAMX_HEADER_SIZE])
    if magic != MAGIC_KAMX:
        raise RolesError("Invalid export magic")
    if version != VERSION_KAMX:
        raise RolesError(f"Unsupported export version: {version}")
    try:
        plain = crypto.sealed_box_open(recipient_sk, blob[KAMX_HEADER_SIZE:])
    except crypto.CryptoError_ as e:
        raise RolesError("Cannot open export (wrong key or tampered)") from e
    try:
        bundle = json.loads(plain.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise RolesError("Corrupt export payload") from e

    out: dict[str, str] = {}
    for name, entry in (bundle.get("secrets") or {}).items():
        wrap = bytes.fromhex(entry["wrap"])
        ct = bytes.fromhex(entry["ciphertext"])
        data_key = crypto.sealed_box_open(recipient_sk, wrap)
        value = crypto.decrypt(data_key, ct).decode("utf-8")
        out[name] = value
    return {"member_id": bundle.get("member_id"), "secrets": out}


def encode_wrapped_secrets_for_save(payload: dict[str, Any]) -> dict[str, Any]:
    """Convert plaintext ``secrets`` + kam2 ACL into on-disk wrapped form.

    Used by ``save_vault`` when writing KAM2. Returns the inner JSON object
    that goes under the outer password SecretBox (secrets as ciphertext+wraps,
    plus kam2 metadata including admin sks so password holders can re-open).
    """
    if not is_kam2_payload(payload):
        raise RolesError("encode_wrapped_secrets_for_save requires kam2")
    kam2 = dict(payload["kam2"])
    members = kam2.get("members") or {}
    acl = kam2.get("acl") or {}
    plaintext = payload.get("secrets") or {}

    wrapped: dict[str, Any] = {}
    for name, value in plaintext.items():
        data_key = crypto.generate_secret_key()
        ct = crypto.encrypt(data_key, str(value).encode("utf-8"))
        holders = list(acl.get(name) or [])
        # Always wrap for admin box pk so password holders (who hold admin_box_sk
        # inside the outer AEAD) can recover every secret.
        admin_pk = kam2.get("admin_box_pk")
        if admin_pk:
            admin_mid = admin_pk  # hex == member id
            if admin_mid not in holders:
                holders = holders + [admin_mid]
        wraps: dict[str, str] = {}
        for mid in holders:
            info = members.get(mid)
            if not info:
                continue
            pk = bytes.fromhex(info["box_pk"])
            wraps[mid] = crypto.sealed_box_seal(pk, data_key).hex()
        wrapped[name] = {"ciphertext": ct.hex(), "wraps": wraps}
        acl[name] = holders

    kam2["acl"] = acl
    sk_hex = kam2.get("admin_signing_sk")
    if sk_hex:
        kam2["acl_signature"] = sign_acl(
            bytes.fromhex(sk_hex), members, acl
        )

    return {
        "format": "KAM2",
        "version": VERSION_KAM2,
        "created_at": payload.get("created_at") or _utc_now_iso(),
        "updated_at": _utc_now_iso(),
        "kam2": kam2,
        "secrets": wrapped,
    }


def decode_wrapped_secrets_after_load(inner: dict[str, Any]) -> dict[str, Any]:
    """Turn on-disk KAM2 inner JSON into the in-memory plaintext-secrets payload."""
    kam2 = inner.get("kam2")
    if not isinstance(kam2, dict):
        raise VaultError("KAM2 payload missing kam2 metadata")
    admin_sk_hex = kam2.get("admin_box_sk")
    if not admin_sk_hex:
        raise VaultError("KAM2 payload missing admin_box_sk")
    admin_sk = bytes.fromhex(admin_sk_hex)
    plaintext: dict[str, str] = {}
    for name, entry in (inner.get("secrets") or {}).items():
        if isinstance(entry, str):
            # Defensive: already plaintext (should not happen on disk).
            plaintext[name] = entry
            continue
        wraps = entry.get("wraps") or {}
        admin_mid = kam2.get("admin_box_pk")
        wrap_hex = wraps.get(admin_mid) if admin_mid else None
        if not wrap_hex:
            # Fall back to any wrap we can open with admin sk.
            for w in wraps.values():
                try:
                    data_key = crypto.sealed_box_open(admin_sk, bytes.fromhex(w))
                    break
                except crypto.CryptoError_:
                    continue
            else:
                raise VaultError(f"No usable wrap for secret '{name}'")
        else:
            data_key = crypto.sealed_box_open(admin_sk, bytes.fromhex(wrap_hex))
        value = crypto.decrypt(data_key, bytes.fromhex(entry["ciphertext"])).decode(
            "utf-8"
        )
        plaintext[name] = value

    return {
        "secrets": plaintext,
        "created_at": inner.get("created_at"),
        "updated_at": inner.get("updated_at"),
        "kam2": kam2,
    }
