"""Vault crypto round-trip, wrong password, tamper tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from key_amnesia import crypto
from key_amnesia.vault import VaultError, load_vault, read_names, save_vault


def test_vault_round_trip(ka_home: Path, password: str) -> None:
    vault = ka_home / "vault.bin"
    payload = {
        "secrets": {"a": "1", "b": "two"},
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
    }
    save_vault(vault, password, payload)
    loaded = load_vault(vault, password)
    assert loaded["secrets"] == {"a": "1", "b": "two"}
    assert read_names() == ["a", "b"]


def test_wrong_password(seeded_vault: Path, password: str) -> None:
    with pytest.raises(VaultError):
        load_vault(seeded_vault, password + "-wrong")


def test_tamper_detected(seeded_vault: Path, password: str) -> None:
    data = bytearray(seeded_vault.read_bytes())
    # Flip a byte in the ciphertext region (past header).
    data[-5] ^= 0xFF
    seeded_vault.write_bytes(bytes(data))
    with pytest.raises(VaultError):
        load_vault(seeded_vault, password)


def test_kdf_uses_sensitive_only() -> None:
    import nacl.pwhash

    assert crypto.OPSLIMIT == nacl.pwhash.argon2id.OPSLIMIT_SENSITIVE
    assert crypto.MEMLIMIT == nacl.pwhash.argon2id.MEMLIMIT_SENSITIVE


def test_save_always_writes_sensitive_params(ka_home: Path, password: str) -> None:
    import struct

    from key_amnesia.vault import HEADER_FMT, HEADER_SIZE

    vault = ka_home / "vault.bin"
    save_vault(vault, password, {"secrets": {"x": "y"}})
    data = vault.read_bytes()
    _, _, _, ops, mem = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])
    assert ops == crypto.OPSLIMIT
    assert mem == crypto.MEMLIMIT
