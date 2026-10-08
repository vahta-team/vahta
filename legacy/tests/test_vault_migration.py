"""Vault migration: obsolete browser-fill keys are dropped, once, quietly."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from key_amnesia import crypto
from key_amnesia.vault import HEADER_FMT, HEADER_SIZE, load_vault, save_vault


def _write_legacy_vault(vault: Path, password: str, payload: dict) -> None:
    """Write a vault file with an arbitrary payload, bypassing normalization
    (i.e. simulating a vault saved by a pre-0.3.0 build that still wrote the
    browser-fill keys)."""
    salt = crypto.generate_salt()
    opslimit = crypto.OPSLIMIT
    memlimit = crypto.MEMLIMIT
    key = crypto.derive_key(password.encode("utf-8"), salt, opslimit=opslimit, memlimit=memlimit)
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    blob = crypto.encrypt(key, plaintext)
    header = struct.pack(HEADER_FMT, b"KAM1", 1, salt, opslimit, memlimit)
    vault.write_bytes(header + blob)


def test_load_drops_obsolete_keys_and_warns_when_logins_nonempty(
    ka_home: Path, password: str, capsys
) -> None:
    vault = ka_home / "vault.bin"
    _write_legacy_vault(
        vault,
        password,
        {
            "secrets": {"a": "1"},
            "logins": [{"url": "https://x", "username": "u", "secret_name": "a"}],
            "browser_associations": [{"id": "key-amnesia", "id_key_b64": "xyz"}],
            "database_id": "deadbeef",
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
    )

    payload = load_vault(vault, password)
    assert "logins" not in payload
    assert "browser_associations" not in payload
    assert "database_id" not in payload
    assert payload["secrets"] == {"a": "1"}

    out = capsys.readouterr().out
    assert "Removed obsolete login associations" in out
    assert "0.3.0" in out


def test_load_drops_empty_obsolete_keys_silently(
    ka_home: Path, password: str, capsys
) -> None:
    vault = ka_home / "vault.bin"
    _write_legacy_vault(
        vault,
        password,
        {
            "secrets": {"a": "1"},
            "logins": [],
            "browser_associations": [],
            "database_id": "",
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
    )

    payload = load_vault(vault, password)
    assert "logins" not in payload
    assert "browser_associations" not in payload
    assert "database_id" not in payload

    out = capsys.readouterr().out
    assert "Removed obsolete" not in out


def test_load_absent_obsolete_keys_no_message(
    ka_home: Path, password: str, capsys
) -> None:
    vault = ka_home / "vault.bin"
    _write_legacy_vault(
        vault,
        password,
        {
            "secrets": {"a": "1"},
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
    )
    payload = load_vault(vault, password)
    assert set(payload.keys()) >= {"secrets", "created_at", "updated_at"}
    assert "logins" not in payload
    out = capsys.readouterr().out
    assert out == ""


def test_load_then_save_persists_the_cleanup_without_double_warning(
    ka_home: Path, password: str, capsys
) -> None:
    vault = ka_home / "vault.bin"
    _write_legacy_vault(
        vault,
        password,
        {
            "secrets": {"a": "1"},
            "logins": [{"url": "https://x", "username": "u", "secret_name": "a"}],
            "browser_associations": [],
            "database_id": "deadbeef",
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
    )

    payload = load_vault(vault, password)
    out_after_load = capsys.readouterr().out
    assert out_after_load.count("Removed obsolete login associations") == 1

    payload["secrets"]["b"] = "2"
    save_vault(vault, password, payload)
    out_after_save = capsys.readouterr().out
    assert "Removed obsolete" not in out_after_save  # save side is silent

    # The cleanup is now persisted on disk — a fresh load sees no legacy keys
    # and prints nothing more.
    reloaded = load_vault(vault, password)
    assert "logins" not in reloaded
    assert reloaded["secrets"] == {"a": "1", "b": "2"}
    out_after_reload = capsys.readouterr().out
    assert out_after_reload == ""


def test_empty_payload_has_no_fill_keys() -> None:
    from key_amnesia.vault import empty_payload

    payload = empty_payload()
    assert set(payload.keys()) == {"secrets", "created_at", "updated_at"}
