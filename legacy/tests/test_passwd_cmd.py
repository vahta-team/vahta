"""`ka passwd` / `ka change-password`: re-encrypt with a fresh salt."""

from __future__ import annotations

import struct
from pathlib import Path

import getpass
import pytest

from key_amnesia.cli import main
from key_amnesia.paths import vault_path
from key_amnesia.vault import HEADER_FMT, HEADER_SIZE, load_vault


def _salt_of(vault: Path) -> bytes:
    data = vault.read_bytes()
    _, _, salt, _, _ = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])
    return salt


def test_passwd_happy_path_reencrypts_with_fresh_salt(
    seeded_vault: Path, password: str, monkeypatch
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr("key_amnesia.guard.guard_is_alive", lambda *a, **k: False)
    old_salt = _salt_of(seeded_vault)

    answers = iter([password, "brand-new-password", "brand-new-password"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))

    rc = main(["passwd"])
    assert rc == 0

    new_salt = _salt_of(seeded_vault)
    assert new_salt != old_salt

    # Old password no longer works; new one does, with the same secrets.
    from key_amnesia.vault import VaultError

    with pytest.raises(VaultError):
        load_vault(seeded_vault, password)
    payload = load_vault(seeded_vault, "brand-new-password")
    assert payload["secrets"]["api_key"] == "super-secret-value-123"


def test_passwd_alias_change_password(
    seeded_vault: Path, password: str, monkeypatch
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr("key_amnesia.guard.guard_is_alive", lambda *a, **k: False)
    answers = iter([password, "another-new-password", "another-new-password"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))

    rc = main(["change-password"])
    assert rc == 0
    load_vault(seeded_vault, "another-new-password")  # does not raise


def test_passwd_refuses_while_guard_alive(
    seeded_vault: Path, password: str, monkeypatch, capsys
) -> None:
    monkeypatch.setattr("key_amnesia.guard.guard_is_alive", lambda *a, **k: True)
    rc = main(["passwd"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "ka lock" in err


def test_passwd_mismatch_aborts_without_changing_vault(
    seeded_vault: Path, password: str, monkeypatch
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr("key_amnesia.guard.guard_is_alive", lambda *a, **k: False)
    before = seeded_vault.read_bytes()

    answers = iter([password, "first-new-password", "second-new-password"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))

    rc = main(["passwd"])
    assert rc == 1
    assert seeded_vault.read_bytes() == before
    # Old password still works — nothing changed.
    load_vault(seeded_vault, password)


def test_passwd_wrong_current_password_aborts(
    seeded_vault: Path, password: str, monkeypatch
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr("key_amnesia.guard.guard_is_alive", lambda *a, **k: False)
    before = seeded_vault.read_bytes()

    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "totally-wrong-password")

    rc = main(["passwd"])
    assert rc == 1
    assert seeded_vault.read_bytes() == before


def test_passwd_requires_tty(seeded_vault: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr("key_amnesia.guard.guard_is_alive", lambda *a, **k: False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    rc = main(["passwd"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "interactive terminal" in err


def test_passwd_no_vault_refuses(ka_home, monkeypatch, capsys) -> None:
    monkeypatch.setattr("key_amnesia.guard.guard_is_alive", lambda *a, **k: False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    rc = main(["passwd"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "ka init" in err
    assert not vault_path().exists()
