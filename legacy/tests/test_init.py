"""Tests for ka init double-confirm and set-without-vault refusal."""

from __future__ import annotations

from pathlib import Path

import getpass
import pytest

from key_amnesia.cli import main
from key_amnesia.paths import vault_path
from key_amnesia.vault import load_vault


def test_init_mismatch_creates_nothing(
    ka_home: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    answers = iter(["first-password", "second-password"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))

    rc = main(["init"])
    err = capsys.readouterr().err

    assert rc == 1
    assert not vault_path().exists()
    assert "match" in err.lower() or "confirm" in err.lower()


def test_init_match_creates_unlockable_vault(
    ka_home: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    pw = "same-confirmed-password"
    answers = iter([pw, pw])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))

    rc = main(["init"])
    captured = capsys.readouterr()
    assert rc == 0
    assert vault_path().exists()
    payload = load_vault(vault_path(), pw)
    assert payload["secrets"] == {}
    assert "Next: ka setup" in captured.out + captured.err


def test_init_refuses_if_vault_exists(
    seeded_vault: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    before = seeded_vault.read_bytes()
    # Would create if somehow allowed — must not be called successfully
    monkeypatch.setattr(
        getpass, "getpass", lambda prompt="": (_ for _ in ()).throw(AssertionError)
    )

    rc = main(["init"])
    err = capsys.readouterr().err

    assert rc == 1
    assert "already initialized" in err.lower()
    assert seeded_vault.read_bytes() == before


def test_set_without_vault_refuses(
    ka_home: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    # Even with a TTY, set must refuse before auth when vault is missing
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)

    rc = main(["set", "SOME_KEY", "value"])
    err = capsys.readouterr().err

    assert rc == 1
    assert "ka init" in err
    assert not vault_path().exists()
