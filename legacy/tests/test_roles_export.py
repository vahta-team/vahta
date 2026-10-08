"""PR6: KAM2 roles, migration, export, runner policy.

All tests use throwaway KEY_AMNESIA_HOME via the shared ``ka_home`` fixture —
never the maintainer's daily vault.
"""

from __future__ import annotations

import getpass
import struct
from pathlib import Path

import pytest

from key_amnesia import crypto
from key_amnesia import roles
from key_amnesia.cli import main
from key_amnesia.vault import (
    HEADER_FMT,
    HEADER_SIZE,
    MAGIC_KAM1,
    MAGIC_KAM2,
    detect_vault_magic,
    load_vault,
    save_vault,
)


def _seed_kam1(vault: Path, password: str, secrets: dict[str, str]) -> None:
    save_vault(
        vault,
        password,
        {
            "secrets": secrets,
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
    )
    assert detect_vault_magic(vault) == MAGIC_KAM1


def test_real_kam1_fixture_migrates_with_verified_backup(
    ka_home: Path, password: str
) -> None:
    vault = ka_home / "vault.bin"
    secrets = {"api_key": "super-secret-value-123", "db_pass": "p@ss"}
    _seed_kam1(vault, password, secrets)
    original = vault.read_bytes()

    announced: list[str] = []

    payload = roles.migrate_kam1_to_kam2(
        vault,
        password,
        confirm=lambda _m: True,
        announce=lambda m: announced.append(m),
    )

    bak = roles.kam1_backup_path(vault)
    assert bak.exists()
    assert bak.read_bytes() == original
    # Backup still decrypts as KAM1.
    assert detect_vault_magic(bak) == MAGIC_KAM1
    assert load_vault(bak, password)["secrets"] == secrets
    # Live vault is KAM2 and round-trips.
    assert detect_vault_magic(vault) == MAGIC_KAM2
    assert payload["secrets"] == secrets
    assert load_vault(vault, password)["secrets"] == secrets
    assert roles.is_kam2_payload(payload)
    assert roles.verify_acl_signature(payload)
    assert announced  # never silent


def test_migration_aborts_if_confirm_declined(ka_home: Path, password: str) -> None:
    vault = ka_home / "vault.bin"
    _seed_kam1(vault, password, {"a": "1"})
    before = vault.read_bytes()

    with pytest.raises(roles.RolesError, match="cancelled"):
        roles.migrate_kam1_to_kam2(
            vault, password, confirm=lambda _m: False, announce=lambda _m: None
        )

    assert vault.read_bytes() == before
    assert not roles.kam1_backup_path(vault).exists()


def test_migration_requires_confirm_even_with_announce(
    ka_home: Path, password: str
) -> None:
    """announce= alone must never migrate — confirm= is mandatory unconditionally."""
    vault = ka_home / "vault.bin"
    _seed_kam1(vault, password, {"a": "1"})
    before = vault.read_bytes()

    with pytest.raises(roles.RolesError, match="explicit confirm"):
        roles.migrate_kam1_to_kam2(
            vault, password, confirm=None, announce=lambda _m: None
        )

    assert vault.read_bytes() == before
    assert detect_vault_magic(vault) == MAGIC_KAM1
    assert not roles.kam1_backup_path(vault).exists()


def test_runner_denies_reveal(ka_home: Path, password: str, monkeypatch, capsys) -> None:
    vault = ka_home / "vault.bin"
    _seed_kam1(vault, password, {"api_key": "super-secret-value-123"})

    # Local identity that will be added as runner.
    ident = roles.create_identity(label="agent")
    payload = roles.migrate_kam1_to_kam2(
        vault, password, confirm=lambda _m: True, announce=lambda _m: None
    )
    roles.add_member(
        payload, name="agent", box_pk_hex=ident["box_pk"], role="runner"
    )
    roles.grant_secret(payload, "api_key", "agent")
    save_vault(vault, password, payload)

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)

    rc = main(["reveal", "api_key"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "role" in err.lower() or "runner" in err.lower()
    assert "Policy" in err or "policy" in err.lower()


def test_export_only_target_member_secrets(ka_home: Path, password: str) -> None:
    vault = ka_home / "vault.bin"
    _seed_kam1(
        vault,
        password,
        {"alice_only": "aaa", "bob_only": "bbb", "shared": "sss"},
    )
    alice_sk, alice_pk = crypto.generate_box_keypair()
    bob_sk, bob_pk = crypto.generate_box_keypair()

    payload = roles.migrate_kam1_to_kam2(
        vault, password, confirm=lambda _m: True, announce=lambda _m: None
    )
    roles.add_member(payload, name="alice", box_pk_hex=alice_pk.hex(), role="writer")
    roles.add_member(payload, name="bob", box_pk_hex=bob_pk.hex(), role="runner")
    roles.grant_secret(payload, "alice_only", "alice")
    roles.grant_secret(payload, "shared", "alice")
    roles.grant_secret(payload, "bob_only", "bob")
    roles.grant_secret(payload, "shared", "bob")
    save_vault(vault, password, payload)
    payload = load_vault(vault, password)

    blob = roles.build_export_blob(payload, "alice")
    opened = roles.open_export_blob(blob, alice_sk)
    assert set(opened["secrets"]) == {"alice_only", "shared"}
    assert opened["secrets"]["alice_only"] == "aaa"
    assert opened["secrets"]["shared"] == "sss"
    assert "bob_only" not in opened["secrets"]

    # Bob's key cannot open Alice's export.
    with pytest.raises(roles.RolesError):
        roles.open_export_blob(blob, bob_sk)

    bob_blob = roles.build_export_blob(payload, "bob")
    bob_opened = roles.open_export_blob(bob_blob, bob_sk)
    assert set(bob_opened["secrets"]) == {"bob_only", "shared"}
    assert "alice_only" not in bob_opened["secrets"]


def test_remove_member_warns_to_rotate(
    ka_home: Path, password: str, monkeypatch, capsys
) -> None:
    vault = ka_home / "vault.bin"
    _seed_kam1(vault, password, {"api_key": "v"})
    _sk, pk = crypto.generate_box_keypair()
    payload = roles.migrate_kam1_to_kam2(
        vault, password, confirm=lambda _m: True, announce=lambda _m: None
    )
    roles.add_member(payload, name="temp", box_pk_hex=pk.hex(), role="writer")
    save_vault(vault, password, payload)

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)

    # Clear local identity so role policy doesn't interfere (we aren't a member).
    if roles.identity_path().exists():
        roles.identity_path().unlink()

    rc = main(["member", "remove", "temp"])
    out = capsys.readouterr()
    assert rc == 0
    combined = out.out + out.err
    assert "Rotate" in combined or "rotate" in combined


def test_member_add_cli_migrates_with_yes(
    ka_home: Path, password: str, monkeypatch, capsys
) -> None:
    vault = ka_home / "vault.bin"
    _seed_kam1(vault, password, {"api_key": "v"})
    _sk, pk = crypto.generate_box_keypair()

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)

    rc = main(
        [
            "member",
            "add",
            "runner1",
            "--pubkey",
            pk.hex(),
            "--role",
            "runner",
            "--yes",
        ]
    )
    assert rc == 0
    assert detect_vault_magic(vault) == MAGIC_KAM2
    assert roles.kam1_backup_path(vault).exists()
    # Backup header still KAM1.
    bak = roles.kam1_backup_path(vault)
    magic, *_rest = struct.unpack(HEADER_FMT, bak.read_bytes()[:HEADER_SIZE])
    assert magic == MAGIC_KAM1
    payload = load_vault(vault, password)
    names = [m["name"] for m in payload["kam2"]["members"].values()]
    assert "runner1" in names
    assert "admin" in names


def test_users_who_never_enable_roles_stay_on_kam1(
    ka_home: Path, password: str
) -> None:
    vault = ka_home / "vault.bin"
    _seed_kam1(vault, password, {"x": "y"})
    save_vault(vault, password, load_vault(vault, password))
    assert detect_vault_magic(vault) == MAGIC_KAM1


def test_acl_signature_tamper_detected(ka_home: Path, password: str) -> None:
    vault = ka_home / "vault.bin"
    _seed_kam1(vault, password, {"x": "y"})
    payload = roles.migrate_kam1_to_kam2(
        vault, password, confirm=lambda _m: True, announce=lambda _m: None
    )
    assert roles.verify_acl_signature(payload)
    # Tamper member role in-memory without re-signing.
    mid = next(iter(payload["kam2"]["members"]))
    payload["kam2"]["members"][mid]["role"] = "runner"
    assert not roles.verify_acl_signature(payload)
