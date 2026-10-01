"""PR4: amnesia.toml schema, ka check, ka run missing-required preflight.

Always uses throwaway KEY_AMNESIA_HOME via `ka_home` — never the
maintainer's real vault.
"""

from __future__ import annotations

import getpass
import json
import sys
from pathlib import Path

import pytest

from key_amnesia import vault as vault_mod
from key_amnesia.cli import main
from key_amnesia.manifest import (
    check_against_names,
    check_project,
    generate_or_merge_manifest,
    load_manifest,
)
from key_amnesia.project import ensure_project_scaffold, project_vault_path


def _seed_project_vault(root: Path, password: str, secrets: dict[str, str]) -> Path:
    vp = project_vault_path(root)
    vault_mod.save_vault(
        vp,
        password,
        {
            "secrets": secrets,
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
    )
    return vp


def test_load_manifest_canonical(tmp_path: Path) -> None:
    path = tmp_path / "amnesia.toml"
    path.write_text(
        "\n".join(
            [
                "[secrets.API_KEY]",
                "required = true",
                'description = "api"',
                'env = "OPENAI_API_KEY"',
                "",
                "[secrets.OPTIONAL]",
                "required = false",
                'description = ""',
                'env = "OPTIONAL"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    man = load_manifest(path)
    assert set(man.secrets) == {"API_KEY", "OPTIONAL"}
    assert man.secrets["API_KEY"].required is True
    assert man.secrets["API_KEY"].env == "OPENAI_API_KEY"
    assert man.secrets["OPTIONAL"].required is False


def test_load_manifest_legacy_array(tmp_path: Path) -> None:
    path = tmp_path / "amnesia.toml"
    path.write_text(
        '[[secret]]\nname = "LEGACY"\nrequired = true\ndescription = ""\nenv = "LEGACY"\n',
        encoding="utf-8",
    )
    man = load_manifest(path)
    assert "LEGACY" in man.secrets
    assert man.secrets["LEGACY"].required is True


def test_check_against_names_missing() -> None:
    from key_amnesia.manifest import Manifest, SecretEntry

    man = Manifest(
        path=Path("amnesia.toml"),
        secrets={
            "A": SecretEntry(name="A", required=True),
            "B": SecretEntry(name="B", required=True),
            "C": SecretEntry(name="C", required=False),
        },
    )
    result = check_against_names(man, {"A"})
    assert result.ok is False
    assert result.missing == ["B"]
    assert result.present == ["A"]
    assert result.optional_absent == ["C"]


def test_check_project_no_manifest_is_ok(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    ensure_project_scaffold(root, use_global=False)
    names = vault_mod.names_path_for_vault(project_vault_path(root))
    result = check_project(root, names_path=names)
    assert result.ok is True
    assert result.manifest_path is None


def test_ka_check_ok_and_json(
    ka_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    ensure_project_scaffold(root, use_global=False)
    pw = "check-pw"
    _seed_project_vault(root, pw, {"API_KEY": "val", "OTHER": "x"})
    generate_or_merge_manifest(["API_KEY"], root)
    monkeypatch.chdir(root)

    rc = main(["check"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "OK" in out
    assert "API_KEY" not in out or "Missing" in out  # human form lists counts

    rc = main(["check", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert out.endswith("}\n") and not out.endswith("\n\n")
    assert data["ok"] is True
    assert data["missing"] == []
    assert "API_KEY" in data["required"]


def test_ka_check_missing_required_fails(
    ka_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    ensure_project_scaffold(root, use_global=False)
    _seed_project_vault(root, "pw", {"PRESENT": "v"})
    (root / "amnesia.toml").write_text(
        "[secrets.PRESENT]\nrequired = true\nenv = \"PRESENT\"\n"
        "[secrets.MISSING]\nrequired = true\nenv = \"MISSING\"\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(root)

    rc = main(["check"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "MISSING" in err
    assert "FAIL" in err

    rc = main(["check", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is False
    assert data["missing"] == ["MISSING"]


def test_ka_check_ignores_global_only_secret(
    ka_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """CI rule: a secret only in the global vault does not satisfy ka check."""
    root = tmp_path / "proj"
    root.mkdir()
    ensure_project_scaffold(root, use_global=True)
    # Project vault empty of REQUIRED; global has it.
    _seed_project_vault(root, "proj-pw", {"OTHER": "o"})
    vault_mod.save_vault(
        ka_home / "vault.bin",
        "global-pw",
        {
            "secrets": {"REQUIRED": "from-global"},
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
    )
    (root / "amnesia.toml").write_text(
        '[secrets.REQUIRED]\nrequired = true\nenv = "REQUIRED"\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(root)

    rc = main(["check", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert data["missing"] == ["REQUIRED"]


def test_ka_check_requires_project(
    ka_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.chdir(tmp_path)
    rc = main(["check"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "project vault" in err.lower() or ".amnesia" in err


def test_ka_check_json_without_project_is_one_document(
    ka_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.chdir(tmp_path)
    rc = main(["check", "--json"])
    out = capsys.readouterr().out
    assert rc == 1
    assert json.loads(out)["ok"] is False
    assert out.endswith("}\n") and not out.endswith("\n\n")


def test_ka_run_fails_on_missing_required(
    ka_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    ensure_project_scaffold(root, use_global=False)
    pw = "run-pw"
    _seed_project_vault(root, pw, {"PRESENT": "v"})
    (root / "amnesia.toml").write_text(
        "[secrets.PRESENT]\nrequired = true\nenv = \"PRESENT\"\n"
        "[secrets.NEEDED]\nrequired = true\nenv = \"NEEDED\"\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(root)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": pw)

    # Even requesting a present secret must fail the preflight first.
    rc = main(["run", "--secret", "PRESENT", "--as", "PRESENT=P", "--", sys.executable, "-c", "print(1)"])
    captured = capsys.readouterr()
    assert rc == 1
    assert "NEEDED" in captured.err
    assert "Missing required" in captured.err
    # Never got far enough to run the child successfully.
    assert "1\n" not in captured.out
    assert "1\r\n" not in captured.out

def test_ka_run_ok_when_all_required_present(
    ka_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    ensure_project_scaffold(root, use_global=False)
    pw = "run-pw-ok"
    _seed_project_vault(root, pw, {"API_KEY": "secret-value-xyz", "EXTRA": "e"})
    generate_or_merge_manifest(["API_KEY"], root)
    monkeypatch.chdir(root)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": pw)

    rc = main(
        [
            "run",
            "--secret",
            "API_KEY",
            "--as",
            "API_KEY=API_KEY",
            "--",
            sys.executable,
            "-c",
            "import os; print('ok' if os.environ.get('API_KEY') else 'missing')",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "ok" in out
    assert "secret-value-xyz" not in out  # scrubbed
