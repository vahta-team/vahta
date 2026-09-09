"""PR5: ka scan LEAK discovery + offer-to-import into project vault.

Always uses throwaway KEY_AMNESIA_HOME via `ka_home` — never the
maintainer's real vault. Never asserts on secret *values* in stdout/err
except to confirm they are absent.
"""

from __future__ import annotations

import getpass
import json
from pathlib import Path

import pytest

from key_amnesia import vault as vault_mod
from key_amnesia.cli import main
from key_amnesia.project import ensure_project_scaffold, project_vault_path
from key_amnesia.scan import (
    DEFAULT_EXCLUDE_DIR_NAMES,
    Finding,
    format_human_report,
    format_import_next_line,
    headline,
    importable_findings,
    iter_agent_transcript_files,
    leak_count,
    scan_deep,
    scan_project,
    transcript_line_hit_count,
)
from key_amnesia.paths import audit_log_path


SECRET_VALUE = "super-secret-value-NEVER-PRINT-me"
SECRET_VALUE_2 = "another-leak-value-XYZ9"


@pytest.fixture
def project_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    proj = tmp_path / "project"
    proj.mkdir()
    monkeypatch.chdir(proj)
    return proj


def test_scan_finds_dotenv_names_not_values(ka_home, project_dir, capsys) -> None:
    (project_dir / ".env").write_text(
        f"API_KEY={SECRET_VALUE}\nDB_PASS={SECRET_VALUE_2}\n",
        encoding="utf-8",
    )

    rc = main(["scan", "--no-import", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert rc == 1
    assert data["leak_count"] == 2
    assert data["possible_count"] == 0
    assert data["certain_count"] == 2
    assert data["likely_count"] == 0
    assert data["strict_certain"] == 2
    assert data["strict_high"] == 2
    assert data["strict_paranoid"] == 2
    assert data["findings"][0]["confidence"] == "certain"
    assert "LEAK" in data["headline"]
    assert "--strict high" in data["headline"]
    assert "high-confidence" not in data["headline"]
    assert "reasons" in data["findings"][0]
    assert SECRET_VALUE not in captured.out
    assert SECRET_VALUE_2 not in captured.out
    assert SECRET_VALUE not in captured.err
    assert "next" not in data

    paths = [f["path"] for f in data["findings"]]
    assert any(p.endswith(".env") for p in paths)
    names = data["findings"][0]["secret_names"]
    assert "API_KEY" in names
    assert "DB_PASS" in names


def test_scan_clean_tree_exits_zero(ka_home, project_dir, capsys) -> None:
    (project_dir / "README.md").write_text("# hello\n", encoding="utf-8")

    rc = main(["scan", "--no-import"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "--strict high" in out
    assert "0 certain · 0 likely · 0 possible" in out
    assert "--strict certain" in out
    assert "--strict paranoid" in out
    assert "LEAK" in out


def test_scan_excludes_node_modules_and_venv_by_default(
    ka_home, project_dir
) -> None:
    (project_dir / "node_modules").mkdir()
    (project_dir / "node_modules" / ".env").write_text(
        f"HIDDEN={SECRET_VALUE}\n", encoding="utf-8"
    )
    (project_dir / ".venv").mkdir()
    (project_dir / ".venv" / ".env").write_text(
        f"HIDDEN2={SECRET_VALUE}\n", encoding="utf-8"
    )
    (project_dir / "build").mkdir()
    (project_dir / "build" / ".env").write_text(
        f"HIDDEN3={SECRET_VALUE}\n", encoding="utf-8"
    )
    (project_dir / ".git").mkdir()
    (project_dir / ".git" / "config").write_text(
        "[core]\n\trepositoryformatversion = 0\n", encoding="utf-8"
    )

    findings = scan_project(project_dir)
    assert findings == []
    assert "node_modules" in DEFAULT_EXCLUDE_DIR_NAMES
    assert ".git" in DEFAULT_EXCLUDE_DIR_NAMES


def test_scan_include_excluded_finds_nested_dotenv(
    ka_home, project_dir, capsys
) -> None:
    nm = project_dir / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / ".env").write_text(f"NESTED={SECRET_VALUE}\n", encoding="utf-8")

    rc = main(["scan", "--include-excluded", "--no-import", "--json"])
    data = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert data["leak_count"] == 1
    assert any("node_modules" in f["path"] for f in data["findings"])
    assert SECRET_VALUE not in json.dumps(data)


def test_scan_wide_aliases_include_excluded(
    ka_home, project_dir, capsys
) -> None:
    nm = project_dir / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / ".env").write_text(f"NESTED={SECRET_VALUE}\n", encoding="utf-8")

    rc = main(["scan", "--wide", "--no-import", "--json"])
    data = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert data["leak_count"] == 1
    assert any("node_modules" in f["path"] for f in data["findings"])
    assert SECRET_VALUE not in json.dumps(data)


def test_scan_detects_sensitive_filenames(ka_home, project_dir) -> None:
    (project_dir / "credentials.json").write_text(
        '{"aws_key": "AKIA", "token": "x"}\n', encoding="utf-8"
    )
    (project_dir / ".npmrc").write_text("//registry.npmjs.org/:_authToken=npm_x\n", encoding="utf-8")
    (project_dir / ".pypirc").write_text("[pypi]\npassword = x\n", encoding="utf-8")
    (project_dir / "id_rsa").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
    (project_dir / "id_ed25519").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
    mcp = project_dir / ".cursor"
    mcp.mkdir()
    (mcp / "mcp.json").write_text('{"mcpServers": {}}\n', encoding="utf-8")

    findings = scan_project(project_dir)
    kinds = {f.kind for f in findings}
    assert "credentials.json" in kinds
    assert ".npmrc" in kinds
    assert ".pypirc" in kinds
    assert "ssh_private_key" in kinds
    assert "mcp_config" in kinds
    assert leak_count(findings) >= 5


def test_scan_assignment_pattern_names_only(ka_home, project_dir, capsys) -> None:
    # High-entropy mixed value so the hook heuristic fires.
    (project_dir / "config.py").write_text(
        'api_key = "AbCdEfGh12345678XyZ"\n',
        encoding="utf-8",
    )

    rc = main(["scan", "--no-import", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert rc == 1
    assert data["leak_count"] >= 1
    assert "AbCdEfGh12345678XyZ" not in captured.out
    inline = [f for f in data["findings"] if f["kind"] == "inline"]
    assert inline
    assert "api_key" in inline[0]["secret_names"]


def test_scan_headline_wording() -> None:
    findings = [
        Finding(
            path="/tmp/.env",
            kind="dotenv",
            secret_names=["A", "B"],
            secret_count=2,
            reason="test",
            importable=True,
            confidence="certain",
        )
    ]
    text = headline(findings)
    assert text.startswith("2 LEAKs found (--strict high)")
    assert "your agent can read 2 secrets in this project" in text
    assert "Locally Exposed Agent Keys" in text


def _headline_finding(
    *,
    scope: str,
    secret_count: int = 1,
    confidence: str = "certain",
) -> Finding:
    return Finding(
        path="/tmp/x",
        kind="inline",
        secret_names=["A"],
        secret_count=secret_count,
        reason="test",
        scope=scope,
        confidence=confidence,
    )


def test_scan_headline_all_project() -> None:
    text = headline([_headline_finding(scope="project", secret_count=3)])
    assert "3 secrets in this project" in text
    assert "outside" not in text


def test_scan_headline_all_deep() -> None:
    text = headline([_headline_finding(scope="deep", secret_count=4)])
    assert "4 secrets on this machine, outside this project" in text


def test_scan_headline_mixed_here_plus_away() -> None:
    findings = [
        _headline_finding(scope="project", secret_count=2),
        _headline_finding(scope="deep", secret_count=3),
    ]
    text = headline(findings)
    assert "5 secrets on this machine — 2 in this project, 3 outside it" in text
    assert leak_count(findings) == 5


def test_scan_headline_empty() -> None:
    text = headline([])
    assert text.startswith("0 LEAKs found (--strict high)")
    assert "0 secrets in this project" in text


def test_format_human_report_project_root_only_for_project_scope(
    tmp_path: Path,
) -> None:
    root = tmp_path / "proj"
    deep_only = format_human_report(
        [_headline_finding(scope="deep", secret_count=1)],
        project_root=root,
    )
    assert "Project root:" not in deep_only
    mixed = format_human_report(
        [
            _headline_finding(scope="project", secret_count=1),
            _headline_finding(scope="deep", secret_count=1),
        ],
        project_root=root,
    )
    assert f"Project root: {root}" in mixed
    empty = format_human_report([], project_root=root)
    assert "Project root:" not in empty


def test_scan_deep_home_paths(ka_home, tmp_path, monkeypatch) -> None:
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    (home / ".env").write_text(f"HOME_KEY={SECRET_VALUE}\n", encoding="utf-8")
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_ed25519").write_text("PRIVATE\n", encoding="utf-8")

    findings = scan_deep(home)
    assert any(f.kind == "dotenv" for f in findings)
    assert any(f.kind == "ssh_private_key" for f in findings)
    blob = json.dumps([f.__dict__ for f in findings])
    assert SECRET_VALUE not in blob


def test_scan_cli_deep_flag(ka_home, project_dir, tmp_path, monkeypatch, capsys) -> None:
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    (home / ".npmrc").write_text("_authToken=npm_xxx\n", encoding="utf-8")

    rc = main(["scan", "--deep", "--no-import", "--json"])
    data = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert any(f["scope"] == "deep" for f in data["findings"])


def test_scan_import_yes_into_project_vault(
    ka_home, password, project_dir, monkeypatch, capsys
) -> None:
    ensure_project_scaffold(project_dir)
    vp = project_vault_path(project_dir)
    vault_mod.save_vault(
        vp,
        password,
        {
            "secrets": {},
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
    )
    (project_dir / ".env").write_text(
        f"SCANNED={SECRET_VALUE}\nOTHER={SECRET_VALUE_2}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)

    rc = main(["scan", "--yes"])
    captured = capsys.readouterr()

    assert rc == 1  # still LEAK until sources cleaned; we keep files with --yes
    assert SECRET_VALUE not in captured.out
    assert SECRET_VALUE_2 not in captured.out
    assert SECRET_VALUE not in captured.err
    assert SECRET_VALUE_2 not in captured.err

    payload = vault_mod.load_vault(vp, password)
    assert payload["secrets"]["SCANNED"] == SECRET_VALUE
    assert payload["secrets"]["OTHER"] == SECRET_VALUE_2
    assert (project_dir / ".env").exists()  # --yes skips delete
    assert not (project_dir / ".env.imported").exists()
    assert (project_dir / "amnesia.toml").exists()
    gitignore = (project_dir / ".gitignore").read_text(encoding="utf-8")
    assert ".env*" in gitignore.splitlines()
    audit_text = audit_log_path().read_text(encoding="utf-8")
    assert SECRET_VALUE not in audit_text
    assert SECRET_VALUE_2 not in audit_text
    assert "SCANNED" in audit_text
    assert "scan_import" in audit_text


def test_scan_import_partial_selection(
    ka_home, password, project_dir, monkeypatch
) -> None:
    ensure_project_scaffold(project_dir)
    vp = project_vault_path(project_dir)
    vault_mod.save_vault(
        vp,
        password,
        {
            "secrets": {},
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
    )
    (project_dir / ".env").write_text(f"ONE={SECRET_VALUE}\n", encoding="utf-8")
    (project_dir / ".env.local").write_text(
        f"TWO={SECRET_VALUE_2}\n", encoding="utf-8"
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)
    # Selection "1"; delete? no; rename? no; gitignore? no.
    answers = iter(["1", "n", "n", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    rc = main(["scan"])
    assert rc == 1

    payload = vault_mod.load_vault(vp, password)
    assert "ONE" in payload["secrets"]
    assert "TWO" not in payload["secrets"]


def test_scan_creates_project_vault_when_missing(
    ka_home, password, project_dir, monkeypatch
) -> None:
    (project_dir / ".env").write_text(f"FRESH={SECRET_VALUE}\n", encoding="utf-8")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    # New vault: master + confirm; then --yes path uses getpass for existing...
    # With --yes and no vault: _prompt_new_master_password uses getpass twice.
    pw_answers = iter([password, password])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(pw_answers))

    rc = main(["scan", "--yes"])
    assert rc == 1

    vp = project_vault_path(project_dir)
    assert vp.exists()
    payload = vault_mod.load_vault(vp, password)
    assert payload["secrets"]["FRESH"] == SECRET_VALUE
    assert (project_dir / ".amnesia").is_dir()


def test_importable_findings_filters() -> None:
    findings = [
        Finding("a", "dotenv", ["A"], 1, "", True),
        Finding("b", "dotenv", [], 0, "", False),
        Finding("c", ".npmrc", [], 1, "", False),
    ]
    imp = importable_findings(findings)
    assert len(imp) == 1
    assert imp[0].path == "a"


def test_scan_never_prints_values_human_report(
    ka_home, project_dir, capsys
) -> None:
    (project_dir / ".env").write_text(
        f"TOKEN={SECRET_VALUE}\n", encoding="utf-8"
    )
    rc = main(["scan", "--no-import"])
    captured = capsys.readouterr()
    assert rc == 1
    assert "TOKEN" in captured.out
    assert SECRET_VALUE not in captured.out
    assert SECRET_VALUE not in captured.err
    assert "Next: in your own terminal, ka import" in captured.out
    assert ".env" in captured.out
    assert "ka import FILE" not in captured.out


def _seed_project_vault(project_dir: Path, password: str, secrets: dict | None = None) -> Path:
    ensure_project_scaffold(project_dir)
    vp = project_vault_path(project_dir)
    vault_mod.save_vault(
        vp,
        password,
        {
            "secrets": dict(secrets or {}),
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
    )
    return vp


def test_scan_import_save_failure_leaves_sources_and_vault(
    ka_home, password, project_dir, monkeypatch
) -> None:
    """Vault save must run before any delete/rename (0.4.13 scan dataloss)."""
    vp = _seed_project_vault(project_dir, password)
    before = vp.read_bytes()
    env = project_dir / ".env"
    local = project_dir / ".env.local"
    env.write_text(f"ONE={SECRET_VALUE}\n", encoding="utf-8")
    local.write_text(f"TWO={SECRET_VALUE_2}\n", encoding="utf-8")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)

    def _boom(*_a, **_k):
        raise vault_mod.VaultError("simulated save failure")

    monkeypatch.setattr("key_amnesia.cli.save_vault", _boom)

    rc = main(["scan", "--yes"])
    assert rc == 1
    assert env.exists()
    assert local.exists()
    assert not (project_dir / ".env.imported").exists()
    assert not (project_dir / ".env.local.imported").exists()
    assert vp.read_bytes() == before
    # in-memory merge must not have reached disk; names sidecar unchanged too.


def test_scan_import_yes_collision_skips_existing(
    ka_home, password, project_dir, monkeypatch
) -> None:
    vp = _seed_project_vault(project_dir, password, {"SCANNED": "keep-me-old"})
    (project_dir / ".env").write_text(
        f"SCANNED={SECRET_VALUE}\nOTHER={SECRET_VALUE_2}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)

    rc = main(["scan", "--yes"])
    assert rc == 1
    payload = vault_mod.load_vault(vp, password)
    assert payload["secrets"]["SCANNED"] == "keep-me-old"
    assert payload["secrets"]["OTHER"] == SECRET_VALUE_2
    assert (project_dir / ".env").exists()


def test_scan_import_interactive_collision_default_skip(
    ka_home, password, project_dir, monkeypatch
) -> None:
    vp = _seed_project_vault(project_dir, password, {"SCANNED": "keep-me-old"})
    (project_dir / ".env").write_text(
        f"SCANNED={SECRET_VALUE}\nOTHER={SECRET_VALUE_2}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)
    # Enter=all; collision skip; delete no; rename no; gitignore no.
    answers = iter(["", "", "n", "n", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    rc = main(["scan"])
    assert rc == 1
    payload = vault_mod.load_vault(vp, password)
    assert payload["secrets"]["SCANNED"] == "keep-me-old"
    assert payload["secrets"]["OTHER"] == SECRET_VALUE_2
    assert (project_dir / ".env").exists()


def test_scan_import_delete_requires_both_confirms(
    ka_home, password, project_dir, monkeypatch
) -> None:
    vp = _seed_project_vault(project_dir, password)
    env = project_dir / ".env"
    env.write_text(f"FRESH={SECRET_VALUE}\n", encoding="utf-8")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)
    answers = iter(["", "y", "y", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    rc = main(["scan"])
    assert rc == 0
    assert not env.exists()
    payload = vault_mod.load_vault(vp, password)
    assert payload["secrets"]["FRESH"] == SECRET_VALUE


def test_scan_import_declining_second_delete_keeps_file(
    ka_home, password, project_dir, monkeypatch
) -> None:
    _seed_project_vault(project_dir, password)
    env = project_dir / ".env"
    env.write_text(f"FRESH={SECRET_VALUE}\n", encoding="utf-8")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)
    answers = iter(["", "y", "n", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    rc = main(["scan"])
    assert rc == 1
    assert env.exists()


def test_scan_import_rename_clears_exit(
    ka_home, password, project_dir, monkeypatch
) -> None:
    vp = _seed_project_vault(project_dir, password)
    env = project_dir / ".env"
    env.write_text(f"FRESH={SECRET_VALUE}\n", encoding="utf-8")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)
    answers = iter(["", "n", "y", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    rc = main(["scan"])
    assert rc == 0
    assert not env.exists()
    assert (project_dir / ".env.imported").exists()
    payload = vault_mod.load_vault(vp, password)
    assert payload["secrets"]["FRESH"] == SECRET_VALUE


def test_scan_non_tty_no_offer_no_getpass(
    ka_home, project_dir, monkeypatch, capsys
) -> None:
    (project_dir / ".env").write_text(f"TOKEN={SECRET_VALUE}\n", encoding="utf-8")
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr(
        getpass,
        "getpass",
        lambda prompt="": (_ for _ in ()).throw(AssertionError("getpass")),
    )

    rc = main(["scan"])
    captured = capsys.readouterr()
    assert rc == 1
    assert "Selection" not in captured.out
    assert SECRET_VALUE not in captured.out
    assert SECRET_VALUE not in captured.err
    assert "LEAK" in captured.out


def test_scan_import_yes_one_password_despite_global_vault(
    seeded_vault, password, project_dir, monkeypatch
) -> None:
    """use_global scaffold must not prompt for the global vault during scan import."""
    vp = _seed_project_vault(project_dir, password)
    (project_dir / ".env").write_text(f"PROJ={SECRET_VALUE}\n", encoding="utf-8")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    calls: list[str] = []

    def _gp(prompt: str = "") -> str:
        calls.append(prompt)
        return password

    monkeypatch.setattr(getpass, "getpass", _gp)

    rc = main(["scan", "--yes"])
    assert rc == 1
    assert len(calls) == 1
    payload = vault_mod.load_vault(vp, password)
    assert payload["secrets"]["PROJ"] == SECRET_VALUE
    global_payload = vault_mod.load_vault(seeded_vault, password)
    assert "PROJ" not in global_payload["secrets"]


def test_scan_import_yes_creating_vault_does_not_prompt_global(
    seeded_vault, password, project_dir, monkeypatch
) -> None:
    (project_dir / ".env").write_text(f"FRESH={SECRET_VALUE}\n", encoding="utf-8")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    calls: list[str] = []

    def _gp(prompt: str = "") -> str:
        calls.append(prompt)
        return password

    monkeypatch.setattr(getpass, "getpass", _gp)

    rc = main(["scan", "--yes"])
    assert rc == 1
    # New vault: master + confirm. Not a third global-vault prompt.
    assert len(calls) == 2
    vp = project_vault_path(project_dir)
    payload = vault_mod.load_vault(vp, password)
    assert payload["secrets"]["FRESH"] == SECRET_VALUE


def test_format_human_report_import_footer_uses_discovered_paths(
    tmp_path: Path,
) -> None:
    env = tmp_path / ".env"
    local = tmp_path / ".env.local"
    planted = SECRET_VALUE
    findings = [
        Finding(
            path=str(env),
            kind="dotenv",
            secret_names=["A"],
            secret_count=1,
            reason="dotenv file",
            importable=True,
            confidence="certain",
        ),
        Finding(
            path=str(local),
            kind="dotenv",
            secret_names=["B"],
            secret_count=1,
            reason="dotenv file",
            importable=True,
            confidence="certain",
        ),
    ]
    text = format_human_report(findings, project_root=tmp_path)
    assert "Next: in your own terminal, ka import .env .env.local" in text
    assert planted not in text
    assert "ka import FILE" not in text
    line = format_import_next_line(findings, project_root=tmp_path)
    assert line == "Next: in your own terminal, ka import .env .env.local"


def test_format_human_report_no_importable_drops_generic_file_line(
    tmp_path: Path,
) -> None:
    findings = [
        Finding(
            path=str(tmp_path / "id_rsa"),
            kind="ssh_private_key",
            secret_names=[],
            secret_count=1,
            reason="ssh key",
            importable=False,
            confidence="certain",
        )
    ]
    text = format_human_report(findings, project_root=tmp_path)
    assert "ka import" not in text
    assert "Detection is advisory" in text
    assert format_import_next_line(findings, project_root=tmp_path) is None


# --- Agent session transcript scan (--deep) ---

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "agent_transcripts"

# Planted fake secrets in fixtures — must never appear in scan output.
_TRANSCRIPT_PLANTED = (
    "sk-ant-FAKESECRET_for_tests_only_xx",
    "AbCdEfGh12345678XyZ",
    "FAKEBEARERTOKEN123456",
    "sk-proj-NOTAREALKEY_but_long_enough_abc",
    "npm_abcdefghijklmnopqrstuv",
)


def _assert_no_planted(blob: str) -> None:
    for secret in _TRANSCRIPT_PLANTED:
        assert secret not in blob


def _install_transcript_home(home: Path) -> dict[str, Path]:
    """Lay out Claude / Codex / Copilot transcript trees under fake home."""
    claude_proj = home / ".claude" / "projects" / "C--tmp-demo"
    claude_proj.mkdir(parents=True)
    session = claude_proj / "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.jsonl"
    session.write_text(
        (_FIXTURES / "claude" / "session-with-leaks.jsonl").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    clean = claude_proj / "ffffffff-1111-2222-3333-444444444444.jsonl"
    clean.write_text(
        (_FIXTURES / "claude" / "session-clean.jsonl").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    sub = (
        claude_proj
        / "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        / "subagents"
        / "agent-deadbeef.jsonl"
    )
    sub.parent.mkdir(parents=True)
    sub.write_text(
        (_FIXTURES / "claude" / "subagent-with-leak.jsonl").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )

    codex_day = home / ".codex" / "sessions" / "2026" / "01" / "01"
    codex_day.mkdir(parents=True)
    codex = codex_day / "rollout-with-leak.jsonl"
    codex.write_text(
        (_FIXTURES / "codex" / "rollout-with-leak.jsonl").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )

    copilot = home / ".copilot" / "session-state" / "sess-1" / "events.jsonl"
    copilot.parent.mkdir(parents=True)
    copilot.write_text(
        (_FIXTURES / "copilot" / "events-with-leak.jsonl").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )

    return {
        "claude_session": session,
        "claude_clean": clean,
        "claude_subagent": sub,
        "codex": codex,
        "copilot": copilot,
    }


def test_scan_deep_agent_transcripts_line_hits(
    ka_home, tmp_path, monkeypatch
) -> None:
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    paths = _install_transcript_home(home)

    findings = scan_deep(home)
    transcripts = [f for f in findings if f.kind == "agent_session_transcript"]

    session_fs = [f for f in transcripts if Path(f.path) == paths["claude_session"]]
    assert session_fs
    # Line 3 (sk-ant prefix → certain) and 5 (nested API_KEY → likely).
    assert sorted(n for f in session_fs for n in f.hit_lines) == [3, 5]
    assert sum(
        f.secret_count for f in session_fs if f.confidence in ("certain", "likely")
    ) == 2
    assert any(n.upper() == "API_KEY" for f in session_fs for n in f.secret_names)

    assert not any(Path(f.path) == paths["claude_clean"] for f in transcripts)

    sub_fs = [f for f in transcripts if Path(f.path) == paths["claude_subagent"]]
    assert any(1 in f.hit_lines for f in sub_fs)
    assert sum(f.secret_count for f in sub_fs if f.confidence in ("certain", "likely")) == 1

    codex_fs = [f for f in transcripts if Path(f.path) == paths["codex"]]
    assert sum(f.secret_count for f in codex_fs if f.confidence in ("certain", "likely")) >= 1
    assert any(1 in f.hit_lines for f in codex_fs)

    copilot_fs = [f for f in transcripts if Path(f.path) == paths["copilot"]]
    assert any(f.hit_lines == [1] for f in copilot_fs)

    assert transcript_line_hit_count(findings) == sum(
        f.secret_count
        for f in transcripts
        if f.confidence in ("certain", "likely")
    )
    blob = json.dumps([f.__dict__ for f in findings])
    _assert_no_planted(blob)


def test_scan_default_skips_home_transcripts(
    ka_home, project_dir, tmp_path, monkeypatch
) -> None:
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    _install_transcript_home(home)

    findings = scan_project(project_dir)
    assert not any(f.kind == "agent_session_transcript" for f in findings)


def test_scan_cli_deep_transcripts_no_values(
    ka_home, project_dir, tmp_path, monkeypatch, capsys
) -> None:
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    _install_transcript_home(home)

    rc = main(["scan", "--deep", "--no-import", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert rc == 1
    assert data["transcript_line_hits"] >= 4
    assert any(f["kind"] == "agent_session_transcript" for f in data["findings"])
    assert "advisory" in data["detection_note"].lower()
    _assert_no_planted(captured.out)
    _assert_no_planted(captured.err)
    _assert_no_planted(json.dumps(data))

    human_rc = main(["scan", "--deep", "--no-import"])
    human = capsys.readouterr().out
    assert human_rc == 1
    assert "agent session transcripts" in human
    assert "advisory" in human.lower()
    _assert_no_planted(human)


def test_iter_agent_transcript_files_globs(tmp_path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    paths = _install_transcript_home(home)
    found = {p.resolve() for p in iter_agent_transcript_files(home)}
    assert paths["claude_session"].resolve() in found
    assert paths["claude_subagent"].resolve() in found
    assert paths["codex"].resolve() in found
    assert paths["copilot"].resolve() in found
    assert paths["claude_clean"].resolve() in found  # present on disk; clean has no LEAK


def test_scan_deep_progress_on_stderr(
    ka_home, project_dir, tmp_path, monkeypatch, capsys
) -> None:
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    _install_transcript_home(home)

    rc = main(["scan", "--deep", "--no-import", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert rc == 1
    assert "agent transcripts" in captured.err
    assert "API_KEY" not in captured.err
    _assert_no_planted(captured.err)
    assert data["headline"]


def test_scan_deep_quiet_silences_progress(
    ka_home, project_dir, tmp_path, monkeypatch, capsys
) -> None:
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    _install_transcript_home(home)

    rc = main(["scan", "--deep", "--no-import", "--json", "--quiet"])
    captured = capsys.readouterr()
    json.loads(captured.out)
    assert rc == 1
    assert captured.err == ""


def test_scan_deep_intra_file_progress(
    ka_home, project_dir, tmp_path, monkeypatch, capsys
) -> None:
    from key_amnesia.scan import _PROGRESS_LINE_EVERY

    home = tmp_path / "fake-home"
    claude = home / ".claude" / "projects" / "big"
    claude.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    lines = ['{"text": "ok"}\n'] * (_PROGRESS_LINE_EVERY + 50)
    (claude / "session.jsonl").write_text("".join(lines), encoding="utf-8")

    rc = main(["scan", "--deep", "--no-import", "--json"])
    captured = capsys.readouterr()
    json.loads(captured.out)
    assert rc == 0
    assert str(_PROGRESS_LINE_EVERY) in captured.err
    assert "session.jsonl" in captured.err
