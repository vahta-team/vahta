"""`ka setup --uninstall`: removes only what `ka setup` wrote. Temp HOME only."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from key_amnesia import setup_cmd as sc
from key_amnesia import uninstall_cmd as un
from key_amnesia.cli import main
from key_amnesia.harness_permissions import (
    CURSOR_ALLOW_INSTRUCTION,
    claude_allow_matchers,
    opencode_plugin_dest,
)

VAHTA = {"type": "command", "command": "/opt/vahta/bin/vahta-hook --check"}
OTHER = {"type": "command", "command": "/usr/local/bin/lint-guard"}


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setattr(sc.Path, "home", staticmethod(lambda: h))
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("USERPROFILE", str(h))
    monkeypatch.setenv("KEY_AMNESIA_HOME", str(tmp_path / "ka-data"))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    return h


def _write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _foreign_claude() -> dict:
    return {
        "model": "opus",
        "permissions": {"allow": ["Bash(git status:*)"], "deny": ["Read(./.env)"]},
        "hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [OTHER]},
                {"matcher": "Bash|Write", "hooks": [VAHTA]},
            ],
            "Stop": [{"hooks": [OTHER]}],
        },
    }


def _foreign_cursor_hooks() -> dict:
    return {
        "version": 1,
        "hooks": {
            "preToolUse": [
                {"command": "/x/vahta-hook", "matcher": "Shell"},
                {"command": "other-tool", "matcher": "Write"},
            ]
        },
    }


def _seed_foreign(home: Path) -> dict[str, dict]:
    docs = {
        "claude": _foreign_claude(),
        "codex": {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [VAHTA, OTHER]}]}},
        "cursor": _foreign_cursor_hooks(),
        "cursor_perm": {"terminalAllowlist": ["git status"]},
        "cursor_cli": {"permissions": {"allow": ["Shell(ls)"], "deny": []}},
        "opencode": {
            "plugin": ["./plugins/mine.js"],
            "permission": {"bash": {"git push *": "ask"}},
        },
    }
    _write(home / ".claude" / "settings.json", docs["claude"])
    _write(home / ".codex" / "hooks.json", docs["codex"])
    _write(home / ".cursor" / "hooks.json", docs["cursor"])
    _write(home / ".cursor" / "permissions.json", docs["cursor_perm"])
    _write(home / ".cursor" / "cli-config.json", docs["cursor_cli"])
    _write(home / ".config" / "opencode" / "opencode.json", docs["opencode"])
    return docs


def _install(home: Path) -> None:
    assert main(["setup", "--skills-only"]) == 0
    assert main(["setup", "--hook-only"]) == 0
    assert main(["setup", "--permissions-only", "--yes"]) == 0


def _paths(home: Path) -> dict[str, Path]:
    return {
        "claude": home / ".claude" / "settings.json",
        "codex": home / ".codex" / "hooks.json",
        "cursor": home / ".cursor" / "hooks.json",
        "cursor_perm": home / ".cursor" / "permissions.json",
        "cursor_cli": home / ".cursor" / "cli-config.json",
        "opencode": home / ".config" / "opencode" / "opencode.json",
    }


def test_install_then_uninstall_restores_foreign_content(home: Path, capsys) -> None:
    docs = _seed_foreign(home)
    _install(home)
    paths = _paths(home)
    # setup really did write into the mixed files
    assert _read(paths["claude"]) != docs["claude"]
    assert opencode_plugin_dest(home).exists()

    assert main(["setup", "--uninstall"]) == 0
    out = capsys.readouterr().out
    for key, path in paths.items():
        assert _read(path) == docs[key], key
    # order kept: the unrelated hook stays ahead of the vahta-hook group
    pre = _read(paths["claude"])["hooks"]["PreToolUse"]
    assert pre[0]["hooks"] == [OTHER] and pre[1]["hooks"] == [VAHTA]
    assert not opencode_plugin_dest(home).exists()
    for host in ("claude", "cursor", "agents"):
        for name in sc.SKILL_NAMES:
            assert not (home / f".{host}" / "skills" / name).exists()
    assert not (home / ".codex" / "skills" / sc.SKILL_NAMES[0]).exists()
    assert "claude:" in out and "settings.json" in out and "never" in out.lower()


def test_hook_only_file_collapses_but_keeps_foreign_keys(home: Path) -> None:
    _write(home / ".claude" / "settings.json", {"model": "opus"})
    assert main(["setup", "--hook-only"]) == 0
    assert main(["setup", "--uninstall"]) == 0
    assert _read(home / ".claude" / "settings.json") == {"model": "opus"}


def test_second_uninstall_changes_nothing(home: Path, capsys) -> None:
    _seed_foreign(home)
    _install(home)
    assert main(["setup", "--uninstall"]) == 0
    snap = {p: p.read_bytes() for p in home.rglob("*") if p.is_file()}
    capsys.readouterr()
    assert main(["setup", "--uninstall"]) == 0
    assert "nothing to remove" in capsys.readouterr().out.lower()
    assert snap == {p: p.read_bytes() for p in home.rglob("*") if p.is_file()}


def test_nothing_installed_exits_zero(home: Path, capsys) -> None:
    assert main(["setup", "--uninstall"]) == 0
    assert "nothing to remove" in capsys.readouterr().out.lower()
    assert list(home.rglob("*")) == []


def test_dry_run_writes_nothing(home: Path, capsys) -> None:
    _seed_foreign(home)
    _install(home)
    snap = {p: p.read_bytes() for p in home.rglob("*") if p.is_file()}
    capsys.readouterr()
    assert main(["setup", "--uninstall", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "would remove" in out
    assert snap == {p: p.read_bytes() for p in home.rglob("*") if p.is_file()}
    assert not list(home.rglob("*.ka-backup"))


def test_malformed_file_left_untouched_others_processed(home: Path, capsys) -> None:
    _seed_foreign(home)
    _install(home)
    bad = home / ".cursor" / "hooks.json"
    bad.write_text('{"hooks": {"preToolUse": [ oops', encoding="utf-8")
    before = bad.read_bytes()
    capsys.readouterr()
    assert main(["setup", "--uninstall"]) == 1
    cap = capsys.readouterr()
    assert bad.read_bytes() == before
    assert not bad.with_name("hooks.json.ka-backup").exists()
    assert "hooks.json" in cap.out + cap.err
    assert "key-amnesia-hook" not in (home / ".claude" / "settings.json").read_text()


def test_non_object_json_left_untouched(home: Path) -> None:
    p = home / ".codex" / "hooks.json"
    p.parent.mkdir(parents=True)
    p.write_text("[1, 2]", encoding="utf-8")
    assert main(["setup", "--uninstall"]) == 1
    assert p.read_text(encoding="utf-8") == "[1, 2]"


def test_edited_skill_kept_without_force(home: Path) -> None:
    assert main(["setup", "--skills-only"]) == 0
    name = sc.SKILL_NAMES[0]
    edited = home / ".claude" / "skills" / name / "SKILL.md"
    edited.write_text("my own notes\n", encoding="utf-8")
    assert main(["setup", "--uninstall"]) == 0
    assert edited.read_text(encoding="utf-8") == "my own notes\n"
    # the unedited copies are gone
    assert not (home / ".cursor" / "skills" / name).exists()
    assert not (home / ".claude" / "skills" / sc.SKILL_NAMES[1]).exists()

    assert main(["setup", "--uninstall", "--force"]) == 0
    assert not edited.exists()
    assert not edited.parent.exists()


def test_edited_skill_message_names_force(home: Path, capsys) -> None:
    assert main(["setup", "--skills-only"]) == 0
    p = home / ".agents" / "skills" / sc.SKILL_NAMES[2] / "SKILL.md"
    p.write_text("changed", encoding="utf-8")
    capsys.readouterr()
    main(["setup", "--uninstall"])
    cap = capsys.readouterr()
    assert "kept" in cap.out + cap.err and "--force" in cap.out + cap.err


def test_skill_dir_with_extra_files_survives(home: Path) -> None:
    assert main(["setup", "--skills-only"]) == 0
    d = home / ".claude" / "skills" / sc.SKILL_NAMES[0]
    (d / "notes.txt").write_text("mine", encoding="utf-8")
    assert main(["setup", "--uninstall"]) == 0
    assert not (d / "SKILL.md").exists()
    assert (d / "notes.txt").read_text(encoding="utf-8") == "mine"


def test_permissions_removed_exactly(home: Path) -> None:
    mine = "Bash(ka run:*) -- but mine"  # near-miss, not ours
    same_shape = "Bash(ka frobnicate:*)"
    ours = claude_allow_matchers()[0]
    _write(
        home / ".claude" / "settings.json",
        {"permissions": {"allow": [mine, same_shape]}},
    )
    assert main(["setup", "--hook-only"]) == 0
    assert main(["setup", "--permissions-only", "--yes"]) == 0
    allow = _read(home / ".claude" / "settings.json")["permissions"]["allow"]
    assert ours in allow and len(allow) > 2
    assert main(["setup", "--uninstall"]) == 0
    data = _read(home / ".claude" / "settings.json")
    assert data == {"permissions": {"allow": [mine, same_shape]}}


def test_opencode_value_changed_by_user_is_kept(home: Path) -> None:
    _write(home / ".config" / "opencode" / "opencode.json", {})
    assert main(["setup", "--hook-only"]) == 0
    assert main(["setup", "--permissions-only", "--yes"]) == 0
    path = home / ".config" / "opencode" / "opencode.json"
    data = _read(path)
    key = next(k for k, v in data["permission"]["bash"].items() if v == "allow")
    data["permission"]["bash"][key] = "ask"
    _write(path, data)
    assert main(["setup", "--uninstall"]) == 0
    assert _read(path) == {"permission": {"bash": {key: "ask"}}}


def test_cursor_instruction_removed(home: Path) -> None:
    _write(home / ".cursor" / "permissions.json", {"autoRun": {"allow_instructions": ["mine"]}})
    assert main(["setup", "--hook-only"]) == 0
    assert main(["setup", "--permissions-only", "--yes"]) == 0
    assert CURSOR_ALLOW_INSTRUCTION in _read(home / ".cursor" / "permissions.json")["autoRun"][
        "allow_instructions"
    ]
    assert main(["setup", "--uninstall"]) == 0
    assert _read(home / ".cursor" / "permissions.json") == {
        "autoRun": {"allow_instructions": ["mine"]}
    }


def test_backup_written_once_and_holds_original(home: Path) -> None:
    docs = _seed_foreign(home)
    _install(home)
    settings = home / ".claude" / "settings.json"
    installed = settings.read_text(encoding="utf-8")
    assert main(["setup", "--uninstall"]) == 0
    backup = settings.with_name("settings.json.ka-backup")
    assert backup.read_text(encoding="utf-8") == installed
    # an existing backup is never overwritten
    backup.write_text("keep me", encoding="utf-8")
    sc.cmd_setup(
        __import__("argparse").Namespace(skills_only=False, hook_only=True)
    )
    assert main(["setup", "--uninstall"]) == 0
    assert backup.read_text(encoding="utf-8") == "keep me"
    assert _read(settings) == docs["claude"]


def test_foreign_opencode_plugin_file_kept(home: Path) -> None:
    dest = opencode_plugin_dest(home)
    dest.parent.mkdir(parents=True)
    dest.write_text("// someone else's plugin\n", encoding="utf-8")
    assert main(["setup", "--uninstall"]) == 0
    assert dest.exists()


def test_vault_and_data_untouched(home: Path, tmp_path: Path, monkeypatch) -> None:
    data = tmp_path / "ka-data"
    data.mkdir()
    vault = data / "vault.bin"
    vault.write_bytes(b"\x00opaque")
    cfg = data / "config.json"
    cfg.write_text('{"terminal": "foot"}', encoding="utf-8")
    project = home / "proj" / ".amnesia"
    project.mkdir(parents=True)
    (project / "vault.bin").write_bytes(b"\x01opaque")
    snap = {p: p.read_bytes() for p in list(data.rglob("*")) + list(project.rglob("*")) if p.is_file()}
    _seed_foreign(home)
    _install(home)
    # setup writes the permissions manifest into the data dir; uninstall must not touch it
    manifest = data / "permissions-manifest.json"
    manifest_bytes = manifest.read_bytes() if manifest.exists() else None
    assert main(["setup", "--uninstall"]) == 0
    for p, b in snap.items():
        assert p.read_bytes() == b
    if manifest_bytes is not None:
        assert manifest.read_bytes() == manifest_bytes


def test_symlinked_config_is_edited_in_place(home: Path, tmp_path: Path) -> None:
    real = tmp_path / "dotfiles" / "settings.json"
    _write(real, _foreign_claude())
    link = home / ".claude" / "settings.json"
    link.parent.mkdir(parents=True)
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert main(["setup", "--hook-only"]) == 0
    assert main(["setup", "--uninstall"]) == 0
    assert link.is_symlink()
    assert _read(real) == _foreign_claude()


def test_flag_validation(home: Path) -> None:
    assert main(["setup", "--dry-run"]) == 2
    assert main(["setup", "--force"]) == 2
    assert main(["setup", "--uninstall", "--hook-only"]) == 2
    assert not list(home.rglob("*"))


def test_help_states_untouched_data(capsys) -> None:
    with pytest.raises(SystemExit):
        main(["setup", "--help"])
    text = " ".join(capsys.readouterr().out.split())
    assert "Never touches the vault" in text and ".amnesia/" in text
    assert "never" in un.NEVER_TOUCHED.lower()
