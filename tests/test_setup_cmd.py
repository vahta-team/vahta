"""`ka setup`: skills copy, hook config merge, PATH check."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

import pytest

from key_amnesia import setup_cmd as sc
from key_amnesia.cli import main


def _ns(**kwargs) -> argparse.Namespace:
    defaults = {"skills_only": False, "hook_only": False}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(sc.Path, "home", staticmethod(lambda: home))
    return home


# --- skills land with correct content ---------------------------------------


def test_setup_copies_all_skills_to_both_hosts(fake_home: Path) -> None:
    rc = sc.cmd_setup(_ns())
    assert rc == 0
    for host_dir in ("claude", "cursor", "agents"):
        root = fake_home / f".{host_dir}" / "skills"
        for name in sc.SKILL_NAMES:
            dest = root / name / "SKILL.md"
            assert dest.exists()
            content = dest.read_text(encoding="utf-8")
            assert content.startswith("---\nname: " + name)
    for name in sc.SKILL_NAMES:
        dest = fake_home / ".codex" / "skills" / name / "SKILL.md"
        assert dest.exists()
        assert dest.read_text(encoding="utf-8").startswith("---\nname: " + name)


def test_setup_skill_content_matches_package_source(fake_home: Path) -> None:
    sc.cmd_setup(_ns())
    from importlib import resources

    root = resources.files("key_amnesia") / "skills"
    for name in sc.SKILL_NAMES:
        expected = (root / name / "SKILL.md").read_text(encoding="utf-8")
        installed = (fake_home / ".claude" / "skills" / name / "SKILL.md").read_text(
            encoding="utf-8"
        )
        assert installed == expected


def test_setup_overwrites_on_rerun_with_stale_content(fake_home: Path) -> None:
    sc.cmd_setup(_ns())
    dest = fake_home / ".claude" / "skills" / sc.SKILL_NAMES[0] / "SKILL.md"
    dest.write_text("stale content that should be replaced", encoding="utf-8")

    sc.cmd_setup(_ns())
    assert dest.read_text(encoding="utf-8") != "stale content that should be replaced"


def test_setup_skills_only_skips_hook_files(fake_home: Path) -> None:
    sc.cmd_setup(_ns(skills_only=True))
    assert not (fake_home / ".claude" / "settings.json").exists()
    assert not (fake_home / ".cursor" / "hooks.json").exists()
    assert not (fake_home / ".codex" / "hooks.json").exists()
    assert (fake_home / ".claude" / "skills" / sc.SKILL_NAMES[0] / "SKILL.md").exists()
    assert (fake_home / ".agents" / "skills" / sc.SKILL_NAMES[0] / "SKILL.md").exists()
    assert (fake_home / ".codex" / "skills" / sc.SKILL_NAMES[0] / "SKILL.md").exists()


def test_setup_hook_only_skips_skills(fake_home: Path) -> None:
    sc.cmd_setup(_ns(hook_only=True))
    assert not (fake_home / ".claude" / "skills").exists()
    assert not (fake_home / ".cursor" / "skills").exists()
    assert not (fake_home / ".agents" / "skills").exists()
    assert not (fake_home / ".codex" / "skills").exists()
    assert (fake_home / ".claude" / "settings.json").exists()
    assert (fake_home / ".cursor" / "hooks.json").exists()
    assert (fake_home / ".codex" / "hooks.json").exists()


def test_setup_rejects_both_only_flags(fake_home: Path, capsys) -> None:
    rc = sc.cmd_setup(_ns(skills_only=True, hook_only=True))
    assert rc == 2
    assert "mutually exclusive" in capsys.readouterr().err


# --- Claude settings.json merge ---------------------------------------------


def test_claude_settings_merge_preserves_unrelated_keys(fake_home: Path) -> None:
    path = fake_home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "some_other_setting": True,
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "some-other-hook"}],
                        }
                    ],
                    "PostToolUse": [{"matcher": "*", "hooks": []}],
                },
            }
        ),
        encoding="utf-8",
    )

    sc.cmd_setup(_ns(hook_only=True))

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["some_other_setting"] is True
    assert "PostToolUse" in data["hooks"]
    matchers = [entry["matcher"] for entry in data["hooks"]["PreToolUse"]]
    assert "Bash" in matchers  # unrelated hook untouched
    commands = [
        h["command"]
        for entry in data["hooks"]["PreToolUse"]
        for h in entry["hooks"]
    ]
    assert "some-other-hook" in commands
    assert any("key-amnesia" in c or "secret_guard" in c for c in commands)


def test_claude_settings_merge_idempotent(fake_home: Path) -> None:
    sc.cmd_setup(_ns(hook_only=True))
    path = fake_home / ".claude" / "settings.json"
    first = json.loads(path.read_text(encoding="utf-8"))

    sc.cmd_setup(_ns(hook_only=True))
    second = json.loads(path.read_text(encoding="utf-8"))

    assert len(second["hooks"]["PreToolUse"]) == len(first["hooks"]["PreToolUse"]) == 1


def test_claude_settings_malformed_recovers_with_fresh_merge(fake_home: Path) -> None:
    path = fake_home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_text("{ not valid json !!", encoding="utf-8")

    rc = sc.cmd_setup(_ns(hook_only=True))
    assert rc == 0
    data = json.loads(path.read_text(encoding="utf-8"))
    assert len(data["hooks"]["PreToolUse"]) == 1


# --- Cursor hooks.json merge -------------------------------------------------


def test_cursor_hooks_merge_preserves_unrelated_entries(fake_home: Path) -> None:
    path = fake_home / ".cursor" / "hooks.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "hooks": {
                    "preToolUse": [{"command": "./other-hook.sh", "matcher": "Shell"}],
                    "afterFileEdit": [{"command": "./format.sh"}],
                },
            }
        ),
        encoding="utf-8",
    )

    sc.cmd_setup(_ns(hook_only=True))

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert "afterFileEdit" in data["hooks"]
    commands = [e["command"] for e in data["hooks"]["preToolUse"]]
    assert "./other-hook.sh" in commands
    assert any("key-amnesia" in c or "secret_guard" in c for c in commands)


def test_cursor_hooks_merge_idempotent(fake_home: Path) -> None:
    sc.cmd_setup(_ns(hook_only=True))
    path = fake_home / ".cursor" / "hooks.json"
    first = json.loads(path.read_text(encoding="utf-8"))

    sc.cmd_setup(_ns(hook_only=True))
    second = json.loads(path.read_text(encoding="utf-8"))

    assert len(second["hooks"]["preToolUse"]) == len(first["hooks"]["preToolUse"]) == 1


def test_cursor_hooks_missing_file_creates_fresh(fake_home: Path) -> None:
    rc = sc.cmd_setup(_ns(hook_only=True))
    assert rc == 0
    path = fake_home / ".cursor" / "hooks.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert data["hooks"]["preToolUse"][0]["matcher"] == sc.CURSOR_MATCHER


def test_claude_hooks_matcher_is_bash_write_edit(fake_home: Path) -> None:
    sc.cmd_setup(_ns(hook_only=True))
    path = fake_home / ".claude" / "settings.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["hooks"]["PreToolUse"][0]["matcher"] == sc.CLAUDE_MATCHER


# --- Codex hooks.json merge -------------------------------------------------


def test_codex_hooks_merge_preserves_unrelated_entries(fake_home: Path) -> None:
    path = fake_home / ".codex" / "hooks.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "description": "workspace hooks",
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "some-other-hook"}],
                        }
                    ],
                    "PostToolUse": [{"matcher": "*", "hooks": []}],
                },
            }
        ),
        encoding="utf-8",
    )

    sc.cmd_setup(_ns(hook_only=True))

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["description"] == "workspace hooks"
    assert "PostToolUse" in data["hooks"]
    matchers = [entry["matcher"] for entry in data["hooks"]["PreToolUse"]]
    assert "Bash" in matchers
    commands = [
        h["command"]
        for entry in data["hooks"]["PreToolUse"]
        for h in entry["hooks"]
    ]
    assert "some-other-hook" in commands
    assert any("key-amnesia" in c or "secret_guard" in c for c in commands)


def test_codex_hooks_merge_idempotent(fake_home: Path) -> None:
    sc.cmd_setup(_ns(hook_only=True))
    path = fake_home / ".codex" / "hooks.json"
    first = json.loads(path.read_text(encoding="utf-8"))

    sc.cmd_setup(_ns(hook_only=True))
    second = json.loads(path.read_text(encoding="utf-8"))

    assert len(second["hooks"]["PreToolUse"]) == len(first["hooks"]["PreToolUse"]) == 1


def test_codex_hooks_matcher_includes_apply_patch(fake_home: Path) -> None:
    sc.cmd_setup(_ns(hook_only=True))
    path = fake_home / ".codex" / "hooks.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["hooks"]["PreToolUse"][0]["matcher"] == sc.CODEX_MATCHER


def test_codex_home_env_redirects_skills_and_hooks(
    fake_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    custom = tmp_path / "custom-codex"
    monkeypatch.setenv("CODEX_HOME", str(custom))
    sc.cmd_setup(_ns())
    assert (custom / "skills" / sc.SKILL_NAMES[0] / "SKILL.md").exists()
    assert (custom / "hooks.json").exists()
    assert not (fake_home / ".codex" / "hooks.json").exists()


# --- PATH check --------------------------------------------------------------


def test_check_path_positive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name, path=None: f"/usr/bin/{name}" if name == "ka" else None)
    result = sc._check_path()
    assert "ka on PATH" in result


def test_check_path_negative(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name, path=None: None)
    result = sc._check_path()
    assert "not found on PATH" in result


def test_check_path_falls_back_to_key_amnesia_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name, path=None: "/usr/bin/key-amnesia" if name == "key-amnesia" else None,
    )
    result = sc._check_path()
    assert "ka on PATH" in result


# --- CLI wiring ---------------------------------------------------------------


def test_cli_setup_subcommand_registered(fake_home: Path) -> None:
    rc = main(["setup"])
    assert rc == 0
    assert (fake_home / ".claude" / "skills" / sc.SKILL_NAMES[0] / "SKILL.md").exists()


def test_cli_setup_flags_parsed(fake_home: Path) -> None:
    rc = main(["setup", "--skills-only"])
    assert rc == 0
    assert not (fake_home / ".claude" / "settings.json").exists()


# --- hook command resolution (isolated venv / missing PATH) -------------------


def _hook_script_name() -> str:
    return "key-amnesia-hook.exe" if sys.platform == "win32" else "key-amnesia-hook"


def _python_name() -> str:
    return "python.exe" if sys.platform == "win32" else "python"


def _venv_scripts_dir(root: Path) -> Path:
    return root / "Scripts" if sys.platform == "win32" else root / "bin"


def _no_which(*_args, **_kwargs):
    return None


def test_hook_command_uses_sibling_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scripts = _venv_scripts_dir(tmp_path / "venv")
    scripts.mkdir(parents=True)
    python = scripts / _python_name()
    python.write_bytes(b"")
    hook = scripts / _hook_script_name()
    hook.write_bytes(b"")
    monkeypatch.setattr(sc.sys, "executable", str(python))
    monkeypatch.setattr(sc.shutil, "which", _no_which)

    cmd = sc._hook_command()
    assert cmd == sc._quote_hook_path(str(hook))
    assert "python -m" not in cmd
    assert "-m key_amnesia" not in cmd


def test_hook_command_fallback_uses_sys_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scripts = _venv_scripts_dir(tmp_path / "venv")
    scripts.mkdir(parents=True)
    python = scripts / _python_name()
    python.write_bytes(b"")
    monkeypatch.setattr(sc.sys, "executable", str(python))
    monkeypatch.setattr(sc.shutil, "which", _no_which)

    cmd = sc._hook_command()
    quoted = sc._quote_hook_path(str(python))
    assert cmd.startswith(quoted)
    assert "-m key_amnesia.hooks.secret_guard" in cmd
    assert not cmd.startswith("python ")
    assert not cmd.startswith("python.exe")


def test_hook_command_uses_which_absolute_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scripts = _venv_scripts_dir(tmp_path / "other-venv")
    scripts.mkdir(parents=True)
    python = scripts / _python_name()
    python.write_bytes(b"")
    found = tmp_path / "on-path" / _hook_script_name()
    found.parent.mkdir(parents=True)
    found.write_bytes(b"")

    def _which(name, mode=None, path=None):
        if name == "key-amnesia-hook":
            return str(found)
        return None

    monkeypatch.setattr(sc.sys, "executable", str(python))
    monkeypatch.setattr(sc.shutil, "which", _which)

    cmd = sc._hook_command()
    assert cmd == sc._quote_hook_path(str(found))


def test_hook_command_quotes_path_with_space(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scripts = _venv_scripts_dir(tmp_path / "my venv")
    scripts.mkdir(parents=True)
    python = scripts / _python_name()
    python.write_bytes(b"")
    hook = scripts / _hook_script_name()
    hook.write_bytes(b"")
    monkeypatch.setattr(sc.sys, "executable", str(python))
    monkeypatch.setattr(sc.shutil, "which", _no_which)

    cmd = sc._hook_command()
    quoted = sc._quote_hook_path(str(hook))
    assert cmd == quoted
    if sys.platform == "win32":
        assert cmd.startswith('"') and cmd.endswith('"')
    else:
        assert cmd.startswith("'") and cmd.endswith("'")


def test_setup_replaces_bare_python_module_hook(fake_home: Path) -> None:
    old = "python -m key_amnesia.hooks.secret_guard"
    claude = fake_home / ".claude" / "settings.json"
    claude.parent.mkdir(parents=True)
    claude.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": old}],
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    cursor = fake_home / ".cursor" / "hooks.json"
    cursor.parent.mkdir(parents=True)
    cursor.write_text(
        json.dumps(
            {
                "version": 1,
                "hooks": {"preToolUse": [{"command": old, "matcher": "Shell"}]},
            }
        ),
        encoding="utf-8",
    )
    codex = fake_home / ".codex" / "hooks.json"
    codex.parent.mkdir(parents=True)
    codex.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": old}],
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    sc.cmd_setup(_ns(hook_only=True))
    new_cmd = sc._hook_command()
    assert new_cmd != old
    assert not new_cmd.startswith("python ")

    claude_cmds = [
        h["command"]
        for entry in json.loads(claude.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
        for h in entry["hooks"]
    ]
    cursor_cmds = [
        e["command"]
        for e in json.loads(cursor.read_text(encoding="utf-8"))["hooks"]["preToolUse"]
    ]
    codex_cmds = [
        h["command"]
        for entry in json.loads(codex.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
        for h in entry["hooks"]
    ]
    assert claude_cmds == [new_cmd]
    assert cursor_cmds == [new_cmd]
    assert codex_cmds == [new_cmd]


def test_setup_prints_resolved_hook_command(fake_home: Path, capsys) -> None:
    sc.cmd_setup(_ns(hook_only=True))
    out = capsys.readouterr().out
    assert f"hook command: {sc._hook_command()}" in out


@pytest.mark.skipif(sys.platform != "win32", reason="Scripts/ next to venv-root python.exe")
def test_hook_command_windows_scripts_beside_venv_root_python(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "venv"
    root.mkdir()
    python = root / "python.exe"
    python.write_bytes(b"")
    scripts = root / "Scripts"
    scripts.mkdir()
    hook = scripts / "key-amnesia-hook.exe"
    hook.write_bytes(b"")
    monkeypatch.setattr(sc.sys, "executable", str(python))
    monkeypatch.setattr(sc.shutil, "which", _no_which)
    assert sc._hook_command() == sc._quote_hook_path(str(hook))
# --- terminal choice --------------------------------------------------------
#
# `ka setup` is where the user says which terminal opens for a password
# prompt. Before this existed the answer was a hardcoded list, and on a
# desktop whose terminal was not in it there was no answer at all.


@pytest.fixture
def linux_setup(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sc.sys, "platform", "linux")
    monkeypatch.setattr(sc, "_test_terminal", lambda: (True, "opened and ran"))
    monkeypatch.setattr(sc.sys.stdin, "isatty", lambda: False)
    # The CI runner has none of these installed; validation must not depend on
    # what happens to be on the machine running the suite.
    monkeypatch.setattr(
        "key_amnesia.config.shutil.which", lambda name: f"/usr/bin/{name}"
    )


def _detected(*names: str):
    table = {
        "ghostty": ["/usr/bin/ghostty", "-e"],
        "kitty": ["/usr/bin/kitty"],
        "foot": ["/usr/bin/foot"],
    }
    return [(n, table[n]) for n in names]


def test_single_terminal_is_chosen_without_asking(linux_setup, monkeypatch, capsys):
    monkeypatch.setattr(sc, "detect_terminals", lambda: _detected("ghostty"))
    assert sc.configure_terminal() == 0
    assert sc.load_config()["terminal"] == "ghostty -e"
    assert "the only one installed" in capsys.readouterr().out


def test_several_terminals_non_interactive_takes_the_first(
    linux_setup, monkeypatch, capsys
):
    monkeypatch.setattr(
        sc, "detect_terminals", lambda: _detected("ghostty", "kitty", "foot")
    )
    assert sc.configure_terminal(yes=True) == 0
    assert sc.load_config()["terminal"] == "ghostty -e"
    assert "not asking" in capsys.readouterr().out


def test_interactive_choice_is_stored_by_name_not_path(
    linux_setup, monkeypatch, capsys
):
    """A stored absolute path goes stale when the terminal moves prefix."""
    monkeypatch.setattr(sc, "detect_terminals", lambda: _detected("ghostty", "kitty"))
    monkeypatch.setattr(sc.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "2")
    assert sc.configure_terminal() == 0
    assert sc.load_config()["terminal"] == "kitty"


def test_interactive_can_choose_detection(linux_setup, monkeypatch):
    monkeypatch.setattr(sc, "detect_terminals", lambda: _detected("ghostty", "kitty"))
    monkeypatch.setattr(sc.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "3")
    assert sc.configure_terminal() == 0
    assert sc.load_config()["terminal"] == ""


def test_existing_choice_is_kept_on_rerun(linux_setup, monkeypatch, capsys):
    """setup is re-run on every update; it must not re-ask what is settled."""
    monkeypatch.setattr(sc, "detect_terminals", lambda: _detected("ghostty", "kitty"))
    sc.set_config_value("terminal", "kitty")
    assert sc.configure_terminal() == 0
    assert sc.load_config()["terminal"] == "kitty"
    assert "already configured" in capsys.readouterr().out


def test_reconfigure_forces_a_new_choice(linux_setup, monkeypatch):
    monkeypatch.setattr(sc, "detect_terminals", lambda: _detected("ghostty"))
    sc.set_config_value("terminal", "kitty")
    assert sc.configure_terminal(force=True) == 0
    assert sc.load_config()["terminal"] == "ghostty -e"


def test_no_terminal_found_explains_the_manual_route(linux_setup, monkeypatch, capsys):
    monkeypatch.setattr(sc, "detect_terminals", list)
    assert sc.configure_terminal() == 0
    out = capsys.readouterr().out
    assert "ka config set terminal" in out
    assert sc.load_config()["terminal"] == ""


def test_failed_terminal_test_is_reported(linux_setup, monkeypatch, capsys):
    monkeypatch.setattr(sc, "detect_terminals", lambda: _detected("ghostty"))
    monkeypatch.setattr(sc, "_test_terminal", lambda: (False, "no window appeared"))
    assert sc.configure_terminal() == 1
    captured = capsys.readouterr()
    assert "no window appeared" in captured.err  # warn goes to stderr
    assert "ka config set terminal" in captured.out


def test_terminal_step_is_skipped_off_linux(monkeypatch, capsys):
    monkeypatch.setattr(sc.sys, "platform", "win32")
    assert sc.configure_terminal() == 0
    assert "not configurable" in capsys.readouterr().out


def test_skills_only_does_not_open_a_terminal(fake_home, monkeypatch):
    """Someone who asked for skills alone did not ask for a window."""
    called = {"n": 0}

    def counted(**_kwargs):
        called["n"] += 1
        return 0

    monkeypatch.setattr(sc, "configure_terminal", counted)
    sc.cmd_setup(_ns(skills_only=True))
    assert called["n"] == 0


def test_terminal_only_skips_skills_and_hooks(fake_home, monkeypatch):
    def fail(*_a, **_k):
        raise AssertionError("--terminal-only must not touch skills or hooks")

    monkeypatch.setattr(sc, "_copy_skills", fail)
    monkeypatch.setattr(sc, "_merge_claude_settings", fail)
    monkeypatch.setattr(sc, "configure_terminal", lambda **_k: 0)
    assert sc.cmd_setup(_ns(terminal_only=True)) == 0


def test_configured_terminal_survives_an_empty_detection(linux_setup, monkeypatch, capsys):
    """Nothing detected but something configured must not crash the picker."""
    monkeypatch.setattr(sc, "detect_terminals", list)
    sc.set_config_value("terminal", "kitty")
    assert sc.configure_terminal(force=True) == 0
    assert sc.load_config()["terminal"] == "kitty"
    assert "none of the known ones found" in capsys.readouterr().out
