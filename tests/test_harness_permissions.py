"""Harness permission merge: Claude / Cursor / Codex, manifest, hook-missing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from key_amnesia.harness_permissions import (
    VALUE_EMIT_VERBS,
    claude_allow_matchers,
    claude_deny_matchers,
    cursor_allow_prefixes,
    deny_in_allow_conflicts,
    dump_json,
    load_json_object_strict,
    merge_string_list,
    opencode_allow_globs,
    opencode_config_dir,
    opencode_config_note,
    opencode_deny_globs,
    opencode_plugin_dest,
    prepare_claude,
    prepare_cursor,
    prepare_codex,
    prepare_opencode,
    run_permissions,
)
from key_amnesia.paths import permissions_manifest_path
from key_amnesia.setup_cmd import (
    CLAUDE_MATCHER,
    _hook_command,
    _merge_claude_settings,
    _merge_cursor_hooks,
    cmd_setup,
    install_opencode_plugin,
)


def _ns(**kwargs):
    import argparse

    defaults = {
        "skills_only": False,
        "hook_only": False,
        "permissions_only": False,
        "permissions_remove": False,
        "yes": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _claude_with_hook(home: Path, extra: dict | None = None) -> Path:
    path = home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    _merge_claude_settings(path)
    if extra:
        data = json.loads(path.read_text(encoding="utf-8"))
        data.update(extra)
        path.write_text(dump_json(data), encoding="utf-8")
    return path


def test_value_emit_never_in_file_allow() -> None:
    blob = "\n".join(
        claude_allow_matchers() + cursor_allow_prefixes() + opencode_allow_globs()
    )
    for verb in VALUE_EMIT_VERBS:
        assert f" {verb}" not in blob
        assert f" {verb}:*" not in blob


def test_claude_skip_missing_home(tmp_path: Path) -> None:
    out = prepare_claude(tmp_path, {"rules": {}})
    assert out.ok
    assert not out.changes
    assert "absent" in out.lines[0]


def test_claude_fail_closed_malformed(tmp_path: Path) -> None:
    claude = tmp_path / ".claude"
    claude.mkdir()
    path = claude / "settings.json"
    path.write_text("{ not json", encoding="utf-8")
    out = prepare_claude(tmp_path, {"rules": {}})
    assert not out.ok
    assert not out.changes
    assert any("fail closed" in ln for ln in out.lines)


def test_claude_merge_permissions_and_automode(tmp_path: Path) -> None:
    path = _claude_with_hook(
        tmp_path,
        extra={
            "autoMode": {
                "environment": {"Z_KEEP": "1", "A_KEEP": "2"},
                "allow": ["Bash(echo:*)"],
            },
            "unrelated": True,
        },
    )
    env_before = list(
        json.loads(path.read_text(encoding="utf-8"))["autoMode"]["environment"]
    )
    rc = run_permissions(
        tmp_path,
        yes=True,
        may_install_hook=False,
        install_hook_fn=None,
        tty=False,
    )
    assert rc == 0
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["unrelated"] is True
    assert list(data["autoMode"]["environment"]) == env_before
    assert "Bash(echo:*)" in data["autoMode"]["allow"]
    assert any(x.startswith("Bash(ka run:*)") for x in data["permissions"]["allow"])
    assert any(x.startswith("PowerShell(ka run:*)") for x in data["permissions"]["allow"])
    assert any(" — key-amnesia" in x for x in data["autoMode"]["allow"])
    assert any(x.startswith("Bash(ka set:*)") for x in data["permissions"]["deny"])
    assert not any("ka reveal" in x for x in data["permissions"]["allow"])


def test_second_write_byte_identical(tmp_path: Path) -> None:
    _claude_with_hook(tmp_path)
    run_permissions(tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False)
    path = tmp_path / ".claude" / "settings.json"
    first = path.read_bytes()
    run_permissions(tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False)
    assert path.read_bytes() == first


def test_manifest_drift_drops_stale_not_user(tmp_path: Path) -> None:
    path = _claude_with_hook(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["permissions"] = {
        "allow": ["Bash(user-own:*)", "Bash(ka stale:*)"],
        "deny": [],
    }
    path.write_text(dump_json(data), encoding="utf-8")
    manifest = {
        "version": 1,
        "rules": {"claude.permissions.allow": ["Bash(ka stale:*)"]},
    }
    permissions_manifest_path().write_text(dump_json(manifest), encoding="utf-8")
    rc = run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    assert rc == 0
    allow = json.loads(path.read_text(encoding="utf-8"))["permissions"]["allow"]
    assert "Bash(user-own:*)" in allow
    assert "Bash(ka stale:*)" not in allow
    assert any(x.startswith("Bash(ka run:*)") for x in allow)


def test_deny_in_allow_loud_not_deleted_with_yes(tmp_path: Path, capsys) -> None:
    conflict = "Bash(ka set:*) in the SpookyOwl repo"
    path = _claude_with_hook(
        tmp_path,
        extra={"autoMode": {"allow": [conflict], "environment": {"X": "1"}}},
    )
    rc = run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert conflict in err
    data = json.loads(path.read_text(encoding="utf-8"))
    assert conflict in data["autoMode"]["allow"]


def test_permissions_only_missing_hook_no_silent_write(tmp_path: Path, capsys) -> None:
    claude = tmp_path / ".claude"
    claude.mkdir()
    path = claude / "settings.json"
    path.write_text(dump_json({"hooks": {}}), encoding="utf-8")
    rc = run_permissions(
        tmp_path,
        yes=True,
        may_install_hook=False,
        install_hook_fn=None,
        tty=False,
    )
    assert rc != 0
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "permissions" not in data
    out = capsys.readouterr()
    combined = out.out + out.err
    assert "hook" in combined.lower()
    assert "ka set" in combined.lower() or "without" in combined.lower()


def test_permissions_only_cli_missing_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        dump_json({"other": True}), encoding="utf-8"
    )
    rc = cmd_setup(_ns(permissions_only=True, yes=True))
    assert rc != 0
    data = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert "permissions" not in data


def test_cursor_never_creates_permissions_json(tmp_path: Path) -> None:
    (tmp_path / ".cursor").mkdir()
    _merge_cursor_hooks(tmp_path / ".cursor" / "hooks.json")
    out = prepare_cursor(tmp_path, {"rules": {}})
    assert not (tmp_path / ".cursor" / "permissions.json").exists()
    assert not any(c.path.name == "permissions.json" for c in out.changes)
    assert any("not creating" in ln for ln in out.lines)


def test_cursor_appends_existing_allowlist(tmp_path: Path) -> None:
    (tmp_path / ".cursor").mkdir()
    _merge_cursor_hooks(tmp_path / ".cursor" / "hooks.json")
    perm = tmp_path / ".cursor" / "permissions.json"
    perm.write_text(
        dump_json({"terminalAllowlist": ["git", "npm"]}),
        encoding="utf-8",
    )
    rc = run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    assert rc == 0
    data = json.loads(perm.read_text(encoding="utf-8"))
    assert "git" in data["terminalAllowlist"]
    assert "npm" in data["terminalAllowlist"]
    assert "ka run" in data["terminalAllowlist"]


def test_cursor_no_add_allowlist_key_uses_instructions(tmp_path: Path) -> None:
    (tmp_path / ".cursor").mkdir()
    _merge_cursor_hooks(tmp_path / ".cursor" / "hooks.json")
    perm = tmp_path / ".cursor" / "permissions.json"
    perm.write_text(dump_json({"other": True}), encoding="utf-8")
    rc = run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    assert rc == 0
    data = json.loads(perm.read_text(encoding="utf-8"))
    assert "terminalAllowlist" not in data
    assert "block_instructions" not in data.get("autoRun", {})
    assert "ka run" in data["autoRun"]["allow_instructions"]


def test_cursor_cli_config_merge_only_if_schema_matches(tmp_path: Path) -> None:
    (tmp_path / ".cursor").mkdir()
    _merge_cursor_hooks(tmp_path / ".cursor" / "hooks.json")
    cli = tmp_path / ".cursor" / "cli-config.json"
    cli.write_text(
        dump_json({"permissions": {"allow": ["Shell(ls)"]}}),
        encoding="utf-8",
    )
    rc = run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    assert rc == 0
    data = json.loads(cli.read_text(encoding="utf-8"))
    assert "Shell(ls)" in data["permissions"]["allow"]
    assert "ka run" in data["permissions"]["allow"]


def test_cursor_cli_config_never_created(tmp_path: Path) -> None:
    (tmp_path / ".cursor").mkdir()
    _merge_cursor_hooks(tmp_path / ".cursor" / "hooks.json")
    run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    assert not (tmp_path / ".cursor" / "cli-config.json").exists()


def test_codex_print_only(tmp_path: Path, capsys) -> None:
    out = prepare_codex(tmp_path)
    assert not out.changes
    assert any("config.toml" in ln for ln in out.lines)
    assert any("/hooks" in ln for ln in out.lines)


def test_fail_closed_wrong_types(tmp_path: Path) -> None:
    path = _claude_with_hook(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["permissions"] = []
    path.write_text(dump_json(data), encoding="utf-8")
    out = prepare_claude(tmp_path, {"rules": {}})
    assert not out.ok
    assert not out.changes


def test_merge_string_list_types() -> None:
    merged, err = merge_string_list(["a"], ["b"], [])
    assert err is None
    assert merged == ["a", "b"]
    merged, err = merge_string_list([1], ["b"], [])  # type: ignore[list-item]
    assert err is not None


def test_deny_in_allow_prefix_match() -> None:
    hits = deny_in_allow_conflicts(
        ["Bash(ka set:*) in the SpookyOwl repo", "Bash(ka run:*)"]
    )
    assert hits == ["Bash(ka set:*) in the SpookyOwl repo"]


def test_load_json_strict_missing(tmp_path: Path) -> None:
    data, err = load_json_object_strict(tmp_path / "nope.json")
    assert data == {}
    assert err is None


def test_permissions_remove_only_manifested(tmp_path: Path) -> None:
    path = _claude_with_hook(tmp_path)
    run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    data["permissions"]["allow"].insert(0, "Bash(user-keep:*)")
    path.write_text(dump_json(data), encoding="utf-8")
    from key_amnesia.harness_permissions import remove_manifested_rules

    rc = remove_manifested_rules(tmp_path)
    assert rc == 0
    allow = json.loads(path.read_text(encoding="utf-8"))["permissions"]["allow"]
    assert "Bash(user-keep:*)" in allow
    assert not any(x.startswith("Bash(ka run:*)") for x in allow)


def test_claude_deny_matchers_omit_prompt_helper() -> None:
    blob = "\n".join(claude_deny_matchers())
    assert "_prompt-helper" not in blob
    assert "ka set:*" in blob or "ka set:*)" in blob


def test_hook_command_still_used() -> None:
    assert "key-amnesia" in _hook_command() or "secret_guard" in _hook_command()
    assert "Bash" in CLAUDE_MATCHER


def _opencode_with_plugin(home: Path, extra: dict | None = None) -> Path:
    oc = home / ".config" / "opencode"
    oc.mkdir(parents=True)
    install_opencode_plugin(home)
    path = oc / "opencode.json"
    if extra is not None:
        path.write_text(dump_json(extra), encoding="utf-8")
    return path


def test_opencode_skip_missing_home(tmp_path: Path) -> None:
    out = prepare_opencode(tmp_path, {"rules": {}})
    assert out.ok
    assert not out.changes
    assert "absent" in out.lines[0]


def test_opencode_fail_closed_malformed(tmp_path: Path) -> None:
    oc = tmp_path / ".config" / "opencode"
    oc.mkdir(parents=True)
    path = oc / "opencode.json"
    path.write_text("{ not json", encoding="utf-8")
    out = prepare_opencode(tmp_path, {"rules": {}})
    assert not out.ok
    assert not out.changes
    assert any("fail closed" in ln for ln in out.lines)


def test_opencode_merge_permissions_and_plugin(tmp_path: Path) -> None:
    path = _opencode_with_plugin(
        tmp_path,
        extra={
            "$schema": "https://opencode.ai/config.json",
            "provider": {"ollama": {"name": "keep-me"}},
            "unrelated": True,
        },
    )
    rc = run_permissions(
        tmp_path,
        yes=True,
        may_install_hook=False,
        install_hook_fn=None,
        tty=False,
    )
    assert rc == 0
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["unrelated"] is True
    assert data["provider"]["ollama"]["name"] == "keep-me"
    assert data["$schema"] == "https://opencode.ai/config.json"
    bash = data["permission"]["bash"]
    assert bash["ka set"] == "deny"
    assert bash["ka set *"] == "deny"
    assert bash["ka run"] == "allow"
    assert bash["ka run *"] == "allow"
    assert "ka reveal" not in bash or bash.get("ka reveal") == "deny"
    assert "./plugins/key-amnesia-secret-guard.js" in data["plugin"]
    manifest = json.loads(permissions_manifest_path().read_text(encoding="utf-8"))
    assert "opencode.permission.bash" in manifest["rules"]
    assert manifest["rules"]["opencode.plugin"] == [
        "./plugins/key-amnesia-secret-guard.js"
    ]


def test_opencode_second_write_byte_identical(tmp_path: Path) -> None:
    _opencode_with_plugin(tmp_path, extra={})
    run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    path = tmp_path / ".config" / "opencode" / "opencode.json"
    first = path.read_bytes()
    run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    assert path.read_bytes() == first


def test_opencode_string_bash_converts_star(tmp_path: Path) -> None:
    path = _opencode_with_plugin(tmp_path, extra={"permission": {"bash": "ask"}})
    rc = run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    assert rc == 0
    bash = json.loads(path.read_text(encoding="utf-8"))["permission"]["bash"]
    assert bash["*"] == "ask"
    assert bash["ka set *"] == "deny"


def test_opencode_conflict_keeps_user_allow(tmp_path: Path, capsys) -> None:
    path = _opencode_with_plugin(
        tmp_path,
        extra={"permission": {"bash": {"ka set *": "allow", "git status": "allow"}}},
    )
    rc = run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "ka set *" in err
    bash = json.loads(path.read_text(encoding="utf-8"))["permission"]["bash"]
    assert bash["ka set *"] == "allow"
    assert bash["git status"] == "allow"


def test_opencode_broad_star_allow_is_conflict(tmp_path: Path) -> None:
    _opencode_with_plugin(
        tmp_path,
        extra={"permission": {"bash": {"*": "allow"}}},
    )
    out = prepare_opencode(tmp_path, {"rules": {}})
    assert "*" in [c[1] for c in out.conflicts]
    rc = run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    assert rc == 0
    bash = json.loads(
        (tmp_path / ".config" / "opencode" / "opencode.json").read_text(encoding="utf-8")
    )["permission"]["bash"]
    assert bash["*"] == "allow"


def test_opencode_plugin_non_string_skips_array_still_writes_bash(
    tmp_path: Path,
) -> None:
    path = _opencode_with_plugin(
        tmp_path,
        extra={"plugin": [["opencode-bar", {"opt": 1}]], "keep": True},
    )
    out = prepare_opencode(tmp_path, {"rules": {}})
    assert out.ok
    assert any("skipping plugin array" in ln for ln in out.lines)
    assert "opencode.plugin" not in out.extra_manifest
    assert "opencode.permission.bash" in out.extra_manifest
    rc = run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    assert rc == 0
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["keep"] is True
    assert data["plugin"] == [["opencode-bar", {"opt": 1}]]
    assert data["permission"]["bash"]["ka set"] == "deny"
    manifest = json.loads(permissions_manifest_path().read_text(encoding="utf-8"))
    assert "opencode.permission.bash" in manifest["rules"]
    assert "opencode.plugin" not in manifest["rules"]


def test_opencode_permissions_remove_restores(tmp_path: Path) -> None:
    path = _opencode_with_plugin(
        tmp_path,
        extra={"permission": {"bash": {"git *": "allow"}}, "keep": True},
    )
    run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    from key_amnesia.harness_permissions import remove_manifested_rules

    rc = remove_manifested_rules(tmp_path)
    assert rc == 0
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["keep"] is True
    assert data["permission"]["bash"] == {"git *": "allow"}
    assert "plugin" not in data
    assert not opencode_plugin_dest(tmp_path).exists()


def test_opencode_conflict_removal_drops_dict_key(tmp_path: Path) -> None:
    path = _opencode_with_plugin(
        tmp_path,
        extra={"permission": {"bash": {"ka set *": "allow"}}},
    )
    rc = run_permissions(
        tmp_path,
        yes=False,
        may_install_hook=False,
        install_hook_fn=None,
        tty=True,
        confirm_fn=lambda prompt, default: True,
    )
    assert rc == 0
    bash = json.loads(path.read_text(encoding="utf-8"))["permission"]["bash"]
    assert "ka set *" not in bash
    assert bash["ka set"] == "deny"


def test_opencode_config_dir_honours_xdg_inside_home(
    tmp_path: Path, monkeypatch
) -> None:
    """OpenCode reads $XDG_CONFIG_HOME/opencode; installing elsewhere protects nothing."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    assert opencode_config_dir(tmp_path) == tmp_path / "cfg" / "opencode"
    assert opencode_plugin_dest(tmp_path).parent.parent == tmp_path / "cfg" / "opencode"


def test_opencode_config_dir_ignores_xdg_outside_home(
    tmp_path: Path, monkeypatch
) -> None:
    """A redirected home must never escape into the running user's own config."""
    monkeypatch.setenv("XDG_CONFIG_HOME", "/somewhere/else")
    assert opencode_config_dir(tmp_path) == tmp_path / ".config" / "opencode"


def test_opencode_config_dir_ignores_relative_xdg(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", "relative/cfg")
    assert opencode_config_dir(tmp_path) == tmp_path / ".config" / "opencode"


def test_opencode_config_note_warns_only_for_the_real_home(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", "/somewhere/else")
    assert opencode_config_note(tmp_path) is None
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    note = opencode_config_note(tmp_path)
    assert note is not None and "/somewhere/else" in note
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    assert opencode_config_note(tmp_path) is None


def test_opencode_install_and_remove_follow_xdg(tmp_path: Path, monkeypatch) -> None:
    """Install, merge and remove must all land in the same XDG-resolved directory."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    oc = tmp_path / "cfg" / "opencode"
    oc.mkdir(parents=True)
    install_opencode_plugin(tmp_path)
    assert (oc / "plugins" / "key-amnesia-secret-guard.js").is_file()
    assert not (tmp_path / ".config").exists()

    path = oc / "opencode.json"
    path.write_text(dump_json({"keep": True}), encoding="utf-8")
    run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["permission"]["bash"]["ka set"] == "deny"

    from key_amnesia.harness_permissions import remove_manifested_rules

    assert remove_manifested_rules(tmp_path) == 0
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data == {"keep": True}
    assert not (oc / "plugins" / "key-amnesia-secret-guard.js").exists()


def test_opencode_deny_globs_omit_prompt_helper() -> None:
    blob = "\n".join(opencode_deny_globs())
    assert "_prompt-helper" not in blob
    assert "ka set *" in blob
    assert "ka set" in blob.splitlines() or "ka set" in blob
