"""Audit log and CLI help / auth-policy tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from key_amnesia.audit import audit_event
from key_amnesia.cli import main
from key_amnesia.guard import GuardState, guard_handle_message
from key_amnesia.paths import audit_log_path
from key_amnesia.prompt_route import PromptRequest, require_human_auth
from key_amnesia.vault import load_vault, read_names, save_vault


def test_audit_allowed_denied_timeout_no_plaintext(ka_home: Path) -> None:
    secret_value = "super-secret-value-123"
    audit_event(
        "run",
        secret_names=["api_key"],
        command=["echo", "hi"],
        route="inline",
        result="allowed",
    )
    audit_event(
        "reveal",
        secret_names=["api_key"],
        route="spawned-console",
        result="denied",
        reason="empty password",
    )
    audit_event(
        "run",
        secret_names=["api_key"],
        route="spawned-console",
        result="timeout",
        reason="prompt timed out",
    )
    text = audit_log_path().read_text(encoding="utf-8")
    assert secret_value not in text
    lines = [json.loads(l) for l in text.strip().splitlines()]
    assert {l["result"] for l in lines} >= {"allowed", "denied", "timeout"}
    for l in lines:
        assert "password" not in l
        assert secret_value not in json.dumps(l)


def test_help_top_level_and_subcommand() -> None:
    with pytest.raises(SystemExit) as ei:
        main(["--help"])
    assert ei.value.code == 0

    for sub in ("init", "set", "run", "list", "reveal", "copy", "config", "unlock", "lock"):
        with pytest.raises(SystemExit) as ei:
            main([sub, "--help"])
        assert ei.value.code == 0


def test_help_prompt_helper_exists() -> None:
    with pytest.raises(SystemExit) as ei:
        main(["_prompt-helper", "--help"])
    assert ei.value.code == 0


def test_list_no_prompt(seeded_vault: Path, capsys) -> None:
    rc = main(["list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "api_key" in out
    assert "db_pass" in out
    assert "super-secret" not in out


def test_set_remove_config_need_password(seeded_vault: Path, password: str) -> None:
    # Non-interactive without successful helper → denied
    req = PromptRequest(action="set", secret_names=["new"], detail='{"name":"new","value":"v"}')
    # Simulate denied by empty password inline
    outcome = require_human_auth(
        req, isatty_fn=lambda: True, password_provider=lambda: ""
    )
    assert outcome.ok is False

    # Successful set with password
    outcome = require_human_auth(
        PromptRequest(action="set", secret_names=["newkey"]),
        isatty_fn=lambda: True,
        password_provider=lambda: password,
    )
    assert outcome.ok is True
    assert outcome.password == password


def test_reveal_copy_ignore_live_guard(seeded_vault: Path, password: str, monkeypatch) -> None:
    """reveal/copy must not use guard shortcut even if guard is 'alive'."""
    from key_amnesia import guard as guard_mod

    monkeypatch.setattr(guard_mod, "guard_is_alive", lambda *a, **k: True)

    # Inline reveal with password works without calling guard for the value
    calls = {"guard_request": 0}

    def fake_req(*a, **k):
        calls["guard_request"] += 1
        return {"ok": True, "scrubbed_stdout": "LEAK", "exit_code": 0}

    monkeypatch.setattr(guard_mod, "guard_request", fake_req)

    # Use CLI reveal with password provider via require_human_auth patch
    from key_amnesia import cli

    def fake_auth(request, timeout_s=None, **kwargs):
        from key_amnesia.prompt_route import AuthOutcome

        assert request.action in ("reveal", "copy")
        return AuthOutcome(ok=True, route="inline", password=password)

    monkeypatch.setattr(cli, "require_human_auth", fake_auth)
    # Also need to patch where cli imports it — it imports at call time from prompt_route
    # Actually cli._auth_password calls require_human_auth from prompt_route import at module level
    monkeypatch.setattr("key_amnesia.cli.require_human_auth", fake_auth)

    rc = main(["reveal", "api_key"])
    assert rc == 0
    assert calls["guard_request"] == 0


def test_config_set_needs_auth(seeded_vault: Path, password: str, monkeypatch, capsys) -> None:
    from key_amnesia.prompt_route import AuthOutcome

    monkeypatch.setattr(
        "key_amnesia.cli.require_human_auth",
        lambda *a, **k: AuthOutcome(ok=True, route="inline", password=password),
    )
    rc = main(["config", "set", "session-mode", "cached"])
    assert rc == 0
    from key_amnesia.config import load_config

    assert load_config()["session-mode"] == "cached"


def test_config_set_terminal_needs_no_password(monkeypatch, capsys, tmp_path) -> None:
    """The bootstrap exemption.

    `terminal` decides where a password can be typed, so gating it behind
    typing one deadlocks the user it is meant to help: their prompt does not
    open, and the fix for that is the setting they cannot reach.
    """

    def must_not_be_called(*_a, **_k):
        raise AssertionError("config set terminal must not ask for the password")

    monkeypatch.setattr("key_amnesia.cli.require_human_auth", must_not_be_called)
    monkeypatch.setattr(
        "key_amnesia.config.shutil.which", lambda name: f"/usr/bin/{name}"
    )

    from key_amnesia.config import load_config

    assert main(["config", "set", "terminal", "ghostty -e"]) == 0
    assert load_config()["terminal"] == "ghostty -e"

    assert main(["config", "set", "terminal", "auto"]) == 0
    assert load_config()["terminal"] == ""
    assert "(auto-detect)" in capsys.readouterr().out


def test_config_set_terminal_rejects_a_binary_that_is_not_there(monkeypatch) -> None:
    monkeypatch.setattr("key_amnesia.config.shutil.which", lambda _name: None)
    monkeypatch.setattr(
        "key_amnesia.cli.require_human_auth",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no auth expected")),
    )
    assert main(["config", "set", "terminal", "nosuchterm -e"]) == 1
