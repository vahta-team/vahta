"""Defect 3: ka run surfaces abandoned guard attempts (never silent)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pytest

from key_amnesia.cli import cmd_run
from key_amnesia.paths import audit_log_path


def _args(**kwargs: Any) -> argparse.Namespace:
    return argparse.Namespace(
        cmd=kwargs.get("cmd", ["--", "echo", "hi"]),
        secret=kwargs.get("secret", ["api_key"]),
        as_env=kwargs.get("as_env", []),
        cwd=kwargs.get("cwd", None),
        env=None,
        vault=None,
        force_global=False,
        no_global=False,
    )


def test_run_unreachable_guard_warns_then_falls_through(
    ka_home: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr("key_amnesia.guard.guard_is_alive", lambda **k: True)
    monkeypatch.setattr("key_amnesia.guard.guard_request", lambda *a, **k: None)

    auth_calls: list[Any] = []

    def fake_auth(request):
        auth_calls.append(request)
        from key_amnesia.prompt_route import AuthOutcome

        return False, None, AuthOutcome(ok=False, route="inline", reason="test stop")

    monkeypatch.setattr("key_amnesia.cli._auth_password", fake_auth)
    rc = cmd_run(_args())
    assert rc == 1
    err = capsys.readouterr().err
    assert "unreachable" in err.lower() or "IPC" in err
    assert len(auth_calls) == 1


def test_run_admission_denied_warns_then_falls_through(
    ka_home: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr("key_amnesia.guard.guard_is_alive", lambda **k: True)
    monkeypatch.setattr(
        "key_amnesia.guard.guard_request",
        lambda *a, **k: {
            "ok": False,
            "reason": "admission denied",
            "code": "admission_denied",
            "admitted": False,
        },
    )

    auth_calls: list[Any] = []

    def fake_auth(request):
        auth_calls.append(request)
        from key_amnesia.prompt_route import AuthOutcome

        return False, None, AuthOutcome(ok=False, route="inline", reason="test stop")

    monkeypatch.setattr("key_amnesia.cli._auth_password", fake_auth)
    rc = cmd_run(_args())
    assert rc == 1
    err = capsys.readouterr().err
    assert "admission denied" in err.lower()
    assert len(auth_calls) == 1


def test_run_unknown_secret_hard_stops(
    ka_home: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr("key_amnesia.guard.guard_is_alive", lambda **k: True)
    monkeypatch.setattr(
        "key_amnesia.guard.guard_request",
        lambda *a, **k: {
            "ok": False,
            "reason": "unknown secrets: missing",
            "code": "unknown_secret",
        },
    )

    def boom(_request):
        raise AssertionError("_auth_password must not be called")

    monkeypatch.setattr("key_amnesia.cli._auth_password", boom)
    rc = cmd_run(_args(secret=["missing"]))
    assert rc == 1
    err = capsys.readouterr().err
    assert "unknown secrets" in err.lower()


def test_run_expired_warns_then_falls_through(
    ka_home: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr("key_amnesia.guard.guard_is_alive", lambda **k: True)
    monkeypatch.setattr(
        "key_amnesia.guard.guard_request",
        lambda *a, **k: {
            "ok": False,
            "reason": "session expired",
            "expired": True,
            "code": "session_expired",
        },
    )

    auth_calls: list[Any] = []

    def fake_auth(request):
        auth_calls.append(request)
        from key_amnesia.prompt_route import AuthOutcome

        return False, None, AuthOutcome(ok=False, route="inline", reason="test stop")

    monkeypatch.setattr("key_amnesia.cli._auth_password", fake_auth)
    rc = cmd_run(_args())
    assert rc == 1
    err = capsys.readouterr().err
    assert "expired" in err.lower()
    assert len(auth_calls) == 1


def test_guard_request_connect_failure_writes_audit_warn(
    ka_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from key_amnesia import guard as guard_mod

    monkeypatch.setattr(guard_mod, "connect_guard", lambda **k: None)
    resp = guard_mod.guard_request({"verb": "run", "secret_names": ["x"]})
    assert resp is None
    log = audit_log_path()
    assert log.exists()
    lines = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert lines
    last = lines[-1]
    assert last["route"] == "guard-session"
    assert last["result"] == "warn"
    assert "connect" in last["reason"].lower()
