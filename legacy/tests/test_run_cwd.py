"""ka run --cwd and audit of trailing command (no secret values)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from key_amnesia.cli import main
from key_amnesia.paths import audit_log_path
from key_amnesia.prompt_route import AuthOutcome


def test_run_cwd_missing_dir_exits_2(tmp_path: Path, capsys) -> None:
    rc = main(
        [
            "run",
            "--cwd",
            str(tmp_path / "no-such-dir"),
            "--secret",
            "api_key",
            "--",
            "echo",
            "hi",
        ]
    )
    assert rc == 2
    assert "not a directory" in capsys.readouterr().err.lower()


def test_run_cwd_not_dir_exits_2(tmp_path: Path, capsys) -> None:
    f = tmp_path / "file.txt"
    f.write_text("x", encoding="utf-8")
    rc = main(
        ["run", "--cwd", str(f), "--secret", "api_key", "--", "echo", "hi"]
    )
    assert rc == 2
    assert "not a directory" in capsys.readouterr().err.lower()


def test_run_cwd_passed_to_guard(
    tmp_path: Path, monkeypatch, seeded_vault: Path
) -> None:
    seen: dict = {}

    monkeypatch.setattr("key_amnesia.guard.guard_is_alive", lambda **k: True)

    def fake_req(msg, **k):
        seen["cwd"] = msg.get("cwd")
        return {"ok": True, "scrubbed_stdout": "", "scrubbed_stderr": "", "exit_code": 0}

    monkeypatch.setattr("key_amnesia.guard.guard_request", fake_req)
    cwd = tmp_path / "work"
    cwd.mkdir()
    rc = main(
        [
            "run",
            "--cwd",
            str(cwd),
            "--secret",
            "api_key",
            "--",
            "echo",
            "hi",
        ]
    )
    assert rc == 0
    assert Path(seen["cwd"]).resolve() == cwd.resolve()


def test_run_audit_trailing_command_no_values(
    seeded_vault: Path, password: str, monkeypatch
) -> None:
    monkeypatch.setattr("key_amnesia.guard.guard_is_alive", lambda **k: False)
    monkeypatch.setattr(
        "key_amnesia.cli.require_human_auth",
        lambda *a, **k: AuthOutcome(ok=True, route="inline", password=password),
    )
    secret_value = "super-secret-value-123"
    rc = main(
        [
            "run",
            "--secret",
            "api_key",
            "--as",
            "api_key=API_KEY",
            "--",
            sys.executable,
            "-c",
            "print(1)",
        ]
    )
    assert rc == 0
    text = audit_log_path().read_text(encoding="utf-8")
    assert secret_value not in text
    rec = json.loads(text.strip().splitlines()[-1])
    assert rec["action"] == "run"
    assert rec["secret_names"] == ["api_key"]
    assert rec["command"] == [sys.executable, "-c", "print(1)"]
    assert secret_value not in json.dumps(rec)
