"""macOS isolated-console spawn: PID-file wrapper (mocked; window experimental)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from key_amnesia.platform import (
    MACOS_SPAWN_EXPERIMENTAL,
    PidFileProcess,
    _applescript_quote,
    _macos_launcher_argv,
    _wait_for_pid_file,
    spawn_isolated_console,
)


HELPER_ARGV = [sys.executable, "-m", "key_amnesia", "_prompt-helper"]
SENSITIVE_ENV = {
    "PATH": "/usr/bin:/bin",
    "KEY_AMNESIA_PROMPT_REQUEST": '{"action":"reveal","secret_names":["api_key"]}',
    "KEY_AMNESIA_PROMPT_AUTHKEY": "a" * 64,
    "KEY_AMNESIA_PROMPT_ADDRESS": "/tmp/key-amnesia-test.sock",
}


@pytest.fixture(autouse=True)
def _fast_pid_poll(monkeypatch):
    monkeypatch.setattr("key_amnesia.platform._MACOS_PID_POLL_S", 0)
    monkeypatch.setattr("key_amnesia.platform._MACOS_PID_WAIT_S", 0.5)


def test_macos_spawn_experimental_flag() -> None:
    assert MACOS_SPAWN_EXPERIMENTAL is True


def test_pid_file_process_poll_and_terminate(monkeypatch) -> None:
    alive = {"n": True}

    def fake_kill(pid: int, sig: int) -> None:
        if not alive["n"]:
            raise ProcessLookupError()
        if sig != 0:
            alive["n"] = False

    monkeypatch.setattr("key_amnesia.platform.os.kill", fake_kill)
    proc = PidFileProcess(4242)
    assert proc.poll() is None
    proc.terminate()
    assert proc.poll() == 0
    assert proc.poll() == 0  # sticky returncode


def test_wait_for_pid_file_reads_pid(tmp_path: Path) -> None:
    pid_path = tmp_path / "helper.pid"
    pid_path.write_text("9911\n", encoding="utf-8")
    assert _wait_for_pid_file(pid_path, timeout_s=0.2) == 9911


def test_wait_for_pid_file_timeout(tmp_path: Path) -> None:
    pid_path = tmp_path / "missing.pid"
    with pytest.raises(OSError, match="did not record a PID|Fail closed"):
        _wait_for_pid_file(pid_path, timeout_s=0.05)


def test_applescript_quote_escapes() -> None:
    assert _applescript_quote('a"b\\c') == '"a\\"b\\\\c"'


def test_macos_launcher_prefers_osascript(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "key_amnesia.platform.shutil.which",
        lambda name: "/usr/bin/osascript" if name == "osascript" else None,
    )
    wrapper = tmp_path / "wrapper.py"
    env_file = tmp_path / "env.json"
    pid_file = tmp_path / "helper.pid"
    cmd = _macos_launcher_argv(wrapper, env_file, pid_file, HELPER_ARGV)
    assert cmd[0] == "/usr/bin/osascript"
    assert cmd[1] == "-e"
    joined = " ".join(cmd)
    assert "Terminal" in joined
    assert "do script" in joined
    assert "wrapper.py" in joined
    assert "_prompt-helper" in joined
    assert "api_key" not in joined
    assert "a" * 64 not in joined
    assert "KEY_AMNESIA_PROMPT" not in joined


def test_macos_launcher_open_fallback(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "key_amnesia.platform.shutil.which",
        lambda name: "/usr/bin/open" if name == "open" else None,
    )
    wrapper = tmp_path / "wrapper.py"
    env_file = tmp_path / "env.json"
    pid_file = tmp_path / "helper.pid"
    command_file = tmp_path / "run.command"
    cmd = _macos_launcher_argv(
        wrapper, env_file, pid_file, HELPER_ARGV, command_file=command_file
    )
    assert cmd == ["/usr/bin/open", "-a", "Terminal", str(command_file)]


def test_darwin_pid_file_spawn_success(monkeypatch, tmp_path: Path) -> None:
    """Launcher returns immediately; wrapper-side PID file drives the handle."""
    monkeypatch.setattr(sys, "platform", "darwin")
    spawn_dir = tmp_path / "spawn"
    captured: dict[str, Any] = {}

    def fake_mkdtemp(prefix=""):
        spawn_dir.mkdir(exist_ok=True)
        return str(spawn_dir)

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        # Simulate the wrapper: load env.json, unlink it, write helper.pid.
        env_path = spawn_dir / "env.json"
        pid_path = spawn_dir / "helper.pid"
        assert env_path.exists()
        data = json.loads(env_path.read_text(encoding="utf-8"))
        assert data["KEY_AMNESIA_PROMPT_AUTHKEY"] == "a" * 64
        env_path.unlink()
        pid_path.write_text("55501", encoding="utf-8")
        return MagicMock(poll=MagicMock(return_value=0))  # launcher exits

    alive = {55501: True}

    def fake_kill(pid: int, sig: int) -> None:
        if pid not in alive or not alive[pid]:
            raise ProcessLookupError()
        if sig != 0:
            alive[pid] = False

    monkeypatch.setattr(
        "key_amnesia.platform.shutil.which",
        lambda name: "/usr/bin/osascript" if name == "osascript" else None,
    )
    monkeypatch.setattr("key_amnesia.platform.os.kill", fake_kill)
    monkeypatch.setattr("key_amnesia.platform.tempfile.mkdtemp", fake_mkdtemp)

    result = spawn_isolated_console(
        HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=fake_popen
    )

    assert isinstance(result, PidFileProcess)
    assert result.pid == 55501
    assert result.poll() is None
    joined = " ".join(str(c) for c in captured["cmd"])
    assert "api_key" not in joined
    assert "a" * 64 not in joined
    assert "KEY_AMNESIA_PROMPT_AUTHKEY" not in joined
    # Secrets were not passed via launcher env=
    assert "env" not in captured["kwargs"]


def test_darwin_pid_file_never_appears_fail_closed(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr("key_amnesia.platform._MACOS_PID_WAIT_S", 0.05)
    spawn_dir = tmp_path / "spawn2"

    def fake_mkdtemp(prefix=""):
        spawn_dir.mkdir(exist_ok=True)
        return str(spawn_dir)

    monkeypatch.setattr(
        "key_amnesia.platform.shutil.which",
        lambda name: "/usr/bin/osascript" if name == "osascript" else None,
    )
    monkeypatch.setattr("key_amnesia.platform.tempfile.mkdtemp", fake_mkdtemp)

    def fake_popen(cmd, **kwargs):
        return MagicMock(poll=MagicMock(return_value=0))

    with pytest.raises(OSError, match="did not record a PID|Fail closed"):
        spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=fake_popen)
