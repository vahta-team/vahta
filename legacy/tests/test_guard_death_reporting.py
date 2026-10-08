"""Honest death reporting: last_guard_state.json + the "no live guard" message.

Every guard exit path — locked, expired, interrupted, crashed — writes an
honest reason before guard.lock is cleared, so `ka lock` / `ka status` can
say what actually happened instead of a bare "No active guard session."
"""

from __future__ import annotations

import json
import threading
import time

from key_amnesia import ipc
from key_amnesia.guard import (
    GuardState,
    format_no_guard_message,
    guard_lock_path,
    guard_serve,
    read_last_guard_state,
    run_foreground_guard,
)


def _best_effort_lock_guard() -> None:
    """Stop a leftover foreground guard so it cannot poison later tests."""
    try:
        if not guard_lock_path().exists():
            return
        lock = json.loads(guard_lock_path().read_text(encoding="utf-8"))
        authkey = ipc.authkey_from_hex(lock["authkey_hex"])
        conn = ipc.connect(lock["address"], authkey)
        try:
            ipc.send_msg(conn, {"verb": "lock", "caller_pid": 0})
            ipc.recv_msg(conn, timeout=2)
        finally:
            conn.close()
    except Exception:
        pass


def test_no_previous_session_message(ka_home) -> None:
    assert format_no_guard_message() == (
        "Guard is not running. No previous session recorded."
    )


def test_guard_serve_returns_locked_reason(ka_home, monkeypatch, stub_peer_identity) -> None:
    monkeypatch.setattr("key_amnesia.guard.default_admit_prompt", lambda *a, **k: True)
    listener, address, authkey = ipc.start_listener()
    state = GuardState(
        secrets={"a": "1"},
        expires_at=time.time() + 600,
        address=address,
        authkey=authkey,
    )

    def client() -> None:
        conn = ipc.connect(address, authkey)
        try:
            ipc.send_msg(conn, {"verb": "lock", "caller_pid": 99})
            ipc.recv_msg(conn, timeout=5)
        finally:
            conn.close()

    t = threading.Thread(target=client, daemon=True)
    t.start()
    reason = guard_serve(state, listener)
    t.join(timeout=5)
    assert reason == "locked"
    listener.close()


def test_guard_serve_returns_expired_reason(ka_home) -> None:
    listener, address, authkey = ipc.start_listener()
    state = GuardState(
        secrets={},
        expires_at=time.time() - 1,  # already expired
        address=address,
        authkey=authkey,
    )
    reason = guard_serve(state, listener)
    assert reason == "expired"
    listener.close()


def test_run_foreground_guard_writes_last_state_on_lock(
    ka_home, monkeypatch, capsys, stub_peer_identity
) -> None:
    """A client `lock` request during run_foreground_guard writes reason=locked
    to last_guard_state.json before guard.lock is cleared, and the guard
    printed its live status banner on start."""
    monkeypatch.setattr("key_amnesia.guard.default_admit_prompt", lambda *a, **k: True)

    result: dict = {}

    def unlock_thread() -> None:
        result["rc"] = run_foreground_guard({"secrets": {"a": "1"}}, timeout_minutes=30)

    t = threading.Thread(target=unlock_thread, daemon=True)
    t.start()
    try:
        # Wait for guard.lock to appear.
        deadline = time.time() + 5
        lock = None
        while time.time() < deadline:
            if guard_lock_path().exists():
                try:
                    candidate = json.loads(guard_lock_path().read_text(encoding="utf-8"))
                    if candidate:
                        lock = candidate
                        break
                except Exception:
                    pass
            time.sleep(0.05)
        assert lock is not None

        authkey = ipc.authkey_from_hex(lock["authkey_hex"])
        conn = ipc.connect(lock["address"], authkey)
        try:
            ipc.send_msg(conn, {"verb": "lock", "caller_pid": 12345})
            reply = ipc.recv_msg(conn, timeout=10)
        finally:
            conn.close()
        assert reply.get("ok") is True

        t.join(timeout=5)
        assert result.get("rc") == 0
        assert not guard_lock_path().exists()

        last = read_last_guard_state()
        assert last is not None
        assert last["reason"] == "locked"

        out = capsys.readouterr().out
        assert "Guard listening" in out
        assert "Waiting for requests" in out
    finally:
        _best_effort_lock_guard()
        t.join(timeout=5)


def test_run_foreground_guard_reports_interrupted(ka_home, monkeypatch, capsys) -> None:
    """Ctrl+C (KeyboardInterrupt) during guard_serve is caught, summarized on
    the guard's own TTY, and recorded as reason="interrupted" — not a bare
    crash and not silently swallowed."""

    def raise_interrupt(state, listener):
        raise KeyboardInterrupt

    monkeypatch.setattr("key_amnesia.guard.guard_serve", raise_interrupt)

    rc = run_foreground_guard({"secrets": {"a": "1"}}, timeout_minutes=30)
    assert rc == 0
    assert not guard_lock_path().exists()

    last = read_last_guard_state()
    assert last is not None
    assert last["reason"] == "interrupted"

    out = capsys.readouterr().out
    assert "interrupted" in out.lower()


def test_run_foreground_guard_reports_crashed(ka_home, monkeypatch, capsys) -> None:
    """Any other exception in guard_serve is recorded as reason="crashed: <ExcType>"
    — an honest failure report instead of pretending nothing went wrong."""

    def raise_runtime_error(state, listener):
        raise RuntimeError("boom")

    monkeypatch.setattr("key_amnesia.guard.guard_serve", raise_runtime_error)

    rc = run_foreground_guard({"secrets": {"a": "1"}}, timeout_minutes=30)
    assert rc == 0
    assert not guard_lock_path().exists()

    last = read_last_guard_state()
    assert last is not None
    assert last["reason"] == "crashed: RuntimeError"

    err = capsys.readouterr().err
    assert "boom" in err


def test_last_guard_state_reason_phrase_for_expired(ka_home) -> None:
    from key_amnesia.guard import _write_last_guard_state

    started = time.time() - 60 * 31
    _write_last_guard_state("expired", started, 4)
    msg = format_no_guard_message()
    assert "expired after" in msg
    assert "handled 4 request" in msg


def test_last_guard_state_reason_phrase_singular_request(ka_home) -> None:
    from key_amnesia.guard import _write_last_guard_state

    _write_last_guard_state("locked", time.time() - 5, 1)
    msg = format_no_guard_message()
    assert "handled 1 request)" in msg  # no trailing 's' for exactly one


def test_last_guard_state_crashed_reason_phrase(ka_home) -> None:
    from key_amnesia.guard import _write_last_guard_state

    _write_last_guard_state("crashed: RuntimeError", time.time() - 5, 0)
    msg = format_no_guard_message()
    assert "crashed: RuntimeError" in msg


def test_read_last_guard_state_roundtrip(ka_home) -> None:
    from key_amnesia.guard import _write_last_guard_state

    assert read_last_guard_state() is None
    _write_last_guard_state("locked", time.time() - 10, 2)
    last = read_last_guard_state()
    assert last is not None
    assert last["reason"] == "locked"
    assert last["request_count"] == 2
    assert "started_at" in last and "ended_at" in last
