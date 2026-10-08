"""Regression: the ~2-minutes-to-expiry extend prompt must fire even when
the guard is completely idle (no incoming ka run/status/list requests).

The prompt check used to live only at the top of guard_serve's outer loop.
An already-idle guard — blocked inside the inner accept-wait loop *before*
crossing the extend-prompt threshold — never revisits the outer-loop top
until a client connects or the session hits hard expiry, because
listener.accept() has no timeout and simply never returns without one.
So the prompt would silently never appear for a session nobody talked to
in its final couple of minutes.

These tests set the extend window artificially small (via
EXTEND_PROMPT_WINDOW_S) so the guard starts *outside* the window, then
crosses into it while parked inside a listener.accept() call that never
returns — exactly the idle real-world shape the bug report described.
"""

from __future__ import annotations

import threading
import time

from key_amnesia.guard import GuardState, guard_serve


class _NeverConnectsListener:
    """Simulates an idle guard: accept() blocks far longer than the test
    needs, so no client connection is ever available."""

    def accept(self):
        time.sleep(5)
        raise RuntimeError("unreachable — test should finish long before this")


def _fake_stdin_isatty(monkeypatch, guard_mod) -> None:
    class _FakeStdin:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(guard_mod.sys, "stdin", _FakeStdin())


def test_extend_prompt_fires_while_idle_in_accept_wait(monkeypatch) -> None:
    from key_amnesia import guard as guard_mod

    monkeypatch.setattr(guard_mod, "EXTEND_PROMPT_WINDOW_S", 0.6)
    prompts: list[str] = []
    monkeypatch.setattr(
        guard_mod.theme, "out", lambda msg="", **k: prompts.append(str(msg))
    )
    _fake_stdin_isatty(monkeypatch, guard_mod)
    monkeypatch.setattr("builtins.input", lambda: "n")  # decline the extend

    # Starts *outside* the (shrunk) 0.6s window, so the very first
    # outer-loop-top check must NOT fire — the guard immediately parks
    # inside the never-returning accept() call, same as a real idle guard.
    state = GuardState(
        secrets={},
        expires_at=time.time() + 1.0,
        address="dummy",
        authkey=b"a" * 32,
    )

    reason = guard_serve(state, _NeverConnectsListener())

    assert reason == "expired"
    assert any("expires in" in p and "Extend?" in p for p in prompts)


def test_extend_accepted_pushes_expiry_out_while_idle_in_accept_wait(
    monkeypatch,
) -> None:
    """Saying yes to an idle-guard extend prompt must actually push the
    expiry forward, with no client ever having connected."""
    from key_amnesia import guard as guard_mod

    monkeypatch.setattr(guard_mod, "EXTEND_PROMPT_WINDOW_S", 0.6)
    monkeypatch.setattr(guard_mod.theme, "out", lambda *a, **k: None)
    monkeypatch.setattr(guard_mod, "write_guard_lock", lambda *a, **k: None)
    _fake_stdin_isatty(monkeypatch, guard_mod)
    monkeypatch.setattr("builtins.input", lambda: "y")

    state = GuardState(
        secrets={},
        expires_at=time.time() + 1.0,
        address="dummy",
        authkey=b"a" * 32,
    )
    original_expiry = state.expires_at

    def _stop_shortly() -> None:
        time.sleep(1.0)  # let the extend prompt fire and get answered first
        state.stop.set()

    threading.Thread(target=_stop_shortly, daemon=True).start()
    guard_serve(state, _NeverConnectsListener())

    assert state.expires_at > original_expiry + 60 * 29  # pushed out by ~30m
