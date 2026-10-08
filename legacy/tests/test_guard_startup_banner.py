"""`ka unlock`'s startup banner must tell you when it expires and how to
stop it early — feedback from a real user who didn't see either."""

from __future__ import annotations

import threading
import time

from key_amnesia.guard import GuardState, guard_serve, run_foreground_guard


class _NeverConnectsListener:
    def accept(self):
        time.sleep(5)
        raise RuntimeError("unreachable — test should finish long before this")

    def close(self) -> None:
        pass


def test_startup_banner_shows_expiry_clock_and_how_to_stop(monkeypatch) -> None:
    from key_amnesia import guard as guard_mod

    monkeypatch.setattr(
        guard_mod.ipc, "start_listener", lambda: (object(), "addr", b"k" * 32)
    )
    monkeypatch.setattr(guard_mod, "write_guard_lock", lambda *a, **k: None)
    monkeypatch.setattr(guard_mod, "clear_guard_lock", lambda *a, **k: None)
    monkeypatch.setattr(guard_mod, "guard_serve", lambda state, listener: "locked")
    monkeypatch.setattr(guard_mod, "_write_last_guard_state", lambda *a, **k: None)

    lines: list[str] = []
    monkeypatch.setattr(
        guard_mod.theme, "success", lambda msg="", **k: lines.append(str(msg))
    )
    monkeypatch.setattr(
        guard_mod.theme, "detail", lambda msg="", **k: lines.append(str(msg))
    )

    rc = run_foreground_guard({"secrets": {}}, timeout_minutes=30)

    assert rc == 0
    assert any("Guard listening" in l and "timeout 30m" in l for l in lines)
    assert any("expires at" in l for l in lines)
    assert any("Ctrl+C" in l and "`ka lock`" in l for l in lines)
    assert any("`ka status`" in l for l in lines)


def test_idle_reminder_fires_while_expiry_still_far_off(monkeypatch) -> None:
    """A guard nobody talks to should still get a periodic nudge with time
    remaining — not just silence until the 2-minute extend prompt."""
    from key_amnesia import guard as guard_mod

    monkeypatch.setattr(guard_mod, "REMINDER_INTERVAL_S", 0.3)
    reminders: list[str] = []
    monkeypatch.setattr(
        guard_mod.theme, "detail", lambda msg="", **k: reminders.append(str(msg))
    )

    class _FakeStdout:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(guard_mod.sys, "stdout", _FakeStdout())

    state = GuardState(
        secrets={},
        expires_at=time.time() + 200.0,  # well outside EXTEND_PROMPT_WINDOW_S
        address="dummy",
        authkey=b"a" * 32,
    )

    def _stop_shortly() -> None:
        time.sleep(1.0)
        state.stop.set()

    threading.Thread(target=_stop_shortly, daemon=True).start()
    guard_serve(state, _NeverConnectsListener())

    assert any("remaining" in r for r in reminders)


def test_reminder_suppressed_once_inside_extend_window(monkeypatch) -> None:
    """Once expiry is within the extend-prompt window, the periodic reminder
    should back off — the extend prompt already covers that ground."""
    from key_amnesia import guard as guard_mod

    monkeypatch.setattr(guard_mod, "REMINDER_INTERVAL_S", 0.3)
    monkeypatch.setattr(guard_mod, "EXTEND_PROMPT_WINDOW_S", 100.0)
    reminders: list[str] = []
    monkeypatch.setattr(
        guard_mod.theme, "detail", lambda msg="", **k: reminders.append(str(msg))
    )
    monkeypatch.setattr(guard_mod.theme, "out", lambda *a, **k: None)

    class _FakeStdout:
        def isatty(self) -> bool:
            return True

    class _FakeStdin:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(guard_mod.sys, "stdout", _FakeStdout())
    monkeypatch.setattr(guard_mod.sys, "stdin", _FakeStdin())
    monkeypatch.setattr("builtins.input", lambda: "n")

    state = GuardState(
        secrets={},
        expires_at=time.time() + 1.0,  # inside the (widened) extend window
        address="dummy",
        authkey=b"a" * 32,
    )

    # Force-stop shortly after hard expiry so a leftover accept thread or a
    # poisoned concurrent guard cannot hang this test in CI.
    def _stop_after_expiry() -> None:
        time.sleep(1.5)
        state.stop.set()

    threading.Thread(target=_stop_after_expiry, daemon=True).start()
    guard_serve(state, _NeverConnectsListener())

    assert not any("remaining" in r for r in reminders)
