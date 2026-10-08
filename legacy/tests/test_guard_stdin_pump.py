"""Regression: a live yes/no prompt must not lose an answer typed for it.

Each admission/extend prompt used to spawn its own thread around a blocking
input() call, joined with a timeout. A thread that timed out was never
killed — Python cannot cancel a blocking input() — so it kept running,
still blocked on stdin, forever. A later prompt's fresh thread then raced
it for the next typed line: whichever thread the OS handed the line to
"won", so an explicit "y" typed in answer to a visible, still-open prompt
could be silently swallowed by an abandoned thread from an earlier,
already-timed-out one — reproduced live: a founder session that answered
"y" to a run request still got "admission denied".

_StdinPump fixes this by ensuring at most one thread is ever blocked in
input() at a time, and that thread reads exactly one line then stops (it
must not loop, or a fast/non-blocking input() — real piped stdin, or a
test double — spins it into an unbounded busy loop; this regressed once
during development and ballooned a test run to several GB of RAM).
"""

from __future__ import annotations

import threading
import time

from key_amnesia.guard import _StdinPump


def test_late_answer_to_an_earlier_timed_out_wait_is_not_lost() -> None:
    """A caller that gave up on timeout must not cost a later caller the
    eventual answer to the same underlying question."""
    calls = {"n": 0}
    lock = threading.Lock()

    def slow_input() -> str:
        with lock:
            calls["n"] += 1
        time.sleep(0.3)
        return "y"

    pump = _StdinPump()

    import builtins

    real_input = builtins.input
    builtins.input = slow_input
    try:
        # Gives up before slow_input() returns — must not spawn a second
        # concurrent reader, and must not lose the eventual answer.
        first = pump.read_line(timeout=0.05)
        assert first is None

        # Same underlying input() call is still in flight; this call must
        # receive its result rather than starting a competing one.
        second = pump.read_line(timeout=1.0)
        assert second == "y"
    finally:
        builtins.input = real_input

    assert calls["n"] == 1, "a stale, still-in-flight reader must be reused, not duplicated"


def test_stale_unclaimed_answer_is_discarded_not_reused() -> None:
    """An answer that arrives while nobody is waiting belongs to whatever
    question was on screen when it was typed — it must not silently answer
    a later, unrelated question instead."""
    calls = {"n": 0}
    lock = threading.Lock()

    def input_stub() -> str:
        with lock:
            calls["n"] += 1
            n = calls["n"]
        if n == 1:
            time.sleep(0.2)
            return "stale-answer"
        return "fresh-answer"

    pump = _StdinPump()

    import builtins

    real_input = builtins.input
    builtins.input = input_stub
    try:
        # Times out well before input_stub()'s first call returns.
        assert pump.read_line(timeout=0.05) is None

        # Let the first input() call actually complete with nobody waiting.
        time.sleep(0.35)

        # A new, unrelated question — must not silently receive the earlier
        # unclaimed "stale-answer".
        answer = pump.read_line(timeout=1.0)
    finally:
        builtins.input = real_input

    assert answer == "fresh-answer"
    assert calls["n"] == 2


def test_eof_is_reported_once_pending_read_settles() -> None:
    def raise_eof() -> str:
        raise EOFError

    pump = _StdinPump()

    import builtins

    real_input = builtins.input
    builtins.input = raise_eof
    try:
        assert pump.read_line(timeout=1.0) is None
        # A stream that has hit EOF will not produce more lines; further
        # calls must fail fast rather than hang waiting for one.
        start = time.monotonic()
        assert pump.read_line(timeout=5.0) is None
        assert time.monotonic() - start < 1.0
    finally:
        builtins.input = real_input
