"""Windows OpenProcess hold for admitted-peer lifetime (0.4.1).

While a handle to the process object stays open, Windows will not recycle
that PID. Ancestor walks still open-read-close (`hold=False`).

We do **not** attempt to reproduce the residual race between
`GetNamedPipeClientProcessId` and `OpenProcess` — that window is
documented (README / DESIGN.md) and not eliminated by holding the handle
after OpenProcess succeeds.
"""

from __future__ import annotations

import os
import sys

import pytest

from key_amnesia.peer_identity import MAX_ANCESTOR_DEPTH, PeerIdentity, get_ancestor_chain


@pytest.mark.skipif(sys.platform != "win32", reason="OpenProcess hold is Windows-only")
def test_win_identity_hold_keeps_open_handle() -> None:
    from key_amnesia.peer_identity import _win_identity_for_pid

    ident = _win_identity_for_pid(os.getpid(), hold=True)
    try:
        assert ident.pid == os.getpid()
        assert ident.process_handle is not None
        assert ident.process_handle.handle != 0
        assert ident.process_handle._closed is False
        # Equality ignores the handle wrapper.
        bare = PeerIdentity(pid=ident.pid, start_time=ident.start_time)
        assert ident == bare
        assert hash(ident) == hash(bare)
    finally:
        ident.release()
    assert ident.process_handle._closed is True
    ident.release()  # idempotent


@pytest.mark.skipif(sys.platform != "win32", reason="OpenProcess hold is Windows-only")
def test_win_identity_default_closes_handle() -> None:
    from key_amnesia.peer_identity import _win_identity_for_pid

    ident = _win_identity_for_pid(os.getpid(), hold=False)
    assert ident.process_handle is None


@pytest.mark.skipif(sys.platform != "win32", reason="OpenProcess hold is Windows-only")
def test_ancestor_chain_does_not_hold_handles() -> None:
    chain = get_ancestor_chain(os.getpid(), max_depth=3)
    assert chain
    assert all(node.process_handle is None for node in chain)


@pytest.mark.skipif(sys.platform != "win32", reason="CreateToolhelp32Snapshot is Windows-only")
def test_ancestor_chain_takes_one_process_snapshot(monkeypatch) -> None:
    """get_ancestor_chain must CreateToolhelp32Snapshot exactly once, any depth."""
    import ctypes

    real_snap = ctypes.windll.kernel32.CreateToolhelp32Snapshot
    calls = {"n": 0}

    def counting_snap(*args, **kwargs):
        calls["n"] += 1
        return real_snap(*args, **kwargs)

    monkeypatch.setattr(
        ctypes.windll.kernel32, "CreateToolhelp32Snapshot", counting_snap
    )
    chain = get_ancestor_chain(os.getpid(), max_depth=MAX_ANCESTOR_DEPTH)
    assert chain
    assert calls["n"] == 1
    # A second walk still snapshots once (not once per hop / prior call).
    calls["n"] = 0
    get_ancestor_chain(os.getpid(), max_depth=1)
    assert calls["n"] == 1


@pytest.mark.skip(
    reason=(
        "Residual race only between GetNamedPipeClientProcessId and OpenProcess "
        "is documented, not eliminated — holding the handle after OpenProcess "
        "prevents later PID recycle for the admission lifetime, but cannot close "
        "the brief pre-OpenProcess window. No reliable deterministic reproduction "
        "in CI; see README limit 7 / DESIGN.md."
    )
)
def test_pid_recycle_race_before_openprocess_documented_not_tested() -> None:
    assert False, "unreachable — documents the residual Windows race"
