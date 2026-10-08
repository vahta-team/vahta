"""Admission-consent layer on top of the guard's authkey trust boundary.

A live authkey alone lets any same-user process talk to the guard (the
ssh-agent-style limit documented in DESIGN.md). Admission adds a UX/consent
gate on top, bound to the connecting process's **kernel-verified identity**
(`peer_identity.PeerIdentity`) rather than a bearer credential: the first
request from an unrecognized process tree is a yes/no prompt on the guard's
own foreground TTY; approval binds admission to that identity (and its real
OS descendants) for the rest of this guard run, scoped to whichever secrets
were actually granted.

These tests exercise `_check_admission`'s kernel-identity path by passing a
`peer=PeerIdentity(...)` kwarg to `guard_handle_message`, exactly as
`guard_serve` does in production. Legacy in-memory opaque-token behavior
is covered separately in `test_guard_admission_legacy.py` via
`guard_handle_message_legacy`.
"""

from __future__ import annotations

import sys
import time

import pytest

from key_amnesia.guard import (
    AdmittedSession,
    GuardState,
    guard_handle_message,
)
from key_amnesia.peer_identity import PeerIdentity

PEER = PeerIdentity(pid=4242, start_time=1000)
OTHER_PEER = PeerIdentity(pid=9999, start_time=2000)


def _state(**overrides) -> GuardState:
    kwargs = dict(
        secrets={"api_key": "super-secret-value-123"},
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"m" * 32,
    )
    kwargs.update(overrides)
    return GuardState(**kwargs)


def _admitted(peer: PeerIdentity, **overrides) -> AdmittedSession:
    kwargs = dict(
        identities=[peer],
        first_seen="2026-01-01T00:00:00+00:00",
        granted_secrets=set(),
        unscoped=True,
        granted_until=time.time() + 600,
    )
    kwargs.update(overrides)
    return AdmittedSession(**kwargs)


def test_unrecognized_peer_prompts_and_admits(ka_home) -> None:
    state = _state()
    calls: list[tuple[PeerIdentity, str]] = []

    def approve(caller: PeerIdentity, summary: str) -> bool:
        calls.append((caller, summary))
        return True

    reply = guard_handle_message(
        {"verb": "list"}, state, peer=PEER, admit_prompt=approve
    )
    assert reply["ok"] is True
    assert reply["names"] == ["api_key"]
    assert "admission_token" not in reply  # nothing minted on this path
    assert calls == [(PEER, "list secret names")]
    assert state.admitted is not None
    assert state.admitted.identities == [PEER]
    assert state.admitted.request_count == 1


def test_unrecognized_peer_denies_on_no(ka_home) -> None:
    state = _state()
    reply = guard_handle_message(
        {"verb": "list"},
        state,
        peer=PEER,
        admit_prompt=lambda caller, summary: False,
    )
    assert reply["ok"] is False
    assert reply["reason"] == "admission denied"
    assert state.admitted is None


def test_unrecognized_peer_denies_on_timeout(monkeypatch, ka_home) -> None:
    """A real (unmocked) prompt that never answers must fail closed quickly."""
    state = _state()
    monkeypatch.setattr("key_amnesia.guard.ADMISSION_TIMEOUT_S", 0.2)
    monkeypatch.setattr("builtins.input", lambda *a, **k: (time.sleep(5), "y")[1])

    start = time.monotonic()
    reply = guard_handle_message({"verb": "list"}, state, peer=PEER)
    elapsed = time.monotonic() - start

    assert reply["ok"] is False
    assert reply["reason"] == "admission denied"
    assert elapsed < 3  # bounded by ADMISSION_TIMEOUT_S, not the 5s hang


def test_unavailable_peer_identity_fails_closed(ka_home) -> None:
    """`peer=None` means a real kernel lookup was attempted and failed — this
    must never be treated as "no peer info supplied" (the legacy fallback)."""
    state = _state()

    def fail_if_called(*_a, **_k):
        raise AssertionError("must never prompt for an unverifiable peer")

    reply = guard_handle_message(
        {"verb": "list"}, state, peer=None, admit_prompt=fail_if_called
    )
    assert reply["ok"] is False
    assert reply["reason"] == "admission denied"
    assert state.admitted is None


def test_admitted_peer_skips_prompt_no_reprompt(ka_home) -> None:
    state = _state()
    state.admitted = _admitted(PEER)

    def fail_if_called(*_a, **_k):
        raise AssertionError("admit_prompt must not be called for an admitted peer")

    reply = guard_handle_message(
        {"verb": "list"}, state, peer=PEER, admit_prompt=fail_if_called
    )
    assert reply["ok"] is True
    assert state.admitted.request_count == 1


def test_descendant_of_admitted_peer_is_silently_in_tree(monkeypatch, ka_home) -> None:
    """A real OS descendant of the admitted process is recognized without a
    prompt (see `peer_identity.is_in_admitted_tree`) — mock the ancestor
    walk rather than spawning a real child process (covered by the E2E
    security tests in `test_peer_identity_e2e.py`)."""
    state = _state()
    state.admitted = _admitted(PEER)
    child = PeerIdentity(pid=5555, start_time=3000)
    monkeypatch.setattr(
        "key_amnesia.peer_identity.get_ancestor_chain",
        lambda pid, max_depth=32: [child, PEER],
    )

    def fail_if_called(*_a, **_k):
        raise AssertionError("descendant of admitted peer must not reprompt")

    reply = guard_handle_message(
        {"verb": "list"}, state, peer=child, admit_prompt=fail_if_called
    )
    assert reply["ok"] is True


def test_unrelated_peer_is_not_in_tree_and_reprompts(ka_home) -> None:
    """A peer sharing no OS ancestry with the admitted process is treated as
    a fresh, unrecognized peer — never silently admitted."""
    state = _state()
    state.admitted = _admitted(PEER)
    calls = {"n": 0}

    def approve(*_a, **_k):
        calls["n"] += 1
        return True

    reply = guard_handle_message(
        {"verb": "list"}, state, peer=OTHER_PEER, admit_prompt=approve
    )
    assert reply["ok"] is True
    assert calls["n"] == 1
    assert state.admitted.identities == [OTHER_PEER]  # grant now bound to the new peer


def test_secret_scoped_grant_allows_granted_secret_without_reprompt(ka_home) -> None:
    state = _state(secrets={"api_key": "v1", "db_pass": "v2"})
    state.admitted = _admitted(PEER, granted_secrets={"api_key"}, unscoped=False)

    def fail_if_called(*_a, **_k):
        raise AssertionError("must not reprompt for an already-granted secret")

    reply = guard_handle_message(
        {
            "verb": "run",
            "secret_names": ["api_key"],
            "command": [sys.executable, "-c", "print('ok')"],
        },
        state,
        peer=PEER,
        admit_prompt=fail_if_called,
    )
    assert reply["ok"] is True


def test_secret_scoped_grant_reprompts_for_ungranted_secret(ka_home) -> None:
    state = _state(secrets={"api_key": "v1", "db_pass": "v2"})
    state.admitted = _admitted(PEER, granted_secrets={"api_key"}, unscoped=False)
    calls = {"n": 0}

    def approve(*_a, **_k):
        calls["n"] += 1
        return True

    reply = guard_handle_message(
        {
            "verb": "run",
            "secret_names": ["db_pass"],
            "command": [sys.executable, "-c", "print('ok')"],
        },
        state,
        peer=PEER,
        admit_prompt=approve,
    )
    assert reply["ok"] is True
    assert calls["n"] == 1
    # Scope expanded to include the newly-approved secret, old grant retained.
    assert state.admitted.granted_secrets == {"api_key", "db_pass"}


def test_secret_scoped_grant_denies_on_no_for_ungranted_secret(ka_home) -> None:
    state = _state(secrets={"api_key": "v1", "db_pass": "v2"})
    state.admitted = _admitted(PEER, granted_secrets={"api_key"}, unscoped=False)

    reply = guard_handle_message(
        {
            "verb": "run",
            "secret_names": ["db_pass"],
            "command": [sys.executable, "-c", "print('ok')"],
        },
        state,
        peer=PEER,
        admit_prompt=lambda *a, **k: False,
    )
    assert reply["ok"] is False
    assert reply["reason"] == "admission denied"
    # Old grant untouched by the rejected expansion attempt.
    assert state.admitted.granted_secrets == {"api_key"}


def test_unscoped_admission_allows_any_secret_without_reprompt(ka_home) -> None:
    state = _state(secrets={"api_key": "v1", "db_pass": "v2"})
    state.admitted = _admitted(PEER, unscoped=True)

    def fail_if_called(*_a, **_k):
        raise AssertionError("unscoped (pre-admit ALL) grant must never reprompt")

    reply = guard_handle_message(
        {
            "verb": "run",
            "secret_names": ["db_pass"],
            "command": [sys.executable, "-c", "print('ok')"],
        },
        state,
        peer=PEER,
        admit_prompt=fail_if_called,
    )
    assert reply["ok"] is True


def test_pre_admit_consumes_window_for_next_unrecognized_peer(ka_home) -> None:
    state = _state()
    state.pre_admit_until = time.time() + 60
    state.pre_admit_unscoped = True

    def fail_if_called(*_a, **_k):
        raise AssertionError("a pre-admitted peer must not be prompted")

    reply = guard_handle_message(
        {"verb": "list"}, state, peer=PEER, admit_prompt=fail_if_called
    )
    assert reply["ok"] is True
    assert state.admitted is not None
    assert state.admitted.unscoped is True
    # Single-use: consumed regardless of the window's remaining time.
    assert state.pre_admit_until is None


def test_pre_admit_scoped_to_specific_secrets(ka_home) -> None:
    state = _state(secrets={"api_key": "v1", "db_pass": "v2"})
    state.pre_admit_until = time.time() + 60
    state.pre_admit_unscoped = False
    state.pre_admit_secrets = {"api_key"}

    def fail_if_called(*_a, **_k):
        raise AssertionError("pre-admitted scope must not reprompt for its own secret")

    reply = guard_handle_message(
        {
            "verb": "run",
            "secret_names": ["api_key"],
            "command": [sys.executable, "-c", "print('ok')"],
        },
        state,
        peer=PEER,
        admit_prompt=fail_if_called,
    )
    assert reply["ok"] is True
    assert state.admitted.granted_secrets == {"api_key"}
    assert state.admitted.unscoped is False


def test_pre_admit_expired_window_falls_back_to_prompt(ka_home) -> None:
    state = _state()
    state.pre_admit_until = time.time() - 1  # already expired
    state.pre_admit_unscoped = True
    calls = {"n": 0}

    def approve(*_a, **_k):
        calls["n"] += 1
        return True

    reply = guard_handle_message(
        {"verb": "list"}, state, peer=PEER, admit_prompt=approve
    )
    assert reply["ok"] is True
    assert calls["n"] == 1


def test_status_reports_admission_state(ka_home) -> None:
    state = _state()
    state.admitted = _admitted(PEER, request_count=3)
    reply = guard_handle_message({"verb": "status"}, state, peer=PEER)
    assert reply["ok"] is True
    assert reply["admitted"] is True
    assert reply["admitted_since"] == "2026-01-01T00:00:00+00:00"
    assert reply["admitted_pids"] == [PEER.pid]
    assert reply["request_count"] == 4  # incremented by this very request


def test_status_reports_pre_admit_pending(ka_home) -> None:
    """`_dispatch_verb` reply shape while pre-admit is armed but not yet
    consumed — dispatched directly (below `_check_admission`) since *any*
    real request from an unrecognized peer would immediately consume the
    single-use pre-admit window before ever reaching this reply."""
    from key_amnesia.guard import _dispatch_verb

    state = _state()
    state.pre_admit_until = time.time() + 60
    state.pre_admit_unscoped = True
    reply = _dispatch_verb("status", {"verb": "status"}, state)
    assert reply["ok"] is True
    assert reply["pre_admit_pending"] is True
    assert reply["pre_admit_scope"] == "ALL (unscoped pre-admit)"


# --- `--admit-tree` (0.4.5) -------------------------------------------------

PARENT = PeerIdentity(pid=100, start_time=10)
GRANDPARENT = PeerIdentity(pid=50, start_time=5)
GREAT_GP = PeerIdentity(pid=40, start_time=4)
# Chain long enough that PARENT is not floored (ANCESTOR_FLOOR_TAIL=2).
_TREE_CHAIN = [PEER, PARENT, GRANDPARENT, GREAT_GP]


def _enable_admit_tree_mocks(monkeypatch, chain_for_pid=None) -> None:
    """Ownability / image / hold stubs so fake pids are offerable in tests."""
    chains = chain_for_pid or {}

    def fake_chain(pid, max_depth=32):
        if pid in chains:
            return list(chains[pid])
        return list(_TREE_CHAIN)

    monkeypatch.setattr(
        "key_amnesia.peer_identity.get_ancestor_chain", fake_chain
    )
    monkeypatch.setattr(
        "key_amnesia.peer_identity.ancestor_owned_by_self", lambda _ident: True
    )
    monkeypatch.setattr(
        "key_amnesia.peer_identity.get_process_image_name",
        lambda pid: f"img-{pid}",
    )
    monkeypatch.setattr(
        "key_amnesia.peer_identity.hold_identity",
        lambda ident: ident,
    )


def test_admit_tree_flag_off_sibling_still_prompts(ka_home, monkeypatch) -> None:
    """Default (flag off): sibling of an admitted peer still gets y/N."""
    state = _state()  # admit_tree defaults False
    state.admitted = _admitted(PEER)
    sibling = PeerIdentity(pid=7777, start_time=4000)
    monkeypatch.setattr(
        "key_amnesia.peer_identity.get_ancestor_chain",
        lambda pid, max_depth=32: [sibling, PARENT, GRANDPARENT, GREAT_GP],
    )
    calls = {"n": 0}

    def approve(*_a, **_k):
        calls["n"] += 1
        return True

    reply = guard_handle_message(
        {"verb": "list"}, state, peer=sibling, admit_prompt=approve
    )
    assert reply["ok"] is True
    assert calls["n"] == 1
    assert state.admitted.identities == [sibling]


def test_admit_tree_parent_root_admits_sibling_silently(ka_home, monkeypatch) -> None:
    """Flag on + human picks parent → sibling sharing that parent is in-tree."""
    _enable_admit_tree_mocks(
        monkeypatch,
        chain_for_pid={
            PEER.pid: _TREE_CHAIN,
            OTHER_PEER.pid: [OTHER_PEER, PARENT, GRANDPARENT, GREAT_GP],
        },
    )
    state = _state(admit_tree=True)
    # Parent is offerable index 2 (after connecting peer).
    state.stdin_pump.read_line = lambda _timeout: "2"  # type: ignore[method-assign]

    def fail_if_y_n(*_a, **_k):
        raise AssertionError("admit_tree path must not use default y/N prompt")

    reply = guard_handle_message(
        {"verb": "list"}, state, peer=PEER, admit_prompt=fail_if_y_n
    )
    assert reply["ok"] is True
    assert state.admitted is not None
    assert state.admitted.identities == [PARENT]
    assert state.admitted.unscoped is False

    def fail_if_called(*_a, **_k):
        raise AssertionError("sibling under admitted parent must not reprompt")

    reply2 = guard_handle_message(
        {"verb": "list"},
        state,
        peer=OTHER_PEER,
        admit_prompt=fail_if_called,
    )
    assert reply2["ok"] is True


def test_admit_tree_message_cannot_supply_root_pid(ka_home, monkeypatch) -> None:
    """Forged message fields are ignored — root comes only from the chain."""
    _enable_admit_tree_mocks(monkeypatch)
    state = _state(admit_tree=True)
    state.stdin_pump.read_line = lambda _timeout: "2"  # type: ignore[method-assign]
    forged = PeerIdentity(pid=99999, start_time=1)

    reply = guard_handle_message(
        {
            "verb": "list",
            "root_pid": forged.pid,
            "admit_root_pid": forged.pid,
            "claimed_root": forged.pid,
        },
        state,
        peer=PEER,
        admit_prompt=lambda *_a, **_k: False,
    )
    assert reply["ok"] is True
    assert state.admitted is not None
    assert state.admitted.identities == [PARENT]
    assert forged not in state.admitted.identities


def test_admit_tree_non_chain_identity_never_stored(ka_home, monkeypatch) -> None:
    """Typing a raw pid (not a menu index) denies — never stores that pid."""
    _enable_admit_tree_mocks(monkeypatch)
    state = _state(admit_tree=True)
    # PARENT.pid happens to be 100 — out of range for [1..k] menu.
    state.stdin_pump.read_line = lambda _timeout: str(PARENT.pid)  # type: ignore[method-assign]

    reply = guard_handle_message(
        {"verb": "list"},
        state,
        peer=PEER,
        admit_prompt=lambda *_a, **_k: True,  # must not fall through
    )
    assert reply["ok"] is False
    assert state.admitted is None


def test_admit_tree_same_pid_different_start_time_not_in_tree(
    ka_home, monkeypatch
) -> None:
    """Recycled pid (same number, different start_time) is not in-tree."""
    _enable_admit_tree_mocks(
        monkeypatch,
        chain_for_pid={PEER.pid: _TREE_CHAIN},
    )
    state = _state(admit_tree=True)
    state.stdin_pump.read_line = lambda _timeout: "2"  # type: ignore[method-assign]
    reply = guard_handle_message({"verb": "list"}, state, peer=PEER)
    assert reply["ok"] is True
    assert state.admitted.identities == [PARENT]

    recycled = PeerIdentity(pid=PARENT.pid, start_time=PARENT.start_time + 999)
    monkeypatch.setattr(
        "key_amnesia.peer_identity.get_ancestor_chain",
        lambda pid, max_depth=32: [recycled],
    )
    calls = {"n": 0}

    def approve(*_a, **_k):
        calls["n"] += 1
        return True

    # admit_tree still on, but recycled's chain is short → normal y/N.
    reply2 = guard_handle_message(
        {"verb": "list"}, state, peer=recycled, admit_prompt=approve
    )
    assert reply2["ok"] is True
    assert calls["n"] == 1
    assert state.admitted.identities == [recycled]


def test_admit_tree_depth_floor_levels_unavailable(ka_home, monkeypatch, capsys) -> None:
    """Last ANCESTOR_FLOOR_TAIL chain entries are listed as skipped, not offered."""
    from key_amnesia.peer_identity import ANCESTOR_FLOOR_TAIL, classify_admit_tree_levels

    monkeypatch.setattr(
        "key_amnesia.peer_identity.ancestor_owned_by_self", lambda _ident: True
    )
    offerable, skipped = classify_admit_tree_levels(_TREE_CHAIN)
    assert PARENT in offerable
    floored_pids = {n.pid for n, _r in skipped}
    assert GRANDPARENT.pid in floored_pids
    assert GREAT_GP.pid in floored_pids
    assert len([r for _n, r in skipped if "depth floor" in r]) == ANCESTOR_FLOOR_TAIL

    _enable_admit_tree_mocks(monkeypatch)
    state = _state(admit_tree=True)
    state.stdin_pump.read_line = lambda _timeout: "1"  # type: ignore[method-assign]
    reply = guard_handle_message({"verb": "list"}, state, peer=PEER)
    assert reply["ok"] is True
    out = capsys.readouterr().out
    assert "skipped" in out
    assert "depth floor" in out
    # Choosing [1] admits connecting peer, never a floored ancestor.
    assert state.admitted.identities == [PEER]


def test_admit_tree_prompt_labels_depth_narrow_to_wide(
    ka_home, monkeypatch, capsys
) -> None:
    """Menu labels show leaf→ancestor so the human can pick trust width."""
    _enable_admit_tree_mocks(monkeypatch)
    state = _state(admit_tree=True)
    state.stdin_pump.read_line = lambda _timeout: "2"  # type: ignore[method-assign]
    reply = guard_handle_message({"verb": "list"}, state, peer=PEER)
    assert reply["ok"] is True
    out = capsys.readouterr().out
    assert "narrower trust" in out or "narrow" in out
    assert "this client (narrowest)" in out
    assert "parent" in out
    assert "Choose root" in out


def test_admit_tree_audit_via_interactive_tree(ka_home, monkeypatch) -> None:
    from key_amnesia.paths import audit_log_path

    _enable_admit_tree_mocks(monkeypatch)
    state = _state(admit_tree=True)
    state.stdin_pump.read_line = lambda _timeout: "2"  # type: ignore[method-assign]
    reply = guard_handle_message({"verb": "list"}, state, peer=PEER)
    assert reply["ok"] is True
    text = audit_log_path().read_text(encoding="utf-8")
    assert "via=interactive-tree" in text
    assert f"pid={PARENT.pid}" in text


def test_admit_tree_empty_or_short_chain_uses_normal_prompt(
    ka_home, monkeypatch
) -> None:
    """Empty / single-entry chain with admit_tree still uses default y/N."""
    state = _state(admit_tree=True)
    monkeypatch.setattr(
        "key_amnesia.peer_identity.get_ancestor_chain",
        lambda pid, max_depth=32: [PEER],
    )
    calls = {"n": 0}

    def approve(*_a, **_k):
        calls["n"] += 1
        return True

    reply = guard_handle_message(
        {"verb": "list"}, state, peer=PEER, admit_prompt=approve
    )
    assert reply["ok"] is True
    assert calls["n"] == 1
    assert state.admitted.identities == [PEER]

    state2 = _state(admit_tree=True)
    monkeypatch.setattr(
        "key_amnesia.peer_identity.get_ancestor_chain",
        lambda pid, max_depth=32: [],
    )
    calls["n"] = 0
    reply2 = guard_handle_message(
        {"verb": "list"}, state2, peer=OTHER_PEER, admit_prompt=approve
    )
    assert reply2["ok"] is True
    assert calls["n"] == 1


@pytest.mark.skipif(sys.platform != "win32", reason="OpenProcess hold is Windows-only")
def test_admit_tree_windows_holds_root_handle_and_releases_on_replace(
    ka_home, monkeypatch
) -> None:
    """Chosen ancestor root gets hold_identity; replace releases prior handle."""
    import os

    from key_amnesia.guard import _admit_peer
    from key_amnesia.peer_identity import _win_identity_for_pid

    parent_held = _win_identity_for_pid(os.getpid(), hold=True)
    try:
        peer = PeerIdentity(pid=4242, start_time=1000)
        gp = PeerIdentity(pid=50, start_time=5)
        ggp = PeerIdentity(pid=40, start_time=4)
        # Bare (no handle) copy used in the chain / offerable list.
        parent_bare = PeerIdentity(
            pid=parent_held.pid, start_time=parent_held.start_time
        )
        chain = [peer, parent_bare, gp, ggp]

        monkeypatch.setattr(
            "key_amnesia.peer_identity.get_ancestor_chain",
            lambda pid, max_depth=32: list(chain),
        )
        monkeypatch.setattr(
            "key_amnesia.peer_identity.ancestor_owned_by_self",
            lambda _ident: True,
        )
        monkeypatch.setattr(
            "key_amnesia.peer_identity.get_process_image_name",
            lambda pid: f"img-{pid}",
        )
        monkeypatch.setattr(
            "key_amnesia.peer_identity.hold_identity",
            lambda ident: parent_held if ident.matches(parent_held) else ident,
        )

        state = _state(admit_tree=True)
        state.stdin_pump.read_line = lambda _timeout: "2"  # type: ignore[method-assign]
        reply = guard_handle_message({"verb": "list"}, state, peer=peer)
        assert reply["ok"] is True
        root = state.admitted.identities[0]
        assert root is parent_held
        assert root.process_handle is not None
        assert root.process_handle._closed is False

        prior_handle = root.process_handle
        replacement = PeerIdentity(pid=9999, start_time=2000)
        _admit_peer(
            state,
            replacement,
            granted_secrets=set(),
            unscoped=False,
            summary="list",
            via="interactive",
        )
        assert prior_handle._closed is True
    finally:
        parent_held.release()
