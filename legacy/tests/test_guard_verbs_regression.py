"""Guard IPC verb set is frozen — hard guarantee of the two-tier model."""

from __future__ import annotations

import sys
import time

import pytest

from key_amnesia.guard import (
    AdmittedSession,
    GuardState,
    guard_handle_message,
    guard_handle_message_legacy,
)
from key_amnesia.peer_identity import PeerIdentity

# Exact dispatch set — must not grow without a deliberate design change.
GUARD_VERBS = frozenset({"run", "list", "lock", "status", "renew"})

ADMITTED_TOKEN = "test-admitted-token"
PEER = PeerIdentity(pid=4242, start_time=1000)


def _legacy_state() -> GuardState:
    state = GuardState(
        secrets={"api_key": "super-secret-value-123"},
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"g" * 32,
    )
    state.admitted = AdmittedSession(
        token=ADMITTED_TOKEN, first_seen="2026-01-01T00:00:00+00:00"
    )
    return state


def _kernel_state() -> GuardState:
    state = GuardState(
        secrets={"api_key": "super-secret-value-123"},
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"g" * 32,
    )
    state.admitted = AdmittedSession(
        identities=[PEER],
        first_seen="2026-01-01T00:00:00+00:00",
        unscoped=True,
        granted_until=state.expires_at,
    )
    return state


def _dispatch(path: str, msg: dict, state: GuardState) -> dict:
    if path == "legacy":
        return guard_handle_message_legacy(msg, state)
    return guard_handle_message(msg, state, peer=PEER)


def _admit_msg(path: str, verb: str, **extra) -> dict:
    msg: dict = {"verb": verb, **extra}
    if path == "legacy":
        msg["admission_token"] = ADMITTED_TOKEN
    return msg


@pytest.mark.parametrize("path", ("legacy", "kernel"))
def test_guard_verb_set_exactly_five(path: str) -> None:
    """Regression: guard recognizes exactly {run, list, lock, status, renew}."""
    state = _legacy_state() if path == "legacy" else _kernel_state()
    recognized: set[str] = set()
    probes = sorted(GUARD_VERBS | {"get-value", "reveal", "get", "copy", "browser-fill"})
    for verb in probes:
        msg = _admit_msg(path, verb)
        if verb == "run":
            msg.update(
                {
                    "secret_names": ["api_key"],
                    "inject_as": {"api_key": "API_KEY"},
                    "command": [sys.executable, "-c", "print('ok')"],
                }
            )
        if verb == "renew":
            msg["minutes"] = 5
        reply = _dispatch(path, msg, state)
        reason = str(reply.get("reason") or "")
        if reason.startswith("unknown verb"):
            continue
        # Explicit value-return denials still "recognize" the probe as rejected.
        if verb in ("get-value", "reveal", "get", "copy"):
            assert reply.get("ok") is False
            continue
        recognized.add(verb)
    assert recognized == GUARD_VERBS


@pytest.mark.parametrize("path", ("legacy", "kernel"))
def test_guard_value_return_probes_fail(path: str) -> None:
    state = _legacy_state() if path == "legacy" else _kernel_state()
    secret = "super-secret-value-123"
    for verb in ("get-value", "reveal", "get", "copy", "get-logins-for-url"):
        reply = _dispatch(
            path,
            _admit_msg(path, verb, name="api_key", url="https://x"),
            state,
        )
        assert reply.get("ok") is False
        blob = str(reply)
        assert secret not in blob
        assert "password" not in reply or reply.get("password") in (None, "")


@pytest.mark.parametrize("path", ("legacy", "kernel"))
def test_guard_run_never_returns_raw_secret(path: str) -> None:
    state = _legacy_state() if path == "legacy" else _kernel_state()
    secret = "super-secret-value-123"
    code = "import os; print(os.environ['API_KEY'])"
    reply = _dispatch(
        path,
        _admit_msg(
            path,
            "run",
            secret_names=["api_key"],
            inject_as={"api_key": "API_KEY"},
            command=[sys.executable, "-c", code],
        ),
        state,
    )
    assert reply["ok"] is True
    assert secret not in reply["scrubbed_stdout"]
    assert "***REDACTED(api_key)***" in reply["scrubbed_stdout"]
    assert secret not in str(reply)
