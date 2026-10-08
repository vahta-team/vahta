"""Pre-0.3.8 opaque-token admission path (`_check_admission_legacy`).

Kept alive via `guard_handle_message_legacy` (aliased below so call sites
stay unchanged). `guard_serve` — the only production dispatch path — always
supplies a real `peer`, so this legacy path never runs against a live guard,
and there is no on-disk token file involved anywhere in 0.3.8 (see
`guard_request`, which no longer attaches or persists anything
admission-related).
"""

from __future__ import annotations

import time

from key_amnesia.guard import (
    AdmittedSession,
    GuardState,
)
from key_amnesia.guard import guard_handle_message_legacy as guard_handle_message


def _state(**overrides) -> GuardState:
    kwargs = dict(
        secrets={"api_key": "super-secret-value-123"},
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"m" * 32,
    )
    kwargs.update(overrides)
    return GuardState(**kwargs)


def test_unknown_token_prompts_and_approves(ka_home) -> None:
    state = _state()
    calls: list[tuple[int, str]] = []

    def approve(claimed_pid_unverified: int, summary: str) -> bool:
        calls.append((claimed_pid_unverified, summary))
        return True

    reply = guard_handle_message(
        {"verb": "list", "claimed_pid_unverified": 4242},
        state,
        admit_prompt=approve,
    )
    assert reply["ok"] is True
    assert reply["names"] == ["api_key"]
    assert "admission_token" in reply  # freshly minted, in-memory only
    assert calls == [(4242, "list secret names")]
    assert state.admitted is not None
    assert state.admitted.token == reply["admission_token"]
    assert state.admitted.request_count == 1


def test_unknown_token_denies_on_no(ka_home) -> None:
    state = _state()
    reply = guard_handle_message(
        {"verb": "list", "claimed_pid_unverified": 1},
        state,
        admit_prompt=lambda pid, summary: False,
    )
    assert reply["ok"] is False
    assert reply["reason"] == "admission denied"
    assert "admission_token" not in reply
    assert state.admitted is None


def test_admitted_token_skips_prompt_no_reprompt(ka_home) -> None:
    state = _state()
    state.admitted = AdmittedSession(token="tok-123", first_seen="2026-01-01T00:00:00+00:00")

    def fail_if_called(*_a, **_k):
        raise AssertionError("admit_prompt must not be called for a known token")

    reply = guard_handle_message(
        {"verb": "list", "admission_token": "tok-123"},
        state,
        admit_prompt=fail_if_called,
    )
    assert reply["ok"] is True
    # Known-token replies never re-mint a token.
    assert "admission_token" not in reply
    assert state.admitted.request_count == 1


def test_stale_token_after_new_guard_reprompts(ka_home) -> None:
    """A token minted by a previous guard run is unknown to a fresh GuardState."""
    state = _state()
    calls = {"n": 0}

    def approve(*_a, **_k):
        calls["n"] += 1
        return True

    reply = guard_handle_message(
        {"verb": "status", "admission_token": "stale-token-from-old-guard"},
        state,
        admit_prompt=approve,
    )
    assert reply["ok"] is True
    assert calls["n"] == 1  # prompted despite a (wrong) token being present


def test_status_reports_admission_state(ka_home) -> None:
    state = _state()
    state.admitted = AdmittedSession(
        token="tok", first_seen="2026-01-01T00:00:00+00:00", request_count=3
    )
    reply = guard_handle_message({"verb": "status", "admission_token": "tok"}, state)
    assert reply["ok"] is True
    assert reply["admitted"] is True
    assert reply["admitted_since"] == "2026-01-01T00:00:00+00:00"
    assert reply["request_count"] == 4  # incremented by this very request
