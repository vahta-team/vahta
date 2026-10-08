"""Guard reload-on-change (PR0) — fixes the stale in-memory secrets snapshot.

A live `ka unlock` guard used to decrypt once at startup and never look
again: a `ka set`/`ka remove` from another terminal updated the vault file
correctly, but the guard kept serving its old in-memory copy for the rest of
its session (README security limit 11 / DESIGN.md "Known limitation"). These
tests exercise the fix directly against `guard_handle_message` / `GuardState`
— no live guard process, no IPC listener needed — using the retained
SecretBox key + content-fingerprint path (`_maybe_reload_secrets`).

Always a throwaway `KEY_AMNESIA_HOME` (see `ka_home` fixture) — vault-layout
and format work must never touch the maintainer's real vault.

No new IPC verb: every request here uses `run`/`list`/`status`, the exact
same five-verb set as before (see `test_guard_verbs_regression.py`, which
this file must never need to modify).
"""

from __future__ import annotations

import sys
import time

from key_amnesia import vault as vault_mod
from key_amnesia.guard import AdmittedSession, GuardState, guard_handle_message
from key_amnesia.peer_identity import PeerIdentity

PEER = PeerIdentity(pid=4242, start_time=1000)


def _admitted_state(vault_path, key, secrets) -> GuardState:
    """A GuardState wired to a real (throwaway) vault file, pre-admitted so
    tests exercise reload behavior rather than the (separately tested)
    admission-consent prompt.

    `vault_content_fingerprint` is seeded to the vault's current fingerprint,
    matching what `run_foreground_guard` does at startup — the first
    dispatch after construction should *not* itself trigger a reload unless
    the file actually changed since.
    """
    state = GuardState(
        secrets=dict(secrets),
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"r" * 32,
        vault_path=vault_path,
        vault_key=key,
        vault_content_fingerprint=vault_mod.vault_fingerprint(vault_path),
    )
    state.admitted = AdmittedSession(
        identities=[PEER],
        first_seen="2026-01-01T00:00:00+00:00",
        unscoped=True,
        granted_until=state.expires_at,
    )
    return state


def _msg(verb: str, **extra) -> dict:
    return {"verb": verb, **extra}


def test_set_while_unlocked_is_seen_by_list(ka_home, seeded_vault, password) -> None:
    payload, key = vault_mod.load_vault_with_key(seeded_vault, password)
    state = _admitted_state(seeded_vault, key, payload["secrets"])

    reply = guard_handle_message(_msg("list"), state, peer=PEER)
    assert reply["ok"] is True
    assert "new_secret" not in reply["names"]

    # Simulate `ka set NEW_SECRET ...` from another terminal while this
    # guard is already live.
    mutated = dict(payload)
    mutated["secrets"] = dict(payload["secrets"], new_secret="brand-new-value")
    vault_mod.save_vault(seeded_vault, password, mutated)

    reply = guard_handle_message(_msg("list"), state, peer=PEER)
    assert reply["ok"] is True
    assert "new_secret" in reply["names"]


def test_set_while_unlocked_is_seen_by_run(ka_home, seeded_vault, password) -> None:
    payload, key = vault_mod.load_vault_with_key(seeded_vault, password)
    state = _admitted_state(seeded_vault, key, payload["secrets"])

    mutated = dict(payload)
    mutated["secrets"] = dict(payload["secrets"], new_secret="brand-new-value")
    vault_mod.save_vault(seeded_vault, password, mutated)

    code = "import os; print(os.environ['NEW_SECRET'])"
    reply = guard_handle_message(
        _msg(
            "run",
            secret_names=["new_secret"],
            inject_as={"new_secret": "NEW_SECRET"},
            command=[sys.executable, "-c", code],
        ),
        state,
        peer=PEER,
    )
    assert reply["ok"] is True
    assert "brand-new-value" not in reply["scrubbed_stdout"]
    assert "***REDACTED(new_secret)***" in reply["scrubbed_stdout"]


def test_remove_while_unlocked_makes_secret_disappear(ka_home, seeded_vault, password) -> None:
    payload, key = vault_mod.load_vault_with_key(seeded_vault, password)
    state = _admitted_state(seeded_vault, key, payload["secrets"])

    reply = guard_handle_message(_msg("list"), state, peer=PEER)
    assert "api_key" in reply["names"]

    mutated = dict(payload)
    mutated["secrets"] = {
        k: v for k, v in payload["secrets"].items() if k != "api_key"
    }
    vault_mod.save_vault(seeded_vault, password, mutated)

    reply = guard_handle_message(_msg("list"), state, peer=PEER)
    assert reply["ok"] is True
    assert "api_key" not in reply["names"]

    # A `run` asking for the now-removed secret must be denied as unknown,
    # not silently served from the stale snapshot.
    reply = guard_handle_message(
        _msg(
            "run",
            secret_names=["api_key"],
            inject_as={"api_key": "API_KEY"},
            command=[sys.executable, "-c", "print('unused')"],
        ),
        state,
        peer=PEER,
    )
    assert reply["ok"] is False
    assert "unknown secrets" in reply["reason"]


def test_reload_driven_by_fingerprint_not_unconditional(
    ka_home, seeded_vault, password, monkeypatch
) -> None:
    """Reload must only re-open the vault when its content fingerprint
    actually changed — not on every single request."""
    payload, key = vault_mod.load_vault_with_key(seeded_vault, password)
    state = _admitted_state(seeded_vault, key, payload["secrets"])

    calls: list[int] = []
    real_reload = vault_mod.load_vault_with_retained_key

    def counting_reload(path, k):
        calls.append(1)
        return real_reload(path, k)

    monkeypatch.setattr(vault_mod, "load_vault_with_retained_key", counting_reload)

    # Unchanged vault: repeated status/list calls must not re-decrypt.
    for _ in range(3):
        reply = guard_handle_message(_msg("status"), state, peer=PEER)
        assert reply["ok"] is True
    assert calls == []

    # One real change -> exactly one reload, even across several requests
    # before the next actual change.
    mutated = dict(payload)
    mutated["secrets"] = dict(payload["secrets"], rotated="v2")
    vault_mod.save_vault(seeded_vault, password, mutated)

    for _ in range(3):
        reply = guard_handle_message(_msg("list"), state, peer=PEER)
        assert reply["ok"] is True
    assert calls == [1]


def test_reload_survives_transient_read_error(
    ka_home, seeded_vault, password, monkeypatch
) -> None:
    """A torn read / transient decrypt failure must not wipe the guard's
    last-known-good secrets — it should keep serving them and try again
    next time."""
    payload, key = vault_mod.load_vault_with_key(seeded_vault, password)
    state = _admitted_state(seeded_vault, key, payload["secrets"])

    mutated = dict(payload)
    mutated["secrets"] = dict(payload["secrets"], will_not_appear_yet="v2")
    vault_mod.save_vault(seeded_vault, password, mutated)

    def boom(path, k):
        raise vault_mod.VaultError("simulated torn read")

    monkeypatch.setattr(vault_mod, "load_vault_with_retained_key", boom)

    reply = guard_handle_message(_msg("list"), state, peer=PEER)
    assert reply["ok"] is True
    # Reload failed silently; last-known-good (pre-mutation) names remain.
    assert "will_not_appear_yet" not in reply["names"]
    assert "api_key" in reply["names"]

    monkeypatch.undo()
    reply = guard_handle_message(_msg("list"), state, peer=PEER)
    assert "will_not_appear_yet" in reply["names"]


def test_guard_state_without_vault_path_skips_reload(ka_home) -> None:
    """Backward compatibility: a GuardState built without vault_path/vault_key
    (every pre-existing guard-dispatch test) must behave exactly as before —
    no reload attempt, no crash."""
    state = GuardState(
        secrets={"api_key": "unchanged"},
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"s" * 32,
    )
    state.admitted = AdmittedSession(
        identities=[PEER],
        first_seen="2026-01-01T00:00:00+00:00",
        unscoped=True,
        granted_until=state.expires_at,
    )
    for verb in ("list", "status"):
        reply = guard_handle_message(_msg(verb), state, peer=PEER)
        assert reply["ok"] is True
    assert state.secrets == {"api_key": "unchanged"}


def test_reload_never_returns_raw_secret_value(ka_home, seeded_vault, password) -> None:
    payload, key = vault_mod.load_vault_with_key(seeded_vault, password)
    state = _admitted_state(seeded_vault, key, payload["secrets"])

    mutated = dict(payload)
    mutated["secrets"] = dict(payload["secrets"], rotated_secret="freshly-rotated-value")
    vault_mod.save_vault(seeded_vault, password, mutated)

    for verb, extra in (
        ("list", {}),
        ("status", {}),
    ):
        reply = guard_handle_message(_msg(verb, **extra), state, peer=PEER)
        assert "freshly-rotated-value" not in str(reply)
        assert "password" not in reply
        assert "secrets" not in reply

    code = "import os; print(os.environ['ROTATED'])"
    reply = guard_handle_message(
        _msg(
            "run",
            secret_names=["rotated_secret"],
            inject_as={"rotated_secret": "ROTATED"},
            command=[sys.executable, "-c", code],
        ),
        state,
        peer=PEER,
    )
    assert reply["ok"] is True
    assert "freshly-rotated-value" not in str(reply)
    assert "***REDACTED(rotated_secret)***" in reply["scrubbed_stdout"]


def test_vault_fingerprint_reflects_content_not_just_mtime(ka_home, seeded_vault) -> None:
    """Fingerprint must change when bytes change (the guard reload path
    relies on this, not on mtime resolution alone)."""
    fp1 = vault_mod.vault_fingerprint(seeded_vault)
    assert fp1 is not None
    data = seeded_vault.read_bytes()
    seeded_vault.write_bytes(data + b"\x00")
    fp2 = vault_mod.vault_fingerprint(seeded_vault)
    assert fp2 is not None
    assert fp1 != fp2


def test_vault_fingerprint_missing_file_returns_none(ka_home, tmp_path) -> None:
    assert vault_mod.vault_fingerprint(tmp_path / "does-not-exist.bin") is None
