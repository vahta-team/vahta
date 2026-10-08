"""Regression: `ka set NAME VALUE` must never echo the secret to the
*caller's own terminal* — but the isolated spawned-console approval window
(agent-triggered, non-interactive path) is SUPPOSED to preview it, per
README.md: "the approval window shows you the incoming value before asking
for your password — so you can still deny it."

Found while investigating an unrelated UX complaint about the auth-prompt
output. `PromptRequest.detail` was doing double duty: it was both the
human-facing text printed at the auth prompt AND the machine payload a
spawned helper used to apply set/config mutations non-interactively. For
`ka set`, that payload embedded the raw secret value — and
`_prompt_password_inline` printed `detail` unconditionally to stderr
*before even asking for the master password*. So an interactive
`ka set NAME VALUE`, typed by a human in their own terminal (who already
knows the value — they just typed it), ALSO echoed it back to that same
screen for no reason, into scrollback / any terminal session logging.

Fixed by splitting the field: `PromptRequest.detail` stays human-facing and
secret-free, printed in the caller's own terminal. A new
`PromptRequest.mutation` field carries the payload; it's never printed by
`_prompt_password_inline`, but `run_prompt_helper` (the isolated,
agent-unreadable spawned console) *does* preview it — restoring the
documented approve-before-you-see-what-you're-approving feature without
re-exposing the value in the caller's own scrollback.
"""

from __future__ import annotations

import getpass
import json
import os
import threading
from dataclasses import asdict
from pathlib import Path

from key_amnesia.cli import main
from key_amnesia.prompt_route import (
    ENV_ADDRESS,
    ENV_AUTHKEY,
    ENV_PARENT_PID,
    ENV_REQUEST,
    ENV_TIMEOUT,
    PromptRequest,
    run_prompt_helper,
)
from key_amnesia.vault import load_vault

SECRET = "sh-VERY-secret-9f8e7d-do-not-print"


def test_set_interactive_inline_never_prints_value(
    seeded_vault: Path, password: str, monkeypatch, capsys
) -> None:
    """The caller's own terminal (they typed the value themselves) must
    never see it echoed back."""
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)

    rc = main(["set", "new_key", SECRET])

    captured = capsys.readouterr()
    assert SECRET not in captured.out
    assert SECRET not in captured.err
    assert rc == 0

    payload = load_vault(seeded_vault, password)
    assert payload["secrets"]["new_key"] == SECRET


def test_set_request_puts_value_in_mutation_not_detail(
    seeded_vault: Path, password: str, monkeypatch
) -> None:
    """Direct check on the request cmd_set builds, independent of capsys
    timing — the value must be reachable only via `mutation`."""
    captured_requests: list[PromptRequest] = []
    from key_amnesia import cli as cli_mod

    real_auth = cli_mod.require_human_auth

    def spy(request, *a, **k):
        captured_requests.append(request)
        return real_auth(request, *a, **k, isatty_fn=lambda: True, password_provider=lambda: password)

    monkeypatch.setattr(cli_mod, "require_human_auth", spy)

    rc = main(["set", "new_key", SECRET])
    assert rc == 0
    assert len(captured_requests) == 1
    req = captured_requests[0]
    assert SECRET not in req.detail
    assert SECRET in req.mutation


def test_spawned_helper_previews_value_in_isolated_console_only(
    ka_home, seeded_vault: Path, password: str, monkeypatch, capsys
) -> None:
    """The non-interactive (spawned-console) path SHOULD preview the value
    it's about to write — this is the isolated, agent-unreadable window the
    README promises — and must still apply the mutation correctly."""
    from key_amnesia import ipc

    request = PromptRequest(
        action="set",
        secret_names=["new_key"],
        mutation=json.dumps({"name": "new_key", "value": SECRET}),
        vault_path=str(seeded_vault),
    )
    listener, address, authkey = ipc.start_listener()
    monkeypatch.setenv(ENV_REQUEST, json.dumps(asdict(request)))
    monkeypatch.setenv(ENV_AUTHKEY, ipc.authkey_to_hex(authkey))
    monkeypatch.setenv(ENV_ADDRESS, address)
    monkeypatch.setenv(ENV_PARENT_PID, str(os.getpid()))
    monkeypatch.setenv(ENV_TIMEOUT, "5")
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)

    replies: list[dict] = []

    def collect() -> None:
        conn = listener.accept()
        try:
            replies.append(ipc.recv_msg(conn, timeout=5))
        finally:
            conn.close()

    t = threading.Thread(target=collect, daemon=True)
    t.start()

    rc = run_prompt_helper()
    t.join(timeout=5)
    listener.close()

    captured = capsys.readouterr()
    assert SECRET in captured.out  # previewed here, by design — this console is isolated
    assert rc == 0
    assert len(replies) == 1
    assert replies[0]["ok"] is True
    assert replies[0]["status_only"] == {"action": "set", "name": "new_key"}

    payload = load_vault(seeded_vault, password)
    assert payload["secrets"]["new_key"] == SECRET
