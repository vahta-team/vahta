#!/usr/bin/env python3
"""PreToolUse / preToolUse secret guard: blocking hook for Claude Code, Cursor, Codex.

Inspects a pending tool call (Bash/Shell command, Write/Edit file content, or
Codex ``apply_patch``) and **denies** it when:

- the Bash/Shell command is a forbidden ``ka`` verb (``set``, ``reveal``,
  ``scan --yes``, nested ``ka run -- ka set``, …), or
- the text contains an inline credential-shaped token.

Allowed agent path is ``ka run`` / ``ka list`` / ``ka status``. Forbidden
verbs must be run in the user's own terminal. Write/Edit contents that
*mention* ``ka set`` are not verb-denied (docs); secret scanning still runs.

Host contracts from the same detection logic:

- Claude Code / Codex ``PreToolUse``: stdin JSON with ``tool_name`` /
  ``tool_input``; deny reply uses ``hookSpecificOutput.permissionDecision``.
  Codex shares Claude's deny shape (no separate contract).
- Cursor ``preToolUse``: stdin JSON with ``tool_name`` / ``tool_input`` (plus
  Cursor-only fields like ``cursor_version`` / ``conversation_id``); deny
  reply uses the flatter ``{"permission": "deny", ...}`` shape.
- OpenCode has no stdin-JSON hook protocol. ``ka setup`` installs a JS
  plugin that feeds this module the Claude-shaped payload and throws on a
  deny reply. There is no ``opencode`` host branch; the Claude deny shape
  is consumed as-is.

Fails **open** on JSON/IO errors or unexpected shapes — a broken hook must
never brick the agent. Set ``KEY_AMNESIA_HOOK_DISABLE=1`` to skip all checks
(e.g. temporarily, or in environments that manage secrets a different way).
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any

from key_amnesia.detect import collect_strings, find_secret_kind
from key_amnesia.ka_policy import (
    deny_message,
    iter_non_ka_chain_texts,
    ka_run_trailing_texts,
    ka_verb_deny_reason,
)

DISABLE_ENV = "KEY_AMNESIA_HOOK_DISABLE"

# Already routing secrets through key-amnesia — do not nag.
_KA_SAFE = re.compile(
    r"\b(?:ka|key-amnesia)\s+(?:run|set|reveal|copy|remove)\b",
    re.IGNORECASE,
)

_SUGGESTION = (
    "Inline credential-shaped token detected ({kind}). "
    "Do not paste secrets into commands or files. Store with `ka set NAME`, "
    "then run with `ka run --secret NAME --as NAME=ENVVAR -- <command>` so "
    "the value never appears on argv, in files, or in chat. "
    "(Set KEY_AMNESIA_HOOK_DISABLE=1 to bypass this hook.)"
)


def _command_text(tool_input: Any) -> str:
    """Extract the text to scan from Bash/Shell `command` or Write/Edit content."""
    if isinstance(tool_input, dict):
        for key in (
            "command",
            "cmd",
            "script",
            "code",
            "contents",
            "new_string",
            "content",
        ):
            val = tool_input.get(key)
            if isinstance(val, str) and val.strip():
                return val
        return "\n".join(collect_strings(tool_input))
    if isinstance(tool_input, str):
        return tool_input
    return ""


def find_finding(text: str, *, ignore_ka_safe: bool = False) -> str | None:
    """Return a short human-readable finding kind, or None if text looks clean.

    ``ignore_ka_safe`` is for the argv after ``ka run --``: the outer command
    matches ``_KA_SAFE`` but a hardcoded key on the trailing command must still
    deny.
    """
    if not text:
        return None
    if not ignore_ka_safe and _KA_SAFE.search(text):
        return None

    return find_secret_kind(text)


def detect_host(payload: dict[str, Any]) -> str:
    """Distinguish Cursor's flatter preToolUse payload from Claude/Codex PreToolUse.

    Codex uses the Claude-shaped deny contract; without Cursor-only markers we
    return ``claude`` (covers Claude Code and Codex).
    """
    if "cursor_version" in payload or "conversation_id" in payload:
        return "cursor"
    event = str(payload.get("hook_event_name") or "")
    if event == "preToolUse":
        return "cursor"
    return "claude"


def deny_claude(kind: str, *, reason: str | None = None) -> dict[str, Any]:
    reason = reason or _SUGGESTION.format(kind=kind)
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
        "systemMessage": reason,
    }


def deny_cursor(kind: str, *, reason: str | None = None) -> dict[str, Any]:
    reason = reason or _SUGGESTION.format(kind=kind)
    return {
        "permission": "deny",
        "agent_message": reason,
        "user_message": (
            f"key-amnesia hook blocked a possible secret ({kind}). "
            "Use `ka set` / `ka run --secret ... --as NAME=ENVVAR -- ...` instead."
        ),
    }


_SHELL_TOOL_NAMES = {"bash", "shell", "powershell"}


def _emit_deny(host: str, kind: str, *, reason: str | None = None) -> dict[str, Any]:
    if host == "cursor":
        reply = deny_cursor(kind, reason=reason)
        if reason is not None:
            reply["user_message"] = reason
        return reply
    return deny_claude(kind, reason=reason)


_ALLOWED_TOOL_NAMES = {"bash", "shell", "powershell", "write", "edit", "multiedit", "apply_patch"}


def main() -> int:
    if os.environ.get(DISABLE_ENV):
        return 0

    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return 0
        payload = json.loads(raw)
    except Exception:
        # Fail open: never brick the agent on parse/IO errors.
        return 0

    try:
        if not isinstance(payload, dict):
            return 0

        tool_name = str(payload.get("tool_name") or "")
        tool_l = tool_name.lower()
        if tool_name and tool_l not in _ALLOWED_TOOL_NAMES:
            return 0

        text = _command_text(payload.get("tool_input"))
        host = detect_host(payload)
        is_shell = tool_l in _SHELL_TOOL_NAMES

        # Verb deny before find_finding / _KA_SAFE (Bash/Shell only).
        if is_shell:
            kind = ka_verb_deny_reason(text)
            if kind:
                reply = _emit_deny(host, kind, reason=deny_message(kind))
                json.dump(reply, sys.stdout)
                sys.stdout.write("\n")
                return 0

        finding: str | None = None
        if is_shell:
            scan_texts = list(ka_run_trailing_texts(text))
            scan_texts.extend(iter_non_ka_chain_texts(text))
            if scan_texts:
                for piece in scan_texts:
                    finding = find_finding(piece, ignore_ka_safe=True)
                    if finding:
                        break
            else:
                finding = find_finding(text)
        else:
            finding = find_finding(text)

        if finding:
            reply = _emit_deny(host, finding)
            json.dump(reply, sys.stdout)
            sys.stdout.write("\n")
            return 0
    except Exception:
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
