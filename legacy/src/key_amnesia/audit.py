"""JSONL audit log — never records secret values."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from key_amnesia.paths import audit_log_path

VALID_ROUTES = frozenset({"inline", "spawned-console", "guard-session"})
# "warn" (0.3.8): a detection-only event that isn't itself an allow/deny
# outcome — e.g. an unrecognized peer showing up at the guard, or a
# pre-admit window being armed. Written unconditionally, independent of
# whatever the admission prompt is eventually answered.
VALID_RESULTS = frozenset({"allowed", "denied", "timeout", "warn"})


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def audit_event(
    action: str,
    *,
    secret_names: Iterable[str] | None = None,
    command: list[str] | str | None = None,
    route: str,
    result: str,
    reason: str = "",
    path: Path | None = None,
) -> dict[str, Any]:
    """Append one audit record. Never includes secret values or passwords."""
    if route not in VALID_ROUTES:
        raise ValueError(f"Invalid audit route: {route}")
    if result not in VALID_RESULTS:
        raise ValueError(f"Invalid audit result: {result}")

    if isinstance(command, list):
        cmd_field: str | list[str] | None = list(command)
    else:
        cmd_field = command

    record: dict[str, Any] = {
        "timestamp": _utc_now_iso(),
        "action": action,
        "secret_names": list(secret_names or []),
        "command": cmd_field,
        "route": route,
        "result": result,
        "reason": reason,
    }

    p = path or audit_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")
    return record
