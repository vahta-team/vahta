"""Configuration load/save for key-amnesia."""

from __future__ import annotations

import json
import shlex
import shutil
from pathlib import Path
from typing import Any

from key_amnesia.paths import config_path

DEFAULTS: dict[str, Any] = {
    "session-mode": "per-call",
    "session-timeout-minutes": 30,
    "prompt-timeout-seconds": 90,
    # Default window for `ka unlock --pre-admit` (no `--pre-admit-seconds`
    # flag exists; this is the only knob) — see guard.run_foreground_guard.
    "pre-admit-seconds": 900,
    # Which terminal opens the isolated console for a password prompt, as a
    # command prefix the helper argv is appended to ("ghostty -e", "kitty").
    # Empty means detect one — see platform._preferred_terminal_command.
    # Linux only; Windows has CREATE_NEW_CONSOLE and macOS has Terminal.app.
    "terminal": "",
}

VALID_SESSION_MODES = frozenset({"per-call", "cached"})

# `config set` normally proves the master password first. `terminal` cannot:
# it is the setting that decides *where* a password can be typed at all, so
# requiring the vault to change it would mean a user whose terminal is wrong
# has to satisfy the very prompt they cannot see. It guards nothing — anyone
# who can write this file can already replace `ka` on PATH — and the agent
# deny for `config set` lives in ka_policy, not in the password check.
AUTH_EXEMPT_KEYS = frozenset({"terminal"})

# Accepted as "go back to detecting one".
_TERMINAL_AUTO = frozenset({"", "auto", "detect", "default", "none"})


class ConfigError(Exception):
    """Invalid configuration value."""


def load_config(path: Path | None = None) -> dict[str, Any]:
    p = path or config_path()
    if not p.exists():
        return dict(DEFAULTS)
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)
    merged = dict(DEFAULTS)
    if isinstance(data, dict):
        merged.update(data)
    return merged


def save_config(cfg: dict[str, Any], path: Path | None = None) -> None:
    p = path or config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, sort_keys=True)
        f.write("\n")


def set_config_value(key: str, value: str, path: Path | None = None) -> dict[str, Any]:
    cfg = load_config(path)
    if key == "session-mode":
        if value not in VALID_SESSION_MODES:
            raise ConfigError(
                f"Invalid session-mode {value!r}; expected one of {sorted(VALID_SESSION_MODES)}"
            )
        cfg[key] = value
    elif key == "session-timeout-minutes":
        try:
            minutes = int(value)
        except ValueError as e:
            raise ConfigError("session-timeout-minutes must be an integer") from e
        if minutes < 1:
            raise ConfigError("session-timeout-minutes must be >= 1")
        cfg[key] = minutes
    elif key == "prompt-timeout-seconds":
        try:
            seconds = int(value)
        except ValueError as e:
            raise ConfigError("prompt-timeout-seconds must be an integer") from e
        if seconds < 1:
            raise ConfigError("prompt-timeout-seconds must be >= 1")
        cfg[key] = seconds
    elif key == "pre-admit-seconds":
        try:
            seconds = int(value)
        except ValueError as e:
            raise ConfigError("pre-admit-seconds must be an integer") from e
        if seconds < 1:
            raise ConfigError("pre-admit-seconds must be >= 1")
        cfg[key] = seconds
    elif key == "terminal":
        cfg[key] = normalize_terminal(value)
    else:
        raise ConfigError(
            f"Unknown config key {key!r}; "
            "supported: session-mode, session-timeout-minutes, "
            "prompt-timeout-seconds, pre-admit-seconds, terminal"
        )
    save_config(cfg, path)
    return cfg


def normalize_terminal(value: str) -> str:
    """Validate a terminal command prefix and return it in canonical form.

    The value is a command, not a binary name, so it carries whatever flag
    that terminal needs to run something: "ghostty -e", "wezterm start --",
    "kitty". That is what lets a terminal nobody has heard of work without a
    code change. The empty string, and a few words meaning the same thing,
    clear the setting and put detection back in charge.
    """
    text = (value or "").strip()
    if text.lower() in _TERMINAL_AUTO:
        return ""
    try:
        parts = shlex.split(text)
    except ValueError as e:
        raise ConfigError(f"terminal is not a valid command line: {e}") from e
    if not parts:
        return ""
    if not shutil.which(parts[0]):
        raise ConfigError(
            f"terminal {parts[0]!r} is not on PATH. Give a command that is, "
            'including the flag it needs to run something (e.g. "ghostty -e"), '
            'or "auto" to detect one.'
        )
    return shlex.join(parts)
