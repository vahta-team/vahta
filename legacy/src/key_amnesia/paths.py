"""Path helpers for key-amnesia data directory and files."""

from __future__ import annotations

import os
import stat
from pathlib import Path


ENV_HOME = "KEY_AMNESIA_HOME"
ENV_VAULT_PATH = "KEY_AMNESIA_VAULT_PATH"


def data_dir() -> Path:
    """Return the key-amnesia data directory, creating it with restrictive perms."""
    override = os.environ.get(ENV_HOME)
    if override:
        root = Path(override)
    else:
        root = Path.home() / ".key-amnesia"
    root.mkdir(parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        # Windows may not honor POSIX mode bits; user-profile ACL is the default.
        pass
    return root


def vault_path() -> Path:
    override = os.environ.get(ENV_VAULT_PATH)
    if override:
        return Path(override)
    return data_dir() / "vault.bin"


def names_path() -> Path:
    """Names sidecar lives next to the vault file."""
    vp = vault_path()
    return vp.with_name(vp.stem + ".names.json")


def config_path() -> Path:
    return data_dir() / "config.json"


def guard_lock_path() -> Path:
    return data_dir() / "guard.lock"


def last_guard_state_path() -> Path:
    """Honest-death-reporting record written by the guard on every teardown."""
    return data_dir() / "last_guard_state.json"


def guard_lock_path_for_vault(vault: Path | str) -> Path:
    """`guard.lock` beside the vault file (project or global)."""
    return Path(vault).resolve().parent / "guard.lock"


def last_guard_state_path_for_vault(vault: Path | str) -> Path:
    """`last_guard_state.json` beside the vault file."""
    return Path(vault).resolve().parent / "last_guard_state.json"


def guards_registry_dir() -> Path:
    """Discovery-only registry of live guards (`~/.key-amnesia/guards/`).

    Entries never carry authkeys — those stay only in the vault-adjacent lock.
    Does not create the directory (callers that write should mkdir).
    """
    return data_dir() / "guards"


def audit_log_path() -> Path:
    return data_dir() / "audit.log"


def permissions_manifest_path() -> Path:
    """Record of allow/deny strings last written by ``ka setup``."""
    return data_dir() / "permissions-manifest.json"
