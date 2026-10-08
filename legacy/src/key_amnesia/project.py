"""Project vault discovery, per-env paths, and vault-context resolution.

Walks up from cwd looking for `.amnesia/`, stops at the home directory
boundary (never crosses into `~`), and resolves which vault file(s) a
command should use. Existing global `~/.key-amnesia/vault.bin` users see
zero-action compatibility: no project → same paths as before.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from key_amnesia.paths import (
    ENV_VAULT_PATH,
    guard_lock_path_for_vault,
    last_guard_state_path_for_vault,
    vault_path as global_vault_path,
)
from key_amnesia.vault import names_path_for_vault

AMNESIA_DIR = ".amnesia"
PROJECT_CONFIG_NAME = "config.json"
ENV_KA_ENV = "KA_ENV"


@dataclass
class VaultContext:
    """Resolved vault target for one CLI invocation."""

    vault_path: Path
    names_path: Path
    lock_path: Path
    last_guard_state_path: Path
    project_root: Path | None = None
    env_name: str | None = None
    merge_with_global: bool = False
    global_vault_path: Path | None = None
    use_global_config: bool = True
    force_global: bool = False
    vault_override: bool = False


def find_project_root(start: Path | None = None) -> Path | None:
    """Walk up from `start` (default cwd) for a directory containing `.amnesia/`.

    Stops at the user's home directory (checks home itself, never walks
    above it). When cwd is outside home, walks to the filesystem root.
    Returns the directory that *contains* `.amnesia/`, or None.
    """
    cur = (start or Path.cwd()).resolve()
    home = Path.home().resolve()
    while True:
        if (cur / AMNESIA_DIR).is_dir():
            return cur
        if cur == home or cur.parent == cur:
            return None
        cur = cur.parent


def amnesia_dir(project_root: Path) -> Path:
    return project_root / AMNESIA_DIR


def project_config_path(project_root: Path) -> Path:
    return amnesia_dir(project_root) / PROJECT_CONFIG_NAME


def load_project_config(project_root: Path) -> dict[str, Any]:
    p = project_config_path(project_root)
    if not p.exists():
        return {"use_global": True}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"use_global": True}
    if not isinstance(data, dict):
        return {"use_global": True}
    out = dict(data)
    if "use_global" not in out:
        out["use_global"] = True
    return out


def save_project_config(project_root: Path, cfg: dict[str, Any]) -> None:
    p = project_config_path(project_root)
    p.parent.mkdir(parents=True, exist_ok=True)
    body = dict(cfg)
    if "use_global" not in body:
        body["use_global"] = True
    p.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")


def project_vault_path(project_root: Path, env_name: str | None = None) -> Path:
    """`.amnesia/vault.bin` or `.amnesia/envs/<name>/vault.bin`."""
    base = amnesia_dir(project_root)
    if env_name:
        return base / "envs" / env_name / "vault.bin"
    return base / "vault.bin"


def ensure_amnesia_gitignore(project_root: Path) -> bool:
    """Ensure `.amnesia/` is listed in the project's `.gitignore`. No prompt.

    Returns True if a line was added, False if already covered or no write.
    """
    gi = project_root / ".gitignore"
    pattern = ".amnesia/"
    covering = (".amnesia/", ".amnesia", "**/.amnesia/", "**/.amnesia")
    if gi.exists():
        try:
            text = gi.read_text(encoding="utf-8")
        except OSError:
            return False
        lines = {ln.strip() for ln in text.splitlines()}
        if any(c in lines for c in covering):
            return False
        sep = "" if text.endswith("\n") or not text else "\n"
        gi.write_text(text + sep + pattern + "\n", encoding="utf-8")
        return True
    gi.write_text(pattern + "\n", encoding="utf-8")
    return True


def ensure_project_scaffold(
    project_root: Path,
    *,
    env_name: str | None = None,
    use_global: bool = True,
) -> Path:
    """Create `.amnesia/` (and optional env dir), write config.json, gitignore.

    Returns the vault path that should be initialized (does not create the vault).
    """
    root = project_root.resolve()
    amnesia = amnesia_dir(root)
    amnesia.mkdir(parents=True, exist_ok=True)
    if env_name:
        (amnesia / "envs" / env_name).mkdir(parents=True, exist_ok=True)
    cfg_path = project_config_path(root)
    if not cfg_path.exists():
        save_project_config(root, {"use_global": bool(use_global)})
    ensure_amnesia_gitignore(root)
    return project_vault_path(root, env_name)


def _resolve_env_name(
    project_root: Path | None,
    *,
    env_flag: str | None,
) -> str | None:
    if env_flag:
        return env_flag
    ka_env = os.environ.get(ENV_KA_ENV)
    if ka_env:
        return ka_env
    if project_root is not None:
        cfg = load_project_config(project_root)
        default_env = cfg.get("default_env")
        if isinstance(default_env, str) and default_env:
            return default_env
    return None


def _context_for_vault(
    vp: Path,
    *,
    project_root: Path | None = None,
    env_name: str | None = None,
    merge_with_global: bool = False,
    global_vp: Path | None = None,
    use_global_config: bool = True,
    force_global: bool = False,
    vault_override: bool = False,
) -> VaultContext:
    return VaultContext(
        vault_path=vp,
        names_path=names_path_for_vault(vp),
        lock_path=guard_lock_path_for_vault(vp),
        last_guard_state_path=last_guard_state_path_for_vault(vp),
        project_root=project_root,
        env_name=env_name,
        merge_with_global=merge_with_global,
        global_vault_path=global_vp,
        use_global_config=use_global_config,
        force_global=force_global,
        vault_override=vault_override,
    )


def resolve_vault_context(
    *,
    vault: str | Path | None = None,
    force_global: bool = False,
    no_global: bool = False,
    env: str | None = None,
    start: Path | None = None,
) -> VaultContext:
    """Resolve which vault a command should use.

    Precedence:
    1. Explicit `--vault PATH` (or KEY_AMNESIA_VAULT_PATH when set and no flags)
    2. `--global` → global vault only
    3. Project walk-up → project vault (+ optional global merge)
    4. Else global vault

    `--no-global` disables merge even when project config says use_global.
    `--env` / KA_ENV / project default_env select per-env vault files.
    """
    # Explicit CLI --vault always wins.
    if vault is not None:
        vp = Path(vault)
        return _context_for_vault(vp, vault_override=True)

    # KEY_AMNESIA_VAULT_PATH: bootstrap/test override — skip project discovery.
    env_override = os.environ.get(ENV_VAULT_PATH)
    if env_override:
        return _context_for_vault(Path(env_override), vault_override=True)

    gvp = global_vault_path()

    if force_global:
        if env:
            raise ValueError("--env requires a project vault (omit --global)")
        return _context_for_vault(gvp, force_global=True)

    project_root = find_project_root(start)
    if project_root is None:
        if env:
            raise ValueError(
                "--env requires a project (.amnesia/); run 'ka init --project' first"
            )
        return _context_for_vault(gvp)

    cfg = load_project_config(project_root)
    use_global = bool(cfg.get("use_global", True))
    if no_global:
        use_global = False

    env_name = _resolve_env_name(project_root, env_flag=env)
    pvp = project_vault_path(project_root, env_name)

    merge = False
    global_for_merge: Path | None = None
    if use_global and gvp.exists() and gvp.resolve() != pvp.resolve():
        merge = True
        global_for_merge = gvp

    return _context_for_vault(
        pvp,
        project_root=project_root,
        env_name=env_name,
        merge_with_global=merge,
        global_vp=global_for_merge,
        use_global_config=use_global,
    )


def merge_secret_maps(*maps: dict[str, str]) -> dict[str, str]:
    """Merge secret dicts left-to-right; later maps win on collision.

    Callers should pass global first, then project, so project wins.
    """
    out: dict[str, str] = {}
    for m in maps:
        out.update(m)
    return out


def merged_names_from_sidecars(ctx: VaultContext) -> list[str]:
    """Union of names sidecars for list-without-guard (project wins order N/A)."""
    from key_amnesia.vault import read_names

    names: set[str] = set()
    if ctx.merge_with_global and ctx.global_vault_path is not None:
        names.update(read_names(names_path_for_vault(ctx.global_vault_path)))
    names.update(read_names(ctx.names_path))
    return sorted(names)
