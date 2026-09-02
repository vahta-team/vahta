"""`ka setup`: skills, secret-guard hook, and best-effort harness allow lists.

Copies the three bundled agent skills to the Claude Code / Cursor / Codex
skills directories and merges a `PreToolUse` (Claude, Codex) / `preToolUse`
(Cursor) hook entry into each host's own config file. Optionally merges
harness *allow* rules so unattended ``ka run`` / ``ka list`` can proceed;
the hook is the load-bearing *deny* for forbidden verbs. Safe to re-run
(idempotent upsert); never drops unrelated keys or other hooks/matchers
already present.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import sys
from importlib import resources
from pathlib import Path

from key_amnesia import theme

SKILL_NAMES = ["key-amnesia-usage", "key-amnesia-hygiene", "key-amnesia-migrate"]

CLAUDE_MATCHER = "Bash|Write|Edit"
CURSOR_MATCHER = "Shell|Write"
# Codex: Bash + apply_patch aliases (Write/Edit also match apply_patch edits).
CODEX_MATCHER = "Bash|Write|Edit|apply_patch"
HOOK_COMMAND = "key-amnesia-hook"
_HOOK_MODULE = "key_amnesia.hooks.secret_guard"
_WIN_NEEDS_QUOTE = frozenset(' \t"&|<>^()%,;=')


def _skills_root():
    return resources.files("key_amnesia") / "skills"


def _codex_home(home: Path | None = None) -> Path:
    """Resolve Codex home: ``$CODEX_HOME`` if set, else ``~/.codex``."""
    home = home or Path.home()
    env = os.environ.get("CODEX_HOME")
    if env:
        return Path(env)
    return home / ".codex"


def _copy_skills(dest_roots: list[Path]) -> list[str]:
    lines: list[str] = []
    root = _skills_root()
    for name in SKILL_NAMES:
        src = root / name / "SKILL.md"
        content = src.read_text(encoding="utf-8")
        for dest_root in dest_roots:
            dest_dir = dest_root / name
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_file = dest_dir / "SKILL.md"
            dest_file.write_text(content, encoding="utf-8")
            lines.append(f"skill updated: {name} -> {dest_file}")
    return lines


def _load_json_object(path: Path) -> dict:
    """Read existing JSON as a dict; recover to `{}` on missing/malformed input."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _quote_hook_path(path: str) -> str:
    """Quote a filesystem path for a PreToolUse hook command line."""
    if sys.platform == "win32":
        if any(c in _WIN_NEEDS_QUOTE for c in path):
            return '"' + path.replace('"', '\\"') + '"'
        return path
    return shlex.quote(path)


def _sibling_hook_script() -> Path | None:
    """Console script next to this interpreter (venv ``bin/`` / ``Scripts/``)."""
    parent = Path(os.path.abspath(sys.executable)).parent
    if sys.platform == "win32":
        names = (f"{HOOK_COMMAND}.exe", HOOK_COMMAND)
        candidates = [parent / n for n in names]
        # ``python.exe`` sometimes lives in the venv root, not ``Scripts/``.
        if parent.name.lower() != "scripts":
            candidates.extend(parent / "Scripts" / n for n in names)
    else:
        candidates = [parent / HOOK_COMMAND]
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def _hook_command() -> str:
    """Resolved hook argv computed at call time (tests monkeypatch ``sys.executable``)."""
    sibling = _sibling_hook_script()
    if sibling is not None:
        return _quote_hook_path(os.path.abspath(str(sibling)))
    found = shutil.which(HOOK_COMMAND)
    if found:
        return _quote_hook_path(os.path.abspath(found))
    return f"{_quote_hook_path(sys.executable)} -m {_HOOK_MODULE}"


def _is_our_hook_command(command: str) -> bool:
    return "key-amnesia-hook" in command or "key_amnesia.hooks.secret_guard" in command


def _merge_pretooluse_hooks(path: Path, matcher: str) -> None:
    """Idempotently upsert our PreToolUse entry (Claude / Codex shape)."""
    settings = _load_json_object(path)
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
    settings["hooks"] = hooks

    pretooluse = hooks.get("PreToolUse")
    if not isinstance(pretooluse, list):
        pretooluse = []

    def _is_ours(entry: object) -> bool:
        if not isinstance(entry, dict):
            return False
        for hook in entry.get("hooks", []) or []:
            if isinstance(hook, dict) and _is_our_hook_command(str(hook.get("command") or "")):
                return True
        return False

    kept = [e for e in pretooluse if not _is_ours(e)]
    kept.append(
        {
            "matcher": matcher,
            "hooks": [{"type": "command", "command": _hook_command()}],
        }
    )
    hooks["PreToolUse"] = kept
    _write_json(path, settings)


def _merge_claude_settings(path: Path) -> None:
    _merge_pretooluse_hooks(path, CLAUDE_MATCHER)


def _merge_codex_hooks(path: Path) -> None:
    _merge_pretooluse_hooks(path, CODEX_MATCHER)


def _merge_cursor_hooks(path: Path) -> None:
    settings = _load_json_object(path)
    settings.setdefault("version", 1)
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
    settings["hooks"] = hooks

    pretooluse = hooks.get("preToolUse")
    if not isinstance(pretooluse, list):
        pretooluse = []

    def _is_ours(entry: object) -> bool:
        return isinstance(entry, dict) and _is_our_hook_command(str(entry.get("command") or ""))

    kept = [e for e in pretooluse if not _is_ours(e)]
    kept.append({"command": _hook_command(), "matcher": CURSOR_MATCHER})
    hooks["preToolUse"] = kept
    _write_json(path, settings)


def _path_guidance() -> str:
    if sys.platform == "win32":
        scripts_dir = Path(sys.executable).parent / "Scripts"
        return (
            "`ka` was not found on PATH. If you installed with `pip install --user`, "
            f"add its Scripts directory to PATH: {scripts_dir}"
        )
    return (
        "`ka` was not found on PATH. If you installed with `pip install --user`, "
        "add ~/.local/bin to PATH (e.g. in your ~/.bashrc or ~/.zshrc), then "
        "restart your shell."
    )


def _check_path() -> str:
    fresh_path = os.environ.get("PATH")
    found = shutil.which("ka", path=fresh_path) or shutil.which("key-amnesia", path=fresh_path)
    if found:
        return f"ka on PATH: {found}"
    return _path_guidance()


def cmd_setup(args: argparse.Namespace) -> int:
    skills_only = bool(getattr(args, "skills_only", False))
    hook_only = bool(getattr(args, "hook_only", False))
    permissions_only = bool(getattr(args, "permissions_only", False))
    permissions_remove = bool(getattr(args, "permissions_remove", False))
    yes = bool(getattr(args, "yes", False))
    only_flags = [skills_only, hook_only, permissions_only, permissions_remove]
    if sum(1 for f in only_flags if f) > 1:
        theme.error(
            "--skills-only, --hook-only, --permissions-only, and "
            "--permissions-remove are mutually exclusive."
        )
        return 2

    home = Path.home()
    codex_home = _codex_home(home)
    lines: list[str] = []
    rc = 0

    if not hook_only and not permissions_only and not permissions_remove:
        dest_roots = [
            home / ".claude" / "skills",
            home / ".cursor" / "skills",
            home / ".agents" / "skills",
            codex_home / "skills",
        ]
        lines.extend(_copy_skills(dest_roots))

    if not skills_only and not permissions_only and not permissions_remove:
        hook_cmd = _hook_command()
        claude_settings = home / ".claude" / "settings.json"
        cursor_hooks = home / ".cursor" / "hooks.json"
        codex_hooks = codex_home / "hooks.json"
        _merge_claude_settings(claude_settings)
        lines.append(f"hook installed: {claude_settings} (PreToolUse)")
        _merge_cursor_hooks(cursor_hooks)
        lines.append(f"hook installed: {cursor_hooks} (preToolUse)")
        _merge_codex_hooks(codex_hooks)
        lines.append(f"hook installed: {codex_hooks} (PreToolUse)")
        lines.append(f"hook command: {hook_cmd}")

    for line in lines:
        theme.out(line)

    if permissions_remove:
        from key_amnesia.harness_permissions import remove_manifested_rules

        rc = remove_manifested_rules(home)
    elif not skills_only and not hook_only:
        from key_amnesia.harness_permissions import run_permissions

        def _install_hook(name: str) -> None:
            if name == "claude":
                _merge_claude_settings(home / ".claude" / "settings.json")
            elif name == "cursor":
                _merge_cursor_hooks(home / ".cursor" / "hooks.json")
            elif name == "codex":
                _merge_codex_hooks(_codex_home(home) / "hooks.json")

        perm_rc = run_permissions(
            home,
            yes=yes,
            may_install_hook=not permissions_only,
            install_hook_fn=_install_hook,
        )
        if perm_rc:
            rc = perm_rc

    if not permissions_only and not permissions_remove:
        theme.out(_check_path())

    theme.info(
        "Restart Claude Code / Cursor / Codex (or reload the window) to pick "
        "up the new skills and hook."
    )
    theme.info(
        "Codex: review and trust the new hook via `/hooks` before it will run."
    )
    theme.info(
        "In your own terminal: `ka init` (first time) or `ka unlock` (start a session)."
    )
    return rc
