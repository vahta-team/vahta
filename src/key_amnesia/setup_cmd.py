"""`ka setup`: terminal choice, skills, secret-guard hook, harness allow lists.

Copies the three bundled agent skills to the Claude Code / Cursor / Codex
skills directories and merges a `PreToolUse` (Claude, Codex) / `preToolUse`
(Cursor) hook entry into each host's own config file. For OpenCode, copies a
JS bridge plugin into ``~/.config/opencode/plugins/`` (skills already
auto-load from ``~/.claude/skills`` / ``~/.agents/skills``). Optionally merges
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
import tempfile
import time
from importlib import resources
from pathlib import Path

from key_amnesia import theme
from key_amnesia.config import ConfigError, load_config, set_config_value
from key_amnesia.platform import detect_terminals, spawn_isolated_console

# How long to wait for the test terminal to run its one command and report.
_TERMINAL_TEST_TIMEOUT_S = 6.0
_TERMINAL_TEST_POLL_S = 0.1

SKILL_NAMES = ["key-amnesia-usage", "key-amnesia-hygiene", "key-amnesia-migrate"]

# MCP tool calls reach the same PreToolUse event under `mcp__<server>__<tool>`;
# without the alternative below the hook is never invoked for them at all.
MCP_MATCHER_ALTERNATIVE = "mcp__.*"
CLAUDE_MATCHER = f"Bash|Write|Edit|{MCP_MATCHER_ALTERNATIVE}"
# Cursor routes MCP calls to its own beforeMCPExecution event, not preToolUse.
CURSOR_MATCHER = "Shell|Write"
# Codex: Bash + apply_patch aliases (Write/Edit also match apply_patch edits).
CODEX_MATCHER = f"Bash|Write|Edit|apply_patch|{MCP_MATCHER_ALTERNATIVE}"
HOOK_COMMAND = "key-amnesia-hook"
_HOOK_MODULE = "key_amnesia.hooks.secret_guard"
_WIN_NEEDS_QUOTE = frozenset(' \t"&|<>^()%,;=')
_HOOK_ARGV_SENTINEL = "const HOOK_ARGV = null; // filled by ka setup"


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


def _opencode_plugin_template() -> str:
    root = resources.files("key_amnesia") / "plugins" / "opencode" / "secret-guard.js"
    return root.read_text(encoding="utf-8")


def _bake_opencode_plugin(source: str) -> str:
    argv = shlex.split(_hook_command())
    baked = "const HOOK_ARGV = " + json.dumps(argv) + "; // filled by ka setup"
    if _HOOK_ARGV_SENTINEL not in source:
        return source
    return source.replace(_HOOK_ARGV_SENTINEL, baked, 1)


def install_opencode_plugin(home: Path) -> list[str]:
    """Copy the OpenCode bridge plugin; never parse opencode.json."""
    from key_amnesia.harness_permissions import (
        OPENCODE_PLUGIN_MARKER,
        opencode_config_dir,
        opencode_config_note,
        opencode_plugin_dest,
    )

    lines: list[str] = []
    note = opencode_config_note(home)
    if note:
        lines.append(note)
    oc = opencode_config_dir(home)
    if not oc.is_dir():
        return lines + [f"skip OpenCode hook: {oc} is absent"]
    dest = opencode_plugin_dest(home)
    if dest.exists():
        try:
            existing = dest.read_text(encoding="utf-8")
        except OSError as e:
            return lines + [f"OpenCode plugin: could not read {dest}: {e}"]
        if OPENCODE_PLUGIN_MARKER not in existing:
            return lines + [f"left in place (not a key-amnesia managed file): {dest}"]
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(_bake_opencode_plugin(_opencode_plugin_template()), encoding="utf-8")
    return lines + [f"hook installed: {dest} (OpenCode plugin)"]


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


def _terminal_applies() -> bool:
    """Only Linux has to be told. Windows opens a console, macOS Terminal.app."""
    return sys.platform.startswith("linux")


def _prompt_terminal_choice(
    detected: list[tuple[str, list[str]]], current: str
) -> str | None:
    """Ask which terminal to use. Returns a command string, or None to keep as-is."""
    theme.info("Which terminal should key-amnesia open when it needs your password?")
    for i, (name, command) in enumerate(detected, start=1):
        shown = shlex.join(command[1:]) if len(command) > 1 else ""
        suffix = f"  ({name} {shown})" if shown else ""
        theme.out(f"  {i}) {name}{suffix}")
    auto_n = len(detected) + 1
    theme.out(f"  {auto_n}) detect one each time (no fixed choice)")

    default_n = 1
    for i, (name, _) in enumerate(detected, start=1):
        if current and shlex.split(current)[0].endswith(name):
            default_n = i
            break

    try:
        raw = input(f"Choice [{default_n}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        theme.out("")
        return None
    if not raw:
        raw = str(default_n)
    try:
        choice = int(raw)
    except ValueError:
        theme.warn(f"Not a number: {raw!r} — leaving the terminal setting alone.")
        return None
    if choice == auto_n:
        return ""
    if 1 <= choice <= len(detected):
        name, command = detected[choice - 1]
        # Store the name plus its flags, not the absolute path: a stored path
        # goes stale when the terminal moves between /usr/bin and /usr/local.
        return shlex.join([name, *command[1:]])
    theme.warn(f"Out of range: {choice} — leaving the terminal setting alone.")
    return None


def _test_terminal() -> tuple[bool, str]:
    """Open the configured terminal on a command that reports back.

    Configuring a terminal and finding out it does not open is the failure this
    whole setting exists to prevent, so setup proves the choice rather than
    trusting it. Returns (ok, detail).
    """
    fd, marker = tempfile.mkstemp(prefix="key-amnesia-terminal-test-")
    os.close(fd)
    os.unlink(marker)
    argv = ["sh", "-c", 'printf ok > "$1"', "sh", marker]
    try:
        spawn_isolated_console(argv, dict(os.environ))
    except OSError as e:
        return False, str(e).splitlines()[0]

    deadline = time.monotonic() + _TERMINAL_TEST_TIMEOUT_S
    while time.monotonic() < deadline:
        if os.path.exists(marker):
            try:
                os.unlink(marker)
            except OSError:
                pass
            return True, "opened and ran the test command"
        time.sleep(_TERMINAL_TEST_POLL_S)
    try:
        os.unlink(marker)
    except OSError:
        pass
    return False, (
        f"the window did not run the command within {_TERMINAL_TEST_TIMEOUT_S:.0f}s"
    )


def configure_terminal(*, yes: bool = False, force: bool = False) -> int:
    """Pick, store and prove the terminal used for the password prompt."""
    if not _terminal_applies():
        theme.out(f"terminal: not configurable on {sys.platform} (uses the OS console)")
        return 0

    current = str(load_config().get("terminal") or "")
    detected = detect_terminals()

    chosen: str | None = None
    if not detected:
        # Nothing to offer. If something is already configured it may still
        # work — it just is not a name this build knows — so keep it and let
        # the check below have the last word.
        if not current:
            theme.warn(
                "No terminal emulator found on PATH. Without one, any `ka` "
                "command that needs your password from a non-interactive "
                "parent cannot ask."
            )
            theme.info(
                'Install one, or name yours: ka config set terminal "myterm --run-in"'
            )
            return 0
        theme.out(f"terminal: {current} (configured; none of the known ones found)")
    elif current and not force:
        theme.out(f"terminal: {current} (already configured)")
    elif len(detected) == 1 and not force:
        chosen = shlex.join([detected[0][0], *detected[0][1][1:]])
        theme.out(f"terminal: {chosen} (the only one installed)")
    elif yes or not sys.stdin.isatty():
        chosen = shlex.join([detected[0][0], *detected[0][1][1:]])
        theme.out(f"terminal: {chosen} (first of {len(detected)} found; not asking)")
    else:
        chosen = _prompt_terminal_choice(detected, current)
        if chosen == "":
            theme.out("terminal: detect one each time")

    if chosen is not None:
        try:
            set_config_value("terminal", chosen)
        except ConfigError as e:
            theme.error(f"Could not store the terminal: {e}")
            return 1

    ok, detail = _test_terminal()
    if ok:
        theme.success(f"Terminal check: {detail}")
        return 0
    theme.warn(f"Terminal check failed: {detail}")
    theme.info(
        'Set one explicitly with the flag it needs, e.g. '
        'ka config set terminal "ghostty -e"'
    )
    return 1


def cmd_setup(args: argparse.Namespace) -> int:
    skills_only = bool(getattr(args, "skills_only", False))
    hook_only = bool(getattr(args, "hook_only", False))
    permissions_only = bool(getattr(args, "permissions_only", False))
    permissions_remove = bool(getattr(args, "permissions_remove", False))
    terminal_only = bool(getattr(args, "terminal_only", False))
    reconfigure_terminal = bool(getattr(args, "reconfigure_terminal", False))
    yes = bool(getattr(args, "yes", False))
    uninstall = bool(getattr(args, "uninstall", False))
    dry_run = bool(getattr(args, "dry_run", False))
    force = bool(getattr(args, "force", False))
    if (dry_run or force) and not uninstall:
        theme.error("--dry-run and --force only apply to --uninstall.")
        return 2
    if uninstall:
        if (
            skills_only
            or hook_only
            or permissions_only
            or permissions_remove
            or terminal_only
            or reconfigure_terminal
            or yes
        ):
            theme.error("--uninstall cannot be combined with other setup flags.")
            return 2
        from key_amnesia.uninstall_cmd import run_uninstall

        return run_uninstall(Path.home(), dry_run=dry_run, force=force)
    only_flags = [
        skills_only,
        hook_only,
        permissions_only,
        permissions_remove,
        terminal_only,
    ]
    if sum(1 for f in only_flags if f) > 1:
        theme.error(
            "--skills-only, --hook-only, --permissions-only, "
            "--permissions-remove and --terminal-only are mutually exclusive."
        )
        return 2

    if terminal_only:
        return configure_terminal(yes=yes, force=True)

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
        lines.append(
            "OpenCode: skills auto-load from ~/.claude/skills and ~/.agents/skills "
            "(nothing extra to install)"
        )

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
        lines.extend(install_opencode_plugin(home))
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
            elif name == "opencode":
                for line in install_opencode_plugin(home):
                    theme.out(line)

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

    if not (skills_only or hook_only or permissions_only or permissions_remove):
        # Only on a full run: the check opens a real window, and someone who
        # asked for skills alone did not ask for that. Last, so a fresh install
        # has already put `ka` where it can be found before we open a terminal
        # that depends on it.
        term_rc = configure_terminal(yes=yes, force=reconfigure_terminal)
        if term_rc and not rc:
            rc = term_rc

    theme.info(
        "Restart Claude Code / Cursor / Codex / OpenCode (or reload the window) to pick "
        "up the new skills and hook."
    )
    theme.info(
        "Codex: review and trust the new hook via `/hooks` before it will run."
    )
    theme.info(
        "In your own terminal: `ka init` (first time) or `ka unlock` (start a session)."
    )
    return rc
