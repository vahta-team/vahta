"""`ka setup --uninstall`: remove what `ka setup` installed, and only that.

Removes the hook entries, the OpenCode bridge plugin, the copied skills and the
harness allow/deny entries that `ka setup` wrote. Everything else in those
files is foreign and is kept intact and in order, including a ``vahta-hook``
entry. The ownership rule for hook commands is the one setup uses
(``setup_cmd._is_our_hook_command``); permission strings are the exact ones the
generators in ``harness_permissions`` produce.

Never touched: the vault, ``.amnesia/`` directories, ``config.json`` (the
terminal choice lives there beside other settings), the audit log and the
permissions manifest. This module does not even resolve the data directory.

A malformed JSON file is reported and left alone (install recovers to ``{}``;
uninstall must not). Each JSON file is backed up once to ``<file>.ka-backup``
and then replaced through a temp file plus rename.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from key_amnesia import theme
from key_amnesia.harness_permissions import (
    CURSOR_ALLOW_INSTRUCTION,
    OPENCODE_PLUGIN_REL,
    claude_allow_matchers,
    claude_automode_allow_matchers,
    claude_deny_matchers,
    cursor_allow_prefixes,
    load_json_object_strict,
    opencode_allow_globs,
    opencode_config_dir,
    opencode_deny_globs,
    opencode_plugin_dest,
    opencode_plugin_managed,
)
from key_amnesia.setup_cmd import (
    SKILL_NAMES,
    _codex_home,
    _is_our_hook_command,
    _skills_root,
)

BACKUP_SUFFIX = ".ka-backup"

# What the help text promises; also printed at the end of every run.
NEVER_TOUCHED = (
    "Never touched: the vault, .amnesia/ directories, config (including the "
    "terminal setting), the audit log and anything else holding your data."
)

Removed = list[tuple[str, str]]  # (harness, what)


@dataclass
class _Report:
    removed: Removed = field(default_factory=list)
    kept: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# --- JSON edit helpers -------------------------------------------------------


def _drop_strings(
    parent: dict, key: str, ours: set[str], *, drop_if_emptied: bool
) -> list[str]:
    """Remove exactly ``ours`` from ``parent[key]`` (a string list).

    Returns the removed strings. The key itself goes only when our removal
    emptied the list and ``drop_if_emptied`` is set.
    """
    val = parent.get(key)
    if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
        return []
    gone = [x for x in val if x in ours]
    if not gone:
        return []
    kept = [x for x in val if x not in ours]
    if kept or not drop_if_emptied:
        parent[key] = kept
    else:
        del parent[key]
    return gone


def _prune_if_empty(parent: dict, key: str) -> None:
    if isinstance(parent.get(key), dict) and not parent[key]:
        del parent[key]


def _hooks_pretooluse_claude(data: dict, event: str = "PreToolUse") -> list[str]:
    """Claude / Codex shape: groups of ``{"matcher", "hooks": [{command}]}``."""
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return []
    groups = hooks.get(event)
    if not isinstance(groups, list):
        return []
    removed: list[str] = []
    new_groups: list[Any] = []
    for group in groups:
        items = group.get("hooks") if isinstance(group, dict) else None
        if not isinstance(items, list) or not items:
            new_groups.append(group)
            continue
        kept_items = []
        for item in items:
            if isinstance(item, dict) and _is_our_hook_command(str(item.get("command") or "")):
                removed.append(f"{event} hook {item.get('command')}")
            else:
                kept_items.append(item)
        if len(kept_items) == len(items):
            new_groups.append(group)
        elif kept_items:
            group["hooks"] = kept_items
            new_groups.append(group)
        # else: our removal emptied the group; drop it
    if not removed:
        return []
    if new_groups:
        hooks[event] = new_groups
    else:
        del hooks[event]
        _prune_if_empty(data, "hooks")
    return removed


def _hooks_cursor(data: dict) -> list[str]:
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return []
    entries = hooks.get("preToolUse")
    if not isinstance(entries, list):
        return []
    removed: list[str] = []
    kept: list[Any] = []
    for entry in entries:
        if isinstance(entry, dict) and _is_our_hook_command(str(entry.get("command") or "")):
            removed.append(f"preToolUse hook {entry.get('command')}")
        else:
            kept.append(entry)
    if not removed:
        return []
    if kept:
        hooks["preToolUse"] = kept
    else:
        del hooks["preToolUse"]
        _prune_if_empty(data, "hooks")
    return removed


def _claude_permissions(data: dict) -> list[str]:
    removed: list[str] = []
    perms = data.get("permissions")
    if isinstance(perms, dict):
        for key, ours in (
            ("allow", claude_allow_matchers()),
            ("deny", claude_deny_matchers()),
        ):
            gone = _drop_strings(perms, key, set(ours), drop_if_emptied=True)
            if gone:
                removed.append(f"permissions.{key}: {len(gone)} entries")
        if removed:
            _prune_if_empty(data, "permissions")
    auto = data.get("autoMode")
    if isinstance(auto, dict):
        # setup only merges into an autoMode.allow that already existed, so an
        # emptied list stays as the (empty) list it was.
        gone = _drop_strings(
            auto, "allow", set(claude_automode_allow_matchers()), drop_if_emptied=False
        )
        if gone:
            removed.append(f"autoMode.allow: {len(gone)} entries")
    return removed


def _cursor_permissions(data: dict) -> list[str]:
    removed: list[str] = []
    # An emptied terminalAllowlist stays: in permissions.json an absent key
    # means "use the in-app list", which is not what the user had.
    gone = _drop_strings(
        data, "terminalAllowlist", set(cursor_allow_prefixes()), drop_if_emptied=False
    )
    if gone:
        removed.append(f"terminalAllowlist: {len(gone)} entries")
    auto = data.get("autoRun")
    if isinstance(auto, dict):
        inst = auto.get("allow_instructions")
        if isinstance(inst, list):
            gone = _drop_strings(
                auto, "allow_instructions", {CURSOR_ALLOW_INSTRUCTION}, drop_if_emptied=True
            )
            if gone:
                removed.append("autoRun.allow_instructions: 1 entry")
        elif isinstance(inst, str):
            lines = inst.split("\n")
            if CURSOR_ALLOW_INSTRUCTION in lines:
                rest = [ln for ln in lines if ln != CURSOR_ALLOW_INSTRUCTION]
                if "".join(rest).strip():
                    auto["allow_instructions"] = "\n".join(rest)
                else:
                    del auto["allow_instructions"]
                removed.append("autoRun.allow_instructions: 1 entry")
        if removed:
            _prune_if_empty(data, "autoRun")
    return removed


def _cursor_cli_config(data: dict) -> list[str]:
    perms = data.get("permissions")
    if not isinstance(perms, dict):
        return []
    gone = _drop_strings(perms, "allow", set(cursor_allow_prefixes()), drop_if_emptied=False)
    return [f"permissions.allow: {len(gone)} entries"] if gone else []


def _opencode_config(data: dict) -> list[str]:
    removed: list[str] = []
    perms = data.get("permission")
    if isinstance(perms, dict) and isinstance(perms.get("bash"), dict):
        bash = perms["bash"]
        expected: dict[str, str] = {g: "deny" for g in opencode_deny_globs()}
        for g in opencode_allow_globs():
            expected.setdefault(g, "allow")
        # Only entries still carrying the value setup wrote: a glob the user
        # re-pointed (say to "ask") is theirs now.
        gone = [k for k, v in bash.items() if expected.get(k) == v]
        for k in gone:
            del bash[k]
        if gone:
            removed.append(f"permission.bash: {len(gone)} entries")
            if not bash:
                del perms["bash"]
            _prune_if_empty(data, "permission")
    gone = _drop_strings(data, "plugin", {OPENCODE_PLUGIN_REL}, drop_if_emptied=True)
    if gone:
        removed.append(f"plugin: {OPENCODE_PLUGIN_REL}")
    return removed


# --- writing -----------------------------------------------------------------


def _backup_once(real: Path) -> None:
    backup = real.with_name(real.name + BACKUP_SUFFIX)
    if not backup.exists():
        shutil.copy2(real, backup)


def _atomic_write_json(real: Path, data: dict) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(real.parent), prefix=real.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        try:
            shutil.copymode(real, tmp)
        except OSError:
            pass
        os.replace(tmp, real)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _edit_json_file(
    harness_label: dict[Callable, str],
    path: Path,
    editors: list[Callable[[dict], list[str]]],
    *,
    dry_run: bool,
    report: _Report,
) -> None:
    if not os.path.lexists(path):
        return
    # A symlinked config (dotfiles) is edited at its target, never replaced.
    real = Path(os.path.realpath(path))
    data, err = load_json_object_strict(real)
    if err or data is None:
        report.errors.append(f"{path}: {err} (left untouched)")
        return
    found: Removed = []
    for editor in editors:
        for what in editor(data):
            found.append((harness_label[editor], f"{what} [{path}]"))
    if not found:
        return
    if not dry_run:
        try:
            _backup_once(real)
            _atomic_write_json(real, data)
        except OSError as e:
            report.errors.append(f"{path}: could not write: {e}")
            return
    report.removed.extend(found)


# --- skills / plugin ---------------------------------------------------------


def _remove_skills(
    harness: str, root: Path, *, dry_run: bool, force: bool, report: _Report
) -> None:
    bundled = _skills_root()
    for name in SKILL_NAMES:
        skill_dir = root / name
        dest = skill_dir / "SKILL.md"
        if not os.path.lexists(dest):
            continue
        if skill_dir.is_symlink() or dest.is_symlink():
            report.kept.append(f"{dest}: kept (symlink; not a copy made by ka setup)")
            continue
        try:
            current = dest.read_text(encoding="utf-8")
            shipped = (bundled / name / "SKILL.md").read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            report.errors.append(f"{dest}: could not read: {e}")
            continue
        if current != shipped and not force:
            report.kept.append(
                f"{dest}: kept (differs from what ka copies, so it looks edited; "
                "--force removes it)"
            )
            continue
        if not dry_run:
            try:
                dest.unlink()
                try:
                    skill_dir.rmdir()  # only if empty; other files are not ours
                except OSError:
                    pass
            except OSError as e:
                report.errors.append(f"{dest}: could not remove: {e}")
                continue
        note = "" if current == shipped else " (edited; removed by --force)"
        report.removed.append((harness, f"skill {name}{note} [{dest}]"))


def _remove_opencode_plugin(home: Path, *, dry_run: bool, report: _Report) -> None:
    dest = opencode_plugin_dest(home)
    if not os.path.lexists(dest):
        return
    if not opencode_plugin_managed(dest):
        report.kept.append(f"{dest}: kept (no ka marker; not managed by ka setup)")
        return
    if not dry_run:
        try:
            dest.unlink()
        except OSError as e:
            report.errors.append(f"{dest}: could not remove: {e}")
            return
    report.removed.append(("opencode", f"plugin file [{dest}]"))


# --- entry point -------------------------------------------------------------


def run_uninstall(home: Path, *, dry_run: bool = False, force: bool = False) -> int:
    report = _Report()
    codex_home = _codex_home(home)
    cursor = home / ".cursor"
    oc = opencode_config_dir(home)

    labels: dict[Callable, str] = {
        _hooks_pretooluse_claude: "claude",
        _claude_permissions: "claude",
    }
    # Claude and Codex share the hook editor but report under their own name.
    def codex_hooks(data: dict) -> list[str]:
        return _hooks_pretooluse_claude(data)

    def cursor_hooks(data: dict) -> list[str]:
        return _hooks_cursor(data)

    labels.update(
        {
            codex_hooks: "codex",
            cursor_hooks: "cursor",
            _cursor_permissions: "cursor",
            _cursor_cli_config: "cursor",
            _opencode_config: "opencode",
        }
    )

    _edit_json_file(
        labels,
        home / ".claude" / "settings.json",
        [_hooks_pretooluse_claude, _claude_permissions],
        dry_run=dry_run,
        report=report,
    )
    _edit_json_file(
        labels, codex_home / "hooks.json", [codex_hooks], dry_run=dry_run, report=report
    )
    _edit_json_file(
        labels, cursor / "hooks.json", [cursor_hooks], dry_run=dry_run, report=report
    )
    _edit_json_file(
        labels,
        cursor / "permissions.json",
        [_cursor_permissions],
        dry_run=dry_run,
        report=report,
    )
    _edit_json_file(
        labels,
        cursor / "cli-config.json",
        [_cursor_cli_config],
        dry_run=dry_run,
        report=report,
    )
    _edit_json_file(
        labels, oc / "opencode.json", [_opencode_config], dry_run=dry_run, report=report
    )
    _remove_opencode_plugin(home, dry_run=dry_run, report=report)

    for harness, root in (
        ("claude", home / ".claude" / "skills"),
        ("cursor", cursor / "skills"),
        ("codex", codex_home / "skills"),
        ("opencode", home / ".agents" / "skills"),
    ):
        _remove_skills(harness, root, dry_run=dry_run, force=force, report=report)

    verb = "would remove" if dry_run else "removed"
    if dry_run:
        theme.info("Dry run: nothing is written.")
    if report.removed:
        for harness in ("claude", "cursor", "codex", "opencode"):
            mine = [what for h, what in report.removed if h == harness]
            if not mine:
                continue
            theme.out(f"{harness}:")
            for what in mine:
                theme.out(f"  {verb} {what}")
    else:
        theme.out("Nothing installed by ka setup was found; nothing to remove.")
    for line in report.kept:
        theme.warn(line)
    for line in report.errors:
        theme.error(line)
    if report.removed and not dry_run:
        theme.info(f"Each edited JSON file was backed up once to <file>{BACKUP_SUFFIX}.")
    theme.info(NEVER_TOUCHED)
    return 1 if report.errors else 0
