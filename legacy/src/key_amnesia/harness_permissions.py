"""Best-effort harness allow-lists. Deny is the PreToolUse hook."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from key_amnesia import theme
from key_amnesia.ka_policy import COVERAGE_ALLOW, FILE_DENY_VERBS, VALUE_EMIT_VERBS
from key_amnesia.paths import permissions_manifest_path

ConfirmFn = Callable[[str, bool], bool]

AUTOMODE_QUALIFIER = "key-amnesia"
MANIFEST_VERSION = 1

_CLAUDE_BINARIES = ("ka", "key-amnesia")
_SHELLS = ("Bash", "PowerShell")
_HOOK_MARKERS = ("key-amnesia-hook", "key_amnesia.hooks.secret_guard")

FILE_ALLOW_COMMANDS: tuple[str, ...] = tuple(sorted(COVERAGE_ALLOW))
FILE_DENY_COMMANDS: tuple[str, ...] = tuple(sorted(FILE_DENY_VERBS))

# Cursor's autoRun.allow_instructions is documented as string[]: free-form
# sentences that steer the auto-run classifier. Cursor calls them steering,
# not enforcement, so this text claims nothing beyond "usually fine".
CURSOR_ALLOW_INSTRUCTION = (
    "key-amnesia: the read-only verbs ka run, ka list, ka status, ka connect, "
    "ka check, ka scan, ka lock, ka config show, ka identity show, "
    "ka member list, ka docs, ka --version and ka --help do not print secret "
    "values and are usually fine to run unattended. This is steering only: "
    "Cursor still applies its own safety check, and the key-amnesia PreToolUse "
    "hook is what denies ka set, ka reveal, ka export and ka copy."
)

_ABSENT = object()

OPENCODE_PLUGIN_REL = "./plugins/key-amnesia-secret-guard.js"
OPENCODE_PLUGIN_FILENAME = "key-amnesia-secret-guard.js"
OPENCODE_PLUGIN_MARKER = "KEY_AMNESIA_PLUGIN_ID=secret-guard"
OPENCODE_BROAD_PATTERNS = ("*", "ka *", "key-amnesia *")


def _is_our_hook_command(command: str) -> bool:
    return any(m in command for m in _HOOK_MARKERS)


def _claude_matcher(shell: str, binary: str, command: str) -> str:
    if command.startswith("--"):
        return f"{shell}({binary} {command})"
    return f"{shell}({binary} {command}:*)"


def claude_allow_matchers() -> list[str]:
    out: list[str] = []
    for shell in _SHELLS:
        for binary in _CLAUDE_BINARIES:
            for command in FILE_ALLOW_COMMANDS:
                out.append(_claude_matcher(shell, binary, command))
    return out


def claude_deny_matchers() -> list[str]:
    out: list[str] = []
    for shell in _SHELLS:
        for binary in _CLAUDE_BINARIES:
            for command in FILE_DENY_COMMANDS:
                out.append(_claude_matcher(shell, binary, command))
    return out


def claude_automode_allow_matchers() -> list[str]:
    return [f"{m} — {AUTOMODE_QUALIFIER}" for m in claude_allow_matchers()]


def cursor_allow_prefixes() -> list[str]:
    out: list[str] = []
    for binary in ("ka", "key-amnesia", "ka.exe", "key-amnesia.exe"):
        for command in FILE_ALLOW_COMMANDS:
            out.append(f"{binary} {command}")
    return out


def cursor_allow_instructions() -> list[str]:
    """Our managed ``autoRun.allow_instructions`` entries.

    Cursor documents this field as ``string[]``: free-form sentences that
    steer its auto-run classifier. They are steering, not enforcement — a
    matching call still goes through Cursor's own safety check — so the text
    must not read as if it grants anything.
    """
    return [CURSOR_ALLOW_INSTRUCTION]


def _json_shape(val: Any) -> str:
    """Name the JSON shape of ``val`` for a diagnosis without a debugger."""
    if val is _ABSENT:
        return "absent"
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "boolean"
    if isinstance(val, str):
        return "string"
    if isinstance(val, list):
        return "list"
    if isinstance(val, dict):
        return "object"
    if isinstance(val, (int, float)):
        return "number"
    return type(val).__name__


def merge_instruction_string(
    existing: str,
    ours: list[str],
    stale_manifest: list[str],
) -> str:
    """Merge into a single-string field in place, without reshaping it.

    Cursor documents ``string[]``, but a user who wrote one string keeps one
    string: we treat its newlines as entries, drop only our own stale lines,
    and append what is missing. The user's own lines are never rewritten or
    reordered.
    """
    if not existing.strip():
        return "\n".join(ours)
    stale = set(stale_manifest) - set(ours)
    kept = [ln for ln in existing.rstrip().split("\n") if ln not in stale]
    have = set(kept)
    for rule in ours:
        if rule not in have:
            kept.append(rule)
            have.add(rule)
    return "\n".join(kept)


def _xdg_opencode_dir(home: Path) -> Path | None:
    """``$XDG_CONFIG_HOME/opencode`` when that variable points inside ``home``.

    OpenCode reads ``$XDG_CONFIG_HOME/opencode`` whenever the variable is set,
    so a hardcoded ``~/.config/opencode`` can install the guard where OpenCode
    never looks. The containment check keeps a redirected ``home`` (tests, and
    any caller installing into another tree) from escaping into the running
    user's own config directory.
    """
    raw = os.environ.get("XDG_CONFIG_HOME")
    if not raw:
        return None
    base = Path(raw)
    if not base.is_absolute():
        return None
    try:
        base.relative_to(home)
    except ValueError:
        return None
    return base / "opencode"


def opencode_config_dir(home: Path) -> Path:
    xdg = _xdg_opencode_dir(home)
    if xdg is not None:
        return xdg
    return home / ".config" / "opencode"


def opencode_config_note(home: Path) -> str | None:
    """Warn when ``$XDG_CONFIG_HOME`` sends OpenCode where we do not write.

    Staying silent here is the worst failure available to this module: `ka
    setup` would report the guard installed while OpenCode reads elsewhere.
    """
    raw = os.environ.get("XDG_CONFIG_HOME")
    if not raw or _xdg_opencode_dir(home) is not None:
        return None
    try:
        if home != Path.home():
            # Installing into some other tree; this process's XDG says nothing
            # about what OpenCode will read there.
            return None
    except (OSError, RuntimeError):
        return None
    return (
        f"OpenCode: XDG_CONFIG_HOME={raw} points outside {home} — writing to "
        f"{home / '.config' / 'opencode'} instead. If OpenCode reads the other "
        "path, the guard is not installed there."
    )


def opencode_plugin_dest(home: Path) -> Path:
    return opencode_config_dir(home) / "plugins" / OPENCODE_PLUGIN_FILENAME


def opencode_plugin_managed(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        return OPENCODE_PLUGIN_MARKER in path.read_text(encoding="utf-8")
    except OSError:
        return False


def opencode_bash_globs(labels: Iterable[str]) -> list[str]:
    out: list[str] = []
    for binary in ("ka", "key-amnesia"):
        for label in sorted(labels):
            out.append(f"{binary} {label}")
            out.append(f"{binary} {label} *")
    return out


def opencode_deny_globs() -> list[str]:
    return opencode_bash_globs(FILE_DENY_COMMANDS)


def opencode_allow_globs() -> list[str]:
    return opencode_bash_globs(FILE_ALLOW_COMMANDS)


def _matcher_core(entry: str) -> str:
    core = entry.split(" — ", 1)[0].strip()
    return core.replace(":*", " *")


def deny_in_allow_conflicts(allow_entries: Iterable[str]) -> list[str]:
    """Exact allow strings whose matcher is a generated deny verb.

    Match by matcher prefix inside a qualified string (`` — `` qualifier or
    `` in the …`` Claude project qualifier). ``Bash(ka set:*)`` ≡ ``Bash(ka set *)``.
    """
    deny_matchers = claude_deny_matchers()
    deny_cores = {_matcher_core(m) for m in deny_matchers}
    found: list[str] = []
    for entry in allow_entries:
        if not isinstance(entry, str):
            continue
        raw = entry.split(" — ", 1)[0].strip()
        core = _matcher_core(entry)
        if core in deny_cores:
            found.append(entry)
            continue
        hit = False
        for dm in deny_matchers:
            dcore = _matcher_core(dm)
            if raw.startswith(dm) or core.startswith(dcore):
                found.append(entry)
                hit = True
                break
        if hit:
            continue
    return found


def load_json_object_strict(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Fail closed: missing file is empty dict; malformed / non-object is an error."""
    if not path.exists():
        return {}, None
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
        return None, f"unparseable JSON at {path}: {e}"
    if not isinstance(data, dict):
        return None, f"{path} is not a JSON object"
    return data, None


def dump_json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2) + "\n"


def claude_hook_registered(settings: dict[str, Any]) -> bool:
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return False
    pre = hooks.get("PreToolUse")
    if not isinstance(pre, list):
        return False
    for entry in pre:
        if not isinstance(entry, dict):
            continue
        for hook in entry.get("hooks") or []:
            if isinstance(hook, dict) and _is_our_hook_command(
                str(hook.get("command") or "")
            ):
                return True
    return False


def cursor_hook_registered(hooks_doc: dict[str, Any]) -> bool:
    hooks = hooks_doc.get("hooks")
    if not isinstance(hooks, dict):
        return False
    pre = hooks.get("preToolUse")
    if not isinstance(pre, list):
        return False
    for entry in pre:
        if isinstance(entry, dict) and _is_our_hook_command(
            str(entry.get("command") or "")
        ):
            return True
    return False


def merge_string_list(
    existing: list[Any],
    ours: list[str],
    stale_manifest: list[str],
) -> tuple[list[str] | None, str | None]:
    """Keep user strings; drop stale manifested rules; append missing ours."""
    if not all(isinstance(x, str) for x in existing):
        return None, "allow/deny list contains a non-string entry"
    stale = set(stale_manifest) - set(ours)
    out = [x for x in existing if x not in stale]
    have = set(out)
    for rule in ours:
        if rule not in have:
            out.append(rule)
            have.add(rule)
    return out, None


def load_manifest() -> dict[str, Any]:
    path = permissions_manifest_path()
    data, err = load_json_object_strict(path)
    if err or data is None:
        return {"version": MANIFEST_VERSION, "rules": {}}
    rules = data.get("rules")
    if not isinstance(rules, dict):
        return {"version": MANIFEST_VERSION, "rules": {}}
    return data


def save_manifest(rules: dict[str, list[str]]) -> None:
    path = permissions_manifest_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": MANIFEST_VERSION, "rules": rules}
    path.write_text(dump_json(payload), encoding="utf-8")


def _manifest_list(manifest: dict[str, Any], key: str) -> list[str]:
    rules = manifest.get("rules") or {}
    val = rules.get(key) if isinstance(rules, dict) else None
    if isinstance(val, list) and all(isinstance(x, str) for x in val):
        return list(val)
    return []


@dataclass
class FileChange:
    path: Path
    new_text: str
    summary: str
    manifest_key: str
    manifest_rules: list[str]


@dataclass
class HarnessOutcome:
    name: str
    ok: bool = True
    lines: list[str] = field(default_factory=list)
    changes: list[FileChange] = field(default_factory=list)
    conflicts: list[tuple[Path, str]] = field(default_factory=list)
    hook_missing: bool = False
    hook_path: Path | None = None
    extra_manifest: dict[str, list[str]] = field(default_factory=dict)


def _ensure_string_list(obj: dict[str, Any], key: str) -> tuple[list[str] | None, str | None]:
    if key not in obj:
        obj[key] = []
    val = obj[key]
    if not isinstance(val, list):
        return None, f"{key!r} is not a list"
    if not all(isinstance(x, str) for x in val):
        return None, f"{key!r} contains a non-string entry"
    return val, None


def prepare_claude(
    home: Path,
    manifest: dict[str, Any],
) -> HarnessOutcome:
    out = HarnessOutcome(name="claude")
    claude_home = home / ".claude"
    if not claude_home.is_dir():
        out.lines.append("skip Claude permissions: ~/.claude is absent")
        return out

    path = claude_home / "settings.json"
    data, err = load_json_object_strict(path)
    if err:
        out.ok = False
        out.lines.append(f"Claude: {err} (fail closed; no write)")
        out.lines.extend(_pasteable_claude())
        return out
    assert data is not None

    if not claude_hook_registered(data):
        out.hook_missing = True
        out.hook_path = path

    perms = data.get("permissions")
    if perms is None:
        perms = {}
        data["permissions"] = perms
    if not isinstance(perms, dict):
        out.ok = False
        out.lines.append(f"Claude: {path} permissions is not an object (fail closed)")
        out.lines.extend(_pasteable_claude())
        return out

    allow_ours = claude_allow_matchers()
    deny_ours = claude_deny_matchers()
    for verb in VALUE_EMIT_VERBS:
        leaked = any(
            f" {verb}:*" in m or m.endswith(f" {verb})") for m in allow_ours
        )
        if leaked:
            raise RuntimeError(
                f"value-emit verb {verb} leaked into file allow list"
            )

    allow_list, err = _ensure_string_list(perms, "allow")
    if err:
        out.ok = False
        out.lines.append(f"Claude: {path} permissions.allow {err} (fail closed)")
        out.lines.extend(_pasteable_claude())
        return out
    deny_list, err = _ensure_string_list(perms, "deny")
    if err:
        out.ok = False
        out.lines.append(f"Claude: {path} permissions.deny {err} (fail closed)")
        out.lines.extend(_pasteable_claude())
        return out
    assert allow_list is not None and deny_list is not None

    for conflict in deny_in_allow_conflicts(allow_list):
        out.conflicts.append((path, conflict))

    new_allow, err = merge_string_list(
        allow_list, allow_ours, _manifest_list(manifest, "claude.permissions.allow")
    )
    if err:
        out.ok = False
        out.lines.append(f"Claude: {err}")
        return out
    new_deny, err = merge_string_list(
        deny_list, deny_ours, _manifest_list(manifest, "claude.permissions.deny")
    )
    if err:
        out.ok = False
        out.lines.append(f"Claude: {err}")
        return out
    assert new_allow is not None and new_deny is not None
    perms["allow"] = new_allow
    perms["deny"] = new_deny

    auto = data.get("autoMode")
    auto_ours = claude_automode_allow_matchers()
    auto_manifest_rules: list[str] = []
    if isinstance(auto, dict) and isinstance(auto.get("allow"), list):
        auto_allow = auto["allow"]
        if not all(isinstance(x, str) for x in auto_allow):
            out.ok = False
            out.lines.append(
                f"Claude: {path} autoMode.allow has a non-string entry (fail closed)"
            )
            out.lines.extend(_pasteable_claude())
            return out
        for conflict in deny_in_allow_conflicts(auto_allow):
            out.conflicts.append((path, conflict))
        merged_auto, err = merge_string_list(
            auto_allow, auto_ours, _manifest_list(manifest, "claude.autoMode.allow")
        )
        if err:
            out.ok = False
            out.lines.append(f"Claude: {err}")
            return out
        assert merged_auto is not None
        auto["allow"] = merged_auto
        auto_manifest_rules = auto_ours
        # Never rewrite/reorder autoMode.environment — we did not touch it.

    out.changes.append(
        FileChange(
            path=path,
            new_text=dump_json(data),
            summary=f"Claude permissions.allow/deny (+ autoMode.allow if present): {path}",
            manifest_key="claude.settings.json",
            manifest_rules=[],
        )
    )
    out.extra_manifest = {
        "claude.permissions.allow": allow_ours,
        "claude.permissions.deny": deny_ours,
        "claude.autoMode.allow": auto_manifest_rules,
    }
    return out


def prepare_cursor(
    home: Path,
    manifest: dict[str, Any],
) -> HarnessOutcome:
    out = HarnessOutcome(name="cursor")
    cursor_home = home / ".cursor"
    if not cursor_home.is_dir():
        out.lines.append("skip Cursor permissions: ~/.cursor is absent")
        return out

    hooks_path = cursor_home / "hooks.json"
    hooks_doc, hooks_err = load_json_object_strict(hooks_path)
    if hooks_err:
        out.ok = False
        out.lines.append(f"Cursor hooks.json: {hooks_err} (fail closed; no write)")
        return out
    assert hooks_doc is not None
    if not cursor_hook_registered(hooks_doc):
        out.hook_missing = True
        out.hook_path = hooks_path

    prefixes = cursor_allow_prefixes()
    perm_path = cursor_home / "permissions.json"
    if not perm_path.exists():
        out.lines.append(
            "Cursor: ~/.cursor/permissions.json is absent — not creating it "
            "(that file replaces the in-app terminal allowlist). "
            "In Cursor Settings → Agents / Terminal allowlist, add prefixes:"
        )
        for p in prefixes[:8]:
            out.lines.append(f"  {p}")
        out.lines.append("  … (ka / key-amnesia allow verbs; hook denies the rest)")
    else:
        data, err = load_json_object_strict(perm_path)
        if err:
            out.ok = False
            out.lines.append(f"Cursor: {err} (fail closed; no write)")
            out.lines.extend(_pasteable_cursor(prefixes))
            return out
        assert data is not None
        if "terminalAllowlist" in data:
            allow = data["terminalAllowlist"]
            if not isinstance(allow, list) or not all(isinstance(x, str) for x in allow):
                out.ok = False
                out.lines.append(
                    f"Cursor: {perm_path} terminalAllowlist is not a string list "
                    "(fail closed)"
                )
                out.lines.extend(_pasteable_cursor(prefixes))
                return out
            merged, err = merge_string_list(
                allow, prefixes, _manifest_list(manifest, "cursor.terminalAllowlist")
            )
            if err:
                out.ok = False
                out.lines.append(f"Cursor: {err}")
                return out
            assert merged is not None
            data["terminalAllowlist"] = merged
            out.changes.append(
                FileChange(
                    path=perm_path,
                    new_text=dump_json(data),
                    summary=f"Cursor terminalAllowlist: {perm_path}",
                    manifest_key="cursor.terminalAllowlist",
                    manifest_rules=prefixes,
                )
            )
        else:
            # Do not add terminalAllowlist. Optional allow_instructions only.
            auto = data.get("autoRun")
            if auto is None:
                data["autoRun"] = {}
                auto = data["autoRun"]
            if not isinstance(auto, dict):
                out.ok = False
                out.lines.append(
                    f"Cursor: {perm_path} autoRun is not an object (fail closed)"
                )
                return out
            if "block_instructions" in auto:
                pass  # never write or modify block_instructions
            ours = cursor_allow_instructions()
            stale = _manifest_list(manifest, "cursor.allow_instructions")
            existing = auto.get("allow_instructions", _ABSENT)
            shape = _json_shape(existing)
            if existing is _ABSENT or existing is None:
                # Cursor documents string[]; that is what we create.
                auto["allow_instructions"] = list(ours)
            elif isinstance(existing, list):
                merged_i, err = merge_string_list(existing, ours, stale)
                if err is not None:
                    out.ok = False
                    out.lines.append(
                        f"Cursor: {perm_path} autoRun.allow_instructions is a "
                        f"list but {err} (fail closed; no write)"
                    )
                    return out
                assert merged_i is not None
                auto["allow_instructions"] = merged_i
            elif isinstance(existing, str):
                # Keep the user's shape: one string stays one string.
                auto["allow_instructions"] = merge_instruction_string(
                    existing, ours, stale
                )
            else:
                out.ok = False
                out.lines.append(
                    f"Cursor: {perm_path} autoRun.allow_instructions is a "
                    f"{shape}; Cursor documents it as a list of strings "
                    "(fail closed; no write)"
                )
                return out
            out.lines.append(
                f"Cursor: {perm_path} autoRun.allow_instructions shape: "
                f"{shape} — merging {len(ours)} key-amnesia instruction in "
                "that shape (steering for Cursor's auto-run check, not a "
                "grant; the hook is what denies)"
            )
            out.changes.append(
                FileChange(
                    path=perm_path,
                    new_text=dump_json(data),
                    summary=f"Cursor autoRun.allow_instructions: {perm_path}",
                    manifest_key="cursor.allow_instructions",
                    manifest_rules=list(ours),
                )
            )

    cli_path = cursor_home / "cli-config.json"
    if cli_path.exists():
        data, err = load_json_object_strict(cli_path)
        if err:
            out.ok = False
            out.lines.append(f"Cursor CLI: {err} (fail closed; no write)")
            return out
        assert data is not None
        perms = data.get("permissions")
        if isinstance(perms, dict) and isinstance(perms.get("allow"), list):
            allow = perms["allow"]
            if not all(isinstance(x, str) for x in allow):
                out.ok = False
                out.lines.append(
                    f"Cursor CLI: {cli_path} permissions.allow has a non-string "
                    "(fail closed)"
                )
                return out
            merged, err = merge_string_list(
                allow, prefixes, _manifest_list(manifest, "cursor.cli.allow")
            )
            if err:
                out.ok = False
                out.lines.append(f"Cursor CLI: {err}")
                return out
            assert merged is not None
            perms["allow"] = merged
            out.changes.append(
                FileChange(
                    path=cli_path,
                    new_text=dump_json(data),
                    summary=f"Cursor cli-config.json permissions.allow: {cli_path}",
                    manifest_key="cursor.cli.allow",
                    manifest_rules=prefixes,
                )
            )
        else:
            out.lines.append(
                f"Cursor CLI: {cli_path} present but schema has no "
                "permissions.allow string list — not modifying"
            )
    return out


def _pasteable_claude() -> list[str]:
    lines = ["Paste-able Claude permissions.allow:"]
    for m in claude_allow_matchers()[:6]:
        lines.append(f"  {m}")
    lines.append("  …")
    return lines


def _pasteable_cursor(prefixes: list[str]) -> list[str]:
    lines = ["Paste-able Cursor terminal prefixes:"]
    for p in prefixes[:6]:
        lines.append(f"  {p}")
    lines.append("  …")
    return lines


def _pasteable_opencode() -> list[str]:
    lines = ["Paste-able OpenCode permission.bash:"]
    for g in opencode_deny_globs()[:4]:
        lines.append(f'  "{g}": "deny"')
    lines.append("  …")
    lines.append(f'  plugin: ["{OPENCODE_PLUGIN_REL}"]')
    return lines


def prepare_codex(home: Path) -> HarnessOutcome:
    out = HarnessOutcome(name="codex")
    out.lines.append(
        "Codex: no command allow/deny list in config.toml (sandbox/trust only) "
        "— not writing command rules. Trust the key-amnesia hook via /hooks; "
        "until then, verb-deny does not run. File-edit tools may not fire "
        "PreToolUse; `ka set` is a Bash command, so Bash PreToolUse is the path "
        "that matters."
    )
    if not (home / ".codex").is_dir() and not os.environ.get("CODEX_HOME"):
        out.lines.append("skip Codex files: ~/.codex is absent (print-only anyway)")
    return out


def prepare_opencode(
    home: Path,
    manifest: dict[str, Any],
) -> HarnessOutcome:
    out = HarnessOutcome(name="opencode")
    oc_home = opencode_config_dir(home)
    note = opencode_config_note(home)
    if note:
        out.lines.append(note)
    if not oc_home.is_dir():
        out.lines.append(f"skip OpenCode permissions: {oc_home} is absent")
        return out

    path = oc_home / "opencode.json"
    data, err = load_json_object_strict(path)
    if err:
        out.ok = False
        out.lines.append(f"OpenCode: {err} (fail closed; no write)")
        out.lines.extend(_pasteable_opencode())
        return out
    assert data is not None

    plugin_path = opencode_plugin_dest(home)
    if not opencode_plugin_managed(plugin_path):
        out.hook_missing = True
        out.hook_path = plugin_path

    deny_ours = opencode_deny_globs()
    allow_ours = opencode_allow_globs()
    for verb in VALUE_EMIT_VERBS:
        leaked = any(g == f"ka {verb}" or g.startswith(f"ka {verb} ") for g in allow_ours)
        leaked = leaked or any(
            g == f"key-amnesia {verb}" or g.startswith(f"key-amnesia {verb} ")
            for g in allow_ours
        )
        if leaked:
            raise RuntimeError(
                f"value-emit verb {verb} leaked into file allow list"
            )

    perms = data.get("permission")
    if perms is None:
        perms = {}
        data["permission"] = perms
    if not isinstance(perms, dict):
        out.ok = False
        out.lines.append(f"OpenCode: {path} permission is not an object (fail closed)")
        out.lines.extend(_pasteable_opencode())
        return out

    bash = perms.get("bash")
    if bash is None:
        bash_map: dict[str, Any] = {}
    elif isinstance(bash, str):
        bash_map = {"*": bash}
    elif isinstance(bash, dict):
        if not all(isinstance(k, str) for k in bash.keys()):
            out.ok = False
            out.lines.append(
                f"OpenCode: {path} permission.bash has a non-string key (fail closed)"
            )
            out.lines.extend(_pasteable_opencode())
            return out
        if not all(isinstance(v, str) for v in bash.values()):
            out.ok = False
            out.lines.append(
                f"OpenCode: {path} permission.bash has a non-string value (fail closed)"
            )
            out.lines.extend(_pasteable_opencode())
            return out
        bash_map = dict(bash)
    else:
        out.ok = False
        out.lines.append(
            f"OpenCode: {path} permission.bash is not a string or object (fail closed)"
        )
        out.lines.extend(_pasteable_opencode())
        return out

    ours = deny_ours + [g for g in allow_ours if g not in set(deny_ours)]
    stale = set(_manifest_list(manifest, "opencode.permission.bash")) - set(ours)
    merged: dict[str, Any] = {}
    for k, v in bash_map.items():
        if k in stale:
            continue
        merged[k] = v
    for g in deny_ours:
        if g not in merged:
            merged[g] = "deny"
    for g in allow_ours:
        if g not in merged:
            merged[g] = "allow"
    perms["bash"] = merged

    deny_set = set(deny_ours)
    seen_conflicts: set[str] = set()
    for k, v in merged.items():
        if not isinstance(v, str) or v == "deny":
            continue
        if k in deny_set or k in OPENCODE_BROAD_PATTERNS:
            if k not in seen_conflicts:
                out.conflicts.append((path, k))
                seen_conflicts.add(k)

    extra: dict[str, list[str]] = {"opencode.permission.bash": list(ours)}

    plugin_val = data.get("plugin")
    plugin_ours = [OPENCODE_PLUGIN_REL]
    if plugin_val is None:
        data["plugin"] = list(plugin_ours)
        extra["opencode.plugin"] = plugin_ours
    elif not isinstance(plugin_val, list):
        out.lines.append(
            f"OpenCode: {path} plugin is not a list — skipping plugin array "
            "entry (directory scan still loads the guard)"
        )
    elif not all(isinstance(x, str) for x in plugin_val):
        out.lines.append(
            f"OpenCode: {path} plugin contains a non-string entry — skipping "
            "plugin array entry (directory scan still loads the guard)"
        )
    else:
        new_plugin, err = merge_string_list(
            plugin_val, plugin_ours, _manifest_list(manifest, "opencode.plugin")
        )
        if err:
            out.lines.append(
                f"OpenCode: {path} plugin {err} — skipping plugin array "
                "entry (directory scan still loads the guard)"
            )
        else:
            assert new_plugin is not None
            data["plugin"] = new_plugin
            extra["opencode.plugin"] = plugin_ours

    out.extra_manifest = extra
    out.changes.append(
        FileChange(
            path=path,
            new_text=dump_json(data),
            summary=f"OpenCode permission.bash (+ plugin array if writable): {path}",
            manifest_key="opencode.settings",
            manifest_rules=[],
        )
    )
    return out


def _confirm_default(prompt: str, default: bool) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    try:
        answer = input(prompt + suffix).strip().lower()
    except EOFError:
        return default
    if not answer:
        return default
    return answer in ("y", "yes")


def _print_diff(path: Path, new_text: str) -> None:
    old = path.read_text(encoding="utf-8") if path.exists() else ""
    if old == new_text:
        theme.info(f"unchanged: {path}")
        return
    theme.info(f"--- {path}")
    old_lines = old.splitlines()
    new_lines = new_text.splitlines()
    # Compact: show only added lines that look like ka rules, plus counts.
    added = [ln for ln in new_lines if ln not in old_lines]
    removed = [ln for ln in old_lines if ln not in new_lines]
    theme.out(f"  +{len(added)} / -{len(removed)} lines")
    for ln in added[:20]:
        theme.out(f"  + {ln.rstrip()}")
    if len(added) > 20:
        theme.out(f"  + … ({len(added) - 20} more)")


def apply_permission_plan(
    outcomes: list[HarnessOutcome],
    *,
    yes: bool,
    may_install_hook: bool,
    install_hook_fn: Callable[[str], None] | None,
    confirm_fn: ConfirmFn | None = None,
    tty: bool | None = None,
) -> int:
    """Show diffs, handle hook-missing / conflicts, write, update manifest.

    ``yes`` skips the write prompt and must not delete user allows.
    ``yes`` is not acknowledgement that allow may ship without the hook.
    """
    import sys

    confirm = confirm_fn or _confirm_default
    is_tty = sys.stdin.isatty() if tty is None else tty
    rc = 0
    manifest = load_manifest()
    new_rules: dict[str, list[str]] = dict(manifest.get("rules") or {})
    if not isinstance(new_rules, dict):
        new_rules = {}

    theme.info(
        "Files try to let the agent run `ka`; the hook stops forbidden `ka` verbs."
    )

    for outcome in outcomes:
        for line in outcome.lines:
            theme.out(line)
        if not outcome.ok:
            rc = 1

    # Conflicts: loud, default No, --yes must not delete.
    all_conflicts = [(o, p, s) for o in outcomes for p, s in o.conflicts]
    if all_conflicts:
        theme.warn(
            "A deny-verb already appears in an allow list. The hook still "
            "denies it. Exact strings:"
        )
        for _o, path, exact in all_conflicts:
            theme.warn(f"  {path}: {exact}")
            theme.warn("    (permits a forbidden ka verb at the file layer)")
        if yes or not is_tty:
            theme.info("Leaving those user allow rules in place (not deleting).")
        else:
            if confirm("Remove the conflicting allow rules listed above?", False):
                for outcome, path, exact in all_conflicts:
                    for change in outcome.changes:
                        if change.path != path:
                            continue
                        data = json.loads(change.new_text)
                        _drop_exact_string(data, exact)
                        change.new_text = dump_json(data)

    # Hook missing: never write allows silently.
    for outcome in outcomes:
        if not outcome.hook_missing:
            continue
        if not outcome.changes:
            continue
        theme.warn(
            f"{outcome.name}: key-amnesia hook is not registered. Writing "
            "allow lists without the hook would unblock `ka` including `ka set`."
        )
        installed = False
        if may_install_hook and install_hook_fn is not None:
            if is_tty and confirm(
                f"Install the key-amnesia hook for {outcome.name} now?", False
            ):
                install_hook_fn(outcome.name)
                if outcome.name == "opencode" and outcome.hook_path is not None:
                    installed = opencode_plugin_managed(outcome.hook_path)
                else:
                    installed = True
                if installed:
                    outcome.hook_missing = False
        if installed:
            continue
        ack = False
        if is_tty:
            ack = confirm(
                f"Write {outcome.name} allow lists anyway without the deny hook?",
                False,
            )
        if not ack:
            theme.error(
                f"Skipping {outcome.name} allow write (hook missing; "
                "`--yes` is not this acknowledgement)."
            )
            outcome.changes = []
            rc = 1

    pending = [c for o in outcomes if o.ok for c in o.changes]
    if not pending:
        _save_rules_from_outcomes(new_rules, outcomes)
        return rc

    for change in pending:
        _print_diff(change.path, change.new_text)

    do_write = True
    if yes:
        do_write = True
    elif is_tty:
        do_write = confirm("Write the permission file changes above?", True)
    # non-TTY without --yes: write (setup is otherwise non-interactive)

    if not do_write:
        theme.info("No permission files written.")
        return rc

    for outcome in outcomes:
        if not outcome.ok:
            continue
        for change in outcome.changes:
            change.path.parent.mkdir(parents=True, exist_ok=True)
            # Re-read at write time
            current, err = load_json_object_strict(change.path)
            if err:
                theme.error(f"Abort write {change.path}: {err}")
                rc = 1
                continue
            if current is None:
                theme.error(f"Abort write {change.path}: unreadable")
                rc = 1
                continue
            change.path.write_text(change.new_text, encoding="utf-8")
            theme.out(f"wrote {change.path}")
            if change.manifest_key and change.manifest_rules:
                new_rules[change.manifest_key] = list(change.manifest_rules)
        if outcome.extra_manifest:
            new_rules.update(outcome.extra_manifest)

    save_manifest(new_rules)
    return rc


def _drop_exact_string(obj: Any, exact: str) -> None:
    """Remove ``exact`` from string lists *and* as a dict key (OpenCode maps)."""
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            if k == exact:
                del obj[k]
                continue
            v = obj[k]
            if isinstance(v, list):
                obj[k] = [x for x in v if x != exact]
            else:
                _drop_exact_string(v, exact)
    elif isinstance(obj, list):
        for item in obj:
            _drop_exact_string(item, exact)


def _save_rules_from_outcomes(
    new_rules: dict[str, list[str]], outcomes: list[HarnessOutcome]
) -> None:
    for outcome in outcomes:
        if outcome.extra_manifest:
            new_rules.update(outcome.extra_manifest)
        for change in outcome.changes:
            if change.manifest_key and change.manifest_rules:
                new_rules[change.manifest_key] = list(change.manifest_rules)


def remove_manifested_rules(home: Path) -> int:
    """Delete only strings recorded in the permissions manifest."""
    manifest = load_manifest()
    rules = manifest.get("rules") or {}
    rc = 0
    if not isinstance(rules, dict) or not rules:
        rc = _remove_opencode_plugin_file(home)
        if rc == 0:
            theme.info("No permissions manifest entries to remove.")
        return rc

    rc = 0
    mapping: list[tuple[str, Path, tuple[str, ...]]] = [
        (
            "claude.permissions.allow",
            home / ".claude" / "settings.json",
            ("permissions", "allow"),
        ),
        (
            "claude.permissions.deny",
            home / ".claude" / "settings.json",
            ("permissions", "deny"),
        ),
        (
            "claude.autoMode.allow",
            home / ".claude" / "settings.json",
            ("autoMode", "allow"),
        ),
        (
            "cursor.terminalAllowlist",
            home / ".cursor" / "permissions.json",
            ("terminalAllowlist",),
        ),
        (
            "cursor.allow_instructions",
            home / ".cursor" / "permissions.json",
            ("autoRun", "allow_instructions"),
        ),
        (
            "cursor.cli.allow",
            home / ".cursor" / "cli-config.json",
            ("permissions", "allow"),
        ),
        (
            "opencode.permission.bash",
            opencode_config_dir(home) / "opencode.json",
            ("permission", "bash"),
        ),
        (
            "opencode.plugin",
            opencode_config_dir(home) / "opencode.json",
            ("plugin",),
        ),
    ]
    for key, path, trail in mapping:
        recorded = rules.get(key)
        if not isinstance(recorded, list) or not recorded:
            continue
        if not path.exists():
            continue
        data, err = load_json_object_strict(path)
        if err or data is None:
            theme.error(f"skip remove at {path}: {err}")
            rc = 1
            continue
        target = data
        ok = True
        for part in trail[:-1]:
            nxt = target.get(part) if isinstance(target, dict) else None
            if not isinstance(nxt, dict):
                ok = False
                break
            target = nxt
        if not ok:
            continue
        last = trail[-1]
        lst = target.get(last) if isinstance(target, dict) else None
        drop = set(recorded)
        if isinstance(lst, list):
            target[last] = [x for x in lst if x not in drop]
        elif isinstance(lst, dict):
            for k in list(lst.keys()):
                if k in drop:
                    del lst[k]
        else:
            continue
        _drop_empty_opencode_containers(data)
        path.write_text(dump_json(data), encoding="utf-8")
        theme.out(f"removed manifested rules from {path} ({key})")

    rc2 = _remove_opencode_plugin_file(home)
    if rc2:
        rc = rc2

    save_manifest({})
    theme.info("Cleared permissions manifest.")
    return rc


def _remove_opencode_plugin_file(home: Path) -> int:
    js_path = opencode_plugin_dest(home)
    if not opencode_plugin_managed(js_path):
        return 0
    try:
        js_path.unlink()
        theme.out(f"removed {js_path}")
    except OSError as e:
        theme.error(f"skip remove at {js_path}: {e}")
        return 1
    return 0


def _drop_empty_opencode_containers(data: dict[str, Any]) -> None:
    perms = data.get("permission")
    if isinstance(perms, dict):
        bash = perms.get("bash")
        if isinstance(bash, dict) and not bash:
            del perms["bash"]
        if not perms:
            del data["permission"]
    plugin = data.get("plugin")
    if isinstance(plugin, list) and not plugin:
        del data["plugin"]


def run_permissions(
    home: Path,
    *,
    yes: bool,
    may_install_hook: bool,
    install_hook_fn: Callable[[str], None] | None,
    confirm_fn: ConfirmFn | None = None,
    tty: bool | None = None,
) -> int:
    manifest = load_manifest()
    outcomes = [
        prepare_claude(home, manifest),
        prepare_cursor(home, manifest),
        prepare_codex(home),
        prepare_opencode(home, manifest),
    ]
    return apply_permission_plan(
        outcomes,
        yes=yes,
        may_install_hook=may_install_hook,
        install_hook_fn=install_hook_fn,
        confirm_fn=confirm_fn,
        tty=tty,
    )
