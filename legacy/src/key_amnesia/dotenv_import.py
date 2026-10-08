"""Shared dotenv parsing + vault-import core.

Used by ``ka import`` and by ``ka scan``'s offer-to-import path —
keep the pure logic here decision-injectable (callbacks) rather than
baking in any particular CLI's prompt wording.

Hard rule: nothing in this module ever prints, logs, or returns a secret
*value* on its own initiative — callers own all display, and even they
should only ever show secret *names*.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal

_LINE_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def parse_dotenv(path: Path) -> dict[str, str]:
    """Parse a dotenv-format file into an ordered ``name -> value`` mapping.

    Supports ``KEY=value``, optional leading ``export ``, single/double
    quoted values (with a trailing unquoted inline ``# comment`` stripped
    for unquoted values only), blank lines, and full-line ``#`` comments.
    Not a full dotenv-spec parser (no multi-line values) — sufficient for
    the common case this feature targets. Never prints anything itself.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    result: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _LINE_RE.match(line)
        if not match:
            continue
        name, raw_value = match.group(1), match.group(2)
        result[name] = _unquote(raw_value)
    return result


def _unquote(raw_value: str) -> str:
    value = raw_value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
        return value[1:-1]
    # Unquoted: an inline ` #comment` is conventionally dropped by dotenv
    # tooling; a bare trailing `#` with no preceding space is left alone
    # since it could legitimately be part of the value.
    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    return value


CollisionDecision = str  # "overwrite" | "skip"


def import_entries(
    entries: dict[str, str],
    existing_secrets: dict[str, str],
    *,
    on_collision: Callable[[str], CollisionDecision] | None = None,
) -> tuple[list[str], list[str]]:
    """Merge ``entries`` into ``existing_secrets`` (mutated in place).

    Returns ``(imported_names, skipped_names)`` — names only, never values.
    A name already present in ``existing_secrets`` is skipped unless
    ``on_collision(name)`` is supplied and returns ``"overwrite"``; the
    default with no callback is always skip (never a silent overwrite).
    """
    imported: list[str] = []
    skipped: list[str] = []
    for name, value in entries.items():
        if name in existing_secrets:
            decision = on_collision(name) if on_collision is not None else "skip"
            if decision != "overwrite":
                skipped.append(name)
                continue
        existing_secrets[name] = value
        imported.append(name)
    return imported, skipped


def generate_or_merge_manifest(names: list[str], project_root: Path) -> Path:
    """Create or merge a minimal ``amnesia.toml`` covering ``names``.

    Delegates to :func:`key_amnesia.manifest.generate_or_merge_manifest`
    (canonical ``[secrets.NAME]`` schema since 0.3.11). Kept as a re-export
    so ``ka import`` and tests keep importing from this module.
    """
    from key_amnesia.manifest import generate_or_merge_manifest as _gen

    return _gen(names, project_root)


_GITIGNORE_ENV_PATTERNS = {".env*", ".env", ".env.*"}


def _gitignore_already_covers_env(gitignore_text: str) -> bool:
    for line in gitignore_text.splitlines():
        if line.strip() in _GITIGNORE_ENV_PATTERNS:
            return True
    return False


def offer_gitignore(project_root: Path, ask: Callable[[], bool]) -> bool:
    """Ask (never silently) whether to add ``.env*`` to ``.gitignore``.

    No-ops (without asking) if a covering pattern is already present.
    Returns True if the pattern was added.
    """
    gitignore_path = project_root / ".gitignore"
    existing_text = gitignore_path.read_text(encoding="utf-8") if gitignore_path.exists() else ""
    if _gitignore_already_covers_env(existing_text):
        return False
    if not ask():
        return False
    new_text = existing_text
    if new_text and not new_text.endswith("\n"):
        new_text += "\n"
    new_text += ".env*\n"
    gitignore_path.write_text(new_text, encoding="utf-8")
    return True


def delete_or_rename_source(
    path: Path,
    *,
    confirm_delete: Callable[[], bool],
    confirm_delete_again: Callable[[], bool],
    confirm_rename: Callable[[], bool],
) -> str:
    """Ask (never silently) what to do with the just-imported source file.

    Flow: ask to delete; a "yes" is double-confirmed before anything is
    removed (declining the second confirmation leaves the file untouched —
    it does not fall through to the rename offer). A "no" to the first
    question offers a rename to ``<name>.imported`` instead.

    Returns one of ``"deleted"``, ``"renamed"``, ``"kept"``.
    """
    if confirm_delete():
        if confirm_delete_again():
            path.unlink()
            return "deleted"
        return "kept"
    if confirm_rename():
        target = path.with_name(path.name + ".imported")
        path.replace(target)
        return "renamed"
    return "kept"


MissingPolicy = Literal["error", "skip"]
PathOutcome = Literal["deleted", "renamed", "kept", "missing", "empty"]


@dataclass
class ImportCommitResult:
    """Names and per-path outcomes only — never secret values."""

    imported: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    path_outcomes: dict[str, PathOutcome] = field(default_factory=dict)
    gitignore_added: bool = False
    manifest_path: Path | None = None


def commit_import(
    paths: list[Path],
    existing_secrets: dict[str, str],
    *,
    on_collision: Callable[[str], CollisionDecision] | None = None,
    on_missing: MissingPolicy = "skip",
    commit_vault: Callable[[], None],
    confirm_delete: Callable[[Path], bool],
    confirm_delete_again: Callable[[Path], bool],
    confirm_rename: Callable[[Path], bool],
    gitignore_ask: Callable[[], bool],
    project_root: Path,
) -> ImportCommitResult:
    """Merge dotenv files into an in-memory secrets dict, save, then dispose.

    Callers inject every decision (collision, delete/rename, gitignore) and
    the vault write. ``commit_vault`` runs after all merges and **before**
    any source delete/rename — so a save failure leaves plaintext files
    untouched. Never prints, logs, or returns secret values.
    """
    if on_missing not in ("error", "skip"):
        raise ValueError("on_missing must be 'error' or 'skip'")

    result = ImportCommitResult()
    imported_from: set[str] = set()

    if on_missing == "error":
        for path in paths:
            if not path.exists():
                raise FileNotFoundError(path)

    for path in paths:
        key = str(path)
        if not path.exists():
            result.path_outcomes[key] = "missing"
            continue
        try:
            entries = parse_dotenv(path)
        except OSError:
            if on_missing == "error":
                raise
            result.path_outcomes[key] = "missing"
            continue
        if not entries:
            result.path_outcomes[key] = "empty"
            continue
        imported, skipped = import_entries(
            entries, existing_secrets, on_collision=on_collision
        )
        result.imported.extend(imported)
        result.skipped.extend(skipped)
        result.path_outcomes[key] = "kept"
        if imported:
            imported_from.add(key)

    if result.imported:
        commit_vault()
        for path in paths:
            key = str(path)
            if key not in imported_from:
                continue
            outcome = delete_or_rename_source(
                path,
                confirm_delete=lambda p=path: confirm_delete(p),
                confirm_delete_again=lambda p=path: confirm_delete_again(p),
                confirm_rename=lambda p=path: confirm_rename(p),
            )
            result.path_outcomes[key] = outcome  # deleted | renamed | kept
        result.gitignore_added = offer_gitignore(project_root, ask=gitignore_ask)
        result.manifest_path = generate_or_merge_manifest(
            result.imported, project_root
        )

    return result
