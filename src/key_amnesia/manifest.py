"""Project manifest (`amnesia.toml`) — schema, load, and CI check.

Committed plaintext contract of which secrets a project expects. Never
holds values. Roles are out of scope until a later PR.

Canonical schema (since 0.3.11)::

    [secrets.OPENAI_API_KEY]
    required = true
    description = "OpenAI API key"
    env = "OPENAI_API_KEY"

``ka import`` writes this form. A legacy ``[[secret]]`` array-of-tables
shape (written by 0.3.9–0.3.10 import) is still *read* for compatibility.

``ka check`` compares required entries against the **project** names
sidecar only — no decrypt, no global vault. Suitable for CI.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

MANIFEST_NAME = "amnesia.toml"


@dataclass(frozen=True)
class SecretEntry:
    """One declared secret in the project manifest. No values."""

    name: str
    required: bool = True
    description: str = ""
    env: str = ""

    def __post_init__(self) -> None:
        if not self.env:
            object.__setattr__(self, "env", self.name)


@dataclass
class Manifest:
    path: Path
    secrets: dict[str, SecretEntry] = field(default_factory=dict)


@dataclass
class CheckResult:
    """Outcome of comparing a manifest to a names sidecar."""

    ok: bool
    manifest_path: Path | None
    names_path: Path | None
    required: list[str]
    present: list[str]
    missing: list[str]
    optional_absent: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "manifest": str(self.manifest_path) if self.manifest_path else None,
            "names_path": str(self.names_path) if self.names_path else None,
            "required": list(self.required),
            "present": list(self.present),
            "missing": list(self.missing),
            "optional_absent": list(self.optional_absent),
            "error": self.error,
        }


def manifest_path_for(project_root: Path) -> Path:
    return project_root / MANIFEST_NAME


def load_manifest(path: Path) -> Manifest:
    """Parse ``amnesia.toml``. Raises ``ValueError`` on malformed TOML/schema."""
    try:
        raw = path.read_bytes()
    except OSError as e:
        raise ValueError(f"cannot read manifest: {e}") from e
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"invalid TOML in {path}: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"manifest root must be a table: {path}")

    secrets: dict[str, SecretEntry] = {}

    # Canonical: [secrets.NAME]
    secrets_table = data.get("secrets")
    if secrets_table is not None:
        if not isinstance(secrets_table, dict):
            raise ValueError(f"[secrets] must be a table of named entries: {path}")
        for name, body in secrets_table.items():
            if not isinstance(name, str) or not name:
                raise ValueError(f"invalid secret name in {path}")
            secrets[name] = _entry_from_table(name, body, path)

    # Legacy: [[secret]] with name = "..."
    legacy = data.get("secret")
    if legacy is not None:
        if not isinstance(legacy, list):
            raise ValueError(f"[[secret]] must be an array of tables: {path}")
        for body in legacy:
            if not isinstance(body, dict):
                raise ValueError(f"[[secret]] entry must be a table: {path}")
            name = body.get("name")
            if not isinstance(name, str) or not name:
                raise ValueError(f"[[secret]] entry missing name= in {path}")
            if name not in secrets:
                secrets[name] = _entry_from_table(name, body, path)

    return Manifest(path=path, secrets=secrets)


def _entry_from_table(name: str, body: Any, path: Path) -> SecretEntry:
    if body is None:
        body = {}
    if not isinstance(body, dict):
        raise ValueError(f"[secrets.{name}] must be a table in {path}")
    required = body.get("required", True)
    if not isinstance(required, bool):
        raise ValueError(f"[secrets.{name}].required must be a boolean in {path}")
    description = body.get("description", "")
    if description is None:
        description = ""
    if not isinstance(description, str):
        raise ValueError(f"[secrets.{name}].description must be a string in {path}")
    env = body.get("env", name)
    if env is None:
        env = name
    if not isinstance(env, str) or not env:
        raise ValueError(f"[secrets.{name}].env must be a non-empty string in {path}")
    return SecretEntry(
        name=name,
        required=required,
        description=description,
        env=env,
    )


def required_secret_names(manifest: Manifest) -> list[str]:
    return sorted(n for n, e in manifest.secrets.items() if e.required)


def check_against_names(
    manifest: Manifest | None,
    present_names: set[str] | list[str],
    *,
    names_path: Path | None = None,
    error: str | None = None,
) -> CheckResult:
    """Compare required manifest entries to a set of vault secret names.

    Does not decrypt. ``present_names`` is typically the project names
    sidecar contents (for ``ka check``) or the injectable name set (for
    ``ka run``).
    """
    present_set = set(present_names)
    if error is not None:
        return CheckResult(
            ok=False,
            manifest_path=manifest.path if manifest else None,
            names_path=names_path,
            required=[],
            present=[],
            missing=[],
            error=error,
        )
    if manifest is None:
        return CheckResult(
            ok=True,
            manifest_path=None,
            names_path=names_path,
            required=[],
            present=[],
            missing=[],
            error=None,
        )

    required = required_secret_names(manifest)
    present = sorted(n for n in required if n in present_set)
    missing = sorted(n for n in required if n not in present_set)
    optional_absent = sorted(
        n
        for n, e in manifest.secrets.items()
        if not e.required and n not in present_set
    )
    return CheckResult(
        ok=not missing,
        manifest_path=manifest.path,
        names_path=names_path,
        required=required,
        present=present,
        missing=missing,
        optional_absent=optional_absent,
        error=None,
    )


def check_project(
    project_root: Path,
    *,
    names_path: Path,
) -> CheckResult:
    """CI-oriented check: project ``amnesia.toml`` vs project names sidecar.

    Never reads the global vault. Never decrypts.
    """
    mpath = manifest_path_for(project_root)
    if not mpath.exists():
        return CheckResult(
            ok=True,
            manifest_path=None,
            names_path=names_path,
            required=[],
            present=[],
            missing=[],
            error=None,
        )
    try:
        manifest = load_manifest(mpath)
    except ValueError as e:
        return CheckResult(
            ok=False,
            manifest_path=mpath,
            names_path=names_path,
            required=[],
            present=[],
            missing=[],
            error=str(e),
        )
    from key_amnesia.vault import read_names

    present = read_names(names_path)
    return check_against_names(manifest, present, names_path=names_path)


def format_check_human(result: CheckResult) -> str:
    """Human-readable multi-line summary for ``ka check`` (stdout)."""
    lines: list[str] = []
    if result.error:
        lines.append(f"Manifest error: {result.error}")
        return "\n".join(lines)
    if result.manifest_path is None:
        lines.append("No amnesia.toml found — nothing to check.")
        return "\n".join(lines)
    lines.append(f"Manifest: {result.manifest_path}")
    if result.names_path is not None:
        lines.append(f"Project names: {result.names_path}")
    if not result.required:
        lines.append("No required secrets declared.")
        lines.append("OK")
        return "\n".join(lines)
    lines.append(f"Required: {len(result.required)}")
    lines.append(f"Present:  {len(result.present)}")
    if result.missing:
        lines.append(f"Missing:  {', '.join(result.missing)}")
        lines.append("FAIL")
    else:
        lines.append("Missing:  (none)")
        lines.append("OK")
    if result.optional_absent:
        lines.append(
            f"Optional absent (informational): {', '.join(result.optional_absent)}"
        )
    return "\n".join(lines)


def format_check_json(result: CheckResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def missing_required_message(missing: list[str]) -> str:
    """Clear one-line / short block for ``ka run`` preflight failure."""
    listed = ", ".join(missing)
    return (
        f"Missing required secret(s) declared in amnesia.toml: {listed}. "
        f"Add them with 'ka set NAME' (or 'ka import') before running."
    )


# --- Write / merge (used by ka import) ---------------------------------------

_ENV_FIELD_RE = re.compile(r'^\s*env\s*=\s*"([^"]*)"\s*$', re.MULTILINE)
_SECRETS_TABLE_RE = re.compile(r"^\s*\[secrets\.([^\]]+)\]\s*$", re.MULTILINE)
_LEGACY_NAME_RE = re.compile(r'^\s*name\s*=\s*"([^"]*)"\s*$', re.MULTILINE)


def existing_manifest_names(manifest_text: str) -> set[str]:
    """Names already covered by a manifest file (canonical or legacy).

    Matched on ``[secrets.NAME]`` table keys, legacy ``name =`` fields, and
    ``env =`` fields (so a hand-edited env alias still suppresses a re-add).
    """
    names: set[str] = set()
    for m in _SECRETS_TABLE_RE.finditer(manifest_text):
        key = m.group(1).strip().strip('"')
        if key:
            names.add(key)
    names.update(_ENV_FIELD_RE.findall(manifest_text))
    names.update(_LEGACY_NAME_RE.findall(manifest_text))
    return names


def _manifest_block(name: str) -> str:
    """Canonical ``[secrets.NAME]`` block written by ``ka import``."""
    return (
        f"[secrets.{name}]\n"
        "required = true\n"
        'description = ""\n'
        f'env = "{name}"\n'
    )


def generate_or_merge_manifest(names: list[str], project_root: Path) -> Path:
    """Create or merge ``amnesia.toml`` covering ``names`` (canonical schema).

    Existing entries (matched via :func:`existing_manifest_names`) are left
    untouched — this only appends blocks for names not already present.
    Returns the manifest path unconditionally (even if nothing was added).
    """
    path = manifest_path_for(project_root)
    existing_text = path.read_text(encoding="utf-8") if path.exists() else ""
    covered = existing_manifest_names(existing_text)

    new_blocks = [_manifest_block(name) for name in names if name not in covered]
    if not new_blocks:
        return path

    content = existing_text
    if content and not content.endswith("\n"):
        content += "\n"
    if content:
        content += "\n"
    content += "\n".join(new_blocks)

    path.write_text(content, encoding="utf-8")
    return path
