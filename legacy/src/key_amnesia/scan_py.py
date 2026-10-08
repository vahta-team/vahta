"""``ka scan`` — LEAK (Locally Exposed Agent Keys) discovery.

Walks a project tree (and optionally ``--deep`` home/shell/MCP locations
plus known agent session transcript JSONL trees) looking for plaintext
secret *files* and light assignment / prefix patterns. Reports **names,
paths, counts, and (for transcripts) line numbers only** — never prints,
logs, or copies secret values.

Detection is **advisory**. The headline names the ``--strict`` gate.
Default ``--strict high`` exit counts ``certain`` + ``likely``. Identifier-
and passphrase-shaped hits are ``possible`` (``--strict paranoid`` to
gate). Policy classification: Scan LEAK report is **advisory** (not
cryptography).
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from key_amnesia.detect import (
    NAMED_WEAKENING_IDENTIFIER,
    NAMED_WEAKENING_LOW_TRANSITION,
    NAMED_WEAKENING_WORD_SHAPED_PASSPHRASE,
    REASON_UNCONFIRMED_MCP,
    REASON_UUID,
    HitSet,
    classify_value,
    collect_strings,
    iter_secret_keyed_strings,
    looks_like_json_container,
    scan_text_hits,
    scan_texts,
)
from key_amnesia.dotenv_import import parse_dotenv

# Directory basenames skipped by default (B4). ``.git`` skips all git
# internals — git-*history* secret scanning is intentionally out of scope.
DEFAULT_EXCLUDE_DIR_NAMES: frozenset[str] = frozenset(
    {
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".git",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "target",
        ".next",
        ".nuxt",
        "coverage",
        ".eggs",
        ".amnesia",  # vault ciphertext — not agent-readable plaintext
        ".hg",
        ".svn",
    }
)

# Filename suffixes / exact names that are build/cache artifacts even when
# the parent dir isn't excluded.
_SKIP_SUFFIXES = (".pyc", ".pyo", ".egg-info")

# Max bytes to read when content-scanning a non-dotenv file.
_MAX_CONTENT_BYTES = 256_000

# Skip oversized session transcripts (line-iter still; refuse open if huge).
_MAX_TRANSCRIPT_BYTES = 100 * 1024 * 1024

# Intra-file --deep progress: tick every N JSONL lines so a single huge
# transcript cannot freeze stderr on a per-file counter.
_PROGRESS_LINE_EVERY = 2000

ProgressFn = Callable[[str, int, int], None]

# Cap human-report line lists; full list remains in ``--json``.
_HIT_LINES_DISPLAY_CAP = 20

STRICT_CERTAIN = "certain"
STRICT_HIGH = "high"
STRICT_PARANOID = "paranoid"
_CONF_ORDER = {"certain": 0, "likely": 1, "possible": 2}
_REASON_LABELS: dict[str, str] = {
    NAMED_WEAKENING_IDENTIFIER: "identifier",
    NAMED_WEAKENING_WORD_SHAPED_PASSPHRASE: "passphrase",
    NAMED_WEAKENING_LOW_TRANSITION: "low-transition",
    REASON_UUID: "uuid",
    REASON_UNCONFIRMED_MCP: "unconfirmed-mcp-shape",
}
_REASON_LABEL_ORDER: tuple[str, ...] = (
    NAMED_WEAKENING_IDENTIFIER,
    NAMED_WEAKENING_WORD_SHAPED_PASSPHRASE,
    NAMED_WEAKENING_LOW_TRANSITION,
    REASON_UUID,
    REASON_UNCONFIRMED_MCP,
)

# Text-ish extensions worth content-scanning for assignment patterns.
_CONTENT_SCAN_SUFFIXES = frozenset(
    {
        "",
        ".env",
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".mjs",
        ".cjs",
        ".json",
        ".toml",
        ".yaml",
        ".yml",
        ".ini",
        ".cfg",
        ".conf",
        ".config",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".bat",
        ".cmd",
        ".txt",
        ".md",
        ".properties",
        ".xml",
        ".rb",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".php",
        ".cs",
    }
)

_SSH_PRIVATE_NAMES = frozenset({"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"})

_MCP_BASENAMES = frozenset(
    {
        "mcp.json",
        "claude_desktop_config.json",
    }
)

_HISTORY_BASENAMES = frozenset(
    {
        ".bash_history",
        ".zsh_history",
        ".zhistory",
        ".python_history",
        ".node_repl_history",
        ".lesshst",
    }
)


@dataclass
class Finding:
    """One LEAK finding. Never carries secret *values*."""

    path: str
    kind: str
    secret_names: list[str] = field(default_factory=list)
    secret_count: int = 0
    reason: str = ""
    importable: bool = False
    scope: str = "project"  # "project" | "deep"
    # 1-based JSONL line numbers (agent transcripts only).
    hit_lines: list[int] = field(default_factory=list)
    # certain | likely | possible — constructions set this explicitly.
    confidence: str = ""
    # Named reason codes (never values): uuid, low-transition, identifier, …
    reasons: list[str] = field(default_factory=list)
    reason_counts: dict[str, int] = field(default_factory=dict)


def _is_dotenv_filename(name: str) -> bool:
    """``.env``, ``.env.local``, ``.env.production``, etc. — not ``.environment``."""
    if name == ".env":
        return True
    if name.startswith(".env."):
        # Skip already-imported leftovers.
        return not name.endswith(".imported")
    return False


def _filename_kind(path: Path) -> str | None:
    name = path.name
    if _is_dotenv_filename(name):
        return "dotenv"
    if name == "credentials.json":
        return "credentials.json"
    if name == ".npmrc":
        return ".npmrc"
    if name == ".pypirc":
        return ".pypirc"
    if name in _SSH_PRIVATE_NAMES:
        return "ssh_private_key"
    if name in _MCP_BASENAMES or (
        name == "mcp.json" or path.as_posix().endswith("/mcp.json")
    ):
        return "mcp_config"
    if name in _HISTORY_BASENAMES or name.endswith("_history"):
        return "shell_history"
    if name == ".gitconfig" or name == ".git-credentials":
        return "git_config"
    return None


def _safe_read_text(path: Path, *, limit: int = _MAX_CONTENT_BYTES) -> str | None:
    try:
        data = path.read_bytes()[:limit]
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return None


def _dotenv_finding(path: Path, *, scope: str) -> Finding | None:
    try:
        entries = parse_dotenv(path)
    except OSError:
        return None
    # Names only; drop empty values from the count (placeholders often empty).
    names = [n for n, v in entries.items() if v.strip()]
    if not names and not entries:
        # Empty / comment-only .env — still a LEAK *file* if it exists and
        # looks like a dotenv path agents will open; count 0 secrets.
        return Finding(
            path=str(path),
            kind="dotenv",
            secret_names=[],
            secret_count=0,
            reason="dotenv file (no KEY=VALUE entries)",
            importable=False,
            scope=scope,
            confidence="certain",
        )
    if not names:
        return Finding(
            path=str(path),
            kind="dotenv",
            secret_names=list(entries.keys()),
            secret_count=0,
            reason="dotenv file (empty values only)",
            importable=False,
            scope=scope,
            confidence="certain",
        )
    return Finding(
        path=str(path),
        kind="dotenv",
        secret_names=names,
        secret_count=len(names),
        reason=f"dotenv file with {len(names)} secret name(s)",
        importable=True,
        scope=scope,
        confidence="certain",
    )


def _json_key_names(path: Path) -> list[str]:
    """Top-level JSON object keys only — never values."""
    text = _safe_read_text(path)
    if text is None:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        return [str(k) for k in data.keys()]
    return []


def scan_text_for_leaks(text: str) -> tuple[list[str], str | None]:
    """High-confidence assignment *names* + optional prefix/Bearer kind.

    Never returns secret values. Possible-tier hits are omitted here;
    use ``scan_text_hits`` for the split.
    """
    if not text:
        return [], None
    hits = scan_text_hits(text)
    return hits.likely_names, hits.prefix


def _apply_secret_keys(acc: HitSet, node: Any) -> None:
    """Classify secret-named dict keys that never appear as ASSIGN text."""
    for key, val in iter_secret_keyed_strings(node):
        extra = HitSet()
        tier, reason = classify_value(val)
        if tier not in ("likely", "possible"):
            continue
        extra.record_assignment(key, tier, [reason] if reason else [])
        acc.merge(extra)


def _scan_transcript_payload(obj: Any) -> HitSet:
    """Run detectors on string payloads and secret-named JSON keys.

    JSON-container strings are unwrapped once and not run through
    ``scan_text_hits`` (ASSIGN on serialized JSON plus a secret-key walk
    would double-count). Non-JSON strings are scanned. Secret-key walk
    covers dict keys that never appear as ASSIGN text. Never returns values.
    """
    acc = HitSet()
    nested_objs: list[Any] = []

    def _ingest_strings(node: Any) -> None:
        # Collected first, scanned once. A transcript holds thousands of tiny
        # strings, and calling the detector per string spends more on the
        # implementation boundary than the detection itself costs.
        batch: list[str] = []
        for s in collect_strings(node):
            if looks_like_json_container(s):
                try:
                    nested = json.loads(s)
                except json.JSONDecodeError:
                    nested = None
                if isinstance(nested, (dict, list)):
                    nested_objs.append(nested)
                    continue
            batch.append(s)
        if batch:
            acc.merge(scan_texts(batch))

    _ingest_strings(obj)
    # One-level unwrap: inner strings of parsed JSON containers, not the
    # container text itself (already skipped above).
    for nested in list(nested_objs):
        batch = [
            s for s in collect_strings(nested) if not looks_like_json_container(s)
        ]
        if batch:
            acc.merge(scan_texts(batch))

    _apply_secret_keys(acc, obj)
    for nested in nested_objs:
        _apply_secret_keys(acc, nested)
    return acc


def iter_agent_transcript_files(home: Path | None = None) -> Iterable[Path]:
    """Yield known agent session JSONL transcript paths under ``home``.

    Not a full home walk — only Claude Code / Codex / Copilot CLI layouts.
    """
    home = (home or Path.home()).resolve()
    seen: set[str] = set()

    def _emit(path: Path) -> Iterable[Path]:
        try:
            if not path.is_file():
                return
            key = str(path.resolve())
        except OSError:
            return
        if key in seen:
            return
        seen.add(key)
        yield path

    claude_projects = home / ".claude" / "projects"
    if claude_projects.is_dir():
        try:
            for path in claude_projects.rglob("*.jsonl"):
                yield from _emit(path)
        except OSError:
            pass

    for sub in ("sessions", "archived_sessions"):
        root = home / ".codex" / sub
        if not root.is_dir():
            continue
        try:
            for path in root.rglob("rollout-*.jsonl"):
                yield from _emit(path)
        except OSError:
            pass

    copilot_state = home / ".copilot" / "session-state"
    if copilot_state.is_dir():
        try:
            for path in copilot_state.glob("*/events.jsonl"):
                yield from _emit(path)
        except OSError:
            pass


def _inline_findings(
    path: Path,
    text: str,
    *,
    scope: str,
    kind: str,
    high_reason: str,
    possible_reason: str,
) -> list[Finding]:
    """Split content hits into high vs possible findings. Never includes values."""
    hits = scan_text_hits(text)
    likely_names = hits.likely_names
    possible_names = hits.possible_names
    prefix = hits.prefix
    bearer_likely = hits.bearer_likely
    bearer_possible = hits.bearer_possible

    out: list[Finding] = []
    if prefix:
        out.append(
            Finding(
                path=str(path),
                kind=kind,
                secret_names=[],
                secret_count=1,
                reason=f"inline credential-shaped token ({prefix})",
                importable=False,
                scope=scope,
                confidence="certain",
            )
        )
    if likely_names or bearer_likely:
        count = len(likely_names) if likely_names else 1
        reason = high_reason
        if bearer_likely and not likely_names:
            reason = "inline credential-shaped token (Bearer token)"
        out.append(
            Finding(
                path=str(path),
                kind=kind,
                secret_names=likely_names,
                secret_count=count,
                reason=reason,
                importable=False,
                scope=scope,
                confidence="likely",
                reasons=list(hits.likely_reasons),
                reason_counts=dict(hits.likely_reason_counts),
            )
        )
    if possible_names or bearer_possible:
        names = possible_names
        count = len(names) if names else 1
        out.append(
            Finding(
                path=str(path),
                kind=kind,
                secret_names=names,
                secret_count=count,
                reason=possible_reason,
                importable=False,
                scope=scope,
                confidence="possible",
                reasons=list(hits.possible_reasons),
                reason_counts=dict(hits.possible_reason_counts),
            )
        )
    return out


def _findings_for_transcript(
    path: Path,
    *,
    scope: str,
    progress: ProgressFn | None = None,
) -> list[Finding]:
    """Scan one JSONL session transcript; names/paths/line hits only."""
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size > _MAX_TRANSCRIPT_BYTES:
        return []

    certain_lines: list[int] = []
    likely_lines: list[int] = []
    possible_lines: list[int] = []
    certain_names: list[str] = []
    likely_names: list[str] = []
    possible_names: list[str] = []
    likely_reasons: list[str] = []
    possible_reasons: list[str] = []
    likely_reason_counts: dict[str, int] = {}
    possible_reason_counts: dict[str, int] = {}
    seen_certain: set[str] = set()
    seen_likely: set[str] = set()
    seen_possible: set[str] = set()

    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line_no, raw in enumerate(fh, start=1):
                if (
                    progress is not None
                    and line_no % _PROGRESS_LINE_EVERY == 0
                ):
                    progress(path.name, line_no, 0)
                line = raw.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                hits = _scan_transcript_payload(obj)
                has_certain = bool(hits.prefix)
                has_likely = bool(hits.likely_names or hits.bearer_likely)
                has_possible = bool(hits.possible_names or hits.bearer_possible)
                if not has_certain and not has_likely and not has_possible:
                    continue
                if has_certain:
                    certain_lines.append(line_no)
                    if hits.prefix and hits.prefix not in seen_certain:
                        seen_certain.add(hits.prefix)
                        certain_names.append(hits.prefix)
                if has_likely:
                    if not has_certain:
                        likely_lines.append(line_no)
                    for name in hits.likely_names:
                        key = name.upper()
                        if key in seen_likely or key in seen_certain:
                            continue
                        seen_likely.add(key)
                        likely_names.append(name)
                    for reason in hits.likely_reasons:
                        if reason not in likely_reasons:
                            likely_reasons.append(reason)
                    for reason, n in hits.likely_reason_counts.items():
                        likely_reason_counts[reason] = (
                            likely_reason_counts.get(reason, 0) + n
                        )
                # Mixed higher-tier lines stay out of possible hit_lines /
                # transcript_line_hit_count, but possible names/reasons are
                # still recorded so histograms stay complete.
                if has_possible:
                    if not has_certain and not has_likely:
                        possible_lines.append(line_no)
                    for name in hits.possible_names:
                        key = name.upper()
                        if (
                            key in seen_possible
                            or key in seen_likely
                            or key in seen_certain
                        ):
                            continue
                        seen_possible.add(key)
                        possible_names.append(name)
                    for reason in hits.possible_reasons:
                        if reason not in possible_reasons:
                            possible_reasons.append(reason)
                    for reason, n in hits.possible_reason_counts.items():
                        possible_reason_counts[reason] = (
                            possible_reason_counts.get(reason, 0) + n
                        )
    except OSError:
        return []

    out: list[Finding] = []
    if certain_lines:
        out.append(
            Finding(
                path=str(path),
                kind="agent_session_transcript",
                secret_names=certain_names,
                secret_count=len(certain_lines),
                reason=(
                    f"agent session transcript: {len(certain_lines)} line(s) with "
                    "vendor-prefix credential-shaped content (advisory; false "
                    "positives/negatives expected)"
                ),
                importable=False,
                scope=scope,
                hit_lines=certain_lines,
                confidence="certain",
            )
        )
    if likely_lines or likely_names:
        if likely_lines:
            likely_reason = (
                f"agent session transcript: {len(likely_lines)} line(s) with "
                "likely assignment-shaped content (advisory; false "
                "positives/negatives expected)"
            )
        else:
            likely_reason = (
                "agent session transcript: likely assignment-shaped names "
                "on higher-confidence lines"
            )
        out.append(
            Finding(
                path=str(path),
                kind="agent_session_transcript",
                secret_names=likely_names,
                secret_count=len(likely_lines),
                reason=likely_reason,
                importable=False,
                scope=scope,
                hit_lines=likely_lines,
                confidence="likely",
                reasons=likely_reasons,
                reason_counts=likely_reason_counts,
            )
        )
    if possible_lines or possible_names:
        if possible_lines:
            poss_reason = (
                f"agent session transcript: {len(possible_lines)} line(s) with "
                "possible identifier- or passphrase-shaped content"
            )
        else:
            poss_reason = (
                "agent session transcript: possible identifier- or "
                "passphrase-shaped names on higher-confidence lines"
            )
        out.append(
            Finding(
                path=str(path),
                kind="agent_session_transcript",
                secret_names=possible_names,
                secret_count=len(possible_lines),
                reason=poss_reason,
                importable=False,
                scope=scope,
                hit_lines=possible_lines,
                confidence="possible",
                reasons=possible_reasons,
                reason_counts=possible_reason_counts,
            )
        )
    return out


def _findings_for_path(path: Path, *, scope: str) -> list[Finding]:
    kind = _filename_kind(path)
    if kind == "dotenv":
        finding = _dotenv_finding(path, scope=scope)
        return [] if finding is None else [finding]

    if kind is not None:
        names: list[str] = []
        count = 1
        reason = f"sensitive filename ({kind})"
        if kind == "credentials.json":
            names = _json_key_names(path)
            count = max(len(names), 1)
            reason = f"credentials.json ({count} top-level key name(s))"
        elif kind == "mcp_config":
            names = _json_key_names(path)
            count = max(len(names), 1)
            confirmed = any(k in ("mcpServers", "servers") for k in names)
            if confirmed:
                return [
                    Finding(
                        path=str(path),
                        kind=kind,
                        secret_names=names,
                        secret_count=count,
                        reason=f"MCP config ({count} top-level key name(s))",
                        importable=False,
                        scope=scope,
                        confidence="certain",
                    )
                ]
            # Unrecognised shape: demote to possible, do not drop.
            # Presence/shape finding: one per file, not per top-level key.
            return [
                Finding(
                    path=str(path),
                    kind=kind,
                    secret_names=names,
                    secret_count=1,
                    reason=(
                        "unconfirmed MCP config shape (no top-level "
                        "mcpServers/servers)"
                    ),
                    importable=False,
                    scope=scope,
                    confidence="possible",
                    reasons=[REASON_UNCONFIRMED_MCP],
                    reason_counts={REASON_UNCONFIRMED_MCP: 1},
                )
            ]
        elif kind in (".npmrc", ".pypirc"):
            reason = f"{kind} (may contain registry auth tokens)"
        elif kind == "ssh_private_key":
            reason = "SSH private key file"
        elif kind == "shell_history":
            text = _safe_read_text(path)
            if not text:
                return []
            return _inline_findings(
                path,
                text,
                scope=scope,
                kind=kind,
                high_reason="shell history with credential-shaped content",
                possible_reason=(
                    "shell history with possible identifier- or "
                    "passphrase-shaped content"
                ),
            )
        elif kind == "git_config":
            text = _safe_read_text(path) or ""
            if not re.search(
                r"(?i)(token|password|authorization|_authToken)\s*=", text
            ) and "://" not in text:
                if not re.search(r"https?://[^/\s:]+:[^/\s]+@", text):
                    return []
            reason = "git config may embed credentials"
        return [
            Finding(
                path=str(path),
                kind=kind,
                secret_names=names,
                secret_count=count,
                reason=reason,
                importable=False,
                scope=scope,
                confidence="certain",
            )
        ]

    suffix = path.suffix.lower()
    if suffix not in _CONTENT_SCAN_SUFFIXES and path.name not in {
        "Dockerfile",
        "Makefile",
        "Jenkinsfile",
    }:
        return []
    text = _safe_read_text(path)
    if not text:
        return []
    return _inline_findings(
        path,
        text,
        scope=scope,
        kind="inline",
        high_reason="assignment pattern matching secret-guard vocabulary",
        possible_reason="possible identifier- or passphrase-shaped assignment",
    )


def _should_skip_dir(name: str, *, include_excluded: bool) -> bool:
    if include_excluded:
        # Still never walk into .amnesia vault storage.
        return name == ".amnesia"
    return name in DEFAULT_EXCLUDE_DIR_NAMES or name.endswith(".egg-info")


def iter_project_files(
    root: Path,
    *,
    include_excluded: bool = False,
) -> Iterable[Path]:
    """Yield files under ``root``, honouring default exclusions."""
    root = root.resolve()
    if not root.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        # Prune in place so os.walk does not descend.
        dirnames[:] = sorted(
            d
            for d in dirnames
            if not _should_skip_dir(d, include_excluded=include_excluded)
        )
        for fname in filenames:
            if any(fname.endswith(suf) for suf in _SKIP_SUFFIXES):
                continue
            yield Path(dirpath) / fname


def scan_project(
    root: Path,
    *,
    include_excluded: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for path in iter_project_files(root, include_excluded=include_excluded):
        try:
            if not path.is_file():
                continue
        except OSError:
            continue
        key = str(path)
        try:
            key = str(path.resolve())
        except OSError:
            pass
        if key in seen:
            continue
        seen.add(key)
        for finding in _findings_for_path(path, scope="project"):
            if (
                finding.kind == "dotenv"
                and finding.secret_count == 0
                and not finding.secret_names
            ):
                continue
            findings.append(finding)
    findings.sort(key=lambda f: (f.path, _CONF_ORDER.get(f.confidence, 9)))
    return findings


def _deep_candidate_paths(home: Path | None = None) -> list[Path]:
    home = (home or Path.home()).resolve()
    candidates: list[Path] = []

    # Dotfiles / known secret homes.
    for name in (
        ".env",
        ".env.local",
        ".npmrc",
        ".pypirc",
        ".gitconfig",
        ".git-credentials",
        ".bash_history",
        ".zsh_history",
        ".zhistory",
        ".python_history",
        ".node_repl_history",
    ):
        candidates.append(home / name)

    ssh = home / ".ssh"
    for key_name in _SSH_PRIVATE_NAMES:
        candidates.append(ssh / key_name)

    # MCP / agent configs (Cursor, Claude Desktop).
    candidates.extend(
        [
            home / ".cursor" / "mcp.json",
            home / ".claude" / "mcp.json",
            home / ".config" / "claude" / "claude_desktop_config.json",
            home / ".config" / "Cursor" / "User" / "mcp.json",
        ]
    )
    appdata = os.environ.get("APPDATA")
    if appdata:
        candidates.extend(
            [
                Path(appdata) / "Claude" / "claude_desktop_config.json",
                Path(appdata) / "Cursor" / "User" / "mcp.json",
            ]
        )
    # PowerShell history (Windows).
    if appdata:
        candidates.append(
            Path(appdata)
            / "Microsoft"
            / "Windows"
            / "PowerShell"
            / "PSReadLine"
            / "ConsoleHost_history.txt"
        )

    return candidates


def scan_deep(
    home: Path | None = None,
    *,
    progress: ProgressFn | None = None,
) -> list[Finding]:
    """Scan known home / shell / MCP / agent-transcript locations.

    Not a full home tree walk — fixed candidates plus known transcript globs.
    """
    findings: list[Finding] = []
    seen: set[str] = set()
    for path in _deep_candidate_paths(home):
        try:
            if not path.is_file():
                continue
        except OSError:
            continue
        key = str(path)
        try:
            key = str(path.resolve())
        except OSError:
            pass
        if key in seen:
            continue
        seen.add(key)
        for finding in _findings_for_path(path, scope="deep"):
            if (
                finding.kind == "dotenv"
                and finding.secret_count == 0
                and not finding.secret_names
            ):
                continue
            findings.append(finding)

    transcripts = list(iter_agent_transcript_files(home))
    n_transcripts = len(transcripts)
    for i, path in enumerate(transcripts, start=1):
        if progress is not None:
            progress("agent transcripts", i, n_transcripts)
        try:
            key = str(path.resolve())
        except OSError:
            key = str(path)
        if key in seen:
            continue
        seen.add(key)
        for finding in _findings_for_transcript(
            path, scope="deep", progress=progress
        ):
            seen.add(finding.path)
            findings.append(finding)

    findings.sort(key=lambda f: (f.path, _CONF_ORDER.get(f.confidence, 9)))
    return findings


def gated_confidences(strict: str) -> frozenset[str]:
    if strict == STRICT_CERTAIN:
        return frozenset({"certain"})
    if strict == STRICT_PARANOID:
        return frozenset({"certain", "likely", "possible"})
    return frozenset({"certain", "likely"})


def leak_count(findings: list[Finding], *, strict: str = STRICT_HIGH) -> int:
    gated = gated_confidences(strict)
    return sum(max(f.secret_count, 0) for f in findings if f.confidence in gated)


def certain_count(findings: list[Finding]) -> int:
    return sum(max(f.secret_count, 0) for f in findings if f.confidence == "certain")


def likely_count(findings: list[Finding]) -> int:
    return sum(max(f.secret_count, 0) for f in findings if f.confidence == "likely")


def possible_count(findings: list[Finding]) -> int:
    return sum(
        max(f.secret_count, 0) for f in findings if f.confidence == "possible"
    )


def transcript_line_hit_count(findings: list[Finding]) -> int:
    """Sum of certain+likely LEAK line-hits in transcript findings."""
    return sum(
        max(f.secret_count, 0)
        for f in findings
        if f.kind == "agent_session_transcript"
        and f.confidence in ("certain", "likely")
    )


def headline(
    findings: list[Finding],
    *,
    strict: str = STRICT_HIGH,
) -> str:
    n = leak_count(findings, strict=strict)
    unit = "LEAK" if n == 1 else "LEAKs"
    return (
        f"{n} {unit} found (--strict {strict}) — your agent can read {n} secret"
        f"{'' if n == 1 else 's'} {_location_clause(findings, strict=strict)} "
        f"(LEAK = Locally Exposed Agent Keys)"
    )


def _location_clause(findings: list[Finding], *, strict: str) -> str:
    gated = gated_confidences(strict)
    here = sum(
        max(f.secret_count, 0)
        for f in findings
        if f.confidence in gated and f.scope == "project"
    )
    away = sum(
        max(f.secret_count, 0)
        for f in findings
        if f.confidence in gated and f.scope != "project"
    )
    if away and not here:
        return "on this machine, outside this project"
    if away and here:
        return (
            f"on this machine — {here} in this project, {away} outside it"
        )
    return "in this project"


def _reason_bucket_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        if f.confidence == "possible":
            if f.reason_counts:
                for reason, n in f.reason_counts.items():
                    counts[reason] = counts.get(reason, 0) + n
            elif f.reasons:
                if len(f.reasons) == 1:
                    counts[f.reasons[0]] = counts.get(f.reasons[0], 0) + max(
                        f.secret_count, 1
                    )
                else:
                    for reason in f.reasons:
                        counts[reason] = counts.get(reason, 0) + 1
            else:
                counts[NAMED_WEAKENING_IDENTIFIER] = counts.get(
                    NAMED_WEAKENING_IDENTIFIER, 0
                ) + max(f.secret_count, 1)
        elif f.confidence == "likely" and REASON_UUID in f.reasons:
            n = 0
            if f.reason_counts and REASON_UUID in f.reason_counts:
                n = f.reason_counts[REASON_UUID]
            else:
                n = max(f.secret_count, 1)
            counts[REASON_UUID] = counts.get(REASON_UUID, 0) + n
    return counts


def format_count_summary(findings: list[Finding]) -> str:
    """Always-printed three-count line. Identical at every ``--strict``."""
    base = (
        f"{certain_count(findings)} certain · {likely_count(findings)} likely · "
        f"{possible_count(findings)} possible"
    )
    buckets = _reason_bucket_counts(findings)
    if not buckets:
        return base
    parts: list[str] = []
    seen: set[str] = set()
    for reason in _REASON_LABEL_ORDER:
        if reason in buckets and buckets[reason] > 0:
            label = _REASON_LABELS.get(reason, reason)
            parts.append(f"{buckets[reason]} {label}")
            seen.add(reason)
    for reason, n in sorted(buckets.items()):
        if reason in seen or n <= 0:
            continue
        parts.append(f"{n} {_REASON_LABELS.get(reason, reason)}")
    if not parts:
        return base
    return f"{base} ({' · '.join(parts)})"


def format_gate_totals(findings: list[Finding]) -> str:
    """Always-printed --strict certain / high / paranoid totals."""
    width = max(len(STRICT_CERTAIN), len(STRICT_HIGH), len(STRICT_PARANOID))
    rows = (
        (STRICT_CERTAIN, leak_count(findings, strict=STRICT_CERTAIN)),
        (STRICT_HIGH, leak_count(findings, strict=STRICT_HIGH)),
        (STRICT_PARANOID, leak_count(findings, strict=STRICT_PARANOID)),
    )
    return "\n".join(f"--strict {name:<{width}}  {n}" for name, n in rows)


def findings_to_json(
    findings: list[Finding],
    *,
    project_root: str,
    strict: str = STRICT_HIGH,
) -> dict[str, Any]:
    n = leak_count(findings, strict=strict)
    transcript_hits = transcript_line_hit_count(findings)
    return {
        "leak_count": n,
        "certain_count": certain_count(findings),
        "likely_count": likely_count(findings),
        "possible_count": possible_count(findings),
        "strict_certain": leak_count(findings, strict=STRICT_CERTAIN),
        "strict_high": leak_count(findings, strict=STRICT_HIGH),
        "strict_paranoid": leak_count(findings, strict=STRICT_PARANOID),
        "transcript_line_hits": transcript_hits,
        "headline": headline(findings, strict=strict),
        "strict": strict,
        "project_root": project_root,
        "findings": [asdict(f) for f in findings],
        "detection_note": (
            "Advisory heuristics; leak_count matches the --strict gate "
            f"({strict}). certain_count / likely_count / possible_count are "
            "ungated. Per-finding confidence and reasons are always present. "
            "Values are never included."
        ),
    }


def _format_hit_lines(hit_lines: list[int]) -> str:
    if not hit_lines:
        return ""
    if len(hit_lines) <= _HIT_LINES_DISPLAY_CAP:
        shown = ", ".join(str(n) for n in hit_lines)
        return f"\n      lines: {shown}"
    head = hit_lines[:_HIT_LINES_DISPLAY_CAP]
    rest = len(hit_lines) - _HIT_LINES_DISPLAY_CAP
    shown = ", ".join(str(n) for n in head)
    return f"\n      lines: {shown} (and {rest} more; see --json)"


def format_human_report(
    findings: list[Finding],
    *,
    project_root: Path,
    strict: str = STRICT_HIGH,
) -> str:
    lines: list[str] = [
        headline(findings, strict=strict),
        "",
        format_count_summary(findings),
        "",
        format_gate_totals(findings),
        "",
    ]
    transcript_hits = transcript_line_hit_count(findings)
    if transcript_hits:
        unit = "LEAK" if transcript_hits == 1 else "LEAKs"
        lines.append(
            f"{transcript_hits} {unit} found in agent session transcripts "
            f"(line-hits; advisory detection)"
        )
        lines.append("")
    gated = gated_confidences(strict)
    listed = [
        f
        for f in findings
        if f.confidence in gated
        and not (
            f.secret_count == 0 and f.kind == "agent_session_transcript"
        )
    ]
    if not listed:
        lines.append(
            "No locally exposed agent keys found under default exclusions."
        )
        return "\n".join(lines)
    if any(f.scope == "project" for f in listed):
        lines.append(f"Project root: {project_root}")
        lines.append("")
    for i, f in enumerate(listed, start=1):
        names = ", ".join(f.secret_names) if f.secret_names else "(filename/presence)"
        extra_reasons = ""
        if f.reasons:
            extra_reasons = f"  reasons={','.join(f.reasons)}"
        lines.append(
            f"  [{i}] {f.path}"
            f"\n      kind={f.kind}  count={f.secret_count}  "
            f"scope={f.scope}  confidence={f.confidence}"
            f"{extra_reasons}"
            f"\n      names: {names}"
            f"\n      {f.reason}"
            + ("  [importable]" if f.importable else "")
            + _format_hit_lines(f.hit_lines)
        )
        lines.append("")
    lines.append("Values are never shown.")
    next_line = format_import_next_line(findings, project_root=project_root)
    if next_line:
        lines.append(next_line)
    lines.append(
        "Detection is advisory; false positives and false negatives are "
        "expected. Word-shaped passphrases appear under possible, not the "
        "default headline count."
    )
    return "\n".join(lines)


def importable_findings(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.importable and f.secret_count > 0]


def format_import_next_line(
    findings: list[Finding], *, project_root: Path
) -> str | None:
    """Compose a ``ka import`` hint from scan-discovered dotenv paths only.

    Uses ``Finding.path`` from this scan — never agent-supplied text.
    """
    parts: list[str] = []
    try:
        root = project_root.resolve()
    except OSError:
        root = project_root
    for f in importable_findings(findings):
        p = Path(f.path)
        if not _is_dotenv_filename(p.name):
            continue
        try:
            display = p.resolve().relative_to(root).as_posix()
        except (ValueError, OSError):
            display = p.as_posix()
        parts.append(display)
    if not parts:
        return None
    return "Next: in your own terminal, ka import " + " ".join(parts)
