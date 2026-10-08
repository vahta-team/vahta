"""Agent-facing `ka` verb policy (allow vs deny). No secret values."""

from __future__ import annotations

import re
import shlex
from typing import Iterable

# CLI subcommands the agent may run unattended (hook does not verb-deny).
ALLOW_VERBS: frozenset[str] = frozenset(
    {
        "run",
        "list",
        "status",
        "connect",
        "check",
        "scan",
        "lock",
        "docs",
        "--version",
        "--help",
    }
)

ALLOW_NESTED: dict[str, frozenset[str]] = {
    "config": frozenset({"show"}),
    "identity": frozenset({"show"}),
    "member": frozenset({"list"}),
}

DENY_VERBS: frozenset[str] = frozenset(
    {
        "set",
        "remove",
        "import",
        "passwd",
        "change-password",
        "init",
        "unlock",
        "grant",
        "revoke",
        "setup",
        "reveal",
        "export",
        "copy",
        "_prompt-helper",
    }
)

DENY_NESTED: dict[str, frozenset[str]] = {
    "config": frozenset({"set"}),
    "identity": frozenset({"create"}),
    "member": frozenset({"add", "remove"}),
}

# File allow/deny lists never include the hidden helper.
VALUE_EMIT_VERBS: frozenset[str] = frozenset({"reveal", "export", "copy"})


def _coverage_labels(
    verbs: frozenset[str], nested: dict[str, frozenset[str]]
) -> frozenset[str]:
    labels = set(verbs)
    for group, subs in nested.items():
        labels.update(f"{group} {sub}" for sub in subs)
    return frozenset(labels)


# Labels for the cli.py coverage test (exactly one table each).
# Derived from the tables classify_ka_argv actually enforces.
COVERAGE_ALLOW: frozenset[str] = _coverage_labels(ALLOW_VERBS, ALLOW_NESTED)
COVERAGE_DENY: frozenset[str] = _coverage_labels(DENY_VERBS, DENY_NESTED)
FILE_DENY_VERBS: frozenset[str] = COVERAGE_DENY - {"_prompt-helper"}

_KA_BASENAMES = frozenset({"ka", "ka.exe", "key-amnesia", "key-amnesia.exe"})
_SHELL_BASENAMES = frozenset({"sh", "bash", "zsh", "dash", "busybox"})
_CHAIN_OPS = frozenset({"&&", "||", ";", "|", "|&", "&"})

_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.")


def _basename(token: str) -> str:
    t = token.replace("\\", "/").rstrip("/")
    if "/" in t:
        t = t.rsplit("/", 1)[-1]
    return t.lower()


def _is_ka_binary(token: str) -> bool:
    return _basename(token) in _KA_BASENAMES


def _is_python(token: str) -> bool:
    b = _basename(token)
    if b in {"py", "py.exe"}:
        return True
    return b.startswith("python")


def _is_shell(token: str) -> bool:
    return _basename(token) in _SHELL_BASENAMES


def _tokenize(text: str) -> list[str]:
    text = text.strip()
    if not text:
        return []
    # Backslashes are Windows path separators; POSIX shlex would eat them.
    posix = "\\" not in text
    try:
        return shlex.split(text, posix=posix, comments=False)
    except ValueError:
        try:
            return shlex.split(text, posix=not posix, comments=False)
        except ValueError:
            return text.split()


def _skip_env_prefix(tokens: list[str], i: int) -> int:
    if i < len(tokens) and _basename(tokens[i]) == "env":
        i += 1
        while i < len(tokens) and tokens[i].startswith("-") and tokens[i] not in _CHAIN_OPS:
            i += 1
    while i < len(tokens) and _ENV_ASSIGN.match(tokens[i]):
        i += 1
    return i


def _extract_shell_c_scripts(tokens: list[str]) -> list[str]:
    scripts: list[str] = []
    i = 0
    while i < len(tokens):
        if _is_shell(tokens[i]):
            j = i + 1
            saw_c = False
            while j < len(tokens) and tokens[j].startswith("-") and tokens[j] not in _CHAIN_OPS:
                flag = tokens[j]
                compact = flag.lstrip("-")
                if flag in ("-c", "-lc") or (
                    not flag.startswith("--") and "c" in compact
                ):
                    saw_c = True
                j += 1
            if saw_c and j < len(tokens) and not tokens[j].startswith("-"):
                scripts.append(tokens[j])
                i = j + 1
                continue
        i += 1
    return scripts


def _split_chain(tokens: list[str]) -> list[list[str]]:
    chunks: list[list[str]] = []
    cur: list[str] = []
    for tok in tokens:
        if tok in _CHAIN_OPS:
            if cur:
                chunks.append(cur)
                cur = []
            continue
        cur.append(tok)
    if cur:
        chunks.append(cur)
    return chunks


def iter_ka_argvs(text: str) -> Iterable[list[str]]:
    """Yield argv *after* the ka/key-amnesia launcher (subcommand + rest)."""
    tokens = _tokenize(text)
    if not tokens:
        return
    for script in _extract_shell_c_scripts(tokens):
        yield from iter_ka_argvs(script)
    for chunk in _split_chain(tokens):
        yield from _iter_ka_argvs_chunk(chunk)


def _iter_ka_argvs_chunk(tokens: list[str]) -> Iterable[list[str]]:
    i = _skip_env_prefix(tokens, 0)
    if i >= len(tokens):
        return
    if _basename(tokens[i]) == "uvx" and i + 1 < len(tokens):
        nxt = tokens[i + 1]
        if nxt in ("key-amnesia", "ka") or _is_ka_binary(nxt):
            yield tokens[i + 2 :]
            return
    if (
        _basename(tokens[i]) == "pipx"
        and i + 2 < len(tokens)
        and tokens[i + 1] == "run"
        and (tokens[i + 2] in ("key-amnesia", "ka") or _is_ka_binary(tokens[i + 2]))
    ):
        yield tokens[i + 3 :]
        return
    if _is_python(tokens[i]):
        j = i + 1
        while j < len(tokens) and tokens[j].startswith("-") and tokens[j] != "-m":
            j += 1
        if j + 1 < len(tokens) and tokens[j] == "-m":
            mod = tokens[j + 1].replace("-", "_")
            if mod == "key_amnesia":
                yield tokens[j + 2 :]
                return
    if _is_ka_binary(tokens[i]):
        yield tokens[i + 1 :]


def _first_verb(argv: list[str]) -> tuple[str, list[str]]:
    """Return the subcommand token and the remainder of argv.

    The ``i += 2`` path assumes a leading ``-flag`` takes a value. That is
    safe only because the top-level parser exposes no optional arguments
    other than ``--version`` / ``--help`` (see
    ``test_top_level_parser_only_version_help``). A new value-less global
    flag would consume the verb (``ka --quiet set FOO bar`` → verb ``FOO``)
    and fail open.
    """
    i = 0
    while i < len(argv) and argv[i].startswith("-") and argv[i] not in ("--",):
        if argv[i] in ("--version", "-V"):
            return "--version", argv[i + 1 :]
        if argv[i] in ("--help", "-h"):
            return "--help", argv[i + 1 :]
        if "=" not in argv[i] and i + 1 < len(argv) and not argv[i + 1].startswith("-"):
            i += 2
            continue
        i += 1
    if i >= len(argv):
        return "", []
    return argv[i], argv[i + 1 :]


def _argv_after_double_dash(argv: list[str]) -> list[str] | None:
    try:
        idx = argv.index("--")
    except ValueError:
        return None
    return argv[idx + 1 :]


def classify_ka_argv(argv: list[str]) -> str | None:
    """Return a deny kind, or None if this argv is not a denied ka invocation.

    Unrecognized verbs fail open (None). Nested ``ka run -- <cmd>`` is checked
    recursively on the trailing command.
    """
    verb, rest = _first_verb(argv)
    if verb in ("--version", "--help", ""):
        return None
    if verb == "scan":
        if any(a == "--yes" or a.startswith("--yes=") for a in rest):
            return "ka scan --yes"
        return None
    if verb == "run":
        trailing = _argv_after_double_dash(argv)
        if trailing:
            inner = ka_verb_deny_reason(" ".join(trailing))
            if inner:
                return f"ka run wrapping {inner}"
        return None
    if verb in DENY_VERBS:
        return f"ka {verb}"
    if verb in DENY_NESTED:
        nested, _ = _first_verb(rest)
        if nested in DENY_NESTED[verb]:
            return f"ka {verb} {nested}"
        return None
    return None


def ka_verb_deny_reason(text: str) -> str | None:
    """If text contains a denied key-amnesia invocation, return a short kind."""
    if not text:
        return None
    for argv in iter_ka_argvs(text):
        kind = classify_ka_argv(argv)
        if kind:
            return kind
    return None


def ka_run_trailing_texts(text: str) -> list[str]:
    """Shell text of commands after ``ka run … --`` (for secret scanning)."""
    out: list[str] = []
    for argv in iter_ka_argvs(text):
        verb, _ = _first_verb(argv)
        if verb != "run":
            continue
        trailing = _argv_after_double_dash(argv)
        if not trailing:
            continue
        joined = " ".join(trailing)
        out.append(joined)
        out.extend(ka_run_trailing_texts(joined))
    return out


def iter_non_ka_chain_texts(text: str) -> Iterable[str]:
    """Yield chain chunks that are not key-amnesia invocations.

    Sibling of ``ka run … -- python a.py && curl …`` is the ``curl`` chunk;
    the ``ka run`` prefix is not yielded (anti-nag on ``--secret`` / ``--as``).
    Recurses into ``sh -c`` / ``bash -lc`` scripts with the same splitter.
    """
    tokens = _tokenize(text)
    if not tokens:
        return
    for script in _extract_shell_c_scripts(tokens):
        yield from iter_non_ka_chain_texts(script)
    for chunk in _split_chain(tokens):
        if list(_iter_ka_argvs_chunk(chunk)):
            continue
        yield " ".join(chunk)


def deny_message(kind: str) -> str:
    """Tell the human the exact command to run in their own terminal.

    Nested kinds (``ka run wrapping ka scan --yes``) name the wrapper in the
    explanation; the runnable slot is the inner command only.
    """
    inner = kind
    wrapper = None
    marker = " wrapping "
    if marker in kind:
        wrapper, inner = kind.split(marker, 1)
    if wrapper:
        blocked = f"`{wrapper}` wrapping `{inner}`"
    else:
        blocked = f"`{inner}`"
    return (
        f"key-amnesia hook blocked {blocked} — agents must not run this. "
        f"In your own terminal, run: `{inner}` "
        "(do not paste the result back into chat). "
        "Agents may use `ka run` / `ka list` / `ka status` instead."
    )
