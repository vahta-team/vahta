"""Shared secret-shape detector for the PreToolUse hook and ``ka scan``.

Tiers (not a score)::

    none      placeholder, too short, function-call, type-annotation
    possible  name matched; 0.4.9 mixed-class + Shannon gate; identifier
              or word-shaped passphrase
    likely    stricter value signals (transition floor / hex exception)
    prefix    vendor prefix (always high), or Bearer whose value is likely

Both consumers import this module. The hook denies on possible|likely|prefix.
``ka scan`` ``leak_count`` / default exit count likely + prefix + filename
hits only.

Two match shapes, both merged at ``scan_text_hits``:

    assignment  ``NAME=<value>`` / ``"api_key": "<value>"``  (``_iter_assignments``)
    flag        ``--api-key <value>`` / ``--token <value>``   (``_iter_flag_values``)

The flag form is a *separate* matcher on purpose. ``_iter_assignments`` must
stay finding-identical to the legacy ``ASSIGN`` regex (differential test), and
``ASSIGN`` itself is quadratic and must never run on scan/hook paths. See
``FLAG_FORM_FIRE_TIERS`` for the one constant that decides how loud the flag
form is.

Never returns or logs secret *values*.

Measured evidence (reconstructed shapes, not harvested content)
---------------------------------------------------------------
Against 0.4.9 ``_assignment_is_secret`` (length ≥ 8, ≥2 of upper/lower/digit,
Shannon ≥ 3.0):

Shannon (raw bits):
    GetTokenFromCache()            3.89
    hook fixture Zk9pL2xQ7mN4vB8w  4.17
    hex-32                         3.81
Hex sits *inside* the identifier band. Shannon ≥ 3.0 cannot split identifiers
from random tokens; it remains the *possible* gate (``SHANNON_POSSIBLE_FLOOR``),
not the likely-floor.

Normalized entropy (H / log2(|alphabet|)):
    identifiers     0.95–1.00
    random strings  0.94–1.00
Completely overlapping. Not adopted.

Character-class transition rate (adjacent pairs that change class among
{upper, lower, digit, other}):
    identifiers         0.18–0.45  (mostly camelCase boundaries)
    random fixtures     1.00
    JWT-shaped          0.71
    hex-32              0.42
``LIKELY_TRANSITION_FLOOR = 0.50`` is the lowest floor that excludes the
entire measured identifier band (ceiling 0.45) while still admitting
JWT-shaped (0.71) and random fixtures (1.00). 0.60 would still pass those
positives but sits farther from the identifier ceiling without additional
evidence. Hex-32 at 0.42 is *below* 0.50, which is why ``HEX_LIKELY`` is an
explicit exception rather than a reason to lower the floor: hex does not
alternate classes the way base62 does.

Length ≥ 20 as a likely-floor: rejected — the 16-char hook fixture
``Zk9pL2xQ7mN4vB8w`` must remain likely.

English-segment demotion: ≥2 vowel-bearing CamelCase/Pascal segments and
*no digits* → possible. Must not apply when digits are present (JWT
``eyJhbGciOi…`` would otherwise demote via ``Gci`` / ``Ikp``).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Literal

Confidence = Literal["none", "possible", "likely"]

# UUID / stripped-hex promotion (hyphenated 8-4-4-4-12 or 32 hex).
REASON_UUID = "uuid"
_UUID_SHAPE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_STRIPPED_UUID_LEN = 32

# --- length / possible-gate (0.4.9 assignment heuristic) -------------------
# Inherited as the *possible* gate, not the likely-floor. Shannon 3.0 is why
# identifiers over-block today; likely uses transition rate instead.
MIN_VALUE_LEN = 8
SHANNON_POSSIBLE_FLOOR = 3.0  # GetTokenFromCache() 3.89; fixture 4.17; hex-32 3.81

# --- likely-floor ----------------------------------------------------------
# Identifiers 0.18–0.45; JWT-shaped 0.71; random fixtures 1.00; hex-32 0.42.
# 0.50 is the lowest floor that excludes the measured identifier band.
LIKELY_TRANSITION_FLOOR = 0.50

# Hex-32 transition 0.42 is below LIKELY_TRANSITION_FLOOR, so hex is an
# explicit likely exception rather than a lowered floor.
HEX_LIKELY_MIN_LEN = 16
_HEX_LIKELY = re.compile(rf"[0-9a-fA-F]{{{HEX_LIKELY_MIN_LEN},}}$")

# Word-shaped passphrase / identifier demotion: ≥2 vowel-bearing segments
# and no digits → possible, not likely (named weakening 3).
MIN_VOWEL_SEGMENTS_FOR_POSSIBLE = 2

# Named weakenings. Hook recall drops only function-call and type-annotation
# (→ none). Identifier, passphrase, and low-transition stay possible so the
# hook still denies; scan leak_count omits them.
NAMED_WEAKENING_FUNCTION_CALL = "function-call"
NAMED_WEAKENING_TYPE_ANNOTATION = "type-annotation"
NAMED_WEAKENING_WORD_SHAPED_PASSPHRASE = "word-shaped-passphrase"
NAMED_WEAKENING_IDENTIFIER = "identifier"
NAMED_WEAKENING_LOW_TRANSITION = "low-transition"
NAMED_WEAKENINGS: tuple[str, ...] = (
    NAMED_WEAKENING_FUNCTION_CALL,
    NAMED_WEAKENING_TYPE_ANNOTATION,
    NAMED_WEAKENING_WORD_SHAPED_PASSPHRASE,
    NAMED_WEAKENING_IDENTIFIER,
    NAMED_WEAKENING_LOW_TRANSITION,
)

# Filename demotion (scan only): mcp.json without a recognised top-level key.
REASON_UNCONFIRMED_MCP = "unconfirmed-mcp-shape"

# Well-known API key / token prefixes (value starts immediately after).
# Anthropic-style checked before the more general OpenAI-style pattern so the
# reported "kind" is the more specific one.
PREFIX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Anthropic-style key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("GitHub PAT", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("GitLab PAT", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")),
    ("Stripe secret key", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    ("Stripe restricted key", re.compile(r"\brk_live_[A-Za-z0-9]{20,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b")),
]

BEARER = re.compile(r"\bBearer\s+([A-Za-z0-9._\-+=/]{16,})", re.IGNORECASE)

# ENV-style / JSON / YAML / TOML assignments. Optional dotted prefix
# (secrets.api_key) is not part of the captured name. Optional matching
# quotes around the name so `"api_key": "…"` matches.
#
# Kept for the 0.4.11 differential test. Production matching uses
# ``_iter_assignments`` (literal-anchored, linear). Do not call ASSIGN
# from scan/hook paths — it is quadratic on long identifier runs.
ASSIGN = re.compile(
    r"""(?ix)
    (?:[A-Za-z_][A-Za-z0-9_]*\.)*
    (?P<nq>['"]?)
    (?P<name>(?:[a-z0-9]+[_-])*(?:api[_-]?key|token|secret|password|passwd|private[_-]?key))
    (?P=nq)
    \s*[:=]\s*
    (?P<q>['"]?)
    (?P<value>[^\s'"]{8,})
    (?P=q)
    """
)

# ASCII only. str.isalnum() is Unicode-aware: accented Latin, Cyrillic and
# CJK all answer True, so using it here would capture names the old
# [a-z0-9] class never did.
_NAME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)
# Bound the leftward walk, or a long alphanumeric run before each keyword
# reintroduces the quadratic behaviour this rewrite exists to remove.
_MAX_NAME_PREFIX = 256

_ASSIGN_KEYWORD = re.compile(
    r"(?i)(?:api[_-]?key|token|secret|password|passwd|private[_-]?key)"
)
_ASSIGN_TAIL = re.compile(
    r"""(?P<nq2>['"]?)\s*[:=]\s*(?P<q>['"]?)(?P<value>[^\s'"]{8,})(?P<q2>['"]?)"""
)

# --- space-separated flag form: `--api-key <value>` ------------------------
# ``_ASSIGN_TAIL`` requires ``\s*[:=]\s*``, so through 0.4.15 the detector was
# assignment-shaped: ``--api-key=<value>`` was caught and ``--api-key <value>``
# was caught nowhere. A credential on argv is the exact leak this product
# exists to prevent, so the flag form gets its own anchored matcher, merged at
# the ``scan_text_hits`` level. It is deliberately NOT folded into
# ``_iter_assignments``, which must remain finding-identical to ``ASSIGN``.
REASON_FLAG_FORM = "flag-form"

# THE ONE LINE TO FLIP. ("likely",) fires only on strong value signals
# (transition floor / hex / UUID). ("likely", "possible") additionally fires on
# word-shaped and low-transition values — which is where most real
# `--password <value>` leaks land, e.g. a passphrase-style DB password whose
# transition rate sits at 0.25, far below LIKELY_TRANSITION_FLOOR.
FLAG_FORM_FIRE_TIERS: tuple[Confidence, ...] = ("likely", "possible")

# Flat name class on purpose: a nested `(?:[-_][A-Za-z0-9]+)*` backtracks
# catastrophically on long underscore runs. The name vocabulary is enforced
# afterwards by ``_SECRET_NAME``, exactly as the assignment form does.
#
# The value class is what keeps the recommended usage quiet. It excludes:
#   $ ` ( )   -> `--token "$GITHUB_TOKEN"`, `--api-key $(pass show x)`
#   < > | & ; -> `gh auth login --with-token < token.txt`, `--api-key <KEY>`
#   = , quote -> `--secret id=app,src=./f` (the assignment form's job)
#   leading - -> `mysql --password --host=db` (the next flag, not a value)
_FLAG_FORM = re.compile(
    r"""(?x)
    (?<![\w./=-])
    --?(?P<name>[A-Za-z][A-Za-z0-9_-]*)
    [ \t]+
    (?P<q>['"]?)
    (?P<value>[^\s'"`;|&<>()$=\\-][^\s'"`;|&<>()$=\\]{7,})
    (?P=q)
    """
)

# `ka run --secret GOOGLE_API_KEY` / `--password PGPASSWORD` name an env var.
# That is indirection, not a value — the whole point of the product.
_ENV_NAME_VALUE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
# `--token ./token.txt` / `--api-key /run/secrets/db` point at a file.
_PATH_VALUE = re.compile(r"^(?:\.{1,2}/|/|~/|[A-Za-z]:[\\/])")

# One-pass gate: any vendor prefix. Kind is still chosen by PREFIX_PATTERNS
# order (not leftmost match) so reported secret_names stay stable.
_ANY_PREFIX = re.compile("|".join(p.pattern for _kind, p in PREFIX_PATTERNS))

_SECRET_NAME = re.compile(
    r"(?ix)^(?:[a-z0-9]+[_-])*(?:api[_-]?key|token|secret|password|passwd|private[_-]?key)$"
)

_PLACEHOLDER_VALUES = {
    "test123",
    "test1234",
    "changeme",
    "change_me",
    "changethis",
    "password",
    "password123",
    "secret",
    "yourkey",
    "your_api_key",
    "your-api-key",
    "placeholder",
    "example",
    "dummy",
    "fake",
    "sample",
    "xxxxxxxx",
    "12345678",
}

# ident(...) / dotted.attr(...) — named weakening 1 → none
_FUNC_CALL = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\(.*\)$"
)

# Name[...] — named weakening 2 → none
_TYPE_ANN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\[.+\]$")

_VOWELS = set("aeiouAEIOU")
_CAMEL_SEGS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")


@dataclass
class HitSet:
    """Assignment/prefix hits for a text blob. Never carries values."""

    likely_names: list[str] = field(default_factory=list)
    possible_names: list[str] = field(default_factory=list)
    prefix: str | None = None
    bearer_likely: bool = False
    bearer_possible: bool = False
    likely_reasons: list[str] = field(default_factory=list)
    possible_reasons: list[str] = field(default_factory=list)
    likely_reason_counts: dict[str, int] = field(default_factory=dict)
    possible_reason_counts: dict[str, int] = field(default_factory=dict)
    # Upper-cased names that were matched as `--flag <value>` rather than
    # `name=<value>`. Phrasing only — the hit itself lives in the name dicts
    # so scan/hook reporting needs no change.
    flag_names: list[str] = field(default_factory=list)
    # upper(name) -> (original_name, reasons). Source of truth for merge.
    _likely_by_name: dict[str, tuple[str, list[str]]] = field(default_factory=dict)
    _possible_by_name: dict[str, tuple[str, list[str]]] = field(default_factory=dict)

    def _rebuild(self) -> None:
        self.likely_names = [pair[0] for pair in self._likely_by_name.values()]
        self.possible_names = [pair[0] for pair in self._possible_by_name.values()]
        self.likely_reasons = []
        self.likely_reason_counts = {}
        for _name, reasons in self._likely_by_name.values():
            for reason in reasons:
                if not reason:
                    continue
                if reason not in self.likely_reasons:
                    self.likely_reasons.append(reason)
                self.likely_reason_counts[reason] = (
                    self.likely_reason_counts.get(reason, 0) + 1
                )
        self.possible_reasons = []
        self.possible_reason_counts = {}
        for _name, reasons in self._possible_by_name.values():
            for reason in reasons:
                if not reason:
                    continue
                if reason not in self.possible_reasons:
                    self.possible_reasons.append(reason)
                self.possible_reason_counts[reason] = (
                    self.possible_reason_counts.get(reason, 0) + 1
                )

    def record_assignment(self, name: str, tier: str, reasons: list[str]) -> None:
        """Highest-wins per name. Does not record values."""
        key = name.upper()
        if tier == "likely":
            if key in self._likely_by_name:
                return
            self._possible_by_name.pop(key, None)
            self._likely_by_name[key] = (name, list(reasons))
        elif tier == "possible":
            if key in self._likely_by_name or key in self._possible_by_name:
                return
            self._possible_by_name[key] = (name, list(reasons))
        else:
            return
        self._rebuild()

    def merge(self, extra: HitSet) -> None:
        for key, pair in extra._likely_by_name.items():
            if key in self._likely_by_name:
                continue
            self._possible_by_name.pop(key, None)
            self._likely_by_name[key] = (pair[0], list(pair[1]))
        for key, pair in extra._possible_by_name.items():
            if key in self._likely_by_name or key in self._possible_by_name:
                continue
            self._possible_by_name[key] = (pair[0], list(pair[1]))
        if extra.prefix and self.prefix is None:
            self.prefix = extra.prefix
        if extra.bearer_likely:
            self.bearer_likely = True
        if extra.bearer_possible:
            self.bearer_possible = True
        for key in extra.flag_names:
            if key not in self.flag_names:
                self.flag_names.append(key)
        self._rebuild()


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_placeholder(value: str) -> bool:
    v = value.strip("'\"").lower()
    if v in _PLACEHOLDER_VALUES:
        return True
    if re.fullmatch(r"x{6,}", v):
        return True
    if re.fullmatch(r"0{6,}|1{6,}", v):
        return True
    return False


def is_secret_name(name: str) -> bool:
    """True if a dict/JSON key matches the assignment name vocabulary."""
    return bool(_SECRET_NAME.fullmatch(name.strip().strip("'\"")))


def _char_class(c: str) -> str:
    if c.isupper():
        return "U"
    if c.islower():
        return "L"
    if c.isdigit():
        return "D"
    return "O"


def transition_rate(s: str) -> float:
    """Fraction of adjacent pairs that change character class.

    Identifiers 0.18–0.45; random fixtures 1.00; JWT-shaped 0.71; hex-32 0.42.
    """
    if len(s) < 2:
        return 0.0
    changes = sum(
        1 for a, b in zip(s, s[1:]) if _char_class(a) != _char_class(b)
    )
    return changes / (len(s) - 1)


def _word_segments(value: str) -> list[str]:
    parts = re.split(r"[^A-Za-z0-9]+", value)
    segs: list[str] = []
    for part in parts:
        if not part:
            continue
        found = _CAMEL_SEGS.findall(part)
        segs.extend(found if found else [part])
    return segs


def _has_vowel(seg: str) -> bool:
    return any(c in _VOWELS or c in "yY" for c in seg)


def _vowel_bearing_segments(value: str) -> int:
    return sum(1 for seg in _word_segments(value) if _has_vowel(seg))


def _compact_hex(value: str) -> str:
    return value.replace("-", "")


def _is_nil_or_all_zero(value: str) -> bool:
    compact = _compact_hex(value)
    return bool(compact) and all(c == "0" for c in compact)


def _uuid_or_stripped_hex(value: str) -> bool:
    """Hyphenated UUID or 32-char hex (stripped UUID). Nil already excluded."""
    if _UUID_SHAPE.fullmatch(value):
        return True
    compact = _compact_hex(value)
    return len(compact) == _STRIPPED_UUID_LEN and bool(_HEX_LIKELY.fullmatch(compact))


def classify_value(value: str) -> tuple[Confidence, str | None]:
    """Classify a captured assignment/Bearer *value* (never logged).

    Returns ``(tier, reason)``. ``reason`` is a named weakening, ``uuid``,
    or None. Never returns the value.
    """
    v = value.strip("'\"")
    if len(v) < MIN_VALUE_LEN:
        return "none", None
    if is_placeholder(v) or _is_nil_or_all_zero(v):
        return "none", None
    if _FUNC_CALL.fullmatch(v):
        return "none", NAMED_WEAKENING_FUNCTION_CALL
    if _TYPE_ANN.fullmatch(v):
        return "none", NAMED_WEAKENING_TYPE_ANNOTATION

    # UUID-shaped / stripped-hex-32: likely even when hyphens make
    # transition_rate sit below LIKELY_TRANSITION_FLOOR (~0.43).
    if _uuid_or_stripped_hex(v):
        return "likely", REASON_UUID

    has_upper = any(c.isupper() for c in v)
    has_lower = any(c.islower() for c in v)
    has_digit = any(c.isdigit() for c in v)
    mixed = sum([has_upper, has_lower, has_digit]) >= 2
    if not mixed:
        return "none", None
    if entropy(v) < SHANNON_POSSIBLE_FLOOR:
        return "none", None

    # Word-shaped / identifier, no digits → possible (hook still denies).
    if not has_digit and _vowel_bearing_segments(v) >= MIN_VOWEL_SEGMENTS_FOR_POSSIBLE:
        if v[:1].isupper():
            return "possible", NAMED_WEAKENING_WORD_SHAPED_PASSPHRASE
        return "possible", NAMED_WEAKENING_IDENTIFIER

    compact = _compact_hex(v)
    if _HEX_LIKELY.fullmatch(compact):
        return "likely", None

    if transition_rate(v) >= LIKELY_TRANSITION_FLOOR:
        return "likely", None
    return "possible", NAMED_WEAKENING_LOW_TRANSITION


def assignment_is_secret(value: str) -> bool:
    """0.4.9 hook meaning: possible or likely (not none)."""
    return classify_value(value)[0] in ("possible", "likely")


def find_prefix_kind(text: str) -> str | None:
    if not text or not _ANY_PREFIX.search(text):
        return None
    for kind, pattern in PREFIX_PATTERNS:
        if pattern.search(text):
            return kind
    return None


def classify_bearer_capture(text: str) -> Confidence:
    match = BEARER.search(text)
    if not match:
        return "none"
    return classify_value(match.group(1))[0]


def _name_kind(name: str, hits: HitSet) -> str:
    """Phrase a name hit. Flag-form hits say so, so the deny message is actionable."""
    if name.upper() in hits.flag_names:
        return f"--{name} flag value"
    return f"{name.upper()} assignment"


def find_secret_kind(text: str) -> str | None:
    """Human-readable kind if possible|likely|prefix, else None. No values.

    Order: vendor prefix, then likely (incl. Bearer-likely), then possible.
    """
    hits = scan_text_hits(text)
    if hits.prefix:
        return hits.prefix
    if hits.bearer_likely:
        return "Bearer token"
    if hits.likely_names:
        return _name_kind(hits.likely_names[0], hits)
    if hits.bearer_possible:
        return "Bearer token"
    if hits.possible_names:
        return _name_kind(hits.possible_names[0], hits)
    return None


def _iter_assignments(text: str) -> Iterator[tuple[str, str]]:
    """Yield (name, value) pairs equivalent to ASSIGN, in linear time.

    Never logs or returns values to callers outside scan_text_hits.
    """
    if not text:
        return
    for kw in _ASSIGN_KEYWORD.finditer(text):
        i = kw.start()
        floor = max(0, i - _MAX_NAME_PREFIX)
        while i > floor and text[i - 1] in "_-":
            j = i - 1
            while j > floor and text[j - 1] in _NAME_CHARS:
                j -= 1
            if j == i - 1:
                break
            i = j
        tail = _ASSIGN_TAIL.match(text, kw.end())
        if tail is None:
            continue
        # Old ASSIGN's (?P=nq) only pairs quotes that are *in the match*.
        # A quote immediately before the name is often JSON wrapping
        # (`"token = …"`), not a quoted key. Require an opener only when
        # the tail itself captured a post-name quote (`"api_key":`).
        nq2 = tail.group("nq2") or ""
        if nq2 and (i == 0 or text[i - 1] != nq2):
            continue
        # Value quotes: old ASSIGN requires a closer only when the opener
        # was captured. An unquoted value may be followed by a JSON `"`.
        q = tail.group("q") or ""
        q2 = tail.group("q2") or ""
        if q and q2 != q:
            continue
        yield text[i : kw.end()], tail.group("value")


def _iter_flag_values(text: str) -> Iterator[tuple[str, str]]:
    """Yield (flag_name, value) for space-separated `--api-key <value>` forms.

    Separate from ``_iter_assignments`` by design (see module docstring).
    Never logs or returns values to callers outside ``scan_text_hits``.
    """
    if not text or "-" not in text:
        return
    for match in _FLAG_FORM.finditer(text):
        name = match.group("name")
        if not _SECRET_NAME.fullmatch(name):
            continue
        value = match.group("value")
        if _ENV_NAME_VALUE.fullmatch(value) or _PATH_VALUE.match(value):
            continue
        yield name, value


def collect_strings(obj: Any) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from collect_strings(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from collect_strings(item)


def iter_secret_keyed_strings(obj: Any) -> Iterator[tuple[str, str]]:
    """Yield (key, string_value) where key matches the secret-name vocabulary."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and is_secret_name(k) and isinstance(v, str):
                yield k, v
            yield from iter_secret_keyed_strings(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_secret_keyed_strings(item)


def _merge_chosen(
    chosen: dict[str, tuple[str, str, list[str]]],
    name: str,
    tier: str,
    reasons: list[str],
) -> None:
    """Highest tier wins per name; reasons accumulate within a tier. No values."""
    key = name.upper()
    prev = chosen.get(key)
    if prev is None:
        chosen[key] = (tier, name, list(reasons))
        return
    prev_tier, _prev_name, prev_reasons = prev
    if prev_tier == "possible" and tier == "likely":
        chosen[key] = (tier, name, list(reasons))
    elif prev_tier == tier:
        for reason in reasons:
            if reason and reason not in prev_reasons:
                prev_reasons.append(reason)


def scan_text_hits(text: str) -> HitSet:
    """Assignment + flag-form names (likely, possible), vendor prefix, Bearer.

    Highest tier wins per name: classify every assignment and every
    space-separated `--flag <value>`, keep likely over possible. Vendor prefix is ``certain``. Bearer whose value is likely is
    ``bearer_likely`` (scan ``likely``). Bearer of an identifier sets
    ``bearer_possible``. Never returns values.
    """
    hits = HitSet()
    if not text:
        return hits

    hits.prefix = find_prefix_kind(text)
    bearer_tier = classify_bearer_capture(text)
    if hits.prefix is None:
        if bearer_tier == "likely":
            hits.bearer_likely = True
        elif bearer_tier == "possible":
            hits.bearer_possible = True

    # key -> (tier, original_name, reasons)
    chosen: dict[str, tuple[str, str, list[str]]] = {}
    for name, value in _iter_assignments(text):
        tier, reason = classify_value(value)
        if tier not in ("likely", "possible"):
            continue
        _merge_chosen(chosen, name, tier, [reason] if reason else [])

    # Space-separated flag form, merged here rather than inside
    # _iter_assignments so the ASSIGN differential stays intact.
    for name, value in _iter_flag_values(text):
        tier, reason = classify_value(value)
        if tier not in FLAG_FORM_FIRE_TIERS:
            continue
        key = name.upper()
        if key not in hits.flag_names:
            hits.flag_names.append(key)
        reasons = [REASON_FLAG_FORM]
        if reason:
            reasons.append(reason)
        _merge_chosen(chosen, name, tier, reasons)

    for tier, name, reasons in chosen.values():
        hits.record_assignment(name, tier, reasons)

    return hits


def looks_like_json_container(s: str) -> bool:
    t = s.lstrip()
    return t.startswith("{") or t.startswith("[")
