"""Exhaustive check: do the Rust Unicode predicates agree with Python?

Every code point, not a sample. A sampled comparison once passed over a
hand-written `isdigit` that was wrong on 806 code points; this one would not
have.

    cargo build --release -p vahta-detect --example dump_unicode
    .venv/bin/python benchmarks/diff_unicode.py

Checks `\\s`, `\\w`, `str.isdigit`, the upper/lower/digit class the entropy
and transition measures use, and `(?i)` folding against every ASCII letter,
digit, `_` and `-`. Exits non-zero on any disagreement.
"""

from __future__ import annotations

import collections
import re
import string
import subprocess
import sys
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DUMPER = REPO / "target" / "release" / "examples" / "dump_unicode"


def main() -> int:
    if not DUMPER.exists():
        print(f"missing {DUMPER}; build it first (see the docstring)", file=sys.stderr)
        return 2
    space, word = re.compile(r"\s"), re.compile(r"\w")
    fold = {L: re.compile("(?i)" + re.escape(L)) for L in string.ascii_lowercase + string.digits + "_-"}
    bad: dict[str, list[str]] = collections.defaultdict(list)
    n = 0
    text = subprocess.run([str(DUMPER)], check=True, capture_output=True, text=True).stdout
    for line in text.splitlines():
        n += 1
        h, flags, cls, folded = line.split()
        c = chr(int(h, 16))
        if (flags[0] == "1") != bool(space.match(c)):
            bad["\\s"].append(c)
        if (flags[1] == "1") != bool(word.match(c)):
            bad["\\w"].append(c)
        if (flags[2] == "1") != c.isdigit():
            bad["isdigit"].append(c)
        want = "U" if c.isupper() else "L" if c.islower() else "D" if c.isdigit() else "O"
        if cls != want:
            bad["char_class"].append(c)
        f = chr(int(folded, 16))
        if any((f == L) != bool(p.fullmatch(c)) for L, p in fold.items()):
            bad["(?i) fold"].append(c)
    print(f"{n} code points, Python {sys.version.split()[0]}, Unicode {unicodedata.unidata_version}")
    for name in ["\\s", "\\w", "isdigit", "char_class", "(?i) fold"]:
        cs = bad[name]
        sample = " ".join(f"U+{ord(c):04X}" for c in cs[:8])
        print(f"  {name:11} {len(cs):6} mismatches  {sample}")
    if n != 0x110000 - 0x800:
        print(f"expected {0x110000 - 0x800} scalar values, got {n}", file=sys.stderr)
        return 1
    return 1 if any(bad.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
