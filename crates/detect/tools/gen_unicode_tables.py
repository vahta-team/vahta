"""Generate `crates/detect/src/pyunicode.rs` from the running interpreter.

Every Unicode predicate the detector needs is read out of Python rather than
approximated with Rust's `char` methods, because the two disagree:

- `\\w` (`str.isalnum()` or `_`): `char::is_alphanumeric` also admits
  `Other_Alphabetic` combining marks and circled letters — about six
  thousand extra characters, each of which moves a `\\b`.
- `str.isdigit()`: `char::is_numeric` is all of `N*`; `to_digit(10)` is
  ASCII-only. Neither is Python's Numeric_Type in {Decimal, Digit}; an
  earlier hand-written rule was wrong on 806 code points.
- `str.isupper()` / `str.islower()`: agree with Rust except on code points
  a newer Unicode version assigned, and on a handful of `Ll` letters.

Generating the tables also pins them to one Unicode version, the
interpreter's, instead of whichever one rustc happens to ship.

Run from the repository root, and commit the output:

    .venv/bin/python crates/detect/tools/gen_unicode_tables.py
"""

from __future__ import annotations

import re
import sys
import unicodedata
from pathlib import Path
from typing import Callable

OUT = Path(__file__).resolve().parent.parent / "src" / "pyunicode.rs"

_WORD = re.compile(r"\w")

TABLES: list[tuple[str, str, Callable[[str], bool]]] = [
    ("WORD", "regex `\\w` on `str`", lambda c: bool(_WORD.match(c))),
    ("DIGIT", "`str.isdigit()`", str.isdigit),
    ("UPPER", "`str.isupper()`", str.isupper),
    ("LOWER", "`str.islower()`", str.islower),
]


def ranges(pred: Callable[[str], bool]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    start = None
    for c in range(0x80, 0x110001):
        ok = c < 0x110000 and pred(chr(c))
        if ok and start is None:
            start = c
        elif not ok and start is not None:
            out.append((start, c - 1))
            start = None
    return out


def main() -> None:
    lines = [
        "//! Python's Unicode predicates beyond ASCII. **Generated — do not edit.**",
        "//!",
        "//! Regenerate with `.venv/bin/python crates/detect/tools/gen_unicode_tables.py`.",
        f"//! Source: Python {sys.version.split()[0]}, Unicode {unicodedata.unidata_version}.",
        "//!",
        "//! Each table is inclusive, sorted, non-overlapping code-point ranges, for",
        "//! code points >= 0x80 only; ASCII is answered by the caller.",
        "",
    ]
    for name, what, pred in TABLES:
        rs = ranges(pred)
        lines.append(f"/// {what}, non-ASCII.")
        lines.append(f"pub(crate) static {name}: [(u32, u32); {len(rs)}] = [")
        lines += [f"    (0x{a:05X}, 0x{b:05X})," for a, b in rs]
        lines += ["];", ""]
        print(f"{name:6} {len(rs):4} ranges")
    lines += [
        "/// Membership in one of the tables above.",
        "#[inline]",
        "pub(crate) fn contains(table: &[(u32, u32)], c: char) -> bool {",
        "    let cp = c as u32;",
        "    table",
        "        .binary_search_by(|&(lo, hi)| {",
        "            if hi < cp {",
        "                std::cmp::Ordering::Less",
        "            } else if lo > cp {",
        "                std::cmp::Ordering::Greater",
        "            } else {",
        "                std::cmp::Ordering::Equal",
        "            }",
        "        })",
        "        .is_ok()",
        "}",
        "",
    ]
    OUT.write_text("\n".join(lines))
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
