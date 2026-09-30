"""Differential check: do the Python and Rust primitives agree?

Hand-written unit tests only prove what someone thought to test. This runs
both implementations over a generated spread of inputs and diffs the output
byte for byte, so disagreements are found rather than anticipated.

    cargo build -p vahta-detect --example dump_primitives
    .venv/bin/python benchmarks/diff_primitives.py

Inputs are generated, never committed as literals, so nothing
credential-shaped ends up in the repository.
"""

from __future__ import annotations

import random
import string
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DUMPER = REPO / "target" / "debug" / "examples" / "dump_primitives"

from key_amnesia.detect_py import (  # noqa: E402
    _vowel_bearing_segments,
    _word_segments,
    classify_value,
    entropy,
    transition_rate,
)


def _escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")


def generate(seed: int = 20260930) -> list[str]:
    rng = random.Random(seed)
    cases: list[str] = [
        "",
        "a",
        "A",
        "AB",
        "ABc",
        "ABCdef",
        "abcDEF",
        "HTTPServer",
        "XMLHttpRequest",
        "summerVineyard",
        "getToken2Cache",
        "correct-horse-battery",
        "A1b2",
        "___",
        "----",
        "Я",
        "ЯблокоTest",
        "½½½",
        "²³¹",
        "٣٤٥",
        "１２３",
        "ΑΒΓδεζ",
        "🔑🔒",
        "a\tb",
        " leading and trailing ",
        "x" * 64,
        "0" * 32,
    ]

    alphabets = [
        string.ascii_letters + string.digits,
        string.ascii_lowercase,
        string.ascii_uppercase + string.digits,
        "0123456789abcdef",
        string.ascii_letters + string.digits + "-_.+/=",
        string.printable.strip(),
        "аеиоуАЕИОУбвгд½²٣１",
        string.ascii_letters + "ЯяΑα½²🔑",
    ]
    for _ in range(4000):
        alpha = rng.choice(alphabets)
        n = rng.randint(0, 48)
        cases.append("".join(rng.choice(alpha) for _ in range(n)))

    # Random strings never produce a call expression or a subscripted type, so
    # the two named weakenings that return `none` *with* a reason would go
    # unexercised and the differential would silently cover four outcomes out
    # of six. Synthesised here, including the near-misses that must NOT match.
    idents = ["GetTokenFromCache", "os.environ.get", "load", "a.b.c.d", "_private"]
    args = ["", "x", "'k'", "a, b", "nested(call())", "line\nbreak"]
    for ident in idents:
        for arg in args:
            cases.append(f"{ident}({arg})")
            cases.append(f"{ident}({arg}) ")
            cases.append(f"({arg})")
            cases.append(f"{ident}({arg}")
    for base in ["Optional", "dict", "List", "_T"]:
        for inner in ["SecretStr", "str, int", "", "x\ny"]:
            cases.append(f"{base}[{inner}]")
            cases.append(f"{base}[{inner}")
            cases.append(f"[{inner}]")
    return cases


def python_row(escaped: str, value: str) -> str:
    tier, reason = classify_value(value)
    return "\t".join(
        (
            escaped,
            repr(entropy(value)),
            repr(transition_rate(value)),
            str(_vowel_bearing_segments(value)),
            repr(_word_segments(value)),
            tier,
            reason if reason is not None else "-",
        )
    )


def normalise_rust(row: str) -> str:
    """Rust prints `["a", "b"]` for a segment list; Python prints `['a', 'b']`.

    Only the segments column is rewritten, so a stray quote in any other
    column still shows up as a mismatch instead of being normalised away.
    """
    cols = row.split("\t")
    cols[4] = cols[4].replace('"', "'")
    return "\t".join(cols)


def main() -> int:
    if not DUMPER.exists():
        print(f"missing {DUMPER}; run: cargo build -p vahta-detect --example dump_primitives")
        return 2

    cases = generate()
    escaped = [_escape(c) for c in cases]
    proc = subprocess.run(
        [str(DUMPER)],
        input="\n".join(escaped).encode(),
        capture_output=True,
        check=True,
    )
    rust_rows = proc.stdout.decode().splitlines()

    if len(rust_rows) != len(cases):
        print(f"row count mismatch: rust {len(rust_rows)} vs python {len(cases)}")
        return 1

    mismatches = 0
    for case, esc, rust in zip(cases, escaped, rust_rows):
        want = python_row(esc, case)
        got = normalise_rust(rust)
        if want != got:
            mismatches += 1
            if mismatches <= 15:
                print(f"case {esc!r}")
                print(f"  python: {want}")
                print(f"  rust  : {got}")

    print()
    print(f"{len(cases)} cases, {mismatches} mismatches")
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
