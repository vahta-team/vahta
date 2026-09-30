"""Differential check for the whole detector: scan_text_hits and find_secret_kind.

The primitives differ only in arithmetic; this one differs in *findings*, which
is what the hook acts on. Inputs are shaped like the things the detector
actually sees — command lines, JSON and YAML fragments, dotenv lines, prose —
rather than random strings, because a matcher that never sees a `--flag value`
is not being tested.

    cargo build -p vahta-detect --example dump_hits
    .venv/bin/python benchmarks/diff_hits.py

Every credential-shaped value is generated, never a literal in this file.
"""

from __future__ import annotations

import random
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DUMPER = REPO / "target" / "debug" / "examples" / "dump_hits"

from key_amnesia.detect_py import find_secret_kind, scan_text_hits  # noqa: E402

NAMES = [
    "API_KEY",
    "api_key",
    "apikey",
    "TOKEN",
    "token",
    "secret",
    "DB_PASSWORD",
    "passwd",
    "my_private_key",
    "PRIVATE-KEY",
    "Api-Key",
    "keystore",
    "tokenizer",
    "host",
]

FLAGS = [
    "--password",
    "--api-key",
    "--token",
    "--secret",
    "--private-key",
    "--vault-password",
    "-token",
    "--host",
    "--with-token",
    "--password-stdin",
]

SEPARATORS = ["=", ": ", " = ", ":", '": "', "' = '"]


def _values(rng: random.Random) -> list[str]:
    """Value shapes, built rather than written down."""
    hexchars = "0123456789abcdef"
    b62 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    out = [
        "".join(rng.choice(b62) for _ in range(rng.randint(8, 40))),
        "".join(rng.choice(hexchars) for _ in range(32)),
        "-".join(
            "".join(rng.choice(hexchars) for _ in range(n)) for n in (8, 4, 4, 4, 12)
        ),
        "correct-horse-battery",
        "hunter7-correct-horse",
        "GetTokenFromCache()",
        "Optional[SecretStr]",
        "$GITHUB_TOKEN",
        "GOOGLE_API_KEY",
        "./token.txt",
        "/run/secrets/db",
        "changeme",
        "x" * 12,
        "short",
        "summerVineyard",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    ]
    # Vendor prefixes, constructed the way the corpus README describes so that
    # nothing here trips a secret scanner on push.
    for lit in (
        "sk-ant-",
        "sk-",
        "AKIA",
        "github_pat_",
        "ghp_",
        "glpat-",
        "xoxb-",
        "AIza",
        "sk_live_",
        "rk_live_",
        "npm_",
    ):
        out.append(lit + "a" * 24)
        out.append(lit + "0" * 24)
        out.append(lit + "a" * 8)  # too short: must not fire
    return out


def generate(seed: int = 20260930) -> list[str]:
    rng = random.Random(seed)
    values = _values(rng)
    cases: list[str] = [
        "",
        "nothing to see here",
        "# a comment about api_key handling",
        "ka run --secret GOOGLE_API_KEY -- ./deploy.sh",
        "gh auth login --with-token < token.txt",
        "docker login registry.example.com -u ci --password-stdin",
        "docker buildx build --secret id=app,src=./secrets/app.env .",
        "aws secretsmanager get-secret-value --secret-name prod/db/password",
    ]

    for name in NAMES:
        for sep in SEPARATORS:
            for value in values:
                cases.append(f"{name}{sep}{value}")
                cases.append(f'{{"{name}"{sep}"{value}"}}')
                cases.append(f"export {name}{sep}{value}")

    for flag in FLAGS:
        for value in values:
            cases.append(f"cli {flag} {value} --other x")
            cases.append(f'cli {flag} "{value}"')
            cases.append(f"cli {flag}={value}")
            cases.append(f"url=https://example.com/a{flag} {value}")

    for value in values:
        cases.append(f"curl -H 'Authorization: Bearer {value}' https://api.example.com")
        cases.append(f"Bearer {value}")
        cases.append(f"bearer  {value}")

    rng.shuffle(cases)
    return cases


def _escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")


def _list(items) -> str:
    return "[" + ",".join(items) + "]"


def python_row(escaped: str, value: str) -> str:
    h = scan_text_hits(value)
    return "\t".join(
        (
            escaped,
            _list(h.likely_names),
            _list(h.possible_names),
            h.prefix if h.prefix else "-",
            "true" if h.bearer_likely else "false",
            "true" if h.bearer_possible else "false",
            _list(h.likely_reasons),
            _list(h.possible_reasons),
            _list(h.flag_names),
            find_secret_kind(value) or "-",
        )
    )


def main() -> int:
    if not DUMPER.exists():
        print(f"missing {DUMPER}; run: cargo build -p vahta-detect --example dump_hits")
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
    for case, esc, got in zip(cases, escaped, rust_rows):
        want = python_row(esc, case)
        if want != got:
            mismatches += 1
            if mismatches <= 12:
                print(f"case {esc!r}")
                print(f"  python: {want}")
                print(f"  rust  : {got}")

    print()
    print(f"{len(cases)} cases, {mismatches} mismatches")
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
