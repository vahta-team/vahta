"""Differential check for filename classification.

The Rust port reproduces `pathlib` semantics by hand, and pathlib has corners
- a leading-dot name has no suffix, a trailing dot does - that are easy to get
subtly wrong and impossible to notice without comparing.
"""

from __future__ import annotations

import itertools
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DUMPER = REPO / "target" / "debug" / "examples" / "dump_filenames"

from key_amnesia.scan import _CONTENT_SCAN_SUFFIXES, _filename_kind  # noqa: E402

STEMS = [
    "a", "main", "Dockerfile", "Makefile", "Jenkinsfile", "credentials",
    "id_rsa", "id_ed25519", "mcp", "claude_desktop_config", "my", "x",
    ".env", ".npmrc", ".pypirc", ".gitconfig", ".git-credentials",
    ".bash_history", ".zsh_history", ".lesshst", "settings",
]
SUFFIXES = [
    "", ".py", ".PY", ".json", ".local", ".production", ".imported",
    ".tar.gz", ".", ".md", ".png", "_history", ".env",
]
DIRS = ["", "/proj", "/proj/sub", "/a/b/c"]


def generate() -> list[str]:
    out = []
    for d, stem, suf in itertools.product(DIRS, STEMS, SUFFIXES):
        out.append(f"{d}/{stem}{suf}" if d else f"{stem}{suf}")
    return out


def main() -> int:
    if not DUMPER.exists():
        print(f"missing {DUMPER}; run: cargo build -p vahta-scan --example dump_filenames")
        return 2
    cases = generate()
    proc = subprocess.run(
        [str(DUMPER)], input="\n".join(cases).encode(), capture_output=True, check=True
    )
    rust_rows = proc.stdout.decode().splitlines()
    mismatches = 0
    for case, got in zip(cases, rust_rows):
        p = Path(case)
        want = "\t".join(
            (
                case,
                p.suffix,
                _filename_kind(p) or "-",
                "true" if p.suffix.lower() in _CONTENT_SCAN_SUFFIXES
                or p.name in {"Dockerfile", "Makefile", "Jenkinsfile"} else "false",
            )
        )
        if want != got:
            mismatches += 1
            if mismatches <= 12:
                print(f"  python: {want}")
                print(f"  rust  : {got}")
    print(f"\n{len(cases)} cases, {mismatches} mismatches")
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
