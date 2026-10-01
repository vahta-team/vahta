"""Byte-for-byte check of `vahta scan --deep` against `ka scan --deep --no-import`.

Builds fake HOME trees in a temporary directory (the generators are
`diff_transcripts.py`'s) and runs both programs against each: the Python one
in-process through `key_amnesia.cli.main`, the Rust one as the real `vahta`
binary. `HOME` and `APPDATA` are set for both; the real home directory is never
read. Compares stdout byte for byte, the exit code, and stderr — where progress
lines name each transcript in discovery order, so it also pins the traversal.

    cargo build --release -p vahta-cli -p vahta-pyext-scan
    cp target/release/lib_scan_rs.so src/key_amnesia/_scan_rs.so   # for the generators
    .venv/bin/python benchmarks/diff_cli_deep.py [--seed N] [--scale K]

Where Python raises (hostile transcript nesting, integers over 4300 digits) the
binary reports it and exits 1; those trees are compared as "both failed".
Exits non-zero on any mismatch.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "benchmarks"))
import diff_transcripts as dt  # noqa: E402  (also puts src/ on sys.path, forces Python impls)

from key_amnesia import cli  # noqa: E402

BINARY = REPO / "target" / "release" / "vahta"

VARIANTS = [
    [],
    ["--json"],
    ["--strict", "paranoid"],
    ["--json", "--strict", "certain"],
    ["--quiet"],
]


def run_python(cwd: Path, home: Path, appdata: str | None, extra: list[str]):
    env_backup = {k: os.environ.get(k) for k in ("HOME", "APPDATA")}
    old_cwd = os.getcwd()
    out, err = io.StringIO(), io.StringIO()
    try:
        os.environ["HOME"] = str(home)
        if appdata is None:
            os.environ.pop("APPDATA", None)
        else:
            os.environ["APPDATA"] = appdata
        os.chdir(cwd)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(["scan", "--deep", "--no-import", *extra])
            except RecursionError:
                code = "crash"
            except ValueError:
                code = "crash"
        return out.getvalue().encode(), code, err.getvalue().encode()
    finally:
        os.chdir(old_cwd)
        for k, v in env_backup.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def run_rust(cwd: Path, home: Path, appdata: str | None, extra: list[str]):
    env = {k: v for k, v in os.environ.items() if k not in ("HOME", "APPDATA")}
    env["HOME"] = str(home)
    if appdata is not None:
        env["APPDATA"] = appdata
    p = subprocess.run([str(BINARY), "scan", "--deep", *extra], cwd=cwd, env=env, capture_output=True)
    return p.stdout, p.returncode, p.stderr


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seed", type=int, default=20260419)
    ap.add_argument("--scale", type=int, default=1)
    args = ap.parse_args()
    if not BINARY.exists():
        print(f"missing {BINARY}; build it first (see the docstring)", file=sys.stderr)
        return 2
    rng = random.Random(args.seed)
    checked = bad = crashes = nonempty = 0
    for i in range(40 * args.scale):
        root = Path(tempfile.mkdtemp(prefix="diff-cli-deep-"))
        hazard = 0.0 if i % 4 else 0.3
        home = dt.build_home(rng, root, hazard=hazard)
        appdata = str(root / "appdata") if rng.random() < 0.3 else None
        projects = []
        outside = root / "project"
        outside.mkdir()
        if rng.random() < 0.5:
            (outside / ".env").write_text(f"{dt.pick_name(rng).upper()}={dt.rand_value(rng) or 'abc12345'}\n")
        projects.append(outside)
        projects.append(home)  # the project is the home directory: everything is seen twice
        inner = home / "work"
        inner.mkdir(exist_ok=True)
        projects.append(inner)
        for project in projects:
            for extra in VARIANTS:
                want = run_python(project, home, appdata, extra)
                got = run_rust(project, home, appdata, extra)
                checked += 1
                if want[1] == "crash":
                    crashes += 1
                    ok = got[1] == 1 and got[0] == b"" and b"error" in got[2]
                else:
                    nonempty += bool(want[0].strip())
                    ok = want[0] == got[0] and want[1] == got[1] and want[2] == got[2]
                if not ok:
                    bad += 1
                    print(f"MISMATCH home={home} cwd={project} args={extra}")
                    print(f"  python code {want[1]} stdout {len(want[0])}B stderr {len(want[2])}B")
                    print(f"  rust   code {got[1]} stdout {len(got[0])}B stderr {len(got[2])}B")
                    for label, a, b in (("stdout", want[0], got[0]), ("stderr", want[2], got[2])):
                        if a != b:
                            la, lb = a.decode(errors="replace").splitlines(), b.decode(errors="replace").splitlines()
                            for n, (x, y) in enumerate(zip(la + [""] * len(lb), lb + [""] * len(la))):
                                if x != y:
                                    print(f"  first {label} difference at line {n + 1}:\n    python: {x[:160]}\n    rust:   {y[:160]}")
                                    break
        if not bad:
            shutil.rmtree(root, ignore_errors=True)
    print(f"{checked} runs ({nonempty} with a non-empty report, {crashes} where Python raises), {bad} mismatches")
    if nonempty == 0:
        print("no run produced a report; the generator is not exercising anything", file=sys.stderr)
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
