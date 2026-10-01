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
binary deliberately does not: it scans those lines. Such a tree is checked
differently. The lines Python cannot scan are blanked out (line numbers kept)
and on that tree the two programs must agree byte for byte, as everywhere
else. On the original tree the binary must succeed without an error message,
and, in the `--json` runs, report a superset of the blanked tree's line hits
plus every planted secret on a hostile line. Exits non-zero on any mismatch.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
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


RANK = {"possible": 1, "likely": 2, "certain": 3}


def report_superset_problems(clean, original) -> list[str]:
    """Problems if the report on `original` reports less than the one on `clean`.

    The report keeps one finding per path, the highest tier, so a hostile line
    with a planted secret can lift a file from "likely" to "certain" and take
    its likely lines with it. That is more reported, not less: a file is lost
    only if its tier drops, and within a tier no line may be.
    """
    best: dict[str, tuple[int, set[int]]] = {}
    for f in original:
        key = str(Path(f["path"]).resolve())
        rank, lines = best.get(key, (0, set()))
        if RANK[f["confidence"]] > rank:
            best[key] = (RANK[f["confidence"]], set(f["hit_lines"]))
        elif RANK[f["confidence"]] == rank:
            lines.update(f["hit_lines"])
    out = []
    for f in clean:
        key = str(Path(f["path"]).resolve())
        rank, lines = best.get(key, (0, set()))
        if rank < RANK[f["confidence"]]:
            out.append(f"{Path(key).name}: {f['confidence']} finding lost")
        elif rank == RANK[f["confidence"]] and not set(f["hit_lines"]) <= lines:
            out.append(f"{Path(key).name}: {f['confidence']} lines {sorted(set(f['hit_lines']) - lines)} lost")
    return out


def hostile_tree(home: Path, root: Path, runs, appdata: str | None) -> list[str]:
    """A tree on which Python aborts: see the module docstring. Mutates `home`."""
    problems: list[str] = []
    # Rust on the original, before anything is blanked.
    original = {}
    for project, extra in runs:
        original[(project, tuple(extra))] = run_rust(project, home, appdata, extra)
    shutil.copytree(home, root / "home-before-blanking", symlinks=True)
    probe = root / "probe"
    probe.mkdir()
    datas: dict[Path, bytes] = {}
    hostile = 0
    for p in dt.scan_py.iter_agent_transcript_files(home):
        rp = p.resolve()
        if rp in datas:
            continue
        data = datas[rp] = rp.read_bytes()
        clean, lines = dt.blank_hostile_lines(data, probe)
        if lines:
            hostile += len(lines)
            rp.write_bytes(clean)
    if not hostile:
        problems.append("python aborted but no single line reproduces it")
    for project, extra in runs:
        tag = f"cwd={project.name} args={extra}"
        want = run_python(project, home, appdata, extra)
        clean = run_rust(project, home, appdata, extra)
        orig = original[(project, tuple(extra))]
        if want[1] == "crash":
            problems.append(f"{tag}: python still aborts with the hostile lines blanked")
            continue
        if want != clean:
            problems.append(f"{tag}: blanked tree differs: python code {want[1]} {len(want[0])}B out {len(want[2])}B err; "
                            f"rust code {clean[1]} {len(clean[0])}B out {len(clean[2])}B err")
        if b"error" in orig[2].lower():
            problems.append(f"{tag}: rust reported an error on the original: {orig[2][-200:]!r}")
        if orig[1] < clean[1]:
            problems.append(f"{tag}: rust exit {orig[1]} on the original but {clean[1]} on the blanked tree")
        if "--json" in extra:
            try:
                doc_o, doc_c = json.loads(orig[0]), json.loads(clean[0])
            except ValueError as e:
                problems.append(f"{tag}: unparseable --json output: {e}")
                continue
            problems += [f"{tag}: {x}" for x in report_superset_problems(doc_c["findings"], doc_o["findings"])]
            if "--strict" not in extra:  # every tier is listed
                for rp, data in datas.items():
                    problems += [f"{tag}: {x}" for x in dt.planted_problems(data, rp, doc_o["findings"])]
    return problems


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
        runs = [(project, extra) for project in projects for extra in VARIANTS]
        probe = run_python(outside, home, appdata, [])
        if probe[1] == "crash":
            crashes += 1
            problems = hostile_tree(home, root, runs, appdata)
            checked += len(runs)
            if problems:
                bad += 1
                print(f"MISMATCH hostile home={home} (kept; pre-blanking copy in {root / 'home-before-blanking'})")
                for line in problems[:12]:
                    print("  " + line)
            else:
                nonempty += 1
            if not bad:
                shutil.rmtree(root, ignore_errors=True)
            continue
        for project, extra in runs:
            want = run_python(project, home, appdata, extra)
            got = run_rust(project, home, appdata, extra)
            checked += 1
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
    planted = dt.COVERAGE.get("hostile lines with a planted secret checked", 0)
    print(f"{planted} planted-secret checks run on hostile lines")
    if crashes and planted == 0:
        print("hostile trees were generated but none carried a planted secret; the check is not running", file=sys.stderr)
        return 1
    if nonempty == 0:
        print("no run produced a report; the generator is not exercising anything", file=sys.stderr)
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
