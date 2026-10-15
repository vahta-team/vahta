#!/usr/bin/env python3
"""Token-free bench for stdio MCP servers under `vahta run`.

    python3 bench/mcp/run.py t1 [--quick]    framing, latency, leakage, stalls, lifecycle
    python3 bench/mcp/run.py t2 [--quick]    windows and timeouts with the scripted surface
    python3 bench/mcp/run.py all [--quick]

Builds (or finds) a test build of `vahta` (the daemon's `test-surface` feature),
makes a temp HOME and temp VAHTA_DATA_DIR / VAHTA_RUNTIME_DIR / VAHTA_CONFIG_DIR,
a project with a vault holding canaries assembled at run time, and writes
bench/out/mcp-<timestamp>/report.json. The report holds names, counts, times
and forms only, never a canary value. Standard library only; no network.
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import sandbox  # noqa: E402
import t1  # noqa: E402
import t2  # noqa: E402

ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))


def build(profile):
    """The test build: the daemon with its `test-surface` feature, in the CLI."""
    cmd = ["cargo", "build", "--locked", "--bin", "vahta", "-p", "vahta-cli",
           "--features", "vahta-daemon/test-surface"]
    if profile == "release":
        cmd.insert(2, "--release")
    print("building the test build (" + profile + ") ...", flush=True)
    r = subprocess.run(cmd, cwd=ROOT)
    if r.returncode != 0:
        sys.exit("cargo build failed")
    return os.path.join(ROOT, "target", profile, "vahta")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("which", choices=["t1", "t2", "all"])
    ap.add_argument("--quick", action="store_true", help="fewer calls and shorter waits (under 2 minutes)")
    ap.add_argument("--vahta", help="a test build of vahta to use instead of building one")
    ap.add_argument("--profile", choices=["release", "debug"], default="release")
    ap.add_argument("--no-build", action="store_true", help="use target/<profile>/vahta as it is")
    ap.add_argument("--out", help="output directory (default bench/out/mcp-<timestamp>)")
    a = ap.parse_args()

    vahta = a.vahta or (os.path.join(ROOT, "target", a.profile, "vahta") if a.no_build else build(a.profile))
    if not os.access(vahta, os.X_OK):
        sys.exit(f"no such binary: {vahta}")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out_dir = a.out or os.path.join(ROOT, "bench", "out", f"mcp-{stamp}")
    os.makedirs(out_dir, exist_ok=True)
    report = {"started": stamp, "quick": a.quick, "profile": a.profile,
              "host": {"python": platform.python_version(), "kernel": platform.release(), "cpus": os.cpu_count()},
              "vahta_commit": subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                                             capture_output=True, text=True).stdout.strip()}
    which = ["t1", "t2"] if a.which == "all" else [a.which]
    for w in which:
        sb = sandbox.Sandbox(vahta)
        canaries = sandbox.make_canaries()
        daemon_gone = None
        try:
            rejected = sb.setup_vault(canaries)
            print(f"{w}: sandbox ready ({len(canaries) - len(rejected)} secrets in the vault)", flush=True)
            if w == "t1":
                sb.unlock()
                report["t1"] = t1.run(t1.Ctx(sb, canaries, a.quick, rejected))
                report["t1"]["secrets_refused_by_vault"] = rejected
            else:
                report["t2"] = t2.run(t2.Ctx(sb, canaries, a.quick, vahta))
        finally:
            daemon_gone = sb.stop()
        report[w]["daemon_stopped"] = daemon_gone
    path = os.path.join(out_dir, "report.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=1)
        f.write("\n")
    print("report:", path)
    ok = all(report[w].get("pass_all", True) for w in which)
    for w in which:
        for k, v in report[w].items():
            if isinstance(v, dict) and "pass" in v:
                print(f"  {w}.{k}: {'pass' if v['pass'] else 'FAIL'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
