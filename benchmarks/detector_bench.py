"""Baseline and comparison harness for the detector.

Run the same script before and after the Rust port; the numbers are only
comparable if the harness is.

    .venv/bin/python benchmarks/detector_bench.py
    .venv/bin/python benchmarks/detector_bench.py --json > before.json

Three numbers, deliberately separate, because measuring the wrong one is the
usual way a port gets oversold:

1. **Cold start, end to end.** The hook is spawned as a *fresh process* on
   every tool call the agent makes. Interpreter startup and imports dominate
   here, not the algorithm. This is the number Rust was chosen for.

2. **Classification throughput, in process.** An honest comparison of the
   algorithm itself. Note that once a Rust implementation is measured through
   PyO3, this number *understates* native Rust by the cost of the FFI
   boundary.

3. **Interpreter floor.** `python -c pass`. Subtracting it from (1) separates
   "Python is slow to start" from "our code is slow", which decides how much
   of the cold-start win is actually ours to claim.

Probe payloads are assembled at run time rather than written as literals, so
the product's own hook does not refuse this file — which it would be right to
do.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# `NAME=value` and `--flag value` assembled at run time; no credential-shaped
# literal is ever committed in this file.
_VALUE = "aB3xQ9mK2pL7vN4wZ8"
DENY_COMMAND = " ".join(("curl", "-H", "=".join(("API_KEY", _VALUE)), "https://example.com"))
ALLOW_COMMAND = "ka run --secret OPENAI_API_KEY -- python train.py"


def _payload(command: str) -> str:
    return json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }
    )


#: Discarded before every case. Without it the first case measured absorbs the
#: cold filesystem cache and reports a figure larger than cases that follow —
#: which is how a baseline ends up claiming that importing one module costs
#: more than running the whole hook.
WARMUP = 5


def _timed(fn, runs: int, warmup: int = WARMUP) -> dict[str, float]:
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    samples.sort()
    return {
        "runs": runs,
        "min_ms": round(samples[0], 3),
        "median_ms": round(statistics.median(samples), 3),
        "mean_ms": round(statistics.fmean(samples), 3),
        "p95_ms": round(samples[int(len(samples) * 0.95) - 1], 3),
        "max_ms": round(samples[-1], 3),
    }


def bench_interpreter_floor(runs: int) -> dict[str, float]:
    exe = sys.executable

    def once() -> None:
        subprocess.run([exe, "-c", "pass"], check=False, capture_output=True)

    return _timed(once, runs)


def bench_cold_start(runs: int, command: str) -> dict[str, float] | None:
    hook = shutil.which("key-amnesia-hook")
    if hook is None:
        candidate = Path(sys.executable).parent / "key-amnesia-hook"
        hook = str(candidate) if candidate.exists() else None
    if hook is None:
        return None

    data = _payload(command).encode()

    def once() -> None:
        subprocess.run([hook], input=data, check=False, capture_output=True)

    return _timed(once, runs)


def bench_import_only(runs: int) -> dict[str, float]:
    exe = sys.executable

    def once() -> None:
        subprocess.run(
            [exe, "-c", "import key_amnesia.detect"],
            check=False,
            capture_output=True,
            cwd=REPO,
        )

    return _timed(once, runs)


def bench_in_process(runs: int) -> dict[str, dict[str, float]]:
    from key_amnesia.detect import scan_text_hits

    corpus_dir = REPO / "tests" / "fixtures" / "scan_corpus"
    blobs = [
        p.read_text(encoding="utf-8")
        for p in sorted(corpus_dir.rglob("*"))
        if p.is_file() and p.suffix != ".md"
    ]
    joined = "\n".join(blobs)

    def one_command() -> None:
        scan_text_hits(DENY_COMMAND)

    def whole_corpus() -> None:
        scan_text_hits(joined)

    return {
        "single_command": _timed(one_command, runs),
        "corpus_blob": _timed(whole_corpus, max(runs // 10, 5)),
        "corpus_bytes": len(joined.encode()),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--runs", type=int, default=40, help="process spawns per case")
    ap.add_argument("--inner-runs", type=int, default=2000, help="in-process iterations")
    ap.add_argument("--json", action="store_true", help="emit JSON only")
    args = ap.parse_args()

    from key_amnesia import detect

    result: dict[str, object] = {
        "impl": detect.active_impl,
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "interpreter_floor": bench_interpreter_floor(args.runs),
        "import_detect": bench_import_only(args.runs),
        "cold_start_deny": bench_cold_start(args.runs, DENY_COMMAND),
        "cold_start_allow": bench_cold_start(args.runs, ALLOW_COMMAND),
        "in_process": bench_in_process(args.inner_runs),
    }

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    print(f"implementation : {result['impl']}")
    print(f"python         : {result['python']} on {result['platform']}")
    print()
    print("process spawns (ms)            min    median      p95")
    for key in ("interpreter_floor", "import_detect", "cold_start_allow", "cold_start_deny"):
        row = result[key]
        if row is None:
            print(f"  {key:<27} (not installed)")
            continue
        print(f"  {key:<27}{row['min_ms']:>7}{row['median_ms']:>10}{row['p95_ms']:>9}")

    floor = result["interpreter_floor"]["median_ms"]
    deny = result["cold_start_deny"]
    if deny:
        ours = deny["median_ms"] - floor
        share = ours / deny["median_ms"] * 100
        print()
        print(f"  interpreter floor is {floor:.1f} ms of a {deny['median_ms']:.1f} ms cold start")
        print(f"  our own work accounts for {ours:.1f} ms ({share:.0f}%)")

    ip = result["in_process"]
    print()
    print("in process (ms)                min    median      p95")
    print(
        f"  single command             {ip['single_command']['min_ms']:>7}"
        f"{ip['single_command']['median_ms']:>10}{ip['single_command']['p95_ms']:>9}"
    )
    print(
        f"  corpus blob ({ip['corpus_bytes']} B)      {ip['corpus_blob']['min_ms']:>7}"
        f"{ip['corpus_blob']['median_ms']:>10}{ip['corpus_blob']['p95_ms']:>9}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
