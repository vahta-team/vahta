"""Where does `ka scan` actually spend its time?

Written before porting anything, because the last time a cost was assumed
rather than measured it turned out to be `importlib.metadata` in a module
docstring's worth of code, not the algorithm.

    .venv/bin/python benchmarks/profile_scan.py            # project scan
    .venv/bin/python benchmarks/profile_scan.py --deep     # synthetic deep tree

The deep case runs against a *generated* transcript tree rather than the
user's real one: the point is to find hot functions, and synthetic JSONL
exercises the same code path without reading anyone's session history.
"""

from __future__ import annotations

import argparse
import cProfile
import json
import pstats
import random
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def build_transcript_tree(root: Path, *, files: int, lines: int) -> Path:
    """A tree shaped like ~/.claude/projects/**/*.jsonl, with no real content."""
    rng = random.Random(20260930)
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    projects = root / ".claude" / "projects"
    for i in range(files):
        d = projects / f"project-{i}"
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"session-{i}.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            for _ in range(lines):
                blob = "".join(rng.choice(alphabet) for _ in range(rng.randint(20, 200)))
                fh.write(
                    json.dumps(
                        {
                            "type": "assistant",
                            "message": {"content": [{"type": "text", "text": blob}]},
                        }
                    )
                    + "\n"
                )
    return root


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--deep", action="store_true")
    ap.add_argument("--top", type=int, default=18)
    args = ap.parse_args()

    from key_amnesia import detect
    from key_amnesia.scan import scan_deep, scan_project

    print(f"detector implementation: {detect.active_impl}")

    if args.deep:
        with tempfile.TemporaryDirectory() as tmp:
            home = build_transcript_tree(Path(tmp), files=12, lines=400)
            total_bytes = sum(
                p.stat().st_size for p in home.rglob("*.jsonl")
            )
            print(f"synthetic transcripts: {total_bytes / 1024:.0f} KiB")
            t0 = time.perf_counter()
            profiler = cProfile.Profile()
            profiler.enable()
            findings = scan_deep(home=home)
            profiler.disable()
            elapsed = time.perf_counter() - t0
    else:
        t0 = time.perf_counter()
        profiler = cProfile.Profile()
        profiler.enable()
        findings = scan_project(REPO)
        profiler.disable()
        elapsed = time.perf_counter() - t0

    print(f"findings: {len(findings)}   wall: {elapsed * 1000:.0f} ms")
    print()
    stats = pstats.Stats(profiler)
    stats.sort_stats("cumulative").print_stats(args.top)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
