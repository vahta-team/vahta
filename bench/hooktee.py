#!/usr/bin/env python3
"""Capture mode for cc-redact: stands in for `vahta-hook` in the container's settings, appends each
payload Claude Code sends and the hook's answer to /out/hook-capture.jsonl, and passes both through
unchanged (the real hook decides everything). TEST ONLY; the capture holds canary-bearing text."""

import json
import subprocess
import sys

raw = sys.stdin.buffer.read()
r = subprocess.run(["/usr/local/bin/vahta-hook", *sys.argv[1:]], input=raw, capture_output=True)
try:
    with open("/out/hook-capture.jsonl", "a") as f:
        f.write(json.dumps({"args": sys.argv[1:], "stdin": raw.decode("utf-8", "replace"),
                            "stdout": r.stdout.decode("utf-8", "replace"), "exit": r.returncode}) + "\n")
except OSError:
    pass
sys.stdout.buffer.write(r.stdout)
sys.stderr.buffer.write(r.stderr)
sys.exit(r.returncode)
