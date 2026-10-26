#!/usr/bin/env python3
"""cc-t3 `--real`, automode episode: stands in for `vahta-hook` in the container's settings.

  python3 hookfilter.py LOGFILE MODE [hook arguments...]       (MODE: normal | silent)

Runs the real hook on the same input and passes its answer and exit code through, except in MODE `silent`:
an explicit "allow" (what the hook says for a `vahta run` the secret's rules let through) is then dropped, so
that Claude Code hears nothing from the hook, as if the hook had no opinion. Every other answer (a refusal,
added context) is passed on unchanged. One line per call goes to LOGFILE: the event, the tool name, and what the
hook said (`allow-explicit`, `deny`, `context`, `silent`); no input and no output text. TEST ONLY: the real hook
is not changed; this is a wrapper in the bench container's HOME.
"""

import json
import subprocess
import sys

log, mode, args = sys.argv[1], sys.argv[2], sys.argv[3:]
raw = sys.stdin.buffer.read()
r = subprocess.run(["/usr/local/bin/vahta-hook", *args], input=raw, capture_output=True)
out = r.stdout
kind = "silent"
try:
    doc = json.loads(out) if out.strip() else {}
    spec = doc.get("hookSpecificOutput") or {}
    said = spec.get("permissionDecision") or doc.get("decision")
    if said == "allow":
        kind = "allow-explicit"
    elif said in ("deny", "block"):
        kind = "deny"
    elif doc:
        kind = "context"
except ValueError:
    kind = "other"
if r.returncode == 2:
    kind = "deny"
try:
    tool = json.loads(raw).get("tool_name")
except ValueError:
    tool = None
try:
    with open(log, "a") as f:
        f.write(json.dumps({"args": args, "tool": tool, "answer": kind, "exit": r.returncode, "dropped": mode == "silent" and kind == "allow-explicit"}) + "\n")
except OSError:
    pass
if not (mode == "silent" and kind == "allow-explicit"):
    sys.stdout.buffer.write(out)
sys.stderr.buffer.write(r.stderr)
sys.exit(r.returncode)
