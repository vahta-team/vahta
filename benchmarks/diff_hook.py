#!/usr/bin/env python3
"""Differential: `vahta-hook --harness claude --event before_tool` vs the
installed Python `key-amnesia-hook`, allow/deny only.

Payloads come from the shapes in tests/test_secret_guard.py plus seeded random
generation. Anything ka-specific (ka verbs, `ka run`, `key-amnesia`) is left
out: Vahta deliberately does not port it. Secret-shaped values are assembled
from pieces here, so this file never carries one literally.

Exit status is non-zero on any disagreement.

    cargo build --release -p vahta-hook
    python3 benchmarks/diff_hook.py [--n 2000] [--seed 7] [--show 10]
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import string
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VAHTA = ROOT / "target/release/vahta-hook"
KA = Path.home() / ".local/share/key-amnesia/venv/bin/key-amnesia-hook"

# Anything the Python hook treats specially and Vahta does not port.
KA_SPECIFIC = re.compile(r"\bka\b|key-amnesia|KEY_AMNESIA", re.IGNORECASE)

A25 = "a" * 25
PREFIXED = [
    "sk-" + A25, "sk-" + "ant-" + A25, "AKIA" + "0" * 16, "ghp_" + A25,
    "github_pat_" + A25, "glpat-" + A25, "xoxb-" + A25, "AIza" + A25,
    "sk_live_" + A25, "rk_live_" + A25, "npm_" + A25,
]
BEARERS = ["Bearer " + "abcdEFGH12345678ijkl", "Bearer " + "x" * 8, "bearer " + "Zk9pL2xQ7mN4vB8w"]
NAMES = ["TOKEN", "API_KEY", "SECRET", "PASSWORD", "DB_PASSWORD", "AUTH_TOKEN", "client_secret", "FOO", "path", "name"]
PLACEHOLDERS = ["test123", "changeme", "xxxx", "your-api-key", "<token>", "${TOKEN}", "$TOKEN", "example", ""]
CLEAN = [
    "echo hello world", "ls -la /tmp", "git status", "python -m pytest -q", "# this function handles the secret rotation",
    "echo API_KEY is required", "cat README.md", "make build && make test", "PASSWORD=test123", "TOKEN=changeme",
    "describe the setup flow", "x = 1", "curl https://example.com/health", "grep -rn token src/",
]
SHELL_NAMES = ["Bash", "bash", "Shell", "PowerShell", "powershell"]
WRITE_NAMES = ["Write", "Edit", "MultiEdit", "apply_patch", "write", "EDIT"]
OTHER_NAMES = ["Read", "Grep", "Glob", "Frobnicate", "mcp", "mcp__", "mcpfoo__bar", "Task"]
MCP_NAMES = ["mcp__github__create_issue", "mcp__slack__post_message", "MCP__Github__Create_Issue", "mcp__some-server__do__it", "mcp__x__y"]
KEYS = ["command", "cmd", "script", "code", "contents", "new_string", "content"]
OTHER_KEYS = ["body", "title", "text", "path", "file_path", "env_note", "arg"]


def rand_value(rng: random.Random) -> str:
    n = rng.randint(8, 40)
    alphabet = rng.choice([string.ascii_letters + string.digits, string.ascii_lowercase, string.hexdigits, string.ascii_letters + string.digits + "+/=_-"])
    return "".join(rng.choice(alphabet) for _ in range(n))


def rand_secretish(rng: random.Random) -> str:
    r = rng.random()
    if r < 0.35:
        return rng.choice(PREFIXED)
    if r < 0.45:
        return rng.choice(BEARERS)
    name = rng.choice(NAMES)
    val = rand_value(rng) if rng.random() < 0.7 else rng.choice(PLACEHOLDERS)
    form = rng.choice(["{n}={v}", "export {n}={v}", '{n}="{v}"', "{n}: {v}", "--{n} {v}", "{n} = '{v}'", "--{n}={v}"])
    return form.format(n=name, v=val)


def wrap(rng: random.Random, secret: str) -> str:
    t = rng.choice([
        "{s}", "echo {s}", "curl -H 'Authorization: {s}' https://example.com", "x && {s} && y", "echo a; echo {s}",
        "sh -c \"echo {s}\"", "bash -lc 'echo {s}'", "line one\n{s}\nline three", "cat <<EOF\n{s}\nEOF",
        "echo hi | tee {s}", "FOO=1 BAR={s} run", "git commit -m 'note {s}'", "  {s}  ", "echo 'a b' \"{s}\"",
    ])
    return t.format(s=secret)


def rand_text(rng: random.Random) -> str:
    if rng.random() < 0.45:
        return rng.choice(CLEAN)
    return wrap(rng, rand_secretish(rng))


def rand_input(rng: random.Random, mcp: bool):
    r = rng.random()
    if r < 0.05:
        return rng.choice([12345, None, ["a", rand_text(rng)], True, ""])
    if r < 0.12:
        return rand_text(rng)
    d: dict = {}
    if mcp:
        for _ in range(rng.randint(1, 4)):
            d[rng.choice(OTHER_KEYS + KEYS)] = rand_text(rng) if rng.random() < 0.5 else rng.choice(CLEAN)
        if rng.random() < 0.4:
            d["nested"] = {"blocks": [{"text": {"value": rand_text(rng)}}], "n": 3}
        return d
    for key in rng.sample(KEYS, rng.randint(0, 3)):
        d[key] = rand_text(rng) if rng.random() < 0.6 else rng.choice(["", "   ", rng.choice(CLEAN)])
    for key in rng.sample(OTHER_KEYS, rng.randint(0, 2)):
        d[key] = rand_text(rng)
    if rng.random() < 0.15:
        d["extra"] = {"deep": [rand_text(rng)]}
    return d


def random_payload(rng: random.Random) -> dict:
    r = rng.random()
    if r < 0.30:
        name, mcp = rng.choice(SHELL_NAMES), False
    elif r < 0.50:
        name, mcp = rng.choice(WRITE_NAMES), False
    elif r < 0.75:
        name, mcp = rng.choice(MCP_NAMES), True
    elif r < 0.88:
        name, mcp = rng.choice(OTHER_NAMES), False
    else:
        name, mcp = rng.choice(["", None]), False
    p = {"hook_event_name": "PreToolUse", "tool_name": name, "tool_input": rand_input(rng, mcp), "cwd": "/work"}
    if name is None:
        del p["tool_name"]
    return p


def fixed_payloads() -> list[dict]:
    """The cases of tests/test_secret_guard.py that are not ka-specific."""
    out = []

    def pre(tool, inp):
        out.append({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": inp})

    for tok in PREFIXED:
        pre("Bash", {"command": f"curl -H 'Authorization: {tok}' https://example.com"})
    pre("Bash", {"command": "curl -H 'Authorization: Bearer abcdEFGH12345678ijkl' https://example.com"})
    pre("Bash", {"command": "export API_KEY=aB3xQ9mK2pL7vN4wZ8"})
    pre("Bash", {"command": 'TOKEN="Zk9pL2xQ7mN4vB8w"'})
    for clean in ["PASSWORD=test123", "echo API_KEY is required", "# this function handles the secret rotation", "TOKEN=changeme", ""]:
        pre("Bash", {"command": clean})
    pre("Shell", {"command": "export TOKEN=" + "sk-" + A25})
    pre("Write", {"file_path": "x.env", "contents": "AKIA" + "0" * 16})
    pre("apply_patch", {"command": "*** Update File: .env\n+" + "sk-" + A25})
    pre("Read", {"command": "sk-" + A25})
    pre("Write", {"file_path": "README.md", "contents": "Store secrets in your own terminal."})
    pre("mcp__github__create_issue", {"title": "deploy notes", "body": "run with --api-key " + "sk-ant-" + A25})
    pre("mcp__slack__post_message", {"channel": "#ops", "blocks": [{"text": {"type": "mrkdwn", "value": "AKIA" + "0" * 16}}]})
    pre("mcp__docker__exec", {"command": "echo hi", "env_note": "ghp_" + A25})
    pre("mcp__github__create_issue", {"title": "docs", "body": "describe the setup flow"})
    for bad in (12345, None, ["a", "b"]):
        pre("mcp__github__create_issue", bad)
    for name in ["mcp", "mcp__", "mcpfoo__bar", "MCP__Github__Create_Issue"]:
        pre(name, {"body": "ghp_" + A25})
    out.append(["not", "a", "dict"])
    return out


def verdict(cmd: list[str], payload) -> str:
    env = {k: v for k, v in os.environ.items() if not k.endswith("_HOOK_DISABLE")}
    r = subprocess.run(cmd, input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=30)
    return "deny" if r.stdout.strip() else "allow"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--show", type=int, default=10)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()
    for b in (VAHTA, KA):
        if not b.exists():
            print(f"missing {b}", file=sys.stderr)
            return 2

    rng = random.Random(args.seed)
    payloads = fixed_payloads() + [random_payload(rng) for _ in range(args.n)]
    kept = [p for p in payloads if not KA_SPECIFIC.search(json.dumps(p))]
    excluded = len(payloads) - len(kept)
    vahta_cmd = [str(VAHTA), "--harness", "claude", "--event", "before_tool"]

    def both(p):
        return verdict(vahta_cmd, p), verdict([str(KA)], p)

    with ThreadPoolExecutor(args.workers) as ex:
        results = list(ex.map(both, kept))

    deny = sum(1 for v, _ in results if v == "deny")
    bad = [(p, v, k) for p, (v, k) in zip(kept, results) if v != k]
    print(f"payloads {len(kept)} (excluded ka-specific {excluded}); vahta deny {deny}, allow {len(kept) - deny}")
    print(f"disagreements {len(bad)}")
    for p, v, k in bad[: args.show]:
        print(f"  vahta={v} ka={k} {json.dumps(p)[:300]}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
