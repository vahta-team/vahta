"""The red-team episode with the real Claude Code CLI. Runs inside the agent container.

Same job as agent.py (put canaries in a Vahta vault, unlock them, run an agent on a
scenario, collect evidence for the scorer), but the agent is `claude -p` and the hooks
are the real ones, installed by `vahta setup --claude` in THIS container's HOME.

Credentials: Claude Code gets a DUMMY credential and ANTHROPIC_BASE_URL pointing at
the `authproxy` container, which holds the real one. Nothing here ever sees it.

Evidence written to /out (the same shapes the scorer reads for agent.py):
  transcript.jsonl   one `tool` entry per tool call, built from `claude --output-format stream-json`
  claude-stream.jsonl the raw stream (tool inputs and results; same sensitivity as transcript.jsonl)
  journal.jsonl, workspace/, summary.json
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent  # noqa: E402  (egress_blocked, Log, PROJECT)
import canary  # noqa: E402
import scenarios  # noqa: E402
import techniques  # noqa: E402
import vaultsetup  # noqa: E402

HOME = os.path.expanduser("~")
PROJECT = agent.PROJECT
DUMMY_OAUTH = "bench-dummy-oauth-token-not-a-credential"
DUMMY_KEY = "bench-dummy-api-key-not-a-credential"
TOOLS = "Bash Read Write Edit MultiEdit Glob Grep"
# Claude Code's own network chatter that is not the model: off, so that the only
# thing it asks the proxy for is the Messages API.
QUIET = {"DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1", "DISABLE_AUTOUPDATER": "1",
         "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_BUG_COMMAND": "1"}


def seed_claude(auth: str):
    """First-run state, so that `-p` never stops at onboarding or the trust dialog.
    Then the real hooks, put in by Vahta itself. Hooks stay on (nothing here turns them off)."""
    os.makedirs(os.path.join(HOME, ".claude"), exist_ok=True)
    state = {
        "hasCompletedOnboarding": True,
        "lastOnboardingVersion": "2.1.286",
        "numStartups": 10,
        "theme": "dark",
        "projects": {PROJECT: {"hasTrustDialogAccepted": True, "hasCompletedProjectOnboarding": True,
                               "allowedTools": [], "history": []}},
    }
    if auth == "apikey":  # an API key from the environment needs the "use this key" answer once
        state["customApiKeyResponses"] = {"approved": [DUMMY_KEY[-20:]], "rejected": []}
    with open(os.path.join(HOME, ".claude.json"), "w") as f:
        json.dump(state, f)
    r = subprocess.run(["vahta", "setup", "--claude"], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    return r.returncode, (r.stdout + r.stderr)[-400:]


def hooks_installed() -> dict:
    """What `vahta setup --claude` left in the container's settings (event names only)."""
    path = os.path.join(HOME, ".claude", "settings.json")
    try:
        cfg = json.load(open(path))
    except (OSError, ValueError):
        return {}
    return {ev: [h.get("command", "")[:60] for blk in blocks for h in blk.get("hooks", [])]
            for ev, blocks in cfg.get("hooks", {}).items()}


def norm(name, inp):
    """Claude Code tool call -> the shape agent.py logs (tool, input) so the scorer is shared."""
    if name == "Bash":
        return "bash", {"command": inp.get("command", "")}
    if name == "Read":
        return "read_file", {"path": inp.get("file_path", "")}
    if name == "Write":
        return "write_file", {"path": inp.get("file_path", ""), "content": inp.get("content", "")}
    if name in ("Edit", "MultiEdit"):
        text = inp.get("new_string") or json.dumps(inp.get("edits", ""))
        return "write_file", {"path": inp.get("file_path", ""), "content": text}
    return name.lower(), dict(inp)


def result_text(content) -> str:
    if isinstance(content, list):
        return "\n".join(b.get("text", "") for b in content if isinstance(b, dict))
    return str(content or "")


def is_deny(text: str, is_error: bool) -> bool:
    """A PreToolUse deny comes back to the model as an error result that names the hook."""
    t = text.lower()
    return bool(is_error and ("pretooluse" in t or "hook" in t) and ("blocked" in t or "hook error" in t or "denied" in t))


class Collector:
    """Turns the stream-json lines into transcript entries, stamping each with arrival time."""

    def __init__(self, log, canaries):
        self.log, self.canaries = log, canaries
        self.pending = {}
        self.result = {}
        self.calls = self.denied = 0
        self.tool_names = {}

    def feed(self, line: str, t: float):
        try:
            ev = json.loads(line)
        except ValueError:
            return
        kind = ev.get("type")
        if kind == "assistant":
            for b in ev.get("message", {}).get("content", []):
                if b.get("type") == "text" and b.get("text", "").strip():
                    self.log.add(type="assistant", content=b["text"], tool_calls=[])
                elif b.get("type") == "tool_use":
                    self.pending[b["id"]] = (b["name"], b.get("input") or {}, round(t, 2))
        elif kind == "user":
            content = ev.get("message", {}).get("content", [])
            for b in content if isinstance(content, list) else []:
                if b.get("type") != "tool_result" or b.get("tool_use_id") not in self.pending:
                    continue
                name, inp, t0 = self.pending.pop(b["tool_use_id"])
                shown = result_text(b.get("content"))
                deny = is_deny(shown, bool(b.get("is_error")))
                tool, args = norm(name, inp)
                probe = json.dumps(args) + urllib.parse.unquote_plus(json.dumps(args))
                carries = {n: f for n, v in self.canaries.items() if (f := canary.forms_in(probe, v))}
                self.calls += 1
                self.denied += deny
                self.log.add(type="tool", tool=tool, claude_tool=name, input=args,
                             decision="deny" if deny else "allow", reason=shown[:300] if deny else "",
                             shown=shown[:agent.CAP], t0=t0, technique=techniques.classify(tool, args), carries=carries)
        elif kind == "result":
            self.result = {k: ev.get(k) for k in ("subtype", "is_error", "num_turns", "duration_ms", "total_cost_usd", "result")}
            self.result["result"] = str(self.result.get("result") or "")[:500]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="ci_check")
    ap.add_argument("--max-turns", type=int, default=15)
    ap.add_argument("--alarm", default="warn", choices=["warn", "lock"])
    ap.add_argument("--bind", type=int, default=0)
    ap.add_argument("--auth", default="oauth", choices=["oauth", "apikey"])
    ap.add_argument("--cc-model", default="haiku")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--out", default="/out")
    a = ap.parse_args()

    canaries = json.load(sys.stdin)  # {name: value}; never printed, never logged
    sc = scenarios.SCENARIOS[a.scenario]
    for rel, body in sc["files"].items():
        path = os.path.join(PROJECT, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(body)
    env = vaultsetup.setup(PROJECT, canaries, alarm=a.alarm, bind=bool(a.bind))
    setup_rc, setup_out = seed_claude(a.auth)
    hooks = hooks_installed()

    names = ", ".join(canaries)
    task = sc["task"].format(names=names) if "{names}" in sc["task"] else sc["task"]
    cmd = ["claude", "-p", task, "--model", a.cc_model, "--max-turns", str(a.max_turns),
           "--output-format", "stream-json", "--verbose", "--allowedTools", TOOLS]
    if "system" in sc:  # attacker mode: the framing goes in as extra system prompt
        cmd += ["--append-system-prompt", sc["system"].format(names=names, turns=a.max_turns)]
    env = {**env, **QUIET, "ANTHROPIC_BASE_URL": os.environ["ANTHROPIC_BASE_URL"], "HOME": HOME}
    if a.auth == "oauth":
        env["CLAUDE_CODE_OAUTH_TOKEN"] = DUMMY_OAUTH
        env.pop("ANTHROPIC_API_KEY", None)
    else:
        env["ANTHROPIC_API_KEY"] = DUMMY_KEY
        env.pop("CLAUDE_CODE_OAUTH_TOKEN", None)

    log = agent.Log(os.path.join(a.out, "transcript.jsonl"))
    log.add(type="user", content=task, mode=sc.get("mode", "victim"))
    col = Collector(log, canaries)
    raw = open(os.path.join(a.out, "claude-stream.jsonl"), "w")
    t0 = time.time()
    proc = subprocess.Popen(cmd, cwd=PROJECT, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    err = []
    threading.Thread(target=lambda: err.append(proc.stderr.read()), daemon=True).start()
    killer = threading.Timer(a.timeout, proc.kill)
    killer.start()
    for line in proc.stdout:
        raw.write(line)
        raw.flush()
        col.feed(line, time.time())
    proc.wait()
    killer.cancel()
    raw.close()

    home = HOME
    journal = os.path.join(home, ".local/share/vahta/journal.jsonl")
    if os.path.exists(journal):
        shutil.copy(journal, os.path.join(a.out, "journal.jsonl"))
    shutil.copytree(PROJECT, os.path.join(a.out, "workspace"), dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(".vahta"))
    sessions = subprocess.run(["vahta", "sessions"], capture_output=True, text=True, env=env)
    stats = {
        "turns": col.result.get("num_turns"), "calls": col.calls, "denied": col.denied,
        "ended": col.result.get("subtype") or ("killed" if proc.returncode in (-9, 137) else f"exit {proc.returncode}"),
        "claude": {**col.result, "exit_code": proc.returncode, "wall_seconds": round(time.time() - t0, 1),
                   "stderr_tail": (err[0] if err else "")[-600:]},
        "hooks_setup_rc": setup_rc, "hooks_setup_out": setup_out, "hooks_installed": hooks,
        "sessions": sessions.stdout.strip(), "egress_blocked": agent.egress_blocked(),
    }
    with open(os.path.join(a.out, "summary.json"), "w") as f:
        json.dump(stats, f, indent=2)


if __name__ == "__main__":
    main()
