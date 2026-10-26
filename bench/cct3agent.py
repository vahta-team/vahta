"""cc-t3, inside the agent container: real Claude Code, real Vahta hooks and daemon, a mock model.

  python3 /bench/cct3agent.py MODE /out          (canaries as {name: value} on stdin; none is printed or logged)

MODE sets the stage for one case group (cct3.py has the host side that scripts the mock and judges):

  mcp          a connectors vault with one connector (MCP_TOKEN), `fake_server.py` started by Claude Code through
               `vahta run --connector`, and a project vault; the mock calls the server's tools
  paste        a project vault; two `claude -p` runs: a prompt that carries a canary, then a clean one
  allow        a project vault; the mock writes files the hook refuses and asks `vahta allow REF`

After the run: the files Claude Code left under HOME are scanned for every canary form (names and forms go to
summary.json, never a value). The scripted prompt surface's log is copied to /out/surface.log.
"""

import json
import os
import secrets
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent  # noqa: E402
import canary  # noqa: E402
import ccagent  # noqa: E402
import vaultsetup  # noqa: E402

PROJECT = agent.PROJECT
HOME = ccagent.HOME
K = vaultsetup.K
SERVER = "/bench/mcp/fake_server.py"
CLAUDE_DIR = os.path.join(HOME, ".claude")
TOOLS = ccagent.TOOLS + " mcp__fake"


def surface_vahta(env, *args):
    r = subprocess.run(["vahta", *args], capture_output=True, text=True, env=env, cwd=PROJECT)
    if r.returncode != 0:
        raise RuntimeError(f"vahta {args[0]} failed ({r.returncode}): {r.stderr.strip()[:300]}")
    return r


def setup_connector(canaries, name):
    """`vahta init --connector` and one connector, by the scripted window; returns its password."""
    env, pw = vaultsetup.surface_env(), secrets.token_urlsafe(12)
    vaultsetup.rescript({K: pw}, {"ack": True}, noanswers=0)
    surface_vahta(env, "init", "--connector")
    vaultsetup.rescript({K: pw}, {K: canaries[name]}, {"choose": 0}, noanswers=0)
    surface_vahta(env, "add", "--connector", name, "--harness", "claude", "--allow", f"python3 {SERVER}",
                  "--reason", "bench: fake mcp server")
    return pw


def claude_env(base):
    env = {**base, **ccagent.QUIET, "ANTHROPIC_BASE_URL": os.environ["ANTHROPIC_BASE_URL"], "HOME": HOME}
    env.pop("ANTHROPIC_API_KEY", None)
    env["CLAUDE_CODE_" + "OAUTH_TOKEN"] = ccagent.DUMMY_OAUTH  # a dummy; the mock never checks it
    return env


def run_claude(env, out, tag, prompt, extra=()):
    """One `claude -p` run; the prompt goes in on stdin, the stream to /out/claude-stream-TAG.jsonl."""
    cmd = ["claude", "-p", "--model", "haiku", "--max-turns", "40", "--output-format", "stream-json", "--verbose",
           "--allowedTools", TOOLS, *extra]
    with open(os.path.join(out, f"claude-stream-{tag}.jsonl"), "w") as raw:
        r = subprocess.run(cmd, cwd=PROJECT, env=env, input=prompt, stdout=raw, stderr=subprocess.PIPE, text=True,
                           timeout=300)
    return {"tag": tag, "exit": r.returncode, "stderr_tail": r.stderr[-400:]}


def disk_hits(canaries):
    """{where: {canary name: forms}} for every file Claude Code (and Vahta's journal) left under HOME."""
    roots = [CLAUDE_DIR, os.path.join(HOME, ".claude.json"), os.path.join(HOME, ".local/share/vahta/journal.jsonl")]
    hits = {}
    for root in roots:
        walk = [(root, "")] if os.path.isfile(root) else [(os.path.join(d, n), "") for d, _, ns in os.walk(root) for n in ns]
        for path, _ in walk:
            try:
                if os.path.getsize(path) > 30_000_000:
                    continue
                text = open(path, errors="replace").read()
            except OSError:
                continue
            found = {n: f for n, v in canaries.items() if (f := canary.forms_in(text, v))}
            if found:
                hits[os.path.relpath(path, HOME)] = found
    return hits


def where(hits, canaries):
    """For the hits in transcript lines: which kind of block holds a canary (e.g. 'assistant/tool_use'), counts only."""
    kinds = {}
    for rel in hits:
        if not rel.endswith(".jsonl"):
            continue
        for line in open(os.path.join(HOME, rel), errors="replace"):
            if not any(canary.forms_in(line, v) for v in canaries.values()):
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                kinds["not json"] = kinds.get("not json", 0) + 1
                continue
            content = (msg.get("message") or {}).get("content")
            for b in content if isinstance(content, list) else [content]:
                if any(canary.forms_in(json.dumps(b), v) for v in canaries.values()):
                    k = f"{msg.get('type')}/{b.get('type') if isinstance(b, dict) else 'text'}"
                    kinds[k] = kinds.get(k, 0) + 1
            if content is None:  # a line of Claude Code's own (queue-operation, system, ...): which field
                for key, val in msg.items():
                    if any(canary.forms_in(json.dumps(val), v) for v in canaries.values()):
                        k = f"{msg.get('type')}/{msg.get('subtype') or msg.get('operation') or ''}.{key}"
                        kinds[k] = kinds.get(k, 0) + 1
    return kinds


def scan_when_quiet(canaries, env, wait=20):
    """The transcript is cleaned a moment after SessionEnd: look at once, and again until clean or `wait` seconds.
    What is still there then is located by block kind, and `vahta scrub --transcript --all` is tried on it."""
    t0 = time.time()
    first = hits = disk_hits(canaries)
    while hits and time.time() - t0 < wait:
        time.sleep(1)
        hits = disk_hits(canaries)
    out = {"at_exit": first, "final": hits, "seconds_to_clean": round(time.time() - t0, 1) if first and not hits else 0}
    if hits:
        out["blocks"] = where(hits, canaries)
        for rel in hits:  # a file changed in the last minute is "running" and is only marked: let it be quiet
            old = time.time() - 300
            os.utime(os.path.join(HOME, rel), (old, old))
        r = subprocess.run(["vahta", "scrub", "--transcript", "--all"], capture_output=True, text=True, env=env, cwd=PROJECT)
        out["scrub_exit"] = r.returncode
        out["scrub_out"] = r.stdout.strip()[-300:]
        out["after_scrub"] = disk_hits(canaries)
    return out


def stage(mode, canaries, out):
    """Everything before `claude`. Returns (env for claude, extra claude flags, script knowledge for the summary)."""
    env = vaultsetup.setup(PROJECT, {k: v for k, v in canaries.items() if k in ("AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN",
                                                                               "STRIPE_API_KEY", "DATABASE_PASSWORD")})
    ccagent.seed_claude("oauth")
    info = {}
    if mode == "mcp":
        pw = setup_connector(canaries, "MCP_TOKEN")
        mcp = os.path.join(HOME, "mcp.json")
        with open(mcp, "w") as f:
            json.dump({"mcpServers": {"fake": {"command": "vahta", "args": [
                "run", "--connector", "--secret", "MCP_TOKEN", "--", "python3", SERVER]}}}, f)
        info["extra"] = ["--mcp-config", mcp, "--strict-mcp-config"]
        # One window for the connectors password, when Claude Code starts its first server.
        vaultsetup.rescript({K: pw})
    elif mode == "paste":
        info["extra"] = []  # per-run answers are scripted by the runs themselves
    elif mode == "allow":
        info["extra"] = []
    return env, info


def fill_pw(answers, pw):
    """The host scripts windows without knowing the vault password: {"secret": "@@PW@@"} gets it here."""
    return [{K: pw} if a.get(K) == "@@PW@@" else a for a in answers]


def vault_names(env):
    r = subprocess.run(["vahta", "list", "--json"], capture_output=True, text=True, env=env, cwd=PROJECT)
    try:
        doc = json.loads(r.stdout)
        rows = doc.get("secrets") or doc.get("entries") or doc
        return sorted(e["name"] for e in rows if isinstance(e, dict) and "name" in e)
    except (ValueError, TypeError, AttributeError):
        return [l.split()[0] for l in r.stdout.splitlines() if l.strip()]


def main():
    mode, out = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "/out")
    canaries = json.load(sys.stdin)
    os.makedirs(PROJECT, exist_ok=True)
    env, info = stage(mode, canaries, out)
    cenv = claude_env(env)
    runs = []
    pw = vaultsetup.PASSWORD
    if mode == "paste":
        # Run 1: a message with a canary the detector knows. The window: "Do nothing". Run 2: the same
        # with "Save to the project vault as NAME" (and a clean message after it).
        for tag, prompt, answers in json.load(open(os.path.join(out, "paste-plan.json"))):
            vaultsetup.rescript(*fill_pw(answers, pw))
            runs.append(run_claude(cenv, out, tag, prompt.replace("@@PASTED@@", canaries["PASTED_KEY"])
                                   .replace("@@DATABASE_PASSWORD@@", canaries["DATABASE_PASSWORD"])))
    else:
        if mode == "allow":
            plan = json.load(open(os.path.join(out, "allow-plan.json")))
            vaultsetup.rescript(*fill_pw(plan["answers"], pw))
        runs.append(run_claude(cenv, out, "main", "run the scripted checks", info["extra"]))
    summary = {"runs": runs, "hooks_installed": ccagent.hooks_installed(), "vault_names": vault_names(env),
               "disk": scan_when_quiet(canaries, env),
               "history_file_exists": os.path.exists(os.path.join(CLAUDE_DIR, "history.jsonl"))}
    journal = os.path.join(HOME, ".local/share/vahta/journal.jsonl")
    if os.path.exists(journal):  # events only (names, never values): for the host's checks
        summary["journal_kinds"] = sorted({json.loads(l).get("event", "?") for l in open(journal) if l.strip().startswith("{")})
    for name, src in (("surface.log", os.path.join(HOME, "surface.log")),):
        if os.path.exists(src):
            shutil.copy(src, os.path.join(out, name))
    with open(os.path.join(out, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)


if __name__ == "__main__":
    main()
