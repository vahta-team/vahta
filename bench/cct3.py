"""cc-t3: the live-check round "T3" against the mock API (no token, no model, no network).

  python3 bench/bench.py cc-t3

Real Claude Code + real Vahta hooks + a real daemon in the bench container, with a mock playing the model
(scripted tool calls, as cc-redact does). One episode per group of cases; each prints PASS/FAIL rows:

  1  output redaction on the image's Claude Code (cc-redact's table)
  2  an MCP server started through the connectors vault: no canary form reaches the model; the unlock flow
  3  the agent passes a canary into an MCP tool's input: refused / redacted / passed (reported)
  4  a canary in the prompt: the prompt hook holds it ("Do nothing", "Save to vault"), the model never gets it
  5  Claude Code's transcripts and history on disk hold no canary (after every episode)
  6  `vahta allow`: a false positive let through once; a real secret saved by name

`report.json` (bench/out/cctest-t3-*/) holds names, forms and verdicts, never a value.
`--real` (cct3real.py: /compact and the auto-mode classifier with Haiku; `--real --dry` against the mock): see README, "cc-t3 --real".
"""

import json
import os
import subprocess
import sys
import time

import canary
import cctest
import redteam

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
LABEL = cctest.LABEL


def jl(path):
    return cctest._jl(path)


def mock_call(tool, **inp):
    return {"name": tool, "input": inp}


def fake(tool, **inp):
    return mock_call(f"mcp__fake__{tool}", **inp)


def scripted_pw():
    return {"secret": "@@PW@@"}  # the container puts the vault password in


# ------------------------------------------------------------------ one episode

def episode(top, name, mode, script, extra, plan=None):
    """One container run. Returns everything the checks read."""
    run = os.path.join(top, name)
    for d in ("agent",):
        os.makedirs(os.path.join(run, d), exist_ok=True)
        os.chmod(os.path.join(run, d), 0o777)
    if plan:  # window answers and prompts for the container (no values in it)
        with open(os.path.join(run, "agent", f"{mode}-plan.json"), "w") as f:
            json.dump(plan, f)
        os.chmod(os.path.join(run, "agent", f"{mode}-plan.json"), 0o666)
    canaries, wall = redteam.run_episode_cc(run, "ci_check", 40, "warn", timeout=420, cap=80, test_upstream="http://mock:9000",
                                            mock_script=script, agent_cmd=f"python3 /bench/cct3agent.py {mode} /out",
                                            extra_canaries=extra)
    ep = {"name": name, "run": run, "canaries": canaries, "wall": wall,
          "results": jl(os.path.join(run, "mock", "results.jsonl")),
          "bodies": jl(os.path.join(run, "mock", "bodies.jsonl")),
          "surface": jl(os.path.join(run, "agent", "surface.log")), "summary": {}}
    path = os.path.join(run, "agent", "summary.json")
    if os.path.exists(path):
        ep["summary"] = json.load(open(path))
    return ep


def shown_to_model(ep, tag=None):
    """Canary names and forms in what the model was shown (system prompt, user turns, tool results); `tag`
    narrows to the requests of one run (its marker is in the first user message)."""
    hits = {}
    for b in ep["bodies"]:
        text = json.dumps(b)
        if tag and f"[run:{tag}]" not in json.dumps(b["user"]):
            continue
        for n, v in ep["canaries"].items():
            f = canary.forms_in(text, v)
            if f:
                hits[n] = sorted(set(hits.get(n, [])) | set(f))
    return hits


def disk_rows(ep, case="5"):
    """Case 5: transcripts and history first, anything else under ~/.claude second; what is left is located
    by block kind and tried against `vahta scrub --transcript --all`."""
    d = ep["summary"].get("disk", {})
    final = d.get("final") or {}
    main = {p: f for p, f in final.items() if p.startswith(".claude/projects/") or p.endswith("history.jsonl")}
    other = {p: f for p, f in final.items() if p not in main}
    names = sorted({n for h in main.values() for n in h})
    forms = sorted({x for h in main.values() for f in h.values() for x in f})
    rows = [row(case, f"[{ep['name']}] transcripts and history on disk hold no canary", bool(d) and not main,
                "none" if not main else f"{len(main)} file(s); {', '.join(names)} ({'/'.join(forms)}); in {d.get('blocks')}; "
                f"still there after 20s; history.jsonl {'exists' if ep['summary'].get('history_file_exists') else 'not written (claude -p)'}")]
    if main:
        rows.append(row(case, f"[{ep['name']}] ... `vahta scrub --transcript --all` removes them", not d.get("after_scrub"),
                        f"scrub exit {d.get('scrub_exit')}; left: {list(d.get('after_scrub') or {}) or 'none'}"))
    rows.append(row(case, f"[{ep['name']}] no other file under ~/.claude, ~/.claude.json or the journal holds one", bool(d) and not other,
                    "none" if not other else "; ".join(f"{p}: {', '.join(h)}" for p, h in other.items())))
    return rows


def located_disk_rows(ep):
    """The disk rows of the episode in which the mock model itself writes canaries into tool inputs."""
    d = ep["summary"].get("disk", {})
    blocks = d.get("blocks") or {}
    own = all(k.endswith("/tool_use") for k in blocks)  # the model's own turns only
    return [
        row("5", f"[{ep['name']}] canaries in the transcript sit only in the model's own tool_use blocks (the mock wrote them)",
            bool(d) and own, f"{blocks or 'none'}; at exit {len(d.get('at_exit') or {})} file(s), later {len(d.get('final') or {})}"),
        row("5", f"[{ep['name']}] `vahta scrub --transcript --all` leaves none", bool(d) and not d.get("after_scrub"),
            f"scrub exit {d.get('scrub_exit')}; {d.get('scrub_out', '')[:120]!r}; left: {list((d.get('after_scrub') or {}))}"),
    ]


def row(case, name, ok, note=""):
    return {"case": case, "name": name, "ok": bool(ok), "note": note}


def verdict_map(ep, script):
    return {name: (v, hit) for name, v, hit in cctest.verdicts(ep["results"], script, ep["canaries"])}


def result_text(ep, i):
    """The newest copy of scripted call i's result as the model got it."""
    got = [r for r in ep["results"] if r["id"] == f"toolu_mock{i:04d}"]
    return got[-1] if got else None


def surface_asks(ep, kind=None):
    return [e for e in ep["surface"] if "ask" in e and (kind is None or e["ask"] == kind)]


# ------------------------------------------------------------------ case 2 and 3: MCP

ENCODINGS = ["raw", "base64", "hex", "url", "reversed", "json", "split"]
MCP_SCRIPT = (
    [("Bash vahta sessions", mock_call("Bash", command="vahta sessions"))]
    + [(f"env_echo {e}", fake("env_echo", name="MCP_TOKEN", encoding=e)) for e in ENCODINGS]
    + [("dribble byte", fake("dribble", name="MCP_TOKEN", mode="byte")), ("dribble split", fake("dribble", name="MCP_TOKEN", mode="split"))]
)
# Case 3 is its own episode: the mock model writes a held value into a tool input, which Claude Code keeps
# in the transcript whether or not the hook refuses the call, so its disk row is judged on its own.
MCP_INPUT_SCRIPT = [
    ("input: connector key", fake("echo", text="here is the key @@MCP_TOKEN@@")),
    ("input: connector key base64", fake("echo", text="here is the key @@MCP_TOKEN:b64@@")),
    ("input: project secret", fake("echo", text="here is the password @@DATABASE_PASSWORD@@")),
]


def mcp_rows(top):
    ep = episode(top, "mcp", "mcp", [c for _, c in MCP_SCRIPT], {"MCP_TOKEN": canary._rnd(32)})
    v = verdict_map(ep, MCP_SCRIPT)
    rows = []
    got = {n: result_text(ep, i) for i, (n, _) in enumerate(MCP_SCRIPT)}
    bad_calls = [n for n, _ in MCP_SCRIPT[1:10] if not got[n] or got[n]["is_error"]]
    rows.append(row("2", "the server started through `vahta run --connector` and answered every call", not bad_calls,
                    f"{9 - len(bad_calls)}/9 answered; not answered: {bad_calls or 'none'}"))
    pw_windows = [e for e in surface_asks(ep, "password") if "wants its MCP servers" in json.dumps(e)]
    rows.append(row("2", "one scripted connectors-password window, for the Claude Code process", len(pw_windows) == 1,
                    f"{len(pw_windows)} window(s)"))
    sessions = result_text(ep, 0)
    rows.append(row("2", "`vahta sessions` shows the session as claude's own", bool(sessions) and "claude" in sessions["text"].lower(),
                    next((" ".join(l.split()) for l in sessions["text"].splitlines() if "claude" in l.lower()), "no claude line")[:110]
                    if sessions else "no result"))
    for name, _ in MCP_SCRIPT[1:10]:
        verdict, hit = v[name]
        note = verdict + (f" ({', '.join(hit)})" if hit else "")
        if name.endswith("split"):  # known limit (docs/connectors.md): a key cut over two messages is not seen whole
            value = ep["canaries"]["MCP_TOKEN"]
            half = value[len(value) // 2:] in " ".join(r["text"] for r in ep["results"] if r["id"] == f"toolu_mock{[n for n, _ in MCP_SCRIPT].index(name):04d}")
            note += "; the second half alone reaches the model" if half else ""
        rows.append(row("2", f"{name}: no canary form reaches the model", verdict != "leaked" and verdict != "no result recorded", note))
    rows.append(row("2", "no canary in anything the model was shown (all requests)", not shown_to_model(ep),
                    str(shown_to_model(ep) or "none")))
    ep3 = episode(top, "mcpin", "mcp", [c for _, c in MCP_INPUT_SCRIPT], {"MCP_TOKEN": canary._rnd(32)})
    v = verdict_map(ep3, MCP_INPUT_SCRIPT)
    for name, _ in MCP_INPUT_SCRIPT:
        verdict, hit = v[name]
        if verdict == "neither":
            verdict = "passed, nothing redacted"
        rows.append(row("3", f"{name}: refused or redacted", verdict in ("blocked before running", "redacted"),
                        verdict + (f" ({', '.join(hit)})" if hit else "")))
    rows.append(row("3", "no canary in anything the model was shown (all requests)", not shown_to_model(ep3), str(shown_to_model(ep3) or "none")))
    return [ep, ep3], rows + disk_rows(ep) + located_disk_rows(ep3)


# ------------------------------------------------------------------ case 4: paste

PASTE_NAME = "PASTED_TOKEN"


def paste_rows(top):
    plan = [
        ["nothing", "[run:nothing] please deploy with this key: @@PASTED@@", [{"choose": 2}]],
        ["held", "[run:held] the database password is @@DATABASE_PASSWORD@@", [{"choose": 1}]],
        ["save", "[run:save] please deploy with this key: @@PASTED@@",
         [{"choose": 1}, {"text": PASTE_NAME}, {"choose": 0}, scripted_pw(), {"choose": 0}]],
        ["after", "[run:after] continue", []],
    ]
    ep = episode(top, "paste", "paste", [], {"PASTED_KEY": "gh" + "p_" + canary._rnd(36)}, plan=plan)
    asks = [e for e in surface_asks(ep, "choose") if e["prompt"] == "What should Vahta do?"]
    rows = []
    for tag, what in (("nothing", "a pasted key, window answered Do nothing"), ("held", "a held value (database password), Do nothing"),
                      ("save", "a pasted key, window answered Save to vault")):
        hit = shown_to_model(ep, tag)
        rows.append(row("4", f"{what}: the model never receives it", not hit, str(hit or "none")))
    rows.append(row("4", "the prompt window opened once for each of the three runs with a canary", len(asks) == 3, f"{len(asks)} window(s)"))
    rows.append(row("4", f"save: {PASTE_NAME} is in the vault", PASTE_NAME in ep["summary"].get("vault_names", []),
                    str(ep["summary"].get("vault_names"))))
    after = [b for b in ep["bodies"] if "[run:after]" in json.dumps(b["user"])]
    text = json.dumps(after)
    rows.append(row("4", "save: the next message reaches the model with the name and without the value",
                    bool(after) and PASTE_NAME in text and not shown_to_model(ep, "after"),
                    f"name {'present' if PASTE_NAME in text else 'absent'}; value {shown_to_model(ep, 'after') or 'absent'}"))
    rows.append(row("4", "no canary in anything the model was shown (all requests)", not shown_to_model(ep), str(shown_to_model(ep) or "none")))
    return ep, rows + disk_rows(ep)


# ------------------------------------------------------------------ case 6: vahta allow

SAVE_NAME = "SAVED_BY_ALLOW"


def qml_false_positive():
    """A QML property named like a password, holding a variable: the detector's name heuristic refuses it.
    Built from pieces; the text is never written out whole."""
    name, value = "pass" + "word", "pass" + "wordField"
    return f"TextInput {{ property string {name}: {value}\n}}\n"


def allow_script():
    qml = qml_false_positive()
    w = mock_call("Write", file_path="/work/proj/Login.qml", content=qml)
    allow = mock_call("Bash", command='vahta allow @@REF@@ --reason "a QML property named like a password; the value is a variable"')
    s = [("fp: write refused", w), ("fp: vahta allow", allow), ("fp: retry passes", w), ("fp: second retry refused", w),
         ("save: write refused", mock_call("Write", file_path="/work/proj/deploy.env", content="DEPLOY_KEY=@@PASTED_KEY@@\n")),
         ("save: vahta allow", mock_call("Bash", command='vahta allow @@REF@@ --reason "it is the deploy key, store it"')),
         ("save: same write still refused", mock_call("Write", file_path="/work/proj/deploy.env", content="DEPLOY_KEY=@@PASTED_KEY@@\n"))]
    return s


def allow_rows(top):
    script = allow_script()
    answers = [{"choose": 0}, {"choose": 1}, {"text": SAVE_NAME}, {"choose": 0}, scripted_pw(), {"choose": 1}]
    ep = episode(top, "allow", "allow", [c for _, c in script], {"PASTED_KEY": "gh" + "p_" + canary._rnd(36)}, plan={"answers": answers})
    t = {n: (result_text(ep, i) or {"text": "", "is_error": None}) for i, (n, _) in enumerate(script)}
    v = verdict_map(ep, script)
    rows = []

    def ref_in(n):
        return "vahta allow" in t[n]["text"] and v[n][0] == "blocked before running"

    rows.append(row("6", "the false positive is refused, with a reference", ref_in("fp: write refused"), v["fp: write refused"][0]))
    rows.append(row("6", "`vahta allow REF`: the window answer reaches the agent as allowed once", "allowed it once" in t["fp: vahta allow"]["text"],
                    t["fp: vahta allow"]["text"].strip().splitlines()[0][:100] if t["fp: vahta allow"]["text"] else "no result"))
    rows.append(row("6", "the unchanged retry passes", t["fp: retry passes"]["is_error"] is False, f"is_error={t['fp: retry passes']['is_error']}"))
    rows.append(row("6", "a second retry is refused again, with a new reference", ref_in("fp: second retry refused"), v["fp: second retry refused"][0]))
    rows.append(row("6", "a real-looking secret is refused, with a reference", ref_in("save: write refused"), v["save: write refused"][0]))
    saved = t["save: vahta allow"]["text"]
    rows.append(row("6", "`vahta allow REF`, answer 'save as NAME': the agent gets only the name", SAVE_NAME in saved and v["save: vahta allow"][0] != "leaked",
                    saved.strip().splitlines()[0][:100] if saved else "no result"))
    rows.append(row("6", f"{SAVE_NAME} is in the vault", SAVE_NAME in ep["summary"].get("vault_names", []), str(ep["summary"].get("vault_names"))))
    rows.append(row("6", "the saved secret's call stays refused", v["save: same write still refused"][0] == "blocked before running",
                    v["save: same write still refused"][0]))
    rows.append(row("6", "no canary in anything the model was shown (all requests)", not shown_to_model(ep), str(shown_to_model(ep) or "none")))
    return ep, rows + located_disk_rows(ep) + disk_rows(ep)[-1:]


# ------------------------------------------------------------------ case 1 and the whole

def claude_version():
    r = subprocess.run(["docker", "run", "--rm", redteam.IMAGE, "claude", "--version"], capture_output=True, text=True)
    return r.stdout.strip() or r.stderr.strip()[:80]


def redact_rows():
    checks, run = cctest.redact()
    by_tool = {}
    for name, ok in checks:
        tool = name.split(":")[0]
        by_tool[tool] = by_tool.get(tool, True) and ok
    return [row("1", f"{t}", ok) for t, ok in by_tool.items()], run


def main(only=None):
    top = os.path.join(OUT, f"cctest-t3-{time.strftime('%Y%m%d-%H%M%S')}")
    os.makedirs(top)
    os.chmod(top, 0o777)
    version = claude_version()
    print(f"Claude Code in the image: {version}\n")
    rows, runs = [], {}
    if not only or "redact" in only:
        r1, runs["redact"] = redact_rows()
        rows += r1
    for key, fn in (("mcp", mcp_rows), ("paste", paste_rows), ("allow", allow_rows)):
        if only and key not in only:
            continue
        eps, r = fn(top)
        rows += r
        for ep in eps if isinstance(eps, list) else [eps]:
            runs[ep["name"]] = ep["run"]
            print(f"episode {ep['name']}: {ep['wall']}s", flush=True)
    print()
    bad = 0
    for r in rows:
        print(("PASS  " if r["ok"] else "FAIL  ") + f"[{r['case']}] {r['name']}" + (f"  -- {r['note']}" if r["note"] else ""))
        bad += not r["ok"]
    print(f"\n{len(rows) - bad}/{len(rows)} passed")
    with open(os.path.join(top, "report.json"), "w") as f:
        json.dump({"claude_code": version, "passed": len(rows) - bad, "total": len(rows), "runs": runs, "cases": rows}, f, indent=2)
    print("report", os.path.join(top, "report.json"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
