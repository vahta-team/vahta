"""T2: windows and timeouts with the scripted surface of a test build.

No session: N `vahta run` start at once, the scripted window answers after a
delay (`after_ms`, test-only). Records whether the windows open together or one
after another, total time, order and exit codes; what a client that is killed
while the window waits leaves behind; and how fast the refusals come.
Names, counts and times only."""

import json
import os
import signal
import threading
import time

import driver
from driver import Proc
from sandbox import K, PW, SERVER

SECRET = "MCP_PLAIN"


class Ctx:
    def __init__(self, sb, canaries, quick, vahta):
        self.sb, self.canaries, self.quick, self.vahta = sb, canaries, quick, vahta
        self.value = canaries[SECRET].encode()


class Watcher(threading.Thread):
    """Timestamps every line the scripted surface appends to its log."""

    def __init__(self, path):
        super().__init__(daemon=True)
        self.path, self.events, self.stop = path, [], threading.Event()
        self.pos, self.buf = 0, b""

    def run(self):
        while not self.stop.is_set():
            self.poll()
            time.sleep(0.01)
        self.poll()

    def poll(self):
        try:
            with open(self.path, "rb") as f:
                f.seek(self.pos)
                data = f.read()
        except OSError:
            return
        self.pos += len(data)
        self.buf += data
        while b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            try:
                e = json.loads(line)
            except ValueError:
                continue
            self.events.append((time.perf_counter(), e))


def reset_log(sb):
    open(sb.log_path, "w").close()


def kind(e):
    if "open" in e:
        return "open"
    if "close" in e:
        return "close"
    return "ask:" + str(e.get("ask"))


def overlap(events, t0):
    """Windows open at once, from the open/close events."""
    cur = peak = 0
    for t, e in events:
        k = kind(e)
        if k == "open":
            cur += 1
            peak = max(peak, cur)
        elif k == "close":
            cur -= 1
    return peak


def client(ctx, tag, secret=SECRET, cwd=None, argv_tail=None, extra=None):
    root = ctx.sb.root
    env = dict(ctx.sb.env)
    env.update({"MCP_FAKE_START_FILE": os.path.join(root, f"start-{tag}"),
                "MCP_FAKE_QUIT_ON_START": "1",
                "MCP_FAKE_PID_FILE": os.path.join(root, f"pid-{tag}")})
    env.update(extra or {})
    argv = [ctx.vahta, "run", "--secret", secret, "--"] + (argv_tail or ["python3", SERVER])
    return Proc(argv, env, cwd or ctx.sb.project)


def safe_text(ctx, b):
    s = bytes(b)
    assert ctx.value not in s
    return s.decode("utf-8", "replace").strip()[:300]


def started_at(ctx, tag, t0):
    f = os.path.join(ctx.sb.root, f"start-{tag}")
    if not os.path.exists(f):
        return None
    return round(os.stat(f).st_mtime - t0_wall(t0), 2)


_WALL = {}


def t0_wall(t0):
    return _WALL[t0]


def parallel(ctx, n, delay_s):
    sb = ctx.sb
    reset_log(sb)
    sb.script(*[{K: PW, "after_ms": int(delay_s * 1000)} for _ in range(n)], replace=True)
    w = Watcher(sb.log_path)
    w.start()
    cap = min(n * delay_s + 30, 330)
    t0 = time.perf_counter()
    _WALL[t0] = time.time()
    procs = [client(ctx, f"p{n}-{delay_s}-{i}") for i in range(n)]
    done = {}
    deadline = t0 + cap
    while len(done) < n and time.perf_counter() < deadline:
        for i, p in enumerate(procs):
            if i not in done and p.p.poll() is not None:
                done[i] = time.perf_counter() - t0
        time.sleep(0.02)
    timed_out = [i for i in range(n) if i not in done]
    for i in timed_out:
        procs[i].kill_group()
    for p in procs:
        p.settle(2)
    time.sleep(0.2)
    w.stop.set()
    w.join(2)
    passwords = [round(t - t0, 2) for t, e in w.events if kind(e) == "ask:password"]
    opens = [round(t - t0, 2) for t, e in w.events if kind(e) == "open"]
    closes = [round(t - t0, 2) for t, e in w.events if kind(e) == "close"]
    order = sorted(done, key=lambda i: done[i])
    rec = {
        "clients": n, "answer_delay_s": delay_s,
        "exit_codes": [procs[i].p.returncode for i in range(n)],
        "exit_times_s": [None if i not in done else round(done[i], 2) for i in range(n)],
        "total_s": round(max(done.values()), 2) if done else None,
        "started_command": [os.path.exists(os.path.join(sb.root, f"start-p{n}-{delay_s}-{i}")) for i in range(n)],
        "exit_order": order, "timed_out_clients": timed_out,
        "windows_opened": len(opens), "password_questions": len(passwords),
        "window_open_times_s": opens, "window_close_times_s": closes,
        "max_windows_open_at_once": overlap(w.events, t0),
        "stderr": sorted({safe_text(ctx, p.err) for p in procs if p.err}),
    }
    rec["mode"] = ("single" if n == 1 else "too fast to tell" if delay_s == 0 else
                   "concurrent" if rec["max_windows_open_at_once"] > 1 else "serialized")
    rec["pass"] = (not timed_out and all(c == 0 for c in rec["exit_codes"]))
    return rec


def gave_up(ctx, kill_at, delay):
    """The harness kills `vahta run` while the window waits for an answer."""
    sb = ctx.sb
    tag = f"gu{kill_at}"
    reset_log(sb)
    sb.script({K: PW, "after_ms": int(delay * 1000)}, replace=True)
    before = len(sb.journal())
    w = Watcher(sb.log_path)
    w.start()
    t0 = time.perf_counter()
    p = client(ctx, tag)
    while time.perf_counter() - t0 < kill_at:
        time.sleep(0.02)
    dpid = sb.daemon_status().get("pid")
    kids_before = daemon_children(dpid)
    asked = any(kind(e) == "ask:password" for _, e in w.events)
    status_before = sb.daemon_status()
    p.p.kill()  # SIGKILL: the harness gave up
    tk = time.perf_counter() - t0
    p.wait(5)
    p.settle(2)
    time.sleep(1.0)
    status_after = sb.daemon_status()
    closed_early = [round(t - t0, 2) for t, e in w.events if kind(e) == "close" and t - t0 < delay]
    # let the scripted answer arrive, then look for a start
    spawned = set()
    first_seen = None
    while time.perf_counter() - t0 < delay + 6:
        new = daemon_children(dpid) - kids_before
        if new and first_seen is None:
            first_seen = time.perf_counter() - t0
        spawned |= new
        time.sleep(0.002)
    w.stop.set()
    w.join(2)
    start_file = os.path.join(sb.root, f"start-{tag}")
    closes = [round(t - t0, 2) for t, e in w.events if kind(e) == "close"]
    jr = sb.journal()[before:]
    events = [{"event": j.get("event"), "result": j.get("result"), "detail": str(j.get("detail"))[:60]}
              for j in jr if j.get("event") in ("run", "run_refused")]
    rec = {
        "kill_at_s": kill_at, "answer_delay_s": delay, "killed_at_s": round(tk, 2),
        "question_was_open_at_kill": asked,
        "window_closed_before_answer_due": bool(closed_early),
        "window_close_times_s": closes,
        "command_started_afterwards": os.path.exists(start_file),
        "daemon_spawned_a_child_after_the_kill": bool(spawned),
        "child_first_seen_at_s": None if first_seen is None else round(first_seen, 2),
        "command_pid_file": os.path.exists(os.path.join(sb.root, f"pid-{tag}")),
        "script_lines_left": len([l for l in open(sb.script_path).read().splitlines() if l.strip()]),
        "daemon_connections_at_kill_plus_1s": status_after.get("connections"),
        "daemon_connections_at_kill": status_before.get("connections"),
        "journal_events_after": events,
    }
    # The scripted window cannot be withdrawn (it only ends when its answer is
    # due), so what is checked is the command: it must never start.
    rec["pass"] = asked and not rec["command_started_afterwards"] and not spawned
    return rec


def daemon_children(pid):
    """Pids of the daemon's direct children (any thread), or an empty set."""
    out = set()
    try:
        for tid in os.listdir(f"/proc/{pid}/task"):
            try:
                with open(f"/proc/{pid}/task/{tid}/children") as f:
                    out.update(int(x) for x in f.read().split())
            except OSError:
                pass
    except OSError:
        pass
    return out


def refusals(ctx):
    sb = ctx.sb
    out = {}

    def timed(label, p, cap=20):
        t = time.perf_counter()
        rc = p.wait(cap)
        took = time.perf_counter() - t
        if rc is None:
            p.kill_group()
        p.settle(2)
        out[label] = {"exit": rc, "seconds": round(took, 2), "stderr": safe_text(ctx, p.err),
                      "stdout_bytes": len(p.out), "command_started": os.path.exists(
                          os.path.join(sb.root, f"start-{label}"))}

    # no session, the person cancels the window
    reset_log(sb)
    sb.script({"cancel": True}, replace=True)
    timed("nosession_cancelled", client(ctx, "nosession_cancelled"))
    # no session, no answer in the script at all (a window that cannot be shown)
    reset_log(sb)
    sb.script(replace=True)
    timed("nosession_nowindow", client(ctx, "nosession_nowindow"))
    # a directory with no .vahta/ above it
    empty = os.path.join(sb.root, "empty")
    os.makedirs(empty, exist_ok=True)
    reset_log(sb)
    sb.script(replace=True)
    timed("cwd_without_vahta", client(ctx, "cwd_without_vahta", cwd=empty))
    out["cwd_without_vahta"]["windows_opened"] = len([e for e in sb.log_events() if "open" in e])

    # an expired session
    sb.script({K: PW}, replace=True)
    sb.must("unlock", "--for", "3s", "--secret", "MCP_QUOTE")
    sb.script({"noanswer": True}, {"noanswer": True}, replace=True)
    time.sleep(6)
    ask_log = sb.log_events()
    reset_log(sb)
    sb.script({"cancel": True}, replace=True)
    timed("expired_session", client(ctx, "expired_session", secret="MCP_QUOTE"))
    out["expired_session"]["windows_opened"] = len([e for e in sb.log_events() if "open" in e])
    out["expired_session"]["extension_question_asked"] = any(
        e.get("prompt") == "Extend this session?" for e in ask_log)

    # with a session
    sb.unlock()
    reset_log(sb)
    timed("command_not_allowed", client(ctx, "command_not_allowed", argv_tail=["python3", "/nonexistent-bench.py"]))
    out["command_not_allowed"]["windows_opened"] = len([e for e in sb.log_events() if "open" in e])
    reset_log(sb)
    timed("unknown_secret", client(ctx, "unknown_secret", secret="NOT_IN_VAULT"))

    # a stale session: the value changed after it was opened
    new = "mcq" + "x" * 3 + driver.__name__[:0] + "".join(reversed(ctx.canaries["MCP_QUOTE"].replace('"', "")[:20]))
    sb.script({K: PW}, {K: new}, {"choose": 0}, replace=True)
    r = sb.vahta("reset", SECRET)
    out["reset_secret"] = {"exit": r.returncode, "stderr": r.stderr.strip()[:200].replace(new, "<v>")}
    sb.script(replace=True)
    reset_log(sb)
    timed("stale_session", client(ctx, "stale_session"))
    out["stale_session"]["windows_opened"] = len([e for e in sb.log_events() if "open" in e])

    return out


def run(ctx):
    r = {}
    ns = (1, 3) if ctx.quick else (1, 3, 8)
    delays = (0, 2) if ctx.quick else (0, 5, 35)
    r["parallel"] = []
    for d in delays:
        for n in ns:
            t = time.time()
            rec = parallel(ctx, n, d)
            r["parallel"].append(rec)
            print(f"  t2 n={n} answer after {d}s: {rec['mode']}, total {rec['total_s']} s, "
                  f"exits {rec['exit_codes']} ({round(time.time() - t, 1)} s)", flush=True)
    r["parallel_pass"] = all(x["pass"] for x in r["parallel"])
    r["gave_up"] = []
    plan = [(2, 6)] if ctx.quick else [(10, 35), (30, 35)]
    for kill_at, delay in plan:
        rec = gave_up(ctx, kill_at, delay)
        r["gave_up"].append(rec)
        print(f"  t2 gave up at {kill_at}s: window closed early={rec['window_closed_before_answer_due']}, "
              f"command started afterwards={rec['command_started_afterwards']}", flush=True)
    r["gave_up_pass"] = all(x["pass"] for x in r["gave_up"])
    r["refusals"] = refusals(ctx)
    for k, v in r["refusals"].items():
        print(f"  t2 refusal {k}: exit {v.get('exit')} in {v.get('seconds')} s", flush=True)
    r["parallel"] = {"cases": r.pop("parallel"), "pass": r.pop("parallel_pass")}
    r["gave_up"] = {"cases": r.pop("gave_up"), "pass": r.pop("gave_up_pass")}
    r["refusals"]["pass"] = all(v.get("exit") not in (None, 0) and not v.get("command_started")
                                for k, v in r["refusals"].items() if isinstance(v, dict) and k != "reset_secret")
    return r
