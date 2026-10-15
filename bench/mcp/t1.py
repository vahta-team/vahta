"""T1: a fake stdio MCP server under `vahta run`: latency, framing, leakage,
stalls, lifecycle. See run.py. Everything recorded is a name, a count, a time
or a form; no canary value is ever put in the report."""

import json
import os
import signal
import time

import driver
from driver import Proc
from sandbox import SERVER

STALL_S = 3.0  # a reply later than this counts as a stall


class Ctx:
    def __init__(self, sb, canaries, quick, rejected):
        self.sb, self.canaries, self.quick, self.rejected = sb, canaries, quick, rejected

    def launch(self, mode, names, extra=None):
        env = dict(self.sb.env)
        env.update(extra or {})
        if mode == "direct":
            for k in [k for k in env if k.startswith("VAHTA")]:
                del env[k]
            for n in names:
                env[n] = self.canaries[n]
            argv = ["python3", SERVER]
        else:
            argv = [self.sb.vahta_bin, "run"]
            for n in names:
                argv += ["--secret", n]
            argv += ["--", "python3", SERVER]
        return Proc(argv, env, self.sb.project)


def text_of(msg):
    try:
        return msg["result"]["content"][0]["text"]
    except (KeyError, IndexError, TypeError):
        return None


def finish(p, timeout=8):
    p.close_stdin()
    rc = p.wait(timeout)
    if rc is None:
        p.kill_group()
    p.settle()
    return rc


# -- 1. sequential latency ------------------------------------------------------
def latency(ctx):
    n = 200 if ctx.quick else 1000
    out = {}
    for mode in ("direct", "vahta"):
        t = time.perf_counter()
        p = ctx.launch(mode, ["MCP_PLAIN"])
        hs = p.handshake(20)
        startup = None if hs is None else time.perf_counter() - t
        lat, fails = [], 0
        for i in range(n + 20):
            r = p.tool("echo", {"text": "ping %d" % i}, 10)
            if r is None or text_of(r[1]) != "ping %d" % i:
                fails += 1
            elif i >= 20:
                lat.append(r[0])
        rc = finish(p)
        out[mode] = {"startup_ms": None if startup is None else round(startup * 1000, 1),
                     "calls": n, "failures": fails, "exit": rc, **driver.lat_summary(lat)}
    d, v = out["direct"], out["vahta"]
    if d.get("p50_ms") and v.get("p50_ms"):
        out["added_p50_ms"] = round(v["p50_ms"] - d["p50_ms"], 3)
        out["added_p99_ms"] = round(v["p99_ms"] - d["p99_ms"], 3)
    out["pass"] = d["failures"] == 0 and v["failures"] == 0
    return out


# -- 2. sizes and concurrency ----------------------------------------------------
def sizes(ctx):
    plan = [(1024, 10), (100 * 1024, 5), (1024 * 1024, 3), (5 * 1024 * 1024, 1 if ctx.quick else 2)]
    out = {}
    ok = True
    for mode in ("direct", "vahta"):
        p = ctx.launch(mode, ["MCP_PLAIN"])
        p.handshake(20)
        res = {}
        for size, reps in plan:
            times, bad = [], 0
            for _ in range(reps):
                r = p.tool("big", {"bytes": size}, 120)
                t = text_of(r[1]) if r else None
                if r is None or t is None or len(t) != size:
                    bad += 1
                else:
                    times.append(r[0])
            res[str(size)] = {"reps": reps, "bad": bad,
                              "median_ms": round(1000 * driver.pct(times, 50), 2) if times else None,
                              "max_ms": round(1000 * max(times), 2) if times else None,
                              "mb_per_s": round(size / driver.pct(times, 50) / 1e6, 1) if times else None}
            ok &= bad == 0
        _, bad_json, _ = driver.check_lines(p.lines)
        res["invalid_json_lines"] = bad_json
        ok &= bad_json == 0
        res["exit"] = finish(p)
        out[mode] = res
    out["pass"] = ok
    return out


def concurrent(ctx, n=50):
    out = {}
    ok = True
    for mode in ("direct", "vahta"):
        p = ctx.launch(mode, ["MCP_PLAIN"])
        p.handshake(20)
        t = time.perf_counter()
        ids = {}
        for i in range(n):
            if i % 2:
                ids[p.request("tools/call", {"name": "big", "arguments": {"bytes": 64 * 1024}})] = 64 * 1024
            else:
                ids[p.request("tools/call", {"name": "echo", "arguments": {"text": "x" * 4096}})] = 4096
        got = {}
        deadline = time.perf_counter() + 60
        while len(got) < n and time.perf_counter() < deadline:
            try:
                item = p.recv(max(0.1, deadline - time.perf_counter()))
            except EOFError:
                break
            if item is None:
                break
            try:
                m = json.loads(item[1])
            except ValueError:
                continue
            if m.get("id") in ids:
                got[m["id"]] = text_of(m)
        elapsed = time.perf_counter() - t
        right = sum(1 for i, s in ids.items() if got.get(i) is not None and len(got[i]) == s)
        out[mode] = {"requests": n, "answered": len(got), "correct": right,
                     "total_ms": round(elapsed * 1000, 1), "exit": finish(p)}
        ok &= right == n
    out["pass"] = ok
    return out


# -- helpers for leak checks ---------------------------------------------------------
def leak_report(p, value):
    wire = bytes(p.out) + b"\n" + bytes(p.err)
    decoded = "\n".join(driver.texts_of(p.lines)).encode("latin-1", "replace")
    return {"wire": driver.forms_leaked(wire, value),
            "decoded": driver.forms_leaked(decoded, value),
            "split_halves": driver.split_halves_leaked(driver.texts_of(p.lines), value)}


def call_lines(p, i0):
    return p.lines[i0:]


# -- 3. one byte at a time, and a write cut inside the secret ----------------------------
def dribble(ctx):
    out = {}
    ok = True
    value = ctx.canaries["MCP_PLAIN"].encode()
    counts = {}
    for mode in ("direct", "vahta"):
        p = ctx.launch(mode, ["MCP_PLAIN"])
        p.handshake(20)
        res = {}
        for how in ("byte", "split"):
            i0 = len(p.lines)
            r = p.tool("dribble", {"name": "MCP_PLAIN", "mode": how}, 20)
            lines = call_lines(p, i0)
            blob = b"\n".join(l for _, l in lines)
            res[how] = {"answered": r is not None,
                        "latency_ms": None if r is None else round(r[0] * 1000, 1),
                        "raw_on_wire": b"" != blob and value in blob,
                        "marker_seen": b"***REDACTED(MCP_PLAIN)***" in blob if mode == "vahta" else None,
                        "invalid_json": driver.check_lines(lines)[1]}
        res["exit"] = finish(p)
        res["stderr_leak"] = value in bytes(p.err)
        counts[mode] = len(p.lines)
        out[mode] = res
    v = out["vahta"]
    out["message_count"] = counts
    ok = (all(v[h]["answered"] and not v[h]["raw_on_wire"] and v[h]["invalid_json"] == 0 for h in ("byte", "split"))
          and not v["stderr_leak"] and counts["direct"] == counts["vahta"])
    out["pass"] = ok
    return out


# -- 4. the canary in every encoding ------------------------------------------------
ENC_FORM = {"raw": "raw", "base64": "base64", "hex": "hex", "url": "url", "reversed": "reversed",
            "json": "json_escaped", "split": "split_halves"}


def encodings(ctx):
    names = ["MCP_PLAIN", "MCP_QUOTE"]
    plan = [("MCP_PLAIN", e) for e in ("raw", "base64", "hex", "url", "reversed", "split")]  # (`json` equals `raw` for a value with no quote)
    plan += [("MCP_QUOTE", e) for e in ("raw", "json", "base64", "split")]
    results = {}
    counts = {}
    invalid = {}
    for mode in ("direct", "vahta"):
        p = ctx.launch(mode, names)
        p.handshake(20)
        for name, enc in plan:
            value = ctx.canaries[name].encode()
            i0 = len(p.lines)
            r = p.tool("env_echo", {"name": name, "encoding": enc}, STALL_S + 2)
            lines = call_lines(p, i0)
            wire = b"\n".join(l for _, l in lines)
            decoded = "\n".join(driver.texts_of(lines)).encode("latin-1", "replace")
            rec = results.setdefault(f"{name}/{enc}", {})
            rec[mode] = {"answered": r is not None,
                         "wire": driver.forms_leaked(wire, value),
                         "decoded": driver.forms_leaked(decoded, value),
                         "split_halves": driver.split_halves_leaked(driver.texts_of(lines), value)}
        counts[mode] = len(p.lines)
        invalid[mode] = driver.check_lines(p.lines)[1]
        rcs = finish(p)
        results.setdefault("_whole_run", {})[mode] = {
            "exit": rcs, "stderr_bytes": len(p.err),
            "plain_raw_on_stdout": "raw" in driver.forms_leaked(bytes(p.out), ctx.canaries["MCP_PLAIN"].encode()),
            "plain_raw_on_stderr": "raw" in driver.forms_leaked(bytes(p.err), ctx.canaries["MCP_PLAIN"].encode()),
            "quote_raw_on_stdout": "raw" in driver.forms_leaked(bytes(p.out), ctx.canaries["MCP_QUOTE"].encode()),
            "quote_raw_on_stderr": "raw" in driver.forms_leaked(bytes(p.err), ctx.canaries["MCP_QUOTE"].encode())}
    table = []
    for name, enc in plan:
        rec = results[f"{name}/{enc}"]
        want = ENC_FORM[enc]

        def has(mode, where):
            x = rec[mode][where]
            return bool(x) if where == "split_halves" else want in x or (enc == "raw" and name == "MCP_QUOTE" and "json_escaped" in x)

        emitted = has("direct", "wire") or has("direct", "decoded") or rec["direct"]["split_halves"] and enc == "split"
        if enc == "split":
            leaked_v = rec["vahta"]["split_halves"]
            emitted = rec["direct"]["split_halves"]
        elif enc == "raw" and name == "MCP_QUOTE":
            # on the wire the quote is escaped; the harness decodes it, so judge both
            leaked_v = bool(rec["vahta"]["decoded"]) or bool(rec["vahta"]["wire"])
            emitted = bool(rec["direct"]["decoded"]) or bool(rec["direct"]["wire"])
        else:
            leaked_v = has("vahta", "wire") or has("vahta", "decoded")
        table.append({"secret": name, "encoding": enc, "form": want, "emitted_by_server": bool(emitted),
                      "answered_under_vahta": rec["vahta"]["answered"],
                      "scrubbed": bool(emitted) and not leaked_v,
                      "passed_through": bool(emitted) and bool(leaked_v),
                      "wire_forms_under_vahta": rec["vahta"]["wire"],
                      "decoded_forms_under_vahta": rec["vahta"]["decoded"]})
    whole = results["_whole_run"]["vahta"]
    out = {"table": table, "message_count": counts, "invalid_json_lines": invalid,
           "whole_run": results["_whole_run"],
           "pass": (counts["direct"] == counts["vahta"] and invalid["vahta"] == 0
                    and not whole["plain_raw_on_stdout"] and not whole["plain_raw_on_stderr"]
                    and not whole["quote_raw_on_stderr"]
                    and all(t["answered_under_vahta"] for t in table))}
    out["not_covered"] = [f'{t["secret"]}/{t["encoding"]}' for t in table if t["passed_through"]]
    out["scrubbed_forms"] = [f'{t["secret"]}/{t["encoding"]}' for t in table if t["scrubbed"]]
    return out


# -- 5. adversarial canaries ------------------------------------------------------------
def adv_sequence(name, value):
    seq = [("tools/call", {"name": "echo", "arguments": {"text": "one"}}),
           ("tools/call", {"name": "echo", "arguments": {"text": "two"}}),
           ("tools/call", {"name": "env_echo", "arguments": {"name": name, "encoding": "len"}}),
           ("tools/call", {"name": "env_echo", "arguments": {"name": name, "encoding": "raw"}}),
           ("tools/call", {"name": "echo", "arguments": {"text": value.decode("latin-1") * 2 + " end"}}),
           ("tools/call", {"name": "echo", "arguments": {"text": "three"}})]
    return seq


def play(p, seq):
    steps = []
    wait = STALL_S  # after the first stall, later steps get a short look only
    hs = p.call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}}, wait)
    steps.append(("initialize", hs is not None))
    if hs is None:
        wait = 0.3
    p.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    for method, params in seq:
        r = p.call(method, params, wait)
        steps.append((params.get("name", method), r is not None))
        if r is None:
            wait = 0.3
    return steps


def adversarial(ctx):
    out = {}
    for name in [n for n in ctx.canaries if n.startswith("ADV_")]:
        if name in ctx.rejected:
            out[name] = {"skipped": "vault refused it: " + ctx.rejected[name]}
            continue
        value = ctx.canaries[name].encode()
        seq = adv_sequence(name, value)
        pd = ctx.launch("direct", [name])
        play(pd, seq)
        finish(pd)
        expected = len(pd.lines)
        t = time.perf_counter()
        p = ctx.launch("vahta", [name])
        steps = play(p, seq)
        before_close = len(p.lines)
        stalled = [s for s, ok in steps if not ok]
        rc = finish(p)
        out[name] = {
            "length": len(value), "starts_with": "newline" if value[:1] == b"\n" else "other",
            "steps": len(steps), "stalled_steps": stalled, "stall": bool(stalled),
            "lines_expected": expected, "lines_before_close": before_close,
            "lines_total": len(p.lines), "exit": rc,
            "elapsed_s": round(time.perf_counter() - t, 1),
            "invalid_json": driver.check_lines(p.lines)[1],
            "leak": leak_report(p, value)}
    probed = {k: v for k, v in out.items() if "skipped" not in v}
    out["pass"] = all(not v["stall"] and not v["leak"]["wire"] and v["lines_total"] == v["lines_expected"]
                      for v in probed.values())
    out["stalled"] = [k for k, v in probed.items() if v["stall"]]
    return out


# -- 6. lifecycle -----------------------------------------------------------------------
def lifecycle(ctx):
    root = ctx.sb.root
    out = {}

    def files(tag):
        return {"MCP_FAKE_PID_FILE": os.path.join(root, f"{tag}.pid"),
                "MCP_FAKE_TERM_FILE": os.path.join(root, f"{tag}.term")}

    for mode in ("direct", "vahta"):
        e = files(f"close-{mode}")
        p = ctx.launch(mode, ["MCP_PLAIN"], e)
        hs = p.handshake(20)
        pid = driver.read_pid(e["MCP_FAKE_PID_FILE"])
        t = time.perf_counter()
        p.close_stdin()
        rc = p.wait(10)
        took = time.perf_counter() - t
        gone = _wait_gone(pid, 5)
        p.settle()
        out[f"close_stdin_{mode}"] = {"handshake": hs is not None, "exit": rc, "exit_after_ms": round(took * 1000),
                                      "server_pid_seen": pid is not None, "server_gone": gone,
                                      "pass": rc == 0 and gone}
        if rc is None:
            p.kill_group()

    e = files("kill")
    p = ctx.launch("vahta", ["MCP_PLAIN"], e)
    p.handshake(20)
    pid = driver.read_pid(e["MCP_FAKE_PID_FILE"])
    seen_alive = bool(pid and driver.alive(pid))
    t = time.perf_counter()
    p.p.kill()  # SIGKILL to `vahta run` alone
    gone_in = None
    while time.perf_counter() - t < 10:
        if not driver.alive(pid):
            gone_in = time.perf_counter() - t
            break
        time.sleep(0.02)
    p.wait(5)
    p.settle()
    out["sigkill_vahta_run"] = {"server_pid_seen": pid is not None, "server_alive_before": seen_alive,
                                "server_gone_after_s": None if gone_in is None else round(gone_in, 2),
                                "pass": seen_alive and gone_in is not None and gone_in <= 3.0}
    if pid and driver.alive(pid):
        try:
            os.kill(pid, signal.SIGKILL)  # tidy up our own fake server
        except OSError:
            pass

    for mode in ("direct", "vahta"):
        e = files(f"term-{mode}")
        p = ctx.launch(mode, ["MCP_PLAIN"], e)
        p.handshake(20)
        pid = driver.read_pid(e["MCP_FAKE_PID_FILE"])
        t = time.perf_counter()
        p.signal(signal.SIGTERM)
        rc = p.wait(10)
        took = time.perf_counter() - t
        time.sleep(0.2)
        got = os.path.exists(e["MCP_FAKE_TERM_FILE"])
        gone = _wait_gone(pid, 3)
        p.settle()
        out[f"sigterm_{mode}"] = {"exit": rc, "exit_after_ms": round(took * 1000), "server_got_sigterm": got,
                                  "server_gone": gone, "pass": got and gone and rc is not None}
        if rc is None:
            p.kill_group()
    out["pass"] = all(v.get("pass") for v in out.values() if isinstance(v, dict))
    return out


def _wait_gone(pid, secs):
    if not pid:
        return False
    end = time.time() + secs
    while time.time() < end:
        if not driver.alive(pid):
            return True
        time.sleep(0.02)
    return not driver.alive(pid)


def run(ctx):
    global STALL_S
    STALL_S = 1.5 if ctx.quick else 3.0
    r = {}
    for name, fn in (("latency", latency), ("sizes", sizes), ("concurrent_50", concurrent),
                     ("one_byte_writes", dribble), ("encodings", encodings),
                     ("adversarial", adversarial), ("lifecycle", lifecycle)):
        t = time.time()
        try:
            r[name] = fn(ctx)
        except Exception as e:  # a crashed case is a finding, not a dead run
            r[name] = {"pass": False, "error": f"{type(e).__name__}: {e}"[:300]}
        r[name]["wall_s"] = round(time.time() - t, 1)
        print(f"  t1 {name}: {'pass' if r[name].get('pass') else 'FAIL'} ({r[name]['wall_s']} s)", flush=True)
    return r
