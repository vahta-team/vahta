"""The harness side of the Vahta MCP bench: spawn a stdio MCP server (directly
or under `vahta run`), send JSON-RPC lines, read replies with timestamps, and
look for a canary in what came back. Standard library only.

The leak finder works on bytes the bench already holds; it reports forms by
name and never returns or prints a value.
"""

import base64
import json
import os
import queue
import signal
import subprocess
import threading
import time
import urllib.parse


class Proc:
    """A child with line-timestamped stdout and fully captured stderr."""

    def __init__(self, argv, env, cwd=None):
        self.t0 = time.perf_counter()
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, env=env, cwd=cwd, bufsize=0,
                                  start_new_session=True)
        self.q = queue.Queue()
        self.out = bytearray()
        self.err = bytearray()
        self.lines = []  # (t, bytes) as they arrived
        self._buf = bytearray()
        self._threads = [threading.Thread(target=self._read_out, daemon=True),
                         threading.Thread(target=self._read_err, daemon=True)]
        for t in self._threads:
            t.start()
        self.next_id = 1

    def _read_out(self):
        fd = self.p.stdout
        while True:
            chunk = fd.read(65536)
            if not chunk:
                break
            self.out += chunk
            self._buf += chunk
            while True:
                i = self._buf.find(b"\n")
                if i < 0:
                    break
                line = bytes(self._buf[:i])
                del self._buf[: i + 1]
                t = time.perf_counter()
                self.lines.append((t, line))
                self.q.put((t, line))
        self.q.put(None)

    def _read_err(self):
        fd = self.p.stderr
        while True:
            chunk = fd.read(65536)
            if not chunk:
                break
            self.err += chunk

    # -- JSON-RPC -------------------------------------------------------
    def send(self, obj):
        data = (json.dumps(obj, separators=(",", ":")) + "\n").encode()
        self.p.stdin.write(data)

    def request(self, method, params=None):
        mid = self.next_id
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})
        return mid

    def recv(self, timeout):
        """The next (t, line), or None on timeout; raises EOFError at end of stream."""
        try:
            item = self.q.get(timeout=timeout)
        except queue.Empty:
            return None
        if item is None:
            self.q.put(None)
            raise EOFError
        return item

    def response(self, mid, timeout=10.0):
        """Read lines until the response with id `mid`; returns (t, parsed, others)
        where others are the other messages seen first. None if it times out."""
        deadline = time.perf_counter() + timeout
        others = []
        while True:
            left = deadline - time.perf_counter()
            if left <= 0:
                return None
            try:
                got = self.recv(left)
            except EOFError:
                return None
            if got is None:
                return None
            t, line = got
            try:
                msg = json.loads(line)
            except ValueError:
                others.append(("invalid", line))
                continue
            if msg.get("id") == mid:
                return t, msg, others
            others.append(("msg", msg))

    def call(self, method, params=None, timeout=10.0):
        t = time.perf_counter()
        mid = self.request(method, params)
        r = self.response(mid, timeout)
        return None if r is None else (r[0] - t, r[1], r[2])

    def tool(self, name, arguments=None, timeout=10.0):
        return self.call("tools/call", {"name": name, "arguments": arguments or {}}, timeout)

    def handshake(self, timeout=15.0):
        r = self.call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                     "clientInfo": {"name": "bench", "version": "0"}}, timeout)
        if r is None:
            return None
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return r[0] if self.call("tools/list", None, timeout) else None

    # -- lifecycle --------------------------------------------------------
    def close_stdin(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass

    def wait(self, timeout):
        try:
            return self.p.wait(timeout)
        except subprocess.TimeoutExpired:
            return None

    def signal(self, sig):
        try:
            self.p.send_signal(sig)
        except ProcessLookupError:
            pass

    def kill_group(self):
        try:
            os.killpg(self.p.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        self.close_stdin()
        self.wait(5)

    def settle(self, timeout=3.0):
        """Wait for the reader threads (the streams ended)."""
        for t in self._threads:
            t.join(timeout)


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def read_pid(path):
    try:
        return int(open(path).read().strip())
    except (OSError, ValueError):
        return None


def pct(values, p):
    if not values:
        return None
    s = sorted(values)
    return s[min(len(s) - 1, int(round(p / 100 * (len(s) - 1))))]


def lat_summary(values):
    ms = [v * 1000 for v in values]
    if not ms:
        return {"n": 0}
    return {"n": len(ms), "p50_ms": round(pct(ms, 50), 3), "p90_ms": round(pct(ms, 90), 3),
            "p99_ms": round(pct(ms, 99), 3), "max_ms": round(max(ms), 3),
            "mean_ms": round(sum(ms) / len(ms), 3)}


# -- leak finder ------------------------------------------------------------

def _b64_variants(raw):
    out = set()
    for pad in (0, 1, 2):
        enc = base64.b64encode(b"\0" * pad + raw)
        # drop the characters that depend on the filler, keep the aligned middle
        skip = {0: 0, 1: 2, 2: 3}[pad]
        core = enc.rstrip(b"=")[skip:-1]
        if len(core) >= 12:
            out.add(core)
            out.add(core.replace(b"+", b"-").replace(b"/", b"_"))
    return out


def needles(value: bytes):
    """form name -> list of byte strings whose presence means that form leaked."""
    text = value.decode("latin-1")
    f = {"raw": [value],
         "base64": sorted(_b64_variants(value)),
         "hex": [value.hex().encode(), value.hex().upper().encode()],
         "url": [urllib.parse.quote(text, safe="").encode(),
                 "".join("%%%02X" % b for b in value).encode(),
                 "".join("%%%02x" % b for b in value).encode()],
         "reversed": [value[::-1]]}
    esc = json.dumps(text)[1:-1].encode()
    if esc != value:
        f["json_escaped"] = [esc]
    return f


def forms_leaked(blob: bytes, value: bytes):
    """Forms of `value` found in `blob`, by name."""
    found = []
    for form, ns in needles(value).items():
        if any(n and n in blob for n in ns):
            found.append(form)
    return found


def texts_of(lines):
    """Every JSON string value of the parsed messages: what the harness would
    hand to the model."""
    out = []

    def walk(o):
        if isinstance(o, str):
            out.append(o)
        elif isinstance(o, list):
            for x in o:
                walk(x)
        elif isinstance(o, dict):
            for x in o.values():
                walk(x)

    for _t, line in lines:
        try:
            walk(json.loads(line))
        except ValueError:
            pass
    return out


def split_halves_leaked(texts, value: bytes):
    """Both halves of the value present in the decoded texts."""
    s = value.decode("latin-1")
    mid = len(s) // 2
    a, b = s[:mid], s[mid:]
    if len(a) < 8 or len(b) < 8:
        return False
    return any(a in t for t in texts) and any(b in t for t in texts)


def check_lines(lines):
    """(n_lines, n_invalid_json, ids) over the stdout lines."""
    bad = 0
    ids = []
    for _t, line in lines:
        try:
            m = json.loads(line)
            if isinstance(m, dict) and "id" in m:
                ids.append(m["id"])
        except ValueError:
            bad += 1
    return len(lines), bad, ids
