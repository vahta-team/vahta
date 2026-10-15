#!/usr/bin/env python3
"""A fake stdio MCP server for the Vahta MCP bench. Standard library only.

Newline-delimited JSON-RPC 2.0 on stdin/stdout. Methods: initialize, tools/list,
tools/call. Tools:

  echo      {"text": s}                       returns s
  big       {"bytes": N}                      returns N bytes of text
  env_echo  {"name": VAR, "encoding": E}      returns the value of VAR in encoding E:
            raw | base64 | hex | url | reversed | json | split | len
            (`split` sends the first half in a notification and the rest in the
            response: two separate messages)
  dribble   {"name": VAR | "text": s, "mode": "byte" | "split"}
            writes the whole response message one byte per write, flushed; mode
            `split` writes it in two writes cut in the middle of the value (50 ms apart)

Options (argv or environment):
  --startup-delay S / MCP_FAKE_DELAY    sleep S seconds before reading stdin
  MCP_FAKE_PID_FILE      write the pid here at start
  MCP_FAKE_START_FILE    create this file at start (the T2 "the command ran" marker)
  MCP_FAKE_QUIT_ON_START exit 0 right after writing the start file
  MCP_FAKE_TERM_FILE     on SIGTERM write "TERM" here, then exit 0
  MCP_FAKE_STDERR_NOISE  write that many bytes of noise to stderr at start

It never prints an environment value except through the env_echo / dribble tools.
"""

import os

# First thing, before the heavier imports: tell the T2 bench the command ran.
if os.environ.get("MCP_FAKE_START_FILE"):
    with open(os.environ["MCP_FAKE_START_FILE"], "w") as _f:
        _f.write("started")

import base64
import json
import signal
import sys
import time
import urllib.parse

OUT = sys.stdout.buffer


def send(obj, pieces=None):
    data = (json.dumps(obj, separators=(",", ":")) + "\n").encode()
    write_raw(data, pieces)


def write_raw(data, pieces=None):
    if pieces is None:
        OUT.write(data)
        OUT.flush()
        return
    for i in range(0, len(data), pieces):
        OUT.write(data[i : i + pieces])
        OUT.flush()


def text_result(mid, text):
    return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": text}]}}


def encode(value, enc):
    if enc == "raw":
        return value
    if enc == "base64":
        return base64.b64encode(value.encode()).decode()
    if enc == "hex":
        return value.encode().hex()
    if enc == "url":
        return urllib.parse.quote(value, safe="")
    if enc == "reversed":
        return value[::-1]
    if enc == "json":  # the value as a JSON string literal, put inside a string
        return json.dumps(value)
    raise ValueError(enc)


def call(mid, name, args):
    if name == "echo":
        send(text_result(mid, args.get("text", "")))
    elif name == "big":
        n = int(args.get("bytes", 0))
        unit = "0123456789abcdef"
        send(text_result(mid, (unit * (n // 16 + 1))[:n]))
    elif name == "env_echo":
        value = os.environ.get(args["name"], "")
        enc = args.get("encoding", "raw")
        if enc == "len":  # lets the driver check the child got the value it expects
            send(text_result(mid, "len=%d" % len(value)))
        elif enc == "split":
            half = len(value) // 2
            send({"jsonrpc": "2.0", "method": "notifications/message",
                  "params": {"level": "info", "data": value[:half]}})
            send(text_result(mid, value[half:]))
        else:
            send(text_result(mid, "v=" + encode(value, enc)))
    elif name == "dribble":
        value = os.environ.get(args["name"], "") if "name" in args else args.get("text", "")
        msg = text_result(mid, "v=" + value)
        data = (json.dumps(msg, separators=(",", ":")) + "\n").encode()
        if args.get("mode", "byte") == "byte":
            write_raw(data, 1)
        else:
            # cut inside the value as it appears on the wire
            probe = json.dumps(value)[1:-1].encode()
            at = data.find(probe)
            cut = at + max(1, len(probe) // 2) if at >= 0 else len(data) // 2
            OUT.write(data[:cut])
            OUT.flush()
            time.sleep(0.05)
            OUT.write(data[cut:])
            OUT.flush()
    else:
        send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "no such tool"}})


TOOLS = [{"name": n, "description": n, "inputSchema": {"type": "object"}}
         for n in ("echo", "big", "env_echo", "dribble")]


def handle(msg):
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:
        return  # a notification
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
            "serverInfo": {"name": "vahta-bench-fake", "version": "0"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        p = msg.get("params", {})
        call(mid, p.get("name"), p.get("arguments", {}))
    elif method == "ping":
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
    else:
        send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "no such method"}})


def main():
    delay = float(os.environ.get("MCP_FAKE_DELAY", "0"))
    if "--startup-delay" in sys.argv:
        delay = float(sys.argv[sys.argv.index("--startup-delay") + 1])
    term = os.environ.get("MCP_FAKE_TERM_FILE")

    def on_term(_sig, _frm):
        if term:
            with open(term, "w") as f:
                f.write("TERM")
        os._exit(0)

    signal.signal(signal.SIGTERM, on_term)
    if os.environ.get("MCP_FAKE_PID_FILE"):
        with open(os.environ["MCP_FAKE_PID_FILE"], "w") as f:
            f.write(str(os.getpid()))
    if os.environ.get("MCP_FAKE_STDERR_NOISE"):
        sys.stderr.write("log " * (int(os.environ["MCP_FAKE_STDERR_NOISE"]) // 4) + "\n")
        sys.stderr.flush()
    if delay:
        time.sleep(delay)
    if os.environ.get("MCP_FAKE_QUIT_ON_START"):
        return 0
    for line in sys.stdin.buffer:
        line = line.strip()
        if not line:
            continue
        try:
            handle(json.loads(line))
        except Exception as e:  # keep the server alive
            sys.stderr.write("bad input: %s\n" % type(e).__name__)
            sys.stderr.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
