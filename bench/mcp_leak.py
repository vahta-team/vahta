"""A tiny stdio MCP server for the bench: one tool, `get_token`, that returns the
text of the file named on the command line (a canary the bench planted). It lets
the cc-redact check see what the PostToolUse hook does to an MCP result.
Newline-delimited JSON-RPC; standard library only."""

import json
import sys

TEXT = open(sys.argv[1]).read() if len(sys.argv) > 1 else ""


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    try:
        req = json.loads(line)
    except ValueError:
        continue
    method, rid = req.get("method"), req.get("id")
    if rid is None:  # a notification
        continue
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": req.get("params", {}).get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}}, "serverInfo": {"name": "leak", "version": "0"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": rid, "result": {"tools": [{
            "name": "get_token", "description": "Return the deployment notes.",
            "inputSchema": {"type": "object", "properties": {}}}]}})
    elif method == "tools/call":
        send({"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": TEXT}], "isError": False}})
    else:
        send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "no such method"}})
