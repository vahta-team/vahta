"""A mock of the Anthropic Messages API, for testing the auth proxy and Claude
Code's plumbing with no token and no network. TEST ONLY: it records every
request including its credential headers (they are test values).

Environment:
  MOCK_SCRIPT   JSON list of tool calls to make, one per model turn:
                [{"name": "Bash", "input": {"command": "ls"}}, ...]
                Then it answers with a final text. Default: none (just text).
  MOCK_LOG      where to append request records (default /out/mock.jsonl)
  MOCK_ECHO    if set: a request with no tools (WebFetch's helper call) is answered with the text of its
                last user message, so a fetched page comes back as the tool's result
  MOCK_CANARIES JSON {name: value} (cc-t3): a script input may hold @@NAME@@ (the value), @@NAME:b64@@ or
                @@NAME:hex@@, and @@REF@@ (the reference in the newest refusal, for `vahta allow REF`)
  MOCK_BODIES   if set: where to append, per request, what the model is shown besides its own turns:
                {"system", "user"} (the system prompt and every user message, tool results included)
  MOCK_RESULTS  if set: where to append the tool_result blocks each request carries
                (the newest user message only), as {"id", "is_error", "text"} lines.
                This is what the model would have been shown.

It answers POST /v1/messages (streaming or not) and /v1/messages/count_tokens;
every other path gets 404 (and is recorded, which shows what a client asks for).
"""

import base64
import http.server
import json
import os
import re
import time

LOG = os.environ.get("MOCK_LOG", "/out/mock.jsonl")
SCRIPT = json.loads(os.environ.get("MOCK_SCRIPT") or "[]")
RESULTS = os.environ.get("MOCK_RESULTS")
BODIES = os.environ.get("MOCK_BODIES")
CANARIES = json.loads(os.environ.get("MOCK_CANARIES") or "{}")
ECHO = bool(os.environ.get("MOCK_ECHO"))
KEEP = ("cookie", "x-forwarded-for", "authorization", "x-api-key", "anthropic-beta", "anthropic-version", "user-agent", "content-type", "host")


def _sse(event, data):
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


def _blocks(history):
    return [b for m in history for b in (m["content"] if isinstance(m.get("content"), list) else [])]


def _text(content):
    if isinstance(content, list):
        return "\n".join(b.get("text", "") if isinstance(b, dict) and b.get("type") == "text" else json.dumps(b)
                         for b in content)
    return str(content or "")


def record_results(body):
    """Append the tool results of the newest user message (each arrives once as new)."""
    # The newest user message, not the last message: Claude Code 2.1.309 may end
    # a request with a turn of its own after the tool results.
    users = [m for m in body.get("messages", []) if m.get("role") == "user"]
    if not RESULTS or not users or not isinstance(users[-1].get("content"), list):
        return
    with open(RESULTS, "a") as f:
        for b in users[-1]["content"]:
            if b.get("type") == "tool_result":
                f.write(json.dumps({"id": b.get("tool_use_id"), "is_error": bool(b.get("is_error")),
                                    "text": _text(b.get("content"))}) + "\n")


def record_bodies(body):
    """What the model is shown: the system prompt and every turn but its own (prompts, tool results, system turns)."""
    if BODIES:
        users = [m for m in body.get("messages", []) if m.get("role") != "assistant"]  # 2.1.309 sends hook context as role "system"
        with open(BODIES, "a") as f:
            f.write(json.dumps({"system": body.get("system"), "user": users}) + "\n")


def _fill_str(text, body):
    """@@NAME@@ and friends in a scripted input (see MOCK_CANARIES)."""
    def sub(m):
        name, enc = m.group(1), m.group(2)
        if name == "REF":
            last = [t for t in re.findall(r"vahta allow (\S+)", _last_user_text(body))]
            return last[-1] if last else "NOREF"
        raw = CANARIES.get(name, "").encode()
        return {None: raw.decode(), "b64": base64.b64encode(raw).decode(), "hex": raw.hex()}[enc]
    return re.sub(r"@@([A-Z_0-9]+)(?::(b64|hex))?@@", sub, text)


def _fill(v, body):
    if isinstance(v, str):
        return _fill_str(v, body)
    if isinstance(v, dict):
        return {k: _fill(x, body) for k, x in v.items()}
    if isinstance(v, list):
        return [_fill(x, body) for x in v]
    return v


def _last_user_text(body):
    for m in reversed(body.get("messages", [])):
        if m.get("role") == "user":
            return _text(m.get("content"))
    return "ok"


def reply_blocks(body):
    """Which content the mock answers with, from how many tool results the conversation holds."""
    if not body.get("tools"):
        # WebFetch asks a small model to answer from the page: quote the page back, as a model told to would.
        return [{"type": "text", "text": _last_user_text(body) if ECHO else "ok"}], "end_turn"
    done = sum(1 for b in _blocks(body.get("messages", [])) if b.get("type") == "tool_result")
    if done < len(SCRIPT):
        call = SCRIPT[done]
        return [{"type": "tool_use", "id": f"toolu_mock{done:04d}", "name": call["name"], "input": _fill(call["input"], body)}], "tool_use"
    return [{"type": "text", "text": "mock: finished"}], "end_turn"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _record(self, body_len, extra=None):
        entry = {"time": time.time(), "method": self.command, "path": self.path,
                 "headers": {k.lower(): v for k, v in self.headers.items() if k.lower() in KEEP},
                 "body_bytes": body_len, **(extra or {})}
        with open(LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def _send(self, status, payload, ctype="application/json"):
        self.send_response(status)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _handle(self):
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n) if n else b""
        path = self.path.split("?")[0]
        if self.command == "POST" and path == "/v1/messages":
            body = json.loads(raw or b"{}")
            record_results(body)
            record_bodies(body)
            blocks, stop = reply_blocks(body)
            self._record(n, {"stream": bool(body.get("stream")), "model": body.get("model"),
                             "has_tools": bool(body.get("tools")), "reply": [b["type"] for b in blocks]})
            msg = {"id": "msg_mock", "type": "message", "role": "assistant", "model": body.get("model", "mock"),
                   "content": blocks, "stop_reason": stop, "stop_sequence": None,
                   "usage": {"input_tokens": 10, "output_tokens": 5}}
            if not body.get("stream"):
                return self._send(200, json.dumps(msg).encode())
            out = [_sse("message_start", {"type": "message_start", "message": {**msg, "content": [], "stop_reason": None}})]
            for i, b in enumerate(blocks):
                if b["type"] == "text":
                    out.append(_sse("content_block_start", {"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}}))
                    out.append(_sse("content_block_delta", {"type": "content_block_delta", "index": i, "delta": {"type": "text_delta", "text": b["text"]}}))
                else:
                    out.append(_sse("content_block_start", {"type": "content_block_start", "index": i,
                                                            "content_block": {"type": "tool_use", "id": b["id"], "name": b["name"], "input": {}}}))
                    out.append(_sse("content_block_delta", {"type": "content_block_delta", "index": i,
                                                            "delta": {"type": "input_json_delta", "partial_json": json.dumps(b["input"])}}))
                out.append(_sse("content_block_stop", {"type": "content_block_stop", "index": i}))
            out.append(_sse("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                                              "usage": {"output_tokens": 5}}))
            out.append(_sse("message_stop", {"type": "message_stop"}))
            return self._send(200, b"".join(out), "text/event-stream")
        if self.command == "POST" and path == "/v1/messages/count_tokens":
            self._record(n)
            return self._send(200, b'{"input_tokens": 10}')
        self._record(n)
        self._send(404, b'{"type":"error","error":{"type":"not_found_error","message":"mock: no such route"}}')

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = _handle

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    open(LOG, "a").close()
    http.server.ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("MOCK_PORT", "9000"))), Handler).serve_forever()
