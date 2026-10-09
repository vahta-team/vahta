"""A mock of the Anthropic Messages API, for testing the auth proxy and Claude
Code's plumbing with no token and no network. TEST ONLY: it records every
request including its credential headers (they are test values).

Environment:
  MOCK_SCRIPT   JSON list of tool calls to make, one per model turn:
                [{"name": "Bash", "input": {"command": "ls"}}, ...]
                Then it answers with a final text. Default: none (just text).
  MOCK_LOG      where to append request records (default /out/mock.jsonl)

It answers POST /v1/messages (streaming or not) and /v1/messages/count_tokens;
every other path gets 404 (and is recorded, which shows what a client asks for).
"""

import http.server
import json
import os
import time

LOG = os.environ.get("MOCK_LOG", "/out/mock.jsonl")
SCRIPT = json.loads(os.environ.get("MOCK_SCRIPT") or "[]")
KEEP = ("cookie", "x-forwarded-for", "authorization", "x-api-key", "anthropic-beta", "anthropic-version", "user-agent", "content-type", "host")


def _sse(event, data):
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


def _blocks(history):
    return [b for m in history for b in (m["content"] if isinstance(m.get("content"), list) else [])]


def reply_blocks(body):
    """Which content the mock answers with, from how many tool results the conversation holds."""
    if not body.get("tools"):
        return [{"type": "text", "text": "ok"}], "end_turn"
    done = sum(1 for b in _blocks(body.get("messages", [])) if b.get("type") == "tool_result")
    if done < len(SCRIPT):
        call = SCRIPT[done]
        return [{"type": "tool_use", "id": f"toolu_mock{done:04d}", "name": call["name"], "input": call["input"]}], "tool_use"
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
