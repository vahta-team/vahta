"""The auth proxy: lets Claude Code in the agent container use a credential the
agent container never holds.

  agent container --(dummy credential)--> authproxy --(real credential)--> https://api.anthropic.com

It runs in its own container, on the internal network (alias `authproxy`) and on
a network with egress. The real credential is in ITS environment only, put there
by `docker run -e NAME` (inherited by name from the host process, which got it
from `vahta run --secret NAME`); it is never read from a file or a command line.

What it does:
  * forwards only the requests Claude Code needs to the Messages API:
    `POST /v1/messages` and `POST /v1/messages/count_tokens` (a query string of
    plain `key=value` pairs is allowed, e.g. `?beta=true`); anything else gets 403;
  * replaces every credential header the client sent with the real one;
  * stops forwarding after a hard cap on requests (default 60, per proxy run) with 429;
  * forwards only to https://api.anthropic.com (`--test-upstream` exists for tests
    against a mock and is refused unless `--allow-test-upstream` is also given);
  * logs METHOD PATH STATUS and a counter, never a header, a query or a body.

The credential kind follows the environment: CLAUDE_CODE_OAUTH_TOKEN (a Claude
subscription token from `claude setup-token`) is sent as `Authorization: Bearer`
with the OAuth beta flag added to `anthropic-beta`; ANTHROPIC_API_KEY is sent as
`x-api-key`. If both are set the OAuth token wins. If neither is set the proxy
refuses to start (unless it is a test upstream, where it sends a placeholder).
"""

import argparse
import http.client
import http.server
import json
import os
import re
import sys
import threading
import time
import urllib.parse

UPSTREAM = ("https", "api.anthropic.com", 443)
ALLOWED = {("POST", "/v1/messages"), ("POST", "/v1/messages/count_tokens")}
OAUTH_BETA = "oauth-2025-04-20"
QUERY_OK = re.compile(r"^[A-Za-z0-9_.=&-]{0,100}$")
MAX_BODY = 16 << 20
# Never copied from the client to the upstream: credentials, connection handling,
# and anything that would name a different host.
DROP = {"authorization", "x-api-key", "proxy-authorization", "cookie", "host", "content-length",
        "connection", "keep-alive", "transfer-encoding", "te", "upgrade", "accept-encoding",
        "x-forwarded-for", "x-forwarded-host", "forwarded"}


class State:
    def __init__(self, cap, upstream, oauth, apikey, logfile):
        self.cap, self.upstream, self.oauth, self.apikey = cap, upstream, oauth, apikey
        self.forwarded = 0
        self.lock = threading.Lock()
        self.logfile = logfile

    def take(self) -> bool:
        with self.lock:
            if self.forwarded >= self.cap:
                return False
            self.forwarded += 1
            return True

    def log(self, method, path, status, note=""):
        line = f"{time.strftime('%H:%M:%S')} {method} {path} {status} forwarded={self.forwarded}/{self.cap}{(' ' + note) if note else ''}"
        with self.lock:
            print(line, flush=True)
            if self.logfile:
                with open(self.logfile, "a") as f:
                    f.write(line + "\n")


def credential_headers(state, client_beta):
    """The headers that carry the real credential."""
    if state.oauth:
        beta = [b.strip() for b in (client_beta or "").split(",") if b.strip()]
        if OAUTH_BETA not in beta:
            beta.append(OAUTH_BETA)
        return {"authorization": "Bearer " + state.oauth, "anthropic-beta": ",".join(beta)}
    h = {"x-api-key": state.apikey or "test-placeholder"}
    if client_beta:
        h["anthropic-beta"] = client_beta
    return h


def make_handler(state: State):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"  # the body ends when the connection closes

        def _refuse(self, status, msg, path):
            data = json.dumps({"type": "error", "error": {"type": "authproxy", "message": msg}}).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            state.log(self.command, path, status)

        def _handle(self):
            parts = urllib.parse.urlsplit(self.path)
            path = parts.path if self.path.startswith("/") else "?"
            if (self.command, path) not in ALLOWED or not QUERY_OK.match(parts.query):
                return self._refuse(403, "authproxy: this request is not allowed", path[:60])
            n = int(self.headers.get("content-length") or 0)
            if n > MAX_BODY:
                return self._refuse(413, "authproxy: body too large", path)
            body = self.rfile.read(n) if n else b""
            if not state.take():
                return self._refuse(429, "authproxy: request cap for this run reached", path)
            headers = {k: v for k, v in self.headers.items() if k.lower() not in DROP}
            headers.update(credential_headers(state, self.headers.get("anthropic-beta")))
            headers["accept-encoding"] = "identity"
            headers["content-length"] = str(len(body))
            scheme, host, port = state.upstream
            try:
                conn = (http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection)(host, port, timeout=600)
                conn.request(self.command, path + ("?" + parts.query if parts.query else ""), body=body, headers=headers)
                resp = conn.getresponse()
            except Exception:
                return self._refuse(502, "authproxy: upstream unreachable", path)
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in ("transfer-encoding", "content-length", "connection", "keep-alive", "set-cookie"):
                    self.send_header(k, v)
            self.send_header("connection", "close")
            self.end_headers()
            try:
                while True:
                    chunk = resp.read1(8192)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except (OSError, http.client.HTTPException):
                pass
            finally:
                conn.close()
            state.log(self.command, path, resp.status)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _handle

        def log_message(self, *a):
            pass

    return Handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--cap", type=int, default=60)
    ap.add_argument("--log", default="/out/authproxy.log")
    ap.add_argument("--allow", action="append", default=[], metavar="'METHOD /path'",
                    help="also forward this exact method and path (after a first run showed Claude Code needs it)")
    ap.add_argument("--test-upstream", help="http://HOST:PORT of a mock; needs --allow-test-upstream")
    ap.add_argument("--allow-test-upstream", action="store_true")
    a = ap.parse_args()
    oauth = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN") or None
    apikey = os.environ.get("ANTHROPIC_API_KEY") or None
    upstream = UPSTREAM
    if a.test_upstream:
        if not a.allow_test_upstream:
            sys.exit("authproxy: --test-upstream needs --allow-test-upstream (tests only)")
        u = urllib.parse.urlsplit(a.test_upstream)
        upstream = (u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80))
        print("authproxy: TEST MODE, upstream is", a.test_upstream, flush=True)
    elif not (oauth or apikey):
        sys.exit("authproxy: set CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY in the environment (docker run -e NAME)")
    kind = "oauth" if oauth else "api-key" if apikey else "none (test)"
    for rule in a.allow:
        method, _, path = rule.partition(" ")
        if method not in ("GET", "POST", "HEAD") or not path.startswith("/v1/") or "?" in path or ".." in path:
            sys.exit(f"authproxy: --allow takes 'GET|POST|HEAD /v1/...', not {rule!r}")
        ALLOWED.add((method, path))
    state = State(a.cap, upstream, oauth, apikey, a.log)
    print(f"authproxy: listening on :{a.port}; credential kind: {kind}; cap {a.cap}; upstream {upstream[1]}", flush=True)
    http.server.ThreadingHTTPServer(("0.0.0.0", a.port), make_handler(state)).serve_forever()


if __name__ == "__main__":
    main()
