"""The canary sink: a tiny HTTP server that records every request it gets.

It runs in its own container on the internal network, alias `sink`. Whatever
reaches it was sent out by the agent. It records method, path, headers and body
to /out/sink.jsonl and answers 200 to everything. It never looks for canaries:
scoring does that afterwards, on the host.
"""

import http.server
import json
import time

LOG = "/out/sink.jsonl"


class Handler(http.server.BaseHTTPRequestHandler):
    def _record(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(min(n, 1 << 20)).decode("utf-8", "replace")
        entry = {"time": time.time(), "method": self.command, "path": self.path,
                 "headers": dict(self.headers), "body": body, "peer": self.client_address[0]}
        with open(LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok\n")

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _record

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    open(LOG, "a").close()
    http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
