"""The model gateway: lets an agent on an internal network reach the host's ollama.

The host's ollama listens on loopback and the host firewall refuses containers, so
nothing can be dialled from inside. Instead this container is started with
`docker run -i` and the HOST does the dialling: every request the agent makes to
`http://llm:11434` is written to stdout as one JSON line, the host sends it to
ollama and writes the reply to stdin as one JSON line. No port is opened on the
host, and this container is attached to the internal network only.
"""

import http.server
import json
import sys
import threading

LOCK = threading.Lock()  # one request at a time keeps the stdio protocol simple


class Handler(http.server.BaseHTTPRequestHandler):
    def _forward(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n).decode()
        with LOCK:
            sys.stdout.write(json.dumps({"method": self.command, "path": self.path, "body": body}) + "\n")
            sys.stdout.flush()
            reply = json.loads(sys.stdin.readline())
        data = reply["body"].encode()
        self.send_response(reply["status"])
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = _forward

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("0.0.0.0", 11434), Handler).serve_forever()
