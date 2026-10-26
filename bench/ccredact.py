"""cc-redact, inside the agent container: real Claude Code, real Vahta hooks, a vault
with canaries, and a mock model that issues scripted tool calls (one per turn) whose
output holds a canary. The mock records every tool_result Claude Code sends back; the
host checks them (cctest.redact). This script only sets the stage and runs `claude`.

Canaries come on stdin ({name: value}); nothing here prints or logs one. The files
the scripted tools read hold them, which is the point of the test.
"""

import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent  # noqa: E402
import ccagent  # noqa: E402
import vaultsetup  # noqa: E402

PROJECT = agent.PROJECT
WEB_PORT = 8099
HOME = os.path.expanduser("~")


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/out"
    canaries = json.load(sys.stdin)
    gh, db = canaries["GITHUB_TOKEN"], canaries["DATABASE_PASSWORD"]
    os.makedirs(PROJECT, exist_ok=True)
    # NOTE lines around the values: an Edit of NOTE shows its neighbours in the result.
    lines = ["NOTE=1", "GITHUB_" + "TOKEN=" + gh, "DB_" + "PASS=" + db, "OTHER=2"]
    with open(os.path.join(PROJECT, "leak.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")
    with open(os.path.join(PROJECT, "bare.txt"), "w") as f:  # NOTE lines around a bare value, for Edit's snippet
        f.write("NOTE=1\n" + db + "\nOTHER=2\n")
    with open(os.path.join(PROJECT, "show.py"), "w") as f:
        f.write("print(open(" + repr(os.path.join(PROJECT, "bare.txt")) + ").read())\n")
    web = os.path.join(HOME, "web")  # WebFetch target: a local page holding the value, served from here
    os.makedirs(web, exist_ok=True)
    with open(os.path.join(web, "page.html"), "w") as f:
        f.write("<html><body><h1>deploy notes</h1><p>" + "GITHUB_" + "TOKEN=" + gh + "</p></body></html>\n")
    # WebFetch upgrades to https: a throwaway certificate for 127.0.0.1, trusted through NODE_EXTRA_CA_CERTS.
    crt, key = os.path.join(web, "../web.crt"), os.path.join(web, "../web.key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "2",
                    "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"], check=True, capture_output=True)
    serve = ("import http.server,ssl,functools;h=functools.partial(http.server.SimpleHTTPRequestHandler,directory=%r);"
             "s=http.server.ThreadingHTTPServer(('127.0.0.1',%d),h);c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);"
             "c.load_cert_chain(%r,%r);s.socket=c.wrap_socket(s.socket,server_side=True);s.serve_forever()" % (web, WEB_PORT, crt, key))
    srv = subprocess.Popen([sys.executable, "-c", serve], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    leakval = os.path.join(HOME, "leakval.txt")
    with open(leakval, "w") as f:
        f.write("deploy notes: " + " ".join(lines[1:3]) + "\n")
    env = vaultsetup.setup(PROJECT, canaries)
    # GITHUB_TOKEN is a publishing token: every run opens a password window, and its category never lets a
    # shell or python3 run. The owner moves it to `ordinary` with printenv and python3 (the second one writes
    # to stderr without a shell), and the two runs below each get their password.
    vaultsetup.rebind(PROJECT, "GITHUB_TOKEN", "--category", "ordinary", "--allow", "printenv", "--allow", "python3")
    vaultsetup.rescript({vaultsetup.K: vaultsetup.PASSWORD}, {vaultsetup.K: vaultsetup.PASSWORD})
    rc, _ = ccagent.seed_claude("oauth")
    settings = os.path.join(HOME, ".claude", "settings.json")
    with open(settings) as f:
        cfg = json.load(f)
    # WebFetch asks claude.ai whether the domain is safe before it fetches; the closed network cannot answer.
    cfg["skipWebFetchPreflight"] = True
    text = json.dumps(cfg)
    if os.environ.get("CC_REDACT_CAPTURE"):  # observe only: payloads and answers are copied to /out
        text = text.replace("/usr/local/bin/vahta-hook", "python3 /bench/hooktee.py")
    with open(settings, "w") as f:
        f.write(text)
    mcp = os.path.join(HOME, "mcp.json")
    with open(mcp, "w") as f:
        json.dump({"mcpServers": {"leak": {"command": "python3", "args": ["/bench/mcp_leak.py", leakval]}}}, f)
    env = {**env, **ccagent.QUIET, "ANTHROPIC_BASE_URL": os.environ["ANTHROPIC_BASE_URL"], "HOME": ccagent.HOME}
    env.pop("ANTHROPIC_API_KEY", None)
    env["NODE_EXTRA_CA_CERTS"] = crt
    env["CLAUDE_CODE_" + "OAUTH_TOKEN"] = ccagent.DUMMY_OAUTH  # a dummy; the mock never checks it
    cmd = ["claude", "-p", "run the scripted checks", "--model", "haiku", "--max-turns", "40",
           "--output-format", "stream-json", "--verbose", "--mcp-config", mcp, "--strict-mcp-config",
           "--allowedTools", ccagent.TOOLS + " WebFetch mcp__leak__get_token"]
    try:
        with open(os.path.join(out, "claude-stream.jsonl"), "w") as raw:
            r = subprocess.run(cmd, cwd=PROJECT, env=env, stdin=subprocess.DEVNULL, stdout=raw, stderr=subprocess.PIPE,
                               text=True, timeout=300)
    finally:
        srv.terminate()
        if os.path.exists(os.path.join(HOME, "surface.log")):  # which windows the daemon opened
            shutil.copy(os.path.join(HOME, "surface.log"), os.path.join(out, "surface.log"))
    with open(os.path.join(out, "summary.json"), "w") as f:
        json.dump({"exit": r.returncode, "stderr_tail": r.stderr[-500:], "hooks_installed": ccagent.hooks_installed(),
                   "setup_rc": rc}, f, indent=2)


if __name__ == "__main__":
    main()
