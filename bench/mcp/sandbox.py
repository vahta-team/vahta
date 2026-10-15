"""A throw-away Vahta world for the MCP bench: temp HOME, the three VAHTA_*
directories, a project with a vault, and the scripted prompt surface of a test
build. Nothing here touches the real HOME, daemon or vault."""

import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "fake_server.py")
K = "sec" + "ret"  # the key of a password / value answer in the surface script
PW = "pw-" + secrets.token_hex(6)  # the vault password of this run only
ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def rnd(n):
    return "".join(secrets.choice(ALNUM) for _ in range(n))


def make_canaries():
    """name -> value, assembled at run time from pieces, never printed."""
    return {
        "MCP_PLAIN": "mc" + "p" + rnd(30),
        "MCP_QUOTE": rnd(14) + '"' + rnd(14),
        "ADV_BRACE": "}" + rnd(24),
        "ADV_REPEAT": "z" * 24,
        "ADV_NLLEAD": "\n" + rnd(24),
        "ADV_BRACENL": "}\n" + rnd(24),
        "ADV_NLTRAIL": rnd(24) + "\n",
        "ADV_NLMID": rnd(12) + "\n" + rnd(12),
    }


class Sandbox:
    def __init__(self, vahta):
        self.vahta_bin = vahta
        self.root = tempfile.mkdtemp(prefix="vmcp-")  # short: it holds a unix socket path
        for d in ("project", "home", "run", "data", "config"):
            os.makedirs(os.path.join(self.root, d))
        self.project = os.path.join(self.root, "project")
        self.script_path = os.path.join(self.root, "script.jsonl")
        self.log_path = os.path.join(self.root, "surface.log")
        self.env = self._env()

    def _env(self):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("VAHTA", "KEY_AMNESIA", "XDG_", "DISPLAY", "WAYLAND", "MCP_FAKE"))}
        env.update({
            "HOME": os.path.join(self.root, "home"),
            "XDG_DATA_HOME": os.path.join(self.root, "data"),
            "XDG_CONFIG_HOME": os.path.join(self.root, "config"),
            "VAHTA_DATA_DIR": os.path.join(self.root, "data"),
            "VAHTA_RUNTIME_DIR": os.path.join(self.root, "run"),
            "VAHTA_CONFIG_DIR": os.path.join(self.root, "config"),
            "VAHTA_TEST_SURFACE": self.script_path,
            "VAHTA_TEST_SURFACE_LOG": self.log_path,
            "VAHTA_TEST_MUTE_REFUSAL_ALARM": "1",
        })
        return env

    # -- the scripted surface ---------------------------------------------
    def script(self, *answers, replace=False):
        with open(self.script_path, "w" if replace else "a") as f:
            for a in answers:
                f.write(json.dumps(a) + "\n")

    def log_events(self):
        out = []
        try:
            with open(self.log_path) as f:
                for line in f:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
        except OSError:
            pass
        return out

    def asks(self, kind=None):
        return [e for e in self.log_events() if "ask" in e and (kind is None or e["ask"] == kind)]

    # -- commands ---------------------------------------------------------
    def vahta(self, *args, timeout=60):
        return subprocess.run([self.vahta_bin, *args], cwd=self.project, env=self.env,
                              capture_output=True, text=True, timeout=timeout)

    def must(self, *args):
        r = self.vahta(*args)
        if r.returncode != 0:
            raise RuntimeError(f"vahta {args[0]} failed ({r.returncode}): {r.stderr.strip()[:300]}")
        return r

    def setup_vault(self, canaries):
        """init + add every canary with rules allowing `python3 <server>`; returns
        {name: reason} for the ones the vault would not take."""
        self.script({K: PW}, {"ack": True}, replace=True)
        self.must("init")
        rejected = {}
        for name, value in canaries.items():
            # a value that starts or ends with white space gets an extra question
            # first: "Store exactly as typed" is choice 1
            # (a line break inside gets one too: choice 0 is "Store exactly as typed")
            extra = [{"choose": 1}] if value != value.strip() else [{"choose": 0}] if "\n" in value else []
            self.script({K: PW}, {K: value}, *extra, {"choose": 0}, replace=True)
            r = self.vahta("add", name, "--allow", f"python3 {SERVER}", "--reason", "bench: fake mcp server")
            if r.returncode != 0:
                rejected[name] = (r.stderr.strip().splitlines() or ["?"])[0][:160]
        self.script(replace=True)
        return rejected

    def unlock(self, names=(), duration="4h"):
        self.script({K: PW}, replace=True)
        self.must("unlock", "--for", duration, *[a for n in names for a in ("--secret", n)])
        self.script({"noanswer": True}, {"noanswer": True}, replace=True)

    def daemon_status(self):
        r = self.vahta("daemon", "status", "--json")
        try:
            return json.loads(r.stdout)
        except ValueError:
            return {"running": False}

    def journal(self):
        try:
            with open(os.path.join(self.root, "data", "journal.jsonl")) as f:
                return [json.loads(l) for l in f if l.strip()]
        except (OSError, ValueError):
            return []

    def stop(self):
        """Stop the daemon of this sandbox and remove it. Returns whether the
        daemon's process is gone."""
        pid = self.daemon_status().get("pid")
        try:
            self.vahta("daemon", "stop", timeout=20)
        except Exception:
            pass
        gone = True
        if pid:
            for _ in range(50):
                if not os.path.exists(f"/proc/{pid}"):
                    break
                time.sleep(0.1)
            else:
                gone = False
                try:
                    os.kill(pid, 9)
                except OSError:
                    pass
        shutil.rmtree(self.root, ignore_errors=True)
        return gone
