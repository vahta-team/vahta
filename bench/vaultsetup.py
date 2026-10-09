"""Set up a Vahta vault with canaries and open a session, inside a container.

The daemon here is the test build (`test-surface`): its prompt surface answers
from a script file instead of opening a terminal window, so a container with no
display can create a vault, add values and unlock them. Everything lives under
the container's HOME. The caller must be a descendant of a non-shell process at
least three levels above init (`bench.py` starts containers with `--init` and two
shells in between): that process becomes the
session's anchor, and the hook calls it makes are covered by the session.
"""

import json
import os
import secrets
import subprocess

K = "sec" + "ret"  # the key of a password answer in the surface script
HOME = os.path.expanduser("~")
SCRIPT = os.path.join(HOME, "surface.jsonl")


def surface_env(base=None) -> dict:
    env = dict(base if base is not None else os.environ)
    env["VAHTA_TEST_SURFACE"] = SCRIPT
    env["VAHTA_TEST_SURFACE_LOG"] = os.path.join(HOME, "surface.log")
    for gone in ("DISPLAY", "WAYLAND_DISPLAY"):
        env.pop(gone, None)
    return env


def _script(*answers):
    with open(SCRIPT, "a") as f:
        for a in answers:
            f.write(json.dumps(a) + "\n")


def _vahta(env, cwd, *args):
    r = subprocess.run(["vahta", *args], capture_output=True, text=True, env=env, cwd=cwd)
    if r.returncode != 0:
        raise RuntimeError(f"vahta {args[0]} failed ({r.returncode}): {r.stderr.strip()[:300]}")
    return r


def setup(project: str, canaries: dict, alarm: str = "warn", hours: int = 2, bind: bool = False) -> dict:
    """Create the vault in `project`, add every canary (name -> value) and
    unlock them for the calling process. Returns the environment to run agent
    commands with (no test-surface variables)."""
    os.makedirs(project, exist_ok=True)
    cfg = os.path.join(HOME, ".config", "vahta")
    os.makedirs(cfg, exist_ok=True)
    with open(os.path.join(cfg, "config.toml"), "w") as f:
        f.write(f'alarm = "{alarm}"\nidle_minutes = 600\n')
    env = surface_env()
    pw = secrets.token_urlsafe(12)
    _script({K: pw}, {"ack": True})
    _vahta(env, project, "init")
    for name, value in canaries.items():
        # A cloud-key shape makes `add` ask which tier; "keep session" is choice 1.
        # Leftover answers are dropped so they cannot answer a later question.
        open(SCRIPT, "w").close()
        _script({K: pw}, {K: value}, {"choose": 1})
        _vahta(env, project, "add", name)
    open(SCRIPT, "w").close()
    _script({K: pw})
    _vahta(env, project, "unlock", "--for", f"{hours}h")
    if bind:  # the owner approves "only printenv, no network, no shells" for each secret
        for name in canaries:
            open(SCRIPT, "w").close()
            _script({"choose": 0}, {K: pw})
            _vahta(env, project, "bind", name, "--allow", "printenv", "--deny", "@network", "--deny", "@shells",
                   "--reason", "bench: owner binds each secret")
    # Questions the alarm may ask later (a window nobody answers: nothing happens).
    _script(*[{"noanswer": True}] * 40)
    clean = dict(os.environ)
    for k in list(clean):
        if k.startswith("VAHTA_TEST"):
            del clean[k]
    return clean

