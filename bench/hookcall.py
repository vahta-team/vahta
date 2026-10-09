"""Call the real `vahta-hook` exactly as a harness would (Claude Code payloads)."""

import json
import subprocess

READ_TOOLS = {"Read", "Grep"}


def payload(tool: str, tool_input: dict, session_id: str = "bench", cwd: str = "/work/proj", response=None) -> dict:
    p = {
        "hook_event_name": "PostToolUse" if response is not None else "PreToolUse",
        "session_id": session_id,
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": cwd,
    }
    if response is not None:
        p["tool_response"] = response
    return p


def run_hook(p: dict, env=None, timeout=10) -> dict:
    """Run the hook for payload `p`; returns its parsed answer ({} for allow)."""
    if p["hook_event_name"] == "PostToolUse":
        event = "after_tool"
    elif p["tool_name"] in READ_TOOLS:
        event = "before_read"
    else:
        event = "before_tool"
    r = subprocess.run(
        ["vahta-hook", "--harness", "claude", "--event", event],
        input=json.dumps(p),
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    out = r.stdout.strip()
    return json.loads(out) if out else {}


def verdict(answer: dict):
    """('deny', reason) or ('allow', '') from a before_tool answer."""
    hso = answer.get("hookSpecificOutput", {})
    if hso.get("permissionDecision") == "deny":
        return "deny", hso.get("permissionDecisionReason", "")
    return "allow", ""
