"""Optional Node smoke test for the OpenCode secret-guard.js bridge."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from key_amnesia.setup_cmd import _opencode_plugin_template

pytestmark = pytest.mark.slow

NODE = shutil.which("node")
SRC = Path(__file__).resolve().parent.parent / "src"


@pytest.mark.skipif(NODE is None, reason="node is not on PATH")
def test_opencode_plugin_throws_on_deny_and_allows_clean(tmp_path: Path) -> None:
    argv = [sys.executable, "-m", "key_amnesia.hooks.secret_guard"]
    baked = _opencode_plugin_template().replace(
        "const HOOK_ARGV = null; // filled by ka setup",
        "const HOOK_ARGV = " + json.dumps(argv) + "; // filled by ka setup",
        1,
    )
    assert "HOOK_ARGV = null" not in baked
    plugin = tmp_path / "secret-guard.js"
    plugin.write_text(baked, encoding="utf-8")
    runner = tmp_path / "run.mjs"
    runner.write_text(
        f"""
import {{ pathToFileURL }} from "node:url";
const mod = await import(pathToFileURL({json.dumps(str(plugin))}).href);
const hooks = await (mod.default)({{}});
const before = hooks["tool.execute.before"];

let denied = false;
try {{
  await before(
    {{ tool: "bash", sessionID: "s", callID: "c" }},
    {{ args: {{ command: "ka reveal FOO" }} }},
  );
}} catch (err) {{
  denied = String(err && err.message || err).includes("reveal");
}}
if (!denied) {{
  console.error("expected throw on ka reveal");
  process.exit(2);
}}

await before(
  {{ tool: "bash", sessionID: "s", callID: "c" }},
  {{ args: {{ command: "echo hi" }} }},
);
await before(
  {{ tool: "read", sessionID: "s", callID: "c" }},
  {{ args: {{ filePath: "/tmp/x" }} }},
);

// An MCP tool call must now reach the Python guard. We cannot name OpenCode's
// MCP tool ids, so this only proves the inverted filter lets an unfamiliar
// name through; the id below is the Claude Code spelling, used as a sample.
let mcpDenied = false;
try {{
  await before(
    {{ tool: "mcp__github__create_issue", sessionID: "s", callID: "c" }},
    {{ args: {{ title: "deploy", body: "AKIA" + "0".repeat(16) }} }},
  );
}} catch (err) {{
  mcpDenied = true;
}}
if (!mcpDenied) {{
  console.error("expected throw on MCP call carrying a credential");
  process.exit(3);
}}
""",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.pop("KEY_AMNESIA_HOOK_DISABLE", None)
    env["PYTHONPATH"] = str(SRC) + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    result = subprocess.run(
        [NODE, runner],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    if result.returncode != 0:
        pytest.fail(
            "node plugin smoke failed:\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


@pytest.mark.skipif(NODE is None, reason="node is not on PATH")
def test_opencode_plugin_filter_guards_all_but_skip_set(tmp_path: Path) -> None:
    """Filter logic alone, against a stub guard that denies everything.

    The point of 0.4.16 is that an unfamiliar tool name — an MCP tool under
    whatever id OpenCode assigns it — reaches the guard. Only the SKIP verbs
    may bypass it, and `webfetch` is not one of them.
    """
    stub = tmp_path / "deny.mjs"
    stub.write_text(
        'process.stdin.resume();\n'
        'process.stdin.on("end", () => {\n'
        '  process.stdout.write(JSON.stringify({\n'
        '    hookSpecificOutput: {\n'
        '      hookEventName: "PreToolUse",\n'
        '      permissionDecision: "deny",\n'
        '      permissionDecisionReason: "STUB-DENY",\n'
        '    },\n'
        '  }));\n'
        '});\n',
        encoding="utf-8",
    )
    argv = [NODE, str(stub)]
    baked = _opencode_plugin_template().replace(
        "const HOOK_ARGV = null; // filled by ka setup",
        "const HOOK_ARGV = " + json.dumps(argv) + "; // filled by ka setup",
        1,
    )
    plugin = tmp_path / "secret-guard.js"
    plugin.write_text(baked, encoding="utf-8")

    reached = ["bash", "write", "edit", "webfetch", "task", "patch",
               "mcp__github__create_issue", "github.create_issue",
               "some_future_opencode_tool"]
    skipped = ["read", "glob", "grep", "list", "todoread", "todowrite",
               "Read", "GREP"]
    runner = tmp_path / "run.mjs"
    runner.write_text(
        f"""
import {{ pathToFileURL }} from "node:url";
const mod = await import(pathToFileURL({json.dumps(str(plugin))}).href);
const hooks = await (mod.default)({{}});
const before = hooks["tool.execute.before"];

async function guarded(tool) {{
  try {{
    await before({{ tool, sessionID: "s", callID: "c" }}, {{ args: {{ x: "y" }} }});
    return false;
  }} catch (err) {{
    return String(err && err.message || err).includes("STUB-DENY");
  }}
}}

const failures = [];
for (const tool of {json.dumps(reached)}) {{
  if (!(await guarded(tool))) failures.push("not guarded: " + tool);
}}
for (const tool of {json.dumps(skipped)}) {{
  if (await guarded(tool)) failures.push("unexpectedly guarded: " + tool);
}}
if (failures.length) {{
  console.error(failures.join("\\n"));
  process.exit(4);
}}
console.log("filter ok: guarded={len(reached)} skipped={len(skipped)}");
""",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.pop("KEY_AMNESIA_HOOK_DISABLE", None)
    result = subprocess.run(
        [NODE, runner], cwd=str(tmp_path), capture_output=True, text=True, timeout=60,
        env=env,
    )
    if result.returncode != 0:
        pytest.fail(
            "node filter check failed:\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    assert "filter ok" in result.stdout


@pytest.mark.skipif(NODE is None, reason="node is not on PATH")
def test_opencode_plugin_fails_open_when_guard_cannot_run(tmp_path: Path) -> None:
    """A guard that cannot be spawned must never block a tool call."""
    argv = [str(tmp_path / "does-not-exist-key-amnesia-guard")]
    baked = _opencode_plugin_template().replace(
        "const HOOK_ARGV = null; // filled by ka setup",
        "const HOOK_ARGV = " + json.dumps(argv) + "; // filled by ka setup",
        1,
    )
    plugin = tmp_path / "secret-guard.js"
    plugin.write_text(baked, encoding="utf-8")
    runner = tmp_path / "run.mjs"
    runner.write_text(
        f"""
import {{ pathToFileURL }} from "node:url";
const mod = await import(pathToFileURL({json.dumps(str(plugin))}).href);
const hooks = await (mod.default)({{}});
await hooks["tool.execute.before"](
  {{ tool: "mcp__whatever__do_it", sessionID: "s", callID: "c" }},
  {{ args: {{ token: "AKIA" + "0".repeat(16) }} }},
);
console.log("failed open");
""",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.pop("KEY_AMNESIA_HOOK_DISABLE", None)
    result = subprocess.run(
        [NODE, runner], cwd=str(tmp_path), capture_output=True, text=True, timeout=30,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert "failed open" in result.stdout


@pytest.mark.skipif(NODE is None, reason="node is not on PATH")
def test_opencode_plugin_unfamiliar_tools_reach_the_real_guard(tmp_path: Path) -> None:
    """Forwarding is not enough — the guard must actually read the arguments.

    The Python guard early-returns on any tool name outside
    ``_ALLOWED_TOOL_NAMES`` that is not ``mcp__``-shaped, so before 0.4.16
    relabelled them these calls were forwarded and discarded unread. Every
    name below is a plausible spelling for an MCP tool in OpenCode; we do not
    know which one OpenCode uses, which is exactly why none may be trusted to
    pass through.
    """
    argv = [sys.executable, "-m", "key_amnesia.hooks.secret_guard"]
    baked = _opencode_plugin_template().replace(
        "const HOOK_ARGV = null; // filled by ka setup",
        "const HOOK_ARGV = " + json.dumps(argv) + "; // filled by ka setup",
        1,
    )
    plugin = tmp_path / "secret-guard.js"
    plugin.write_text(baked, encoding="utf-8")

    # Fabricated, non-functional token shapes; never a real credential.
    aws = "AKIA" + "0" * 16
    gh = "ghp_" + "a" * 25
    cases = [
        ["webfetch", {"url": "https://example.test/v1?api_key=" + gh}],
        ["mcp__github__create_issue", {"body": aws}],
        ["github.create_issue", {"body": aws}],
        ["github_create_issue", {"body": aws}],
        ["some_future_opencode_tool", {"nested": {"token": aws}}],
        ["patch", {"patch": "+token = " + aws}],
    ]
    runner = tmp_path / "run.mjs"
    runner.write_text(
        f"""
import {{ pathToFileURL }} from "node:url";
const mod = await import(pathToFileURL({json.dumps(str(plugin))}).href);
const before = (await mod.default({{}}))["tool.execute.before"];

const failures = [];
for (const [tool, args] of {json.dumps(cases)}) {{
  let denied = false;
  try {{
    await before({{ tool, sessionID: "s", callID: "c" }}, {{ args }});
  }} catch (err) {{
    denied = String(err && err.message || err).includes("credential-shaped");
  }}
  if (!denied) failures.push("credential passed for tool: " + tool);
}}

// Relabelling must not cost bash its shell semantics: `cd X && ka export` is
// only split for a tool the Python guard knows as a shell.
let chainDenied = false;
try {{
  await before(
    {{ tool: "bash", sessionID: "s", callID: "c" }},
    {{ args: {{ command: "cd /tmp && ka export" }} }},
  );
}} catch (err) {{
  chainDenied = String(err && err.message || err).includes("export");
}}
if (!chainDenied) failures.push("bash lost its shell-verb deny");

if (failures.length) {{
  console.error(failures.join("\\n"));
  process.exit(5);
}}
console.log("relabel ok");
""",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.pop("KEY_AMNESIA_HOOK_DISABLE", None)
    env["PYTHONPATH"] = str(SRC) + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    result = subprocess.run(
        [NODE, runner], cwd=str(tmp_path), capture_output=True, text=True, timeout=60,
        env=env,
    )
    if result.returncode != 0:
        pytest.fail(
            "node relabel check failed:\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    assert "relabel ok" in result.stdout
