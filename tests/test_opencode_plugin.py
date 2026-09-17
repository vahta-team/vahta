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
