// installed by key-amnesia
// managed by key-amnesia; re-running `ka setup` overwrites this file.
// add custom hooks/plugins beside this file instead of editing it.
// KEY_AMNESIA_PLUGIN_ID=secret-guard
// KEY_AMNESIA_PLUGIN_VERSION=0.4.16

import { spawn } from "node:child_process";

const HOOK_ARGV = null; // filled by ka setup

// Guard everything except the tools below. OpenCode hands us a bare `tool`
// string with no documented naming convention for MCP-provided tools — the
// plugin SDK types declare `tool.execute.before` input as
// `{tool, sessionID, callID}` and say nothing about how an MCP tool id is
// built — so an allow-list keyed on `mcp__` would be a guess. Inverting the
// filter covers MCP tools whatever OpenCode decides to call them.
//
// Cost of the inversion: every non-skipped tool call now spawns the Python
// guard: measured 85-185 ms per call on the development machine, ~130 ms
// typical, and it is a Python interpreter start, not the scan. SKIP is what keeps
// read/grep/list loops at their old speed, so it holds only high-frequency
// builtins whose *arguments* cannot carry a credential. When unsure about a
// verb, leave it out of SKIP — over-covering costs latency, under-covering
// costs a leak.
//
// `webfetch` is deliberately NOT skipped: a URL can carry a token in a query
// parameter.
//
// The names are OpenCode's own, read from a headless server on 2026-09-29
// (`GET /experimental/tool/ids`), not guessed. Its builtin ids at that version:
// invalid, question, bash, read, glob, grep, edit, write, task, webfetch,
// todowrite, websearch, skill, apply_patch. Everything outside SKIP is guarded,
// so `task` (carries a subagent prompt), `websearch` (a query), `question`,
// `skill` and every MCP tool are scanned.
const SKIP = new Set([
  "read", // args are a file path plus offset/limit
  "glob", // args are a filename pattern plus a directory
  "grep", // args are a search pattern plus a directory
  "todowrite", // args are the agent's own task list
]);

// Names the Python guard inspects under their own spelling. Keep this equal to
// `_ALLOWED_TOOL_NAMES` in key_amnesia/hooks/secret_guard.py: those get the
// shell treatment (ka-verb deny, `cd X && ka export` chain splitting), which
// only applies to a tool the guard recognises.
const NATIVE = new Set(["bash", "shell", "powershell", "write", "edit",
                        "multiedit", "apply_patch"]);

// Measured on 2026-09-29, live: OpenCode names an MCP tool
// `<server>_<tool>` — a call to the `echo_note` tool of a server registered as
// `kademo` arrives here as `kademo_echo_note`. So it is NOT `mcp__`-shaped, and
// a prefix guess would have missed every MCP tool there is. The relabelling
// below is what makes that irrelevant: a server name is arbitrary and may even
// collide with a native verb, so the filter stays "guard everything outside
// SKIP" rather than trying to recognise MCP names.
//
// Everything else is forwarded under an `mcp__`-shaped name. This is NOT a
// guess at what OpenCode calls an MCP tool — it is the opposite. The Python
// guard drops any tool name that is neither in `_ALLOWED_TOOL_NAMES` nor
// `mcp__`-shaped, so forwarding an unfamiliar name verbatim would be a no-op:
// measured before this change, `webfetch` and `github.create_issue` reached
// the guard and were discarded unread. Relabelling tells the guard what we
// actually know about the call — opaque tool, scan every argument string,
// no shell semantics — without inventing a naming convention for OpenCode.
const RELABEL_PREFIX = "mcp__opencode__";
const MCP_SHAPED = /^mcp__./i;

function guardName(tool) {
  if (NATIVE.has(tool.toLowerCase())) return tool;
  if (MCP_SHAPED.test(tool)) return tool;
  return RELABEL_PREFIX + tool;
}

const TIMEOUT_MS = 5000;

export async function KeyAmnesiaSecretGuard() {
  return {
    "tool.execute.before": async (input, output) => {
      if (process.env.KEY_AMNESIA_HOOK_DISABLE) return;
      if (!Array.isArray(HOOK_ARGV) || HOOK_ARGV.length === 0) return;
      const tool = String(input?.tool || "").toLowerCase();
      if (SKIP.has(tool)) return;

      const reason = await askGuard(guardName(String(input.tool)), output.args);
      if (reason) throw new Error(reason);
    },
  };
}

export default KeyAmnesiaSecretGuard;

function askGuard(toolName, args) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    let child;
    try {
      child = spawn(HOOK_ARGV[0], HOOK_ARGV.slice(1), {
        stdio: ["pipe", "pipe", "ignore"],
      });
    } catch {
      finish(null);
      return;
    }

    const timer = setTimeout(() => {
      try {
        child.kill();
      } catch {
        /* fail open */
      }
      finish(null);
    }, TIMEOUT_MS);

    let stdout = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.on("error", () => {
      clearTimeout(timer);
      finish(null);
    });
    child.on("close", () => {
      clearTimeout(timer);
      try {
        const text = stdout.trim();
        if (!text) {
          finish(null);
          return;
        }
        const reply = JSON.parse(text);
        const hso = reply && reply.hookSpecificOutput;
        if (hso && hso.permissionDecision === "deny") {
          const reason =
            (typeof hso.permissionDecisionReason === "string" &&
              hso.permissionDecisionReason) ||
            (typeof reply.systemMessage === "string" && reply.systemMessage) ||
            "key-amnesia hook denied this tool call.";
          finish(reason);
          return;
        }
      } catch {
        /* unparseable stdout — fail open */
      }
      finish(null);
    });

    try {
      child.stdin.write(
        JSON.stringify({ tool_name: toolName, tool_input: args }),
      );
      child.stdin.end();
    } catch {
      clearTimeout(timer);
      try {
        child.kill();
      } catch {
        /* fail open */
      }
      finish(null);
    }
  });
}
