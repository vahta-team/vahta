// installed by key-amnesia
// managed by key-amnesia; re-running `ka setup` overwrites this file.
// add custom hooks/plugins beside this file instead of editing it.
// KEY_AMNESIA_PLUGIN_ID=secret-guard
// KEY_AMNESIA_PLUGIN_VERSION=0.4.15

import { spawn } from "node:child_process";

const HOOK_ARGV = null; // filled by ka setup

const GUARDED = new Set(["bash", "shell", "powershell", "write", "edit",
                         "multiedit", "apply_patch", "patch"]);

const TIMEOUT_MS = 5000;

export async function KeyAmnesiaSecretGuard() {
  return {
    "tool.execute.before": async (input, output) => {
      if (process.env.KEY_AMNESIA_HOOK_DISABLE) return;
      if (!Array.isArray(HOOK_ARGV) || HOOK_ARGV.length === 0) return;
      const tool = String(input?.tool || "").toLowerCase();
      if (!GUARDED.has(tool)) return;

      const reason = await askGuard(input.tool, output.args);
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
