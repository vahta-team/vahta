# Secrets in tool output

The Vahta hook (`vahta-hook`, registered by `vahta setup`) looks at what goes
*into* an agent's tools (commands, file writes, MCP arguments) and refuses a
secret there. This page is about what comes *out*: the output of a command, a
file the agent reads, an MCP server's result. That output is about to enter
the model's context, and a secret in it would stay there.

## What happens

After every tool call, before the model sees the result:

1. The hook looks for secrets in every string of the result, in two ways:
   - **the detector**: the same one that guards tool input. Only *likely* finds
     are cut (a vendor-prefixed key, a likely `Bearer` token, a likely value
     after `password=` or `--token`). A merely *possible* one is left alone, and
     nobody is told; the daemon's journal records it if the daemon is running;
   - **exact values**, if the daemon is running: every place a value appears
     that the daemon holds for this agent. That means the values of the
     sessions open for it, and the values given to commands it ran with
     `vahta run` in the last 30 minutes. Values shorter than 8 characters are
     not matched; they would cut ordinary words.
2. Each value found is replaced by `***REDACTED(<NAME or kind>)***`: the
   secret's name when the daemon knew the value (`***REDACTED(DB_PASSWORD)***`),
   the detector's kind otherwise (`***REDACTED(OpenAI-style key)***`). The rest
   of the result is unchanged, in the shape the tool gave it.
3. The model is told how many values were cut and of what kind, and how to ask
   for them (below). If the daemon is not running, the original was not kept:
   the model is told it cannot be shown, and the person is told what was cut.
4. Clean output gets no answer at all and reaches the model as it was.

The hook never starts the daemon and waits at most 0.3 seconds for it. If the
daemon is not there, or does not answer, the detector's cuts stand: the hook
never lets through more than it did before there was a daemon.

## When the agent needs what was cut

The model's message names a reference, and the command to ask with:

```
vahta output allow <ref> --reason "why it is needed"
```

A window opens for the person (never the agent's terminal). It shows the tool,
the directory, the agent's reason marked as unverified, and each value that was
cut: its name or kind, its length and its line with the value masked. It never
shows a value, because a window can be captured. The person chooses:

- **Show to the agent**: the output is printed by `vahta output allow`, as the
  tool gave it, and from then on the hook lets those values through for this
  agent: for as long as its session lasts, or 30 minutes if it has none. If the
  agent has a session open, choosing is all it takes; if not, the vault's
  password (of the project the output came from) approves it.
- **No**: nothing is shown; the command exits 4.
- **Save as a secret**: the window asks which value (if several), a name and a
  tier, then the vault password, and stores the value. The output stays cut,
  and the agent is told to use it with `vahta run --secret NAME`.

Only the agent whose tool produced the output may ask for it: a reference from
another agent's hook is refused (exit 3), as is one that has expired. The
original is kept in the daemon's memory for 10 minutes, never on disk, and not
at all for an output over 768 KiB. Every request and its outcome are in the
journal, with the reference and the names or kinds; never a value.

`vahta output allow` is the one place a `vahta` command receives what may be a
secret value, and only after the person said so in the window.

## Observe mode

```toml
# <config dir>/vahta/config.toml
hook_output = "observe"   # default: "redact"
```

With `observe`, the hook changes no output. It tells the person and the model
that a secret reached the transcript (and to rotate it), as it did before
redaction, and the daemon, if running, journals what was seen (kinds and
counts). Use it to see what redaction would do before turning it on, or when
another hook of yours also rewrites tool output. A config the hook cannot read
counts as `redact`.

`hook_tool = "observe"` is the same for a secret in a tool call before it runs
(default `"block"`): the call goes through and the daemon is told. See "Detector
rules" in [daemon.md](daemon.md) for what is looked for and what is never let
through.

## Other hooks that rewrite output

If another of your hooks also rewrites tool output on the same event, which
rewrite the model gets is not settled: Claude Code's documentation runs
matching hooks in parallel and does not define which of several output
rewrites wins.

By default `vahta setup` leaves our hook entries where they are in your config
and adds new ones after the entries already there; it does not reorder your
hooks behind your back. If you want ours to come last, run:

```
vahta setup --claude --last      # or --refresh --last, --all --last
```

This moves our entries behind every other hook of the same event. It is a
choice, not the default, because it changes the order of hooks you set up. If
the result still matters, use observe mode, or one rewriting hook per event.

## Per harness

| Harness | Rewrites | How |
|---|---|---|
| Claude Code | Bash, Read, Grep, Glob, MCP tools (the PostToolUse matcher) | `updatedToolOutput`, in the tool's own shape; `updatedMCPToolOutput` for MCP tools. The model is told through `additionalContext`. |
| Cursor | MCP tools only | `updated_mcp_tool_output`. Cursor has no rewrite for its own tools (Shell, Read): there a secret gets the old notice instead. |
| Codex | Bash, apply_patch, MCP tools (the matcher) | `decision: "block"` with the cut output, then the message for the model, as the reason. |

### What was checked, per tool

Claude Code 2.1.286, live, with the real hooks and a mock model (no token):
`python3 bench/bench.py cc-redact`. A canary held by Vahta is made to appear in
each tool's output, and the mock records every `tool_result` Claude Code sends
back to the model.

| Tool | Result |
|---|---|
| Bash (`cat`, a script) | redacted by the hook |
| Bash under `vahta run` | already cut by `vahta run` itself; the hook sees nothing |
| Read, Grep (content) | redacted by the hook |
| MCP tool (stdio server) | redacted by the hook (`updatedMCPToolOutput`) |
| Read, Grep, `cat` of a file holding an inline credential | refused before running (PreToolUse) |
| Edit, Write | the result carries no file content in this version; not in the matcher |
| WebFetch, WebSearch, Agent | not in the matcher, so not rewritten, and not tested offline |

The trap: Claude Code ignores, silently, a replacement that does not match the
built-in tool's output shape, and the original reaches the model. The hook sends
back the structure Claude sent (`tool_response`) with only its strings changed,
so the shape is the tool's own. `crates/harness/harnesses/claude/fixtures/shape_*.json`
pin it for Bash (stdout, stderr), Read, Grep, Glob and MCP (block array, string),
using the shapes captured from the live run. If a Claude Code release changes a
tool's shape, `cc-redact` is the check to rerun.

Cursor and Codex have not been run live; their replies follow the documentation
(Codex: https://learn.chatgpt.com/docs/hooks; Cursor: https://cursor.com/docs/agent/hooks,
read 2026-10-13). Codex's PostToolUse takes `systemMessage`, `continue`, `stopReason`,
`decision`, `reason` and `hookSpecificOutput.additionalContext`; `updatedMCPToolOutput`
and `suppressOutput` are parsed but unsupported, and a hook that emits one is marked
failed while the original result goes on to the model, so we never emit them (a unit
test pins the keys). Live checks still to do:

- Codex: `decision: "block"` really replaces the result for Bash, apply_patch and MCP;
  `additionalContext` is accepted in the notice reply; hooks trusted in `/hooks`.
- Cursor: `updated_mcp_tool_output` is documented as an object; we give a plain-string
  MCP result back as a string. If Cursor rejects that the original goes through.
- Cursor: whether Shell/Read output can be rewritten at all (undocumented; we treat it
  as impossible and only warn).

## What cannot be done

- A value the model has already seen cannot be taken back. No harness has a hook that
  edits the conversation so far (compaction hooks cannot rewrite it either), and a
  provider-side or on-disk transcript copy is out of reach. The person should rotate
  the key.
- A tool the harness gives no rewrite for (Cursor's Shell and Read; hosted tools such
  as web search; tools outside the matcher) leaves the output as it was.

## What this does not catch

- A value that appears **transformed**: base64, URL-encoded, escaped inside a
  JSON string, split across lines or across two strings of the result.
- A value the detector does not see as likely and the daemon does not hold:
  a secret that is not in the vault, read while the daemon is not running.
- Values shorter than 8 characters, by exact match.
- A result nested more than 64 levels deep is not rewritten; it gets the old
  notice.
- The cut happens in what the model is shown. The tool itself ran with the
  real output: a file it wrote, a request it sent, are not changed.
