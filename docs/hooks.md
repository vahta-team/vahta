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
| Claude Code | every tool | `updatedToolOutput`, in the tool's own shape; `updatedMCPToolOutput` for MCP tools. The model is told through `additionalContext`. |
| Cursor | MCP tools only | `updated_mcp_tool_output`. Cursor has no rewrite for its own tools (Shell, Read): there a secret gets the old notice instead. |
| Codex | every tool | `decision: "block"` with the cut output, then the message for the model, as the reason. |

The Cursor and Codex replies follow their documentation but have not yet been
checked against the running agents; their manifests say so.

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
