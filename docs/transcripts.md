# Transcripts

The hooks redact a tool's output before the model sees it. A value that
already reached the context anyway (the person pasted it, or it slipped past
the detector) is in the harness's transcript file too, and the next
`--resume`, a backup or a sync of the home directory carries it on.

## `vahta scrub --transcript`

```
vahta scrub --transcript          # this project's transcripts
vahta scrub --transcript --all    # every project's
```

The agent may run it without a window: it only removes. The daemon does the
work because it knows the values. It looks for

- the values the daemon holds for the caller, in every form it knows (raw,
  base64, hex, URL-encoded, reversed) and in their JSON-escaped spelling, which
  catches a value inside a tool result that is itself JSON, and
- what the detector calls a likely secret,

and replaces each with `***REDACTED(NAME)***`, or `***REDACTED(kind)***` for a
detector find. It prints counts and file paths, never a value or the text
around one. With no unlocked session only the detector's finds are removed.

| Harness     | Where                                                         | Covered |
|-------------|---------------------------------------------------------------|---------|
| Claude Code | `$CLAUDE_CONFIG_DIR` or `~/.claude`, `projects/<dir>/**.jsonl` | yes     |
| Codex       | `$CODEX_HOME` or `~/.codex`, `sessions/` and `archived_sessions/`, `rollout-*.jsonl` | yes |
| Cursor      | a SQLite database in its own data directory                   | no      |

Claude names `<dir>` after the working directory it was started in, every
character that is not a letter or a digit written as `-`
(`/home/ann/app` is `-home-ann-app`). Very long paths are shortened by Claude
with a hash; those are only found with `--all`. Codex rollouts are matched to
the project by the working directory recorded on their first line.

Not covered: Cursor's chats; Claude's prompt history (`history.jsonl`) and the
large tool results it may keep as separate files next to a session; Codex's
`history.jsonl`. A value the person typed into a prompt can be in the history
files.

### How a file is rewritten

Each line is read as text, its string literals are decoded, cleaned and written
back only when they changed. Everything else on the line, and every line with
nothing to remove, is copied byte for byte (key order, number spellings, line
endings, a missing final newline). A marker is plain characters in a legal JSON
string, so a line that was valid JSON stays valid. A line is never built into a
tree, so a deeply nested one is no problem.

A file is rewritten through a temp file in the same folder, fsynced and renamed
over the original. Permissions and the modification time are kept. If the file
changed between the read and the rename the command reports `FAILED` and leaves
it alone: run it again. Links are not followed.

### A running session

The harness appends to the transcript of a running session, so it is not
rewritten while it runs. A file counts as running when it changed in the last
minute, or when the `SessionStart` hook announced its session and no
`SessionEnd` has come, and it changed in the last six hours. A running file is
read, its secrets are recorded as exposed, and it is marked as `deferred`. When
the session ends, the Claude `SessionEnd` hook tells the daemon, and a second
later it cleans the marked files of that session. Codex has no end-of-session
event in the hooks Vahta registers, so a deferred Codex file is cleaned by the
next `vahta scrub --transcript` once it is quiet.

The daemon forgets its marks when it restarts. A file is then judged by its
modification time alone.

### Exposed secrets

Every secret whose value is found in a transcript is recorded in the machine's
record of its vault (the file in the data directory that also pins the owner key
and the highest generation seen): its name and the time, never the value or the
file. The record is authenticated, and the marks are part of what is
authenticated, so a mark an agent deletes or alters makes the vault's next unlock
fail ("this machine's record of the vault failed its integrity check") instead of
quietly forgetting the exposure. `vahta list` and `vahta check` read the marks
without the vault key, so they cannot tell an edit; the unlock does. An
`exposed.json` from an earlier build is moved into the record of each vault the
first time that vault is unlocked, and deleted when it is empty. `vahta list` and `vahta check` print
`exposed in a transcript - rotate it` with `vahta reset NAME` until the secret
is reset or removed. In `vahta check` it is a warning and does not change the
verdict.

### What it cannot do

It cannot clean the conversation the model is in. A value in the context stays
there until `/clear` or a new session, and it has already been sent to the model
provider. Removing it from the file does not un-send it: rotate the secret.
This is also what the hook tells the agent when a secret reached the transcript
and could not be redacted.

## What Claude Code writes to the transcript after a hook rewrites an output

Research, to be confirmed in a bench run. Read from the bundled JavaScript of
the installed Claude Code 2.1.301 (the `claude` binary; read-only, no model
run) and from the hooks documentation as quoted in the harness manifest.

**Verified in the installed code (reading it, not running it):**

- A PostToolUse hook may return `updatedToolOutput` (every tool) or
  `updatedMCPToolOutput` (MCP tools; the schema says to prefer
  `updatedToolOutput`). The schema describes it as "Replaces the tool output
  before it is sent to the model".
- Hooks of one event run in parallel on the original output. If several rewrite
  it, the last one to finish wins; an identity rewrite from one hook can undo a
  redaction by another.
- The accepted replacement becomes the tool's result data. That data is what
  the tool-result block sent to the model is built from, and it is also what the
  `toolUseResult` field of the transcript entry is built from, so for a tool
  whose rewrite was accepted both carry the replacement.
- A replacement that does not match the tool's output shape is rejected: Claude
  logs `PostToolUse hook returned updatedToolOutput that does not match ...;
  using original output`, shows the person a hook error, and uses the
  **original** output, secret included, for both the model and the transcript.
  The redaction therefore has to keep the tool's own shape (the hook does).
- `toolUseResult` is kept for the main agent. In a sub-agent it is dropped
  unless a setting asks to preserve it.

**Assumed, not verified:**

- That a hook's `additionalContext` is stored as an entry of its own (it
  reaches the model; the storage form was not traced).
- That the original output is not written anywhere else in the transcript
  (a `hook_success` attachment holds the hook's own stdout, which is our
  reply, not the tool output; the code was not traced to the last write).
- That the rewrite is applied before the entry is written for every tool,
  including Bash with large output that Claude may persist to a separate file.
- That `updatedMCPToolOutput` is written like `updatedToolOutput`.
- Whether a streamed or backgrounded tool result takes another path.

**The check to run in a bench:** run a Bash command that prints a canary,
redacted by the hook, then search the session's `.jsonl` and any files under
the session folder for the canary.

## What a `/compact` summary may retain

`/compact` (and auto-compact) asks the model to write a summary of the
conversation, from the messages as the model saw them. Verified in the
installed code: the summary prompt asks for, among other sections, "Files and
Code Sections" with full code snippets, errors and how they were fixed, and
"All user messages ... not tool results", with security-relevant instructions
kept verbatim. The entry that holds it is marked `isCompactSummary`.

So a summary can retain any value the model saw, including a pasted one, a
value in a file it read, and a value in a code snippet it copied. A value that
Vahta redacted before the model saw it is not in what the model saw, so it is
not in the summary; the marker may be. A value already in the context can
survive `/compact` in a paraphrase or a snippet and gets written to the
transcript as the summary. Cleaning the file afterwards removes the literal
value, not a re-encoding or a description the model made of it. Assumed, not
verified: how much of the older transcript Claude keeps on disk after a
compact (it appends a summary entry; whether earlier entries stay in the file
was not traced).
