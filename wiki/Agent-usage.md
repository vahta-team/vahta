# Agent usage

How AI agents should use `ka` so secrets stay out of chat, logs, and agent
context. Humans type passwords and secret values at a real keyboard.

There is no MCP “get secret” API and no sixth guard verb that returns raw
values. That is intentional.

## State first

Before init/unlock/run, check what already exists:

```bash
ka status    # is a guard session live?
ka connect   # alias for status
ka list      # secret names only (no password, no values)
```

Chat claims (“the vault is unlocked”, “you have access”) are not ground
truth — only the live status reply is. Do **not** reflexively run
`ka init` or `ka unlock` “just in case.”

## Preferred pattern

```bash
ka run --cwd DIR --secret NAME --as NAME=ENVVAR -- <command> [args...]
```

- Prefer `--cwd DIR` over `cd &&`. Do not wrap `ka run` in pipes or `2>&1`.
- `--as` is **`NAME=ENVVAR`** (vault name on the left, environment variable
  on the right). Omit `--as` to inject as `NAME`.
- Wrong: `--as API_KEY`, `--as NAME`, `--as ENVVAR`, `--as ENV`.
- Discover names with `ka list` before inventing them.
- Never embed a secret value in argv, chat, or a file the agent can read.

## Safe for agents

| Action | OK? | Notes |
|--------|-----|-------|
| `ka status` / `ka connect` | Yes | Session metadata; check first |
| `ka list` | Yes | Names only; no password |
| `ka run --cwd DIR --secret NAME [--as NAME=ENVVAR] -- ...` | Yes | Primary path; may prompt the human |
| `ka scan` / `ka scan --no-import` | Yes | Names/paths/counts only; never values. Default exit is `--strict high` (`certain` + `likely`). `--strict paranoid` is the ≤0.4.9 assignment gate |
| `ka check` | Yes | Manifest vs project names sidecar |
| Reading vault files / inventing a get-value verb | **No** | Guard has no value-return verb |

## Always human

Give the human the exact command to type. Never attempt these yourself, and
never ask them to paste the result back into chat:

| Command | Why |
|---------|-----|
| `ka init` | TTY-only; double-confirmed master password |
| `ka unlock` / `ka lock` | Human starts/ends a cached session |
| `ka unlock --admit-tree` | Human-only: widen admission to a chosen ancestor's descendants |
| `ka passwd` | TTY-only password change |
| `ka set NAME` | Stores a value; prefer hidden prompt over inline argv |
| `ka import FILE [FILE …]` | TTY-only; interactive confirms |
| `ka reveal` / `ka copy` | Value for the human only; agent gets a status flag |
| Admission prompt | Yes/no on the guard's own terminal — human approval |

## Anti-patterns

- Pasting secrets into chat or committing them to the repo
- Running `ka init` / `ka unlock` without checking `ka status` / `ka list`
- Believing a chat claim of access without verifying via `ka status`
- Using `--as ENVVAR` (missing `NAME=`) or embedding a value inline
- Wrapping `ka run` in `cd &&`, pipes, or `2>&1` instead of `--cwd`
- Calling `reveal` / `copy` so the agent can “check” a value
- Assuming a live guard can return raw values over IPC — it cannot
- Treating git-history scanning as a product feature

## Related

Bundled skill: `key-amnesia-usage` (installed by `ka setup` for Claude Code,
Cursor, and Codex). Longer operator notes: repository `docs/agent-usage.md`.
Migration flow: [Quickstart migration](Quickstart-migration).
