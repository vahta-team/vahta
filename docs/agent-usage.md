# Agent usage with key-amnesia

How humans and AI agents should use `ka` so secrets stay out of chat, logs, and agent context.

## The contract

- Agents may **trigger** commands that need secrets.
- Agents must **never** read vault values.
- Humans type the master password (and secret values on `set`) at a real keyboard — in their own TTY, or in the isolated approval console when an agent invokes a privileged command.

There is no MCP “get secret” API. That is intentional.

## What agents should do

1. Discover secret names with `ka list` (safe; names only; no password).
2. Run tools through injection:

   ```bash
   ka run --cwd DIR --secret OPENAI_API_KEY --as OPENAI_API_KEY=OPENAI_API_KEY -- python my_script.py
   ```

   Remap with `--as NAME=ENVVAR` (vault name on the left). Wrong: `--as OPENAI_API_KEY` without `=`.
   Prefer `--cwd` over `cd &&`; do not wrap `ka run` in pipes or `2>&1`.

3. Use scrubbed stdout/stderr and the exit code. Do not try to recover the original secret from output.

## What agents must not do

- Paste API keys or passwords into chat, commits, `.env` files, or command lines.
- Call `ka reveal` / `ka copy` to obtain a value for the agent. Even if invoked by an agent, the value appears only for the human (TTY or helper window / clipboard); the agent process gets a status flag only.
- Rely on a cached session (`ka unlock`) to unlock `reveal` or `copy` — it does not. Fresh human auth is always required for those commands (and for `remove`, `config set`, and `set`).
- Run `ka init` non-interactively. Vault creation is TTY-only with a double-confirmed master password. If the vault is missing, the human runs `ka init` locally.

## Human-only commands (summary)

| Command | Why |
|---------|-----|
| `ka init` | TTY-only; creates the vault |
| `ka set` | Stores a value; password required; prefer hidden prompt over inline argv |
| `ka remove` | Deletes a secret; password required |
| `ka config set` | Changes settings; password required |
| `ka reveal` / `ka copy` | Surfaces a value to the human only; always fresh auth |

## Cached vs per-call

- **per-call** (default): each privileged use prompts.
- **cached**: after `ka unlock`, `run` and `list` can proceed without prompts until timeout or `ka lock`. `reveal` / `copy` still always prompt. Operators who want fewer re-prompts for sibling agent invocations can unlock with `--pre-admit` (next connection only) or `--admit-tree` (choose an ancestor as root). Agents never run `unlock`.

## Related

Agent-oriented short form: the `key-amnesia-usage` skill (`src/key_amnesia/skills/key-amnesia-usage/SKILL.md`), installed for Claude Code / Cursor / Codex / OpenCode via `ka setup` (OpenCode auto-loads from `~/.claude/skills` and `~/.agents/skills`).

Human docs: [GitHub wiki — Agent usage](https://github.com/vahta-team/vahta/wiki/Agent-usage)
(`ka docs`).
