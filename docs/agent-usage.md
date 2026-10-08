# Agent usage

How an AI agent should use Vahta so that secrets stay out of its context, and
what it must leave to the person. The mechanics are in [daemon.md](daemon.md).

## The contract

- The agent may **trigger** commands that need secrets.
- The agent never reads a vault value. There is no command that returns one to it.
- The person types the vault password, and any value to store, in the window
  Vahta opens, never in the agent's terminal.

## What the agent does

1. Find what is available: `vahta list` (names, kinds and tiers; no password).
   `vahta check` compares the vault with `vahta.toml`.
2. Run a command with the secrets it needs:

   ```bash
   vahta run --secret OPENAI_API_KEY --as OPENAI_API_KEY=OPENAI_API_KEY -- python my_script.py
   ```

   `--as NAME=VAR` maps a vault name (left) to an environment variable (right).
   Without `--secret`, every name in `vahta.toml` that the vault holds is used.
3. If there is no session, a window asks the person for the password for that
   run. To avoid asking each time, open a session:
   `vahta unlock --secret A --secret B --for 1h --label "why"`. The person
   approves it once; `vahta run` from that process and what it starts then needs
   no window.
4. Use the scrubbed output and the exit code. A value in the output is replaced
   by `***REDACTED(NAME)***`; do not try to recover it.
5. If a run is refused (exit 3), the answer names the reason; with `--json` it is
   structured. Fix the command rather than retry it.
6. To get a secret's allowed commands set, propose rules with `vahta bind NAME
   --allow PROGRAM --reason "..."`. The person approves. `vahta run --ask` asks
   the person about one command that the rules do not allow.
7. If the hook cut something out of a tool's output that is needed,
   `vahta output allow REF --reason "..."` asks the person to show it
   ([hooks.md](hooks.md)).

## What the agent must not do

- Put a key or password in chat, a commit, a `.env` file or a command line.
- Run `vahta reveal`, `vahta copy` or `vahta _surface`. The hook refuses them: a
  window can be captured and the clipboard can be read.
- Read, edit, copy or redirect into `.vahta/` or Vahta's data directory, or edit
  a harness's hook settings. To pause the hook, ask with `vahta hooks pause
  --for 1h --reason "..."`.
- Run `vahta init` expecting it to complete: it needs the person at the window.
- Encode or split a secret-shaped value to get it past the hook. That is read as
  an injection signal, and several of them lock the sessions.

## Human-only commands

| Command | Why |
|---|---|
| `vahta init` | Creates the vault; the recovery key is shown once, to the person |
| `vahta add`, `reset`, `tier`, `remove` | Change the vault; password required |
| `vahta reveal`, `vahta copy` | Show a value to the person only; always a fresh password |
| `vahta bind` (approval) | The agent proposes; the person approves |

A session is a *runner*: it can `run` and nothing else. `reveal`, `copy` and every
write need a fresh password even inside one.
