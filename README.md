<p align="center">
  <img src="https://raw.githubusercontent.com/vahta-team/vahta/master/media/assets/approved/logo-512.png" alt="Vahta" width="200">
</p>

# Vahta

**Let your AI agent *use* your passwords and API keys, without ever letting it
*see* them.**

Vahta keeps a project's secrets in an encrypted vault. You type the vault
password, and any secret you store, in a window the Vahta daemon opens, never in
the terminal an agent is reading. The agent runs `vahta run -- COMMAND`; the
daemon starts the command with the secrets in its environment and hands back the
output with the secrets taken out. The agent gets an exit code and scrubbed
output, and never a value. A hook registered with the agent's harness refuses a
secret-shaped value in a tool call and cuts one out of a tool's output.

> **Status: pre-release.** This is version 0.0.1 in development. It is not yet
> published to any registry; you build it from source.

Vahta is the Rust rewrite of [key-amnesia](#coming-from-key-amnesia). It is
Apache-2.0 licensed.

## Install

From a checkout, with a Rust toolchain (the exact version is pinned in
[`rust-toolchain.toml`](rust-toolchain.toml); `rustup` picks it up by itself):

```bash
git clone https://github.com/vahta-team/vahta.git
cd vahta
scripts/install-local.sh
```

This builds `vahta`, `vh` (the same program under a short name) and `vahta-hook`,
and copies them into `~/.local/bin` (or `$XDG_BIN_HOME`; `--prefix DIR` picks
another). Make sure that directory is on your `PATH`. `scripts/install-local.sh
--uninstall` removes them again.

Then register the hook with the coding agents on the machine:

```bash
vahta setup              # shows which harnesses were found and their state
vahta setup --all        # installs the hook in every harness that was found
vahta setup --claude     # or --codex, --cursor, one at a time
```

Bare `vahta setup` changes nothing. `--dry-run` prints the change as a diff,
`--uninstall` takes the entries out and leaves everything else alone. After an
install, on a terminal, setup also asks whether to run the hook watchdog (below).

## The core flow

```bash
cd my-project
vahta init                         # create .vahta/ and the vault; the recovery key is shown once
vahta add OPENAI_API_KEY           # type the value in the window that opens
vahta import --dotenv .env         # or bring in an existing .env file
vahta unlock --for 1h              # one password, then `run` needs no window
vahta run --secret OPENAI_API_KEY -- python my_script.py
vahta lock                         # end this project's sessions
```

- Every command that needs the password opens a new terminal window that says
  what is about to happen. No command takes a secret or the password as an
  argument or on standard input.
- `vahta unlock` opens a **session** that belongs to the calling agent process and
  what it starts. It ends at its deadline, when that process exits, on `vahta
  lock`, and on suspend or screen lock (Linux).
- Without a session, `vahta run` asks for the password for that one run.
- A secret is **session** tier (the default) or **each-use**, which needs the
  password every time and never enters a session.
- `vahta scan` finds plaintext secrets an agent could read in a project (names and
  counts, never values). `vahta list` and `vahta check` show what the vault holds
  and compare it with `vahta.toml`, the committed list of names.
- `reveal` and `copy` show a value to the person only, always with a fresh
  password, and the hook refuses them when an agent runs them.

Commands, exit codes, sessions, delegation to sub-agents and the configuration
file are in [docs/daemon.md](docs/daemon.md). A short guide for the agent itself
is [docs/agent-usage.md](docs/agent-usage.md).

## What the hook does

`vahta-hook` runs on the agent's tool calls. It:

- **blocks a secret-shaped value** in a command, a file write or an MCP argument:
  vendor token shapes (about 400 rules, kept as data), passwords in connection
  strings and in program arguments, private-key headers, names that mean secret
  (`API_KEY=`, `--token`, Bearer values);
- **blocks evasion**: values hidden in base64 or hex, or joined from pieces, and,
  with the daemon running, the values Vahta holds in other encodings (base64,
  hex, URL-encoded, reversed);
- **redacts tool output** before the model sees it, replacing each value with
  `***REDACTED(NAME)***`. If the agent needs what was cut, `vahta output allow`
  asks the person ([docs/hooks.md](docs/hooks.md));
- **guards Vahta's own files**: reading, editing or copying `.vahta/` and the
  data directory is refused, as are `vahta reveal`, `vahta copy` and the prompt
  window command;
- **guards the hook settings**: an edit that would remove Vahta's entries or turn
  hooks off is refused; the one door is `vahta hooks pause`, which the person
  approves with the password;
- **runs a watchdog** (if you said yes at setup): a small separate process that
  holds no keys and only watches the three harnesses' hook settings. If the hooks
  disappear it asks you before putting them back;
- **raises an injection alarm**: refusals are scored per agent, and several in a
  few minutes (a secret retried in base64, a touch of Vahta's files) open a
  window offering to lock every session, or lock them at once with
  `alarm = "lock"`.

What each side is told: the agent gets the category and the fix; the person gets
the rule. Every refusal is journaled without the value.

## Binding secrets to commands

Without rules, a secret works with any command, so an injected instruction could
send it somewhere in an open session. A secret can carry rules saying which
commands may have it:

```toml
[secrets.STRIPE_KEY]
description = "Stripe live key"
allow = ["stripe", "./scripts/deploy.sh", "git push"]
deny  = ["@network", "@shells"]
```

The agent proposes rules with `vahta bind`; the person approves them in a window
with the password. The rules that count are the approved copy inside the signed
vault, not the file. A command the rules do not allow is refused;
`vahta run --ask` lets the person decide once or add it to the list. Binding has
real limits (an allowed program can itself pass a secret on); they are written
down in [docs/daemon.md](docs/daemon.md#binding-secrets-to-commands).

## Supported harnesses and platforms

| Harness | Hook installed by `vahta setup` |
|---|---|
| Claude Code | yes |
| Codex | yes |
| Cursor | yes (its own tools' output cannot be rewritten; only MCP output is) |

Each harness is described by a manifest under
[`crates/harness/harnesses/`](crates/harness/harnesses). The Cursor and Codex
output replies follow their documentation and have not yet been checked against
the running agents.

Linux is the platform tested most, and the one the sleep and lock handling is
written for. macOS and Windows build and run the test suite in CI, and have the
operating-system pieces (peer identity, local socket, autostart) in place, but
have seen less real use. The window opens in a terminal, so a machine with no
display cannot run commands that need a password.

## Limits

Vahta stops an agent from *asking* for a secret. It cannot stop everything an
agent running as you could *do*: the command `vahta run` starts has the secret in
its environment and can print or send it, another process of yours can read
`/proc/<pid>/environ` while it runs, and the hook is a speed bump that does not
follow globs, variables or interpreters. Read
[What this does not protect against](docs/daemon.md#what-this-does-not-protect-against)
before relying on it.

## Coming from key-amnesia

Vahta is the successor of key-amnesia (`ka`), the Python tool. `key-amnesia`
stays on PyPI, and its code is kept in [`legacy/`](legacy) for reference. To bring
a ka vault over:

```bash
vahta import --ka PATH_TO_KA_VAULT
```

The daemon reads the file itself and asks for the ka password in the window. A
name the Vahta vault already has refuses the whole import.

## Documentation

- [docs/daemon.md](docs/daemon.md): commands, sessions, binding, the daemon, the
  watchdog, the alarm, detector rules, limits
- [docs/hooks.md](docs/hooks.md): tool output redaction and observe mode
- [docs/agent-usage.md](docs/agent-usage.md): how an agent should use Vahta
- [DESIGN.md](DESIGN.md): how the parts fit together
- [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md),
  [CHANGELOG.md](CHANGELOG.md)
