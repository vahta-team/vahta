# The Vahta daemon: sessions, `vahta run` and the vault commands

Vahta keeps a project's secrets in an encrypted vault, `.vahta/vault.vht`, and
lets an agent *use* them without ever *seeing* them. The pieces that do that are
a small background process, the daemon, and the `vahta` commands that talk to it.

This page says what each command does, what you will see, and, at the end, what
Vahta does not protect against.

## The idea in one paragraph

You type the vault password, and any secret you store, in a **window the daemon
opens**, never in the terminal an agent is reading and never on a command line.
The agent runs `vahta run`; the **daemon** starts the command with the secrets in
its environment and sends the output back with the secrets taken out. The agent
gets an exit code and scrubbed output, and never a value.

## Commands

Every command that needs the password opens a **new terminal window** (never the
one you or the agent typed in) showing what is about to happen, then asks. If no
window can be opened (no display, no terminal found) the command fails and says
nothing was done.

| Command | What it does | Password |
|---|---|---|
| `vahta init` | Create `.vahta/` and the vault here. The recovery key is shown once, in the window. | new password, twice |
| `vahta set NAME [--tier session\|each-use] [--file FILENAME]` | Store or replace a secret. The value is typed in the window, hidden, twice. | yes |
| `vahta remove NAME` | Remove a secret. | yes |
| `vahta import --ka PATH` / `--dotenv PATH` | Add the secrets of a ka vault or a `.env` file. The daemon reads the file itself. A name the vault already has refuses the whole import. | yes (and the ka password for `--ka`) |
| `vahta reveal NAME` | Show the value in the window until a key is pressed or 60 seconds pass. | yes |
| `vahta copy NAME` | Put the value on the clipboard; it is cleared after 30 seconds if it is unchanged. Needs `wl-copy`, `xclip`, `xsel`, `pbcopy` or `clip`. | yes |
| `vahta unlock [--secret NAME]... [--for DURATION] [--label TEXT]` | Open a **session** (below). | yes |
| `vahta lock [--all]` | End this project's sessions, or all of them. | no |
| `vahta sessions [--json]` / `vahta sessions kill ID` | List sessions, or end one and everything below it. | no |
| `vahta run [--secret NAME]... [--as NAME=VAR]... -- COMMAND` | Run a command with secrets in its environment. | only without a session |
| `vahta delegate --secret NAME... [--for DURATION] -- COMMAND` | Give a sub-agent a narrower session. | no |
| `vahta list`, `vahta check` | Names, kinds and tiers; compare with `vahta.toml`. | no (they read the signed name index) |
| `vahta daemon run\|status\|stop\|restart` | The daemon itself. | no |

None of these takes a secret or the password as an argument or on standard input.
There is no flag for it, on purpose.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | done |
| the command's | `vahta run` and `vahta delegate` pass the command's exit code through (128 plus the signal for a command a signal ended) |
| 1 | the request failed |
| 2 | usage |
| 3 | **refused**, with a reason (see below) |
| 4 | the window was cancelled, or nobody answered |
| 5 | the daemon is not available |

A refusal is structured. With `--json` the answer names the kind and each name and
why, so an agent that made a mistake can rebuild the command:

```json
{"ok": false, "refused": {"kind": "each_use", "message": "...", "names": [{"name": "DB_PASSWORD", "why": "each_use"}]}}
```

## Tiers

A secret is **session** (the default) or **each-use**.

- A *session* secret can be held by a session, so `vahta run` can use it without a
  window while a session is open.
- An *each-use* secret needs the password **every time** and never enters a
  session. Use it for the few things you want a person to approve each time.

## Sessions

`vahta unlock` is meant to be called by the agent. A window opens and shows you the
project, the vault, the names, how long, and **which process the session belongs
to** (its name and pid). You read it and type the password. From then on, `vahta
run` from that process, and from everything it starts, needs no window.

- **Scope.** Without `--secret`, every session-tier secret in the project's vault.
  With `--secret A --secret B`, only those. Naming an each-use secret, or one that
  does not exist, refuses the *whole* request before any window opens (exit 3),
  and the refusal goes to the journal.
- **Length.** 30 minutes by default (`session_minutes` in `config.toml`);
  `--for 2h` (also `90s`, `1h30m`) per unlock; `--for forever` until revoked.
- **Extension.** Two minutes before a session ends the window asks "Extend by 30
  minutes?". Yes or no; no password, because the keys are still in memory. With no
  answer the session ends at its deadline, and a new one needs the password.
- **The anchor.** A session belongs to an *anchor* process and everything it
  starts. The anchor is the nearest ancestor of the calling `vahta` that is not a
  shell or a wrapper (`bash`, `zsh`, `sudo`, `env`, `timeout`, ...), so Claude
  Code's `bash -c` anchors to `claude`. A shell sitting directly under a terminal,
  `sshd`, `login`, a `tmux` server or `systemd` is the anchor itself, so your own
  `vahta unlock` covers the shell you typed it in and nothing else. The anchor must
  be yours, above the lowest pid and more than two levels above init.
- **Role.** A session is a *runner*: it can `run` and nothing else. `reveal`,
  `copy`, `export` and every write need a fresh password.
- **Label.** `--label` lets the agent say why. It is shown in the window marked
  "from the agent, not verified", cleaned to one plain line of at most 200
  characters. What you approve is the list Vahta renders, not the label.
- **Ending.** At the deadline, when the anchor process exits, on `vahta lock` or
  `vahta sessions kill`, when the daemon stops, and (Linux, `lock_on_sleep`, on by
  default) when the machine suspends or the screen locks through logind.
  Ending a session also ends every session below it and overwrites its keys.
- **Changes.** If a secret is changed after a session opened, a read through the
  session fails with "changed since this session was opened; unlock again" (exit
  3). It never quietly falls back to something else.

### Delegation

`vahta delegate --secret A --for 10m -- sub-agent ...` narrows *your* session for a
sub-agent. The new session covers a subset of yours, ends no later than yours, and
belongs to the `vahta delegate` process, so it ends when the sub-agent does. A
secret your session does not have, or a longer time, is a hard refusal with no
window. When several sessions match, the narrowest wins: a `vahta run` inside the
sub-agent can use only what it was given and never asks you for more.

## `vahta run`

```
vahta run --secret API_KEY --as API_KEY=SERVICE_TOKEN -- ./deploy.sh
```

- **Names.** `--secret NAME` (repeatable), else every name in `vahta.toml` that the
  vault holds. The variable is `--as NAME=VAR`, else the `env` of NAME in
  `vahta.toml`, else the name.
- **When there is a window.** If the caller's session covers every name and all
  are session-tier, none. Otherwise a window asks for the password *for this one
  run* and no session is created. An each-use secret always asks, even inside a
  session.
- **The command** gets your arguments, working directory and environment, minus
  `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, `DYLD_*` and `VAHTA_*`, plus the
  secrets. Standard input is relayed, Ctrl-C and termination are forwarded, the
  exit code passes through, and if `vahta run` is killed the command is ended.
- **Output** comes back with every value replaced by `***REDACTED(NAME)***`.
  Matches are found even when a value is split across two reads, overlaps another
  value, or contains one.
- **Children inherit the session.** A `vahta run` from inside a command the daemon
  started uses the same session.

## The daemon

One runs per user, started on demand by the `vahta` commands (never by the agent
hook) and not a system service. It exits after 10 idle minutes (no sessions, no
connections). It listens on a Unix socket in a private runtime directory (a named
pipe only you can open, on Windows), and it knows who is calling from the
operating system, never from what the caller says.

If a newer `vahta` meets an older daemon with no sessions, the old one exits and a
new one starts. If it holds sessions, the command says so and points to `vahta
daemon restart` (which ends them).

On Linux the daemon is not dumpable and writes no core files, and it keeps every
key in memory that is wiped when it is dropped. Its memory is **not** locked
against swap: locking all of it makes the system refuse new threads once the
locked-memory limit is reached, and locking only the pages that hold keys is not
done yet. Use encrypted swap (or none) if a key paged to disk matters to you. A session keeps only the data keys of
the secrets it covers; the vault key is dropped right after the password is
checked.

### Configuration: `<config dir>/vahta/config.toml`

```toml
session_minutes = 30    # default length of `vahta unlock`
lock_on_sleep = true    # end sessions on suspend and screen lock (Linux)
terminal = "kitty"      # the terminal the window opens in (Linux); empty = detect
idle_minutes = 10       # the daemon exits after this long with nothing to do
```

A misspelt key is an error, not a silent default. On Linux the window opens in
the first terminal that works: `VAHTA_TERMINAL` if set, else `terminal` from the
config, else `$TERMINAL`, else the first of the table Vahta carries that is
installed (your desktop's own first). Name yours with the flag that makes it run a
command if it is not found: `terminal = "alacritty -e"`.

### Files

- `.vahta/` in a project: the vault, its lock and its backups, with a `.gitignore`
  of `*`. `vahta.toml` (the committed list of names) sits beside it.
- `<data dir>/vahta/`: what this machine remembers about each vault (the pinned
  owner key and the highest generation seen, so a swapped or rolled-back vault is
  refused), and `journal.jsonl`.
- `journal.jsonl`, mode 0600: each line is a time, an event, the session and its
  parent, the vault, the secret *names*, the peer's program and pid, the result
  and reason, and use counts. **Never a value and never a password.**

The agent hook refuses to read, edit, write, move, copy, remove or redirect into
any `.vahta/` directory or `<data dir>/vahta/`, and says which path.

## What this does not protect against

Vahta is built so that an agent cannot *ask* for a secret. It cannot stop everything
an agent running as you could *do*. Read this before relying on it.

- **The command sees the secret.** The command `vahta run` starts has it in its
  environment, and can print it, send it somewhere, or write it to a file. The
  scrubber catches a value that appears in the output as it is; it does **not**
  catch one that is encoded (base64, URL-encoded, split by the program's own
  formatting). Run commands you trust with secrets you can afford to have used.
- **`/proc/<pid>/environ`.** On Linux, a process of the same user can read the
  environment of another of its processes. While a command that was given a secret
  runs, another process running as you (including an agent's other tools) can read
  it from there. The daemon's own memory is protected from that (not dumpable); a
  command it started is not.
- **Revocation is not recall.** Ending a session, or the daemon, stops *future*
  uses. It cannot take a value back from a command that is already running, nor
  from output that already left.
- **Same user.** Everything runs as you. A hostile process of yours that can
  attach to the daemon would be refused a session it has no password for, but it
  can run what you can run. The window is a terminal window; a program that can
  watch or type into your terminals can watch or type into it.
- **No terminal for the command.** A command that needs a terminal gets pipes, not
  a terminal.
- **The anchor is a process, not a person.** A session covers the process it
  belongs to and everything it starts. If you unlock from inside an agent, the
  agent and its tools can use the secrets until the session ends.
- **Sleep and lock.** Ending sessions on suspend and screen lock is Linux only
  (logind); a screen locker that does not tell logind is not heard. macOS and
  Windows do not do it yet.
- **The hook is a speed bump.** The protection of Vahta's own files in the agent
  hook covers the common ways of reading or changing them (the read, edit and
  write tools, common shell readers, `rm`, `mv`, `cp`, redirections). It does not
  cover globs, `$VARS`, command substitution, interpreters (`python -c`), or a
  program that is handed a directory containing a vault. The vault's own
  encryption is what holds when the hook does not.
