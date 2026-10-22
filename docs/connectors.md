# Connectors: the keys of MCP servers

Claude Code, Codex and Cursor start MCP servers (connectors) at user scope: a
GitHub or Gmail server, say, with an API key in its environment. Such a key
belongs to no project, so it does not live in a project's vault. Vahta keeps
**one connectors vault per user**, in its own data directory:

```
<data dir>/connectors/vault.vht      the vault
<data dir>/connectors/vahta.toml     the rules as proposed, next to it
```

(`<data dir>` is `VAHTA_DATA_DIR`, else the platform's, for example
`~/.local/share/vahta`.) It is a vault of its own kind. It is never found from a
working directory, never serves an ordinary `vahta run`, and `--connector`
never uses a project's vault.

You set it up yourself, in your own terminal. An agent cannot: the hook refuses
`vahta init|add|bind|remove|unlock|run --connector` from an agent's Bash tool,
and reading the vault directory is refused like any other Vahta file.

## Set up

```sh
vahta init --connector
vahta add --connector GITHUB_PERSONAL_ACCESS_TOKEN \
    --harness claude,codex \
    --allow 'npx -y @modelcontextprotocol/server-github@1.2.3'
```

`NAME` is the environment variable the server reads its key from. The value is
typed in the window, as always. A connector needs both:

- `--harness`: the harnesses that may start it (`claude`, `codex`, `cursor`);
- `--allow`: the server's command as the harness starts it after `--`. Pin the
  version: the rule trusts whatever that command runs. For `npx`, `bunx`, `uvx` and
  `pipx run` the rule may name just the program and the package; see
  [Rules for package runners](#rules-for-package-runners).

Without both it has no rules and nothing may start it. `remote` and `from` do
not apply to this vault. Change them later with
`vahta bind --connector NAME --harness ... --allow ...` (you approve in a
window); remove a connector with `vahta remove --connector NAME`. To replace a
key, remove it and add it again.

A server that must call its own API gets its hosts with the other rules, for
example `--net hosts:api.github.com` on `vahta add|bind --connector`. On Linux
the server then runs with no network except TLS to those hosts (see
[agent-usage.md](agent-usage.md)); on macOS and Windows that is not enforced.
A host that resolves to this machine or the local network is refused unless the
rule writes it `private:HOST`, as for any secret.

`vahta list --connector` shows each connector, its harnesses and command, and the
launches that were refused; `vahta check --connector` fails if one has no rules.

## Configure the harness

Put `vahta run --connector --secret NAME --` in front of the server's own
command. The harness must start `vahta` itself, not a shell or a script that
starts it.

### Claude Code (`.mcp.json` or `~/.claude.json`)

```json
{
  "mcpServers": {
    "github": {
      "command": "vahta",
      "args": [
        "run", "--connector", "--secret", "GITHUB_PERSONAL_ACCESS_TOKEN", "--",
        "npx", "-y", "@modelcontextprotocol/server-github@1.2.3"
      ]
    }
  }
}
```

Claude Code gives a server 30 seconds to finish starting and shows you nothing
of its error output, only "Connection closed". See
[Keys kept in a project vault](#keys-kept-in-a-project-vault) for `MCP_TIMEOUT`.

If a key needs a different variable name than the connector's (the server reads
`GITHUB_PERSONAL_ACCESS_TOKEN`, but you named the connector `GITHUB_TOKEN`), add
`--as NAME=VAR`, the same form as `vahta run --as`:
`"run", "--connector", "--secret", "GITHUB_TOKEN", "--as", "GITHUB_TOKEN=GITHUB_PERSONAL_ACCESS_TOKEN", "--", ...`.

### Codex (`~/.codex/config.toml`)

```toml
[mcp_servers.github]
command = "vahta"
args = [
  "run", "--connector", "--secret", "GITHUB_PERSONAL_ACCESS_TOKEN", "--",
  "npx", "-y", "@modelcontextprotocol/server-github@1.2.3",
]
# Codex waits 10 seconds by default; `npx` may need longer the first time.
startup_timeout_sec = 30
```

### Cursor (`~/.cursor/mcp.json`) - not checked live

```json
{
  "mcpServers": {
    "github": {
      "command": "vahta",
      "args": [
        "run", "--connector", "--secret", "GITHUB_PERSONAL_ACCESS_TOKEN", "--",
        "npx", "-y", "@modelcontextprotocol/server-github@1.2.3"
      ]
    }
  }
}
```

## Every day: the harness asks, you answer

There is nothing to run first. The first time a Claude Code, Codex or Cursor
process starts one of its connectors, a password window opens at once:

> Claude Code (pid 4242) wants its MCP servers: GITHUB_PERSONAL_ACCESS_TOKEN,
> GMAIL_TOKEN. Enter the connectors password.

Type the password of the connectors vault (or use whatever else your unlock
windows already accept for it, such as a paired phone). A session opens that
belongs to **that process**, by pid and start time, and covers the connectors
bound to its harness. Every other server that process starts, now or later, runs
with no window. Honestly: **each new harness process asks once**. A second Claude
Code, a Codex, or the same Claude Code after you quit and started it again has no
session of its own and gets its own window; a session never passes from one
process to another, and there is no way to leave the connectors open "for the
day" or until a reboot.

A harness starts several servers at once. Their launches wait for one window and
share its answer: all start when you type the password, or all fail when you
cancel. While the window for one harness process is open, another process's
window waits its turn (one window at a time per vault).

The session ends when the harness process exits, and also on `vahta lock --all`,
`vahta sessions kill ID`, `vahta lock --connector`, when the machine goes to sleep or the injection alarm
goes off, and at a reboot. `vahta sessions` shows it ("claude (pid 4242)", no end
time) and so does `vahta daemon status`. It is never extended or timed out, and
`vahta lock --connector` ends the connectors sessions of every harness process
(and nothing else); `vahta lock` without `--all` does not touch them (it ends
the current project's sessions). The journal names the harness and its pid when a connectors session
opens and when it ends, never a value.

**The harness waits about 30 seconds.** The window opens immediately, so answer
it promptly. If the harness gives up on a server and kills `vahta run`, Vahta
withdraws the window and nothing runs (journal: `cancelled`). If you cancel, or
the password is wrong after three tries, the server exits at once with a line on
its stderr, which the harness may show you:

```
vahta run: cancelled; nothing was done. The connectors were not unlocked and the
server did not start: reconnect the server in Claude Code (`/mcp`) to be asked for
the connectors password again.
```

**Reconnect after a no.** A server that did not start stays down until the
harness starts it again. In Claude Code run `/mcp` and reconnect the server (or
restart Claude Code); in Codex restart the session; in Cursor reload the MCP
server in its settings. You are asked again then.

`vahta unlock --connector` no longer exists; it prints this flow and exits.

## When Vahta tells you something

Vahta is silent when all is well: a launch with a session, or the password
window on the first one, is not news. It raises a desktop notification
(`notify-send` on Linux, `osascript` on macOS, a PowerShell toast on Windows)
only when something is really off, in plain words, naming the connector and
never a value:

| What happened | What it says |
|---|---|
| A process that is not the connector's harness tried to start its server | "A process that is not Claude Code tried to start the MCP server for NAME. Nothing ran." |
| A command outside the connector's `allow` rules (a different package or version, `npx -p`, `uvx --from`, another program) | "The MCP server for NAME was asked to run `npx -p evil ...`, which its rules do not allow. Nothing ran." |
| The connector's own key turned up in its server's output (Vahta hid it) | "The MCP server for NAME printed its own key. Vahta hid it." |
| Many refused launches in a short time (the same score the injection alarm keeps) | "Many launches of MCP servers (NAME) were refused in a short time. Nothing ran." |

Each points to `vahta journal` (try `vahta journal --kind connector`), which
shows the events in plain words, suspicious ones marked `!`. Limits: at most one notification per vault, kind and connector
every 10 minutes, and five in all in that time, so an agent cannot flood your
desktop. Every event is in the journal whether or not it was shown, and a
notification that was sent adds a `notified` line (kind and connector names).
Where the desktop has no notification service nothing is shown and only the
journal remembers.

## Keys kept in a project vault

Not every key is a connector. If a server's key lives in a project vault
(`vahta run --secret NAME -- ...` in the harness config), the first start of the
day opens a window for the password, and the harness is waiting meanwhile:

- **Claude Code** gives a server 30 seconds to start (`MCP_TIMEOUT`, in
  milliseconds, raises it: `MCP_TIMEOUT=120000 claude`). The server is killed at
  the cutoff and only "Connection closed" is shown, because its stderr is hidden.
- **Codex** waits `startup_timeout_sec` (10 seconds by default) per server:
  `startup_timeout_sec = 120` under `[mcp_servers.NAME]`.

Open a session first (`vahta unlock`) so no window is needed, or use a connector:
its window opens at once on the first launch of a harness process and the rest of
that process's servers share it.

## Rules for package runners

An `allow` rule is an argv prefix, so `npx -y @pkg/server@1.2.3` matches exactly
that start of a command. For the runners `npx`, `bunx`, `uvx` and `pipx run` (in
the project vaults too) a rule that names the package right after the program also
matches the command with the runner's harmless flags in front of it:

| Rule | Matches | Does not match |
|---|---|---|
| `npx @pkg/server@1.2.3` (pinned) | `npx @pkg/server@1.2.3`, `npx -y @pkg/server@1.2.3` | `npx -y @pkg/server@1.2.4`, `npx -y @pkg/server` |
| `npx @pkg/server` (any version) | `npx -y @pkg/server@1.2.3`, `npx @pkg/server@latest` | `npx -y @pkg/server-evil`, `npx -y evil @pkg/server`, `npx -p evil @pkg/server`, `npx @pkg/server@npm:evil` |

- The skipped flags are `-y`, `--yes`, `-q`, `--quiet` (npx), `--bun`, `-b`
  (bunx), `-q`, `--quiet` (uvx), `--no-cache` (after `run`, pipx). Any other
  option, or any word, before the package makes the command not match. In
  particular `npx -p`, `uvx --from` and `pipx run --spec` change what the package
  word means and are not skipped.
- **A version in the rule pins it**: the package word must be exactly that. **No
  version in the rule accepts any version**, but only a plain one (letters,
  digits, `.`, `_`, `+`, `-`); `@npm:other`, `@git+https://...`, a path, Python
  extras (`pkg[x]`) or ranges are not a version and do not match. An unpinned
  rule trusts whatever the maintainers publish next. **Pin the version**; the
  unpinned form is for a server you trust to stay what it is.
- The package name must be the whole word: `@pkg/server-evil` is another package.
- Words after the package are the package's own arguments. As with any prefix
  rule they are allowed (and reported as extra); put them in the rule to require
  them: `npx @pkg/server --stdio`.
- A rule that starts with a flag (`npx -y @pkg/server@1.2.3`) is a plain prefix
  rule, as before. `deny` rules of this form work the same way. `docker run` is
  not covered.

## What is checked at each start

1. The command must pass the connector's `allow` rules (and no `deny` rule).
2. The direct parent of the `vahta run` process must be a harness the connector is
   bound to: `claude` (the `claude` program, or `node`/`bun` running something
   with `claude` in its command line), `codex`, or `cursor`/`cursor-agent`. Read
   from the system, not from anything the caller says. On Linux this is checked
   in full. On macOS and Windows the command line of another process is not read
   here, so a `node` or `bun` parent counts as Claude Code. A start from any
   other parent is refused (`NotFromHarness`), journaled as suspicious and
   counted for the injection alarm.
3. The harness process that started it must have a connectors session that
   covers the connector; with none, a password window opens (see above) and the
   launch waits for it.

## What this does not protect against

- **A key split across two separate output messages is not detected.** The
  output hook looks for a connector's key (and its encoded forms) in each tool
  result as one whole; a result that carries half of it and a later one the other
  half is cut by neither. The hook now knows connector keys by value for every
  agent, while the connectors session is open and for a while after a start, but
  only that way.

- The check of the parent is a speed bump. Any program of yours can be run with a
  parent called `claude`. The allow rule, the hook and the vault are the boundary.
- While a server runs, **its environment is readable by processes of the same
  user** (`/proc/PID/environ` on Linux, for example). That includes an agent's
  Bash tool, unless the hook stops the particular command. The key is as exposed
  as it would be in any MCP server's environment, for as long as the server runs;
  Vahta keeps it out of config files, chat and transcripts, not out of the
  server's own process.
- The server itself holds the key and can do with it what its code does. Pin its
  version and review what you allow.
