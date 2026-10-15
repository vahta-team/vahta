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
- `--allow`: the server's command, exactly as the harness starts it after `--`.
  Pin the version: the rule trusts whatever that command runs.

Without both it has no rules and nothing may start it. `remote` and `from` do
not apply to this vault. Change them later with
`vahta bind --connector NAME --harness ... --allow ...` (you approve in a
window); remove a connector with `vahta remove --connector NAME`. To replace a
key, remove it and add it again.

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

Claude Code gives a server 30 seconds to finish starting (`MCP_TIMEOUT` raises it)
and shows you nothing of its error output, only "Connection closed".

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

## Every day: unlock first, then start the harness

```sh
vahta unlock --connector --for 8h
```

You type the password once. Until the session ends, `vahta run --connector` starts
each server with no window. The session is yours, not a process tree's, so it
covers a harness started from a launcher as well as from a terminal.

**What you see when you forgot.** No window opens: the harness would give up on
the server in about 30 seconds and show you nothing. The launch is refused at
once with exit code 3, the server never starts, and the harness reports a closed
connection. Vahta remembers it:

```
$ vahta daemon status
...
connector GITHUB_PERSONAL_ACCESS_TOKEN was refused at 2026-10-15 09:12:40 UTC: no connectors session: run `vahta unlock --connector`, then start the harness again
```

`vahta list --connector` shows the same line, and the journal has it. Run
`vahta unlock --connector`, then restart the server in the harness.

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
3. A connectors session must be open and cover the connector.

## What this does not protect against

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
