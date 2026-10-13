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
   `--ask`, `--reason`, or one `vahta http --secret ... URL` to a host the
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
4. Then `vahta add` with all of it in one command. The reply repeats the
   category's checklist.

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

A session is a *runner*: it can `run` and nothing else. `reveal`, `copy` and every
write need a fresh password even inside one.
