# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Vahta 0.0.1 (unreleased)

Vahta is a Rust rewrite of key-amnesia. It is not published to any registry yet;
it builds from source (`scripts/install-local.sh`). What exists on this branch:

### Changed

- **`vahta hooks pause` is narrow** (protocol 19). It no longer takes the hooks out
  of the harness config. It lets the agent change that harness's hook settings for
  15 minutes by default (at most 1 hour, was 8 hours); the hook guard lets
  through shell writes it cannot judge (`sed -i`, `tee`, a redirect), while an edit
  that removes Vahta's entries or sets `disableAllHooks`, `rm` and `truncate` are
  still refused, and the watchdog keeps watching and restores removed entries at
  once. The secret detector and the other checks keep running. The window says what is allowed and
  for how long. A pause written by an older version still puts the hooks back when
  it ends. The detector's refusal no longer points to the pause.
- **Approvals name the vault.** The window for a pause or the watchdog's questions
  says whose vault password it wants, and with several vaults known the person picks
  one (no more silently taking the first one in `projects.json`). A password that
  does not fit says which vault was tried. `projects.json` drops projects whose
  vault file is gone.

### Added

- **Transcript scrub** ([docs/transcripts.md](docs/transcripts.md)): `vahta scrub
  --transcript [--all]` takes the values the daemon holds (every encoded form, and
  inside JSON text) and likely secrets out of Claude Code and Codex transcript files,
  with `***REDACTED(NAME)***`, keeping every line valid JSON and unchanged lines
  byte for byte. A running session's file is marked and cleaned at `SessionEnd`
  (new Claude hook; setup version 6, and `permissions.allow` for the command).
  Secrets found are marked exposed: `vahta list` and `vahta check` say to rotate
  them until `vahta reset`. The hook's "reached the transcript" message now names
  the command and says the current conversation stays contaminated.

- **Input checked against known values.** A tool call (an MCP argument, a Write or
  Edit, a command or commit) that carries the value of a secret Vahta holds, in any
  encoding, is denied and the person is told the secret's name. A prompt that holds a
  detected secret or a held value opens a window: "False alarm" sends it (remembered
  as keyed hashes until the daemon exits), "Save to the project vault as NAME" stores
  the value and holds the prompt, "Do nothing" holds it. No answer, no daemon or no
  window holds it too; one prompt window is open at a time and one requester gets four a
  minute, then is held, journaled as suspicious and counted for the alarm. The window shows a kind and length, never the value. New
  daemon requests `CheckInput` and `PromptAsk`; setup writes a 120 s hook timeout on
  Claude's `UserPromptSubmit` and Cursor's `beforeSubmitPrompt` (Claude setup v5,
  Cursor v2; Codex and Cursor not tested live).
- **Only these hosts, on Linux.** A secret (or connector) with `network = hosts`
  now lets any program under `vahta run` open TLS connections to the listed hosts
  and nowhere else, rootless: a network namespace with a replaced `/etc/hosts`
  (each host its own `127.0.0.x`), listeners handed to the daemon, which checks
  the TLS server name, connects from outside and copies bytes (no decryption).
  Wrong or missing server names are refused and journaled as suspicious;
  connections and bytes are journaled per host. macOS and Windows stay a speed
  bump.

- **Team members** ([docs/team.md](docs/team.md)): share a vault by sending a file
  through a chat. `vahta id` (a key sealed with the member's own password),
  `vahta members add|list|extend|remove` (the owner types the six verification
  words the member read out; expiry on every membership), `vahta grant|revoke`,
  `vahta share MEMBER -o FILE` (a package with only that member's secrets, signed by
  the owner), `vahta join FILE` (the member pins the owner after confirming the
  owner's words; an older package is refused) and `vahta share --to owner` for an
  editor to send one secret back. Roles limit what a member may do.
  Second iteration: the verification code is six groups of four digits (about 79
  bits, language-neutral, separators forgiven) instead of syllable words; a member
  can `vahta unlock` (run and http only), and the session ends no later than the
  membership; a package is compared by the owner's generation, so an editor's own
  `add` no longer makes the owner's next package look old; `join` follows an owner
  re-key along the vault's successor chain after the member confirms the new
  digits; an editor's transfer carries a signed per-editor counter the owner
  tracks (no clock), and may propose rules for a new secret, which the owner reads
  in plain words and approves or not. Rules that name a place inside the project
  are stored relative to it (`$PROJECT/lib/x.py`) and expanded on whichever
  machine runs them; `share` writes older absolute ones that way too and warns,
  by secret name, about places outside the project. The v5 body gained a `team`
  field (not readable by earlier builds of this branch).

- **The connectors vault** (`--connector`): one vault per user, in Vahta's data
  directory, for the keys of the MCP servers Claude Code, Codex and Cursor start.
  Each connector names its harnesses and its server command; `vahta run --connector`
  starts it, checks the direct parent is a harness it is bound to, and opens a
  password window at once for the first server a harness process starts; that
  process's session covers its other servers and ends with it. See
  docs/connectors.md.

- **The hook starts the daemon** when none answers: the `vahta` beside the hook
  binary only (never through `PATH` or the working directory), waiting at most
  1.2 s, giving up after 3 failed starts in a row (count in the runtime directory,
  cleared when a daemon answers). Without it in time the call is strict, as before.

- **`vahta journal`** shows the journal in plain words (`--last`, `--since`, `--secret`,
  `--kind`, `--json`), suspicious lines marked `!`. It reads the file, needs no
  daemon, and is refused to agents by the hook.

- **Connectors, second round.** There is no `vahta unlock --connector` and no
  until-reboot session: the connectors session belongs to the harness process
  that asked (pid and start time), opens with the connectors password in a window
  at its first launch, is shared by that process's concurrent launches, and ends
  when the process exits. Another Claude Code or a Codex asks for itself. A
  desktop notification (rate limited, journaled as `notified`) says when a
  connector is launched by a process that is not its harness, by a command outside
  its rules, prints its own key, or is refused in a burst. The
  output hook now cuts a connector's key by value in any agent's tool output, while the
  connectors session is open and for a while after a connector run. `vahta run
  --connector --as NAME=VAR` renames the variable. An `allow` rule may be
  "program + package" (`npx @pkg/server`) for `npx`, `bunx`, `uvx` and `pipx run`:
  it matches the command with the runner's known flags before the package, a version
  in the rule pins it, and no version in the rule accepts any plain version.

- **Hardening of rules.** `vahta check` compares the rules a category implies, not
  the literal `vahta.toml`; a `vahta run` or `vahta http` refused by a secret's rules
  counts for the injection alarm (a refused network tool, shell or interpreter at
  once, any two refusals otherwise); `publish` and `payment` runs get a fixed
  environment (`env_keep` in the category data), and the run window shows the
  arguments beyond the allowed prefix and the variables dropped.

- **Rules for every secret** (`vahta-policy`): six compiled-in categories (payment,
  server, ordinary, database, publish, local-only), mandatory rule sets (a secret with
  none is refused), folders, a network axis (none, hosts, app; no network on Linux),
  rules proposed and shown in the `vahta add` window, downgrades shown loudly and
  journaled.
- **`vahta http`**: one HTTPS request made by the daemon with a secret in a header
  or query value, only to hosts the secret is bound to; the response is scrubbed.
  All network code is `crates/net` behind the `http` feature.
- **Using a vault from another project** (`--vault DIR` on `run`, `http`, `unlock`,
  `delegate`, `list`, `check`): the vault opts in with `vahta remote on` (signed
  flag, the person and the master password), each secret names the projects it may
  be used from (`vahta bind NAME --from`, `from = [...]` in `vahta.toml`), and the
  daemon reads the caller's directory from the kernel instead of trusting the
  client. Sessions bind to the pair (vault, calling project). Vault format 4;
  protocol 16.
- **The vault** (`vault.vht`, format 5; older files upgrade on the owner's
  unlock and the original is kept as `vault.vht.vN.bak`): Argon2id for the password,
  XChaCha20-Poly1305 for every sealed value, a per-secret key wrapped for the
  owner and each recipient, and an Ed25519-signed, plaintext name index so names
  can be listed without a password. Padded values, a recovery key, generations
  that this machine remembers so a rolled-back vault is refused.
- **The daemon**, the vault's only owner: one per user, started on demand, local
  socket or named pipe, caller identity taken from the operating system. Prompt
  windows open in a separate terminal; a password or a value crosses only the
  window's own one-time connection.
- **Commands**: `init`, `add`, `reset`, `tier`, `remove`, `import --ka|--dotenv`,
  `reveal`, `copy`, `list`, `check`, `scan`, `unlock`, `lock`, `sessions`,
  `delegate`, `run`, `bind`, `output allow`, `hooks pause|resume|status`, `setup`,
  `daemon run|status|stop|restart`. `vh` is the short name.
- **Sessions** anchored to the calling agent process, with extension prompts,
  delegation to sub-agents, ending on sleep or screen lock (Linux), and an
  honest "changed since this session was opened" instead of a stale read.
- **Binding**: per-secret `allow` and `deny` rules in `vahta.toml`, approved
  into the signed vault, matched against the resolved program, with `--ask`.
- **The hook** (`vahta-hook`) for Claude Code, Codex and Cursor, described by
  per-harness manifests: blocks secret-shaped values in tool calls, finds values
  hidden in base64, hex, percent-encoding or joined strings, redacts tool output, guards Vahta's
  files and the harnesses' hook settings.
- **The detector** and its rules as data (about 400 vendor token shapes with
  samples), structural rules for connection strings and program arguments, and
  a size-bounded scan.
- **The hook watchdog** (`vahta _guard`, opt-in at `vahta setup`), the
  **injection alarm**, administrator-policy install (`vahta setup --managed`),
  and the journal.
- **CI** on Linux, macOS and Windows: format, clippy and the workspace tests.

### Fixed

- **The agent is told which secret was blocked.** When a value Vahta holds is refused in a
  command, a file write, an MCP argument or a prompt, or cut from a tool's output, the
  message for the agent now names the secret (and, for input, how the value was written)
  and says to use `vahta run --secret NAME -- ...`; before, only the person heard the
  name. Never the value or a part of it. A value only the detector knew still gets the
  old advice. The daemon marks which cuts are a secret's name so a detector's kind is
  never offered as one.
- **The paste check is stricter when the daemon is not running.** Without it the hook
  cannot ask you, so besides the detector's finds it holds any prompt with a long
  key-like string (20+ characters of a key alphabet, letters and digits, random-looking;
  git commit ids, UUIDs, slugs and paths are let through). With the daemon up nothing
  changes. The hook's own "allow" for `vahta run` and `vahta http` already needed the
  daemon's yes; each harness now has a fixture for both pinning that without the daemon
  the decision is the harness's.
- **Windows: places in rules are compared the way Windows compares them.** Directories
  and program paths in rule matching, a secret's `from` list, the "agent can change this
  file" warning and role narrowing ignore case, `/` against `\` and the `\\?\` prefix on
  Windows (one helper, `vahta_vault::rules::place_inside`, tested on every OS); other
  systems are unchanged.
- **A role is no longer "wider" for spelling a place another way.** A role's program,
  argument or folder written `$PROJECT/...` against a secret's rule stored as an absolute
  path (or the reverse, or through a symlink to the project) was refused as wider. Both
  sides are now expanded from the project root and resolved before the narrowing check;
  a role that really names another program, fewer arguments or a folder outside the
  secret's is still refused.
- **The hook marks the session for transcript cleanup itself.** When it cuts a secret
  out of a tool's output (or finds one it cannot cut), the daemon is told, and the
  session's transcript is cleaned at `SessionEnd` with no `vahta scrub` run. The
  hook's note to the agent no longer asks for the command first.
- **Save from the paste window: "propose rules now".** After "Save to the project
  vault" a second question asks whether the agent should propose rules for the new
  secret. If you say yes, the first clean message you send afterwards reaches the agent
  with an instruction (secret name only) to write `[secrets.NAME]` in `vahta.toml` and
  run `vahta bind NAME`; the blocked message itself is erased from the agent's context,
  so it cannot carry it. Either way the held message now tells you the secret still
  needs rules. Codex's version of the note stays off until it is seen to work.
- **Prompt history.** `vahta scrub --transcript` also cleans Claude Code's and
  Codex's `history.jsonl` (the prompts kept for arrow-up), and when the paste check
  holds a prompt (the person chose "save" or "do nothing") the daemon removes that
  prompt's entry from both files at once, then again a few times as the harness may
  write it late. Atomic rewrite, never cut short while the harness appends.
- **"Exposed in a transcript" can no longer be erased by deleting a file.** The marks
  moved from `exposed.json` into the machine's authenticated record of each vault (the
  one that pins the owner key); a deleted or edited mark fails the next unlock as
  tampering. An existing `exposed.json` is migrated once per vault and removed.
- **`vahta lock --connector`** ends the connectors session and nothing else (before,
  only `lock --all` and `sessions kill` did); a plain `vahta lock` still leaves it.
- **DNS rebinding in the host filter.** A name allowed by `network = hosts` that
  resolves to a loopback, private, shared (100.64/10), link-local or unspecified
  address is refused by the relay under `vahta run` and by `vahta http`, with the
  address and the reason in the error and the journal. A host rule written
  `private:HOST[:PORT]` allows it for that host; a role cannot widen a secret's rule
  that way.
- **A window no longer outlives a client that gave up.** When the harness killed
  `vahta run` (or `unlock`, `http`, `bind`, ...) while a password or approval window
  was open, the window stayed up to five minutes and the journal said the command
  "started" though it never ran. The daemon now watches the connection while a
  request waits on the person: the window is withdrawn at once, nothing is started and
  the journal says `cancelled` (client gone).
- **N requests at once no longer open N windows.** The first request for a vault opens
  the window; the others wait. A session opened by that window serves the waiters it
  covers (the usual process-tree and scope lookup; the others get their own window
  afterwards); the same command asked again meanwhile shares the one-use approval; a
  "no" is the answer for waiters asking the same question; a different command is
  asked after the first, never beside it.
- **Output scrubber: JSON-escaped values.** A secret with a quote, a backslash or a
  control character that a program prints as JSON (`\"`, `\\`, `\n`, `\u000a`,
  `\/`, `\uXXXX`) was not recognised, and the harness that decodes the JSON showed
  it to the model. These spellings are now held as another form of the value
  (`NAME (JSON-escaped)`) in `vahta run` and everywhere forms are used.
- **Output scrubber: stall.** A value that starts or ends with a newline (or starts
  with `}\n`) made the scrubber hold back the end of every message until the next
  one, so an MCP server looked hung. The held tail is now let go after 25 ms with
  no more output; a value written in pieces within that time is still redacted
  whole, and one cut by a longer pause has the rest redacted.

### Changed

- The Python key-amnesia moved to `legacy/` on this branch. It is maintained on
  `master` until its final release.

## key-amnesia (Python)

The history of the Python tool, which Vahta replaces. Versions follow the git
tags `0.4.0` ... `0.4.16`.

### [0.4.16] — 2026-09-29

> **Upgrade: re-run `ka setup`.** The tool-name matcher that decides which calls
> reach the guard lives in *your* `~/.claude/settings.json` (and Codex
> `hooks.json`) on disk, written at setup time. Upgrading the package does not
> rewrite it, so MCP calls keep bypassing the guard **silently** until setup runs
> again — and nothing warns you: `claude_hook_registered` reports "registered"
> regardless of which matcher is stored. A matcher-aware check is deliberately
> deferred, so for this release the re-run is the whole mechanism.
>
> The same re-run is what replaces the OpenCode bridge plugin (its content marker
> moves to 0.4.16) and what writes the Cursor instruction in the shape Cursor
> actually documents. Three files on disk, one command.

#### Fixed

- **A credential passed as a space-separated flag was detected nowhere.**
  `--api-key <value>`, `--token <value>` and `--password <value>` walked through
  both the hook and `ka scan`; only `NAME=value`, `--api-key=value` and
  `Bearer <val>` were caught. The detector was assignment-shaped — it required
  `[:=]` between name and value — so the leak this product exists to prevent, a
  credential sitting on argv where it lands in `ps`, shell history and CI logs,
  was the one shape that passed. Flag-form hits report as `--password flag value`
  rather than `PASSWORD assignment`, so a finding says which form it came from.

  The name vocabulary is **end-anchored**: `--secret-name`, `--password-stdin`
  and `--token-file` do not qualify. Values that are env indirection (`"$VAR"`),
  command substitutions, paths, or shaped like an env-var name are excluded, so
  `ka run --secret GOOGLE_API_KEY` and `--token "$GITHUB_TOKEN"` stay quiet.
  Shipped tier is `likely+possible`, set by one constant in `detect.py`
  (`FLAG_FORM_FIRE_TIERS`) — `likely` alone misses the common case, since a
  human-authored password classifies as `possible`. Measured at **0 false
  positives** over 39 authored command lines and the whole repo corpus, cutting
  misses **7 → 1**.

- **Cursor's `autoRun.allow_instructions` was read as a string.** Cursor
  documents the field as `string[]`, so on a correctly configured machine
  `ka setup` printed `is not a string (fail closed; no write)` and contributed no
  Cursor allow-list at all. Both shapes are now read and **merged in place** — a
  list stays a list, a string stays a string, user entries keep their order and
  wording, and a genuinely unknown shape still fails closed, now naming the shape
  it found. The merged sentence was reworded to match what the field actually is:
  Cursor's own documentation calls these instructions steering for its auto-run
  check, not enforcement, so the text no longer opens with "Allow unattended" and
  says outright that the PreToolUse hook is what denies. A test fails the build if
  that wording drifts back toward sounding like a grant. `--remove` can now take
  the entry back out; it was manifested but missing from the removal map, so it
  never could before.

#### Added

- **MCP tool calls are scanned.** On Claude Code and Codex, MCP calls arrive at
  the same `PreToolUse` event as Bash/Write/Edit, under names shaped
  `mcp__<server>__<tool>`. key-amnesia dropped them twice: the installed matcher
  was `Bash|Write|Edit`, which never matches such a name, and the hook's own
  allow-list early-returned even when a matcher did fire. So an agent could hand
  a credential to any MCP server with the guard installed and nothing objected.

  MCP arguments are scanned across **all** their strings rather than through the
  known-key shortcut, because argument names belong to the MCP server: one naming
  an argument `command` would otherwise shadow a credential sitting in a sibling
  argument. Verb denial stays shell-only — an MCP call is not a shell command, so
  `ka reveal` in its arguments is scanned, not verb-denied. Deny reply shapes are
  unchanged.

  Together with the flag-form fix above, a call such as
  `mcp__github__create_issue` carrying `deploy with --api-key <value>` is now
  denied; neither change denies it alone.

- **OpenCode covers MCP too, without guessing a name.** The bridge plugin used
  to forward only the tool names in its own `GUARDED` set, so an MCP call never
  reached the guard. The filter is inverted: everything is forwarded except a
  skip set of `read`, `glob`, `grep`, `list`, `todoread` and `todowrite`, whose
  arguments are paths, patterns and task text. `webfetch` is deliberately not
  skipped — a token fits in a query string — and a test asserts it never joins the
  skip set. Inverting alone would have been a no-op: the Python guard ignores tool
  names it does not recognise, so the plugin now relabels anything that is not one
  of its native verbs as `mcp__opencode__<tool>` before forwarding. That is not a
  guess at OpenCode's MCP naming; it removes the need to know it, by telling the
  guard what is actually known — an opaque tool, scan every argument, no shell
  semantics. Measured afterwards against a live OpenCode session: it names an MCP
  tool `<server>_<tool>` (`kademo_echo_note`), so it is not `mcp__`-shaped and a
  prefix guess would have missed every MCP tool. The relabelling covers it
  unchanged. Native names still go over verbatim, so `bash` keeps verb denial and
  chain splitting. This also closed a silent hole: `patch` was in the plugin's old
  guarded set but absent from the guard's own allowed names, so it was being
  forwarded and discarded unread. Cost, measured: a guarded call spawns the guard,
  85–185 ms depending on load; skipped verbs spawn nothing.

#### Not covered

Stated plainly, because a guard's gaps are part of its contract:

- **Whatever the OpenCode skip set skips.** A credential typed as a grep pattern
  or into a todo item is unseen by construction. The set is four verbs wide and
  exists so that read and search loops do not pay the guard's start-up cost.
- **Cursor MCP and file reads.** Cursor routes MCP to `beforeMCPExecution` and
  reads to `beforeReadFile`; `ka setup` registers neither.
- **MCP *results*.** `PreToolUse` sees only the request, so a server that returns
  a secret is still invisible.
- **Positional credentials with no flag to anchor on** — `mysql -u root <secret>`.
  Firing on bare argv words would need a per-tool argument table.
- **Single-character-class values** such as `--password postgres-dev-local`, which
  fail the inherited mixed-class gate in `classify_value`. The tier is not what
  stops these.

### [0.4.15] — 2026-09-17

#### Added

- **OpenCode support.** `ka setup` installs a JS bridge plugin at `~/.config/opencode/plugins/key-amnesia-secret-guard.js` (or under `$XDG_CONFIG_HOME/opencode`, which is where OpenCode itself looks when that variable is set) that spawns the existing `secret_guard` module on `tool.execute.before` and throws on a Claude-shaped deny. Skills already auto-load from `~/.claude/skills` and `~/.agents/skills` — nothing extra is copied for OpenCode. Best-effort `permission.bash` deny/allow globs are merged into `opencode.json`; the plugin is the enforcement (it sees `cd`-led chains; the globs do not).

### [0.4.14] — 2026-09-09

#### Changed

- **`ka scan` import matches `ka import`.** One numbered selection prompt (`Selection [all]:` — empty/`all` takes every listed finding, `n`/`no` takes none). Enter now means import all; the master-password prompt is the backstop. Scan and `ka import` share one save-then-delete core, so a vault write failure leaves every source file in place (0.4.13 could delete plaintext before a failed save).
- **`ka scan --yes`** still imports all, skips collisions, never deletes or renames, and still needs a TTY for the master password. It now adds `.env*` to `.gitignore` when missing (`offer_gitignore(..., ask=True)`; no-op if already covered). Gitignore is **filesystem policy, not cryptographic** — it does not stop an agent that can read the tree. `--yes` still **exits 1** while those source files remain (`ka scan --yes && deploy` is not a clean gate).
- **Exit after a TTY / `--yes` import** is 1 only when gated findings still have a source path on disk. Deleted or renamed-to-`.imported` dotenv files no longer fail the gate. `--json`, `--no-import`, and non-TTY scans keep the snapshot exit. The printed report is still a snapshot; it is not re-walked or reprinted.
- Human report footer: when importable dotenv findings exist, `Next: in your own terminal, ka import .env …` is composed from scan-discovered paths only. No generic `ka import FILE` line; no JSON `next` field.
- **`ka import FILE [FILE …]`** — one password, one gitignore ask, one manifest merge. No new flag.

#### Fixed

- Scan import no longer disposes source files before the vault is saved.

### [0.4.13] — 2026-09-06

#### Fixed

- **`ka run` could not prompt on a current Linux desktop.** The isolated-console spawn knew four terminals — `x-terminal-emulator`, `gnome-terminal`, `konsole`, `xterm` — and invoked all but one of them with a blanket `-e`. On a Wayland desktop that ships ghostty, kitty, foot or alacritty and none of those four, any `ka` command that needed the master password from a non-TTY parent (an agent harness, a CI shell, a `.desktop` launcher) failed closed with `No suitable terminal emulator found`, and nothing in the message said how to proceed.

  The table now carries nineteen terminals with the argument convention each one actually takes: trailing argv for `xdg-terminal-exec`, `kitty` and `foot`, which reject `-e`; `-e` for ghostty, alacritty, konsole and the X11 set; `--` for gnome-terminal, kgx and mate-terminal; `-x` for xfce4-terminal and terminator; `start --` for wezterm; and one shell-quoted string, built with `shlex.join`, for tilix, lxterminal and qterminal, whose `-e` is string-shaped and used to silently truncate a path containing a space.

  `xdg-terminal-exec` — the freedesktop reference implementation of "open the user's chosen terminal" — is tried first when present. `x-terminal-emulator` moved down the list: it is an alternatives symlink that may land on gnome-terminal, whose `-e` is deprecated, so hitting the real binary with the right flag is always better.

#### Added

- **The terminal is now configuration, not a list in the source.** `terminal` joins `ka config set`: a command prefix carrying whatever flag that terminal needs — `"ghostty -e"`, `"kitty"`, `"wezterm start --"` — or `auto` to detect one. A terminal nobody has heard of works without waiting for a release.
- `ka setup` asks which terminal to use, offering the ones it finds. One installed is chosen silently; several are offered as a numbered list; `--yes` or a non-interactive run takes the first and says so. A choice already stored is reported and kept, so re-running setup after an update does not re-ask. `ka setup --terminal-only` picks again, `--reconfigure-terminal` re-asks during a full setup. The choice is then proved by opening the terminal on a test command rather than assumed.
- Unlike every other config key, `terminal` does not require the master password. It is the setting that decides where a password can be typed, so gating it behind typing one deadlocks exactly the user it exists to help. It guards nothing — anyone who can write the config file can already replace `ka` on `PATH` — and `config set` stays denied to agents by `ka_policy`, which is where that deny has always lived.
- **A terminal that opens but never starts the helper no longer costs the whole prompt timeout.** The helper now touches a marker file as its first act, before it prints anything, and the spawn layer waits up to 8s for it. Proof of *life* — a process still running 150 ms after spawn — could not distinguish a working window from one that opened and failed to exec its command; the caller then sat out its full 90-second wait on a window that would never answer. Proof of *start* can. It is only used to decide whether to try another terminal, so the last candidate is never abandoned on it: a slow terminal with no fallback is still waited for, unchanged. An abandoned candidate is closed rather than left on screen asking for a password nobody will read.

  The marker rather than the IPC connection, because the helper asks for the password *before* it connects — a short deadline on the connection would kill the window while the user was typing in it.
- `ka status` prints the terminal that would open and where the setting came from (`KEY_AMNESIA_TERMINAL`, config, `TERMINAL`, or detection).
- `KEY_AMNESIA_TERMINAL` — the same command-prefix shape, overriding the stored setting for one run.
- The running desktop's own terminal is moved to the front of the candidate list from `XDG_CURRENT_DESKTOP`, so a KDE user gets Konsole on a machine that also has ghostty installed.
- The fail-closed message now names the ways out: `ka config set terminal`, `ka setup`, or starting a session with `ka unlock` in a terminal you already have.

### [0.4.12] — 2026-09-01

#### Fixed

- `ka setup` writes a working PreToolUse hook command when the package lives in an isolated venv and `key-amnesia-hook` is not on PATH. Resolution prefers the sibling console script next to this install's interpreter, then `shutil.which` (absolute path), then `{sys.executable} -m key_amnesia.hooks.secret_guard` — never bare `python`. Upgrade: re-run `ka setup`, then restart the agent.

### [0.4.11] — 2026-08-20

#### Behavior change

- `ka scan` headline location follows gated `Finding.scope`. All-project (and the zero case) still says `in this project`. All-deep says `on this machine, outside this project`. Mixed says `on this machine — {here} in this project, {away} outside it`. `Project root:` is printed only when a listed finding is in the project.

#### Fixed

- Assignment matching no longer runs the unanchored `ASSIGN` regex (quadratic, and a denial-of-service surface: transcript strings are attacker-influenced). Production uses a literal-anchored two-stage matcher; finding identity is unchanged. Vendor-prefix detection gates on one combined regex, then still picks the kind from `PREFIX_PATTERNS` order.

#### Added

- `ka scan --deep` writes progress to stderr (TTY: one rewritten line; otherwise plain lines). `--quiet` suppresses it. `--json` stdout stays pipeable.
- Human report (and JSON `strict_certain` / `strict_high` / `strict_paranoid`) prints the three `--strict` gate totals from the same scan.

### [0.4.10] — 2026-08-19

#### Behavior change

- `ka scan` exit 1 follows `--strict` (`certain` / `high` / `paranoid`, default `high`): **certain** is vendor prefixes and confirmed filenames; **likely** is assignment and UUID hits; **possible** is identifier, passphrase, low-transition, and unconfirmed `mcp.json`. Default exit 1 means certain + likely. Trees that exited 1 on identifier / function-call / doc-assignment hits in ≤0.4.9 now exit **0** unless you pass `--strict paranoid` (that is the ≤0.4.9 assignment gate). Invalid `--strict` exits 2.

Finding counts from ≤0.4.9 are **not comparable**: 0.4.9 counted every hook-threshold assignment hit (English identifiers, `token = secrets.token_hex(8)`, this repo’s own typed annotations). The three-count summary (`N certain · N likely · N possible`) prints at every strictness; only the listing, exit, and headline number change.

#### Added

- Shared detector module (`key_amnesia.detect`) with explicit tiers: `none` / `possible` / `likely` / `prefix`. Hook still denies `possible|likely|prefix` except function-call and `Name[...]` type-annotation values.
- `ka scan --strict` with values `certain`, `high`, or `paranoid` (default `high`). `--wide` aliases `--include-excluded` and is independent of `--deep`.
- Quoted-name assignments (`"api_key": "…"`) and JSON key walk for transcripts.
- Named reasons on findings (`uuid`, `identifier`, `word-shaped-passphrase`, `low-transition`, `unconfirmed-mcp-shape`). Unconfirmed `mcp.json` / `claude_desktop_config.json` demote to possible; they are not dropped. Unconfirmed MCP is one possible per file, not per top-level key.

#### Changed

- Human headline: `N LEAKs found (--strict high) — your agent can read N secrets in this project (LEAK = Locally Exposed Agent Keys)`. The gate name is in the headline. The three-count summary is unconditional.

### [0.4.9] — 2026-08-17

#### Behavior change

- Agents that previously ran `ka set` (and other mutating verbs) because `_KA_SAFE` skipped secret scanning will now be **hook-denied**. The deny message names the exact command to run in the user's own terminal (do not paste the result into chat). File allow-lists are best-effort so unattended `ka run` / `ka list` can proceed; **the PreToolUse hook is the load-bearing deny**.

#### Added

- `ka setup` merges harness **allow** rules (Claude `permissions.allow` plus existing `autoMode.allow`; Cursor prefixes only when that cannot clobber the IDE list). `--permissions-only`, `--permissions-remove`, `--yes`. Codex remains print-only (`config.toml` has no command rules); trust the hook via `/hooks`.
- Hook verb-deny for forbidden `ka` invocations (including `python -m key_amnesia`, `uvx`/`pipx`, path suffixes, `env` prefixes, `sh -c`, and nested `ka run -- …`). `ka scan --yes` is denied; unrecognized verbs fail open.
- Secret scan of the command **after** `ka run --` (so `python deploy.py --api-key sk-ant-…` is denied) without nagging on `--secret NAME --as NAME=VAR`.
- `ka run --cwd DIR` (absolute resolve; missing/not-a-directory → exit 2).

#### Changed

- Usage skill prefers a bare `ka run --cwd DIR --secret … --as … -- <command>` — no `cd &&`, pipes, or `2>&1`.
- `ka init` prints `Next: ka setup`.

### [0.4.8] — 2026-08-11

#### Added

- `ka scan --deep` walks known **agent session transcript** JSONL trees (Claude Code `~/.claude/projects/**/*.jsonl` including subagents; Codex `~/.codex/sessions|archived_sessions/**/rollout-*.jsonl`; Copilot CLI `~/.copilot/session-state/*/events.jsonl`). Reports path + line hits; never prints values. Detection remains advisory (regex+entropy; false positives/negatives expected).

### [0.4.7] — 2026-08-04

#### Changed

- `--admit-tree` prompt labels each offered level by depth (`this client` / `parent` / `grandparent` / `ancestor ↑N`) so it is clear which choice is narrower vs wider trust up the process tree.

### [0.4.6] — 2026-08-04

#### Fixed

- Spawned-console auth helper: single `Listener.accept` thread (restarting accept each second orphaned the connection → parent closed the pipe → helper `WinError 232`); connect to parent *before* running `ka run` commands; do not abort the wait on flaky `Popen.poll`; `parent_alive` fail-open only on access-denied (not missing PIDs).
- Helper always attempts an IPC status reply with a reason instead of silent exit (`helper exited without connecting`).

### [0.4.5] — 2026-08-04

#### Security model

- Added opt-in `ka unlock --admit-tree`: at the first unrecognized-peer prompt, choose a kernel-verified ancestor as the admission root so its OS descendants (including later sibling CLI invocations under that parent) are in-tree for the session (`via=interactive-tree`). Off by default; no config/env; `--pre-admit` unchanged.
- Windows holds `OpenProcess` on the chosen root for the admission lifetime.
- Offer floors: max 8 ancestors; never the last 2 chain entries (connecting peer never floored out); never `pid <=` platform minimum; foreign-owned levels skipped.

#### Fixed

- CI: import `conftest` without a `tests` package (`#48`).
- CI: POSIX failures from the pytest console-spawn guard (`#49`).

### [0.4.4] — 2026-08-03

#### Fixed

- Suite isolation: `ka_home` autouse with fail-if-outside-tmp.
- Agent TTY routing: inline auth requires stdin **and** stdout TTY; `KEY_AMNESIA_NONINTERACTIVE` forces spawned-console.
- Guard visibility: `guard_request` audits IPC abandon as `warn`; structured `code` on replies; `ka run`/`list` print why the guard path was abandoned.

### [0.4.3] — 2026-08-02

#### Added

- OpenAI Codex support in `ka setup`: skills under `~/.agents/skills/` and `~/.codex/skills/`; Codex `PreToolUse` hook (`Bash|Write|Edit|apply_patch`); secret-guard allows `apply_patch`.

### [0.4.2] — 2026-07-31

#### Security model

- `migrate_kam1_to_kam2` requires `confirm=` unconditionally.
- Windows ancestor walk takes one `CreateToolhelp32Snapshot` per chain.
- `guard_handle_message` requires keyword-only `peer=`; legacy opaque-token path is tests-only (`guard_handle_message_legacy`).
- Linux `SO_PEERCRED` compares kernel uid to `os.geteuid()` and fails closed on mismatch.
- Optional `@pytest.mark.slow` for process-spawning tests.

### [0.4.1] — 2026-07-31

#### Security model

- Windows connecting-peer `OpenProcess` HANDLE held on `PeerIdentity` for the admission lifetime (ancestor walks still open-read-close); `release()` on replace and foreground-guard teardown.
- README honesty on Windows vs Linux `SO_PEERCRED`, ancestry UX vs in-tree malware, and the residual GetNamedPipeClientProcessId→OpenProcess race.
- Legacy IPC display field renamed `caller_pid` → `claimed_pid_unverified`.

#### Changed

- Usage skill: verify with `ka status` / `ka connect` before assuming vault access.

### [0.4.0] — 2026-07-31

#### Added

- Experimental macOS PID-file isolated-console spawn (`open`/`osascript` lose the process handle; wrapper writes PID then `exec`s helper). Marked experimental until confirmed on a real Mac.
- CI matrix adds `macos-latest` (Python 3.10 / 3.13) alongside Windows and Ubuntu.

#### Security model

- Kernel peer-identity admission on macOS remains fail-closed (unchanged). Other non-Win/Linux/Darwin platforms still fail closed.

[0.4.14]: https://github.com/vahta-team/vahta/compare/0.4.13...0.4.14
[0.4.13]: https://github.com/vahta-team/vahta/compare/0.4.12...0.4.13
[0.4.12]: https://github.com/vahta-team/vahta/compare/0.4.11...0.4.12
[0.4.11]: https://github.com/vahta-team/vahta/compare/0.4.10...0.4.11
[0.4.10]: https://github.com/vahta-team/vahta/compare/0.4.7...0.4.10
[0.4.7]: https://github.com/vahta-team/vahta/compare/0.4.6...0.4.7
[0.4.6]: https://github.com/vahta-team/vahta/compare/0.4.5...0.4.6
[0.4.5]: https://github.com/vahta-team/vahta/compare/0.4.4...0.4.5
[0.4.4]: https://github.com/vahta-team/vahta/compare/0.4.3...0.4.4
[0.4.3]: https://github.com/vahta-team/vahta/compare/0.4.2...0.4.3
[0.4.2]: https://github.com/vahta-team/vahta/compare/0.4.1...0.4.2
[0.4.1]: https://github.com/vahta-team/vahta/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/vahta-team/vahta/releases/tag/0.4.0
