# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow the git tags `0.4.0` … `0.4.16`.

## [0.4.16] — 2026-09-29

> **Upgrade: re-run `ka setup`.** The tool-name matcher that decides which calls
> reach the guard lives in *your* `~/.claude/settings.json` (and Codex
> `hooks.json`) on disk, written at setup time. Upgrading the package does not
> rewrite it, so MCP calls keep bypassing the guard **silently** until setup runs
> again — and nothing warns you: `claude_hook_registered` reports "registered"
> regardless of which matcher is stored. A matcher-aware check is deliberately
> deferred, so for this release the re-run is the whole mechanism.

### Fixed

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

### Added

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

### Not covered

Stated plainly, because a guard's gaps are part of its contract:

- **OpenCode MCP calls.** The bundled plugin filters on its own tool-name set,
  and OpenCode's MCP tool-id shape is undocumented in the plugin SDK types.
  Unverified, so not guessed at.
- **Cursor MCP and file reads.** Cursor routes MCP to `beforeMCPExecution` and
  reads to `beforeReadFile`; `ka setup` registers neither.
- **MCP *results*.** `PreToolUse` sees only the request, so a server that returns
  a secret is still invisible.
- **Positional credentials with no flag to anchor on** — `mysql -u root <secret>`.
  Firing on bare argv words would need a per-tool argument table.
- **Single-character-class values** such as `--password postgres-dev-local`, which
  fail the inherited mixed-class gate in `classify_value`. The tier is not what
  stops these.

## [0.4.15] — 2026-09-17

### Added

- **OpenCode support.** `ka setup` installs a JS bridge plugin at `~/.config/opencode/plugins/key-amnesia-secret-guard.js` (or under `$XDG_CONFIG_HOME/opencode`, which is where OpenCode itself looks when that variable is set) that spawns the existing `secret_guard` module on `tool.execute.before` and throws on a Claude-shaped deny. Skills already auto-load from `~/.claude/skills` and `~/.agents/skills` — nothing extra is copied for OpenCode. Best-effort `permission.bash` deny/allow globs are merged into `opencode.json`; the plugin is the enforcement (it sees `cd`-led chains; the globs do not).

## [0.4.14] — 2026-09-09

### Changed

- **`ka scan` import matches `ka import`.** One numbered selection prompt (`Selection [all]:` — empty/`all` takes every listed finding, `n`/`no` takes none). Enter now means import all; the master-password prompt is the backstop. Scan and `ka import` share one save-then-delete core, so a vault write failure leaves every source file in place (0.4.13 could delete plaintext before a failed save).
- **`ka scan --yes`** still imports all, skips collisions, never deletes or renames, and still needs a TTY for the master password. It now adds `.env*` to `.gitignore` when missing (`offer_gitignore(..., ask=True)`; no-op if already covered). Gitignore is **filesystem policy, not cryptographic** — it does not stop an agent that can read the tree. `--yes` still **exits 1** while those source files remain (`ka scan --yes && deploy` is not a clean gate).
- **Exit after a TTY / `--yes` import** is 1 only when gated findings still have a source path on disk. Deleted or renamed-to-`.imported` dotenv files no longer fail the gate. `--json`, `--no-import`, and non-TTY scans keep the snapshot exit. The printed report is still a snapshot; it is not re-walked or reprinted.
- Human report footer: when importable dotenv findings exist, `Next: in your own terminal, ka import .env …` is composed from scan-discovered paths only. No generic `ka import FILE` line; no JSON `next` field.
- **`ka import FILE [FILE …]`** — one password, one gitignore ask, one manifest merge. No new flag.

### Fixed

- Scan import no longer disposes source files before the vault is saved.

## [0.4.13] — 2026-09-06

### Fixed

- **`ka run` could not prompt on a current Linux desktop.** The isolated-console spawn knew four terminals — `x-terminal-emulator`, `gnome-terminal`, `konsole`, `xterm` — and invoked all but one of them with a blanket `-e`. On a Wayland desktop that ships ghostty, kitty, foot or alacritty and none of those four, any `ka` command that needed the master password from a non-TTY parent (an agent harness, a CI shell, a `.desktop` launcher) failed closed with `No suitable terminal emulator found`, and nothing in the message said how to proceed.

  The table now carries nineteen terminals with the argument convention each one actually takes: trailing argv for `xdg-terminal-exec`, `kitty` and `foot`, which reject `-e`; `-e` for ghostty, alacritty, konsole and the X11 set; `--` for gnome-terminal, kgx and mate-terminal; `-x` for xfce4-terminal and terminator; `start --` for wezterm; and one shell-quoted string, built with `shlex.join`, for tilix, lxterminal and qterminal, whose `-e` is string-shaped and used to silently truncate a path containing a space.

  `xdg-terminal-exec` — the freedesktop reference implementation of "open the user's chosen terminal" — is tried first when present. `x-terminal-emulator` moved down the list: it is an alternatives symlink that may land on gnome-terminal, whose `-e` is deprecated, so hitting the real binary with the right flag is always better.

### Added

- **The terminal is now configuration, not a list in the source.** `terminal` joins `ka config set`: a command prefix carrying whatever flag that terminal needs — `"ghostty -e"`, `"kitty"`, `"wezterm start --"` — or `auto` to detect one. A terminal nobody has heard of works without waiting for a release.
- `ka setup` asks which terminal to use, offering the ones it finds. One installed is chosen silently; several are offered as a numbered list; `--yes` or a non-interactive run takes the first and says so. A choice already stored is reported and kept, so re-running setup after an update does not re-ask. `ka setup --terminal-only` picks again, `--reconfigure-terminal` re-asks during a full setup. The choice is then proved by opening the terminal on a test command rather than assumed.
- Unlike every other config key, `terminal` does not require the master password. It is the setting that decides where a password can be typed, so gating it behind typing one deadlocks exactly the user it exists to help. It guards nothing — anyone who can write the config file can already replace `ka` on `PATH` — and `config set` stays denied to agents by `ka_policy`, which is where that deny has always lived.
- **A terminal that opens but never starts the helper no longer costs the whole prompt timeout.** The helper now touches a marker file as its first act, before it prints anything, and the spawn layer waits up to 8s for it. Proof of *life* — a process still running 150 ms after spawn — could not distinguish a working window from one that opened and failed to exec its command; the caller then sat out its full 90-second wait on a window that would never answer. Proof of *start* can. It is only used to decide whether to try another terminal, so the last candidate is never abandoned on it: a slow terminal with no fallback is still waited for, unchanged. An abandoned candidate is closed rather than left on screen asking for a password nobody will read.

  The marker rather than the IPC connection, because the helper asks for the password *before* it connects — a short deadline on the connection would kill the window while the user was typing in it.
- `ka status` prints the terminal that would open and where the setting came from (`KEY_AMNESIA_TERMINAL`, config, `TERMINAL`, or detection).
- `KEY_AMNESIA_TERMINAL` — the same command-prefix shape, overriding the stored setting for one run.
- The running desktop's own terminal is moved to the front of the candidate list from `XDG_CURRENT_DESKTOP`, so a KDE user gets Konsole on a machine that also has ghostty installed.
- The fail-closed message now names the ways out: `ka config set terminal`, `ka setup`, or starting a session with `ka unlock` in a terminal you already have.

## [0.4.12] — 2026-09-01

### Fixed

- `ka setup` writes a working PreToolUse hook command when the package lives in an isolated venv and `key-amnesia-hook` is not on PATH. Resolution prefers the sibling console script next to this install's interpreter, then `shutil.which` (absolute path), then `{sys.executable} -m key_amnesia.hooks.secret_guard` — never bare `python`. Upgrade: re-run `ka setup`, then restart the agent.

## [0.4.11] — 2026-08-20

### Behavior change

- `ka scan` headline location follows gated `Finding.scope`. All-project (and the zero case) still says `in this project`. All-deep says `on this machine, outside this project`. Mixed says `on this machine — {here} in this project, {away} outside it`. `Project root:` is printed only when a listed finding is in the project.

### Fixed

- Assignment matching no longer runs the unanchored `ASSIGN` regex (quadratic, and a denial-of-service surface: transcript strings are attacker-influenced). Production uses a literal-anchored two-stage matcher; finding identity is unchanged. Vendor-prefix detection gates on one combined regex, then still picks the kind from `PREFIX_PATTERNS` order.

### Added

- `ka scan --deep` writes progress to stderr (TTY: one rewritten line; otherwise plain lines). `--quiet` suppresses it. `--json` stdout stays pipeable.
- Human report (and JSON `strict_certain` / `strict_high` / `strict_paranoid`) prints the three `--strict` gate totals from the same scan.

## [0.4.10] — 2026-08-19

### Behavior change

- `ka scan` exit 1 follows `--strict` (`certain` / `high` / `paranoid`, default `high`): **certain** is vendor prefixes and confirmed filenames; **likely** is assignment and UUID hits; **possible** is identifier, passphrase, low-transition, and unconfirmed `mcp.json`. Default exit 1 means certain + likely. Trees that exited 1 on identifier / function-call / doc-assignment hits in ≤0.4.9 now exit **0** unless you pass `--strict paranoid` (that is the ≤0.4.9 assignment gate). Invalid `--strict` exits 2.

Finding counts from ≤0.4.9 are **not comparable**: 0.4.9 counted every hook-threshold assignment hit (English identifiers, `token = secrets.token_hex(8)`, this repo’s own typed annotations). The three-count summary (`N certain · N likely · N possible`) prints at every strictness; only the listing, exit, and headline number change.

### Added

- Shared detector module (`key_amnesia.detect`) with explicit tiers: `none` / `possible` / `likely` / `prefix`. Hook still denies `possible|likely|prefix` except function-call and `Name[...]` type-annotation values.
- `ka scan --strict` with values `certain`, `high`, or `paranoid` (default `high`). `--wide` aliases `--include-excluded` and is independent of `--deep`.
- Quoted-name assignments (`"api_key": "…"`) and JSON key walk for transcripts.
- Named reasons on findings (`uuid`, `identifier`, `word-shaped-passphrase`, `low-transition`, `unconfirmed-mcp-shape`). Unconfirmed `mcp.json` / `claude_desktop_config.json` demote to possible; they are not dropped. Unconfirmed MCP is one possible per file, not per top-level key.

### Changed

- Human headline: `N LEAKs found (--strict high) — your agent can read N secrets in this project (LEAK = Locally Exposed Agent Keys)`. The gate name is in the headline. The three-count summary is unconditional.

## [0.4.9] — 2026-08-17

### Behavior change

- Agents that previously ran `ka set` (and other mutating verbs) because `_KA_SAFE` skipped secret scanning will now be **hook-denied**. The deny message names the exact command to run in the user's own terminal (do not paste the result into chat). File allow-lists are best-effort so unattended `ka run` / `ka list` can proceed; **the PreToolUse hook is the load-bearing deny**.

### Added

- `ka setup` merges harness **allow** rules (Claude `permissions.allow` plus existing `autoMode.allow`; Cursor prefixes only when that cannot clobber the IDE list). `--permissions-only`, `--permissions-remove`, `--yes`. Codex remains print-only (`config.toml` has no command rules); trust the hook via `/hooks`.
- Hook verb-deny for forbidden `ka` invocations (including `python -m key_amnesia`, `uvx`/`pipx`, path suffixes, `env` prefixes, `sh -c`, and nested `ka run -- …`). `ka scan --yes` is denied; unrecognized verbs fail open.
- Secret scan of the command **after** `ka run --` (so `python deploy.py --api-key sk-ant-…` is denied) without nagging on `--secret NAME --as NAME=VAR`.
- `ka run --cwd DIR` (absolute resolve; missing/not-a-directory → exit 2).

### Changed

- Usage skill prefers a bare `ka run --cwd DIR --secret … --as … -- <command>` — no `cd &&`, pipes, or `2>&1`.
- `ka init` prints `Next: ka setup`.

## [0.4.8] — 2026-08-11

### Added

- `ka scan --deep` walks known **agent session transcript** JSONL trees (Claude Code `~/.claude/projects/**/*.jsonl` including subagents; Codex `~/.codex/sessions|archived_sessions/**/rollout-*.jsonl`; Copilot CLI `~/.copilot/session-state/*/events.jsonl`). Reports path + line hits; never prints values. Detection remains advisory (regex+entropy; false positives/negatives expected).

## [0.4.7] — 2026-08-04

### Changed

- `--admit-tree` prompt labels each offered level by depth (`this client` / `parent` / `grandparent` / `ancestor ↑N`) so it is clear which choice is narrower vs wider trust up the process tree.

## [0.4.6] — 2026-08-04

### Fixed

- Spawned-console auth helper: single `Listener.accept` thread (restarting accept each second orphaned the connection → parent closed the pipe → helper `WinError 232`); connect to parent *before* running `ka run` commands; do not abort the wait on flaky `Popen.poll`; `parent_alive` fail-open only on access-denied (not missing PIDs).
- Helper always attempts an IPC status reply with a reason instead of silent exit (`helper exited without connecting`).

## [0.4.5] — 2026-08-04

### Security model

- Added opt-in `ka unlock --admit-tree`: at the first unrecognized-peer prompt, choose a kernel-verified ancestor as the admission root so its OS descendants (including later sibling CLI invocations under that parent) are in-tree for the session (`via=interactive-tree`). Off by default; no config/env; `--pre-admit` unchanged.
- Windows holds `OpenProcess` on the chosen root for the admission lifetime.
- Offer floors: max 8 ancestors; never the last 2 chain entries (connecting peer never floored out); never `pid <=` platform minimum; foreign-owned levels skipped.

### Fixed

- CI: import `conftest` without a `tests` package (`#48`).
- CI: POSIX failures from the pytest console-spawn guard (`#49`).

## [0.4.4] — 2026-08-03

### Fixed

- Suite isolation: `ka_home` autouse with fail-if-outside-tmp.
- Agent TTY routing: inline auth requires stdin **and** stdout TTY; `KEY_AMNESIA_NONINTERACTIVE` forces spawned-console.
- Guard visibility: `guard_request` audits IPC abandon as `warn`; structured `code` on replies; `ka run`/`list` print why the guard path was abandoned.

## [0.4.3] — 2026-08-02

### Added

- OpenAI Codex support in `ka setup`: skills under `~/.agents/skills/` and `~/.codex/skills/`; Codex `PreToolUse` hook (`Bash|Write|Edit|apply_patch`); secret-guard allows `apply_patch`.

## [0.4.2] — 2026-07-31

### Security model

- `migrate_kam1_to_kam2` requires `confirm=` unconditionally.
- Windows ancestor walk takes one `CreateToolhelp32Snapshot` per chain.
- `guard_handle_message` requires keyword-only `peer=`; legacy opaque-token path is tests-only (`guard_handle_message_legacy`).
- Linux `SO_PEERCRED` compares kernel uid to `os.geteuid()` and fails closed on mismatch.
- Optional `@pytest.mark.slow` for process-spawning tests.

## [0.4.1] — 2026-07-31

### Security model

- Windows connecting-peer `OpenProcess` HANDLE held on `PeerIdentity` for the admission lifetime (ancestor walks still open-read-close); `release()` on replace and foreground-guard teardown.
- README honesty on Windows vs Linux `SO_PEERCRED`, ancestry UX vs in-tree malware, and the residual GetNamedPipeClientProcessId→OpenProcess race.
- Legacy IPC display field renamed `caller_pid` → `claimed_pid_unverified`.

### Changed

- Usage skill: verify with `ka status` / `ka connect` before assuming vault access.

## [0.4.0] — 2026-07-31

### Added

- Experimental macOS PID-file isolated-console spawn (`open`/`osascript` lose the process handle; wrapper writes PID then `exec`s helper). Marked experimental until confirmed on a real Mac.
- CI matrix adds `macos-latest` (Python 3.10 / 3.13) alongside Windows and Ubuntu.

### Security model

- Kernel peer-identity admission on macOS remains fail-closed (unchanged). Other non-Win/Linux/Darwin platforms still fail closed.

[0.4.14]: https://github.com/fujitoid/key-amnesia/compare/0.4.13...0.4.14
[0.4.13]: https://github.com/fujitoid/key-amnesia/compare/0.4.12...0.4.13
[0.4.12]: https://github.com/fujitoid/key-amnesia/compare/0.4.11...0.4.12
[0.4.11]: https://github.com/fujitoid/key-amnesia/compare/0.4.10...0.4.11
[0.4.10]: https://github.com/fujitoid/key-amnesia/compare/0.4.7...0.4.10
[0.4.7]: https://github.com/fujitoid/key-amnesia/compare/0.4.6...0.4.7
[0.4.6]: https://github.com/fujitoid/key-amnesia/compare/0.4.5...0.4.6
[0.4.5]: https://github.com/fujitoid/key-amnesia/compare/0.4.4...0.4.5
[0.4.4]: https://github.com/fujitoid/key-amnesia/compare/0.4.3...0.4.4
[0.4.3]: https://github.com/fujitoid/key-amnesia/compare/0.4.2...0.4.3
[0.4.2]: https://github.com/fujitoid/key-amnesia/compare/0.4.1...0.4.2
[0.4.1]: https://github.com/fujitoid/key-amnesia/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/fujitoid/key-amnesia/releases/tag/0.4.0
