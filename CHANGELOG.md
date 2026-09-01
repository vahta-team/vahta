# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow the git tags `0.4.0` … `0.4.12`.

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
