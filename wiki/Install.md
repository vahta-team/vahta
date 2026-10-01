# Install

```bash
pip install key-amnesia
```

Or from source: `pip install git+https://github.com/vahta-team/vahta`,
or from a local clone: `pip install .`. You get both `key-amnesia` and the
`ka` alias.

Windows and Linux are supported. macOS isolated-console spawn is
**experimental** (PID-file wrapper around Terminal.app / osascript; visible
window path unconfirmed by a real Mac user) — see [macOS](macOS).

Kernel peer-identity admission on macOS is **not** supported: lookup fails
closed, so a macOS guard cannot admit clients the way Windows/Linux do.
Experimental console spawn does not change that.

## Agent setup

```bash
ka setup
```

Copies bundled skills (`key-amnesia-usage`, `key-amnesia-hygiene`,
`key-amnesia-migrate`) into `~/.claude/skills/`, `~/.cursor/skills/`,
`~/.agents/skills/` (current Codex user path), and `~/.codex/skills/`
(legacy / `$CODEX_HOME`). OpenCode auto-loads those skills from
`~/.claude/skills` and `~/.agents/skills` with nothing extra to copy.
Setup merges a PreToolUse / preToolUse hook that **denies forbidden `ka`
verbs** (and inline credential-shaped tokens), and best-effort **allow**
rules so the harness will let unattended `ka run` / `ka list` through. On
OpenCode the guard is a plugin under `~/.config/opencode/plugins/` — or
`$XDG_CONFIG_HOME/opencode/plugins/` when that variable is set, since that is
where OpenCode reads its config — plus
`permission.bash` globs — the plugin is the enforcement. Files try to let
the agent run `ka`; the hook is the load-bearing deny (`ka set`,
`ka reveal`, `ka scan --yes`, and other mutating verbs). Restart or reload
the host afterward. On Codex, review and trust the new hook via `/hooks`
before it will run.

Codex also reads project `AGENTS.md` for instructions; that is separate from
skills installed by `ka setup`. Cursor: `ka setup` never creates
`~/.cursor/permissions.json` (that file replaces the in-app terminal
allowlist).

Flags: `--skills-only`, `--hook-only`, `--permissions-only`,
`--permissions-remove`, `--uninstall`, `--dry-run`, `--force`, `--yes` (do not prompt before writing permission
files; never deletes user allows).

### Uninstall

```
ka setup --uninstall --dry-run   # print what would be removed, write nothing
ka setup --uninstall             # remove it
```

Removes only what `ka setup` put there, and leaves every other entry intact and
in order (a `vahta-hook` entry or any unrelated hook is foreign):

- the `key-amnesia-hook` command item in `~/.claude/settings.json`,
  `$CODEX_HOME/hooks.json` (default `~/.codex/hooks.json`) and
  `~/.cursor/hooks.json`; a hook group, event array or `hooks` object is dropped
  only when that removal emptied it;
- the OpenCode plugin file `key-amnesia-secret-guard.js` (only if it carries the
  ka marker) and its `plugin` entry in `opencode.json`;
- the three skills (`key-amnesia-usage`, `-hygiene`, `-migrate`) from the Claude,
  Cursor, Codex and `~/.agents` skills directories. A skill whose content differs
  from what ka copies is kept and reported; `--force` removes it;
- the exact allow/deny strings `ka setup` adds (Claude `permissions` and
  `autoMode.allow`, Cursor `terminalAllowlist` / `allow_instructions` and
  `cli-config.json`, OpenCode `permission.bash`).

Never touched: the vault, `.amnesia/` directories, `config.json` (including the
`terminal` setting), the audit log, and anything else holding your data. Each
edited JSON file is backed up once to `<file>.ka-backup` and written through a
temp file plus rename. A malformed JSON file is reported and left untouched
(exit 1). With nothing of ours present it says so and exits 0. Entries written
by an older ka whose text differs from today's are not recognised; remove those
by hand.

After any upgrade, re-run `ka setup` (it rewrites the hook command) and
restart Claude Code / Cursor / Codex / OpenCode.

An isolated venv (`~/.local/share/key-amnesia/venv/`) does **not** need
`key-amnesia-hook` on PATH; setup writes the venv console script (or this
install's `python -m`). The 0.4.11 bug wrote bare `python -m …`, which hit
system Python and failed with `ModuleNotFoundError: No module named
'key_amnesia'` on every tool call — upgrade to 0.4.12, `ka setup`, restart.

## Agent bootstrap prompt

Paste into a coding agent:

```
Install key-amnesia and set yourself up to use it correctly for secrets in
this project:
1. pip install key-amnesia
2. Verify `ka --version` works in a fresh terminal (if not found, fix PATH
   as instructed).
3. Run `ka setup` (installs its skills + safety hook globally).
4. Tell me to restart this session so the skill loads, then tell me exactly
   what to do in my OWN terminal to finish setup (master password etc.) —
   you cannot do that step yourself.
```

## Open these docs

```bash
ka docs          # print URL + best-effort browser open
ka docs --print  # URL only
```

## Environment notes

| Variable | Effect |
|----------|--------|
| `KEY_AMNESIA_HOME` | Override data dir (default `~/.key-amnesia`) |
| `KEY_AMNESIA_VAULT_PATH` | Override vault file path |
| `KEY_AMNESIA_NONINTERACTIVE=1` | Force spawned-console auth (never inline `getpass`), even if both streams claim to be a TTY — use in agent harnesses |
| `KEY_AMNESIA_CLIENT_NAME` | Display-only label on guard IPC (not a credential) |
| `KEY_AMNESIA_HOOK_DISABLE=1` | Disable the secret-guard hook |

Auth routing requires **both** stdin and stdout to look like a TTY before prompting inline; otherwise `ka` opens an isolated console the human can see.
