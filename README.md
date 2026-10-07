<p align="center">
  <img src="https://raw.githubusercontent.com/vahta-team/vahta/master/media/assets/approved/logo-512.png" alt="key-amnesia" width="200">
</p>

# key-amnesia

> ### key-amnesia is now **Vahta**
>
> **Vahta lets your AI agent *use* your passwords and API keys — without ever
> letting it *see* them.**
>
> The product and the concept are tested. What comes next is not an iteration
> but a hard reboot: a deep refactor onto a new core, which is why the project
> has been renamed and moved here.
>
> Faster, and more reliable, on more platforms — with enterprise-grade quality
> and the features small and medium teams actually need. Individual developers
> stay a first-class priority rather than an afterthought, because the mission
> is **safe autonomous long-running agents for everyone**, and security is a
> baseline, not a luxury.
>
> Everything below still describes the software as it ships today.
> `key-amnesia` remains installable from PyPI and will get one final release.
> It will never be yanked, so pinned installs keep working.

**Let your AI agent *use* your passwords and API keys — without ever letting it *see* them.**

<!-- Absolute URL, not a repo-relative path: PyPI renders this README outside the
     repository and cannot resolve relative image paths, so a relative link shows
     as a broken image on the project page. -->
![key-amnesia — the vault hands the agent a sealed envelope it cannot open](https://raw.githubusercontent.com/vahta-team/vahta/master/media/assets/approved/readme-hero.png)

## The problem is `.env`

`.env` was designed for a threat model whose adversary was **git**. One line in `.gitignore` and you were done. That model is obsolete: the adversary is now the **agent sitting in your project**. Anything the agent can read — `.env`, shell history, MCP configs, a credentials JSON left in the tree — is a LEAK (Locally Exposed Agent Key). Pasting a key into chat is worse; it lives in the conversation forever.

Your choices used to be ugly: paste the key, leave it in plaintext where the agent can read it, or do that part yourself.

**key-amnesia is the fourth option.** Secrets live in an encrypted vault. The agent triggers commands that *use* them — values are injected into the child process environment, out of the agent's sight. If a command prints a secret, key-amnesia censors it before the agent sees the output. The master password can only ever be typed by you, at a real keyboard: when an agent needs approval, a **separate console window** pops up — one the agent cannot read or type into. Auth routing requires both stdin and stdout to look like a TTY before prompting inline; set `KEY_AMNESIA_NONINTERACTIVE=1` in agent harnesses to always force that window.

The agent gets amnesia. That's the whole point.

**Docs:** [github.com/vahta-team/vahta/wiki](https://github.com/vahta-team/vahta/wiki) — or run `ka docs` (prints the URL; opens a browser unless you pass `--print`).

## How it works, in 30 seconds

```bash
pip install key-amnesia
ka setup                          # skills + secret-guard hook for Claude Code / Cursor / Codex / OpenCode
ka init --project                 # or: ka init  for a global vault
ka import .env .env.local         # move plaintext into the vault (TTY-only; never prints values)
ka scan                           # find remaining LEAKs (names/paths only)
ka scan --deep                    # also home/shell/MCP + agent session transcripts
ka scan --strict paranoid         # also exit 1 on identifier/passphrase-shaped hits
ka scan --wide                    # include default-excluded dirs (alias of --include-excluded)

ka run --cwd DIR --secret API_KEY -- python my_script.py
```

`ka scan` reports **names, paths, and counts** (plus line numbers for agent session transcripts under `--deep`). It never prints secret values. The headline names the `--strict` gate (default `high`: **certain** vendor prefixes and confirmed filenames + **likely** assignments/UUID) and whether those gated findings are in the project, outside it (`--deep`), or both. Identifier-, passphrase-, low-transition, and unconfirmed-`mcp.json` hits are `possible`: they appear in the always-printed three-count summary (`N certain · N likely · N possible`) and in the three `--strict` gate totals; `--strict paranoid` gates on them (the ≤0.4.9 assignment gate). Detection is **advisory**. `--deep` is not a full home walk — it checks known candidates including Claude Code `~/.claude/projects/**/*.jsonl`, Codex `~/.codex/sessions|archived_sessions/**/rollout-*.jsonl`, and Copilot CLI `~/.copilot/session-state/*/events.jsonl`. Progress for `--deep` goes to stderr (`--quiet` suppresses it). `--wide` aliases `--include-excluded` and does not imply `--deep`. `ka scan --yes` imports all importable dotenv hits (password still required, never deletes, adds `.env*` to `.gitignore` when missing). Gitignore is filesystem policy, not cryptographic; `--yes` still exits 1 while those source files remain.

`ka init` asks for the master password twice; if the entries do not match, nothing is created. **There is no recovery** if you forget that password — Argon2id + SecretBox leave none by design.

When the agent triggers `ka run` and your approval is needed, a new console window appears with a clear message — only your password, typed there, lets it proceed. Close the window to deny.

## Install

```bash
pip install key-amnesia
```

Or from source: `pip install git+https://github.com/vahta-team/vahta`, or from a local clone: `pip install .` — every path gets you both the full `key-amnesia` command and the short `ka` alias.

> Windows and Linux supported. macOS isolated-console spawn is **experimental** (PID-file wrapper around Terminal.app / osascript) until a real Mac user confirms the visible window path — see [wiki — macOS](https://github.com/vahta-team/vahta/wiki/macOS).

### Install from source (local)

To run the Rust binaries (`vahta` and `vahta-hook`) from a checkout, every day, on your own machine — this publishes nothing:

```bash
scripts/install-local.sh                  # into ${XDG_BIN_HOME:-~/.local/bin}
scripts/install-local.sh --prefix DIR     # or somewhere else
scripts/install-local.sh --uninstall      # remove both binaries again
```

It builds with `cargo build --release --locked`, installs `vahta-hook` and then `vahta` and `vh` (its short name) by copying to a temp file and renaming over the target (a harness running the hook at that moment is not disturbed), runs a smoke check on both, and warns if the prefix is not on your `PATH`. Harness hooks follow the new copy: the script runs `vahta setup --refresh`, which repoints every harness that already has our entries and leaves the rest alone (`--no-setup` skips that). `--uninstall` refuses while a harness config still points into the prefix; run `vahta setup --all --uninstall` first, or pass `--force`. Linux and macOS; Windows is not covered yet.

### Agent bootstrap

Paste this into your coding agent when you want it to install and teach itself key-amnesia:

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

`ka setup` copies the bundled skills to `~/.claude/skills/`, `~/.cursor/skills/`,
`~/.agents/skills/` (Codex), and `~/.codex/skills/` (legacy Codex /
`$CODEX_HOME`). OpenCode auto-loads those skills from `~/.claude/skills` and
`~/.agents/skills` with nothing extra to copy. Setup merges a PreToolUse /
preToolUse hook that **denies forbidden `ka` verbs** (and inline
credential-shaped tokens), and best-effort **allow** rules so the harness will
let unattended `ka run` / `ka list` through. On OpenCode the guard is a plugin
under `~/.config/opencode/plugins/` plus `permission.bash` globs — the plugin
is the enforcement (it sees `cd`-led chains; the globs do not). Files try to
let the agent run `ka`; the hook stops `ka set`, `ka reveal`, `ka scan --yes`,
and other mutating verbs. Codex also needs you to review and trust the new hook
via `/hooks` before it will run. If Claude `autoMode.allow` entries vanish after
a restart, re-run `ka setup`. Cursor: `ka setup` never creates
`~/.cursor/permissions.json` (that file replaces the in-app terminal
allowlist).

Agent-facing `ka run` should be a **bare** command with `--cwd` rather than
`cd && … | tail`:

```bash
ka run --cwd DIR --secret NAME --as NAME=ENVVAR -- <command>
```

## Two modes: ask every time, or unlock a session

| Mode | What it feels like |
|------|--------------------|
| **`per-call`** (default) | Every use of a secret asks for your password. Maximum safety, maximum prompts. |
| **`cached`** | You run `ka unlock` once; a background guard keeps the vault open for 30 minutes (configurable). Agent commands run without prompts until it expires or you `ka lock`. |

```bash
ka config set session-mode cached
ka unlock                           # see flags below
ka lock
```

**Unlock admission flags** (both opt-in; never the default):

| Flag | What it does |
|------|----------------|
| *(default)* | First unrecognized client gets a y/N prompt on the guard TTY. Approval admits **that connecting process** only. Real OS *descendants* of it are silent later; **siblings** under a shared parent (typical next `ka` from the same shell/IDE) are not — they re-prompt. |
| `--pre-admit` | Auto-admits the **very next** connecting process for a bounded window (no prompt). Arrival-time grant — whoever connects first. Optional `--pre-admit-secret NAME` scopes it. |
| `--admit-tree` | At the first unrecognized-peer prompt, pick a kernel-verified **ancestor** as the admission root. Admits that ancestor **and its OS descendants** for the rest of the session. Use this when the connecting client is a short-lived `ka` and you want later sibling invocations under the same parent to stay silent. Does **not** admit processes outside that root's subtree (including siblings *of the root*). Distinct from `--pre-admit` (lineage vs who arrives next). |

```bash
ka unlock --admit-tree              # choose parent/IDE as root when prompted
ka unlock --pre-admit               # next client only, no ancestry picker
```

## Which terminal opens for the password (Linux)

When `ka` is called from something that has no terminal of its own — an agent,
a CI shell, a `.desktop` launcher — it opens one of yours to ask for the master
password, so the password is never typed into the caller's stdin. Windows uses
`CREATE_NEW_CONSOLE` and macOS uses Terminal.app; on Linux there is no single
answer, so key-amnesia has to be told.

`ka setup` asks once, offering what is installed, and stores the answer. To
change it, or to name a terminal the picker did not find:

```bash
ka config set terminal "ghostty -e"     # the command, with the flag it needs
ka config set terminal "kitty"          # kitty, foot and others take none
ka config set terminal auto             # go back to detecting one each time
ka setup --terminal-only                # pick again from what is installed
```

The value is a command, not a program name, which is why a terminal nobody has
heard of works without a code change. `KEY_AMNESIA_TERMINAL` overrides it for a
single run. `ka status` prints the terminal that would open and where the
setting came from.

Full command reference, project vaults, manifests, roles/export, and admission details: **[the wiki](https://github.com/vahta-team/vahta/wiki)** (`ka docs`).

## Security limits — read this part honestly

No tool in this class can promise absolute secrecy, and we'd rather tell you exactly where the edges are:

1. **A command you run can still leak its own secret.** Censoring catches exact copies of the value in output — a command that base64-encodes or otherwise obfuscates the secret before printing slips through. This limit is shared by every tool of this kind (`op run`, `teller run`).
2. **Output is not live.** Command output is collected fully, censored, then released — the agent sees it only after the command finishes.
3. **Secret *names* are stored in plain text** (so `ka list` can work without a password). Values never are. Treat names as non-sensitive labels.
4. **The pop-up window assumes the agent can't control your screen.** If you've given an agent screen-reading *and* keyboard/mouse-injection powers, the window's isolation weakens — your typed password stays hidden, but a yes/no confirmation could theoretically be clicked by such an agent. The same caveat applies to the guard's admission prompt.
5. **Headless machines fail closed.** No display → no way to approve → the operation is denied. By design.
6. **Same-user processes share your privileges.** Any program running under your OS account can talk to a live guard session (this is equally true of `ssh-agent`). That's why the guard is designed to never return raw values — the worst a rogue same-user process gets is the same bounded "run a command" capability the legitimate path has, and even that requires one admission prompt to be approved on your own screen first.
7. **Windows peer identity is weaker than Linux.** Linux binds admission to `SO_PEERCRED` (kernel-verified at accept) and rejects a peer whose kernel uid differs from the guard's `geteuid()`. Windows uses `GetNamedPipeClientProcessId` then an immediate `OpenProcess` whose handle is **held for the admission lifetime** so that PID cannot be recycled while admitted — but the residual race between those two calls is not eliminated, and process-tree ancestry is a consent UX (real OS descendants of an admitted root), not an airtight boundary against in-tree malware that already shares your account.
8. **The master password never crosses any inter-process channel**, in any form — it's consumed only inside the process that prompted you for it.
9. **Avoid `ka set NAME VALUE` with the value inline.** It's supported for scripting, but an inline value briefly appears on the calling process's command line — visible to same-user process inspection and Windows command-line auditing. Prefer plain `ka set NAME` and type the value at the hidden prompt. (If an agent tries the inline form, the approval window shows you the incoming value before asking for your password — so you can still deny it.)
10. **`--pre-admit` is an explicit, opt-in trust-widening you ask for.** It auto-admits whichever process happens to connect first within the window — not necessarily the one you meant — so only use it right before the command you're expecting, for a short window, and treat the loud confirmation line + audit log entry as the evidence of what it actually admitted.
11. **`--admit-tree` is a separate opt-in trust-widening (also never the default, no config/env).** At the first unrecognized-peer prompt it lets you pick a kernel-verified *ancestor* as the admission root, so every real OS descendant of that root (including later sibling CLI invocations under the same parent) is silently in-tree for the rest of the session. That is wider than admitting the short-lived connecting `ka` process alone — use it only when you intend lineage trust, and read the loud `via=interactive-tree` announce + audit line for the root you actually chose. It does **not** change `--pre-admit` (arrival-time grant vs lineage root).
12. **A live guard session reloads on change, not on a fixed schedule.** The guard checks a cheap content fingerprint of the vault file on every `run`/`list`/`status`; when another terminal changes it, the guard re-opens with the SecretBox key it already derived at unlock — no new password prompt. The tradeoff: the guard keeps that **derived key** in memory for the session. Detail: [DESIGN.md](DESIGN.md) and the [threat-model wiki page](https://github.com/vahta-team/vahta/wiki/Threat-model).
13. **Runner role is not a cryptographic ACL against you.** If your local identity is enrolled as `runner`, `ka` refuses `reveal`/`copy` — effective against an agent. Anyone who knows the master password can still decrypt the vault offline. Per-member `ka export` ciphertext *is* cryptographic (only that member's key opens it).
14. **Harness file allow-lists are best-effort; the hook/plugin is the deny.** Claude `permissions.allow` / `autoMode.allow`, Cursor prefixes, and OpenCode `permission.bash` globs try to let the agent run `ka run` / `ka list`. They do not authorize `cd && … | tail` compound chains (each subcommand is classified separately). Codex has no command rules in `config.toml`. Without a trusted hook (or, on OpenCode, the JS plugin), auto-mode deny is inert. An agent that can write harness config can remove or disable the hook; hook self-protection is not in this release.
15. **Hook verb-deny is not a complete `ka` sandbox.** Shell aliases, functions, and renamed copies of the binary are not recognized. A trailing command that *constructs* a `ka` invocation at runtime (`python -c "os.system('ka set …')"`) is not verb-denied. `KEY_AMNESIA_HOOK_DISABLE` on the inner command does not disable the hook process; a **user login** env var can inherit into the harness and is the operator bypass.
16. **Write/Edit tools are not verb-denied** so docs can mention `ka set`. Secret scanning on those tools is unchanged.

Longer honesty notes and policy-vs-crypto labels: [wiki — Threat model](https://github.com/vahta-team/vahta/wiki/Threat-model) (draft; maintainer judgement flagged).

## Community

Questions, bugs, and ideas: [Discord](https://discord.gg/4WnQfk49xX), [GitHub Discussions](https://github.com/vahta-team/vahta/discussions), or [GitHub issues](https://github.com/vahta-team/vahta/issues).

## Support

key-amnesia is free and open source. If it's useful to you, you can support its development here:

<a href="https://www.buymeacoffee.com/fujitoid" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;" ></a>

## Development

```bash
pip install -e ".[dev]"
pytest
```

Design rationale, file formats, invariants: [DESIGN.md](DESIGN.md). Wiki drafts suitable for publishing live in [`wiki/`](wiki/).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
