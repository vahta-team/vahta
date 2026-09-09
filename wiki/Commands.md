# Commands

Skeleton reference. Prefer `ka <command> --help` for flags. Full design
notes live in the repository `DESIGN.md`.

| Command | What it does |
|---------|--------------|
| `ka init [--project] [--env NAME]` | Create vault (double-confirm password). `--project` → `.amnesia/` |
| `ka passwd` / `ka change-password` | Change master password (refuses while session active) |
| `ka set NAME` | Store/update secret (hidden prompt preferred over inline value) |
| `ka remove NAME` | Delete a secret |
| `ka import FILE [FILE …]` | Import dotenv file(s) into resolved vault (TTY-only) |
| `ka check [--json]` | Manifest vs project names sidecar (CI; no decrypt) |
| `ka scan [--deep] [--wide] [--include-excluded] [--json] [--strict] [--yes] [--no-import] [--quiet]` | LEAK report (names/paths/counts only); optional offer-to-import |
| `ka run --cwd DIR --secret NAME [--as NAME=ENVVAR] -- <cmd>` | Inject + scrub; agent-facing path (`=` form required for `--as`) |
| `ka list` | Names only; safe for agents; no prompt |
| `ka unlock [--pre-admit] [--pre-admit-secret NAME] [--admit-tree]` | Start cached guard session (pre-admit / admit-tree flags opt-in) |
| `ka lock` | End session early |
| `ka reveal NAME` / `ka copy NAME` | Human-only surface of a value; always fresh auth |
| `ka config show` / `ka config set KEY VALUE` | Settings |
| `ka status` / `ka connect` | Session status (+ registry of live guards). `connect` is a **CLI alias** for `status` — not a sixth IPC verb |
| `ka setup [--skills-only] [--hook-only] [--permissions-only] [--permissions-remove] [--terminal-only] [--reconfigure-terminal] [--yes]` | Install skills, secret-guard hook, and harness allow-lists (Claude / Cursor / Codex); on Linux, also pick the terminal that opens for the password |
| `ka docs [--print]` | Print wiki URL; open browser unless `--print` |
| `ka identity create` / `show` | Local X25519 identity for KAM2 |
| `ka member add` / `list` / `remove` | Members/roles (first add enables KAM2) |
| `ka grant` / `ka revoke` | Per-secret ACL |
| `ka export --for MEMBER` | Ciphertext bundle for one member |

### `run` mapping

```bash
ka run --cwd DIR --secret API_KEY --as API_KEY=API_KEY -- python my_script.py
# or inject under the secret's own name:
ka run --cwd DIR --secret API_KEY -- python my_script.py
```

`--as` takes `NAME=ENVVAR` only (CLI requires the `=` form). Omitting
`--as` injects the secret under its vault name. Prefer `--cwd DIR` over
`cd &&`; do not wrap `ka run` in pipes or `2>&1`.

### `scan` flags

- `--deep` — also check home dotfiles, shell history, global git config,
  known MCP paths (not a full home walk). Independent of `--wide`.
- `--include-excluded` / `--wide` — include default-excluded dirs; git-history scan
  still out of scope. `--wide` is an alias only.
- `--json` — machine-readable report (`leak_count` matches the `--strict` gate; always includes `certain_count`, `likely_count`, `possible_count`, `strict_certain` / `strict_high` / `strict_paranoid`, and per-finding `confidence` + `reasons`)
- `--strict certain|high|paranoid` — default `high`: exit 1 iff certain+likely `leak_count` > 0. `certain` is prefixes and confirmed filenames. `likely` is assignments and UUID-shaped values. `paranoid` also fails on identifier/passphrase/low-transition hits and unconfirmed `mcp.json` (the ≤0.4.9 assignment gate). Invalid value → exit 2. Headline names the gate and the location of gated findings. The three-count summary and the three gate totals print at every strictness. Unconfirmed MCP configs count as one possible per file.
- `--yes` — import all importable dotenv findings without selection
  prompts (password still required from a TTY). Never deletes or
  renames. Adds `.env*` to `.gitignore` when missing (filesystem
  policy, not cryptographic). Still exits 1 while those source files
  remain — do not treat `ka scan --yes && deploy` as a clean gate.
- `--no-import` — report only; never offer vault store
- `--quiet` — suppress `--deep` progress on stderr (stdout unchanged)

### `unlock` flags

- `--pre-admit` — loudly pre-admit the next client for a bounded window
- `--pre-admit-secret NAME` — scope that window (repeatable); omit for
  unscoped ALL-secrets pre-admit
- `--admit-tree` — at the first unrecognized-peer prompt, choose a
  kernel-verified ancestor as the admission root (widens trust to its
  descendants); session-only, off by default

### `config set terminal` (Linux)

Which terminal `ka` opens to ask for the master password when the caller has
none of its own — an agent, a CI shell, a `.desktop` launcher. The value is a
**command prefix**, carrying whatever flag that terminal needs, so a terminal
the detector has never heard of works without a release.

```bash
ka config set terminal "ghostty -e"     # -e for ghostty, alacritty, konsole
ka config set terminal "kitty"          # kitty and foot reject -e; no flag
ka config set terminal "wezterm start --"
ka config set terminal auto             # detect one on each run (default)
```

`KEY_AMNESIA_TERMINAL` overrides the stored value for one run.
`ka status` prints the terminal that would open and where the setting came
from. `ka setup` asks once and keeps the answer; `ka setup --terminal-only`
picks again.

Unlike every other config key, `terminal` does **not** require the master
password: it is the setting that decides where a password can be typed, so
gating it behind typing one would deadlock exactly the user it exists to help.
It guards nothing — anyone who can write the config file can already replace
`ka` on `PATH` — and `config set` stays denied to agents by `ka_policy`.

Vault-aware commands also accept `--vault PATH`, `--global`, `--no-global`,
`--env NAME`. Guard-talking commands accept display-only `--name LABEL`.

`reveal` / `copy`: even if an agent invokes them, the value appears only in
the human's window/clipboard; the agent process gets a status flag.

Guard IPC verbs remain exactly `{run, list, lock, status, renew}`.
