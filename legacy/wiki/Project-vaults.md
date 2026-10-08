# Project vaults

Since **0.3.10**. Walk-up from cwd finds the nearest `.amnesia/` (stops at
your home directory). No `.amnesia/` means the global vault at
`~/.key-amnesia` (override: `KEY_AMNESIA_HOME`, `KEY_AMNESIA_VAULT_PATH`).

## Layout

```
.amnesia/
  config.json              # {"use_global": true, "default_env": optional}
  vault.bin                # default env
  vault.names.json
  envs/<name>/vault.bin    # from --env / KA_ENV / default_env
  envs/<name>/vault.names.json
```

```bash
ka init --project
ka init --project --env staging
```

`ka init --project` scaffolds the tree and auto-gitignores `.amnesia/`.

## Merge with global

By default `"use_global": true` in `.amnesia/config.json` — project and
global vaults merge; **project wins** on name collision. Independent
ciphertexts mean **two password prompts** when both vaults exist and both
contribute (unlock / run / list paths that merge). Set `"use_global": false`
or pass `--no-global` to isolate at the CLI level — that is policy isolation
for agents, not a cryptographic boundary. `--global` forces the home vault;
`--vault PATH` skips discovery.

Fresh-auth mutations (`set` / `remove` / `reveal` / `copy` / `import`)
target a **single** resolved vault only — usually the project vault when
you are inside one.

Flags on vault-aware commands: `--vault PATH`, `--global`, `--no-global`,
`--env NAME` (also `KA_ENV` or `default_env` in config).

## Guard placement

Daily use: **one `ka unlock` per project vault**. Guard lock and
`last_guard_state.json` sit beside the active vault (e.g. `.amnesia/` or
`.amnesia/envs/<name>/`).

A discovery-only registry at `~/.key-amnesia/guards/` lists live guards
(vault path, env, pid, expiry, endpoint address — **never** the authkey).
`ka status` / `ka connect` consult it and drop stale entries.

Existing global-only setups need no migration.
