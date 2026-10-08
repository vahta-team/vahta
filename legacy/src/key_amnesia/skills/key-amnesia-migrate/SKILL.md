---
name: key-amnesia-migrate
description: >-
  One-shot workflow to migrate a project's existing plaintext secrets (.env
  files, hardcoded API keys, config files) into the key-amnesia vault. Use
  when the user asks to "migrate to key-amnesia", "move my secrets to the
  vault", or clean up plaintext credentials in a repo. Locates candidates by
  filename/pattern only, reports name + path (never values), and walks the
  user through `ka set` + code changes to `ka run`.
---

# Migrating a project to key-amnesia

A one-shot workflow for moving a project's existing plaintext secrets into the vault, without the agent ever reading or echoing a value.

## Step 1 — Locate candidates (name + path only)

Search the project for likely secret sources by **filename/pattern**, not content inspection of values:

- `.env`, `.env.local`, `.env.*` files
- Config files with credential-shaped keys (`config.json`, `settings.yaml`, `secrets.*`)
- Source files with hardcoded assignments matching the hygiene skill's vocabulary (`API_KEY = "..."`, `TOKEN=...`, etc.)

For each candidate, report only:

```
Found: OPENAI_API_KEY  (in .env line 3)
Found: DB_PASSWORD      (in config/settings.yaml)
```

**Never** print, echo, or otherwise surface the actual value — not in chat, not in a summary, not in a "let me confirm this is right" message. Name and location only.

## Step 2 — Walk the user through `ka set`

For each secret name found, tell the user to run (in their own terminal — this is human-only, same as `ka init`):

```bash
ka set OPENAI_API_KEY
ka set DB_PASSWORD
```

Each prompts hidden for the value. Do not attempt to script or automate this step — `ka set` without a value argument is the safe form, and the value must come from the human typing it, not from the agent reading the old plaintext file and piping it in.

## Step 3 — Update code to use `ka run`

Rewrite the project's run/start scripts (or document the new invocation) to inject secrets via `ka run` instead of reading `.env`/config files directly:

```bash
# Before
python app.py   # reads OPENAI_API_KEY, DB_PASSWORD from .env

# After
ka run --secret OPENAI_API_KEY --as OPENAI_API_KEY=OPENAI_API_KEY \
       --secret DB_PASSWORD --as DB_PASSWORD=DB_PASSWORD \
       -- python app.py
```

Remember `--as` is **`NAME=ENVVAR`** — left side is the vault secret name, right side is the environment variable name the app expects (often the same string, but not always).

## Step 4 — Remove the plaintext originals

Once the user confirms the migrated commands work:

- Delete the plaintext `.env`/config values (or the whole file if nothing else lives there).
- Make sure `.env` (or equivalent) is in `.gitignore` if it isn't already — but don't assume it's safe to leave the file around "just in case."
- Remind the user to rotate any secret that was ever committed to version control, chat, or logs — migrating a compromised value to the vault doesn't un-compromise it.

## Hard bans (same as every other key-amnesia skill)

- Never read the value out of the old file and pass it to `ka set NAME VALUE` on the agent's behalf — that still puts the value through agent hands and onto argv. Always have the human type it via `ka set NAME`.
- Never paste a discovered value into chat "to confirm it's the right one."
- Never read `~/.key-amnesia` directly, or call `reveal`/`copy` to double-check a migrated value.
