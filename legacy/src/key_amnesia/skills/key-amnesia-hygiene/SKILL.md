---
name: key-amnesia-hygiene
description: >-
  Advisory secret hygiene for chat, about-to-write, and about-to-run content.
  Use when the user pastes a secret, shares credentials in a message, or you
  are about to write a file or run a command that might contain an inline API
  key, token, or password. Offers `ka set` and prefers `ka run` for env
  injection. Same detection vocabulary as the secret_guard hook, but advisory
  — this skill has no enforcement power on its own.
---

# key-amnesia hygiene

This skill is advisory: it describes the same detection vocabulary as the blocking `secret_guard` PreToolUse hook, so you can catch and avoid secret leaks *before* the hook (if installed) would deny the tool call — and so you still behave correctly if the hook isn't installed.

## When to apply this

1. **Chat.** The user pastes a password, API key, token, or similar secret into the conversation.
2. **About to write.** You are about to create or edit a file (script, `.env`, config, command output) whose content would contain a credential-shaped value.
3. **About to run.** You are about to run a shell command whose argv would contain a credential-shaped value.

## Detection vocabulary (advisory — mirrors the hook)

Treat text as secret-shaped if either is true:

- **Known prefixes anywhere:** `sk-`, `sk-ant-`, `ghp_`/`github_pat_`, `AKIA...`, `xoxb-`/other `xox*-`, `AIza...`, plus Stripe (`sk_live_`/`rk_live_`), `npm_`, `glpat-`, and generic `Bearer <token>`.
- **Assignment + high entropy:** a `(API_KEY|TOKEN|SECRET|PASSWORD)[:=]` style assignment whose value is long and mixed-case/digit (looks random), not a placeholder. Function-call values (`secrets.token_hex(8)`) and type annotations (`Optional[str]`) are not findings. CamelCase identifiers and word-shaped passphrases (`CorrectHorseBattery`) still match this hook vocabulary — that over-block is intentional. (`ka scan` counts those as `possible` only; the default `--strict high` headline uses certain + likely / prefix.)

**Not** a finding by itself (do not flag): bare `API_KEY` with no value, a comment that merely mentions "secret", or an assignment to an obvious placeholder like `PASSWORD=test123` / `TOKEN=changeme`. Advisory judgment still applies — use sense, don't nag on clearly-fake values.

## Rules

1. **Stop echoing.** Do not repeat the secret in your reply, in tool args, in commits, or in files. Refer to it only by a short placeholder (e.g. `[redacted]`) or by the intended vault name.
2. **Offer `ka set`.** Suggest storing it in the key-amnesia vault so it never needs to live in the conversation, a file, or a command again:

   ```bash
   ka set SECRET_NAME
   ```

   The human types the value at a hidden prompt in their own terminal — you do not need (and must not ask them to re-paste) the value in chat.
3. **Prefer `ka run`.** For any command that needs the secret, inject via env instead of inline:

   ```bash
   ka run --secret SECRET_NAME --as SECRET_NAME=ENV_VAR -- <command>
   ```

   Never put the raw value on argv, in `.env` files the agent can read, or in shell history via `export SECRET=...`.
4. **Do not "helpfully" rewrite** the user's paste into a script, curl header, or config with the value filled in. Point them at `ka set` + `ka run` instead.
5. If they already pasted a secret, acknowledge briefly that it should be rotated if the chat is retained, then move them to the vault flow — still without echoing the value.
6. If a `secret_guard` hook denial fires on something you were about to write or run, treat it as confirmation, not an obstacle to route around — rewrite the command/file to use `ka run`/`ka set` instead of retrying with a rephrased secret.

## Out of scope

- Reading vault values (`reveal` / `copy`) — always human-prompted; agents must not chase raw values.
- General vault CLI usage — see the `key-amnesia-usage` skill.
