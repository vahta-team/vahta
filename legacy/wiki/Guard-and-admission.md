# Guard and admission

## Cached sessions

```bash
ka config set session-mode cached
ka unlock
ka lock
ka status          # CLI alias: ka connect (same handler; not an IPC verb)
```

`ka unlock` runs the guard **in that terminal**. Startup shows expiry and
how to stop early (`Ctrl+C` or `ka lock` from another terminal). Before
expiry the guard asks whether to extend; no answer means lock.

## Guard never returns values

IPC verbs stay exactly `{run, list, lock, status, renew}` — five only.
There is no "give me the secret" request and no sixth verb. `ka connect`
is a plain CLI alias for `status`; it is **not** a guard IPC verb. The
guard runs your command itself (with injection) and returns scrubbed
output + exit code.

## Kernel-verified admission

The first command from an unrecognized process triggers a yes/no prompt on
the guard's own TTY. Approval binds to the connecting process's
**kernel-verified** identity — `(pid, start_time)` from the OS, not a
client-claimed field. There is **no on-disk bearer / admission token** to
steal, read, or leave stale.

Descendants of an admitted tree are recognized via OS ancestry (consent
UX). Unrelated processes — including a sibling CLI from the same login
shell — get their own prompt. Ancestry is **not** an airtight boundary
against in-tree malware that already shares your account.

Optional display-only `--name LABEL` / `KEY_AMNESIA_CLIENT_NAME` for the
prompt text — **zero security weight**.

## Secret-scoped grants

Admission tracks *which* secrets a tree may use, not only whether it is
admitted. A later `run` that names a secret outside the current grant
re-prompts to expand scope (audit: `"scope expanded"`), rather than a
blanket allow or a full re-admit. An unscoped grant (interactive approval
with no secret names, or `--pre-admit` with no `--pre-admit-secret`)
covers every secret without further prompts.

## Pre-admit

```bash
ka unlock --pre-admit
ka unlock --pre-admit --pre-admit-secret NAME   # repeatable; scoped
```

Opt-in, never default. Auto-admits the **next** connecting process for a
bounded window (default 15 minutes / `pre-admit-seconds`). Unscoped
(ALL secrets) is loud on the TTY and in the audit log. Single-use —
consumed by the first peer to connect. This trades consent-before for
audit-after for one bounded tree; use it only right before the command
you expect.

## Admit-tree

```bash
ka unlock --admit-tree
```

Opt-in, session-only (no config/env). At the first unrecognized-peer
prompt, offers numbered kernel-verified ancestors so you can admit a
*parent* (or other ancestor) as the root — every real OS descendant of
that root is then silently in-tree. Fixes the empty-tree case when the
connecting peer is a short-lived `ka`. Distinct audit `via=interactive-tree`.
Does **not** change `--pre-admit` (arrival-time vs lineage). Agents never
run `unlock`; only the human enables this when lineage trust is intended.

## Platform honesty

- **Linux:** `SO_PEERCRED` at accept (kernel-verified pid/uid/gid). Kernel
  uid is compared to the guard's `os.geteuid()`; mismatch **fails closed**.
  Start time comes from `/proc/<pid>/stat`. Stronger than Windows.
- **Windows:** `GetNamedPipeClientProcessId`, then immediate `OpenProcess`
  + `GetProcessTimes`. For an admitted peer, that `OpenProcess` handle is
  **held for the admission lifetime** so the PID cannot be recycled while
  admitted. Residual race only in the brief window *before* `OpenProcess`
  succeeds. Weaker than Linux peer creds against determined same-user
  attackers.
- **macOS / other:** kernel peer-identity lookup is **not** implemented —
  admission **fails closed**. Experimental macOS isolated-console spawn
  (password prompts) does not enable peer admission. See [macOS](macOS).

## Reload

On every `run` / `list` / `status`, the guard fingerprints vault file(s).
If changed, it re-opens with the retained derived SecretBox key (no
Argon2id, no new password prompt). Merged project+global unlocks
fingerprint every contributing file. Tradeoff: that derived key stays in
guard memory for the session (not the master password).
