# Threat model

> **Maintainer judgement required.** Prefer the plain voice of the README
> "Security limits" section. Do not claim OS identity binding is equally
> strong on every platform. Align policy-vs-crypto rows with DESIGN.md
> before treating this page as final.

## What key-amnesia tries to do

- Keep vault values out of agent context (chat, tool output, transcripts).
- Require a real human at a real keyboard for password and for admission.
- Never return raw secrets over guard IPC (exactly five verbs:
  `{run, list, lock, status, renew}` — `connect` is a CLI alias only).
- Scrub exact copies of injected values from command output (best-effort).

## What it does not claim

Aligned with README Security limits — do not invent stronger crypto or OS
isolation than the product states:

1. **Obfuscated leaks.** Base64 / transform-before-print bypasses exact
   substring scrubbing — same class of limit as `op run` / `teller run`.
2. **Live streaming output.** Buffer-then-scrub-then-relay only.
3. **Secret names are ciphertext.** Names sidecar is plaintext by design.
4. **Agents with full UI control.** Screen + input injection weakens the
   isolated console story for yes/no clicks (typed password stays hidden).
5. **Headless approval.** No display → deny.
6. **Cross-user OS isolation inside one account.** Same-user processes
   share privileges; defence is "no value-return verb" + admission, not a
   new OS sandbox.
7. **Windows peer identity equals Linux.** It does not — see below.
8. **Password never on IPC** — true; do not confuse with "derived key never
   in guard memory" (it is retained for reload).
9. **Inline `ka set NAME VALUE`** — argv exposure; prefer hidden prompt.
10. **`--pre-admit`** — consent-before → audit-after for one bounded tree;
    whichever process connects first wins the window.
11. **Guard reload key retention** — derived SecretBox key in memory for
    the session (not the master password).
12. **Runner role** — not a crypto ACL against the master-password holder;
    per-member `ka export` ciphertext *is* cryptographic.
13. **Harness allow files vs hook deny.** File allow-lists try to let
    agents run `ka run` / `ka list`. The PreToolUse hook is the
    load-bearing deny for `ka set` / `reveal` / `scan --yes` / nested
    `ka run -- ka set`. Removing or disabling the hook removes deny.
    Aliases, renamed binaries, and runtime-constructed `ka` invocations
    are out of scope. Codex deny runs only after `/hooks` trust.
14. **Write/Edit hook self-protection** (agent rewriting the hook or
    harness config) is planned, not this release.

## Platform honesty (admission)

- **Linux:** `SO_PEERCRED` (kernel-verified at accept) + start time; kernel
  uid compared to the guard's `geteuid()` — mismatch fails closed.
- **Windows:** `GetNamedPipeClientProcessId`, then immediate `OpenProcess`
  whose handle is **held for the admission lifetime** (PID not recycled
  while admitted). Residual race only between those two calls — not
  eliminated. Weaker than Linux against determined same-user attackers.
- **Ancestry** is consent UX (real OS descendants of an admitted root),
  not an airtight boundary against in-tree malware that already shares
  your account.
- **macOS:** kernel peer-identity admission remains fail-closed; do not
  treat experimental console spawn as peer-admission support.
- There is **no on-disk bearer / admission token** in the current model
  (pre-0.3.8 opaque-token path is tests-only / legacy).

## Policy vs cryptography (summary)

| Feature | Class |
|---------|--------|
| Vault AEAD / Argon2id | Crypto |
| Guard never returns values over IPC | Protocol invariant |
| Five-verb freeze (`{run,list,lock,status,renew}`) | Protocol invariant |
| Output scrubbing | Best-effort |
| Derived key retained in guard | In-memory exposure (documented) |
| Kernel peer binding | OS-backed — strong Linux (incl. uid check); weaker Windows |
| Process-tree admission | Consent UX; not airtight vs in-tree malware |
| Secret-scoped grants / pre-admit | Consent UX / blast-radius policy |
| Manifest / `ka check` | Project contract / CI policy |
| Scan LEAK report | Advisory |
| KAM2 per-secret wrap / export | Crypto |
| Admin signature | Tamper-evident / detection only |
| Runner no reveal/copy | Policy vs human; effective vs agent |
| Harness file allow-lists | Best-effort (unattended `ka run`) |
| PreToolUse verb deny | Load-bearing vs agent Bash; not a sandbox |

Canonical design text: repository `DESIGN.md`. README Security limits are
the short honesty contract.
