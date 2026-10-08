# Roles and export

> **Maintainer judgement required.** This draft restates README/DESIGN
> labels. Do not soften "policy vs human / effective vs agent" or claim
> cryptographic ACLs where only policy holds. Review before publishing to
> the live wiki.

> **Honesty:** Runner denial is **not** a crypto ACL against someone who
> knows the master password. The admin signature is **tamper-evident only**
> (detection), not prevention. Offline decrypt with the master password
> still works.

## When KAM2 appears

Users who never touch roles stay on **KAM1** forever. First
`ka member add` upgrades the vault after you confirm:

1. Announce: enabling roles upgrades format; name backup path
   `vault.bin.kam1.bak` (same directory as the vault).
2. Write `vault.bin.kam1.bak`.
3. **Verify the backup decrypts** (re-open with the password).
4. Only then rewrite the live file as KAM2.

**Backup → verify → rewrite.** Never silent. An unverified backup is not a
backup — abort leaves the live KAM1 file untouched. `--yes` skips the
interactive confirm when scripting. Downgrade is not supported; keep the
`.kam1.bak` if you need to pin an older key-amnesia.

## Roles

| Role | Intent |
|------|--------|
| `admin` | Full member/ACL management |
| `writer` | Can mutate secrets they can unwrap |
| `runner` | `run` yes; `reveal` / `copy` no |

**Runner denial is policy** against a human who still knows the master
password, and **effective** against an agent enrolled as runner. It is
**not** a cryptographic ACL against the password holder. Offline decrypt
with the master password still works.

## Crypto vs policy (KAM2)

| Capability | Class |
|------------|--------|
| Per-secret unwrap for members (SealedBox wraps) | **Cryptographic** |
| Admin signature over member/ACL metadata | **Cryptographic, detection only** (tamper-evident — not prevention) |
| Runner cannot `reveal`/`copy` | **Policy** vs human; **effective** vs agent |

Outer vault wrap remains Argon2id + SecretBox (same as KAM1). KAM2 adds
inner per-secret data keys and member wraps; it does not invent a sixth
IPC verb or revive bearer-token admission.

## Identity and export

```bash
ka identity create --label me
ka identity show                 # pubkey only
ka member add alice --pubkey HEX --role runner
ka grant API_KEY --to alice
ka export --for alice -o alice.kamx
```

`ka export --for MEMBER` writes a KAMX ciphertext bundle containing only
that member's ACL'd secrets — that per-member export **is** cryptographic
(only that member's key opens it). Full byte layout: repository
`DESIGN.md` ("KAM2 specification").
