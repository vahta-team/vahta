# Vahta design

An overview of how the parts fit. Behaviour is specified in [docs/daemon.md](docs/daemon.md)
and [docs/hooks.md](docs/hooks.md); this page says where things live and why they
are split the way they are.

## The shape

```
                     ┌───────────────┐   window (one-time connection)
  person ──────────► │ prompt window │◄───────────────┐
                     └───────────────┘                │
  agent ─► vahta CLI ──┐                              │
                       ├─► socket ─► daemon ──────────┘   owns the vault, sessions, journal
  agent ─► vahta-hook ─┘                │
                                        └─► vault.vht (.vahta/), journal.jsonl
```

The **daemon** is the vault's only owner. The **CLI** and the **hook** are
clients: they ask, and none of them holds a vault key. The rule that makes this
worth anything is that the client messages have no field in which a secret value or
the password could travel; the one connection that does carry them is the prompt
window's, opened by the daemon for one request.

## Crates

| Crate | Role |
|---|---|
| `cli` | `vahta` / `vh`: parses arguments, talks to the daemon, `scan`, `setup` front end |
| `daemon` | The vault owner: sessions, `run`, binding, prompt surface, journal, alarm, lock sources, watchdog operations |
| `ipc` | What a client needs: wire protocol, client, paths, `config.toml`, the hook spool. Kept free of the vault's crypto so the hook stays small and fast |
| `hook` | `vahta-hook`: the agent hook, run on every tool call |
| `harness` | Per-harness manifests (Claude Code, Codex, Cursor): event names, payload and reply shapes, config locations |
| `setup` | Merges and removes our hook entries in a harness's config; the watchdog's restore uses it too |
| `vault` | `vault.vht` format, crypto, local store, `vahta.toml`, the ka import |
| `detect`, `rules` | Secret-shape detection; the rules as data |
| `scan` | Finds plaintext credentials an agent can read in a project |
| `os` | The operating-system calls: peer identity, process ancestry, hardening, the local socket. The only crate that may contain `unsafe` |
| `json` | A JSON parser for hostile input, with limits |

## Prompt surface

Anything that needs the person opens a **new terminal window** running
`vahta _surface`, never the terminal of whoever typed the command. It connects
back to the daemon with a token valid for one request. What the person approves is
what Vahta renders (project, vault, names, duration, anchor); the only text an agent
supplies, a label or reason, is cleaned and shown marked unverified. The surface is a
trait, so tests use a scripted one.

## Vault format

`vault.vht` is a frame (magic, format number, body, signature section) followed by a
format-specific body. Argon2id derives the key from the password; values are
padded and sealed with XChaCha20-Poly1305 under a per-secret key; that key is
wrapped for the owner and for each recipient; the name index is plaintext and
Ed25519-signed so that `list` and `check` need no password. Each format has a frozen
module and an upgrade chain; there is no way to write an older format. The machine
remembers each vault's owner key and highest generation, so a swapped or rolled-back
file is refused. The approved binding rules live inside the signed vault; `vahta.toml`
is only a proposal.

Format 2 differs from format 1 in three places, all inside the signed body:

- **Key slots are generic.** A slot is a kind number, an id, a label, creation and
  optional expiry times, kind-specific `params` and `ct` (the vault key wrapped under
  the kind's key-encryption key). Password (kind 0, Argon2id salt and cost in `params`)
  and recovery (kind 1) are kinds; at most one of each, at most 16 slots in all. A kind
  a build does not know is kept byte for byte on every write and skipped when
  unlocking, so a slot from a newer Vahta never makes the file unreadable. A slot's AAD
  binds the vault, the kind and the slot id.
- **Rule sets** replace bindings: besides `allow`/`deny` command rules a rule set holds
  an optional category (and the one it was downgraded from), directories (canonical
  absolute path, read-only or read-write, and the text the person saw) and a network
  (`None`, a list of host rules, or `App`: not narrowed by Vahta). Directories and
  network are stored and signed; enforcement comes with the sandbox.
- **Paired devices** (id, name, P-256 signing and ECDH public keys, pairing and expiry
  times, transports) are listed in the body. A device's key slot is an ordinary slot.

A format 1 file is read as it is and upgraded by an owner unlock: bindings become rule
sets with network `App` and no directories, slots keep their bytes (no key needed),
every secret is re-sealed for the new format number. Nothing is written by opening. The
first save writes the upgraded file and, before that, the original byte for byte to
`<vault>.v1.bak` (mode 0600, never overwritten). The generation continues, so the
rollback check is unaffected.

Format 3 adds one list to the signed body, `successors`: the owner
successor chain. A re-key (new vault key, so new owner signing key) appends a record
`{old_owner_sign_pub, new_owner_sign_pub, generation, created_at, signature_by_old}`,
signed by the old owner key over `"vahta/successor" ‖ vault_id ‖ old ‖ new ‖
generation ‖ created_at`. The generation counts re-keys (1, 2, ...), not file saves;
the last four records are kept. A reader checks the whole chain at decode (each
signature, each record starting where the one before ended, generations rising, the
last record naming the file's owner) and refuses a file whose chain is broken. A machine pinned to an
old owner key follows the chain only after the vault has opened there with the
person's own secret and the person has confirmed in a window (a stolen old key can
sign a fake successor; opening the new file needs a secret it does not give). Format
3 shares everything else with format 2 (`v3.rs` re-exports it; the sealed secrets are
sealed again under the number 3). A format 2 file is read as it is and upgraded the
same way as 1 to 2: an owner unlock, the original kept once as `<vault>.v2.bak`, the
generation continuing. Slots keep their creation time through re-keys, password
changes and a device slot's rewrap, because "the last enrolled unlock method" is read
from it. See `docs/daemon.md` ("Devices, factors, re-keying and recovery").

Format 4 adds `remote` to the signed body (the person's opt-in that the vault
may be used from other projects; off) and `from` to every rule set (absolute, canonical
project folders the secret may be used from outside the vault's own project; empty).
`v4.rs` re-exports format 3 and redefines the rule set, the body and the model; the
sealed secrets are sealed again under the number 4. A format 3 file is read as it is and
upgraded by an owner unlock with the flag off and every `from` empty, the original kept
once as `<vault>.v3.bak`. The body is postcard, so a field this build does not know is
not carried: a file with extra or missing bytes is refused (`Corrupt`), and a newer format
number is refused before that (`NewerFormat`). See `docs/daemon.md` ("Using a vault from
another project").

Format 5 (current) adds four things to the signed body: `kind` (`Project`, or
`Connectors` for a vault of the person's own connections; fixed at creation), `roles`
(named agent grants: secrets, command rules, directories, network, limits and the
allowed actions, each with the time the person approved it), `expires_at` on every
member (covered by the member's certificate, so it cannot change without the issuer),
and `harnesses` on a rule set (`claude`, `codex`, `cursor`; only a `Connectors` vault
may have any). `v5.rs` re-exports format 4 and redefines the member, the rule set, the
body and the model. A format 4 file is read as it is and upgraded by an owner unlock
(kind `Project`, no roles, no expiries, no harnesses), the original kept once as
`<vault>.v4.bak`; a member without an expiry is certified exactly as before, so no
certificate needs re-signing.

## Sessions and anchors

A session is a set of unwrapped secret keys held by the daemon for an **anchor**
process and everything it starts: the nearest ancestor of the calling `vahta` that
is not a shell or wrapper. Identity is `(pid, start time)` from the kernel
(`SO_PEERCRED`, `LOCAL_PEERPID`, `GetNamedPipeClientProcessId`), never a field in a
message. A session is a runner (it can `run`, nothing else), has a deadline, can be
extended, narrowed for a sub-agent, and ends on lock, sleep, the anchor's exit or
daemon stop; ending it overwrites its keys.

## Protocol and journal

Requests and replies are length-prefixed JSON over a Unix socket in a private
runtime directory (a named pipe restricted to the user on Windows). A refusal is
structured, with a kind and the names concerned, and has its own exit code. The
journal (`journal.jsonl`, 0600, append-only) records what happened, to which
session and names, and who asked, and has no field for a value or a password.

## Detector and rules

`detect` decides whether a string carries a credential and how confidently:
vendor prefixes, then the data rules in `crates/rules` (TOML, with samples that the
tests check, a keyword prefilter and lazily compiled regexes), then structural
rules, then name matchers, then a decode-and-look-again pass for hidden values. All
limits (window size, rules per call, regex size) are constants, so the cost of a
call is known before the text is read. The hook, `scan` and the output scrubber
share it.

## The hook

The hook reads a harness event on stdin and answers allow or deny, and must never
brick the agent: a failure means allow. It checks tool input (detector, held values
through the daemon, Vahta's own files, hook settings, commands for the person) and
rewrites tool output. It waits at most 0.3 s for the daemon. When none answers it starts one in the
background (only the `vahta` next to the hook binary, never one found through `PATH`
or the working directory), waits at most 1.2 s for it, and gives up for good after
three failed starts in a row (a count in the runtime directory, cleared when a
daemon is seen answering); late or never, that call is strict and the next one looks
at the socket again.
Each refusal is reported to the daemon, or spooled to disk when none is running.

## Watchdog and alarm

The **watchdog** (`vahta _guard`) is a separate process that holds no key and only
watches the harnesses' hook settings; on tampering it asks the person through the
daemon and restores the hooks. It starts only if the person agreed at setup. The
**alarm** scores hook reports per agent over a ten-minute window and, past a
threshold, asks the person to lock every session (or locks them at once).

## Platforms

Linux first; macOS and Windows build and test in CI. Platform differences stay in
`os` (peer identity, socket, hardening) and in the harness manifests (config paths).
