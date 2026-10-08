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
rewrites tool output. It never starts the daemon and waits at most 0.3 s for it.
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
