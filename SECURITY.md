# Security Policy

## Reporting a vulnerability

Please use [GitHub private vulnerability reporting](https://github.com/vahta-team/vahta/security/advisories/new) for this repository.

Do **not** open a public issue, discussion, or Discord message that includes exploit details or secret values.

There is no published personal email for security reports.

## Supported versions

Vahta 0.0.1 is not released yet. Until it is, security fixes go to the
`release/0.0.1` branch, and, for the Python key-amnesia, to `master`; the latest
release on [PyPI](https://pypi.org/project/key-amnesia/) is its supported version.

## Threat model

Vahta is built so that an agent can use a secret without being able to ask for
its value. In short:

- The **daemon** is the vault's only owner. The `vahta` command and the agent
  hook are clients and hold no vault key. The client messages have no field in
  which a secret or the password could travel.
- The password and secret values are typed in a **window the daemon opens**, over
  a one-time connection, never in the agent's terminal or on a command line.
- The daemon learns who is calling from the operating system, not from what the
  caller says.
- `vahta run` returns output with every held value removed, including common
  encodings. The agent hook refuses secret-shaped values in tool calls, redacts
  tool output, and guards Vahta's own files and the hook settings.
- Sessions are scoped to an anchor process, are runners only, and end on
  deadline, lock, sleep or when the anchor exits.

The full account, including what is **not** protected, is in
[docs/daemon.md](docs/daemon.md#what-this-does-not-protect-against), with the
hook in [docs/hooks.md](docs/hooks.md) and the structure in [DESIGN.md](DESIGN.md).

## Scope

Reports should assume those documented limits. In particular:

- The command `vahta run` starts holds the secret and can print or send it; the scrubber catches the value and the common encodings, not arbitrary transformations.
- Everything runs as the same user: on Linux a process of yours can read another's `/proc/<pid>/environ`, and can do what you can do.
- The agent hook is a best-effort speed bump. It does not follow globs, variables, command substitution or interpreters.
- Command rules (`allow`, `deny`) are narrower than they look: an allowed program can itself pass a secret on.
- Revoking a session stops future use; it cannot recall a value already handed to a running command.

Reports that ignore these edges are expected behavior unless they show a break of an invariant the docs claim holds (a client message that carries a value or a password; a caller identified by what it says rather than by the operating system; a vault value written to the journal or an error message; a session read that quietly falls back after a secret changed; and the like).
