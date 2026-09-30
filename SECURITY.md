# Security Policy

## Reporting a vulnerability

Please use [GitHub private vulnerability reporting](https://github.com/vahta-team/vahta/security/advisories/new) for this repository.

Do **not** open a public issue, discussion, or Discord message that includes exploit details or secret values.

There is no published personal email for security reports.

## Supported versions

Only the latest release on [PyPI](https://pypi.org/project/key-amnesia/) (`key-amnesia`) is supported for security fixes. Older versions may receive fixes only by upgrading.

## Scope

Security reports should assume the documented limits in [README.md — Security limits](README.md#security-limits--read-this-part-honestly). In particular:

- Scrubbing is exact-substring only; obfuscated leaks in command output can slip through.
- Same-user processes share OS privileges with a live guard (comparable to `ssh-agent`).
- Windows peer identity is weaker than Linux `SO_PEERCRED`; process-tree ancestry is a consent UX, not an airtight boundary against in-tree malware under the same account.
- Opt-in flags `--pre-admit` and `--admit-tree` deliberately widen trust when the operator asks for them.
- Runner-role denials for `reveal`/`copy` are policy against an agent, not a cryptographic ACL against someone who knows the master password.

Reports that ignore these documented edges (for example “same-user process can talk to the guard”) are expected behavior unless they show a break of an invariant the docs claim holds (guard never returns raw vault values; master password never crosses IPC; kernel identity rather than message fields for admission; etc.).
