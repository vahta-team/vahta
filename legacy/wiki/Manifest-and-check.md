# Manifest and `ka check`

Since **0.3.11**. Commit `amnesia.toml` at the project root — names and
metadata only, no values:

```toml
[secrets.API_KEY]
required = true
description = "Provider API key"
env = "API_KEY"
```

`ka import` writes/merges this automatically. Legacy `[[secret]]`
array-of-tables (0.3.9–0.3.10 import shape) is still read.

## CI

```bash
ka check
ka check --json
```

Compares required entries to the **project** names sidecar only
(`.amnesia/vault.names.json` or the active `--env` sidecar) — **no
decrypt, no global vault**. Requires a project vault (`.amnesia/`).
Non-zero exit on missing required secrets or a malformed manifest.

Locally, `ka run` also refuses to inject when required secrets from that
manifest are absent from the injectable name set (sidecars only — still no
decrypt for the gate). When merge is enabled, `ka run`'s pre-check may
consider merged sidecar names; `ka check` itself always forces project-only.

This is a **project contract / CI policy**, not cryptography.
