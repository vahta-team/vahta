# Why not `.env`

`.env` was designed for a threat model whose adversary was **git**. One line
in `.gitignore` and you were done.

That model is obsolete. The adversary is now the **agent sitting in your
project**. Anything the agent can read is a **LEAK** — Locally Exposed Agent
Key:

- `.env` / `.env.local` / `.env.production`
- credentials JSON, `.npmrc`, `.pypirc`
- SSH private keys left in the tree
- shell history and MCP configs (see `ka scan --deep`)

Pasting a key into chat is worse: it lives in the conversation (and often in
JSONL transcripts) forever.

key-amnesia stores values in an encrypted vault. Agents trigger
`ka run --cwd DIR --secret NAME --as NAME=ENVVAR -- <command>`; injection happens in the
child environment; scrubbed output comes back. `--as` must be
`NAME=ENVVAR` (or omit `--as` and inject under the secret name). Prefer
`--cwd` over `cd &&`. There is no
"get secret" API for the agent.

Find plaintext with:

```bash
ka scan
ka scan --no-import           # report only
ka scan --deep                # home/shell/MCP + agent session transcripts
ka scan --strict paranoid     # ≤0.4.9 assignment gate
```

The headline names the `--strict` gate and where the gated findings are:
`in this project`, or `on this machine, outside this project` when `--deep`
hits are only outside the tree (mixed: both counts). A three-count summary
(`N certain · N likely · N possible`) always follows, then the three gate
totals (`--strict certain` / `high` / `paranoid`). Only the listing and
exit follow `--strict`. Names, paths, and counts only — never values. After the
report you can store selected dotenv findings into a project vault (TTY
import path), or migrate known files with `ka import .env .env.local`.
`.gitignore` is filesystem policy, not cryptographic: it does not stop an
agent that can read the tree.
