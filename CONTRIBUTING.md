# Contributing

## Setup

```bash
pip install -e ".[dev]"
```

Requires Python 3.10+.

## Tests

CI runs the same command on Windows, Ubuntu, and macOS (Python 3.10 and 3.13):

```bash
pytest -q
```

Optional marker: `@pytest.mark.slow` for heavy process-spawning tests. Skip with `pytest -q -m "not slow"` for a faster local loop.

There is no separate linter job in CI today — keep changes consistent with surrounding code.

## Pull requests

- Prefer a focused PR with a short description of *why*.
- Branch names in this repo usually look like `feat/…`, `fix/…`, `docs/…`, or `chore/…`.
- Keep the suite green (`pytest -q`).
- Do not paste secret values into issues, PRs, or commit messages.
- A merged PR's branch is deleted automatically. To keep one, name it
  `keep/...` when you create it, or add the label `keep-branch` to the PR
  before it merges. A branch that another open PR targets is always kept.

## Security issues

Report vulnerabilities through [SECURITY.md](SECURITY.md) (GitHub private vulnerability reporting). Do not open a public issue for security reports.
