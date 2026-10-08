# Contributing

## Setup

Vahta is a Rust workspace (`crates/`). Install [rustup](https://rustup.rs/); the
toolchain, 1.99, is pinned in `rust-toolchain.toml` and is fetched on the first
`cargo` command, together with `rustfmt` and `clippy`.

```bash
git clone https://github.com/vahta-team/vahta.git
cd vahta
cargo build --workspace
```

`scripts/install-local.sh` builds and installs the binaries for daily use.

## Checks

CI runs these three on Linux, macOS and Windows; run them before you push:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

A change under `crates/rules/` also runs that crate's rule tests in CI
(`cargo test -p vahta-rules`).

## Tests

- **Never write a secret-shaped literal** in a test, a doc or a fixture. Build it
  from pieces at run time (`["prefix", "_", "..."].concat()`); repository tests
  fail the build if a committed file reads as a key.
- **Tests never touch the real HOME.** Point `HOME`, the config, data and runtime
  directories at a temporary directory. A test must not read or write a real
  vault, journal or harness settings file.
- The vault tests run the real KDF and are slow in a debug build; the crypto
  crates are optimised in the dev profile for that reason.

`legacy/` is the Python key-amnesia, kept for reference. It is not built or tested
here; changes to it belong on `master`.

## Pull requests

- Prefer a focused PR with a short description of *why*.
- Branch names in this repo usually look like `feat/…`, `fix/…`, `docs/…`, or `chore/…`.
- Keep format, clippy and the tests green.
- Do not paste secret values into issues, PRs, or commit messages.
- A merged PR's branch is deleted automatically. To keep one, name it
  `keep/...` when you create it, or add the label `keep-branch` to the PR
  before it merges. A branch that another open PR targets is always kept.

## Security issues

Report vulnerabilities through [SECURITY.md](SECURITY.md) (GitHub private vulnerability reporting). Do not open a public issue for security reports.
