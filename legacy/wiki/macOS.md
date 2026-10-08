# macOS

**Experimental** (0.4.0). Do **not** treat macOS as fully supported for
daily use. Neither the maintainer nor the usual reviewers own a Mac; treat
the visible Terminal.app window path as unconfirmed until a real Mac user
reports success.

## What works in CI

Unit tests on `macos-latest` cover the **PID-file wrapper** path with mocks:
`open` / `osascript` return immediately, so a short-lived launcher cannot be
waited on. The wrapper records its PID, then `exec`s the prompt helper; the
parent polls that PID file and uses the same parent-death / `poll` /
`terminate` semantics as Windows and Linux — without relying on the launcher
`Popen`.

## What is experimental

Opening a real Terminal.app window via `osascript` (`do script`) or
`open -a Terminal` and typing a password there. Headless / no-GUI sessions
still **fail closed** when the helper never records a PID.

## What is still fail-closed

- Other platforms (FreeBSD, etc.)
- **Kernel peer-identity admission on macOS** — unsupported today; when
  peer lookup returns `None`, guard admission **fails closed** (no
  unrecognized-peer fallback, no bearer-token revival). See
  [Guard and admission](Guard-and-admission).

Windows and Linux remain the supported platforms for daily use.
