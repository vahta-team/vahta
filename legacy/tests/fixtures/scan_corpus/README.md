# Scan corpus

Labeled synthetic *shapes* for the shared detector in `key_amnesia.detect`.
No harvested transcripts. No live keys. Tests must never print fixture values.

## Categories

**`negatives/`** — not credentials. Scan default `leak_count` (`--strict high`)
must be 0. Classifier must not return `likely` or `prefix`. May be `none`
(function-call, type annotation, placeholder) or `possible` (camelCase
identifiers the hook still denies). The label means “must not be certain or
likely,” not “the hook allows.”

**`demoted/`** — plausible credentials **intentionally** classified below
`likely` (named weakenings: word-shaped passphrase, low-transition, and
unconfirmed `mcp.json` shape). Must be `possible`, not `none`, not `likely`.
The hook still denies value-shaped demotions. Not in default `leak_count`.
`--strict paranoid` is the CI opt-in (the ≤0.4.9 assignment gate). Every
named weakening has a fixture here or in `negatives/` (function-call and
type-annotation are `none`). `uuid` is generated at test time, not committed.
Expected field shape (docs only, no live tree): 1 certain dotenv + 2 possible
unconfirmed-mcp.

**`positives/`** — on-disk prefix samples only, constructed like
`KNOWN_PREFIX_SAMPLES` (repeated `a` / `0`). Must classify as `prefix` /
certain. Stripe `sk_live_` / `rk_live_` prefixes are **not** on disk: GitHub
push protection flags even the repeated-`a` construction. Cover them in
hook tests via concatenation. Unprefixed `likely` values are **generated at
test time** into pytest tmp (`.env` / JSON / YAML / TOML / `export` / UUID),
not committed, so GitHub secret scanning does not block the PR.

## Order

A “before” measurement using the 0.4.9 assignment heuristic is recorded in
`tests/test_scan_corpus.py`. Thresholds were frozen only after that.
