# Wiki drafts (GitHub Wiki publish)

These markdown files are **first drafts** for the live GitHub wiki at
[https://github.com/vahta-team/vahta/wiki](https://github.com/vahta-team/vahta/wiki).

**Docs as of 0.4.15** — in-repo wording targets that release. Live wiki last
published for 0.4.5 (0.4.6–0.4.9 had no wiki republish; bump when republishing).


They are kept in-repo so PRs can review IA and wording before (or instead of)
pushing to the separate wiki git remote. `ka docs` always opens/prints that
wiki URL — not these paths.

## Publish

Option A — copy pages into the wiki remote:

```bash
git clone https://github.com/vahta-team/vahta.wiki.git
# copy *.md from this directory (except this README.md) into the clone
# commit + push on the wiki repo
```

Option B — treat this tree as the source of truth and sync periodically.

GitHub wiki page titles come from filenames (`Home.md` → Home,
`Why-not-dotenv.md` → Why not dotenv). `_Sidebar.md` renders the left nav.

**Never copy this `README.md` into the wiki publish set** — it is
maintainer publish instructions only.

After a successful publish, update the “last published” note here (still
keep docs-as-of version accurate). Last published: 0.4.5.

## Proposed IA

| Page | Purpose |
|------|---------|
| [Home](Home.md) | Pitch + 30s path + TOC; docs as of version |
| [Why-not-dotenv](Why-not-dotenv.md) | `.env` / LEAK framing |
| [Install](Install.md) | pip, `ka setup`, agent bootstrap |
| [Quickstart-migration](Quickstart-migration.md) | `ka import` → `ka scan` → `ka run` |
| [Agent-usage](Agent-usage.md) | Agent-first path; status/list first; human-only |
| [Project-vaults](Project-vaults.md) | `.amnesia/`, merge, `--env` |
| [Manifest-and-check](Manifest-and-check.md) | `amnesia.toml`, `ka check`, CI |
| [Guard-and-admission](Guard-and-admission.md) | unlock, peer identity, pre-admit |
| [Commands](Commands.md) | Command reference skeleton |
| [Roles-and-export](Roles-and-export.md) | KAM2 / export — **needs maintainer judgement** |
| [Threat-model](Threat-model.md) | Limits + policy vs crypto — **needs maintainer judgement** |
| [macOS](macOS.md) | Experimental Terminal.app / PID-file spawn (0.4.0) |

## Maintainer judgement flags

Do **not** treat Roles-and-export or Threat-model as final public wording until
a human maintainer reviews policy-vs-crypto labels (especially runner =
policy vs human / effective vs agent, Windows peer identity strength, and
admin signature = tamper-evident only).
