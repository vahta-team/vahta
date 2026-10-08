# Agent skills — moved

The `key-amnesia-usage`, `key-amnesia-hygiene`, and `key-amnesia-migrate` skills are now packaged inside `key_amnesia` itself (`src/key_amnesia/skills/*/SKILL.md`) instead of living here as a separate root-level copy.

Install them for Claude Code / Cursor / Codex / OpenCode with:

```bash
ka setup
```

This copies the current package version of each `SKILL.md` to
`~/.claude/skills/`, `~/.cursor/skills/`, `~/.agents/skills/` (Codex), and
`~/.codex/skills/` (legacy Codex / `$CODEX_HOME`). OpenCode auto-loads the
copies under `~/.claude/skills` and `~/.agents/skills`. There is now exactly
one canonical copy of each skill (inside the installed package); this
directory is a pointer only.
