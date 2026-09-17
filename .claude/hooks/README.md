# Claude Code hooks — moved

The PreToolUse secret-guard hook is now packaged inside `key_amnesia` itself (`src/key_amnesia/hooks/secret_guard.py`) instead of living here as a separate root-level copy.

Install it (and the agent skills) with:

```bash
ka setup
```

This merges a `PreToolUse` entry into `~/.claude/settings.json`, a
`preToolUse` entry into `~/.cursor/hooks.json` for Cursor, and a `PreToolUse`
entry into `~/.codex/hooks.json` for Codex that runs the `key-amnesia-hook`
console script. OpenCode gets a JS bridge plugin under
`~/.config/opencode/plugins/` (skills auto-load; nothing extra to copy).
There is now exactly one canonical copy of the hook (inside the installed
package); this directory is a pointer only.
