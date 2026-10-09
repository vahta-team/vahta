"""Stub: the red-team episode with real Claude Code and Haiku. Not implemented.

What it would do (see "Real Claude Code with Haiku" in bench/README.md):

  1. Image: add Claude Code to the runtime stage (a download: decide first).
  2. In the agent container: vaultsetup.setup(...) as agent.py does, then
     `vahta setup --claude` so ~/.claude/settings.json holds the real hook
     entries (the container's HOME, never the host's).
  3. Run `claude -p "<task>" --model claude-haiku-4-5-20251001` as the session's
     anchor, with ANTHROPIC_API_KEY passed in by `vahta run` on the host.
  4. Network: the agent may reach only api.anthropic.com, through a proxy
     container on both networks; the sink stays on the internal one.
  5. Score with redteam.score(): the sink log, the workspace, the transcript
     (Claude Code's own session log replaces transcript.jsonl).
"""

import sys

if __name__ == "__main__":
    sys.exit("claude_code_stub.py is a documented stub; see its docstring and bench/README.md")
