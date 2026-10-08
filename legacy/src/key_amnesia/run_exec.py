"""Buffer-then-scrub-then-relay command execution."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Mapping

from key_amnesia.scrub import scrub_text


@dataclass
class RunResult:
    exit_code: int
    scrubbed_stdout: str
    scrubbed_stderr: str


def run_with_secrets(
    command: list[str],
    env_inject: Mapping[str, str],
    secrets_by_name: Mapping[str, str],
    cwd: str | None = None,
) -> RunResult:
    """Run a command with injected env, fully buffer stdout/stderr, scrub, relay.

    No streaming. Each stream is decoded once, scrubbed independently with
    *all* injected secret values, then returned.
    """
    env = os.environ.copy()
    env.update(dict(env_inject))
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=env,
    )
    raw_out, raw_err = proc.communicate()
    exit_code = proc.returncode if proc.returncode is not None else -1

    # Decode each stream once at the end.
    stdout_text = raw_out.decode("utf-8", errors="replace")
    stderr_text = raw_err.decode("utf-8", errors="replace")

    secrets = dict(secrets_by_name)
    scrubbed_stdout = scrub_text(stdout_text, secrets)
    scrubbed_stderr = scrub_text(stderr_text, secrets)

    return RunResult(
        exit_code=exit_code,
        scrubbed_stdout=scrubbed_stdout,
        scrubbed_stderr=scrubbed_stderr,
    )
