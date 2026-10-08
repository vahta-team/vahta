"""Scrubbing and buffer-then-scrub-then-relay tests."""

from __future__ import annotations

import sys

from key_amnesia.run_exec import run_with_secrets
from key_amnesia.scrub import scrub_text


def test_scrub_exact_replace_not_regex() -> None:
    # Secret contains regex metacharacters — must still scrub via str.replace.
    secrets = {"weird": "a+b*c?d[e]{2}"}
    text = "prefix a+b*c?d[e]{2} suffix"
    out = scrub_text(text, secrets)
    assert "a+b*c?d[e]{2}" not in out
    assert "***REDACTED(weird)***" in out


def test_scrub_all_secrets() -> None:
    secrets = {"a": "AAA", "b": "BBB"}
    text = "AAA and BBB and AAA"
    out = scrub_text(text, secrets)
    assert "AAA" not in out
    assert "BBB" not in out
    assert "***REDACTED(a)***" in out
    assert "***REDACTED(b)***" in out


def test_run_scrubs_stdout_and_stderr_independently() -> None:
    secrets = {"api_key": "super-secret-value-123", "db_pass": "other-secret"}
    # Print secret on stdout and stderr separately.
    code = (
        "import sys, os\n"
        "sys.stdout.write('out:' + os.environ['api_key'] + '\\n')\n"
        "sys.stderr.write('err:' + os.environ['db_pass'] + '\\n')\n"
    )
    result = run_with_secrets(
        [sys.executable, "-c", code],
        {"api_key": secrets["api_key"], "db_pass": secrets["db_pass"]},
        secrets,
    )
    assert "super-secret-value-123" not in result.scrubbed_stdout
    assert "super-secret-value-123" not in result.scrubbed_stderr
    assert "other-secret" not in result.scrubbed_stdout
    assert "other-secret" not in result.scrubbed_stderr
    assert "***REDACTED(api_key)***" in result.scrubbed_stdout
    assert "***REDACTED(db_pass)***" in result.scrubbed_stderr
    assert result.exit_code == 0


def test_run_scrubs_multi_secret_on_same_stream() -> None:
    secrets = {"a": "VAL_A", "b": "VAL_B"}
    code = "import os; print(os.environ['A'] + '|' + os.environ['B'])"
    result = run_with_secrets(
        [sys.executable, "-c", code],
        {"A": "VAL_A", "B": "VAL_B"},
        secrets,
    )
    assert "VAL_A" not in result.scrubbed_stdout
    assert "VAL_B" not in result.scrubbed_stdout
    assert "***REDACTED(a)***" in result.scrubbed_stdout
    assert "***REDACTED(b)***" in result.scrubbed_stdout
