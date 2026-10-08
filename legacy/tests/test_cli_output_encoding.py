"""Regression: relaying scrubbed command output must never crash on a
console codepage (e.g. legacy Windows cp1252) that can't represent one of
its characters.

Found live while publishing to PyPI: twine's own stdout contained a
character cp1252 couldn't encode, and `ka run` crashed with a raw
UnicodeEncodeError from `sys.stdout.write(...)` — *after* the underlying
command (the actual upload) had already succeeded, hiding that success
behind a traceback instead of just showing degraded text like theme.py
already does for its own output.
"""

from __future__ import annotations

from key_amnesia.cli import _write_command_output, main


class _FakeCp1252Stream:
    encoding = "cp1252"

    def __init__(self) -> None:
        self._chunks: list[bytes] = []

    def write(self, s: str) -> int:
        self._chunks.append(s.encode(self.encoding))  # raises on unencodable chars
        return len(s)

    def getvalue(self) -> str:
        return b"".join(self._chunks).decode(self.encoding)


def test_write_command_output_degrades_instead_of_crashing() -> None:
    stream = _FakeCp1252Stream()
    _write_command_output(stream, "Uploading key-amnesia-0.3.2 � done\n")
    out = stream.getvalue()
    assert "Uploading key-amnesia-0.3.2" in out
    assert "done" in out


def test_write_command_output_passes_through_encodable_text_unchanged() -> None:
    stream = _FakeCp1252Stream()
    _write_command_output(stream, "plain ascii output\n")
    assert stream.getvalue() == "plain ascii output\n"


def test_guard_run_path_does_not_crash_on_unencodable_output(monkeypatch) -> None:
    """End-to-end: `ka run` against a live guard must survive output the
    console codepage can't represent, not crash after the command already
    succeeded."""
    from key_amnesia import cli as cli_mod
    from key_amnesia import guard as guard_mod

    monkeypatch.setattr(guard_mod, "guard_is_alive", lambda *a, **k: True)
    monkeypatch.setattr(
        guard_mod,
        "guard_request",
        lambda *a, **k: {
            "ok": True,
            "scrubbed_stdout": "Uploading � done\n",
            "scrubbed_stderr": "",
            "exit_code": 0,
        },
    )
    stream = _FakeCp1252Stream()
    monkeypatch.setattr(cli_mod.sys, "stdout", stream)

    rc = main(["run", "--secret", "x", "--as", "x=X", "--", "true"])

    assert rc == 0
    assert "Uploading" in stream.getvalue()
