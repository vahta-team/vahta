"""cp1252 console regression for --help across every subcommand.

v2 shipped a crash: `login`'s help text contained a unicode arrow (`->`)
that raised UnicodeEncodeError on a legacy Windows console codepage
(cp1252). `login` is gone in 0.3.0, but this walks the *entire* parser tree
(root + every `_SubParsersAction` choice) so any future non-ASCII help /
description string trips the same regression test instead of shipping.
"""

from __future__ import annotations

import argparse

from key_amnesia.cli import _build_parser


class _FakeCp1252Console:
    """Writable stream that actually enforces a legacy codepage encoding.

    Mirrors a real Windows console using cp1252: raises UnicodeEncodeError
    on any character the codepage can't represent — exactly like the crash
    this simulates.
    """

    encoding = "cp1252"

    def __init__(self) -> None:
        self._chunks: list[bytes] = []

    def isatty(self) -> bool:
        return False

    def write(self, s: str) -> int:
        self._chunks.append(s.encode(self.encoding))  # raises on unencodable chars
        return len(s)

    def flush(self) -> None:
        pass

    def getvalue(self) -> str:
        return b"".join(self._chunks).decode(self.encoding)


def _iter_parsers(parser: argparse.ArgumentParser):
    """Yield *parser* and every subparser reachable from its actions."""
    yield parser
    for action in parser._actions:  # noqa: SLF001 — argparse has no public walk API
        choices = getattr(action, "choices", None)
        if not isinstance(choices, dict):
            continue
        for sub in choices.values():
            if isinstance(sub, argparse.ArgumentParser):
                yield from _iter_parsers(sub)


def test_all_help_renders_on_cp1252_console() -> None:
    """format_help() for the root parser and every subparser must be pure
    ASCII-safe enough to write to a cp1252 console without raising."""
    root = _build_parser()
    parsers = list(_iter_parsers(root))
    # Sanity: we actually walked into subparsers (init/set/run/config/... plus
    # config's own show/set nested subparsers).
    assert len(parsers) > 10

    console = _FakeCp1252Console()
    for parser in parsers:
        text = parser.format_help()
        console.write(text)  # must not raise UnicodeEncodeError
