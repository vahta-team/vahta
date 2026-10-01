"""Where ``json.loads`` is odd, the transcript scan must be odd the same way.

A transcript line the scanner parses and Python rejects (or the reverse) is a
secret never looked at, or a finding Python would not report. Each case here is
a hazard where a hand-written JSON parser would plausibly differ from CPython's;
they run against whichever implementation is active, so the same assertions pin
the Python spec and the Rust port. ``benchmarks/diff_transcripts.py`` compares
the two on generated input; this file is the human-readable list.

Credential-shaped values are assembled at run time from pieces.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from key_amnesia.scan import _findings_for_transcript

_NAME = "API" + "_KEY"
_VALUE = "aB3xQ9" + "mK2pL7" + "vN4wZ8"


def _scan(tmp_path: Path, data: bytes | str, **kw):
    p = tmp_path / "t.jsonl"
    p.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
    return _findings_for_transcript(p, scope="deep", **kw)


def _hit_lines(findings) -> list[int]:
    return sorted(n for f in findings for n in f.hit_lines)


def _assign(extra: str = "") -> str:
    """A line holding one likely assignment, plus `extra` JSON members."""
    return '{"text": "%s=%s"%s}' % (_NAME, _VALUE, extra)


def test_the_assignment_line_alone_is_found(tmp_path) -> None:
    assert _hit_lines(_scan(tmp_path, _assign() + "\n")) == [1]


@pytest.mark.parametrize("extra", [', "n": NaN', ', "n": Infinity', ', "n": -Infinity', ', "n": 1e999'])
def test_nan_infinity_and_overflowing_floats_parse(tmp_path, extra) -> None:
    assert _hit_lines(_scan(tmp_path, _assign(extra) + "\n")) == [1]


@pytest.mark.parametrize(
    "line",
    [
        '{"text": "%s=%s",}' % (_NAME, _VALUE),  # trailing comma
        "{'text': '%s=%s'}" % (_NAME, _VALUE),  # single quotes
        '{"text": "%s=%s"} // comment' % (_NAME, _VALUE),
        '/* c */ {"text": "%s=%s"}' % (_NAME, _VALUE),
        '{"text": "%s=%s"}}' % (_NAME, _VALUE),  # extra data
        '{"text": "%s=%s"' % (_NAME, _VALUE),  # unterminated
        '{"text": "%s=%s", "n": 01}' % (_NAME, _VALUE),  # leading zero
        '{"text": "%s=%s", "n": 1.}' % (_NAME, _VALUE),
        '{"text": "%s=%s", "n": +1}' % (_NAME, _VALUE),
        '{"text": "%s=%s", "n": nan}' % (_NAME, _VALUE),
        '{"text": "%s=%s\t"}' % (_NAME, _VALUE),  # raw control character in a string
        '{"text": "%s=%s", "n": "\\x41"}' % (_NAME, _VALUE),  # invalid escape
    ],
)
def test_what_python_rejects_is_skipped(tmp_path, line) -> None:
    assert _scan(tmp_path, line + "\n") == []


def test_only_four_whitespace_characters_separate_json_tokens(tmp_path) -> None:
    # Inside the line, tab/CR/LF/space are fine; a vertical tab is not.
    assert _hit_lines(_scan(tmp_path, '{"text":\t"%s=%s"\t,\t"n":\t1}\n' % (_NAME, _VALUE))) == [1]
    assert _scan(tmp_path, '{"text":\x0b"%s=%s"}\n' % (_NAME, _VALUE)) == []


def test_unicode_whitespace_around_a_line_is_stripped_before_parsing(tmp_path) -> None:
    # str.strip() removes NBSP, U+2028, VT, FF, U+3000 ... so these parse.
    line = _assign()
    data = "\xa0" + line + " \n\x0b" + line + "\x0c\n　" + line + "　\n"
    assert _hit_lines(_scan(tmp_path, data)) == [1, 2, 3]


def test_a_byte_order_mark_spoils_only_the_line_it_precedes(tmp_path) -> None:
    line = _assign()
    assert _hit_lines(_scan(tmp_path, "﻿" + line + "\n" + line + "\n")) == [2]


def test_lone_cr_ends_a_line_and_other_separators_do_not(tmp_path) -> None:
    line = _assign()
    assert _hit_lines(_scan(tmp_path, line + "\r" + line + "\r\n" + line + "\n")) == [1, 2, 3]
    # U+2028 / VT / FF / FS are not line breaks to a file iterator.
    glued = line + " " + line  # one line, two documents: not JSON
    assert _scan(tmp_path, glued + "\n") == []


def test_invalid_utf8_is_replaced_not_fatal(tmp_path) -> None:
    line = _assign().encode()
    data = b"\xff\xfe\n" + line + b"\n" + b'{"t": "\xc0\xaf \xed\xa0\x80 \xf0\x9f\x92"}\n' + line + b"\n"
    assert _hit_lines(_scan(tmp_path, data)) == [2, 4]


def test_duplicate_keys_the_last_value_wins(tmp_path) -> None:
    key = _NAME.lower()
    hidden = '{"%s": "%s", "%s": "short"}\n' % (key, _VALUE, key)
    shown = '{"%s": "short", "%s": "%s"}\n' % (key, key, _VALUE)
    assert _scan(tmp_path, hidden) == []
    assert _hit_lines(_scan(tmp_path, shown)) == [1]


def test_lone_surrogate_escapes_are_accepted_and_scanned(tmp_path) -> None:
    key = _NAME.lower()
    for value in (_VALUE + "\\ud800", "\\udc00" + _VALUE, _VALUE[:6] + "\\udbff" + _VALUE[6:]):
        assert _hit_lines(_scan(tmp_path, '{"%s": "%s"}\n' % (key, value))) == [1], value
    # A surrogate *pair* is one astral character, and does not break the line.
    pair = '{"%s": "%s\\ud83d\\ude00"}\n' % (key, _VALUE)
    assert _hit_lines(_scan(tmp_path, pair)) == [1]
    # A malformed escape right after a high surrogate invalidates the line.
    assert _scan(tmp_path, '{"%s": "%s\\ud800\\u12"}\n' % (key, _VALUE)) == []


def test_json_inside_a_string_is_unwrapped_once(tmp_path) -> None:
    inner = json.dumps({_NAME.lower(): _VALUE})
    assert _hit_lines(_scan(tmp_path, json.dumps({"content": inner}) + "\n")) == [1]
    # Wrapped twice: the second layer is only text, so there is no key to see.
    twice = json.dumps({"content": json.dumps({"deeper": inner})})
    findings = _scan(tmp_path, twice + "\n")
    assert all(f.hit_lines in ([], [1]) for f in findings)


def test_non_container_json_strings_are_scanned_as_text(tmp_path) -> None:
    assert _hit_lines(_scan(tmp_path, json.dumps({"c": "[1, 2] %s=%s" % (_NAME, _VALUE)}) + "\n")) == [1]


def test_progress_ticks_every_2000_lines_with_name_and_zero(tmp_path) -> None:
    calls: list[tuple] = []
    _scan(tmp_path, '{"t": "ok"}\n' * 4100, progress=lambda *a: calls.append(a))
    assert calls == [("t.jsonl", 2000, 0), ("t.jsonl", 4000, 0)]


def test_progress_exceptions_propagate(tmp_path) -> None:
    def boom(*_a):
        raise KeyError("stop")

    with pytest.raises(KeyError):
        _scan(tmp_path, '{"t": "ok"}\n' * 2001, progress=boom)


def test_nesting_past_the_recursion_limit_raises_rather_than_skips(tmp_path) -> None:
    """Not a JSONDecodeError, so Python's caller does not catch it.

    Uncaught, one such line aborts the whole ``--deep`` scan. The Rust port
    reproduces that instead of quietly skipping the line.
    """
    findings = _scan(tmp_path, "[" * 300 + "]" * 300 + "\n" + _assign() + "\n")
    assert _hit_lines(findings) == [2]
    with pytest.raises(RecursionError):
        _scan(tmp_path, _assign() + "\n" + "[" * 3000 + "]" * 3000 + "\n")
    with pytest.raises(RecursionError):
        _scan(tmp_path, json.dumps({"a": "[" * 3000 + "]" * 3000}) + "\n")


def test_integers_over_4300_digits_raise_value_error(tmp_path) -> None:
    assert _scan(tmp_path, "[" + "9" * 4300 + "]\n") == []
    with pytest.raises(ValueError):
        _scan(tmp_path, "[" + "9" * 4301 + "]\n")
    with pytest.raises(ValueError):
        _scan(tmp_path, json.dumps({"a": "[" + "9" * 4301 + "]"}) + "\n")
    # Floats have no such limit, and a syntax error earlier on the line wins.
    assert _scan(tmp_path, "[" + "9" * 4301 + ".5]\n") == []
    assert _scan(tmp_path, "[x, " + "9" * 4301 + "]\n") == []


def test_scalars_and_garbage_lines_are_skipped(tmp_path) -> None:
    assert _scan(tmp_path, '42\n"just text"\nnull\n[]\n{}\nnot json\n\n   \n') == []
