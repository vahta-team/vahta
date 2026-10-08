"""`ka docs`: print wiki URL; best-effort browser open; never fail on open."""

from __future__ import annotations

from argparse import Namespace
from unittest.mock import patch

import pytest

from key_amnesia.cli import DOCS_URL, cmd_docs, main


def test_docs_url_is_standard_wiki() -> None:
    assert DOCS_URL == "https://github.com/vahta-team/vahta/wiki"


def test_docs_print_only_skips_browser(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("key_amnesia.cli.webbrowser.open") as open_browser:
        rc = cmd_docs(Namespace(print_only=True))
    assert rc == 0
    open_browser.assert_not_called()
    assert capsys.readouterr().out.strip() == DOCS_URL


def test_docs_opens_browser_by_default(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("key_amnesia.cli.webbrowser.open", return_value=True) as open_browser:
        rc = cmd_docs(Namespace(print_only=False))
    assert rc == 0
    open_browser.assert_called_once_with(DOCS_URL)
    assert capsys.readouterr().out.strip() == DOCS_URL


def test_docs_open_failure_still_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("key_amnesia.cli.webbrowser.open", side_effect=OSError("no browser")):
        rc = cmd_docs(Namespace(print_only=False))
    assert rc == 0
    assert capsys.readouterr().out.strip() == DOCS_URL


def test_docs_main_print_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("key_amnesia.cli.webbrowser.open") as open_browser:
        rc = main(["docs", "--print"])
    assert rc == 0
    open_browser.assert_not_called()
    assert capsys.readouterr().out.strip() == DOCS_URL


def test_docs_does_not_touch_vault(tmp_path, monkeypatch, capsys) -> None:
    """docs must work with no vault home and no password."""
    monkeypatch.setenv("KEY_AMNESIA_HOME", str(tmp_path / "missing-home"))
    with patch("key_amnesia.cli.webbrowser.open"):
        rc = main(["docs", "--print"])
    assert rc == 0
    assert (tmp_path / "missing-home").exists() is False
    assert capsys.readouterr().out.strip() == DOCS_URL
