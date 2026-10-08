"""Clipboard helper for `copy` (interactive / helper window only)."""

from __future__ import annotations


def copy_to_clipboard(text: str) -> None:
    import pyperclip

    pyperclip.copy(text)
