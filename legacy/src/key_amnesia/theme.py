"""Branded CLI output helpers.

Palette (brushed chrome, retro-futurist restraint — one accent per state):
  chrome #AAC8E1  — info / success
  brass  #C8965A  — warn / prompt
  red    #D84444  — hard denials only
  slate  #94A0A8  — neutrals / non-denial errors

Respects NO_COLOR and non-TTY streams: never emits escapes when not a TTY
(agent parsing / scrubbing safety). Glyphs fall back to ASCII when unicode
or color is unsupported.

Scrubbed run relays and raw revealed secret values must NEVER go through
these helpers — keep those on plain sys.stdout/stderr.write.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any, TextIO

# --- palette -----------------------------------------------------------------

_CHROME = (170, 200, 225)  # #AAC8E1 — brushed chrome / polished steel-blue
_BRASS = (200, 150, 90)  # #C8965A — warm brass, retro-futurist accent
_RED = (216, 68, 68)  # #D84444 — warning-lamp red, hard denials only
_SLATE = (148, 160, 168)  # #94A0A8 — gunmetal neutral

# Approximate 256-color indices for the same hues
_CHROME_256 = 152
_BRASS_256 = 180
_RED_256 = 167
_SLATE_256 = 145

_RESET = "\033[0m"
_CSI_RE = re.compile(r"\033\[[0-9;]*m")

# Glyphs (unicode) / ASCII fallbacks
_OK_U, _OK_A = "✅", "[OK]"
_DENIED_U, _DENIED_A = "❌", "[DENIED]"
_LOCKED_U, _LOCKED_A = "🔒", "[LOCKED]"
_UNLOCKED_U, _UNLOCKED_A = "🔓", "[LISTENING]"
_EXPIRED_U, _EXPIRED_A = "⏳", "[EXPIRED]"
_CRASHED_U, _CRASHED_A = "💀", "[CRASHED]"

_VT_ENABLED = False


def _enable_windows_vt() -> None:
    """Best-effort enable ANSI VT processing on Windows consoles."""
    global _VT_ENABLED
    if _VT_ENABLED or sys.platform != "win32":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        enable = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        for std_id in (-11, -12):  # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
            handle = kernel32.GetStdHandle(std_id)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | enable)
        _VT_ENABLED = True
    except Exception:
        pass


def _no_color_env() -> bool:
    return bool(os.environ.get("NO_COLOR"))


def _stream_is_tty(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def color_enabled(stream: TextIO | None = None) -> bool:
    """True when ANSI color escapes may be emitted on *stream*."""
    if _no_color_env():
        return False
    target = stream if stream is not None else sys.stdout
    if not _stream_is_tty(target):
        return False
    _enable_windows_vt()
    return True


def _color_mode(stream: TextIO) -> str | None:
    """Return 'truecolor', '256', or None."""
    if not color_enabled(stream):
        return None
    colorterm = (os.environ.get("COLORTERM") or "").lower()
    if "truecolor" in colorterm or "24bit" in colorterm:
        return "truecolor"
    # Modern Windows Terminal / conhost VT: prefer truecolor
    if sys.platform == "win32" and (
        os.environ.get("WT_SESSION")
        or os.environ.get("TERM_PROGRAM") == "vscode"
        or _VT_ENABLED
    ):
        return "truecolor"
    term = (os.environ.get("TERM") or "").lower()
    if "256color" in term or term in ("xterm-kitty", "alacritty", "wezterm"):
        return "256"
    if term and term not in ("dumb",):
        return "256"
    return "truecolor"


def unicode_enabled(stream: TextIO | None = None) -> bool:
    """True when unicode glyphs are safe to emit on *stream*."""
    if not color_enabled(stream):
        # Plain / agent-facing paths: stick to ASCII for parseability
        return False
    target = stream if stream is not None else sys.stdout
    encoding = getattr(target, "encoding", None) or "utf-8"
    try:
        (
            _OK_U + _DENIED_U + _LOCKED_U + _UNLOCKED_U + _EXPIRED_U + _CRASHED_U
        ).encode(encoding)
        return True
    except (LookupError, UnicodeEncodeError):
        return False


def _fg(rgb: tuple[int, int, int], idx256: int, stream: TextIO) -> str:
    mode = _color_mode(stream)
    if mode is None:
        return ""
    if mode == "truecolor":
        r, g, b = rgb
        return f"\033[38;2;{r};{g};{b}m"
    return f"\033[38;5;{idx256}m"


def _paint(msg: str, rgb: tuple[int, int, int], idx256: int, stream: TextIO) -> str:
    prefix = _fg(rgb, idx256, stream)
    if not prefix:
        return msg
    return f"{prefix}{msg}{_RESET}"


def _glyph(kind: str, stream: TextIO) -> str:
    use_u = unicode_enabled(stream)
    if kind == "ok":
        return _OK_U if use_u else _OK_A
    if kind == "denied":
        return _DENIED_U if use_u else _DENIED_A
    if kind == "locked":
        return _LOCKED_U if use_u else _LOCKED_A
    if kind == "unlocked":
        return _UNLOCKED_U if use_u else _UNLOCKED_A
    if kind == "expired":
        return _EXPIRED_U if use_u else _EXPIRED_A
    if kind == "crashed":
        return _CRASHED_U if use_u else _CRASHED_A
    return ""


def _is_denial(msg: Any) -> bool:
    text = str(msg).lstrip()
    return text.lower().startswith("denied")


def _is_locked(msg: Any) -> bool:
    text = str(msg).lstrip()
    return text.lower().startswith("locked")


def _is_unlocked(msg: Any) -> bool:
    text = str(msg).lstrip()
    return text.lower().startswith("guard listening")


def _is_expired(msg: Any) -> bool:
    text = str(msg).lstrip()
    return "expired" in text.lower()


def _is_crashed(msg: Any) -> bool:
    text = str(msg).lstrip()
    return text.lower().startswith("guard crashed")


def _is_rule(msg: Any) -> bool:
    text = str(msg)
    return len(text) >= 3 and set(text) <= {"=", "─", "-", "═"}


def _emit(msg: Any, *, stream: TextIO, style: str | None = None, **kwargs: Any) -> None:
    text = "" if msg is None else str(msg)
    if style == "success":
        if _is_locked(text):
            g = _glyph("locked", stream)
        elif _is_unlocked(text):
            g = _glyph("unlocked", stream)
        else:
            g = _glyph("ok", stream)
        body = f"{g} {text}" if text else g
        text = _paint(body, _CHROME, _CHROME_256, stream)
    elif style == "info":
        if _is_rule(text):
            text = _paint(text, _SLATE, _SLATE_256, stream)
        else:
            text = _paint(text, _CHROME, _CHROME_256, stream)
    elif style == "warn":
        if _is_expired(text):
            g = _glyph("expired", stream)
            body = f"{g} {text}" if text else g
            text = _paint(body, _BRASS, _BRASS_256, stream)
        else:
            text = _paint(text, _BRASS, _BRASS_256, stream)
    elif style == "error":
        if _is_denial(text):
            g = _glyph("denied", stream)
            body = f"{g} {text}" if text else g
            text = _paint(body, _RED, _RED_256, stream)
        elif _is_crashed(text):
            g = _glyph("crashed", stream)
            body = f"{g} {text}" if text else g
            text = _paint(body, _RED, _RED_256, stream)
        else:
            text = _paint(text, _SLATE, _SLATE_256, stream)
    elif style == "detail":
        # Secondary/supplementary context — always dimmed, never accent, so
        # the primary message it's attached to keeps visual priority.
        text = _paint(text, _SLATE, _SLATE_256, stream)
    elif style == "out":
        # Neutrals — slate only for sparse rule lines; otherwise plain
        if _is_rule(text):
            text = _paint(text, _SLATE, _SLATE_256, stream)
    # style None / "err": plain (no accent)

    kwargs.setdefault("file", stream)
    try:
        print(text, **kwargs)
    except UnicodeEncodeError:
        # Stream encoding (e.g. a legacy non-UTF-8 Windows console codepage)
        # can't represent a character in caller-supplied text — degrade the
        # unencodable characters rather than crash the command outright.
        encoding = getattr(stream, "encoding", None) or "ascii"
        safe = text.encode(encoding, errors="replace").decode(encoding, errors="replace")
        print(safe, **kwargs)


def info(msg: Any = "", **kwargs: Any) -> None:
    stream = kwargs.pop("file", sys.stdout)
    _emit(msg, stream=stream, style="info", **kwargs)


def success(msg: Any = "", **kwargs: Any) -> None:
    stream = kwargs.pop("file", sys.stdout)
    _emit(msg, stream=stream, style="success", **kwargs)


def warn(msg: Any = "", **kwargs: Any) -> None:
    stream = kwargs.pop("file", sys.stderr)
    _emit(msg, stream=stream, style="warn", **kwargs)


def error(msg: Any = "", **kwargs: Any) -> None:
    stream = kwargs.pop("file", sys.stderr)
    _emit(msg, stream=stream, style="error", **kwargs)


def out(msg: Any = "", **kwargs: Any) -> None:
    stream = kwargs.pop("file", sys.stdout)
    _emit(msg, stream=stream, style="out", **kwargs)


def detail(msg: Any = "", **kwargs: Any) -> None:
    """Secondary/supplementary context (e.g. an auth prompt's detail line):
    always dimmed slate, never the primary accent color."""
    stream = kwargs.pop("file", sys.stdout)
    _emit(msg, stream=stream, style="detail", **kwargs)


def err(msg: Any = "", **kwargs: Any) -> None:
    stream = kwargs.pop("file", sys.stderr)
    _emit(msg, stream=stream, style=None, **kwargs)


# Test helpers (not part of the public CLI surface, but stable for unit tests)
def strip_csi(text: str) -> str:
    return _CSI_RE.sub("", text)
