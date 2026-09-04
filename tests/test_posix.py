"""Linux isolated-console spawn: emulator choice, env handoff, fail-closed."""

from __future__ import annotations

import io
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

from key_amnesia.platform import (
    _INSTALLABLE_EMULATORS,
    _LINUX_EMULATORS,
    _pkg_install_command,
    spawn_isolated_console,
)

_EMULATOR_NAMES = tuple(name for name, _, _ in _LINUX_EMULATORS)


HELPER_ARGV = [sys.executable, "-m", "key_amnesia", "_prompt-helper"]
SENSITIVE_ENV = {
    "PATH": "/usr/bin",
    "KEY_AMNESIA_PROMPT_REQUEST": '{"action":"reveal","secret_names":["api_key"]}',
    "KEY_AMNESIA_PROMPT_AUTHKEY": "a" * 64,
    "KEY_AMNESIA_PROMPT_ADDRESS": "/tmp/key-amnesia-test.sock",
    "DISPLAY": ":0",
}


def _fake_which(available: dict[str, str]):
    def which(name: str) -> str | None:
        return available.get(name)

    return which


class _FakeTTY(io.StringIO):
    """Controlling-tty double: scripted readline answers + captured writes."""

    def __init__(self, answers: list[str]):
        super().__init__()
        self._answers = list(answers)
        self.writes: list[str] = []

    def write(self, s: str) -> int:
        self.writes.append(s)
        return super().write(s)

    def readline(self, *args: Any, **kwargs: Any) -> str:  # noqa: ARG002
        if not self._answers:
            return "\n"
        return self._answers.pop(0) + "\n"

    def isatty(self) -> bool:
        return True

    def close(self) -> None:
        # Leave buffer readable for assertions after the offer closes the tty.
        pass

    @property
    def text(self) -> str:
        return "".join(self.writes)


@pytest.fixture(autouse=True)
def _no_poll_delay(monkeypatch):
    """Skip the real post-spawn liveness pause so this suite stays fast."""
    monkeypatch.setattr("key_amnesia.platform._POLL_DELAY_S", 0)


@pytest.fixture(autouse=True)
def _neutral_terminal_env(monkeypatch):
    """The developer's own terminal must not decide what these tests assert."""
    monkeypatch.delenv("KEY_AMNESIA_TERMINAL", raising=False)
    monkeypatch.delenv("TERMINAL", raising=False)
    monkeypatch.delenv("XDG_CURRENT_DESKTOP", raising=False)


def test_linux_prefers_named_terminal_over_alternatives_symlink(monkeypatch) -> None:
    """A named terminal beats x-terminal-emulator.

    The symlink may resolve to gnome-terminal, whose -e is deprecated and
    takes a single string; invoking the real binary with -- is always safer.
    """
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(
        "key_amnesia.platform.shutil.which",
        _fake_which(
            {
                "x-terminal-emulator": "/usr/bin/x-terminal-emulator",
                "gnome-terminal": "/usr/bin/gnome-terminal",
                "xterm": "/usr/bin/xterm",
            }
        ),
    )
    captured: dict[str, Any] = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        proc = MagicMock()
        proc.poll.return_value = None  # still running
        return proc

    spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=fake_popen)

    cmd = captured["cmd"]
    assert cmd[0] == "/usr/bin/gnome-terminal"
    assert cmd[1] == "--"
    assert cmd[2:] == HELPER_ARGV
    assert "_prompt-helper" in cmd
    joined = " ".join(cmd)
    assert "api_key" not in joined
    assert "authkey" not in joined.lower()
    assert "a" * 64 not in joined

    kwargs = captured["kwargs"]
    assert "stdin" not in kwargs
    assert "stdout" not in kwargs
    assert "stderr" not in kwargs
    assert kwargs["env"]["KEY_AMNESIA_PROMPT_AUTHKEY"] == "a" * 64
    assert kwargs["env"]["KEY_AMNESIA_PROMPT_REQUEST"]


def test_linux_falls_through_to_gnome_terminal(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.setattr(
        "key_amnesia.platform.shutil.which",
        _fake_which({"gnome-terminal": "/usr/bin/gnome-terminal"}),
    )
    captured: dict[str, Any] = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        proc = MagicMock()
        proc.poll.return_value = None  # still running
        return proc

    spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=fake_popen)

    assert captured["cmd"] == [
        "/usr/bin/gnome-terminal",
        "--",
        *HELPER_ARGV,
    ]


def test_linux_konsole_and_xterm_wiring(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("DISPLAY", ":1")

    for name, path in (
        ("konsole", "/usr/bin/konsole"),
        ("xterm", "/usr/bin/xterm"),
    ):
        monkeypatch.setattr(
            "key_amnesia.platform.shutil.which",
            _fake_which({name: path}),
        )
        captured: dict[str, Any] = {}

        def fake_popen(cmd, **kwargs):
            captured["cmd"] = cmd
            proc = MagicMock()
            proc.poll.return_value = None  # still running
            return proc

        spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=fake_popen)
        assert captured["cmd"] == [path, "-e", *HELPER_ARGV]


def test_linux_emulator_exits_immediately_falls_through(monkeypatch) -> None:
    """A found emulator that dies right after spawn is not reported as success."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(
        "key_amnesia.platform.shutil.which",
        _fake_which(
            {
                "x-terminal-emulator": "/usr/bin/x-terminal-emulator",
                "gnome-terminal": "/usr/bin/gnome-terminal",
            }
        ),
    )
    captured: dict[str, Any] = {"cmds": []}

    def fake_popen(cmd, **kwargs):
        captured["cmds"].append(cmd)
        proc = MagicMock()
        if cmd[0] == "/usr/bin/gnome-terminal":
            proc.poll.return_value = 1  # exited immediately (bad flag / broken alias)
        else:
            proc.poll.return_value = None  # the next candidate stays running
        return proc

    result = spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=fake_popen)

    assert [c[0] for c in captured["cmds"]] == [
        "/usr/bin/gnome-terminal",
        "/usr/bin/x-terminal-emulator",
    ]
    assert result.poll() is None


def test_linux_all_emulators_exit_immediately_fail_closed(monkeypatch) -> None:
    """If every found emulator dies right after spawn, fail closed with a clear reason."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(
        "key_amnesia.platform.shutil.which",
        _fake_which({"xterm": "/usr/bin/xterm"}),
    )

    def fake_popen(cmd, **kwargs):
        proc = MagicMock()
        proc.poll.return_value = 1  # exited immediately
        return proc

    with pytest.raises(OSError, match="none stayed running|Fail closed"):
        spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=fake_popen)


def test_linux_headless_fail_closed(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)

    with pytest.raises(OSError, match="DISPLAY/WAYLAND_DISPLAY|Fail closed"):
        spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=MagicMock())


def test_linux_no_emulator_tty_unavailable_fail_closed(monkeypatch) -> None:
    """No emulator + no /dev/tty → identical fail-closed (no offer attempted)."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(
        "key_amnesia.platform.shutil.which",
        _fake_which({}),
    )
    monkeypatch.setattr("key_amnesia.platform._open_controlling_tty", lambda: None)

    with pytest.raises(OSError, match="terminal emulator|Fail closed"):
        spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=MagicMock())


def test_linux_no_emulator_decline_install_fail_closed(monkeypatch) -> None:
    """User declines Install one now? → same OSError as today."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(
        "key_amnesia.platform.shutil.which",
        _fake_which({}),
    )
    tty = _FakeTTY(answers=["n"])
    monkeypatch.setattr("key_amnesia.platform._open_controlling_tty", lambda: tty)

    with pytest.raises(OSError, match="terminal emulator|Fail closed"):
        spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=MagicMock())

    assert "Install one now?" in tty.text
    assert "No suitable terminal emulator found" in tty.text


def test_linux_no_emulator_retry_still_empty_fail_closed(monkeypatch) -> None:
    """Accept offer + menu + retry, second scan still empty → OSError (one offer only)."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(
        "key_amnesia.platform.shutil.which",
        _fake_which({"apt": "/usr/bin/apt"}),
    )
    # y → pick xterm (4) → Enter after install → y retry; which never finds emulators
    tty = _FakeTTY(answers=["y", str(_INSTALLABLE_EMULATORS.index("xterm") + 1), "", "y"])
    monkeypatch.setattr("key_amnesia.platform._open_controlling_tty", lambda: tty)

    with pytest.raises(OSError, match="terminal emulator|Fail closed"):
        spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=MagicMock())

    text = tty.text
    assert "Install one now?" in text
    assert "xterm" in text
    assert "sudo apt install xterm" in text
    assert "Installed it? Retry now?" in text
    # Menu shown once — no second Install offer.
    assert text.count("Install one now?") == 1


def test_linux_no_emulator_retry_success(monkeypatch) -> None:
    """Accept offer; second which scan finds an emulator → spawn succeeds."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("DISPLAY", ":0")

    calls = {"n": 0}

    def which(name: str) -> str | None:
        # First pass (and pkg-mgr probes during offer): no emulators.
        # After retry confirmation, xterm appears.
        if name in _EMULATOR_NAMES:
            calls["n"] += 1
            # Emulator which is consulted once per name per scan. First scan
            # misses every name; the offer path may re-probe pkg managers;
            # the scan after the retry finds xterm.
            if calls["n"] > len(_EMULATOR_NAMES) and name == "xterm":
                return "/usr/bin/xterm"
            return None
        if name == "apt":
            return "/usr/bin/apt"
        return None

    monkeypatch.setattr("key_amnesia.platform.shutil.which", which)
    tty = _FakeTTY(answers=["y", "4", "", "y"])
    monkeypatch.setattr("key_amnesia.platform._open_controlling_tty", lambda: tty)

    captured: dict[str, Any] = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        proc = MagicMock()
        proc.poll.return_value = None
        return proc

    result = spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=fake_popen)

    assert result.poll() is None
    assert captured["cmd"] == ["/usr/bin/xterm", "-e", *HELPER_ARGV]
    assert "sudo apt install xterm" in tty.text


def test_pkg_manager_detection_order(monkeypatch) -> None:
    """apt-get/apt, dnf, pacman, apk, zypper — first on PATH wins."""
    order = ["apt-get", "apt", "dnf", "pacman", "apk", "zypper"]
    expected = {
        "apt-get": "sudo apt-get install xterm",
        "apt": "sudo apt install xterm",
        "dnf": "sudo dnf install xterm",
        "pacman": "sudo pacman -S xterm",
        "apk": "sudo apk add xterm",
        "zypper": "sudo zypper install xterm",
    }
    for name in order:
        available = {name: f"/usr/bin/{name}"}
        monkeypatch.setattr(
            "key_amnesia.platform.shutil.which",
            _fake_which(available),
        )
        assert _pkg_install_command("xterm") == expected[name]

    monkeypatch.setattr("key_amnesia.platform.shutil.which", _fake_which({}))
    assert _pkg_install_command("xterm") is None

    # Precedence: apt-get before apt when both present.
    monkeypatch.setattr(
        "key_amnesia.platform.shutil.which",
        _fake_which({"apt-get": "/usr/bin/apt-get", "apt": "/usr/bin/apt"}),
    )
    assert _pkg_install_command("xterm") == "sudo apt-get install xterm"


def test_other_platform_fail_closed(monkeypatch) -> None:
    """Non-Win/Linux/Darwin platforms still fail closed (macOS covered in test_macos)."""
    monkeypatch.setattr(sys, "platform", "freebsd14")

    with pytest.raises(OSError, match="not implemented|fail closed|Fail closed"):
        spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=MagicMock())


# --- terminal discovery on a desktop that is not GNOME/KDE/X11 -------------
#
# The bug these cover: the table used to be x-terminal-emulator, gnome-terminal,
# konsole, xterm, invoked with a blanket -e. On a current Wayland desktop none
# of those four is installed, so `ka run` from a non-TTY parent failed closed
# with "No suitable terminal emulator found" and no way to proceed.


def _spawn_capturing(monkeypatch, available: dict[str, str]) -> list[str]:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-1")
    monkeypatch.setattr(
        "key_amnesia.platform.shutil.which", _fake_which(available)
    )
    captured: dict[str, Any] = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        proc = MagicMock()
        proc.poll.return_value = None
        return proc

    spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=fake_popen)
    return captured["cmd"]


def test_wayland_terminals_are_found_at_all(monkeypatch) -> None:
    """ghostty/kitty/foot alone on PATH must produce a spawn, not a fail-closed."""
    for name in ("ghostty", "kitty", "foot", "alacritty", "wezterm"):
        cmd = _spawn_capturing(monkeypatch, {name: f"/usr/bin/{name}"})
        assert cmd[0] == f"/usr/bin/{name}"
        assert cmd[-len(HELPER_ARGV):] == HELPER_ARGV


def test_trailing_argv_terminals_get_no_dash_e(monkeypatch) -> None:
    """kitty and foot take the command as trailing args and reject -e."""
    for name in ("kitty", "foot", "xdg-terminal-exec"):
        cmd = _spawn_capturing(monkeypatch, {name: f"/usr/bin/{name}"})
        assert cmd == [f"/usr/bin/{name}", *HELPER_ARGV]


def test_flag_argv_terminals(monkeypatch) -> None:
    for name, flags in (
        ("ghostty", ["-e"]),
        ("alacritty", ["-e"]),
        ("wezterm", ["start", "--"]),
        ("xfce4-terminal", ["-x"]),
        ("kgx", ["--"]),
    ):
        cmd = _spawn_capturing(monkeypatch, {name: f"/usr/bin/{name}"})
        assert cmd == [f"/usr/bin/{name}", *flags, *HELPER_ARGV]


def test_joined_argv_terminal_is_shell_quoted(monkeypatch) -> None:
    """tilix -e takes one string; a path with a space must survive it."""
    argv = ["/opt/my tools/python3", "-m", "key_amnesia", "_prompt-helper"]
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(
        "key_amnesia.platform.shutil.which", _fake_which({"tilix": "/usr/bin/tilix"})
    )
    captured: dict[str, Any] = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        proc = MagicMock()
        proc.poll.return_value = None
        return proc

    spawn_isolated_console(argv, dict(SENSITIVE_ENV), popen_fn=fake_popen)
    assert captured["cmd"][:2] == ["/usr/bin/tilix", "-e"]
    assert len(captured["cmd"]) == 3
    assert "'/opt/my tools/python3'" in captured["cmd"][2]


def test_xdg_terminal_exec_wins_when_present(monkeypatch) -> None:
    cmd = _spawn_capturing(
        monkeypatch,
        {
            "xdg-terminal-exec": "/usr/bin/xdg-terminal-exec",
            "ghostty": "/usr/bin/ghostty",
            "xterm": "/usr/bin/xterm",
        },
    )
    assert cmd[0] == "/usr/bin/xdg-terminal-exec"


def test_key_amnesia_terminal_env_overrides_everything(monkeypatch) -> None:
    """The escape hatch: a command prefix, flag included, for unknown terminals."""
    monkeypatch.setenv("KEY_AMNESIA_TERMINAL", "myterm --run-in")
    cmd = _spawn_capturing(
        monkeypatch,
        {"myterm": "/opt/bin/myterm", "ghostty": "/usr/bin/ghostty"},
    )
    assert cmd == ["/opt/bin/myterm", "--run-in", *HELPER_ARGV]


def test_key_amnesia_terminal_env_ignored_when_not_on_path(monkeypatch) -> None:
    monkeypatch.setenv("KEY_AMNESIA_TERMINAL", "nosuchterm -e")
    cmd = _spawn_capturing(monkeypatch, {"ghostty": "/usr/bin/ghostty"})
    assert cmd[0] == "/usr/bin/ghostty"


def test_terminal_env_is_honoured_with_table_flags(monkeypatch) -> None:
    """$TERMINAL names a binary; its invocation style comes from the table."""
    monkeypatch.setenv("TERMINAL", "alacritty")
    cmd = _spawn_capturing(
        monkeypatch,
        {"alacritty": "/usr/bin/alacritty", "xterm": "/usr/bin/xterm"},
    )
    assert cmd == ["/usr/bin/alacritty", "-e", *HELPER_ARGV]


def test_desktop_preference_moves_its_own_terminal_first(monkeypatch) -> None:
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "KDE")
    cmd = _spawn_capturing(
        monkeypatch,
        {"konsole": "/usr/bin/konsole", "ghostty": "/usr/bin/ghostty"},
    )
    assert cmd[0] == "/usr/bin/konsole"

    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "Hyprland")
    cmd = _spawn_capturing(
        monkeypatch,
        {"konsole": "/usr/bin/konsole", "ghostty": "/usr/bin/ghostty"},
    )
    assert cmd[0] == "/usr/bin/ghostty"


def test_fail_closed_message_names_the_escape_hatch(monkeypatch) -> None:
    """A user who hits this must be told how to get out of it without guessing."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr("key_amnesia.platform.shutil.which", _fake_which({}))
    monkeypatch.setattr("key_amnesia.platform._open_controlling_tty", lambda: None)

    with pytest.raises(OSError) as excinfo:
        spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=MagicMock())

    message = str(excinfo.value)
    assert "KEY_AMNESIA_TERMINAL" in message
    assert "ka unlock" in message
