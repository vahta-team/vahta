"""OS-specific process spawn helpers for isolated-console prompts."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, TextIO

from key_amnesia import theme

# Environment override: a command prefix, shell-quoted, that we append the
# helper argv to. `KEY_AMNESIA_TERMINAL="alacritty -e"` is the escape hatch for
# any terminal this table does not know, and it beats the stored setting so a
# one-off run can differ from the configured choice.
ENV_TERMINAL = "KEY_AMNESIA_TERMINAL"

# How a terminal takes "now run this argv".
#
# There is no single convention, and getting it wrong is not a soft failure:
# the emulator either refuses to start or opens an interactive shell with no
# helper in it, and the prompt never appears.
_TRAILING = "trailing"  # term CMD ARGS…        — the command is just argv
_FLAG = "flag"  # term FLAG… CMD ARGS…  — a flag, then argv
_JOINED = "joined"  # term FLAG "CMD ARGS…" — one shell-quoted string

# Linux terminal emulators known to this module.
#
# This is *detection data for `ka setup`*, not a runtime policy: at run time
# the terminal comes from the configured `terminal` command, and the entries
# below only supply the invocation flags for one picked by name and the
# candidate order used when nothing is configured yet. A terminal absent from
# this table is fully usable — configure it as a command prefix.
#
# Order is deliberate. `xdg-terminal-exec` is the freedesktop reference
# implementation of "launch the user's chosen terminal" and is right whenever
# it exists. After that come the terminals people on Wayland actually run,
# then the X11-era ones. `x-terminal-emulator` sits low even though it is a
# user preference on Debian: it is an alternatives symlink that may land on
# gnome-terminal, whose `-e` is deprecated and string-shaped, so a direct hit
# on a named terminal above it is always the better invocation.
_LINUX_EMULATORS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("xdg-terminal-exec", _TRAILING, ()),
    ("ghostty", _FLAG, ("-e",)),
    ("kitty", _TRAILING, ()),
    ("foot", _TRAILING, ()),
    ("alacritty", _FLAG, ("-e",)),
    ("wezterm", _FLAG, ("start", "--")),
    ("gnome-terminal", _FLAG, ("--",)),
    ("kgx", _FLAG, ("--",)),
    ("konsole", _FLAG, ("-e",)),
    ("xfce4-terminal", _FLAG, ("-x",)),
    ("mate-terminal", _FLAG, ("--",)),
    ("terminator", _FLAG, ("-x",)),
    ("tilix", _JOINED, ("-e",)),
    ("lxterminal", _JOINED, ("-e",)),
    ("qterminal", _JOINED, ("-e",)),
    ("urxvt", _FLAG, ("-e",)),
    ("st", _FLAG, ("-e",)),
    ("x-terminal-emulator", _FLAG, ("-e",)),
    ("xterm", _FLAG, ("-e",)),
)

_EMULATOR_STYLES: dict[str, tuple[str, tuple[str, ...]]] = {
    name: (style, flags) for name, style, flags in _LINUX_EMULATORS
}

# Desktop-environment preference, applied by moving these to the front when
# XDG_CURRENT_DESKTOP names the environment. A KDE user gets Konsole even on a
# box that also has ghostty installed.
_DESKTOP_PREFERENCE: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("KDE", ("konsole",)),
    ("GNOME", ("kgx", "gnome-terminal")),
    ("XFCE", ("xfce4-terminal",)),
    ("MATE", ("mate-terminal",)),
    ("LXQT", ("qterminal",)),
)

# Offered for installation when nothing is on PATH. Deliberately shorter than
# the table above: these are packaged under the same name everywhere, and one
# of them is the right answer on any desktop.
_INSTALLABLE_EMULATORS: tuple[str, ...] = (
    "alacritty",
    "gnome-terminal",
    "konsole",
    "xterm",
)

_LINUX_EMULATOR_DESCRIPTIONS: dict[str, str] = {
    "alacritty": "small, fast, works on Wayland and X11",
    "gnome-terminal": "full-featured, best if you're on GNOME",
    "konsole": "full-featured, best if you're on KDE",
    "xterm": "lightest and fastest, no desktop-environment dependencies",
}

# Package-manager detection order (first on PATH wins).
_PKG_MANAGERS: tuple[tuple[str, str], ...] = (
    ("apt-get", "sudo apt-get install {pkg}"),
    ("apt", "sudo apt install {pkg}"),
    ("dnf", "sudo dnf install {pkg}"),
    ("pacman", "sudo pacman -S {pkg}"),
    ("apk", "sudo apk add {pkg}"),
    ("zypper", "sudo zypper install {pkg}"),
)

# Brief pause after spawn to catch an emulator that launches then exits right
# away (e.g. a broken alias, or a build that doesn't accept our -e/-- flag).
# Overridable so tests don't pay this cost.
_POLL_DELAY_S = 0.15

# macOS: open/osascript return immediately — parent polls a PID file written by
# a wrapper that then execs the helper. Overridable for tests.
_MACOS_PID_WAIT_S = 8.0
_MACOS_PID_POLL_S = 0.05

# Visible Terminal.app window path is unconfirmed by a real Mac user.
MACOS_SPAWN_EXPERIMENTAL = True

# Embedded into the temp wrapper script; must stay self-contained (no imports
# from key_amnesia — the wrapper may run before the package is on PYTHONPATH
# the way Terminal.app launches it).
_MACOS_WRAPPER_SOURCE = '''\
import json
import os
import sys

def main() -> None:
    if len(sys.argv) < 4:
        sys.stderr.write("key-amnesia macOS wrapper: missing args\\n")
        sys.exit(2)
    env_path, pid_path = sys.argv[1], sys.argv[2]
    helper = sys.argv[3:]
    with open(env_path, "r", encoding="utf-8") as f:
        env = json.load(f)
    try:
        os.unlink(env_path)
    except OSError:
        pass
    os.environ.clear()
    os.environ.update({str(k): str(v) for k, v in env.items()})
    with open(pid_path, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.execvpe(helper[0], helper, os.environ)

if __name__ == "__main__":
    main()
'''


class PidFileProcess:
    """Popen-like handle bound to a helper PID from a PID file (macOS).

    ``open -a Terminal`` / ``osascript`` exit immediately, so the launcher
    Popen cannot be waited on for parent-death or cancel. The wrapper records
    its PID (stable across ``exec`` of the helper) and this object exposes
    ``poll`` / ``terminate`` against that PID.
    """

    def __init__(
        self,
        pid: int,
        *,
        cleanup_paths: list[Path] | None = None,
        cleanup_dir: Path | None = None,
    ) -> None:
        self.pid = int(pid)
        self.returncode: int | None = None
        self._cleanup_paths = list(cleanup_paths or [])
        self._cleanup_dir = cleanup_dir

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        try:
            os.kill(self.pid, 0)
        except ProcessLookupError:
            self.returncode = 0
            self._cleanup()
            return 0
        except PermissionError:
            # Exists but not signalable — treat as alive.
            return None
        except OSError:
            self.returncode = 0
            self._cleanup()
            return 0
        return None

    def terminate(self) -> None:
        try:
            os.kill(self.pid, signal.SIGTERM)
        except OSError:
            pass

    def _cleanup(self) -> None:
        for p in self._cleanup_paths:
            try:
                p.unlink(missing_ok=True)  # type: ignore[call-arg]
            except TypeError:
                # Python <3.8 missing_ok — not our floor, but be safe.
                try:
                    if p.exists():
                        p.unlink()
                except OSError:
                    pass
            except OSError:
                pass
        if self._cleanup_dir is not None:
            try:
                self._cleanup_dir.rmdir()
            except OSError:
                pass


def _has_interactive_display() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _linux_emulator_argv(emulator: str, argv: list[str]) -> list[str]:
    """Build emulator + helper argv. Secrets stay in env, never on argv."""
    name = os.path.basename(emulator)
    style, flags = _EMULATOR_STYLES.get(name, (_TRAILING, ()))
    if style == _JOINED:
        # -e here takes one string, not a vector. shlex.join keeps a path with
        # a space in it from splitting into two arguments.
        return [emulator, *flags, shlex.join(argv)]
    return [emulator, *flags, *argv]


def terminal_command_for(name: str) -> list[str]:
    """Command prefix that runs something in the terminal called *name*.

    Flags come from the table when the name is in it, and default to none —
    the modern convention, which kitty, foot and xdg-terminal-exec all use —
    when it is not. Returns [] if the binary is not on PATH.
    """
    path = shutil.which(name)
    if not path:
        return []
    _, flags = _EMULATOR_STYLES.get(os.path.basename(name), (_TRAILING, ()))
    return [path, *flags]


def detect_terminals() -> list[tuple[str, list[str]]]:
    """Every known terminal installed here, best candidate first.

    `ka setup` shows this list; nothing at run time depends on it once a
    terminal has been configured.
    """
    found: list[tuple[str, list[str]]] = []
    for name in _emulator_candidates():
        command = terminal_command_for(name)
        if command:
            found.append((name, command))
    return found


def _resolve_command_prefix(text: str) -> list[str] | None:
    """Turn a stored/env command prefix into an absolute argv prefix."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        parts = shlex.split(text)
    except ValueError:
        return None
    if not parts:
        return None
    path = shutil.which(parts[0])
    if not path:
        return None
    # Resolve here so the spawn does not depend on a PATH that the emulator's
    # own environment might not share.
    return [path, *parts[1:]]


def describe_terminal() -> str:
    """One line for `ka status`: the terminal that will open, and why.

    Cheap to print and the only place a user can check the setting without
    triggering a real prompt — which is the whole difficulty with this code
    path, since it only ever runs when nobody is watching a TTY.
    """
    if not sys.platform.startswith("linux"):
        return f"handled by the OS on {sys.platform}"
    command, source = resolve_terminal()
    if command is None:
        found = ", ".join(name for name, _ in detect_terminals())
        if found:
            return f"none configured; would try {found}"
        return "none configured and none detected — `ka setup --terminal-only`"
    shown = shlex.join(command)
    return f"{shown} (from {source})"


def resolve_terminal() -> tuple[list[str] | None, str]:
    """The terminal command to use and where it came from."""
    from_env = _resolve_command_prefix(os.environ.get(ENV_TERMINAL, ""))
    if from_env:
        return from_env, ENV_TERMINAL

    try:
        from key_amnesia.config import load_config

        configured = str(load_config().get("terminal") or "")
    except Exception:  # noqa: BLE001 — a broken config must not block the prompt
        configured = ""
    from_config = _resolve_command_prefix(configured)
    if from_config:
        return from_config, "config"

    named = os.environ.get("TERMINAL", "").strip()
    if named:
        command = terminal_command_for(named)
        if command:
            return command, "TERMINAL"
    return None, "detection"


def _preferred_terminal_command() -> list[str] | None:
    """The terminal to use, in precedence order, or None to fall back to a scan.

    KEY_AMNESIA_TERMINAL wins: a per-invocation override for CI and for
    debugging a bad setting. Then the `terminal` config value, which is what
    `ka setup` writes and what a user edits — this is the intended source, and
    the reason the table below it is only a fallback. Then TERMINAL, the
    widely set convention, whose value names a binary rather than a command,
    so its flags are looked up.

    A configured terminal that has since been uninstalled resolves to None
    here rather than raising, so detection still gets its turn: losing a
    terminal should degrade to a scan, not to no password prompt at all.
    """
    return resolve_terminal()[0]


def _emulator_candidates() -> tuple[str, ...]:
    """Table order, with the running desktop's own terminal moved to the front."""
    names = [name for name, _, _ in _LINUX_EMULATORS]
    desktop = os.environ.get("XDG_CURRENT_DESKTOP", "").upper()
    if not desktop:
        return tuple(names)
    for token, preferred in _DESKTOP_PREFERENCE:
        if token in desktop:
            front = [n for n in preferred if n in names]
            return tuple(front + [n for n in names if n not in front])
    return tuple(names)


def _process_alive(proc: Any) -> bool:
    """Best-effort liveness check shortly after spawn.

    Treat a stub without a working `.poll()` (e.g. an unconfigured test
    double) as alive rather than reject it — this only needs to catch a
    *real* process that has already exited.
    """
    poll = getattr(proc, "poll", None)
    if not callable(poll):
        return True
    try:
        return poll() is None
    except Exception:
        return True


def _no_emulator_oserror(tried: list[str] | None = None) -> OSError:
    names = tried if tried else list(_emulator_candidates())
    return OSError(
        "No suitable terminal emulator found "
        f"(tried {', '.join(names)}). Fail closed.\n"
        "  Tell key-amnesia which terminal you use — the command, including "
        'whatever flag it takes to run something:\n'
        '    ka config set terminal "alacritty -e"\n'
        "  `ka setup` offers the same choice from what is installed, and "
        f"{ENV_TERMINAL} overrides both for one run.\n"
        "  Or start a session in your own terminal first with `ka unlock`, "
        "which needs no window here."
    )


def _open_controlling_tty() -> TextIO | None:
    """Open the controlling terminal, or None if unavailable."""
    try:
        return open("/dev/tty", "r+", encoding="utf-8", errors="replace")
    except OSError:
        return None


def _tty_readline(tty: TextIO, prompt: str) -> str:
    tty.write(prompt)
    tty.flush()
    return tty.readline().strip()


def _pkg_install_command(package: str) -> str | None:
    """Return a one-line install command for *package*, or None if unknown pm."""
    for binary, template in _PKG_MANAGERS:
        if shutil.which(binary):
            return template.format(pkg=package)
    return None


def _try_spawn_linux_emulators(
    argv: list[str],
    env: dict[str, str],
    *,
    popen_fn: Callable[..., Any],
) -> tuple[Any | None, list[str]]:
    """Try each known emulator on PATH. Return (proc_or_None, names_tried)."""
    tried: list[str] = []
    candidates: list[list[str]] = []

    override = _preferred_terminal_command()
    if override is not None:
        candidates.append([*override, *argv])
        tried.append(os.path.basename(override[0]))

    for name in _emulator_candidates():
        path = shutil.which(name)
        if not path:
            continue
        tried.append(name)
        candidates.append(_linux_emulator_argv(path, argv))

    for cmd in candidates:
        try:
            # No stdin/stdout/stderr kwargs — emulator owns stdio.
            proc = popen_fn(cmd, env=env, close_fds=True)
        except OSError:
            continue
        if _POLL_DELAY_S:
            time.sleep(_POLL_DELAY_S)
        if _process_alive(proc):
            return proc, tried
        # Launched but exited immediately (bad invocation, broken alias) —
        # don't report false success; try the next emulator instead.
        continue
    return None, tried


def _offer_linux_emulator_install(
    argv: list[str],
    env: dict[str, str],
    *,
    popen_fn: Callable[..., Any],
) -> Any | None:
    """Interactive /dev/tty recovery when no emulator is on PATH.

    Returns a live process if the user installs and retry succeeds; otherwise
    None (caller raises the existing OSError). Never prompts on the headless
    branch — that path never reaches here. Never asks for a password.
    """
    tty = _open_controlling_tty()
    if tty is None:
        return None

    err = _no_emulator_oserror()
    try:
        theme.warn(str(err), file=tty)
        answer = _tty_readline(tty, "Install one now? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            return None

        theme.info("Choose a terminal emulator to install:", file=tty)
        for i, name in enumerate(_INSTALLABLE_EMULATORS, start=1):
            desc = _LINUX_EMULATOR_DESCRIPTIONS.get(name, "")
            theme.info(f"  {i}) {name} - {desc}", file=tty)
        skip_n = len(_INSTALLABLE_EMULATORS) + 1
        theme.info(f"  {skip_n}) skip, don't install anything", file=tty)

        choice_raw = _tty_readline(tty, "Choice: ").strip()
        try:
            choice = int(choice_raw)
        except ValueError:
            return None
        if choice == skip_n or choice < 1 or choice > skip_n:
            return None

        package = _INSTALLABLE_EMULATORS[choice - 1]
        cmd = _pkg_install_command(package)
        if cmd is not None:
            theme.info("Run this in another shell (not executed by key-amnesia):", file=tty)
            theme.out(f"  {cmd}", file=tty)
        else:
            theme.info(
                f"Install package '{package}' with your distro's package manager "
                "(no known package manager found on PATH).",
                file=tty,
            )
        _tty_readline(tty, "Press Enter after installing… ")

        retry = _tty_readline(tty, "Installed it? Retry now? [y/N] ").strip().lower()
        if retry not in ("y", "yes"):
            return None

        proc, tried = _try_spawn_linux_emulators(argv, env, popen_fn=popen_fn)
        if proc is not None:
            return proc
        if tried:
            # Found but none stayed running — surface the same message as the
            # normal path rather than the "none on PATH" OSError.
            raise OSError(
                f"Terminal emulator(s) found ({', '.join(tried)}) but none stayed "
                "running (bad invocation or immediate exit). Fail closed."
            )
        return None
    finally:
        try:
            tty.close()
        except Exception:
            pass


def _spawn_linux(
    argv: list[str],
    env: dict[str, str],
    *,
    popen_fn: Callable[..., Any],
) -> Any:
    if not _has_interactive_display():
        raise OSError(
            "No interactive display available (DISPLAY/WAYLAND_DISPLAY unset); "
            "cannot spawn isolated console. Fail closed."
        )

    proc, tried = _try_spawn_linux_emulators(argv, env, popen_fn=popen_fn)
    if proc is not None:
        return proc

    if tried:
        raise OSError(
            f"Terminal emulator(s) found ({', '.join(tried)}) but none stayed "
            "running (bad invocation or immediate exit). Fail closed."
        )

    # Display present, nothing on PATH — one interactive install offer via /dev/tty.
    offered = _offer_linux_emulator_install(argv, env, popen_fn=popen_fn)
    if offered is not None:
        return offered
    raise _no_emulator_oserror(tried)


def _applescript_quote(s: str) -> str:
    """Quote *s* as an AppleScript string literal."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _wait_for_pid_file(pid_path: Path, *, timeout_s: float | None = None) -> int:
    """Poll *pid_path* until it contains a positive integer PID."""
    limit = _MACOS_PID_WAIT_S if timeout_s is None else timeout_s
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        try:
            text = pid_path.read_text(encoding="utf-8").strip()
        except OSError:
            text = ""
        if text.isdigit():
            pid = int(text)
            if pid > 0:
                return pid
        if _MACOS_PID_POLL_S:
            time.sleep(_MACOS_PID_POLL_S)
    raise OSError(
        "macOS isolated-console helper did not record a PID in time "
        "(Terminal/osascript may have failed to launch). Fail closed."
    )


def _macos_launcher_argv(
    wrapper_py: Path,
    env_file: Path,
    pid_file: Path,
    helper_argv: list[str],
    *,
    command_file: Path | None = None,
) -> list[str]:
    """Build osascript/open argv. Secrets stay in *env_file*, never on argv."""
    inner = " ".join(
        shlex.quote(p)
        for p in [
            sys.executable,
            str(wrapper_py),
            str(env_file),
            str(pid_file),
            *helper_argv,
        ]
    )
    osascript = shutil.which("osascript")
    if osascript:
        script = (
            'tell application "Terminal"\n'
            f"  do script {_applescript_quote(inner)}\n"
            "  activate\n"
            "end tell"
        )
        return [osascript, "-e", script]

    open_bin = shutil.which("open")
    if open_bin and command_file is not None:
        return [open_bin, "-a", "Terminal", str(command_file)]

    raise OSError(
        "Neither osascript nor open found on PATH; cannot spawn macOS "
        "isolated console. Fail closed."
    )


def _spawn_macos(
    argv: list[str],
    env: dict[str, str],
    *,
    popen_fn: Callable[..., Any],
) -> PidFileProcess:
    """Spawn helper via Terminal.app using a PID-file wrapper.

    ``open`` / ``osascript`` return immediately; the wrapper writes its PID
    then ``exec``s the helper so parent-death / ``poll`` / ``terminate`` track
    the real helper, not the launcher.
    """
    tmp = Path(tempfile.mkdtemp(prefix="key-amnesia-macos-"))
    try:
        try:
            tmp.chmod(0o700)
        except OSError:
            pass

        env_file = tmp / "env.json"
        pid_file = tmp / "helper.pid"
        wrapper_py = tmp / "wrapper.py"
        command_file = tmp / "run.command"

        env_file.write_text(
            json.dumps({str(k): str(v) for k, v in env.items()}),
            encoding="utf-8",
        )
        try:
            env_file.chmod(0o600)
        except OSError:
            pass

        wrapper_py.write_text(_MACOS_WRAPPER_SOURCE, encoding="utf-8")
        try:
            wrapper_py.chmod(0o700)
        except OSError:
            pass

        # open -a Terminal fallback: a .command file Terminal will execute.
        inner = " ".join(
            shlex.quote(p)
            for p in [
                sys.executable,
                str(wrapper_py),
                str(env_file),
                str(pid_file),
                *argv,
            ]
        )
        command_file.write_text("#!/bin/bash\nexec " + inner + "\n", encoding="utf-8")
        try:
            command_file.chmod(0o700)
        except OSError:
            pass

        launch_argv = _macos_launcher_argv(
            wrapper_py, env_file, pid_file, argv, command_file=command_file
        )
        # Launcher env is the *caller's* environment without prompt secrets —
        # those live only in env.json until the wrapper loads and unlinks it.
        try:
            popen_fn(launch_argv, close_fds=True)
        except OSError as e:
            raise OSError(
                f"Failed to launch macOS Terminal for isolated console: {e}. "
                "Fail closed."
            ) from e

        helper_pid = _wait_for_pid_file(pid_file)
        return PidFileProcess(
            helper_pid,
            cleanup_paths=[env_file, pid_file, wrapper_py, command_file],
            cleanup_dir=tmp,
        )
    except Exception:
        # Best-effort scrub of the temp dir (may still hold env.json).
        for p in tmp.iterdir() if tmp.exists() else []:
            try:
                p.unlink()
            except OSError:
                pass
        try:
            tmp.rmdir()
        except OSError:
            pass
        raise


def spawn_isolated_console(
    argv: list[str],
    env: dict[str, str],
    *,
    popen_fn: Callable[..., Any] | None = None,
) -> Any:
    """Spawn *argv* in an isolated console; sensitive data only in *env*.

    Windows: CREATE_NEW_CONSOLE, no stdio kwargs.
    Linux: the configured terminal (KEY_AMNESIA_TERMINAL, then the `terminal`
    config value, then TERMINAL), else the first terminal from _LINUX_EMULATORS
    on PATH, when DISPLAY or WAYLAND_DISPLAY is set; otherwise fail closed.
    macOS (experimental): Terminal.app via osascript/open + PID-file wrapper
    so parent-death tracks the helper, not the short-lived launcher.
    Other platforms: fail closed.
    """
    popen = popen_fn or subprocess.Popen

    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NEW_CONSOLE  # type: ignore[attr-defined]
        # No stdin/stdout/stderr kwargs — new console owns stdio.
        return popen(
            argv,
            env=env,
            creationflags=creationflags,
            close_fds=False,
        )

    if sys.platform.startswith("linux"):
        return _spawn_linux(argv, env, popen_fn=popen)

    if sys.platform == "darwin":
        return _spawn_macos(argv, env, popen_fn=popen)

    raise OSError(
        "Isolated-console spawn is not implemented on this platform "
        f"({sys.platform}); fail closed."
    )
