"""Human-auth prompt routing: inline getpass or CREATE_NEW_CONSOLE helper.

Nothing sensitive on argv — ever. Helper gets request/authkey/reply address
via environment variables on Popen env=.
"""

from __future__ import annotations

import getpass
import json
import os
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, Callable

# How often the parent looks for the helper's start marker.
_START_POLL_S = 0.1

from key_amnesia import ipc
from key_amnesia import theme
from key_amnesia.audit import audit_event
from key_amnesia.config import load_config
from key_amnesia.platform import spawn_isolated_console

# Environment keys for helper handoff (never put these on argv).
ENV_REQUEST = "KEY_AMNESIA_PROMPT_REQUEST"
ENV_AUTHKEY = "KEY_AMNESIA_PROMPT_AUTHKEY"
ENV_ADDRESS = "KEY_AMNESIA_PROMPT_ADDRESS"
ENV_PARENT_PID = "KEY_AMNESIA_PROMPT_PARENT_PID"
ENV_TIMEOUT = "KEY_AMNESIA_PROMPT_TIMEOUT"
# Path the helper touches the moment it starts. Not sensitive — an empty file
# in a 0700 temp dir — and the only early proof that the terminal we opened
# actually ran our command, since the helper's first IPC contact comes after
# the human has typed the password.
ENV_STARTED = "KEY_AMNESIA_PROMPT_STARTED"
# Force spawned-console even when both streams claim to be a TTY (agent harnesses).
ENV_NONINTERACTIVE = "KEY_AMNESIA_NONINTERACTIVE"


@dataclass
class PromptRequest:
    action: str
    secret_names: list[str] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    # For run: mapping secret_name -> env var name
    inject_as: dict[str, str] = field(default_factory=dict)
    # Human-facing context shown at the auth prompt (e.g. reveal target name).
    # Must NEVER carry secret material — this gets printed to the screen.
    detail: str = ""
    # Machine payload for the spawned helper to apply a mutation (set/config)
    # when the parent process can't hold the password itself. May contain a
    # raw secret value — never printed, only json.loads()'d by the helper.
    mutation: str = ""
    # Vault path override for helper
    vault_path: str = ""
    # Working directory for `ka run` (absolute). Empty = helper process cwd.
    cwd: str = ""


@dataclass
class AuthOutcome:
    ok: bool
    route: str  # inline | spawned-console
    reason: str = ""
    # Present only for inline successful auth where caller needs password locally.
    # For spawned-console run, helper executes; password is never returned.
    password: str | None = None
    # Helper-executed run results (scrubbed only)
    run_result: dict[str, Any] | None = None
    # Helper reveal/copy status
    status_only: dict[str, Any] | None = None


def _env_noninteractive() -> bool:
    v = os.environ.get(ENV_NONINTERACTIVE, "").strip().lower()
    return v in ("1", "true", "yes", "on")


def _isatty() -> bool:
    """True only when *both* stdin and stdout look like a TTY.

    Agent harnesses often attach a pty to stdin while redirecting stdout.
    stdin-only checks then select the unanswerable inline path; requiring
    both streams avoids that failure mode. Still a heuristic — see
    KEY_AMNESIA_NONINTERACTIVE to force the spawned-console route.
    """
    try:
        in_tty = sys.stdin.isatty()
    except Exception:
        in_tty = False
    try:
        out_tty = sys.stdout.isatty()
    except Exception:
        out_tty = False
    return bool(in_tty and out_tty)


def _prompt_password_inline(request: PromptRequest, timeout_s: int | None = None) -> str:
    theme.info(
        f"key-amnesia: authentication required for '{request.action}'",
        file=sys.stderr,
    )
    if request.secret_names:
        theme.detail(f"  secrets: {', '.join(request.secret_names)}", file=sys.stderr)
    if request.detail:
        theme.detail(f"  {request.detail}", file=sys.stderr)

    if timeout_s is None:
        return getpass.getpass("Master password: ")

    # A tty-shaped stdin does not guarantee an attentive human (e.g. a pty
    # allocated for a subprocess with nobody actually watching it) — bound
    # the wait so a fooled isatty() check fails closed instead of hanging.
    outcome: dict[str, Any] = {}

    def _read() -> None:
        try:
            outcome["password"] = getpass.getpass("Master password: ")
        except BaseException as exc:  # noqa: BLE001 — relayed to caller below
            outcome["error"] = exc

    t = threading.Thread(target=_read, daemon=True)
    t.start()
    t.join(timeout=timeout_s)
    if t.is_alive():
        raise TimeoutError("prompt timed out waiting for master password")
    if "error" in outcome:
        raise outcome["error"]
    return str(outcome["password"])


def _helper_command() -> list[str]:
    """Bare argv for the prompt helper — no secrets, no request JSON."""
    # Prefer installed console script; fall back to python -m for tests/dev.
    return [sys.executable, "-m", "key_amnesia", "_prompt-helper"]


def _make_start_marker() -> tuple[Path, Callable[[float], bool]]:
    """A file the helper touches on start, and a waiter for it.

    Returned rather than polled inline because the spawn layer decides *when*
    to give up on a candidate terminal and try the next one.
    """
    tmp = Path(tempfile.mkdtemp(prefix="key-amnesia-start-"))
    os.chmod(tmp, 0o700)
    marker = tmp / "started"

    def wait(timeout_s: float) -> bool:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if marker.exists():
                return True
            time.sleep(_START_POLL_S)
        return False

    return marker, wait


def _cleanup_start_marker(marker: Path) -> None:
    try:
        marker.unlink(missing_ok=True)
    except OSError:
        pass
    try:
        marker.parent.rmdir()
    except OSError:
        pass


def _spawn_helper(
    request: PromptRequest,
    address: str,
    authkey: bytes,
    timeout_s: int,
    *,
    popen_fn: Callable[..., Any] | None = None,
    start_marker: Path | None = None,
    confirm_started: Callable[[float], bool] | None = None,
) -> Any:
    """Spawn helper with CREATE_NEW_CONSOLE; sensitive data only in env."""
    env = os.environ.copy()
    env[ENV_REQUEST] = json.dumps(asdict(request))
    env[ENV_AUTHKEY] = ipc.authkey_to_hex(authkey)
    env[ENV_ADDRESS] = address
    env[ENV_PARENT_PID] = str(os.getpid())
    env[ENV_TIMEOUT] = str(timeout_s)
    if start_marker is not None:
        env[ENV_STARTED] = str(start_marker)

    cmd = _helper_command()
    return spawn_isolated_console(
        cmd, env, popen_fn=popen_fn, confirm_started=confirm_started
    )


def require_human_auth(
    request: PromptRequest,
    timeout_s: int | None = None,
    *,
    password_provider: Callable[[], str] | None = None,
    popen_fn: Callable[..., Any] | None = None,
    isatty_fn: Callable[[], bool] | None = None,
) -> AuthOutcome:
    """Route to inline getpass or spawned console helper.

    Master password is never satisfiable non-interactively without a spawned
    console. Password never travels over IPC.
    """
    cfg = load_config()
    if timeout_s is None:
        timeout_s = int(cfg.get("prompt-timeout-seconds", 90))

    # Env wins over stream heuristics / injected isatty_fn — agent harnesses
    # that look like a TTY but cannot answer must force the visible console.
    if _env_noninteractive():
        tty = False
    else:
        tty = (isatty_fn or _isatty)()
    if tty:
        try:
            if password_provider is not None:
                password = password_provider()
            else:
                password = _prompt_password_inline(request, timeout_s)
        except (EOFError, KeyboardInterrupt):
            audit_event(
                request.action,
                secret_names=request.secret_names,
                command=request.command or None,
                route="inline",
                result="denied",
                reason="prompt cancelled",
            )
            return AuthOutcome(ok=False, route="inline", reason="prompt cancelled")
        except TimeoutError:
            audit_event(
                request.action,
                secret_names=request.secret_names,
                command=request.command or None,
                route="inline",
                result="timeout",
                reason="prompt timed out",
            )
            return AuthOutcome(ok=False, route="inline", reason="prompt timed out")
        if not password:
            audit_event(
                request.action,
                secret_names=request.secret_names,
                command=request.command or None,
                route="inline",
                result="denied",
                reason="empty password",
            )
            return AuthOutcome(ok=False, route="inline", reason="empty password")
        return AuthOutcome(ok=True, route="inline", password=password)

    # Non-interactive: spawn helper console (Win / Linux / experimental macOS).
    listener = None
    proc = None
    start_marker, confirm_started = _make_start_marker()
    try:
        listener, address, authkey = ipc.start_listener()
        try:
            proc = _spawn_helper(
                request,
                address,
                authkey,
                timeout_s,
                popen_fn=popen_fn,
                start_marker=start_marker,
                confirm_started=confirm_started,
            )
        except OSError as e:
            audit_event(
                request.action,
                secret_names=request.secret_names,
                command=request.command or None,
                route="spawned-console",
                result="denied",
                reason=str(e),
            )
            return AuthOutcome(ok=False, route="spawned-console", reason=str(e))

        # Wait for helper to connect. One accept thread for the whole wait —
        # restarting accept each second orphaned connections on older threads
        # (parent never saw them; later closed the listener → helper WinError 232).
        deadline = time.monotonic() + timeout_s
        conn: Connection | None = None
        accepted: list[Connection | BaseException] = []

        def _accept() -> None:
            try:
                accepted.append(listener.accept())
            except BaseException as exc:  # noqa: BLE001
                accepted.append(exc)

        accept_thread = threading.Thread(target=_accept, daemon=True)
        accept_thread.start()
        while time.monotonic() < deadline:
            accept_thread.join(timeout=0.5)
            if accepted:
                item = accepted[0]
                if isinstance(item, BaseException):
                    raise item
                conn = item
                break
            # Do not abort on proc.poll(): WindowsApps/store Python + 
            # CREATE_NEW_CONSOLE can make the tracked Popen exit while the
            # real helper console is still alive (password prompt / run).
        else:
            audit_event(
                request.action,
                secret_names=request.secret_names,
                command=request.command or None,
                route="spawned-console",
                result="timeout",
                reason="prompt timed out",
            )
            return AuthOutcome(ok=False, route="spawned-console", reason="prompt timed out")

        if conn is None:
            audit_event(
                request.action,
                secret_names=request.secret_names,
                command=request.command or None,
                route="spawned-console",
                result="denied",
                reason="helper exited without connecting",
            )
            return AuthOutcome(
                ok=False,
                route="spawned-console",
                reason=(
                    "helper exited without connecting "
                    "(keep the auth window open until it finishes, "
                    "or use `ka unlock` then retry)"
                ),
            )

        try:
            # After connect (post-password), `run` may take far longer than the
            # prompt window — mirror guard_request's generous bound.
            remaining = max(0.1, deadline - time.monotonic())
            recv_timeout = remaining
            if request.action == "run":
                recv_timeout = max(remaining, 3600.0)
            reply = ipc.recv_msg(conn, timeout=recv_timeout)
        except TimeoutError:
            audit_event(
                request.action,
                secret_names=request.secret_names,
                command=request.command or None,
                route="spawned-console",
                result="timeout",
                reason="helper reply timed out",
            )
            return AuthOutcome(
                ok=False, route="spawned-console", reason="helper reply timed out"
            )
        finally:
            try:
                conn.close()
            except Exception:
                pass

        # Sanitize: never accept password / secret values from helper.
        if "password" in reply or "secret_value" in reply or "secrets" in reply:
            # Strip and treat as protocol violation — do not propagate.
            reply = {k: v for k, v in reply.items() if k not in ("password", "secret_value", "secrets")}

        ok = bool(reply.get("ok"))
        reason = str(reply.get("reason", ""))
        result = "allowed" if ok else ("timeout" if "timeout" in reason.lower() else "denied")
        audit_event(
            request.action,
            secret_names=request.secret_names,
            command=request.command or None,
            route="spawned-console",
            result=result,
            reason=reason,
        )
        outcome = AuthOutcome(ok=ok, route="spawned-console", reason=reason)
        if "run_result" in reply and isinstance(reply["run_result"], dict):
            # Scrubbed I/O + exit only — never raw secrets.
            rr = reply["run_result"]
            outcome.run_result = {
                "exit_code": rr.get("exit_code"),
                "scrubbed_stdout": rr.get("scrubbed_stdout", ""),
                "scrubbed_stderr": rr.get("scrubbed_stderr", ""),
            }
        if "status_only" in reply and isinstance(reply["status_only"], dict):
            outcome.status_only = {
                k: v
                for k, v in reply["status_only"].items()
                if k in ("shown", "copied", "action", "name", "approved", "key")
            }
        return outcome
    finally:
        _cleanup_start_marker(start_marker)
        if listener is not None:
            try:
                listener.close()
            except Exception:
                pass
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass


def clear_helper_env() -> dict[str, str]:
    """Read and clear helper env vars from os.environ. Returns the values."""
    keys = [
        ENV_REQUEST,
        ENV_AUTHKEY,
        ENV_ADDRESS,
        ENV_PARENT_PID,
        ENV_TIMEOUT,
        ENV_STARTED,
    ]
    out: dict[str, str] = {}
    for k in keys:
        if k in os.environ:
            out[k] = os.environ.pop(k)
    return out


def parent_alive(pid: int) -> bool:
    """Best-effort check whether *pid* is still a live process.

    Fail-open only when the OS refuses access to a process that may exist
    (Windows ERROR_ACCESS_DENIED / POSIX EPERM): a false "dead" after the
    human typed the master password aborts the helper without an IPC reply
    (common when the parent is an agent harness the helper cannot OpenProcess).
    A missing process (ERROR_INVALID_PARAMETER / ProcessLookupError) is dead.
    """
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        ERROR_ACCESS_DENIED = 5
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.SetLastError(0)
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            # Access denied → process may exist; anything else (e.g. 87
            # ERROR_INVALID_PARAMETER for a missing pid) → dead.
            return kernel32.GetLastError() == ERROR_ACCESS_DENIED
        try:
            exit_code = ctypes.c_ulong()
            ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            if not ok:
                return True
            return exit_code.value == STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    else:
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except OSError:
            # EPERM / other — process may exist but be unsignalable.
            return True


def run_prompt_helper() -> int:
    """Entry for `_prompt-helper`: read env, prompt, act, reply over IPC.

    Never puts password or raw secrets on the reply channel for reveal/copy
    beyond local console/clipboard. For run: executes locally and returns
    scrubbed I/O only.
    """
    from pathlib import Path

    from key_amnesia.clipboard import copy_to_clipboard
    from key_amnesia.vault import VaultError, load_vault

    env = clear_helper_env()

    # First thing, before any output: tell the parent this window really did
    # start us. Best effort — a prompt must never fail over a missing marker.
    started_at = env.get(ENV_STARTED)
    if started_at:
        try:
            Path(started_at).touch()
        except OSError:
            pass

    try:
        request_raw = env[ENV_REQUEST]
        authkey = ipc.authkey_from_hex(env[ENV_AUTHKEY])
        address = env[ENV_ADDRESS]
        parent_pid = int(env.get(ENV_PARENT_PID, "0"))
        timeout_s = int(env.get(ENV_TIMEOUT, "90"))
    except (KeyError, ValueError) as e:
        theme.error(f"key-amnesia helper: missing/invalid env handoff: {e}")
        input("Press Enter to close...")
        return 1

    request_data = json.loads(request_raw)
    request = PromptRequest(**{
        k: request_data.get(k, v)
        for k, v in {
            "action": "",
            "secret_names": [],
            "command": [],
            "inject_as": {},
            "detail": "",
            "vault_path": "",
            "cwd": "",
        }.items()
    })
    # Fix types from JSON
    request = PromptRequest(
        action=str(request_data.get("action", "")),
        secret_names=list(request_data.get("secret_names") or []),
        command=list(request_data.get("command") or []),
        inject_as=dict(request_data.get("inject_as") or {}),
        detail=str(request_data.get("detail") or ""),
        mutation=str(request_data.get("mutation") or ""),
        vault_path=str(request_data.get("vault_path") or ""),
        cwd=str(request_data.get("cwd") or ""),
    )

    if parent_pid and not parent_alive(parent_pid):
        theme.error("key-amnesia helper: parent process gone; cancelling.")
        return 1

    theme.info("=" * 50)
    theme.info("  key-amnesia - human authentication")
    theme.info("=" * 50)
    theme.out(f"Action : {request.action}")
    if request.secret_names:
        theme.out(f"Secrets: {', '.join(request.secret_names)}")
    if request.command:
        theme.out(f"Command: {' '.join(request.command)}")
    if request.detail:
        theme.out(request.detail)
    if request.action in ("set", "config") and request.mutation:
        # Preview the incoming value in THIS isolated window only — never in
        # the caller's own terminal (see _prompt_password_inline). The agent
        # cannot read or type into this console, so showing the value here
        # lets you deny before it's committed, per README's documented promise.
        try:
            mut_preview = json.loads(request.mutation)
            theme.out(f"Value  : {mut_preview.get('value', '')}")
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass
    theme.out()

    # Watch parent in background
    cancel = {"flag": False}

    def _watch() -> None:
        while not cancel["flag"]:
            if parent_pid and not parent_alive(parent_pid):
                cancel["flag"] = True
                return
            time.sleep(0.5)

    watcher = threading.Thread(target=_watch, daemon=True)
    watcher.start()

    reply: dict[str, Any] = {"ok": False, "reason": ""}

    try:
        password = getpass.getpass("Master password: ")
    except (EOFError, KeyboardInterrupt):
        password = ""

    if cancel["flag"]:
        # Still reply over IPC — silent exit made parents report only
        # "helper exited without connecting" with no usable reason.
        reply["reason"] = "cancelled (parent exited)"
        return _helper_reply_and_exit(address, authkey, reply, cancel)

    try:
        if not password:
            reply["reason"] = "empty password"
        else:
            vault = Path(request.vault_path) if request.vault_path else None
            try:
                payload = load_vault(vault, password)
            except VaultError as e:
                reply["reason"] = str(e)
                payload = None

            if payload is not None:
                secrets_map: dict[str, str] = {
                    k: str(v) for k, v in payload.get("secrets", {}).items()
                }
                action = request.action

                # Role policy (KAM2): runner cannot reveal/copy.
                # Classification: policy vs human; effective vs agent.
                if action in ("reveal", "copy", "set", "remove"):
                    from key_amnesia import roles as roles_mod

                    role = roles_mod.role_for_identity(
                        payload, roles_mod.load_identity()
                    )
                    if not roles_mod.policy_allows(action, role):
                        assert role is not None
                        reply["reason"] = roles_mod.deny_reason(action, role)
                        action = "__denied__"

                if action == "run":
                    missing = [n for n in request.secret_names if n not in secrets_map]
                    if missing:
                        reply["reason"] = f"unknown secrets: {', '.join(missing)}"
                    elif not request.command:
                        reply["reason"] = "no command"
                    else:
                        env_inject = {
                            request.inject_as.get(n, n): secrets_map[n]
                            for n in request.secret_names
                        }
                        by_name = {n: secrets_map[n] for n in request.secret_names}
                        # Connect *before* running so the parent holds the pipe
                        # for the whole command. Late connect after a long run
                        # hit WinError 232 when the parent had already closed.
                        password = ""  # noqa: F841 — wipe before child work
                        return _helper_run_connected(
                            address,
                            authkey,
                            cancel,
                            request.command,
                            env_inject,
                            by_name,
                            cwd=request.cwd or None,
                        )

                elif action == "reveal":
                    name = request.secret_names[0] if request.secret_names else ""
                    if name not in secrets_map:
                        reply["reason"] = f"unknown secret: {name}"
                    else:
                        theme.out()
                        theme.out(f"--- {name} ---")
                        # Raw secret value — never themed.
                        sys.stdout.write(f"{secrets_map[name]}\n")
                        theme.out("--- end ---")
                        reply["ok"] = True
                        reply["status_only"] = {
                            "shown": True,
                            "action": "reveal",
                            "name": name,
                        }

                elif action == "copy":
                    name = request.secret_names[0] if request.secret_names else ""
                    if name not in secrets_map:
                        reply["reason"] = f"unknown secret: {name}"
                    else:
                        copy_to_clipboard(secrets_map[name])
                        theme.success(f"Copied '{name}' to clipboard (this window only).")
                        reply["ok"] = True
                        reply["status_only"] = {
                            "copied": True,
                            "action": "copy",
                            "name": name,
                        }

                elif action in ("set", "remove", "config", "unlock", "auth"):
                    # Auth-only: prove password works; caller (parent) cannot
                    # get the password back over IPC. For set/remove/config
                    # that need the password in the parent, those must be
                    # interactive (inline) OR the helper must perform the
                    # mutation. Per design: non-interactive set/remove/config
                    # still need fresh auth — helper will perform mutation
                    # when request carries mutation fields.
                    # For unlock/auth/set/remove/config: password verified;
                    # helper may apply mutation if request.mutation JSON says so.
                    reply["ok"] = True
                    reply["reason"] = "authenticated"
                    # Mutation payloads arrive in request.mutation as JSON for
                    # set/remove/config when parent cannot hold the password.
                    # Never printed — request.detail (already shown above) is
                    # the human-facing field and must stay secret-free.
                    if action == "set" and request.mutation:
                        try:
                            mut = json.loads(request.mutation)
                            name = mut["name"]
                            value = mut["value"]
                            secrets_map[name] = value
                            from key_amnesia.vault import save_vault

                            save_vault(
                                vault,
                                password,
                                {
                                    "secrets": secrets_map,
                                    "created_at": payload.get("created_at"),
                                    "updated_at": payload.get("updated_at"),
                                },
                            )
                            reply["status_only"] = {"action": "set", "name": name}
                        except Exception as e:  # noqa: BLE001
                            reply["ok"] = False
                            reply["reason"] = f"set failed: {e}"
                    elif action == "remove" and request.secret_names:
                        name = request.secret_names[0]
                        if name not in secrets_map:
                            reply["ok"] = False
                            reply["reason"] = f"unknown secret: {name}"
                        else:
                            del secrets_map[name]
                            from key_amnesia.vault import save_vault

                            save_vault(
                                vault,
                                password,
                                {
                                    "secrets": secrets_map,
                                    "created_at": payload.get("created_at"),
                                    "updated_at": payload.get("updated_at"),
                                },
                            )
                            reply["status_only"] = {"action": "remove", "name": name}
                    elif action == "config" and request.mutation:
                        try:
                            mut = json.loads(request.mutation)
                            from key_amnesia.config import set_config_value

                            set_config_value(mut["key"], str(mut["value"]))
                            reply["status_only"] = {
                                "action": "config",
                                "key": mut["key"],
                            }
                        except Exception as e:  # noqa: BLE001
                            reply["ok"] = False
                            reply["reason"] = f"config failed: {e}"
                    elif action == "unlock":
                        # `ka unlock` is now the guard itself — it blocks in
                        # the caller's own foreground terminal. A spawned
                        # helper console is a different process/terminal, so
                        # it cannot become that guard on the parent's behalf.
                        reply["ok"] = False
                        reply["reason"] = (
                            "unlock must be run in a foreground terminal"
                        )
                else:
                    reply["reason"] = f"unsupported helper action: {action}"
    except Exception as e:  # noqa: BLE001
        reply["ok"] = False
        reply["reason"] = f"helper error: {e}"
    finally:
        # Wipe password from locals as best-effort
        password = ""  # noqa: F841

    return _helper_reply_and_exit(address, authkey, reply, cancel)


def _helper_run_connected(
    address: str,
    authkey: bytes,
    cancel: dict[str, bool],
    command: list[str],
    env_inject: dict[str, str],
    by_name: dict[str, str],
    cwd: str | None = None,
) -> int:
    """Connect to parent first, then execute *command*, then send scrubbed I/O."""
    from key_amnesia.run_exec import run_with_secrets

    try:
        conn = ipc.connect(address, authkey)
    except Exception as e:  # noqa: BLE001
        theme.error(f"Failed to reply to parent: {e}")
        input("Press Enter to close...")
        cancel["flag"] = True
        return 1

    reply: dict[str, Any] = {"ok": False, "reason": ""}
    try:
        try:
            result = run_with_secrets(command, env_inject, by_name, cwd=cwd)
            reply["ok"] = True
            reply["run_result"] = {
                "exit_code": result.exit_code,
                "scrubbed_stdout": result.scrubbed_stdout,
                "scrubbed_stderr": result.scrubbed_stderr,
            }
        except Exception as e:  # noqa: BLE001
            reply["ok"] = False
            reply["reason"] = f"helper error: {e}"
        safe = {
            k: v
            for k, v in reply.items()
            if k in ("ok", "reason", "run_result", "status_only")
        }
        if "run_result" in safe and isinstance(safe["run_result"], dict):
            rr = safe["run_result"]
            safe["run_result"] = {
                "exit_code": rr.get("exit_code"),
                "scrubbed_stdout": rr.get("scrubbed_stdout", ""),
                "scrubbed_stderr": rr.get("scrubbed_stderr", ""),
            }
        ipc.send_msg(conn, safe)
    except Exception as e:  # noqa: BLE001
        theme.error(f"Failed to reply to parent: {e}")
        input("Press Enter to close...")
        cancel["flag"] = True
        return 1
    finally:
        try:
            conn.close()
        except Exception:
            pass

    cancel["flag"] = True
    if reply.get("ok"):
        theme.success("Done.")
    else:
        theme.out(f"Failed: {reply.get('reason', 'unknown')}")
    time.sleep(0.8)
    return 0 if reply.get("ok") else 1


def _helper_reply_and_exit(
    address: str,
    authkey: bytes,
    reply: dict[str, Any],
    cancel: dict[str, bool],
) -> int:
    """Connect back to parent with a status-only reply, then exit.

    Always attempts IPC — skipping it left parents with only
    "helper exited without connecting" and no reason string.
    """
    try:
        # Do not skip connect on a soft parent_alive miss — try anyway.
        conn = ipc.connect(address, authkey)
        try:
            # Final hard filter: never send password or raw secret maps.
            safe = {
                k: v
                for k, v in reply.items()
                if k in ("ok", "reason", "run_result", "status_only")
            }
            if "run_result" in safe and isinstance(safe["run_result"], dict):
                rr = safe["run_result"]
                safe["run_result"] = {
                    "exit_code": rr.get("exit_code"),
                    "scrubbed_stdout": rr.get("scrubbed_stdout", ""),
                    "scrubbed_stderr": rr.get("scrubbed_stderr", ""),
                }
            ipc.send_msg(conn, safe)
        finally:
            conn.close()
    except Exception as e:  # noqa: BLE001
        theme.error(f"Failed to reply to parent: {e}")
        input("Press Enter to close...")
        cancel["flag"] = True
        return 1

    cancel["flag"] = True
    if reply.get("ok"):
        theme.success("Done.")
    else:
        theme.out(f"Failed: {reply.get('reason', 'unknown')}")
    # Brief pause so user can read the console before it closes.
    time.sleep(0.8)
    return 0 if reply.get("ok") else 1
