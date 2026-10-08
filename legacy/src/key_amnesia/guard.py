"""Cached-session guard — foreground singleton holding decrypted vault in memory.

IPC verbs: run, list, lock, status, renew only.
Never returns raw secret values. No get-value / reveal verb.
Authkey only (no session_key).

`ka unlock` *is* the guard: unlike v2, there is no detached child process and
no bootstrap-env handoff. `run_foreground_guard` runs in the caller's own
terminal, printing live status lines and blocking in `guard_serve` until the
vault is locked, the session expires, or the terminal is interrupted.

Admission (0.3.8): a lightweight consent layer sits on top of the authkey
trust boundary. The first request from an unrecognized process *tree* is
gated by a yes/no prompt on the guard's own TTY; approval binds admission to
the connecting process's **kernel-verified identity** (`peer_identity.py`),
not to a bearer credential — there is nothing admission-related on disk to
steal. See `_check_admission` for the full model, including secret-scoped
grants and opt-in pre-admit.
"""

from __future__ import annotations

import json
import os
import secrets as secrets_mod
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, Callable

from key_amnesia import ipc
from key_amnesia import peer_identity
from key_amnesia import theme
from key_amnesia import vault as vault_mod
from key_amnesia.audit import audit_event
from key_amnesia.paths import (
    guard_lock_path,
    guards_registry_dir,
    last_guard_state_path,
)
from key_amnesia.peer_identity import PeerIdentity
from key_amnesia.run_exec import run_with_secrets

# `AdmitPromptFn` covers two calling conventions depending on which
# admission path is in play — see `_check_admission` / `_check_admission_legacy`:
#   - new (kernel-identity) path: called as `admit_prompt(peer, summary)`
#     where `peer` is a `PeerIdentity`.
#   - legacy (no-`peer`-supplied) path: called as `admit_prompt(pid, summary)`
#     with a bare int, exactly as before 0.3.8.
AdmitPromptFn = Callable[[Any, str], bool]

# How long the guard's admission prompt waits for a yes/no before denying.
ADMISSION_TIMEOUT_S = 60.0

# How far ahead of expiry the guard offers to extend the session.
EXTEND_PROMPT_WINDOW_S = 120.0

# How often the guard nudges an idle terminal with time remaining.
REMINDER_INTERVAL_S = 300.0

# Sentinel for `guard_handle_message_legacy` only — distinguishes "caller
# doesn't know about kernel peer identity at all" (pre-0.3.8 test helpers;
# falls back to the legacy opaque-token comparison) from an explicit
# `peer=None` ("a real lookup was attempted and failed"), which always
# fails closed. Module-private; not part of the public `guard_handle_message`
# signature. See `_check_admission`.
_PEER_UNSET = object()


def _format_hms(seconds: float) -> str:
    seconds = max(0, int(seconds))
    minutes, secs = divmod(seconds, 60)
    return f"{minutes}m {secs}s" if minutes else f"{secs}s"


@dataclass
class AdmittedSession:
    """One in-memory admitted process-tree record — lives only for this guard run.

    `identities` holds the kernel-verified `PeerIdentity` of the process
    that was actually admitted (see `peer_identity.is_in_admitted_tree` for
    how later connections are matched against it — a real OS descendant of
    an admitted process is silently in-tree; a merely-sibling process, even
    one sharing a distant common ancestor like a login shell, is not).

    `granted_secrets` / `unscoped` implement secret-scoped grants: a `run`
    naming a secret outside the current grant re-prompts instead of being
    silently allowed, unless `unscoped` (only ever true for the loud,
    opt-in `--pre-admit` ALL-secrets case — see `run_foreground_guard`).

    `token` is a **legacy-only** field: it exists purely so
    `guard_handle_message_legacy` keeps working for callers that predate
    kernel peer identity. `guard_serve` — the only production caller —
    always supplies a real `peer`, so this field is never consulted on a
    live guard; see `_check_admission_legacy`.
    """

    identities: list[PeerIdentity] = field(default_factory=list)
    first_seen: str = ""
    request_count: int = 0
    last_summary: str = ""
    granted_secrets: set[str] = field(default_factory=set)
    granted_until: float = 0.0
    unscoped: bool = False
    token: str = ""


@dataclass
class VaultSource:
    """One on-disk vault contributing to a (possibly merged) guard view.

    `key` is the derived SecretBox key only — never the master password.
    Sources are ordered low→high precedence; later sources win on name
    collision when rebuilding `state.secrets` (global then project).
    """

    path: Path
    key: bytes
    fingerprint: str | None = None


@dataclass
class GuardState:
    secrets: dict[str, str]
    expires_at: float  # epoch seconds
    address: str
    authkey: bytes
    pid: int = field(default_factory=os.getpid)
    created_at: float = field(default_factory=time.time)
    stop: threading.Event = field(default_factory=threading.Event)
    admitted: AdmittedSession | None = None
    request_count: int = 0
    # One stdin reader per guard run (see _StdinPump) — every prompt this
    # guard shows (admission, extend) must share the same reader, or two
    # concurrent input() calls race for the same typed line.
    stdin_pump: "_StdinPump" = field(default_factory=lambda: _StdinPump())
    # Stale-secrets reload support (see `_maybe_reload_secrets`). All three
    # default to None so a `GuardState(...)` built without them (every
    # existing test, and any future caller that genuinely has no on-disk
    # vault behind it) simply never attempts a reload — never a required
    # argument, never a behavior change for those callers.
    vault_path: Path | None = None
    # Derived SecretBox key only — NEVER the master password. Same trust
    # tier as the plaintext secrets already held in `state.secrets`; see
    # DESIGN.md "Derived key retained in guard memory".
    vault_key: bytes | None = None
    vault_content_fingerprint: str | None = None
    # Multi-vault merge (project + global): when set, `_maybe_reload_secrets`
    # fingerprints *every* source. Singular vault_path/vault_key remain for
    # single-vault callers and tests.
    vault_sources: list[VaultSource] | None = None
    # Opt-in, single-use pre-admit window (`ka unlock --pre-admit`) — see
    # `_check_admission`. `pre_admit_until` is cleared (set back to None)
    # the moment it is consumed by the first unrecognized peer, whether or
    # not the window itself has since expired.
    pre_admit_until: float | None = None
    pre_admit_unscoped: bool = False
    pre_admit_secrets: set[str] = field(default_factory=set)
    # Opt-in session-only `--admit-tree` (never config/env). When True, an
    # unrecognized peer with a walkable ancestor chain is offered a numbered
    # kernel-verified ancestor as admission root instead of the default y/N.
    # See `_admit_tree_prompt` / DESIGN.md "Process-tree ancestry admission".
    admit_tree: bool = False


def _utc_iso(ts: float | None = None) -> str:
    t = ts if ts is not None else time.time()
    return datetime.fromtimestamp(t, tz=timezone.utc).replace(microsecond=0).isoformat()


# --- guard.lock ---------------------------------------------------------


def write_guard_lock(
    address: str,
    authkey: bytes,
    pid: int,
    expires_at: float,
    path: Path | None = None,
) -> None:
    p = path or guard_lock_path()
    data = {
        "address": address,
        "authkey_hex": ipc.authkey_to_hex(authkey),
        "pid": pid,
        "expires_at": _utc_iso(expires_at),
        "expires_at_epoch": expires_at,
    }
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def read_guard_lock(path: Path | None = None) -> dict[str, Any] | None:
    p = path or guard_lock_path()
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def clear_guard_lock(path: Path | None = None) -> None:
    p = path or guard_lock_path()
    try:
        p.unlink(missing_ok=True)
    except OSError:
        pass


def guard_is_alive(
    lock: dict[str, Any] | None = None,
    *,
    path: Path | None = None,
) -> bool:
    lock = lock if lock is not None else read_guard_lock(path=path)
    if not lock:
        return False
    pid = int(lock.get("pid") or 0)
    expires = float(lock.get("expires_at_epoch") or 0)
    if expires and time.time() > expires:
        return False
    if pid <= 0:
        return False
    from key_amnesia.prompt_route import parent_alive

    return parent_alive(pid)


def connect_guard(
    lock: dict[str, Any] | None = None,
    *,
    path: Path | None = None,
) -> Connection | None:
    lock = lock if lock is not None else read_guard_lock(path=path)
    if not lock or not guard_is_alive(lock):
        return None
    try:
        authkey = ipc.authkey_from_hex(lock["authkey_hex"])
        return ipc.connect(lock["address"], authkey)
    except Exception:
        return None


def guard_request(
    msg: dict[str, Any],
    timeout: float = 30.0,
    *,
    lock_path: Path | None = None,
) -> dict[str, Any] | None:
    """Send a message to the live guard; return response or None.

    Since 0.3.8 the client attaches nothing admission-related — the guard
    identifies the caller straight from the kernel at the IPC layer (see
    `peer_identity.py`), so there is no opaque token to cache or present.
    `client_name` is a **display-only** label (never a credential — see
    `--name` / `KEY_AMNESIA_CLIENT_NAME`), defaulted here from the
    environment so every guard-talking command picks it up automatically.

    Connectivity / protocol failures return `None` after writing a
    `guard-session` / `warn` audit entry — never silently.
    """
    out = dict(msg)
    out.setdefault("client_name", os.environ.get("KEY_AMNESIA_CLIENT_NAME", ""))
    action = str(out.get("verb") or out.get("action") or "guard")
    secret_names = [str(n) for n in (out.get("secret_names") or [])] or None
    command = [str(c) for c in (out.get("command") or [])] or None

    def _abandon(reason: str) -> None:
        audit_event(
            action,
            secret_names=secret_names,
            command=command,
            route="guard-session",
            result="warn",
            reason=reason,
            path=None,
        )

    conn = connect_guard(path=lock_path)
    if conn is None:
        _abandon("guard connect failed")
        return None
    try:
        ipc.send_msg(conn, out)
        reply = ipc.recv_msg(conn, timeout=timeout)
    except (OSError, TimeoutError, EOFError, ConnectionError, ValueError) as exc:
        _abandon(f"{type(exc).__name__}: {exc}")
        return None
    except Exception as exc:  # noqa: BLE001 — never drop the reason
        _abandon(f"{type(exc).__name__}: {exc}")
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return reply


# --- admission consent ----------------------------------------------------


def _summarize_request(verb: str, msg: dict[str, Any]) -> str:
    if verb == "run":
        names = [str(n) for n in (msg.get("secret_names") or [])]
        if names:
            return f"run with {', '.join(names)}"
        cmd = " ".join(str(c) for c in (msg.get("command") or []))
        return f"run `{cmd}`" if cmd else "run a command"
    if verb == "list":
        return "list secret names"
    if verb == "status":
        return "check guard status"
    if verb == "lock":
        return "lock the vault"
    if verb == "renew":
        return f"renew the session ({msg.get('minutes', '?')}m)"
    return f"'{verb or 'unknown'}' request"


class _StdinPump:
    """Coordinates prompts so at most one thread is ever blocked in input().

    Every prompt used to spawn its own thread around a blocking input()
    call, bounded by joining that thread with a timeout. But a thread that
    times out is never killed — Python cannot cancel a blocking input() —
    so it keeps running, still blocked in input(), forever. If a second
    prompt then spawned its own thread while the first was still alive,
    both threads were blocked on the same stdin at once: whichever the OS
    handed the next typed line to "won", and it was not necessarily the one
    whose prompt was currently on screen. That let an explicit "y" typed in
    answer to a visible prompt be silently swallowed by an abandoned thread
    from an earlier, already-timed-out prompt — the visible prompt then
    timed out too and reported denied, despite the correct answer having
    been typed.

    This coordinator starts at most one input()-reading thread at a time,
    and that thread reads exactly one line then stops — it does not loop,
    so a fast/non-blocking input() (real piped stdin, or a test double)
    cannot spin it into a busy loop. read_line() either starts that one
    read (if none is in flight) or waits on the read already in flight, so
    concurrent callers see the same next typed line instead of racing for
    it. An answer that arrives when nobody is waiting is discarded the next
    time read_line() is called rather than handed to an unrelated later
    prompt — a stale "y" for one question must not silently approve a
    different one.
    """

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._pending = False  # a reader thread is currently blocked in input()
        self._result: str | None = None
        self._have_result = False
        self._eof = False

    def _read(self) -> None:
        try:
            line = input()
        except BaseException:
            line = None
            hit_eof = True
        else:
            hit_eof = False
        with self._cond:
            self._pending = False
            if hit_eof:
                self._eof = True
            else:
                self._result = line
                self._have_result = True
            self._cond.notify_all()

    def read_line(self, timeout: float | None = None) -> str | None:
        """Wait up to `timeout` seconds for the next line (block until EOF if None)."""
        with self._cond:
            # An unclaimed answer from an earlier read nobody was still
            # waiting for belongs to a different question — drop it rather
            # than silently hand it to this new one.
            if self._have_result and not self._pending:
                self._have_result = False
                self._result = None

            if self._eof and not self._pending:
                return None

            if not self._pending and not self._have_result:
                self._pending = True
                threading.Thread(target=self._read, daemon=True).start()

            deadline = None if timeout is None else time.time() + timeout
            while not self._have_result:
                if self._eof and not self._pending:
                    return None
                if deadline is None:
                    self._cond.wait()
                    continue
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self._cond.wait(timeout=remaining)

            self._have_result = False
            line, self._result = self._result, None
            return line


def default_admit_prompt(
    caller: "PeerIdentity | int", summary: str, stdin_pump: _StdinPump, client_name: str = ""
) -> bool:
    """Blocking yes/no prompt on the guard's own foreground TTY.

    Accepts either a kernel-verified `PeerIdentity` (new admission path,
    shown as "verified") or a bare pid int (legacy path — see
    `_check_admission_legacy`) so one function serves both. Reads via the
    guard run's shared `stdin_pump` rather than its own input() thread —
    see `_StdinPump` for why a per-call thread is the wrong shape here.
    Bounded by ADMISSION_TIMEOUT_S; deny on timeout or any non-yes answer.
    """
    verified = isinstance(caller, PeerIdentity)
    pid = caller.pid if isinstance(caller, PeerIdentity) else int(caller)
    label = f"pid {pid}" + (", verified" if verified else "")
    if client_name:
        label = f"{client_name} ({label})"
    try:
        theme.out(f"Session ({label}) wants: {summary}. Admit? [y/N] ", end="")
    except Exception:
        pass

    line = stdin_pump.read_line(ADMISSION_TIMEOUT_S)
    if line is None:
        return False
    return line.strip().lower() in ("y", "yes")


def _describe_scope(session: "AdmittedSession") -> str:
    if session.unscoped:
        return "ALL (unscoped pre-admit)"
    if session.granted_secrets:
        return ", ".join(sorted(session.granted_secrets))
    return "(no secrets granted yet)"


def _announce_admission(peer: PeerIdentity, session: "AdmittedSession", *, via: str) -> None:
    """Loud TTY line + a distinct audit event for every new admission grant
    (initial or scope-expanded), pre-admit or interactive alike."""
    scope = _describe_scope(session)
    if via == "interactive-tree":
        image = peer_identity.get_process_image_name(peer.pid) or "?"
        try:
            theme.success(
                f"Admitted process TREE rooted at pid {peer.pid} ({image}) — "
                f"every process it spawns is now admitted, scope: {scope}."
            )
        except Exception:
            pass
        audit_event(
            "admission",
            route="guard-session",
            result="allowed",
            reason=(
                f"via={via} pid={peer.pid} start_time={peer.start_time} "
                f"image={image} scope={scope}"
            ),
        )
        return
    try:
        theme.success(f"Admitted client (pid {peer.pid}, {via}) — scope: {scope}.")
    except Exception:
        pass
    audit_event(
        "admission",
        route="guard-session",
        result="allowed",
        reason=f"via={via} pid={peer.pid} scope={scope}",
    )


def _release_admitted_handles(state: GuardState) -> None:
    """Close any Windows OpenProcess handles held by the current admission.

    Safe no-op when nothing is admitted or identities have no handles
    (Linux / ancestor-walk / legacy opaque-token sessions).
    """
    if state.admitted is None:
        return
    for ident in state.admitted.identities:
        ident.release()


def _admit_peer(
    state: GuardState,
    peer: PeerIdentity,
    *,
    granted_secrets: set[str],
    unscoped: bool,
    summary: str,
    via: str,
) -> None:
    """Create (or replace) `state.admitted` for a newly-approved peer.

    By default admission binds to the connecting peer's own kernel-verified
    identity — not a hop up to its parent — so a genuine OS descendant of
    this exact process is silently in-tree (see
    `peer_identity.is_in_admitted_tree`) while a merely-sibling process
    (e.g. the next separate CLI invocation from the same shell) is treated
    as a fresh, unrecognized peer. Opt-in `--admit-tree` may instead store
    a kernel-verified *ancestor* as the root (`via=interactive-tree`);
    `--pre-admit` remains the separate single-use arrival-time grant.
    See DESIGN.md "Process-tree ancestry admission".

    Replacing an existing admission releases any OpenProcess handle held
    on the previous root (Windows).
    """
    _release_admitted_handles(state)
    state.admitted = AdmittedSession(
        identities=[peer],
        first_seen=_utc_iso(),
        request_count=1,
        last_summary=summary,
        granted_secrets=set() if unscoped else set(granted_secrets),
        granted_until=state.expires_at,
        unscoped=unscoped,
    )
    _announce_admission(peer, state.admitted, via=via)


def _admit_tree_depth_label(depth: int, *, widest: bool) -> str:
    """Human label for how far *depth* sits above the connecting client."""
    if depth <= 0:
        return "this client (narrowest)"
    if depth == 1:
        base = "parent"
    elif depth == 2:
        base = "grandparent"
    else:
        base = f"ancestor ↑{depth}"
    if widest:
        return f"{base} (widest here)"
    return base


def _admit_tree_prompt(
    peer: PeerIdentity,
    msg: dict[str, Any],
    verb: str,
    chain: list[PeerIdentity],
    state: GuardState,
) -> PeerIdentity | None:
    """Numbered ancestor picker for `ka unlock --admit-tree`.

    Offers only identities from *chain* after `classify_admit_tree_levels`
    (never message fields — a forged `root_pid` / similar is ignored).
    Returns the chosen `PeerIdentity` from the offerable list, or None on
    deny / timeout / empty / garbage input.
    """
    offerable, skipped = peer_identity.classify_admit_tree_levels(chain)
    summary = _summarize_request(verb, msg)
    client_name = str(msg.get("client_name") or "")
    label = f"pid {peer.pid}, verified"
    if client_name:
        label = f"{client_name} ({label})"
    try:
        theme.out(f"Session ({label}) wants: {summary}. Admit process tree?")
        theme.out(
            "List order is up the tree: lower numbers = closer to this client "
            "(narrower trust); higher numbers = parents/ancestors (wider)."
        )
        if not offerable:
            theme.out("  (no offerable ancestors)")
        depths: list[int] = []
        for node in offerable:
            depth = next(
                (d for d, c in enumerate(chain) if c.matches(node)),
                0,
            )
            depths.append(depth)
        max_depth = max(depths) if depths else 0
        for i, (node, depth) in enumerate(zip(offerable, depths), start=1):
            image = peer_identity.get_process_image_name(node.pid) or "?"
            rank = _admit_tree_depth_label(depth, widest=(depth == max_depth and depth > 0))
            theme.out(f"  [{i}] {rank}  —  pid {node.pid}  {image}")
        for node, reason in skipped:
            theme.out(f"  (skipped: pid {node.pid} — {reason})")
        if offerable:
            theme.out(
                f"Choose root [1-{len(offerable)}], or n to deny: ",
                end="",
            )
        else:
            theme.out("Deny [n]: ", end="")
    except Exception:
        pass

    if not offerable:
        return None

    line = state.stdin_pump.read_line(ADMISSION_TIMEOUT_S)
    if line is None:
        return None
    answer = line.strip().lower()
    if answer in ("", "n", "no"):
        return None
    try:
        idx = int(answer)
    except ValueError:
        return None
    if idx < 1 or idx > len(offerable):
        return None
    return offerable[idx - 1]


def _check_admission(
    peer: Any,
    msg: dict[str, Any],
    state: GuardState,
    verb: str,
    admit_prompt: AdmitPromptFn | None,
) -> tuple[bool, str | None]:
    """Gate every verb behind kernel-verified process-tree identity.

    `peer` is the connection's kernel-verified `PeerIdentity` — see
    `peer_identity.py` — never a message-supplied pid. The module-private
    `_PEER_UNSET` sentinel (only via `guard_handle_message_legacy`) routes
    to `_check_admission_legacy`, the pre-0.3.8 opaque-token check, kept
    only for tests that predate kernel identity; `guard_serve` always
    supplies a real `peer`. An explicit `peer=None` (a real lookup that
    failed) always fails closed — never treated as the legacy case.

    Returns `(admitted, new_token_or_None)` — the token is always `None` on
    this path (nothing is minted or handed back; see `_check_admission_legacy`
    for where a token can still appear).
    """
    summary = _summarize_request(verb, msg)

    if peer is _PEER_UNSET:
        return _check_admission_legacy(msg, state, summary, admit_prompt)

    if peer is None:
        audit_event(
            "admission",
            route="guard-session",
            result="warn",
            reason="peer identity unavailable (unsupported platform or kernel lookup failed)",
        )
        return False, None

    requested = set(msg.get("secret_names") or []) if verb == "run" else set()
    client_name = str(msg.get("client_name") or "")
    now = time.time()

    def _prompt(caller: PeerIdentity) -> bool:
        if admit_prompt is not None:
            return bool(admit_prompt(caller, summary))
        return bool(default_admit_prompt(caller, summary, state.stdin_pump, client_name))

    # Pre-admit: an opt-in, single-use grant for the very next unrecognized
    # peer within the configured window — consumed here, whether or not
    # the peer would otherwise have needed a prompt.
    if (
        state.admitted is None
        and state.pre_admit_until is not None
        and now <= state.pre_admit_until
    ):
        unscoped = state.pre_admit_unscoped
        _admit_peer(
            state,
            peer,
            granted_secrets=set(state.pre_admit_secrets),
            unscoped=unscoped,
            summary=summary,
            via="pre-admit",
        )
        state.pre_admit_until = None
        state.pre_admit_unscoped = False
        state.pre_admit_secrets = set()
        return True, None

    if state.admitted is not None and peer_identity.is_in_admitted_tree(
        state.admitted.identities, peer
    ):
        session = state.admitted
        in_scope = session.unscoped or requested <= session.granted_secrets
        if in_scope and now <= session.granted_until:
            session.request_count += 1
            session.last_summary = summary
            return True, None
        # A recognized tree asking for something outside its current grant
        # (a new secret name, or the grant itself lapsed) gets a fresh
        # prompt to expand it — never a silent bypass.
        if not _prompt(peer):
            return False, None
        if not session.unscoped:
            session.granted_secrets = session.granted_secrets | requested
        session.granted_until = state.expires_at
        session.request_count += 1
        session.last_summary = summary
        _announce_admission(peer, session, via="interactive (scope expanded)")
        return True, None

    # Genuinely unrecognized peer/tree — loud regardless of the outcome.
    audit_event(
        "admission",
        route="guard-session",
        result="warn",
        reason=f"unrecognized peer pid={peer.pid} wants: {summary}",
    )
    # Opt-in `--admit-tree`: offer a kernel-verified ancestor as admission
    # root when the chain is long enough to walk. Empty/short chains and
    # flag-off keep the default y/N prompt byte-identical.
    if state.admit_tree:
        chain = peer_identity.get_ancestor_chain(peer.pid)
        if len(chain) >= 2:
            chosen = _admit_tree_prompt(peer, msg, verb, chain, state)
            if chosen is None:
                return False, None
            # Never trust message fields for the root — only chain/offerable.
            # Prefer the connecting peer object when it matches (held handle).
            if chosen.matches(peer):
                root = peer
            else:
                try:
                    root = peer_identity.hold_identity(chosen)
                except peer_identity.PeerIdentityError:
                    return False, None
            _admit_peer(
                state,
                root,
                granted_secrets=requested,
                unscoped=False,
                summary=summary,
                via="interactive-tree",
            )
            return True, None
    if not _prompt(peer):
        return False, None
    _admit_peer(state, peer, granted_secrets=requested, unscoped=False, summary=summary, via="interactive")
    return True, None


def _check_admission_legacy(
    msg: dict[str, Any],
    state: GuardState,
    summary: str,
    admit_prompt: AdmitPromptFn | None,
) -> tuple[bool, str | None]:
    """Pre-0.3.8 opaque-token admission.

    Kept **only** so `guard_handle_message_legacy` can exercise the
    pre-kernel-identity path in tests. `guard_serve` — the only production
    dispatch path — always supplies a real `peer`, so this function never
    runs against a live guard. It is the same in-memory equality check that
    existed pre-0.3.8; the vulnerable *on-disk* bearer file
    (`admitted_session.token`) it used to pair with is gone (see
    `guard_request`) — nothing here is reachable from outside this process.
    """
    token = str(msg.get("admission_token") or "")
    # Attacker-controlled display hint only — never a trust input. Renamed
    # from `caller_pid` so call sites cannot mistake it for kernel identity.
    claimed_pid_unverified = int(msg.get("claimed_pid_unverified") or 0)

    if state.admitted is not None and token and token == state.admitted.token:
        state.admitted.request_count += 1
        state.admitted.last_summary = summary
        return True, None

    if admit_prompt is not None:
        approved = bool(admit_prompt(claimed_pid_unverified, summary))
    else:
        approved = bool(
            default_admit_prompt(claimed_pid_unverified, summary, state.stdin_pump)
        )
    if not approved:
        return False, None

    new_token = secrets_mod.token_urlsafe(32)
    _release_admitted_handles(state)
    state.admitted = AdmittedSession(
        token=new_token,
        first_seen=_utc_iso(),
        request_count=1,
        last_summary=summary,
    )
    return True, new_token


# --- stale-secrets reload ---------------------------------------------------


def _maybe_reload_secrets(state: GuardState) -> None:
    """Re-open vault file(s) if on-disk content changed since we last looked.

    Fixes the guard's stale in-memory snapshot: `ka set` / `ka remove` from
    another terminal write the vault file directly, but a long-running `ka
    unlock` guard used to decrypt once at startup and never look again (see
    README security limit 11 / DESIGN.md). Cheap content fingerprint first —
    only re-opens (SecretBox decrypt with the already-derived key, no
    Argon2id, no password prompt) when that fingerprint actually moved.

    When `state.vault_sources` is set (project+global merge), every source
    is fingerprinted and reloaded independently; secrets are rebuilt with
    later sources winning on name collision. Singular vault_path/vault_key
    remain the single-vault path.

    No-ops when the state was built without vault backing (every
    guard-dispatch test constructs `GuardState` directly with just an
    in-memory `secrets` dict — those must keep working unchanged).
    """
    if state.vault_sources:
        changed = False
        for src in state.vault_sources:
            current = vault_mod.vault_fingerprint(src.path)
            if current is None:
                continue
            if current != src.fingerprint:
                changed = True
                break
        if not changed:
            return
        merged: dict[str, str] = {}
        for src in state.vault_sources:
            current = vault_mod.vault_fingerprint(src.path)
            if current is None:
                # Keep last fingerprint; skip this source's update this pass.
                continue
            try:
                payload = vault_mod.load_vault_with_retained_key(src.path, src.key)
            except vault_mod.VaultError:
                continue
            merged.update(
                {k: str(v) for k, v in payload.get("secrets", {}).items()}
            )
            src.fingerprint = current
        state.secrets = merged
        return

    if state.vault_path is None or state.vault_key is None:
        return
    current = vault_mod.vault_fingerprint(state.vault_path)
    if current is None or current == state.vault_content_fingerprint:
        return
    try:
        payload = vault_mod.load_vault_with_retained_key(state.vault_path, state.vault_key)
    except vault_mod.VaultError:
        # Torn read from a write-in-progress, or a corrupt file — keep
        # serving the last-known-good snapshot rather than dropping every
        # secret because of a transient read.
        return
    state.secrets = {k: str(v) for k, v in payload.get("secrets", {}).items()}
    state.vault_content_fingerprint = current


# --- guard registry (discovery only; never authkey) -------------------------


def _registry_key_for_vault(vault_path: Path | str) -> str:
    import hashlib

    resolved = str(Path(vault_path).resolve())
    return hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:32]


def write_guard_registry_entry(
    *,
    vault_path: Path | str,
    address: str,
    pid: int,
    expires_at: float,
    project_root: str | None = None,
    env_name: str | None = None,
) -> Path:
    """Write a discovery-only registry entry. Never stores authkey."""
    key = _registry_key_for_vault(vault_path)
    d = guards_registry_dir()
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{key}.json"
    data = {
        "vault_path": str(Path(vault_path).resolve()),
        "project_root": project_root,
        "env": env_name,
        "pid": pid,
        "expires_at": _utc_iso(expires_at),
        "expires_at_epoch": expires_at,
        "address": address,
        # authkey intentionally omitted — stays only in vault-adjacent lock
    }
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return p


def remove_guard_registry_entry(vault_path: Path | str) -> None:
    key = _registry_key_for_vault(vault_path)
    p = guards_registry_dir() / f"{key}.json"
    try:
        p.unlink(missing_ok=True)
    except OSError:
        pass


def list_guard_registry_entries() -> list[dict[str, Any]]:
    """Return live registry entries; drop stale ones."""
    from key_amnesia.prompt_route import parent_alive

    d = guards_registry_dir()
    if not d.is_dir():
        return []
    live: list[dict[str, Any]] = []
    for p in d.glob("*.json"):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass
            continue
        if not isinstance(data, dict):
            continue
        pid = int(data.get("pid") or 0)
        expires = float(data.get("expires_at_epoch") or 0)
        stale = False
        if expires and time.time() > expires:
            stale = True
        elif pid <= 0 or not parent_alive(pid):
            stale = True
        if stale:
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass
            continue
        live.append(data)
    return live


# --- verb dispatch ----------------------------------------------------------


def _dispatch_verb(verb: str, msg: dict[str, Any], state: GuardState) -> dict[str, Any]:
    if time.time() > state.expires_at and verb not in ("lock", "status"):
        return {
            "ok": False,
            "reason": "session expired",
            "expired": True,
            "code": "session_expired",
        }

    # Only verbs that consult state.secrets need a freshness check.
    if verb in ("run", "list", "status"):
        _maybe_reload_secrets(state)

    if verb == "status":
        admitted = state.admitted
        reply: dict[str, Any] = {
            "ok": True,
            "pid": state.pid,
            "expires_at": _utc_iso(state.expires_at),
            "expires_at_epoch": state.expires_at,
            "secret_count": len(state.secrets),
            "expired": time.time() > state.expires_at,
            "admitted": admitted is not None,
            "admitted_since": admitted.first_seen if admitted else None,
            "request_count": admitted.request_count if admitted else 0,
        }
        if admitted is not None:
            reply["admitted_pids"] = [i.pid for i in admitted.identities]
            reply["granted_secrets"] = _describe_scope(admitted)
            reply["granted_until"] = _utc_iso(admitted.granted_until)
        elif state.pre_admit_until is not None and time.time() <= state.pre_admit_until:
            reply["pre_admit_pending"] = True
            reply["pre_admit_scope"] = (
                "ALL (unscoped pre-admit)"
                if state.pre_admit_unscoped
                else ", ".join(sorted(state.pre_admit_secrets)) or "(none)"
            )
            reply["pre_admit_until"] = _utc_iso(state.pre_admit_until)
        return reply

    if verb == "list":
        names = sorted(state.secrets.keys())
        audit_event(
            "list",
            secret_names=names,
            route="guard-session",
            result="allowed",
        )
        return {"ok": True, "names": names}

    if verb == "lock":
        audit_event("lock", route="guard-session", result="allowed")
        state.stop.set()
        return {"ok": True, "lock": True}

    if verb == "renew":
        minutes = int(msg.get("minutes") or 30)
        if minutes < 1:
            return {
                "ok": False,
                "reason": "invalid minutes",
                "code": "invalid_minutes",
            }
        state.expires_at = time.time() + minutes * 60
        write_guard_lock(state.address, state.authkey, state.pid, state.expires_at)
        audit_event(
            "renew",
            route="guard-session",
            result="allowed",
            reason=f"extended {minutes}m",
        )
        return {
            "ok": True,
            "expires_at": _utc_iso(state.expires_at),
            "expires_at_epoch": state.expires_at,
        }

    if verb == "run":
        secret_names = list(msg.get("secret_names") or [])
        inject_as = dict(msg.get("inject_as") or {})
        command = list(msg.get("command") or [])
        cwd = msg.get("cwd") or None
        if not command:
            return {"ok": False, "reason": "no command", "code": "no_command"}
        missing = [n for n in secret_names if n not in state.secrets]
        if missing:
            audit_event(
                "run",
                secret_names=secret_names,
                command=command,
                route="guard-session",
                result="denied",
                reason=f"unknown secrets: {', '.join(missing)}",
            )
            return {
                "ok": False,
                "reason": f"unknown secrets: {', '.join(missing)}",
                "code": "unknown_secret",
            }
        env_inject = {
            inject_as.get(n, n): state.secrets[n] for n in secret_names
        }
        by_name = {n: state.secrets[n] for n in secret_names}
        result = run_with_secrets(command, env_inject, by_name, cwd=cwd)
        audit_event(
            "run",
            secret_names=secret_names,
            command=command,
            route="guard-session",
            result="allowed",
        )
        # Scrubbed I/O + exit only — never raw values.
        return {
            "ok": True,
            "exit_code": result.exit_code,
            "scrubbed_stdout": result.scrubbed_stdout,
            "scrubbed_stderr": result.scrubbed_stderr,
        }

    # Explicitly reject any attempt to fetch values.
    if verb in ("get-value", "reveal", "get", "copy"):
        audit_event(
            verb,
            route="guard-session",
            result="denied",
            reason="guard has no value-return verbs",
        )
        return {
            "ok": False,
            "reason": "guard does not expose secret values",
            "code": "value_return_refused",
        }

    return {
        "ok": False,
        "reason": f"unknown verb: {verb}",
        "code": "unknown_verb",
    }


def guard_handle_message(
    msg: dict[str, Any],
    state: GuardState,
    *,
    peer: Any,
    admit_prompt: AdmitPromptFn | None = None,
) -> dict[str, Any]:
    """Handle one guard IPC message. Never returns raw secret values.

    Authkey check happens at the IPC layer (Listener/Client) before this
    function ever sees the message. On top of that, every verb is gated by
    admission consent bound to kernel-verified process-tree identity — see
    `_check_admission` for the full model. `peer` is required (keyword-only);
    pass a real `PeerIdentity` or `None` (fail closed). Legacy opaque-token
    dispatch is only via `guard_handle_message_legacy` (tests only).
    """
    if not isinstance(msg, dict):
        return {"ok": False, "reason": "invalid message", "code": "invalid_message"}

    verb = str(msg.get("verb") or msg.get("action") or "")
    state.request_count += 1

    admitted, new_token = _check_admission(peer, msg, state, verb, admit_prompt)
    if not admitted:
        return {
            "ok": False,
            "reason": "admission denied",
            "admitted": False,
            "code": "admission_denied",
        }

    reply = _dispatch_verb(verb, msg, state)
    if new_token:
        reply["admission_token"] = new_token
    return reply


def guard_handle_message_legacy(
    msg: dict[str, Any],
    state: GuardState,
    *,
    admit_prompt: AdmitPromptFn | None = None,
) -> dict[str, Any]:
    """Pre-0.3.8 opaque-token dispatch — tests only, never a live guard."""
    return guard_handle_message(msg, state, peer=_PEER_UNSET, admit_prompt=admit_prompt)


# --- serve loop + honest death reporting -----------------------------------


def guard_serve(state: GuardState, listener: Any) -> str:
    """Main guard loop: accept connections until lock or expiry.

    Returns the exit reason ("locked" or "expired"); KeyboardInterrupt and
    any other exception propagate to the caller (`run_foreground_guard`) so
    it can record an honest death reason.
    """
    extend_prompted = False
    reason = "expired"

    def _maybe_prompt_extend() -> None:
        # ~2 min before expiry: prompt extend if TTY still interactive.
        # Called both at the top of the outer loop and on every accept-poll
        # tick below — an idle guard (no incoming requests) would otherwise
        # sit inside the inner accept-wait loop for its whole remaining
        # lifetime and never reach this check until it was too late.
        nonlocal extend_prompted
        now = time.time()
        if (
            not extend_prompted
            and state.expires_at - now <= EXTEND_PROMPT_WINDOW_S
            and state.expires_at > now
            and sys.stdin.isatty()
        ):
            extend_prompted = True
            try:
                theme.out(
                    f"key-amnesia guard: session expires in "
                    f"{int(state.expires_at - now)}s. Extend? [y/N] ",
                    end="",
                )
                line = state.stdin_pump.read_line()
                ans = (line or "").strip().lower()
                if ans in ("y", "yes"):
                    # Default extend by original remaining window or 30m
                    state.expires_at = time.time() + 30 * 60
                    write_guard_lock(
                        state.address, state.authkey, state.pid, state.expires_at
                    )
                    extend_prompted = False
            except (EOFError, KeyboardInterrupt):
                pass

    next_reminder_at = state.created_at + REMINDER_INTERVAL_S

    def _maybe_remind_time_left() -> None:
        # Periodic "still here, here's how long you've got" nudge for an
        # idle terminal. Same idle-tick placement as _maybe_prompt_extend —
        # otherwise a guard nobody's talking to would never print one until
        # it was already inside the extend window (or past it).
        nonlocal next_reminder_at
        if not sys.stdout.isatty():
            return
        now = time.time()
        if now < next_reminder_at:
            return
        next_reminder_at = now + REMINDER_INTERVAL_S
        remaining = state.expires_at - now
        if remaining <= EXTEND_PROMPT_WINDOW_S:
            return  # the extend prompt already covers this ground
        expiry_clock = datetime.fromtimestamp(state.expires_at).strftime("%H:%M")
        theme.detail(
            f"key-amnesia guard: {_format_hms(remaining)} remaining "
            f"(expires {expiry_clock})."
        )

    while not state.stop.is_set():
        now = time.time()
        _maybe_prompt_extend()
        _maybe_remind_time_left()

        if now > state.expires_at:
            state.stop.set()
            reason = "expired"
            break

        # Accept with short poll via thread-less approach: use listener
        # backlog — on Windows named pipes accept blocks. Use a timeout
        # wrapper by setting a short wait via polling thread in serve_forever
        # alternative: accept in thread with stop flag.
        conn: Connection | None = None
        accepted: list[Any] = []

        def _accept() -> None:
            try:
                accepted.append(listener.accept())
            except Exception as e:  # noqa: BLE001
                accepted.append(e)

        t = threading.Thread(target=_accept, daemon=True)
        t.start()
        while t.is_alive():
            if state.stop.is_set() or time.time() > state.expires_at:
                break
            t.join(timeout=0.5)
            _maybe_prompt_extend()
            _maybe_remind_time_left()
        if not accepted:
            # Timed out waiting / expired / stop
            if state.stop.is_set():
                break
            if time.time() > state.expires_at:
                reason = "expired"
                break
            continue
        item = accepted[0]
        if isinstance(item, Exception):
            continue
        conn = item
        peer: PeerIdentity | None = None
        try:
            msg = ipc.recv_msg(conn, timeout=30.0)
            verb = str(msg.get("verb") or msg.get("action") or "") if isinstance(msg, dict) else "?"
            peer = peer_identity.get_peer_identity(conn)
            reply = guard_handle_message(msg, state, peer=peer)
            ipc.send_msg(conn, reply)
            theme.info(f"guard: {verb or '?'} -> {'ok' if reply.get('ok') else 'denied'}")
            if reply.get("lock"):
                state.stop.set()
                reason = "locked"
                break
        except Exception:
            pass
        finally:
            # Windows: get_peer_identity holds OpenProcess for the connecting
            # peer. Keep that handle only if this exact object is the admitted
            # root we just stored; otherwise close it (descendant / denied /
            # unrecognized-but-not-admitted connections).
            if peer is not None:
                kept = (
                    state.admitted is not None
                    and any(peer is ident for ident in state.admitted.identities)
                )
                if not kept:
                    peer.release()
            try:
                conn.close()
            except Exception:
                pass

    state.stop.set()
    # Wipe secrets from state
    state.secrets.clear()
    return reason


def _write_last_guard_state(
    reason: str,
    started_at: float,
    request_count: int,
    path: Path | None = None,
) -> None:
    p = path or last_guard_state_path()
    data = {
        "started_at": _utc_iso(started_at),
        "ended_at": _utc_iso(),
        "reason": reason,
        "request_count": request_count,
    }
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def read_last_guard_state(path: Path | None = None) -> dict[str, Any] | None:
    p = path or last_guard_state_path()
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def _reason_phrase(last: dict[str, Any]) -> str:
    reason = str(last.get("reason") or "unknown")
    if reason == "expired":
        try:
            started = datetime.fromisoformat(str(last.get("started_at")))
            ended = datetime.fromisoformat(str(last.get("ended_at")))
            minutes = max(0, round((ended - started).total_seconds() / 60))
            return f"expired after {minutes}m"
        except (ValueError, TypeError):
            return "expired"
    return reason


def format_no_guard_message(path: Path | None = None) -> str:
    """Honest "no live guard" message used by cmd_lock / cmd_status.

    Prefers reporting the *actual* outcome of the last session over a bare
    "No active guard session." — e.g. "Last session ended 14:32 (expired
    after 30m, handled 4 requests)."
    """
    last = read_last_guard_state(path)
    if not last:
        return "Guard is not running. No previous session recorded."
    ended_at = str(last.get("ended_at") or "")
    try:
        time_part = datetime.fromisoformat(ended_at).strftime("%H:%M")
    except ValueError:
        time_part = ended_at
    count = int(last.get("request_count") or 0)
    plural = "" if count == 1 else "s"
    return (
        f"Guard is not running. Last session ended {time_part} "
        f"({_reason_phrase(last)}, handled {count} request{plural})."
    )


def run_foreground_guard(
    payload: dict[str, Any],
    timeout_minutes: int,
    *,
    vault_path: Path | str | None = None,
    vault_key: bytes | None = None,
    vault_sources: list[VaultSource] | None = None,
    lock_path: Path | None = None,
    last_guard_state_path: Path | None = None,
    project_root: str | None = None,
    env_name: str | None = None,
    pre_admit: bool = False,
    pre_admit_secrets: list[str] | None = None,
    pre_admit_seconds: int = 900,
    admit_tree: bool = False,
) -> int:
    """`ka unlock`'s foreground body: build state, serve, block until done.

    Runs entirely in the caller's own terminal — no subprocess, no bootstrap
    JSON handoff. Writes guard.lock for other terminals' soft-singleton check
    and prints a status line, then blocks in guard_serve. On every exit path
    (locked / expired / interrupted / crashed) writes last_guard_state.json
    with an honest reason before clearing guard.lock.

    `vault_path`/`vault_key` are optional: when the caller (cmd_unlock)
    provides both, the guard retains the already-derived SecretBox key
    (never the password) and re-opens the vault on a content change — see
    `_maybe_reload_secrets`. Omitting them (as every existing test does)
    keeps the old fixed-at-startup-only behavior.

    `vault_sources` (optional) enables a merged project+global view: each
    source is fingerprinted independently; later sources win on name
    collision. When provided, `payload["secrets"]` should already be the
    merged map (caller builds it).

    Registry write/remove runs **only** when `vault_path` is explicitly
    passed (or derived from `vault_sources`) — tests that call this without
    a vault path must not touch real `~/.key-amnesia/guards/`.

    `pre_admit` (opt-in, never the default) arms a single-use grant for the
    very next unrecognized peer within `pre_admit_seconds` — scoped to
    `pre_admit_secrets` if given, else unscoped ALL secrets. Must be loud:
    printed here immediately, plus a distinct audit event, *and* announced
    again at the moment it's actually consumed (see `_check_admission`).

    `admit_tree` (opt-in, never the default, no config/env) widens the
    interactive admission prompt so a human can pick a kernel-verified
    ancestor as the admission root — every real OS descendant of that root
    is then silently in-tree for the rest of the session. Distinct from
    `--pre-admit` (arrival-time grant vs lineage root).
    """
    secrets_map = {k: str(v) for k, v in payload.get("secrets", {}).items()}
    expires_at = time.time() + timeout_minutes * 60
    listener, address, authkey = ipc.start_listener()
    pid = os.getpid()

    sources = list(vault_sources) if vault_sources else None
    if sources:
        for src in sources:
            if src.fingerprint is None:
                src.fingerprint = vault_mod.vault_fingerprint(src.path)
        vp = sources[-1].path  # primary (highest precedence) vault
        vkey = sources[-1].key
        fingerprint = sources[-1].fingerprint
    else:
        vp = Path(vault_path) if vault_path is not None else None
        vkey = vault_key
        fingerprint = (
            vault_mod.vault_fingerprint(vp)
            if vp is not None and vault_key is not None
            else None
        )

    state = GuardState(
        secrets=secrets_map,
        expires_at=expires_at,
        address=address,
        authkey=authkey,
        pid=pid,
        vault_path=vp,
        vault_key=vkey,
        vault_content_fingerprint=fingerprint,
        vault_sources=sources,
        admit_tree=bool(admit_tree),
    )
    if pre_admit:
        scoped_names = set(pre_admit_secrets or ())
        state.pre_admit_until = time.time() + pre_admit_seconds
        state.pre_admit_unscoped = not scoped_names
        state.pre_admit_secrets = scoped_names
        if scoped_names:
            theme.warn(
                f"pre-admitting next client for: {', '.join(sorted(scoped_names))} "
                f"(window {pre_admit_seconds}s)."
            )
            audit_event(
                "pre-admit-armed",
                route="guard-session",
                result="warn",
                reason=f"scope: {sorted(scoped_names)}",
            )
        else:
            theme.warn(
                f"pre-admitting next client for ALL {len(secrets_map)} secrets "
                f"(window {pre_admit_seconds}s)."
            )
            audit_event(
                "pre-admit-armed",
                route="guard-session",
                result="warn",
                reason="scope: ALL (unscoped pre-admit)",
            )

    # Lock / last-state beside the active vault when paths are supplied;
    # otherwise fall back to the global defaults (existing tests).
    effective_lock = lock_path
    if effective_lock is None and vp is not None:
        from key_amnesia.paths import guard_lock_path_for_vault

        effective_lock = guard_lock_path_for_vault(vp)
    effective_last = last_guard_state_path
    if effective_last is None and vp is not None:
        from key_amnesia.paths import last_guard_state_path_for_vault

        effective_last = last_guard_state_path_for_vault(vp)

    write_guard_lock(address, authkey, pid, expires_at, path=effective_lock)

    # Registry only when vault_path was explicitly provided (or via sources).
    registry_vault: Path | None = vp
    if registry_vault is not None:
        try:
            write_guard_registry_entry(
                vault_path=registry_vault,
                address=address,
                pid=pid,
                expires_at=expires_at,
                project_root=project_root,
                env_name=env_name,
            )
        except OSError:
            pass

    started_at = state.created_at

    theme.success(
        f"Guard listening (pid {pid}, timeout {timeout_minutes}m). "
        "Waiting for requests..."
    )
    expiry_clock = datetime.fromtimestamp(expires_at).strftime("%H:%M")
    theme.detail(
        f"  expires at {expiry_clock} — Ctrl+C or `ka lock` (another terminal) "
        f"to stop early. `ka status` shows time left."
    )

    reason = "expired"
    try:
        reason = guard_serve(state, listener)
    except KeyboardInterrupt:
        reason = "interrupted"
        uptime = int(time.time() - started_at)
        theme.info(
            f"Guard interrupted after {uptime}s uptime, "
            f"{state.request_count} request(s) handled, "
            f"admitted={'yes' if state.admitted else 'no'}."
        )
    except Exception as exc:  # noqa: BLE001 — honest crash reporting, then re-raise-free exit
        reason = f"crashed: {type(exc).__name__}"
        theme.error(f"Guard crashed: {exc}")
    finally:
        _write_last_guard_state(
            reason, started_at, state.request_count, path=effective_last
        )
        _release_admitted_handles(state)
        state.admitted = None
        state.secrets.clear()
        clear_guard_lock(path=effective_lock)
        if registry_vault is not None:
            try:
                remove_guard_registry_entry(registry_vault)
            except OSError:
                pass
        try:
            listener.close()
        except Exception:
            pass
    return 0
