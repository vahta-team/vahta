"""Kernel-verified peer process identity for guard admission.

Replaces the pre-0.3.8 model where admission trusted a message-supplied
`claimed_pid_unverified` (formerly `caller_pid`) plus a machine-global
bearer token file (`admitted_session.token`) — after one approval, *any*
same-user process that could read that file was admitted. This module
instead asks the **kernel** who is on the other end of the already-
authenticated IPC connection:

- Windows: `GetNamedPipeClientProcessId` on the connected pipe handle,
  then an **immediate** `OpenProcess` + `GetProcessTimes` on that bare pid.
  For the peer that will be *admitted*, that `OpenProcess` handle is
  **held for the admission lifetime** — while a handle to the process
  object is open, Windows will not recycle that PID. Residual race: only
  the brief window between `GetNamedPipeClientProcessId` and `OpenProcess`
  itself (documented, not eliminated — see DESIGN.md / README).
  Ancestor-chain walks still open-read-close (they are not the admitted
  root and do not need a long-lived handle).
- Linux: `SO_PEERCRED` on the connected socket (kernel-verified pid/uid/gid
  at accept time — considerably stronger than the Windows path). The kernel
  uid is compared to `os.geteuid()` and a mismatch raises
  `PeerIdentityError` (fail-closed `None` from `get_peer_identity`); then an
  immediate `/proc/<pid>/stat` read for the same creation-time comparison.
- Anything else (macOS, unknown platforms): unsupported — returns `None`,
  which callers must treat as an unrecognized peer (fail closed), exactly
  like the rest of this project's isolated-console spawn story.

Never trust message fields for identity — a `claimed_pid_unverified` in
the IPC payload is attacker-controlled and is not read by anything in
this module.
"""

from __future__ import annotations

import os
import struct
import sys
from dataclasses import dataclass, field
from multiprocessing.connection import Connection

# Bound on how many parent hops we're willing to walk. Real process trees
# are shallow (a handful of levels); this just stops a pathological/cyclic
# parent chain from spinning forever.
MAX_ANCESTOR_DEPTH = 32

# `--admit-tree` offer limits (see DESIGN.md "Process-tree ancestry admission").
MAX_OFFERED_ANCESTORS = 8
ANCESTOR_FLOOR_TAIL = 2


class PeerIdentityError(Exception):
    """Kernel peer-identity lookup failed — callers must treat this as an
    unrecognized peer, never fall back to a message-supplied pid."""


def platform_min_pid() -> int:
    """Refuse admitting roots at or below this pid (session/init/System)."""
    if sys.platform == "win32":
        return 4  # System
    return 1  # init


@dataclass
class _WinProcessHandle:
    """Owned Windows `OpenProcess` HANDLE — closed exactly once.

    Holding this open for an admitted peer prevents Windows from recycling
    that PID for the lifetime of the admission (the residual race is only
    the brief window *before* OpenProcess succeeds — see module docstring).
    """

    handle: int
    _closed: bool = False

    def close(self) -> None:
        if self._closed or not self.handle:
            return
        import ctypes

        ctypes.windll.kernel32.CloseHandle(self.handle)  # type: ignore[attr-defined]
        self._closed = True

    def __del__(self) -> None:  # pragma: no cover — best-effort GC cleanup
        try:
            self.close()
        except Exception:
            pass


@dataclass(frozen=True)
class PeerIdentity:
    """A kernel-verified `(pid, start_time)` pair — the unit of admission trust.

    `start_time` is only meaningful compared against another `PeerIdentity`
    captured the same way on the same machine (Windows: FILETIME 100ns
    ticks since 1601 from `GetProcessTimes`; Linux: clock ticks since boot,
    field 22 of `/proc/<pid>/stat`) — never format it for a human and never
    compare instances captured on different platforms.

    On Windows, `process_handle` may hold an open `OpenProcess` HANDLE for
    the admission lifetime (peer from `get_peer_identity` only). Call
    `release()` when the admission ends. Ancestor-walk identities do not
    hold a handle. Not part of equality / hashing.
    """

    pid: int
    start_time: int
    process_handle: _WinProcessHandle | None = field(
        default=None, compare=False, hash=False, repr=False
    )

    def matches(self, other: "PeerIdentity") -> bool:
        return self.pid == other.pid and self.start_time == other.start_time

    def release(self) -> None:
        """Drop any held OS process handle (Windows admission root only)."""
        if self.process_handle is not None:
            self.process_handle.close()


# --- Windows ---------------------------------------------------------------

_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def _win_process_times(handle: int) -> int:
    import ctypes

    creation = ctypes.c_ulonglong(0)
    exit_t = ctypes.c_ulonglong(0)
    kernel_t = ctypes.c_ulonglong(0)
    user_t = ctypes.c_ulonglong(0)
    ok = ctypes.windll.kernel32.GetProcessTimes(  # type: ignore[attr-defined]
        ctypes.c_void_p(handle),
        ctypes.byref(creation),
        ctypes.byref(exit_t),
        ctypes.byref(kernel_t),
        ctypes.byref(user_t),
    )
    if not ok:
        raise PeerIdentityError("GetProcessTimes failed")
    return int(creation.value)


def _win_identity_for_pid(pid: int, *, hold: bool = False) -> PeerIdentity:
    """Open *pid* immediately and read its creation time from that handle.

    When *hold* is True (connecting peer about to be admitted), the
    OpenProcess HANDLE is retained on the returned `PeerIdentity` for the
    admission lifetime — Windows will not recycle that PID while the handle
    stays open. Ancestor-chain walks use hold=False (open-read-close).
    """
    import ctypes

    handle = ctypes.windll.kernel32.OpenProcess(  # type: ignore[attr-defined]
        _PROCESS_QUERY_LIMITED_INFORMATION, False, pid
    )
    if not handle:
        raise PeerIdentityError(f"OpenProcess failed for pid {pid}")
    try:
        start_time = _win_process_times(handle)
    except Exception:
        ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]
        raise
    if hold:
        return PeerIdentity(
            pid=pid,
            start_time=start_time,
            process_handle=_WinProcessHandle(handle=int(handle)),
        )
    ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]
    return PeerIdentity(pid=pid, start_time=start_time)


def _win_get_peer_identity(conn: Connection) -> PeerIdentity:
    import ctypes

    handle = conn.fileno()  # HANDLE of the connected named pipe (server end)
    client_pid = ctypes.c_ulong(0)
    ok = ctypes.windll.kernel32.GetNamedPipeClientProcessId(  # type: ignore[attr-defined]
        ctypes.c_void_p(handle), ctypes.byref(client_pid)
    )
    if not ok:
        raise PeerIdentityError("GetNamedPipeClientProcessId failed")
    # Hold the process handle for admission lifetime (plan A1).
    return _win_identity_for_pid(int(client_pid.value), hold=True)


def _win_ppid_map() -> dict[int, int]:
    """One-shot `{pid: ppid}` map from a single process snapshot.

    `th32ParentProcessID` is recorded once at process creation and is never
    updated by Windows if the real parent later exits — a stale/possibly
    recycled ppid is an accepted, documented residual limit (see
    DESIGN.md), not something this function can detect on its own.
    """
    import ctypes
    from ctypes import wintypes

    TH32CS_SNAPPROCESS = 0x00000002
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_char * 260),
        ]

    snap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)  # type: ignore[attr-defined]
    if snap in (0, INVALID_HANDLE_VALUE, None):
        return {}
    try:
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        if not ctypes.windll.kernel32.Process32First(snap, ctypes.byref(entry)):  # type: ignore[attr-defined]
            return {}
        out: dict[int, int] = {}
        while True:
            out[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
            if not ctypes.windll.kernel32.Process32Next(snap, ctypes.byref(entry)):  # type: ignore[attr-defined]
                break
        return out
    finally:
        ctypes.windll.kernel32.CloseHandle(snap)  # type: ignore[attr-defined]


def _win_ancestor_chain(pid: int, max_depth: int) -> list[PeerIdentity]:
    """Walk parents using one CreateToolhelp32Snapshot; start_time via OpenProcess.

    Snapshot once → `{pid: ppid}` map, then walk in memory. Per-node
    `(pid, start_time)` still comes from `_win_identity_for_pid` (OpenProcess
    + GetProcessTimes), not from the snapshot. Residual caveat:
    `th32ParentProcessID` is fixed at creation time (see `_win_ppid_map`).
    """
    ppid_by_pid = _win_ppid_map()
    chain: list[PeerIdentity] = []
    seen: set[int] = set()
    current: int | None = pid
    for _ in range(max_depth):
        if not current or current in seen:
            break
        seen.add(current)
        try:
            chain.append(_win_identity_for_pid(current))
        except PeerIdentityError:
            break
        parent = ppid_by_pid.get(current)
        if parent is None or parent == current:
            break
        current = parent
    return chain


# --- Linux -------------------------------------------------------------


def _read_proc_stat(pid: int) -> tuple[int, int]:
    """Return `(ppid, start_time_ticks)` for *pid* from `/proc/<pid>/stat`."""
    with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as f:
        content = f.read()
    # `comm` (field 2) is parenthesized and may itself contain ")" or
    # spaces — split on the *last* ')' to get past it reliably.
    rparen = content.rfind(")")
    if rparen == -1:
        raise PeerIdentityError(f"unparseable /proc/{pid}/stat")
    rest = content[rparen + 1 :].split()
    # rest[0] = state (field 3); ppid is field 4 -> rest[1]; starttime is
    # field 22 -> rest[19].
    if len(rest) <= 19:
        raise PeerIdentityError(f"unexpected /proc/{pid}/stat field count")
    ppid = int(rest[1])
    start_time = int(rest[19])
    return ppid, start_time


def _linux_identity_for_pid(pid: int) -> PeerIdentity:
    try:
        _ppid, start_time = _read_proc_stat(pid)
    except (OSError, ValueError) as e:
        raise PeerIdentityError(str(e)) from e
    return PeerIdentity(pid=pid, start_time=start_time)


def _linux_get_peer_identity(conn: Connection) -> PeerIdentity:
    import socket

    fd = conn.fileno()
    sock = socket.socket(fileno=fd)
    try:
        raw = sock.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
    except OSError as e:
        raise PeerIdentityError(f"SO_PEERCRED failed: {e}") from e
    finally:
        sock.detach()  # never close the caller's fd
    pid, uid, _gid = struct.unpack("3i", raw)
    euid = os.geteuid()
    if uid != euid:
        raise PeerIdentityError(
            f"SO_PEERCRED uid {uid} != geteuid {euid}"
        )
    return _linux_identity_for_pid(pid)


def _linux_ancestor_chain(pid: int, max_depth: int) -> list[PeerIdentity]:
    chain: list[PeerIdentity] = []
    seen: set[int] = set()
    current: int | None = pid
    for _ in range(max_depth):
        if not current or current in seen:
            break
        seen.add(current)
        try:
            ppid, start_time = _read_proc_stat(current)
        except (OSError, ValueError):
            break
        chain.append(PeerIdentity(pid=current, start_time=start_time))
        if not ppid or ppid == current:
            break
        current = ppid
    return chain


# --- Public API --------------------------------------------------------


def get_peer_identity(conn: Connection) -> PeerIdentity | None:
    """Kernel-verified identity of the process on the other end of *conn*.

    Returns `None` on any failure (unsupported platform, lookup error) —
    callers must treat that as an unrecognized/untrusted peer, never as
    "skip the check".
    """
    try:
        if sys.platform == "win32":
            return _win_get_peer_identity(conn)
        if sys.platform.startswith("linux"):
            return _linux_get_peer_identity(conn)
    except (PeerIdentityError, OSError, ValueError):
        return None
    return None  # macOS / other: not yet supported, fail closed


def get_ancestor_chain(pid: int, max_depth: int = MAX_ANCESTOR_DEPTH) -> list[PeerIdentity]:
    """`[pid's own identity, parent's, grandparent's, ...]`, best-effort.

    Stops at an unreadable/exited process, pid 0, a repeated pid (cycle
    guard), or `max_depth`. Never raises — an unwalkable chain is simply
    short (down to a single entry, or empty if *pid* itself is already
    gone), which callers treat as "nothing else to check".
    """
    try:
        if sys.platform == "win32":
            return _win_ancestor_chain(pid, max_depth)
        if sys.platform.startswith("linux"):
            return _linux_ancestor_chain(pid, max_depth)
    except OSError:
        return []
    return []


def is_in_admitted_tree(admitted: list[PeerIdentity], peer: PeerIdentity) -> bool:
    """True if *peer* is one of `admitted`, or a real OS descendant of one.

    Walks *peer's own* ancestor chain (parent, grandparent, ...) and checks
    for an exact `(pid, start_time)` match against the admitted set — never
    the reverse (we do not walk up from the admitted identity), so two
    unrelated processes that merely share a distant common ancestor (e.g.
    the same login shell or, in tests, the same test runner) are never
    confused for one being a descendant of the other.
    """
    if any(peer.matches(a) for a in admitted):
        return True
    admitted_set = {(a.pid, a.start_time) for a in admitted}
    for node in get_ancestor_chain(peer.pid)[1:]:
        if (node.pid, node.start_time) in admitted_set:
            return True
    return False


def get_process_image_name(pid: int) -> str | None:
    """Best-effort executable basename for *pid*, or None if unreadable."""
    try:
        if sys.platform == "win32":
            return _win_process_image_name(pid)
        if sys.platform.startswith("linux"):
            return _linux_process_image_name(pid)
    except (OSError, ValueError, PeerIdentityError):
        return None
    return None


def hold_identity(ident: PeerIdentity) -> PeerIdentity:
    """Ensure *ident* holds a Windows OpenProcess pin for admission lifetime.

    If a handle is already held, return *ident* unchanged. Otherwise reopen
    via `_win_identity_for_pid(..., hold=True)` and require the creation
    time still matches (pid-reuse guard). Non-Windows: return unchanged.
    """
    if sys.platform != "win32":
        return ident
    if ident.process_handle is not None and not ident.process_handle._closed:
        return ident
    held = _win_identity_for_pid(ident.pid, hold=True)
    if held.start_time != ident.start_time:
        held.release()
        raise PeerIdentityError(
            f"pid {ident.pid} start_time changed while opening hold handle "
            f"(possible recycle)"
        )
    return held


def ancestor_owned_by_self(ident: PeerIdentity) -> bool:
    """True if *ident* is owned by this process's effective user.

    Linux: `/proc/<pid>/status` Uid vs `geteuid()`. Windows: successful
    `OpenProcess(QUERY_LIMITED)` is treated as same-user visibility; failure
    refuses the level (fail closed).
    """
    try:
        if sys.platform.startswith("linux"):
            return _linux_owned_by_self(ident.pid)
        if sys.platform == "win32":
            return _win_owned_by_self(ident.pid)
    except (OSError, ValueError, PeerIdentityError):
        return False
    return False


def classify_admit_tree_levels(
    chain: list[PeerIdentity],
) -> tuple[list[PeerIdentity], list[tuple[PeerIdentity, str]]]:
    """Split *chain* into (offerable, skipped_with_reason) for `--admit-tree`.

    Never offers the last `ANCESTOR_FLOOR_TAIL` entries of the full chain
    (except the connecting peer at index 0 is never floored out), nor pids
    at or below `platform_min_pid()`, nor foreign-owned processes. Caps the
    offer list at `MAX_OFFERED_ANCESTORS`.
    """
    offerable: list[PeerIdentity] = []
    skipped: list[tuple[PeerIdentity, str]] = []
    min_pid = platform_min_pid()
    floor_cut = len(chain) - ANCESTOR_FLOOR_TAIL
    for i, node in enumerate(chain):
        if i >= floor_cut and i > 0:
            skipped.append(
                (node, "too close to session/init (depth floor)"),
            )
            continue
        if node.pid <= min_pid:
            skipped.append((node, f"pid <= {min_pid} (platform minimum)"))
            continue
        if not ancestor_owned_by_self(node):
            skipped.append((node, "not owned by this user"))
            continue
        if len(offerable) >= MAX_OFFERED_ANCESTORS:
            skipped.append((node, "beyond max offered ancestors"))
            continue
        offerable.append(node)
    return offerable, skipped


def _win_process_image_name(pid: int) -> str | None:
    import ctypes
    from ctypes import wintypes

    handle = ctypes.windll.kernel32.OpenProcess(  # type: ignore[attr-defined]
        _PROCESS_QUERY_LIMITED_INFORMATION, False, pid
    )
    if not handle:
        return None
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buf))
        # QueryFullProcessImageNameW — kernel32 on Vista+
        ok = ctypes.windll.kernel32.QueryFullProcessImageNameW(  # type: ignore[attr-defined]
            ctypes.c_void_p(handle), 0, buf, ctypes.byref(size)
        )
        if not ok:
            return None
        path = buf.value or ""
        if not path:
            return None
        return path.rsplit("\\", 1)[-1] or path
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]


def _linux_process_image_name(pid: int) -> str | None:
    try:
        target = os.readlink(f"/proc/{pid}/exe")
        if target:
            return target.rsplit("/", 1)[-1] or target
    except OSError:
        pass
    try:
        with open(f"/proc/{pid}/comm", "r", encoding="utf-8") as f:
            name = f.read().strip()
            return name or None
    except OSError:
        return None


def _linux_owned_by_self(pid: int) -> bool:
    with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("Uid:"):
                parts = line.split()
                # real, effective, saved, fs
                if len(parts) < 3:
                    return False
                return int(parts[2]) == os.geteuid()
    return False


def _win_owned_by_self(pid: int) -> bool:
    """Best-effort: OpenProcess QUERY_LIMITED succeeding ⇒ treat as same-user."""
    import ctypes

    handle = ctypes.windll.kernel32.OpenProcess(  # type: ignore[attr-defined]
        _PROCESS_QUERY_LIMITED_INFORMATION, False, pid
    )
    if not handle:
        return False
    ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]
    return True
