"""Real spawned-process security tests for kernel-verified peer identity.

`test_guard_admission.py` mocks `peer_identity.get_ancestor_chain` to keep
unit tests fast and deterministic. These tests do the opposite: they spawn
*genuine* OS processes and exercise the real, platform-specific kernel
lookups in `peer_identity.py` (and, for the guard-level tests, the real IPC
+ `guard_handle_message` path) end to end. The security property under
test: a real *sibling* process must never be silently trusted just because
it happens to share a distant common ancestor with an admitted one; a real
*child* process of an admitted one must be recognized without a prompt.

Every subprocess spawned here sleeps briefly so its pid/start-time stay
queryable for the duration of the assertion, then is terminated in a
`finally` block.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time

import pytest

from key_amnesia import ipc
from key_amnesia.guard import GuardState, guard_handle_message
from key_amnesia.peer_identity import get_ancestor_chain, is_in_admitted_tree

pytestmark = pytest.mark.slow

SLEEP_SCRIPT = "import time; time.sleep(30)"


def _identity_of(pid: int):
    """A living pid's own `PeerIdentity`, via the same public lookup
    `is_in_admitted_tree` itself uses — never a private, platform-specific
    helper reached into directly from a test."""
    chain = get_ancestor_chain(pid, max_depth=1)
    assert chain, f"could not read kernel identity for live pid {pid}"
    return chain[0]


def _spawn_sleeper() -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-c", SLEEP_SCRIPT])


def _kill(proc: subprocess.Popen) -> None:
    try:
        proc.kill()
        proc.wait(timeout=5)
    except Exception:
        pass


@pytest.mark.skipif(
    sys.platform not in ("win32",) and not sys.platform.startswith("linux"),
    reason="kernel peer identity only implemented for Windows and Linux",
)
def test_sibling_process_is_never_silently_admitted() -> None:
    """Two independent processes spawned by the same parent share a common
    ancestor (this test process) — but neither is a descendant of the
    other, so admitting one must never silently admit the other."""
    proc_a = _spawn_sleeper()
    proc_b = _spawn_sleeper()
    try:
        identity_a = _identity_of(proc_a.pid)
        identity_b = _identity_of(proc_b.pid)
        assert not is_in_admitted_tree([identity_a], identity_b)
        assert not is_in_admitted_tree([identity_b], identity_a)
    finally:
        _kill(proc_a)
        _kill(proc_b)


@pytest.mark.skipif(
    sys.platform not in ("win32",) and not sys.platform.startswith("linux"),
    reason="kernel peer identity only implemented for Windows and Linux",
)
def test_child_process_is_recognized_as_real_descendant() -> None:
    """A genuine OS child of an admitted process is silently in-tree."""
    child = _spawn_sleeper()
    try:
        parent_identity = _identity_of(os.getpid())
        child_identity = _identity_of(child.pid)
        assert is_in_admitted_tree([parent_identity], child_identity)
    finally:
        _kill(child)


@pytest.mark.skipif(
    sys.platform not in ("win32",) and not sys.platform.startswith("linux"),
    reason="kernel peer identity only implemented for Windows and Linux",
)
def test_grandchild_process_is_recognized_via_ancestor_walk() -> None:
    """A two-hop descendant (child's child) is still recognized — the walk
    isn't limited to immediate children."""
    spawn_grandchild_script = (
        "import subprocess, sys, time\n"
        f"gc = subprocess.Popen([sys.executable, '-c', {SLEEP_SCRIPT!r}])\n"
        "print(gc.pid, flush=True)\n"
        "time.sleep(30)\n"
    )
    child = subprocess.Popen(
        [sys.executable, "-c", spawn_grandchild_script],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        line = child.stdout.readline().strip()
        assert line, "child never reported its own spawned grandchild pid"
        grandchild_pid = int(line)

        child_identity = _identity_of(child.pid)
        grandchild_identity = _identity_of(grandchild_pid)
        assert is_in_admitted_tree([child_identity], grandchild_identity)
    finally:
        _kill(child)
        try:
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(grandchild_pid)],
                    capture_output=True,
                )
            else:
                os.kill(grandchild_pid, 9)
        except Exception:
            pass


def _guard_state(**overrides) -> GuardState:
    kwargs = dict(
        secrets={"api_key": "super-secret-value-123"},
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"e" * 32,
    )
    kwargs.update(overrides)
    return GuardState(**kwargs)


@pytest.mark.skipif(
    sys.platform not in ("win32",) and not sys.platform.startswith("linux"),
    reason="kernel peer identity only implemented for Windows and Linux",
)
def test_guard_e2e_admits_real_child_process_without_reprompt(ka_home, tmp_path) -> None:
    """Full IPC + admission path, real spawned client: a genuine child of
    an already-admitted process connects to a live guard and is served
    without any prompt at all."""
    listener, address, authkey = ipc.start_listener()
    state = _guard_state(address=address, authkey=authkey)
    # Pre-admit *this test process's own* identity — the real client below
    # is a genuine OS child of it, spawned after this point.
    from key_amnesia.guard import AdmittedSession

    state.admitted = AdmittedSession(
        identities=[_identity_of(os.getpid())],
        first_seen="2026-01-01T00:00:00+00:00",
        unscoped=True,
        granted_until=state.expires_at,
    )

    def fail_if_called(*_a, **_k):
        raise AssertionError("real descendant of an admitted process must not be prompted")

    result: dict = {}

    def serve_one() -> None:
        conn = listener.accept()
        try:
            from key_amnesia import peer_identity

            msg = ipc.recv_msg(conn, timeout=10)
            peer = peer_identity.get_peer_identity(conn)
            reply = guard_handle_message(
                msg, state, peer=peer, admit_prompt=fail_if_called
            )
            ipc.send_msg(conn, reply)
            result["reply"] = reply
        finally:
            conn.close()

    t = threading.Thread(target=serve_one, daemon=True)
    t.start()

    client_script = (
        "import sys\n"
        "from key_amnesia import ipc\n"
        f"conn = ipc.connect({address!r}, bytes.fromhex({authkey.hex()!r}))\n"
        "ipc.send_msg(conn, {'verb': 'list'})\n"
        "reply = ipc.recv_msg(conn, timeout=10)\n"
        "sys.stdout.write('ok' if reply.get('ok') else 'denied')\n"
        "conn.close()\n"
    )
    client = subprocess.run(
        [sys.executable, "-c", client_script],
        capture_output=True,
        text=True,
        timeout=15,
    )
    t.join(timeout=10)
    listener.close()

    assert client.stdout.strip() == "ok", client.stderr
    assert result.get("reply", {}).get("ok") is True
    assert result["reply"]["names"] == ["api_key"]


@pytest.mark.skipif(
    sys.platform not in ("win32",) and not sys.platform.startswith("linux"),
    reason="kernel peer identity only implemented for Windows and Linux",
)
def test_guard_e2e_denies_unrelated_real_process_without_consent(ka_home) -> None:
    """A real, unrelated spawned process reaching the guard is never
    silently admitted — it is gated by the consent prompt like any other
    unrecognized peer, and denied here to prove there is no silent bypass."""
    listener, address, authkey = ipc.start_listener()
    state = _guard_state(address=address, authkey=authkey)
    # Admit a decoy sibling process's identity — unrelated to the real
    # client spawned below, so the client must not match its tree.
    decoy = _spawn_sleeper()
    try:
        from key_amnesia.guard import AdmittedSession

        state.admitted = AdmittedSession(
            identities=[_identity_of(decoy.pid)],
            first_seen="2026-01-01T00:00:00+00:00",
            unscoped=True,
            granted_until=state.expires_at,
        )

        prompted = {"n": 0}

        def deny(*_a, **_k):
            prompted["n"] += 1
            return False

        result: dict = {}

        def serve_one() -> None:
            conn = listener.accept()
            try:
                from key_amnesia import peer_identity

                msg = ipc.recv_msg(conn, timeout=10)
                peer = peer_identity.get_peer_identity(conn)
                reply = guard_handle_message(msg, state, peer=peer, admit_prompt=deny)
                ipc.send_msg(conn, reply)
                result["reply"] = reply
            finally:
                conn.close()

        t = threading.Thread(target=serve_one, daemon=True)
        t.start()

        client_script = (
            "import sys\n"
            "from key_amnesia import ipc\n"
            f"conn = ipc.connect({address!r}, bytes.fromhex({authkey.hex()!r}))\n"
            "ipc.send_msg(conn, {'verb': 'list'})\n"
            "reply = ipc.recv_msg(conn, timeout=10)\n"
            "sys.stdout.write('ok' if reply.get('ok') else 'denied')\n"
            "conn.close()\n"
        )
        client = subprocess.run(
            [sys.executable, "-c", client_script],
            capture_output=True,
            text=True,
            timeout=15,
        )
        t.join(timeout=10)
        listener.close()

        assert client.stdout.strip() == "denied", client.stderr
        assert prompted["n"] == 1  # gated by consent, not silently allowed or blocked
        assert result.get("reply", {}).get("ok") is False
        assert "super-secret-value-123" not in str(result.get("reply"))
    finally:
        _kill(decoy)
