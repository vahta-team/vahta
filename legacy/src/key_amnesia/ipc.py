"""Named-pipe IPC via multiprocessing.connection — authkey only.

No session_key / no payload SecretBox. Authkey authentication alone defines
the trust boundary. Master password never appears on this channel.
"""

from __future__ import annotations

import os
import secrets
import sys
from multiprocessing.connection import Client, Connection, Listener
from typing import Any


def make_authkey() -> bytes:
    return secrets.token_bytes(32)


def make_pipe_address() -> str:
    """Return a platform-appropriate listener address."""
    token = secrets.token_hex(8)
    if sys.platform == "win32":
        return rf"\\.\pipe\key-amnesia-{token}"
    # POSIX: AF_UNIX abstract/path via tempfile-like name under /tmp
    return f"/tmp/key-amnesia-{token}.sock"


def start_listener(address: str | None = None, authkey: bytes | None = None) -> tuple[Listener, str, bytes]:
    addr = address or make_pipe_address()
    key = authkey if authkey is not None else make_authkey()
    # family=None lets multiprocessing pick based on address form
    listener = Listener(addr, authkey=key)
    return listener, addr, key


def connect(address: str, authkey: bytes, timeout: float | None = None) -> Connection:
    # Client accepts address + authkey; timeout via connect retry is caller's concern
    kwargs: dict[str, Any] = {"authkey": authkey}
    if timeout is not None and sys.version_info >= (3, 11):
        # Python 3.11+ Client supports timeout on some platforms; keep portable.
        pass
    return Client(address, **kwargs)


def send_msg(conn: Connection, msg: dict[str, Any]) -> None:
    """Send a message. Never include password or raw secret values."""
    conn.send(msg)


def recv_msg(conn: Connection, timeout: float | None = None) -> dict[str, Any]:
    if timeout is not None:
        if not conn.poll(timeout):
            raise TimeoutError("IPC receive timed out")
    msg = conn.recv()
    if not isinstance(msg, dict):
        raise TypeError("IPC message must be a dict")
    return msg


def authkey_to_hex(authkey: bytes) -> str:
    return authkey.hex()


def authkey_from_hex(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)
