"""Linux SO_PEERCRED uid check — fail closed on foreign uid."""

from __future__ import annotations

import os
import socket
import struct
import sys
from unittest.mock import MagicMock

import pytest

from key_amnesia import peer_identity


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="SO_PEERCRED uid check is Linux-only",
)
def test_peercred_foreign_uid_fails_closed(monkeypatch) -> None:
    """Kernel uid != geteuid → get_peer_identity returns None (fail closed)."""
    foreign_uid = os.geteuid() + 1
    raw = struct.pack("3i", os.getpid(), foreign_uid, 0)

    class FakeSock:
        def getsockopt(self, *a, **k):
            return raw

        def detach(self):
            pass

    monkeypatch.setattr(socket, "socket", lambda *a, **k: FakeSock())
    conn = MagicMock()
    conn.fileno.return_value = 3
    assert peer_identity.get_peer_identity(conn) is None
