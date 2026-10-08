"""Shared fixtures for key-amnesia tests. Always use tmp_path."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from key_amnesia.peer_identity import PeerIdentity


def assert_ka_paths_isolated(tmp_path: Path) -> None:
    """Fail loudly if vault/audit/lock resolve outside pytest's tmp root.

    Belt-and-braces for Defect 1: a silent regression that points
    KEY_AMNESIA_HOME at a real home must not be able to pass the suite.
    """
    from key_amnesia.paths import audit_log_path, data_dir, guard_lock_path

    root = tmp_path.resolve()
    checks = (
        ("data_dir", data_dir()),
        ("audit_log_path", audit_log_path()),
        ("guard_lock_path", guard_lock_path()),
    )
    for label, path in checks:
        resolved = path.resolve()
        if not resolved.is_relative_to(root):
            pytest.fail(
                f"KEY_AMNESIA {label} resolved outside pytest tmp: {resolved} "
                f"(expected under {root})"
            )


def stub_interactive_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both streams must look like a TTY for inline auth (0.4.4 dual-stream)."""
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)


@pytest.fixture
def stub_peer_identity(monkeypatch: pytest.MonkeyPatch) -> PeerIdentity:
    """Stand-in kernel peer for tests that exercise real IPC admission.

    Product `get_peer_identity` returns `None` on macOS (fail closed). Tests
    that need a successful admit/lock/run path over a live listener request
    this fixture so the lookup returns a stable identity for this process —
    product code stays fail-closed on unsupported platforms.
    """
    peer = PeerIdentity(pid=os.getpid(), start_time=1)

    def _fake_get_peer_identity(_conn=None) -> PeerIdentity:
        return PeerIdentity(pid=os.getpid(), start_time=1)

    monkeypatch.setattr(
        "key_amnesia.peer_identity.get_peer_identity", _fake_get_peer_identity
    )
    return peer


@pytest.fixture(autouse=True)
def ka_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect KEY_AMNESIA_HOME under pytest tmp — never ~/.key-amnesia."""
    home = tmp_path / "ka-home"
    home.mkdir()
    monkeypatch.setenv("KEY_AMNESIA_HOME", str(home))
    monkeypatch.delenv("KEY_AMNESIA_VAULT_PATH", raising=False)
    assert_ka_paths_isolated(tmp_path)
    return home


@pytest.fixture(autouse=True)
def block_real_isolated_console(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never open a real CREATE_NEW_CONSOLE / Terminal window during pytest.

    Agent harnesses often look non-TTY on stdout, so `require_human_auth`
    takes the spawned-console path. Without this guard the suite pops real
    password windows on the developer's desktop.

    When *popen_fn* is omitted we still call the real platform helper, but
    with a popen that refuses to exec — so headless Linux/macOS fail-closed
    messages (no DISPLAY, etc.) stay product-shaped, while Windows never
    opens a console. Tests that need a successful spawn pass `popen_fn=`.
    """
    from key_amnesia import platform as platform_mod
    from key_amnesia import prompt_route as prompt_route_mod

    real = platform_mod.spawn_isolated_console

    def _blocked_popen(*_a, **_k):
        raise OSError(
            "pytest blocked real isolated-console spawn; "
            "pass popen_fn= to require_human_auth or mock spawn_isolated_console"
        )

    def _guarded(cmd, env, *, popen_fn=None, confirm_started=None):
        return real(
            cmd,
            env,
            popen_fn=popen_fn or _blocked_popen,
            confirm_started=confirm_started,
        )

    monkeypatch.setattr(platform_mod, "spawn_isolated_console", _guarded)
    monkeypatch.setattr(prompt_route_mod, "spawn_isolated_console", _guarded)


@pytest.fixture
def password() -> str:
    return "test-master-password-敏感"


@pytest.fixture
def seeded_vault(ka_home: Path, password: str) -> Path:
    from key_amnesia.vault import save_vault

    vault = ka_home / "vault.bin"
    save_vault(
        vault,
        password,
        {
            "secrets": {
                "api_key": "super-secret-value-123",
                "db_pass": "p@ssw0rd!.*+?[]{}",
                "token": "tok_abc_xyz",
            },
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
    )
    return vault
