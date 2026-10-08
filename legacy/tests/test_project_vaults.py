"""Project vaults + merge + registry (PR3 / 0.3.10).

Always uses throwaway KEY_AMNESIA_HOME via the `ka_home` fixture — never
the maintainer's real vault.
"""

from __future__ import annotations

import getpass
import json
import time
from pathlib import Path

import pytest

from key_amnesia import vault as vault_mod
from key_amnesia.cli import main
from key_amnesia.guard import (
    AdmittedSession,
    GuardState,
    VaultSource,
    guard_handle_message,
    list_guard_registry_entries,
    remove_guard_registry_entry,
    write_guard_registry_entry,
)
from key_amnesia.paths import guard_lock_path_for_vault, guards_registry_dir
from key_amnesia.peer_identity import PeerIdentity
from key_amnesia.project import (
    ensure_project_scaffold,
    find_project_root,
    load_project_config,
    merge_secret_maps,
    project_vault_path,
    resolve_vault_context,
)


PEER = PeerIdentity(pid=4242, start_time=1000)


def _make_project(tmp_path: Path, *, use_global: bool = True) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    ensure_project_scaffold(root, use_global=use_global)
    return root


def test_find_project_root_walks_up(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _make_project(tmp_path)
    nested = root / "a" / "b"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    assert find_project_root() == root.resolve()


def test_find_project_root_stops_at_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    # Put .amnesia above the home boundary so walk must not find it when
    # cwd is under fake home with no .amnesia.
    (tmp_path / ".amnesia").mkdir()
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    monkeypatch.chdir(home)
    assert find_project_root() is None


def test_init_project_creates_vault_config_gitignore(
    ka_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    proj = tmp_path / "myproj"
    proj.mkdir()
    monkeypatch.chdir(proj)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    pw = "project-master-pw"
    answers = iter([pw, pw])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))

    rc = main(["init", "--project"])
    assert rc == 0
    vp = proj / ".amnesia" / "vault.bin"
    assert vp.exists()
    cfg = load_project_config(proj)
    assert cfg.get("use_global") is True
    gi = (proj / ".gitignore").read_text(encoding="utf-8")
    assert ".amnesia/" in gi
    payload = vault_mod.load_vault(vp, pw)
    assert payload["secrets"] == {}


def test_init_project_env_path(
    ka_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proj = tmp_path / "myproj"
    proj.mkdir()
    monkeypatch.chdir(proj)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    pw = "env-pw"
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": pw)

    rc = main(["init", "--project", "--env", "staging"])
    assert rc == 0
    assert (proj / ".amnesia" / "envs" / "staging" / "vault.bin").exists()


def test_resolve_defaults_to_global_without_project(
    ka_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ka_home)
    ctx = resolve_vault_context()
    assert ctx.project_root is None
    assert ctx.vault_path == ka_home / "vault.bin"
    assert not ctx.merge_with_global


def test_resolve_project_merge_when_global_exists(
    ka_home: Path, tmp_path: Path, password: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Seed global vault
    vault_mod.save_vault(
        ka_home / "vault.bin",
        password,
        {"secrets": {"GLOBAL_ONLY": "g", "SHARED": "from-global"}},
    )
    proj = _make_project(tmp_path, use_global=True)
    pvp = project_vault_path(proj)
    vault_mod.save_vault(
        pvp,
        "proj-pw",
        {"secrets": {"PROJ_ONLY": "p", "SHARED": "from-project"}},
    )
    monkeypatch.chdir(proj)
    ctx = resolve_vault_context()
    assert ctx.project_root == proj.resolve()
    assert ctx.vault_path == pvp.resolve() or ctx.vault_path == pvp
    assert ctx.merge_with_global is True
    assert ctx.global_vault_path is not None


def test_resolve_no_global_flag(
    ka_home: Path, tmp_path: Path, password: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault_mod.save_vault(
        ka_home / "vault.bin", password, {"secrets": {"G": "1"}}
    )
    proj = _make_project(tmp_path, use_global=True)
    vault_mod.save_vault(
        project_vault_path(proj), "proj-pw", {"secrets": {"P": "1"}}
    )
    monkeypatch.chdir(proj)
    ctx = resolve_vault_context(no_global=True)
    assert ctx.merge_with_global is False


def test_resolve_force_global(
    ka_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proj = _make_project(tmp_path)
    monkeypatch.chdir(proj)
    ctx = resolve_vault_context(force_global=True)
    assert ctx.project_root is None
    assert ctx.force_global is True
    assert ctx.vault_path == ka_home / "vault.bin"


def test_merge_secret_maps_project_wins() -> None:
    merged = merge_secret_maps(
        {"A": "g", "SHARED": "g"},
        {"B": "p", "SHARED": "p"},
    )
    assert merged == {"A": "g", "B": "p", "SHARED": "p"}


def test_guard_reload_covers_all_merged_sources(
    ka_home: Path, password: str, tmp_path: Path
) -> None:
    global_v = ka_home / "vault.bin"
    vault_mod.save_vault(
        global_v, password, {"secrets": {"G": "gv1", "SHARED": "g"}}
    )
    proj = _make_project(tmp_path, use_global=True)
    proj_v = project_vault_path(proj)
    proj_pw = "proj-password"
    vault_mod.save_vault(
        proj_v, proj_pw, {"secrets": {"P": "pv1", "SHARED": "p"}}
    )

    g_payload, g_key = vault_mod.load_vault_with_key(global_v, password)
    p_payload, p_key = vault_mod.load_vault_with_key(proj_v, proj_pw)
    sources = [
        VaultSource(
            path=global_v,
            key=g_key,
            fingerprint=vault_mod.vault_fingerprint(global_v),
        ),
        VaultSource(
            path=proj_v,
            key=p_key,
            fingerprint=vault_mod.vault_fingerprint(proj_v),
        ),
    ]
    merged = merge_secret_maps(
        {k: str(v) for k, v in g_payload["secrets"].items()},
        {k: str(v) for k, v in p_payload["secrets"].items()},
    )
    state = GuardState(
        secrets=merged,
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"r" * 32,
        vault_sources=sources,
        vault_path=proj_v,
        vault_key=p_key,
    )
    state.admitted = AdmittedSession(
        identities=[PEER],
        first_seen="2026-01-01T00:00:00+00:00",
        unscoped=True,
        granted_until=state.expires_at,
    )

    reply = guard_handle_message({"verb": "list"}, state, peer=PEER)
    assert reply["ok"] is True
    assert set(reply["names"]) == {"G", "P", "SHARED"}

    # Mutate global vault while merged guard is live — must refresh.
    vault_mod.save_vault(
        global_v,
        password,
        {"secrets": {"G": "gv2", "SHARED": "g", "G_NEW": "x"}},
    )
    reply = guard_handle_message({"verb": "list"}, state, peer=PEER)
    assert reply["ok"] is True
    assert "G_NEW" in reply["names"]
    # Project still wins on SHARED
    assert state.secrets["SHARED"] == "p"
    assert state.secrets["G"] == "gv2"


def test_lock_path_beside_project_vault(tmp_path: Path) -> None:
    proj = _make_project(tmp_path)
    vp = project_vault_path(proj)
    assert guard_lock_path_for_vault(vp) == vp.parent / "guard.lock"


def test_registry_write_remove_no_authkey(
    ka_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    vp = ka_home / "vault.bin"
    vp.write_bytes(b"x")
    fake_pid = 12345
    p = write_guard_registry_entry(
        vault_path=vp,
        address="\\\\.\\pipe\\test",
        pid=fake_pid,
        expires_at=time.time() + 600,
        project_root=None,
        env_name=None,
    )
    data = json.loads(p.read_text(encoding="utf-8"))
    assert "authkey" not in data
    assert "authkey_hex" not in data
    assert data["vault_path"] == str(vp.resolve())
    assert data["pid"] == fake_pid
    # Only treat the current process as alive. A recycled Windows PID (or
    # parent_alive fail-open on ACCESS_DENIED) must not keep the fake entry.
    monkeypatch.setattr(
        "key_amnesia.prompt_route.parent_alive",
        lambda pid: pid == os.getpid(),
    )
    assert list_guard_registry_entries() == []
    # Re-write with current pid so it stays live briefly
    write_guard_registry_entry(
        vault_path=vp,
        address="addr",
        pid=os.getpid(),
        expires_at=time.time() + 600,
    )
    live = list_guard_registry_entries()
    assert len(live) == 1
    remove_guard_registry_entry(vp)
    assert list_guard_registry_entries() == []


def test_import_targets_project_vault(
    ka_home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proj = _make_project(tmp_path, use_global=False)
    monkeypatch.chdir(proj)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    pw = "import-proj-pw"
    vault_mod.save_vault(project_vault_path(proj), pw, {"secrets": {}})

    env_file = proj / ".env"
    env_file.write_text("FROM_ENV=secret-value-xyz\n", encoding="utf-8")

    # password, then decline delete, decline rename, decline gitignore
    prompts = iter([pw])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(prompts))
    answers = iter(["n", "n", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    rc = main(["import", str(env_file)])
    assert rc == 0
    payload = vault_mod.load_vault(project_vault_path(proj), pw)
    assert "FROM_ENV" in payload["secrets"]
    # Must not have written into the global vault
    assert not (ka_home / "vault.bin").exists() or "FROM_ENV" not in (
        vault_mod.read_names(ka_home / "vault.names.json")
        if (ka_home / "vault.names.json").exists()
        else []
    )


def test_set_targets_project_vault(
    ka_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from key_amnesia.prompt_route import AuthOutcome

    proj = _make_project(tmp_path, use_global=False)
    monkeypatch.chdir(proj)
    pw = "set-proj-pw"
    vault_mod.save_vault(project_vault_path(proj), pw, {"secrets": {}})
    monkeypatch.setattr(
        "key_amnesia.cli.require_human_auth",
        lambda *a, **k: AuthOutcome(ok=True, route="inline", password=pw),
    )
    rc = main(["set", "PROJ_KEY", "proj-value"])
    assert rc == 0
    payload = vault_mod.load_vault(project_vault_path(proj), pw)
    assert payload["secrets"]["PROJ_KEY"] == "proj-value"
