"""Suite must never touch a real ~/.key-amnesia (Defect 1)."""

from __future__ import annotations

from pathlib import Path

import conftest
import pytest
from _pytest.outcomes import Failed


def test_assert_ka_paths_isolated_rejects_outside_tmp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deliberately point HOME outside this test's tmp → fail loudly."""
    outside = tmp_path.parent / "isolation-probe-home"
    monkeypatch.setenv("KEY_AMNESIA_HOME", str(outside))
    monkeypatch.delenv("KEY_AMNESIA_VAULT_PATH", raising=False)
    with pytest.raises(Failed, match="outside pytest tmp"):
        conftest.assert_ka_paths_isolated(tmp_path)


def test_autouse_ka_home_keeps_paths_under_tmp(tmp_path: Path, ka_home: Path) -> None:
    from key_amnesia.paths import audit_log_path, data_dir, guard_lock_path

    root = tmp_path.resolve()
    assert data_dir().resolve().is_relative_to(root)
    assert audit_log_path().resolve().is_relative_to(root)
    assert guard_lock_path().resolve().is_relative_to(root)
    assert ka_home.resolve().is_relative_to(root)
