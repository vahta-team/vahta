"""Build a real wheel and assert the packaged skills/hook data land inside it.

Uses `pip wheel` (always available alongside pip) rather than requiring the
separate `build` package as a test-only dependency. Slow (spawns a build
subprocess) — kept to one test module so `-k` can skip it if needed.
"""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.slow

EXPECTED_SKILL_MEMBERS = [
    "key_amnesia/skills/key-amnesia-usage/SKILL.md",
    "key_amnesia/skills/key-amnesia-hygiene/SKILL.md",
    "key_amnesia/skills/key-amnesia-migrate/SKILL.md",
]

EXPECTED_HOOK_MEMBERS = [
    "key_amnesia/hooks/secret_guard.py",
    "key_amnesia/hooks/__init__.py",
]

EXPECTED_PLUGIN_MEMBERS = [
    "key_amnesia/plugins/opencode/secret-guard.js",
]


@pytest.fixture(scope="module")
def built_wheel_members(tmp_path_factory: pytest.TempPathFactory) -> list[str]:
    out_dir = tmp_path_factory.mktemp("ka-wheel")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", str(REPO_ROOT), "--no-deps", "-w", str(out_dir)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode != 0:
        pytest.fail(
            "pip wheel build failed:\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    wheels = list(out_dir.glob("key_amnesia-*.whl"))
    assert wheels, f"no wheel produced in {out_dir}: {list(out_dir.iterdir())}"
    with zipfile.ZipFile(wheels[0]) as zf:
        return zf.namelist()


def test_wheel_contains_all_three_skill_md(built_wheel_members: list[str]) -> None:
    for member in EXPECTED_SKILL_MEMBERS:
        assert member in built_wheel_members, f"missing {member} in wheel"


def test_wheel_contains_hook_module(built_wheel_members: list[str]) -> None:
    for member in EXPECTED_HOOK_MEMBERS:
        assert member in built_wheel_members, f"missing {member} in wheel"


def test_wheel_contains_opencode_plugin(built_wheel_members: list[str]) -> None:
    for member in EXPECTED_PLUGIN_MEMBERS:
        assert member in built_wheel_members, f"missing {member} in wheel"
