"""The scanner dispatcher must forward reads *and writes*, like the detector's.

The mechanism is shared (:mod:`key_amnesia._dispatch`) and its subtleties are
tested in ``test_detect_dispatch.py``. What is tested here is that ``scan`` is
wired to it correctly: its own variable, its own implementation module, and
writes landing where the implementation reads them.
"""

from __future__ import annotations

import pytest

from key_amnesia import _dispatch
from key_amnesia import scan as scan_mod
from key_amnesia import scan_py


def test_the_scanner_has_its_own_variable() -> None:
    """Separate from the detector's, so the two can be selected apart."""
    assert scan_mod.IMPL_ENV_VAR == "KEY_AMNESIA_SCAN_IMPL"
    assert scan_mod.IMPL_ENV_VAR != "KEY_AMNESIA_DETECT_IMPL"


def test_reads_reach_the_implementation() -> None:
    assert scan_mod.STRICT_HIGH is scan_py.STRICT_HIGH
    assert scan_mod.scan_project is scan_py.scan_project


def test_a_write_lands_where_the_implementation_reads_it() -> None:
    """The failure mode that verifies nothing if it is got wrong."""
    original = scan_py._MAX_CONTENT_BYTES
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(scan_mod, "_MAX_CONTENT_BYTES", 7)
        assert scan_py._MAX_CONTENT_BYTES == 7
    assert scan_py._MAX_CONTENT_BYTES == original


def test_own_names_are_not_forwarded_onto_the_implementation() -> None:
    assert not hasattr(scan_py, "IMPL_ENV_VAR")
    assert not hasattr(scan_py, "active_impl")


def test_the_python_implementation_is_active_without_an_extension() -> None:
    if scan_mod.active_impl == _dispatch.IMPL_RUST:
        pytest.skip("extension is installed in this environment")
    assert scan_mod.implemented_natively() == frozenset()
