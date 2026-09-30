"""The detector dispatcher must forward reads *and writes*.

Writes are the half that fails silently. ``test_assign_differential_corpus``
swaps ``_iter_assignments`` for the legacy ``ASSIGN`` matcher and asserts the
two agree; if that assignment lands on the dispatcher while the implementation
keeps reading its own global, the test compares the new matcher against itself,
passes, and verifies nothing. A read-only forwarder does exactly that. These
tests exist so that regression is loud instead.

Probe text is built at run time rather than written as a literal, so the
product's own hook does not refuse this file — which it would be right to do.
"""

from __future__ import annotations

from types import ModuleType

import pytest

from key_amnesia import _dispatch
from key_amnesia import detect as detect_mod
from key_amnesia import detect_py

# `NAME=value` assembled at run time; never a credential-shaped literal on disk.
_PROBE = "=".join(("API_KEY", "aB3xQ9mK2pL7vN4wZ8"))


PYTHON_ONLY = pytest.mark.skipif(
    detect_mod.active_impl != detect_mod.IMPL_PYTHON,
    reason="asserts identity with the Python implementation",
)


def test_every_name_resolves_under_either_implementation() -> None:
    """The dispatcher chains: the extension first, then Python for the rest."""
    for name in ("scan_text_hits", "classify_value", "find_secret_kind", "entropy"):
        assert callable(getattr(detect_mod, name))
    # Never ported, always served by Python.
    assert detect_mod.ASSIGN is detect_py.ASSIGN
    assert detect_mod.FLAG_FORM_FIRE_TIERS == detect_py.FLAG_FORM_FIRE_TIERS


@PYTHON_ONLY
def test_reads_forward_to_the_implementation() -> None:
    assert detect_mod.scan_text_hits is detect_py.scan_text_hits
    assert detect_mod.classify_value is detect_py.classify_value


def test_private_helpers_forward_too() -> None:
    """Tests import these by name; they must not stop at the dispatcher."""
    assert callable(detect_mod._iter_assignments)
    assert callable(detect_mod._iter_flag_values)
    if detect_mod.active_impl == detect_mod.IMPL_PYTHON:
        assert detect_mod._iter_assignments is detect_py._iter_assignments
        assert detect_mod._iter_flag_values is detect_py._iter_flag_values


@PYTHON_ONLY
def test_a_write_through_the_dispatcher_reaches_the_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The guard against a silently tautological differential test.

    Python-only by nature: a compiled implementation reads its own constants
    and cannot be handed a patched one, so this asserts a property of the
    Python path rather than of the detector.
    """
    baseline = detect_mod.scan_text_hits(_PROBE)
    assert baseline.likely_names == ["API_KEY"], "probe stopped being a hit"

    monkeypatch.setattr(detect_mod, "_iter_assignments", lambda _text: iter(()))

    patched = detect_mod.scan_text_hits(_PROBE)
    assert patched.likely_names == [], (
        "patching the dispatcher did not reach the code that reads the name: "
        "any test that swaps an internal is now verifying nothing"
    )


@PYTHON_ONLY
def test_monkeypatch_undo_restores_the_implementation() -> None:
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(detect_mod, "_iter_assignments", lambda _text: iter(()))
        assert detect_mod.scan_text_hits(_PROBE).likely_names == []
    assert detect_mod.scan_text_hits(_PROBE).likely_names == ["API_KEY"]
    assert detect_py._iter_assignments is not None


def test_unknown_attribute_names_the_active_implementation() -> None:
    with pytest.raises(AttributeError) as excinfo:
        detect_mod.definitely_not_a_real_name
    assert "definitely_not_a_real_name" in str(excinfo.value)
    assert detect_mod.active_impl in str(excinfo.value)


def test_a_missing_extension_falls_back_rather_than_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The released wheel ships no extension; asking for it must be a no-op.

    Installed onto a throwaway module against an extension name that cannot
    exist, so this exercises the fallback itself rather than skipping wherever
    the real extension happens to be built.
    """
    monkeypatch.setenv("KEY_AMNESIA_TEST_IMPL", _dispatch.IMPL_RUST)
    scratch = ModuleType("key_amnesia._dispatch_probe")
    result = _dispatch.install(
        scratch,
        env_var="KEY_AMNESIA_TEST_IMPL",
        python_module="key_amnesia.detect_py",
        rust_module="key_amnesia._no_such_extension",
    )
    assert result.active == _dispatch.IMPL_PYTHON
    assert result.impl is detect_py
    assert scratch.active_impl == _dispatch.IMPL_PYTHON
    # And the forwarding still works, so the fallback is usable and not merely
    # selected.
    assert scratch.scan_text_hits(_PROBE).likely_names == ["API_KEY"]
    assert result.implemented_natively() == frozenset()


def test_own_names_are_not_forwarded_onto_the_implementation() -> None:
    """Dispatcher bookkeeping must not leak into the implementation module."""
    assert not hasattr(detect_py, "IMPL_ENV_VAR")
    assert not hasattr(detect_py, "active_impl")
