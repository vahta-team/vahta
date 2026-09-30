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

import pytest

from key_amnesia import detect as detect_mod
from key_amnesia import detect_py

# `NAME=value` assembled at run time; never a credential-shaped literal on disk.
_PROBE = "=".join(("API_KEY", "aB3xQ9mK2pL7vN4wZ8"))


def test_reads_forward_to_the_implementation() -> None:
    assert detect_mod.scan_text_hits is detect_py.scan_text_hits
    assert detect_mod.classify_value is detect_py.classify_value
    assert detect_mod.FLAG_FORM_FIRE_TIERS == detect_py.FLAG_FORM_FIRE_TIERS


def test_private_helpers_forward_too() -> None:
    """Tests import these by name; they must not stop at the dispatcher."""
    assert detect_mod._iter_assignments is detect_py._iter_assignments
    assert detect_mod._iter_flag_values is detect_py._iter_flag_values


def test_a_write_through_the_dispatcher_reaches_the_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The guard against a silently tautological differential test."""
    baseline = detect_mod.scan_text_hits(_PROBE)
    assert baseline.likely_names == ["API_KEY"], "probe stopped being a hit"

    monkeypatch.setattr(detect_mod, "_iter_assignments", lambda _text: iter(()))

    patched = detect_mod.scan_text_hits(_PROBE)
    assert patched.likely_names == [], (
        "patching the dispatcher did not reach the code that reads the name: "
        "any test that swaps an internal is now verifying nothing"
    )


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
    """The released wheel ships no extension; asking for it must be a no-op."""
    monkeypatch.setenv(detect_mod.IMPL_ENV_VAR, detect_mod.IMPL_RUST)
    impl, name = detect_mod._load_impl()
    if name == detect_mod.IMPL_RUST:
        pytest.skip("extension is installed in this environment")
    assert impl is detect_py
    assert name == detect_mod.IMPL_PYTHON


def test_own_names_are_not_forwarded_onto_the_implementation() -> None:
    """Dispatcher bookkeeping must not leak into the implementation module."""
    assert not hasattr(detect_py, "IMPL_ENV_VAR")
    assert not hasattr(detect_py, "active_impl")
