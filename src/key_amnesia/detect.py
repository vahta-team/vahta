"""Implementation dispatcher for the shared secret-shape detector.

The detector itself, and the measured evidence behind every threshold in it,
lives in :mod:`key_amnesia.detect_py`. That module is the specification; read
it, not this one.

This module exists so the same test suite can be run against two
implementations of the same behaviour. ``KEY_AMNESIA_DETECT_IMPL`` selects
one:

    python   the Python implementation (default)
    rust     the compiled extension, when it is installed

The Rust extension is a development and CI artefact, never a dependency of the
released wheel: if it is missing, or if importing it fails for any reason, this
module falls back to Python silently. A released ``py3-none-any`` wheel
therefore behaves exactly as it did before this indirection existed, and
``KEY_AMNESIA_DETECT_IMPL=rust`` on a machine without the extension is a no-op
rather than a crash.

The port is **incremental**, so lookups chain: a name the extension defines
comes from the extension, and everything else — the legacy ``ASSIGN`` pattern
object, ``collect_strings`` over arbitrary containers, the constants — still
comes from Python. :func:`implemented_natively` reports which is which, which
is more useful than claiming the whole module was replaced.

Why this is a module *subclass* and not a PEP 562 ``__getattr__``
-----------------------------------------------------------------
Forwarding reads alone is not enough, and getting that wrong is silent rather
than loud. ``tests/test_scan_corpus.py::test_assign_differential_corpus``
swaps ``_iter_assignments`` for the legacy ``ASSIGN`` matcher and asserts the
two produce identical findings. A read-only forwarder leaves that assignment
sitting on this module while ``detect_py.scan_text_hits`` keeps reading its own
global — so the test compares the new matcher against itself, passes, and
verifies nothing. Measured, not reasoned: patching this module left the hit
list unchanged while patching ``detect_py`` emptied it.

So writes are forwarded too, to whichever module owns the name. Nothing is
cached, because a cached read would go stale the moment someone patched an
implementation directly.

Never returns or logs secret *values*, exactly as the implementations it wraps.
"""

from __future__ import annotations

import importlib
import os
import sys
from types import ModuleType

__all__: list[str] = []

IMPL_ENV_VAR = "KEY_AMNESIA_DETECT_IMPL"
IMPL_PYTHON = "python"
IMPL_RUST = "rust"

#: Extension module name. Absent from the released wheel by design.
_RUST_MODULE = "key_amnesia._detect_rs"
_PYTHON_MODULE = "key_amnesia.detect_py"


def _requested_impl() -> str:
    return os.environ.get(IMPL_ENV_VAR, IMPL_PYTHON).strip().lower()


def _load_impl() -> tuple[ModuleType, str]:
    """Return the primary implementation module and the name it resolved to.

    Falls back to Python rather than raising: an unset or unknown value, and a
    missing or unimportable extension, all mean the same thing to a caller —
    use the implementation that is always present.
    """
    if _requested_impl() == IMPL_RUST:
        try:
            return importlib.import_module(_RUST_MODULE), IMPL_RUST
        except ImportError:
            pass
    return importlib.import_module(_PYTHON_MODULE), IMPL_PYTHON


_fallback = importlib.import_module(_PYTHON_MODULE)
_impl, active_impl = _load_impl()


def implemented_natively() -> frozenset[str]:
    """Names the active implementation actually serves itself."""
    if _impl is _fallback:
        return frozenset()
    return frozenset(n for n in dir(_impl) if not n.startswith("__"))


#: Names this module owns. Everything else belongs to an implementation.
_OWN_NAMES = frozenset(
    {
        "IMPL_ENV_VAR",
        "IMPL_PYTHON",
        "IMPL_RUST",
        "_RUST_MODULE",
        "_PYTHON_MODULE",
        "_requested_impl",
        "_load_impl",
        "_impl",
        "_fallback",
        "active_impl",
        "implemented_natively",
        "_OWN_NAMES",
        "_Dispatcher",
        "importlib",
        "os",
        "sys",
        "ModuleType",
        "annotations",
    }
)


class _Dispatcher(ModuleType):
    """Forwards reads *and writes* to whichever implementation owns the name."""

    def __getattr__(self, name: str):
        # Reached only for names absent from this module's own __dict__.
        try:
            return getattr(_impl, name)
        except AttributeError:
            pass
        try:
            return getattr(_fallback, name)
        except AttributeError:
            raise AttributeError(
                f"module {__name__!r} has no attribute {name!r} "
                f"(active implementation: {active_impl})"
            ) from None

    def __setattr__(self, name: str, value) -> None:
        if name.startswith("__") or name in _OWN_NAMES:
            ModuleType.__setattr__(self, name, value)
            return
        # Write where the name is read, so monkeypatching still works. A
        # compiled extension cannot accept a patched constant, which is why a
        # test that swaps one is a test of the Python implementation.
        target = _impl if hasattr(_impl, name) else _fallback
        setattr(target, name, value)

    def __delattr__(self, name: str) -> None:
        if name.startswith("__") or name in _OWN_NAMES:
            ModuleType.__delattr__(self, name)
            return
        target = _impl if hasattr(_impl, name) else _fallback
        delattr(target, name)

    def __dir__(self) -> list[str]:
        return sorted(set(dir(_impl)) | set(dir(_fallback)) | set(self.__dict__))


sys.modules[__name__].__class__ = _Dispatcher
