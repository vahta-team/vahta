"""Turns a module into a chooser between two implementations of itself.

Used by :mod:`key_amnesia.detect` and :mod:`key_amnesia.scan`. Each keeps its
Python implementation in a sibling ``*_py`` module and lets an environment
variable select a compiled one, so the same test suite can be run against
both without a test file changing.

The compiled extension is a development and CI artefact, never a dependency of
the released wheel: a missing or unimportable extension falls back to Python
silently, so a ``py3-none-any`` wheel behaves exactly as it did before this
indirection existed, and asking for ``rust`` on a machine without the
extension is a no-op rather than a crash.

The port is **incremental**, so lookups chain: a name the extension defines
comes from the extension, everything else from Python.

Why a module *subclass* and not a PEP 562 ``__getattr__``
---------------------------------------------------------
Forwarding reads alone is not enough, and getting it wrong fails silently
rather than loudly. ``tests/test_scan_corpus.py::test_assign_differential_corpus``
swaps ``_iter_assignments`` for the legacy ``ASSIGN`` matcher and asserts the
two find the same things. A read-only forwarder leaves that assignment sitting
on the wrapper while ``detect_py.scan_text_hits`` keeps reading its own global
— so the test compares the new matcher against itself, passes, and verifies
nothing. Measured, not reasoned: patching the wrapper left the hit list
unchanged while patching ``detect_py`` emptied it.

So writes are forwarded too, to whichever module owns the name, and nothing is
cached — a cached read would go stale the moment someone patched an
implementation directly.

Never returns or logs secret *values*, exactly as the modules it wraps.
"""

from __future__ import annotations

import importlib
import os
from dataclasses import dataclass
from types import ModuleType
from typing import Callable

IMPL_PYTHON = "python"
IMPL_RUST = "rust"


@dataclass(frozen=True)
class Dispatch:
    """What :func:`install` set up, for a caller that wants to introspect it."""

    active: str
    impl: ModuleType
    fallback: ModuleType
    implemented_natively: Callable[[], frozenset[str]]


def install(
    module: ModuleType,
    *,
    env_var: str,
    python_module: str,
    rust_module: str,
) -> Dispatch:
    """Make ``module`` forward every unknown name to an implementation.

    Names already in ``module.__dict__`` when this is called stay the module's
    own — a snapshot rather than a hand-maintained list, because a list is one
    more thing to forget to update. ``active_impl`` and ``implemented_natively``
    are added by this function and counted as the module's own.
    """
    fallback = importlib.import_module(python_module)

    requested = os.environ.get(env_var, IMPL_PYTHON).strip().lower()
    impl, active = fallback, IMPL_PYTHON
    if requested == IMPL_RUST:
        try:
            impl, active = importlib.import_module(rust_module), IMPL_RUST
        except ImportError:
            # Absent by design in a released wheel; not an error.
            pass

    def implemented_natively() -> frozenset[str]:
        """Names the active implementation actually serves itself."""
        if impl is fallback:
            return frozenset()
        return frozenset(n for n in dir(impl) if not n.startswith("__"))

    own = frozenset(module.__dict__) | {"active_impl", "implemented_natively"}
    name = module.__name__

    class _Dispatcher(ModuleType):
        """Forwards reads *and writes* to whichever module owns the name."""

        def __getattr__(self, attr: str):
            # Reached only for names absent from this module's own __dict__.
            for source in (impl, fallback):
                try:
                    return getattr(source, attr)
                except AttributeError:
                    continue
            raise AttributeError(
                f"module {name!r} has no attribute {attr!r} "
                f"(active implementation: {active})"
            ) from None

        # Name-mangled, so an implementation is free to export a plain
        # `_target` without this helper shadowing it.
        def __target(self, attr: str) -> ModuleType:
            # Write where the name is read, so monkeypatching still works. A
            # compiled extension cannot accept a patched constant, which is
            # why a test that swaps one is a test of the Python module.
            return impl if hasattr(impl, attr) else fallback

        def __setattr__(self, attr: str, value) -> None:
            if attr.startswith("__") or attr in own:
                ModuleType.__setattr__(self, attr, value)
                return
            setattr(self.__target(attr), attr, value)

        def __delattr__(self, attr: str) -> None:
            if attr.startswith("__") or attr in own:
                ModuleType.__delattr__(self, attr)
                return
            delattr(self.__target(attr), attr)

        def __dir__(self) -> list[str]:
            return sorted(set(dir(impl)) | set(dir(fallback)) | set(self.__dict__))

    ModuleType.__setattr__(module, "active_impl", active)
    ModuleType.__setattr__(module, "implemented_natively", implemented_natively)
    module.__class__ = _Dispatcher
    return Dispatch(
        active=active,
        impl=impl,
        fallback=fallback,
        implemented_natively=implemented_natively,
    )
