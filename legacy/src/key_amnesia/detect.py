"""Implementation dispatcher for the shared secret-shape detector.

The detector itself, and the measured evidence behind every threshold in it,
lives in :mod:`key_amnesia.detect_py`. That module is the specification; read
it, not this one.

``KEY_AMNESIA_DETECT_IMPL`` selects an implementation:

    python   the Python implementation (default)
    rust     the compiled extension, when it is installed

The mechanism, and why it forwards writes as well as reads, is documented in
:mod:`key_amnesia._dispatch`.
"""

from __future__ import annotations

import sys

from . import _dispatch

__all__: list[str] = []

IMPL_ENV_VAR = "KEY_AMNESIA_DETECT_IMPL"
IMPL_PYTHON = _dispatch.IMPL_PYTHON
IMPL_RUST = _dispatch.IMPL_RUST

#: Extension module name. Absent from the released wheel by design.
_RUST_MODULE = "key_amnesia._detect_rs"
_PYTHON_MODULE = "key_amnesia.detect_py"

_dispatch.install(
    sys.modules[__name__],
    env_var=IMPL_ENV_VAR,
    python_module=_PYTHON_MODULE,
    rust_module=_RUST_MODULE,
)
