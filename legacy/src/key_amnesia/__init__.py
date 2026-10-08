"""key-amnesia: encrypted vault with human-prompt routing and output scrubbing.

``__version__`` is resolved lazily, and that is a latency decision rather than
a style one. Calling ``importlib.metadata.version()`` at import time pulls in
``importlib.metadata``, which drags ``email.message`` and ``inspect`` behind
it — measured with ``python -X importtime`` at **70-78 ms of a ~165 ms hook
cold start**, roughly half of it, paid on *every tool call the agent makes*,
to produce a string the hook never reads.

Deferring it with PEP 562 keeps ``key_amnesia.__version__`` working for every
caller that actually wants the version, and charges nobody else for it. The
value is cached in the module globals on first access, so it costs at most one
resolution per process.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - for type checkers only
    __version__: str

__all__ = ["__version__"]


def __getattr__(name: str) -> str:
    if name == "__version__":
        from importlib.metadata import PackageNotFoundError, version

        try:
            resolved = version("key-amnesia")
        except PackageNotFoundError:
            resolved = "0.0.0"
        globals()["__version__"] = resolved
        return resolved
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | {"__version__"})
