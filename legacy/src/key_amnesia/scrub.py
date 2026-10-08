"""Exact substring scrubbing of secret values from text.

Never builds a regex from secret values — special characters would corrupt
the pattern. Uses str.replace for every name→value pair independently.
"""

from __future__ import annotations


def scrub_text(text: str, secrets: dict[str, str]) -> str:
    """Replace every secret value with ***REDACTED(name)*** via exact str.replace.

    Longer values are replaced first so a value that is a substring of another
    is less likely to leave partial residue when both are present.
    """
    if not secrets or not text:
        return text
    # Sort by value length descending for deterministic multi-secret scrubbing.
    items = sorted(secrets.items(), key=lambda kv: len(kv[1]), reverse=True)
    out = text
    for name, value in items:
        if not value:
            continue
        out = out.replace(value, f"***REDACTED({name})***")
    return out
