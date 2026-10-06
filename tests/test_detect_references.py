"""A value that starts with a reference is not a credential.

`${GH_TOKEN}@github.com/...` in a push URL, a CI expression, a template with
a JSON escape after it: each names where the credential comes from. Before,
the text after the reference made the value look random and the hook refused
ordinary commands and fixture files.

Runs through the dispatcher, so the Rust leg of CI checks the extension with
the same cases. Probe text is built at run time, so the product's own hook
does not refuse this file.
"""

from __future__ import annotations

import pytest

from key_amnesia import detect

D, LB, RB = "$", "{", "}"
NAME = "_".join(("API", "KEY"))
RANDOM = "".join(("aB3x", "Q9mK", "2pL7", "vN4w", "Z8"))


def _assign(value: str) -> str:
    return NAME + "=" + value


REFERENCES = [
    D + LB + "GH_TOKEN" + RB + "@github.com/o/r.git",
    D + LB + "VAR:-fallbackValue9" + RB,
    D + LB * 2 + " secrets.GITHUB_TOKEN " + RB * 2 + "@github.com",
    LB * 2 + "TEMPLATE_NAME" + RB * 2 + "\\n",
    D + "(cat .token-file)Xy9",
    D + "TOKEN" + "/path/Ab9",
    "%" + "TOKEN" + "%Ab9xyz",
]


@pytest.mark.parametrize("value", REFERENCES)
def test_a_value_starting_with_a_reference_is_not_a_credential(value: str) -> None:
    assert detect.classify_value(value)[0] == "none"
    assert detect.find_secret_kind(_assign(value)) is None


def test_a_push_url_with_a_variable_token_is_not_a_finding() -> None:
    url = (
        "git push https://x-access-" + "token:" + D + LB + "GH_TOKEN" + RB
        + "@github.com/o/r.git"
    )
    assert detect.find_secret_kind(url) is None


@pytest.mark.parametrize(
    "value",
    [
        RANDOM,
        # `$` and a digit: a bcrypt hash, not a reference.
        D + "2b" + D + "12" + D + RANDOM + RANDOM,
        # A reference later in the value does not excuse what comes first.
        RANDOM + D + LB + "X" + RB,
        # Not a Windows variable: no closing %.
        "%" + RANDOM,
    ],
)
def test_real_looking_values_are_still_found(value: str) -> None:
    assert detect.classify_value(value)[0] in ("possible", "likely")
