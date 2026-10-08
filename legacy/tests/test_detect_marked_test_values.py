"""A value spelled as words and short numbers, one of them a test marker
(``fake``, ``dummy``, ``example``, ...), is not a credential.

Found dogfooding: a scripted-window fixture whose value was
``fake-plain-value-1`` was refused by the hook as a likely secret. Values are
assembled at run time, so the product's own hook does not refuse this file.
"""

from __future__ import annotations

import pytest

from key_amnesia import detect


def _j(*parts: str) -> str:
    return "-".join(parts)


@pytest.mark.parametrize(
    "value",
    [
        _j("fake", "plain", "value", "1"),
        _j("dummy", "token"),
        "TEST_API_KEY_2024",
        "example.secret.value",
    ],
)
def test_a_marked_test_value_is_none(value: str) -> None:
    assert detect.classify_value(value)[0] == "none"


@pytest.mark.parametrize(
    "value",
    [
        _j("fake", "aB3xQ9mK2pL7vN4wZ8"),
        _j("test", "qzx7Kp"),
        _j("correct", "horse", "battery", "1"),
        _j("fake", "123456789"),
        _j("Fake", "value"),
        "fakevalue1",
        "fake--value",
    ],
)
def test_a_value_not_spelled_as_marked_words_is_classified_as_before(value: str) -> None:
    from key_amnesia import detect_py

    assert not detect_py.is_marked_test_value(value)


def test_a_random_part_after_a_marker_is_still_likely() -> None:
    assert detect.classify_value(_j("fake", "aB3xQ9mK2pL7vN4wZ8"))[0] == "likely"


def test_the_hook_no_longer_refuses_the_dogfooding_fixture() -> None:
    text = "{" + '"secret":"' + _j("fake", "plain", "value", "1") + '"' + "}"
    assert detect.find_secret_kind(text) is None
