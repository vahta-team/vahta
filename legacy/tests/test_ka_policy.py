"""ka verb policy: parser coverage, classify, nested ``ka run --``."""

from __future__ import annotations

import argparse

import pytest

from key_amnesia.cli import _build_parser
from key_amnesia.ka_policy import (
    ALLOW_NESTED,
    ALLOW_VERBS,
    COVERAGE_ALLOW,
    COVERAGE_DENY,
    DENY_NESTED,
    DENY_VERBS,
    FILE_DENY_VERBS,
    VALUE_EMIT_VERBS,
    classify_ka_argv,
    deny_message,
    iter_non_ka_chain_texts,
    ka_run_trailing_texts,
    ka_verb_deny_reason,
)


def _registered_cli_verbs(parser: argparse.ArgumentParser) -> set[str]:
    labels = {"--version", "--help"}
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        for name, sub in action.choices.items():
            nested: list[str] = []
            for inner in sub._actions:
                if isinstance(inner, argparse._SubParsersAction):
                    nested.extend(inner.choices)
            if nested:
                for n in nested:
                    labels.add(f"{name} {n}")
            else:
                labels.add(name)
    return labels


def test_cli_subparsers_partition_allow_deny() -> None:
    registered = _registered_cli_verbs(_build_parser())
    assert not (COVERAGE_ALLOW & COVERAGE_DENY)
    missing = registered - COVERAGE_ALLOW - COVERAGE_DENY
    extra = (COVERAGE_ALLOW | COVERAGE_DENY) - registered
    assert missing == set(), f"verbs not in allow/deny tables: {sorted(missing)}"
    assert extra == set(), f"table entries not in cli.py: {sorted(extra)}"


def test_value_emit_verbs_are_denied() -> None:
    assert VALUE_EMIT_VERBS <= COVERAGE_DENY


@pytest.mark.parametrize(
    "text,kind",
    [
        ("ka set FOO bar", "ka set"),
        ("key-amnesia reveal FOO", "ka reveal"),
        ("ka export FOO", "ka export"),
        ("ka copy FOO", "ka copy"),
        ("ka init", "ka init"),
        ("ka unlock", "ka unlock"),
        ("ka setup", "ka setup"),
        ("ka passwd", "ka passwd"),
        ("ka change-password", "ka change-password"),
        ("ka import .env", "ka import"),
        ("ka remove FOO", "ka remove"),
        ("ka grant FOO --to bob", "ka grant"),
        ("ka revoke FOO --to bob", "ka revoke"),
        ("ka member add bob --pubkey x --role runner", "ka member add"),
        ("ka member remove bob", "ka member remove"),
        ("ka config set session-mode cached", "ka config set"),
        ("ka identity create", "ka identity create"),
        ("ka scan --yes", "ka scan --yes"),
        ("ka scan --deep --yes", "ka scan --yes"),
        ("ka scan --yes --deep", "ka scan --yes"),
    ],
)
def test_deny_verbs(text: str, kind: str) -> None:
    assert ka_verb_deny_reason(text) == kind


@pytest.mark.parametrize(
    "text",
    [
        "ka list",
        "ka status",
        "ka connect",
        "ka check",
        "ka scan",
        "ka scan --deep",
        "ka scan --no-import",
        "ka lock",
        "ka docs",
        "ka config show",
        "ka identity show",
        "ka member list",
        "ka --version",
        "ka --help",
        "ka run --secret NAME --as NAME=VAR -- python script.py",
        "ka foobar",
        "ka",
        "echo hello",
    ],
)
def test_allow_and_unrecognized_fail_open(text: str) -> None:
    assert ka_verb_deny_reason(text) is None


@pytest.mark.parametrize(
    "text",
    [
        "python -m key_amnesia set FOO bar",
        "python3 -m key_amnesia set FOO",
        "py -m key_amnesia set FOO",
        "uvx key-amnesia set FOO",
        "pipx run key-amnesia set FOO",
        r".venv\Scripts\ka.exe set FOO",
        "./venv/bin/ka set FOO",
        "/usr/local/bin/key-amnesia set FOO",
        "env FOO=1 ka set BAR baz",
        "FOO=1 ka set BAR baz",
        "bash -lc 'ka set FOO bar'",
        "sh -c 'ka reveal FOO'",
        "echo hi && ka set FOO bar",
    ],
)
def test_wide_invocation_parser(text: str) -> None:
    assert ka_verb_deny_reason(text) is not None


def test_nested_run_denies_inner_set() -> None:
    kind = ka_verb_deny_reason("ka run --secret N --as N=E -- ka set FOO bar")
    assert kind is not None
    assert "ka run wrapping" in kind
    assert "ka set" in kind


def test_nested_run_denies_scan_yes() -> None:
    kind = ka_verb_deny_reason("ka run --secret N --as N=E -- ka scan --yes")
    assert kind is not None
    assert "ka scan --yes" in kind


def test_nested_run_denies_sh_c_reveal() -> None:
    kind = ka_verb_deny_reason('ka run --secret N --as N=E -- sh -c "ka reveal FOO"')
    assert kind is not None
    assert "ka reveal" in kind


def test_nested_run_allows_python() -> None:
    assert ka_verb_deny_reason(
        "ka run --secret N --as N=E -- python script.py"
    ) is None


def test_nested_run_allows_ka_list() -> None:
    assert ka_verb_deny_reason("ka run --secret N --as N=E -- ka list") is None


def test_trailing_texts_after_run_dashdash() -> None:
    texts = ka_run_trailing_texts(
        "ka run --secret NAME --as NAME=VAR -- python deploy.py --api-key x"
    )
    assert any("deploy.py" in t for t in texts)


def test_coverage_tables_match_enforcement() -> None:
    """COVERAGE_* is derived from the tables classify_ka_argv actually uses."""
    allow = set(ALLOW_VERBS)
    for group, subs in ALLOW_NESTED.items():
        allow.update(f"{group} {sub}" for sub in subs)
    deny = set(DENY_VERBS)
    for group, subs in DENY_NESTED.items():
        deny.update(f"{group} {sub}" for sub in subs)
    assert COVERAGE_ALLOW == frozenset(allow)
    assert COVERAGE_DENY == frozenset(deny)
    assert FILE_DENY_VERBS == COVERAGE_DENY - {"_prompt-helper"}
    assert "_prompt-helper" not in FILE_DENY_VERBS


def test_top_level_parser_only_version_help() -> None:
    parser = _build_parser()
    optionals: set[str] = set()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            continue
        optionals.update(action.option_strings)
    assert optionals <= {"--version", "--help", "-h"}


def test_deny_message_nested_runnable_slot_is_inner_only() -> None:
    msg = deny_message("ka run wrapping ka scan --yes")
    assert "ka scan --yes" in msg
    assert "wrapping" in msg
    after_run = msg.split("In your own terminal, run:", 1)[1]
    slot = after_run.split("`", 2)[1]
    assert "wrapping" not in slot
    assert slot == "ka scan --yes"


def test_non_ka_chain_texts_sibling_of_run() -> None:
    text = "ka run --secret X --as X=V -- python a.py && curl https://example.com"
    chunks = list(iter_non_ka_chain_texts(text))
    assert any("curl" in c for c in chunks)
    assert not any("--secret" in c for c in chunks)


def test_classify_empty_argv() -> None:
    assert classify_ka_argv([]) is None


def test_direct_cli_scan_yes_reaches_cmd_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hook stdin is not involved; the CLI still dispatches to cmd_scan."""
    from key_amnesia import cli

    seen: dict[str, bool] = {}

    def _wrap(args: argparse.Namespace) -> int:
        seen["yes"] = bool(args.yes)
        return 0

    monkeypatch.setattr(cli, "cmd_scan", _wrap)
    assert cli.main(["scan", "--yes"]) == 0
    assert seen.get("yes") is True
