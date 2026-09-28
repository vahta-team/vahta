"""Labeled scan corpus: before-measurement, tiers, and ka scan exit paths.

Never asserts on secret *values* except to confirm they are absent from
captured output. Generated likely values live only under pytest tmp.
"""

from __future__ import annotations

import json
import math
import re
import shutil
import time
import uuid
from collections import Counter
from pathlib import Path

import pytest

from key_amnesia.cli import main
from key_amnesia.detect import (
    ASSIGN,
    FLAG_FORM_FIRE_TIERS,
    NAMED_WEAKENING_FUNCTION_CALL,
    NAMED_WEAKENING_IDENTIFIER,
    NAMED_WEAKENING_LOW_TRANSITION,
    NAMED_WEAKENING_TYPE_ANNOTATION,
    NAMED_WEAKENING_WORD_SHAPED_PASSPHRASE,
    NAMED_WEAKENINGS,
    REASON_FLAG_FORM,
    REASON_UNCONFIRMED_MCP,
    REASON_UUID,
    _iter_assignments,
    _iter_flag_values,
    classify_value,
    find_prefix_kind,
    find_secret_kind,
    scan_text_hits,
)
from key_amnesia.hooks import secret_guard as sg
from key_amnesia.scan import (
    Finding,
    _findings_for_path,
    _findings_for_transcript,
    format_count_summary,
    format_gate_totals,
    headline,
    leak_count,
    possible_count,
    scan_project,
    transcript_line_hit_count,
)

CORPUS = Path(__file__).resolve().parent / "fixtures" / "scan_corpus"
NEGATIVES = CORPUS / "negatives"
DEMOTED = CORPUS / "demoted"
POSITIVES = CORPUS / "positives"

# Generated at test time only — not committed. Shapes match 0.4.9 hook fixtures.
_GEN_MIXED = "aB3xQ9mK2pL7vN4wZ8"
_GEN_MIXED_B = "Zk9pL2xQ7mN4vB8w"
_GEN_HEX32 = "a1b2c3d4e5f6789012345678abcdef01"
_GEN_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
_GEN_URLSAFE = "A7xQ2mK9pL4vN8wZ1bC3dE5fG6hJ0kL"
_GEN_VALUES = (_GEN_MIXED, _GEN_MIXED_B, _GEN_HEX32, _GEN_JWT, _GEN_URLSAFE)

# Space-separated flag form. `_GEN_WEAK_PW` is the shape that decides the tier:
# a human password whose transition rate (0.25) sits far below
# LIKELY_TRANSITION_FLOOR, so it is `possible`, not `likely`.
_GEN_WEAK_PW = "hunter7-correct-horse"
_GEN_UUID = "4f8a1c9e-2b7d-4e63-9a15-0c8bd3f7e214"

DEMOTED_TO_WEAKENING = {
    "passphrase_correct_horse_battery.py": NAMED_WEAKENING_WORD_SHAPED_PASSPHRASE,
    "low_transition_summervineyard.py": NAMED_WEAKENING_LOW_TRANSITION,
}
NEGATIVE_TO_WEAKENING = {
    "function_call_secrets.py": NAMED_WEAKENING_FUNCTION_CALL,
    "function_call_get_token.py": NAMED_WEAKENING_FUNCTION_CALL,
    "type_annotation.py": NAMED_WEAKENING_TYPE_ANNOTATION,
    "camelcase_identifier.py": NAMED_WEAKENING_IDENTIFIER,
}
FILENAME_DEMOTED = frozenset({"mcp.json"})

# 0.4.9 assignment heuristic — before-measurement only.
_LEGACY_ASSIGN = re.compile(
    r"""(?ix)
    (?P<name>(?:[a-z0-9]+[_-])*(?:api[_-]?key|token|secret|password|passwd|private[_-]?key))
    \s*[:=]\s*
    (?P<q>['"]?)
    (?P<value>[^\s'"]{8,})
    (?P=q)
    """
)
_LEGACY_PLACEHOLDERS = {
    "test123",
    "test1234",
    "changeme",
    "change_me",
    "changethis",
    "password",
    "password123",
    "secret",
    "yourkey",
    "your_api_key",
    "your-api-key",
    "placeholder",
    "example",
    "dummy",
    "fake",
    "sample",
    "xxxxxxxx",
    "12345678",
}


def _iter_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file() and p.name != "README.md")


def _legacy_entropy(s: str) -> float:
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _legacy_assignment_is_secret(value: str) -> bool:
    v = value.strip("'\"")
    if len(v) < 8:
        return False
    low = v.lower()
    if low in _LEGACY_PLACEHOLDERS:
        return False
    if re.fullmatch(r"x{6,}", low) or re.fullmatch(r"0{6,}|1{6,}", low):
        return False
    mixed = sum(
        [
            any(c.isupper() for c in v),
            any(c.islower() for c in v),
            any(c.isdigit() for c in v),
        ]
    ) >= 2
    if not mixed:
        return False
    return _legacy_entropy(v) >= 3.0


def _legacy_flags(text: str) -> bool:
    if re.search(r"\bBearer\s+[A-Za-z0-9._\-+=/]{16,}", text, re.I):
        return True
    for match in _LEGACY_ASSIGN.finditer(text):
        if _legacy_assignment_is_secret(match.group("value")):
            return True
    return False


def _file_has_likely_or_prefix(text: str) -> bool:
    if find_prefix_kind(text):
        return True
    hits = scan_text_hits(text)
    return bool(hits.likely_names or hits.prefix or hits.bearer_likely)


def _assert_no_gen_values(blob: str) -> None:
    for value in _GEN_VALUES:
        assert value not in blob
    assert "CorrectHorseBattery" not in blob


def test_before_measurement_legacy_over_blocks_negatives() -> None:
    """0.4.9 assignment heuristic flagged function-call / identifier shapes."""
    flagged = [
        path.name
        for path in _iter_files(NEGATIVES)
        if _legacy_flags(path.read_text(encoding="utf-8"))
    ]
    assert flagged, "before-measurement expected 0.4.9 to over-block some negatives"
    assert "function_call_secrets.py" in flagged
    assert "camelcase_identifier.py" in flagged
    assert "type_annotation.py" in flagged


@pytest.mark.parametrize("path", _iter_files(NEGATIVES), ids=lambda p: p.name)
def test_negatives_not_likely_or_prefix(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert not _file_has_likely_or_prefix(text)


@pytest.mark.parametrize(
    "path",
    [p for p in _iter_files(DEMOTED) if p.name not in FILENAME_DEMOTED],
    ids=lambda p: p.name,
)
def test_demoted_is_possible_and_named(path: Path) -> None:
    assert path.name in DEMOTED_TO_WEAKENING
    assert DEMOTED_TO_WEAKENING[path.name] in NAMED_WEAKENINGS
    text = path.read_text(encoding="utf-8")
    hits = scan_text_hits(text)
    assert hits.prefix is None
    assert not hits.likely_names
    assert hits.possible_names or hits.bearer_possible
    assert classify_value("CorrectHorseBattery")[0] == "possible"
    assert classify_value("SummerVineyard2026")[0] == "possible"
    assert classify_value("SummerVineyard2026")[1] == NAMED_WEAKENING_LOW_TRANSITION
    assert find_secret_kind(text) is not None


def test_demoted_files_all_mapped() -> None:
    names = {p.name for p in _iter_files(DEMOTED)}
    assert names == set(DEMOTED_TO_WEAKENING) | FILENAME_DEMOTED


def test_every_named_weakening_has_a_fixture() -> None:
    mapped = set(DEMOTED_TO_WEAKENING.values()) | set(NEGATIVE_TO_WEAKENING.values())
    assert set(NAMED_WEAKENINGS) <= mapped
    assert (DEMOTED / "mcp.json").is_file()


@pytest.mark.parametrize("path", _iter_files(POSITIVES), ids=lambda p: p.name)
def test_on_disk_positives_are_prefix(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert find_prefix_kind(text) is not None


def test_generated_likely_values_classify_likely() -> None:
    for value in _GEN_VALUES:
        assert classify_value(value)[0] == "likely"


def test_negatives_only_tmp_scan_zero(ka_home, tmp_path, monkeypatch, capsys) -> None:
    tree = tmp_path / "neg"
    shutil.copytree(NEGATIVES, tree)
    monkeypatch.chdir(tree)
    rc = main(["scan", "--no-import", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out or "{}")
    assert rc == 0
    assert data.get("leak_count", 0) == 0
    _assert_no_gen_values(captured.out + captured.err)


def test_demoted_only_tmp_scan_exit_paths(
    ka_home, tmp_path, monkeypatch, capsys
) -> None:
    tree = tmp_path / "dem"
    shutil.copytree(DEMOTED, tree)
    monkeypatch.chdir(tree)

    rc = main(["scan", "--no-import", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert rc == 0
    assert data["leak_count"] == 0
    assert data["possible_count"] > 0
    assert all(
        f["confidence"] in ("certain", "likely", "possible") for f in data["findings"]
    )
    _assert_no_gen_values(captured.out + captured.err)

    rc = main(["scan", "--no-import", "--strict", "high"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "--strict high" in captured.out
    assert "certain ·" in captured.out
    assert "possible" in captured.out.lower()
    _assert_no_gen_values(captured.out + captured.err)

    rc = main(["scan", "--no-import", "--strict", "paranoid"])
    captured = capsys.readouterr()
    assert rc == 1
    assert "--strict paranoid" in captured.out
    _assert_no_gen_values(captured.out + captured.err)


def test_likely_tree_exits_1_strict_high_and_paranoid(
    ka_home, tmp_path, monkeypatch, capsys
) -> None:
    tree = tmp_path / "high"
    tree.mkdir()
    (tree / "config.py").write_text(f'api_key = "{_GEN_MIXED}"\n', encoding="utf-8")
    monkeypatch.chdir(tree)

    rc = main(["scan", "--no-import", "--strict", "high", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert rc == 1
    assert data["leak_count"] >= 1
    _assert_no_gen_values(captured.out + captured.err)

    rc = main(["scan", "--no-import", "--strict", "paranoid"])
    captured = capsys.readouterr()
    assert rc == 1
    _assert_no_gen_values(captured.out + captured.err)


def test_strict_invalid_exits_2(ka_home) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--no-import", "--strict", "nope"])
    assert exc.value.code == 2


def test_generated_likely_in_env_json_yaml_toml_export(
    ka_home, tmp_path, monkeypatch, capsys
) -> None:
    tree = tmp_path / "gen"
    tree.mkdir()
    (tree / ".env").write_text(f"API_KEY={_GEN_MIXED}\n", encoding="utf-8")
    (tree / "config.json").write_text(
        json.dumps({"api_key": _GEN_MIXED_B}), encoding="utf-8"
    )
    (tree / "config.yaml").write_text(f"api_key: {_GEN_HEX32}\n", encoding="utf-8")
    (tree / "config.toml").write_text(f'api_key = "{_GEN_JWT}"\n', encoding="utf-8")
    (tree / "quoted.toml").write_text(
        f'"api_key" = "{_GEN_URLSAFE}"\n', encoding="utf-8"
    )
    (tree / "export.sh").write_text(f"export TOKEN={_GEN_MIXED}\n", encoding="utf-8")
    monkeypatch.chdir(tree)

    rc = main(["scan", "--no-import", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert rc == 1
    assert data["leak_count"] >= 1
    kinds_or_names = json.dumps(data)
    assert "api_key" in kinds_or_names.lower() or "API_KEY" in kinds_or_names
    _assert_no_gen_values(captured.out + captured.err)

    findings = scan_project(tree)
    assert leak_count(findings) >= 1
    paths = {
        Path(f.path).name
        for f in findings
        if f.confidence in ("certain", "likely")
    }
    assert ".env" in paths
    assert "config.json" in paths
    assert "config.yaml" in paths
    assert "config.toml" in paths
    assert "quoted.toml" in paths
    assert "export.sh" in paths


def test_md_likely_assignment_counts_under_default_gate(
    ka_home, tmp_path, monkeypatch, capsys
) -> None:
    tree = tmp_path / "docs"
    tree.mkdir()
    (tree / "notes.md").write_text(f'api_key = "{_GEN_MIXED}"\n', encoding="utf-8")
    monkeypatch.chdir(tree)
    rc = main(["scan", "--no-import", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["leak_count"] >= 1
    assert rc == 1
    _assert_no_gen_values(captured.out + captured.err)

    (tree / "readme.md").write_text("sk-" + "a" * 25 + "\n", encoding="utf-8")
    rc = main(["scan", "--no-import", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["leak_count"] >= 2
    assert rc == 1
    _assert_no_gen_values(captured.out + captured.err)


def test_bearer_identifier_hook_denies_scan_not_leak(ka_home, tmp_path) -> None:
    text = "Authorization: Bearer someVariableName"
    assert sg.find_finding(text) == "Bearer token"
    tree = tmp_path / "b"
    tree.mkdir()
    (tree / "hdr.txt").write_text(text + "\n", encoding="utf-8")
    findings = scan_project(tree)
    assert leak_count(findings) == 0
    assert possible_count(findings) >= 1


def test_product_diff_has_no_new_network_imports() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "key_amnesia"
    banned = ("urllib.request", "urllib3", "requests", "http.client", "aiohttp")
    for path in (
        root / "detect.py",
        root / "scan.py",
        root / "hooks" / "secret_guard.py",
    ):
        text = path.read_text(encoding="utf-8")
        for name in banned:
            assert name not in text


def test_highest_tier_wins_both_assignment_orderings() -> None:
    ident = "mySecretValue"
    likely = _GEN_MIXED
    texts = (
        f'api_key = "{ident}"\napi_key = "{likely}"\n',
        f'api_key = "{likely}"\napi_key = "{ident}"\n',
    )
    for text in texts:
        hits = scan_text_hits(text)
        assert any(n.upper() == "API_KEY" for n in hits.likely_names)
        assert all(n.upper() != "API_KEY" for n in hits.possible_names)
        assert find_secret_kind(text) == "API_KEY assignment"


def test_transcript_mixed_line_records_possible_names(tmp_path: Path) -> None:
    path = tmp_path / "mixed.jsonl"
    line = json.dumps(
        {
            "type": "user",
            "content": f'api_key = "{_GEN_MIXED}"\ntoken = mySecretValue',
        }
    )
    path.write_text(line + "\n", encoding="utf-8")
    findings = _findings_for_transcript(path, scope="deep")
    high = [f for f in findings if f.confidence in ("certain", "likely")]
    poss = [f for f in findings if f.confidence == "possible"]
    assert high and high[0].hit_lines == [1]
    assert poss
    assert poss[0].hit_lines == []
    assert poss[0].secret_count == 0
    assert any(n.upper() == "TOKEN" for n in poss[0].secret_names)
    assert leak_count(findings) == 1
    assert leak_count(findings, strict="paranoid") == 1
    assert possible_count(findings) == 0
    assert transcript_line_hit_count(findings) == high[0].secret_count


def test_transcript_prefix_and_likely_same_line_keeps_likely_names(
    tmp_path: Path,
) -> None:
    path = tmp_path / "prefix-likely.jsonl"
    prefix = "sk-" + "a" * 25
    line = json.dumps(
        {
            "type": "user",
            "content": f'{prefix}\napi_key = "{_GEN_MIXED}"',
        }
    )
    path.write_text(line + "\n", encoding="utf-8")
    findings = _findings_for_transcript(path, scope="deep")
    certain = [f for f in findings if f.confidence == "certain"]
    likely = [f for f in findings if f.confidence == "likely"]
    assert certain and certain[0].secret_count == 1
    assert likely
    assert any(n.upper() == "API_KEY" for n in likely[0].secret_names)
    assert likely[0].secret_count == 0
    assert leak_count(findings, strict="high") == 1


def test_uuid_assignment_is_likely_with_reason(ka_home, tmp_path, monkeypatch, capsys) -> None:
    generated = str(uuid.uuid4())
    while generated.strip("0-") == "":
        generated = str(uuid.uuid4())
    tree = tmp_path / "uuid"
    tree.mkdir()
    (tree / "config.py").write_text(f'api_key = "{generated}"\n', encoding="utf-8")
    monkeypatch.chdir(tree)

    tier, reason = classify_value(generated)
    assert tier == "likely"
    assert reason == REASON_UUID
    assert classify_value("00000000-0000-0000-0000-000000000000")[0] == "none"
    assert sg.find_finding(f'api_key = "{generated}"') is not None

    findings = scan_project(tree)
    assert leak_count(findings) >= 1
    uuid_findings = [f for f in findings if REASON_UUID in f.reasons]
    assert uuid_findings
    rc = main(["scan", "--no-import", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert rc == 1
    assert data["leak_count"] >= 1
    assert generated not in captured.out
    assert generated not in captured.err


def test_mcp_json_unrecognised_shape_demotes_not_dropped(ka_home, tmp_path) -> None:
    tree = tmp_path / "mcp-tree"
    tree.mkdir()
    # Expected field shape (docs only, no live tree): 1 certain dotenv +
    # 2 possible unconfirmed-mcp.
    (tree / ".env").write_text("API_KEY=placeholder_not_used\n", encoding="utf-8")
    (tree / "mcp.json").write_text('{"name": "demo"}\n', encoding="utf-8")
    other = tree / "claude_desktop_config.json"
    other.write_text('{"theme": "dark"}\n', encoding="utf-8")

    findings = scan_project(tree)
    mcp = [f for f in findings if f.kind == "mcp_config"]
    assert len(mcp) == 2
    assert all(f.confidence == "possible" for f in mcp)
    assert all(REASON_UNCONFIRMED_MCP in f.reasons for f in mcp)
    assert possible_count(findings) == 2

    (tree / "mcp.json").write_text(
        '{"alpha": 1, "beta": 2, "gamma": 3}\n', encoding="utf-8"
    )
    findings = scan_project(tree)
    fat = [f for f in findings if Path(f.path).name == "mcp.json"]
    assert fat and fat[0].confidence == "possible"
    assert fat[0].secret_count == 1
    assert fat[0].reason_counts.get(REASON_UNCONFIRMED_MCP) == 1
    assert len(fat[0].secret_names) == 3
    assert possible_count(findings) == 2

    (tree / "mcp.json").write_text('{"mcpServers": {}}\n', encoding="utf-8")
    findings = scan_project(tree)
    confirmed = [
        f
        for f in findings
        if f.kind == "mcp_config" and Path(f.path).name == "mcp.json"
    ]
    assert confirmed
    assert confirmed[0].confidence == "certain"
    assert leak_count(findings) >= 1


def test_nested_jsonl_secret_key_walk_and_timing(tmp_path: Path) -> None:
    """Secret-named keys that never appear as ASSIGN text are still found.

    Nested-JSON double-walk removed. Same generated 4000-line secret-keyed
    nested JSONL (23_464_000 bytes) timed 75.8432s before (recursive
    ``_apply_obj`` re-walk) vs 51.9149s after. File is throwaway, not committed.
    """
    path = tmp_path / "nested.jsonl"
    path.write_text(
        json.dumps({"wrapper": {"api_key": _GEN_MIXED}}) + "\n",
        encoding="utf-8",
    )
    findings = _findings_for_transcript(path, scope="deep")
    assert leak_count(findings) >= 1
    assert any(
        n.upper() == "API_KEY" for f in findings for n in f.secret_names
    )

    generated = str(uuid.uuid4())
    while generated.strip("0-") == "":
        generated = str(uuid.uuid4())
    wrapped = tmp_path / "wrapped.jsonl"
    wrapped.write_text(
        json.dumps({"content": json.dumps({"api_key": generated})}) + "\n",
        encoding="utf-8",
    )
    wrapped_findings = _findings_for_transcript(wrapped, scope="deep")
    likely = [f for f in wrapped_findings if f.confidence == "likely"]
    assert leak_count(wrapped_findings) == 1
    assert likely
    assert likely[0].reason_counts.get(REASON_UUID) == 1
    assert sum(1 for n in likely[0].secret_names if n.upper() == "API_KEY") == 1

    bulky = tmp_path / "bulky.jsonl"
    inner = {
        "wrapper": {"inner": {"note": "no-assign-here", "blob": "x" * 200}},
        "more": [{"k": "v" * 50} for _ in range(20)],
        "extra": ["n" * 80 for _ in range(30)],
    }
    payload = {
        "type": "user",
        "message": {
            "content": "debug this",
            "api_key": json.dumps(inner),
            "token": json.dumps({"deeper": ["z" * 100 for _ in range(15)]}),
        },
    }
    n_lines = 200
    with bulky.open("w", encoding="utf-8") as fh:
        for _ in range(n_lines):
            fh.write(json.dumps(payload) + "\n")
    t0 = time.perf_counter()
    _findings_for_transcript(bulky, scope="deep")
    elapsed = time.perf_counter() - t0
    # 200 lines of the 4000-line secret-keyed shape; after-fix 4000-line was
    # 51.9s so this budget is ~2.6s typical. Fail if the double-walk returns.
    assert elapsed < 8.0


def test_strict_headline_and_summary_example_shape() -> None:
    findings = [
        Finding(
            path="a.env",
            kind="dotenv",
            secret_names=["A"],
            secret_count=1,
            reason="dotenv",
            confidence="certain",
        ),
        Finding(
            path="b.py",
            kind="inline",
            secret_names=["k"],
            secret_count=3,
            reason="likely",
            confidence="likely",
        ),
        Finding(
            path="c.py",
            kind="inline",
            secret_names=["i"],
            secret_count=19,
            reason="possible",
            confidence="possible",
            reasons=["identifier"],
            reason_counts={"identifier": 19},
        ),
        Finding(
            path="d.py",
            kind="inline",
            secret_names=["p"],
            secret_count=6,
            reason="possible",
            confidence="possible",
            reasons=["word-shaped-passphrase"],
            reason_counts={"word-shaped-passphrase": 6},
        ),
        Finding(
            path="e.py",
            kind="inline",
            secret_names=["l"],
            secret_count=3,
            reason="possible",
            confidence="possible",
            reasons=["low-transition"],
            reason_counts={"low-transition": 3},
        ),
    ]
    summary = format_count_summary(findings)
    assert summary == (
        "1 certain · 3 likely · 28 possible "
        "(19 identifier · 6 passphrase · 3 low-transition)"
    )
    assert headline(findings, strict="certain").startswith(
        "1 LEAK found (--strict certain)"
    )
    assert headline(findings, strict="high").startswith(
        "4 LEAKs found (--strict high)"
    )
    assert headline(findings, strict="paranoid").startswith(
        "32 LEAKs found (--strict paranoid)"
    )
    gates = format_gate_totals(findings)
    assert "--strict certain" in gates
    assert "--strict high" in gates
    assert "--strict paranoid" in gates
    assert gates.splitlines()[0].endswith("1")
    assert gates.splitlines()[1].endswith("4")
    assert gates.splitlines()[2].endswith("32")


def _summary_line(text: str) -> str:
    for line in text.splitlines():
        if "certain ·" in line:
            return line
    return ""


def test_strict_three_levels_listing_exit_and_summary(
    ka_home, tmp_path, monkeypatch, capsys
) -> None:
    tree = tmp_path / "mix"
    tree.mkdir()
    (tree / ".env").write_text("API_KEY=placeholder_not_used\n", encoding="utf-8")
    (tree / "a.py").write_text(f'api_key = "{_GEN_MIXED}"\n', encoding="utf-8")
    (tree / "b.py").write_text("token = mySecretValue\n", encoding="utf-8")
    monkeypatch.chdir(tree)

    rc_c = main(["scan", "--no-import", "--strict", "certain"])
    out_c = capsys.readouterr().out
    assert rc_c == 1
    assert "--strict certain" in out_c
    assert "confidence=certain" in out_c
    assert "confidence=likely" not in out_c
    assert "confidence=possible" not in out_c

    rc_h = main(["scan", "--no-import", "--strict", "high"])
    out_h = capsys.readouterr().out
    assert rc_h == 1
    assert "--strict high" in out_h
    assert "confidence=likely" in out_h
    assert "confidence=possible" not in out_h

    rc_p = main(["scan", "--no-import", "--strict", "paranoid"])
    out_p = capsys.readouterr().out
    assert rc_p == 1
    assert "--strict paranoid" in out_p
    assert "confidence=possible" in out_p

    assert _summary_line(out_c) == _summary_line(out_h) == _summary_line(out_p)
    _assert_no_gen_values(out_c + out_h + out_p)

    rc_j = main(["scan", "--no-import", "--strict", "certain", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["leak_count"] == data["certain_count"]
    assert "--strict certain" in data["headline"]


def test_scan_help_has_strict_wide_not_unreleased_flags(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--help"])
    blob = capsys.readouterr().out + capsys.readouterr().err
    assert exc.value.code == 0
    assert "--fail-on" not in blob
    assert "--show-possible" not in blob
    assert "--strict" in blob
    assert "--wide" in blob
    assert "--quiet" in blob


def _assign_name_and_len(text: str) -> list[tuple[str, int]]:
    return [(name, len(value)) for name, value in _iter_assignments(text)]


def _legacy_assign_name_and_len(text: str) -> list[tuple[str, int]]:
    return [
        (match.group("name"), len(match.group("value")))
        for match in ASSIGN.finditer(text)
    ]


def _finding_sig(finding: Finding) -> tuple:
    return (
        finding.kind,
        tuple(finding.secret_names),
        finding.secret_count,
        finding.confidence,
        tuple(finding.reasons),
        tuple(finding.hit_lines),
        tuple(sorted(finding.reason_counts.items())),
    )


def test_assign_differential_corpus() -> None:
    """New matcher must be finding-identical to ASSIGN on the labeled corpus."""
    from key_amnesia import detect as detect_mod

    orig = detect_mod._iter_assignments

    def _legacy(text: str):
        for match in ASSIGN.finditer(text):
            yield match.group("name"), match.group("value")

    for path in _iter_files(CORPUS):
        text = path.read_text(encoding="utf-8")
        assert _legacy_assign_name_and_len(text) == _assign_name_and_len(text), (
            path.name
        )
        old_vals = [match.group("value") for match in ASSIGN.finditer(text)]
        new_vals = [value for _name, value in _iter_assignments(text)]
        if old_vals != new_vals:
            pytest.fail(f"{path.name}: assignment value mismatch (values omitted)")

        new_findings = [_finding_sig(f) for f in _findings_for_path(path, scope="project")]
        detect_mod._iter_assignments = _legacy
        try:
            old_findings = [
                _finding_sig(f) for f in _findings_for_path(path, scope="project")
            ]
        finally:
            detect_mod._iter_assignments = orig
        assert old_findings == new_findings, path.name


def test_assign_rewrite_shapes() -> None:
    v = _GEN_MIXED
    assert _assign_name_and_len(f"secrets.api_key = {v}") == [("api_key", len(v))]
    assert _assign_name_and_len(f"my_db_password: {v}") == [("my_db_password", len(v))]
    assert _assign_name_and_len(f'"api_key": "{v}"') == [("api_key", len(v))]
    assert _assign_name_and_len(f"api_key='{v}'") == [("api_key", len(v))]
    assert _assign_name_and_len(f"API_KEY={v}") == [("API_KEY", len(v))]
    # Opening quote without a closing name quote: old ASSIGN still matches
    # from the keyword (nq empty). Value-side mismatch does not.
    assert _assign_name_and_len(f'"api_key: {v}') == [("api_key", len(v))]
    assert _assign_name_and_len(f"api_key=\"{v}'") == []
    assert _assign_name_and_len(f"!api_key={v}") == [("api_key", len(v))]
    assert _assign_name_and_len(f"café_token={v}") == [("token", len(v))]
    assert _assign_name_and_len(f"secret_token={v}") == [("secret_token", len(v))]
    hits = scan_text_hits(f"secret_token={v}")
    assert [name.upper() for name in hits.likely_names] == ["SECRET_TOKEN"]


def test_prefix_kind_follows_pattern_order_not_leftmost() -> None:
    aws = "AKIAAAAAAAAAAAAAAAAA"
    openai = "sk-" + ("a" * 24)
    text = aws + " then " + openai
    assert find_prefix_kind(text) == "OpenAI-style key"
    assert scan_text_hits(text).prefix == "OpenAI-style key"


def test_assign_blowup_dotted_run_under_one_second() -> None:
    n = (256 * 1024) // 12
    text = ("a1234567890." * n) + "token"
    t0 = time.perf_counter()
    consumed = list(_iter_assignments(text))
    elapsed = time.perf_counter() - t0
    assert elapsed < 1.0
    assert consumed == []


def test_assign_blowup_alnum_prefix_under_one_second() -> None:
    unit = ("a" * 4000) + "_token="
    n = max(1, (256 * 1024) // len(unit))
    text = unit * n
    t0 = time.perf_counter()
    list(_iter_assignments(text))
    elapsed = time.perf_counter() - t0
    assert elapsed < 1.0


# --- space-separated flag form (`--api-key <value>`) -----------------------
# Measured against installed 0.4.15: `NAME=<value>`, `--api-key=<value>` and
# `Bearer <v>` were caught; `--api-key <value>` / `--token <value>` /
# `--password <value>` were caught nowhere. A credential on argv is the exact
# leak this product exists to prevent.


FLAG_FORM_MUST_FIRE = [
    f"mysql --password {_GEN_MIXED_B} -u root app_db",
    f"./cli --api-key {_GEN_MIXED} sync",
    f"curl --token {_GEN_HEX32} https://api.example.com",
    f"curl --api-key {_GEN_UUID} https://api.example.com",
    f"ansible-playbook site.yml --vault-password {_GEN_MIXED_B}",
    f"java -jar app.jar --private-key {_GEN_URLSAFE}",
    f"pgcli --password {_GEN_WEAK_PW} -h db.example.com",
    f'docker login -u me --password "{_GEN_WEAK_PW}"',
]

# Recommended usage and env/file indirection. Denying any of these would make
# the product unusable, so they are the hard constraint on the matcher.
FLAG_FORM_MUST_NOT_FIRE = [
    "ka run --secret GOOGLE_API_KEY -- ./deploy.sh",
    "ka run --secret OPENAI_API_KEY --as OPENAI_API_KEY=OPENAI_API_KEY -- python train.py",
    'gh release create v1.2.3 --token "$GITHUB_TOKEN"',
    'psql --password "$PGPASSWORD" -h db.example.com -U app',
    "python app.py --api-key $OPENAI_API_KEY",
    "aws secretsmanager get-secret-value --secret-name prod/db/password",
    "docker login registry.example.com -u ci --password-stdin",
    "vault login --token-file ./token.txt",
    "gh auth login --with-token < token.txt",
    "mysql --password --host=db.internal.example.com",
    "docker buildx build --secret id=app,src=./secrets/app.env .",
    "curl --api-key ./keys/Prod2Key.pem https://api.example.com",
    "curl --api-key /run/secrets/api_key https://api.example.com",
    'git commit -m "rotate the api key and token in CI"',
    "mysql --password changeme -u root",
    "curl --api-key <YOUR_KEY_HERE> https://api.example.com",
]


@pytest.mark.parametrize("command", FLAG_FORM_MUST_FIRE)
def test_flag_form_space_separated_fires(command: str) -> None:
    kind = find_secret_kind(command)
    assert kind is not None, command
    # Never leak the value through the reported kind.
    for value in (*_GEN_VALUES, _GEN_WEAK_PW, _GEN_UUID):
        assert value not in kind


@pytest.mark.parametrize("command", FLAG_FORM_MUST_NOT_FIRE)
def test_flag_form_env_indirection_stays_quiet(command: str) -> None:
    assert find_secret_kind(command) is None, command
    assert list(_iter_flag_values(command)) == [] or not scan_text_hits(
        command
    ).flag_names


def test_flag_form_reason_and_kind_name_the_flag() -> None:
    hits = scan_text_hits(f"mysql --password {_GEN_MIXED_B} -u root")
    assert [n.upper() for n in hits.likely_names] == ["PASSWORD"]
    assert hits.flag_names == ["PASSWORD"]
    assert REASON_FLAG_FORM in hits.likely_reasons
    assert find_secret_kind(f"mysql --password {_GEN_MIXED_B}") == "--password flag value"
    # Assignment hits keep the old phrasing.
    assert find_secret_kind(f"PASSWORD={_GEN_MIXED_B}") == "PASSWORD assignment"


def test_flag_form_tier_is_one_flippable_constant(monkeypatch: pytest.MonkeyPatch) -> None:
    """FLAG_FORM_FIRE_TIERS is the whole tier decision — nothing else changes."""
    from key_amnesia import detect as detect_mod

    strong = f"mysql --password {_GEN_MIXED_B} -u root"
    weak = f"pgcli --password {_GEN_WEAK_PW} -h db.example.com"
    assert classify_value(_GEN_MIXED_B)[0] == "likely"
    assert classify_value(_GEN_WEAK_PW) == ("possible", NAMED_WEAKENING_LOW_TRANSITION)

    monkeypatch.setattr(detect_mod, "FLAG_FORM_FIRE_TIERS", ("likely",))
    assert find_secret_kind(strong) is not None
    assert find_secret_kind(weak) is None

    monkeypatch.setattr(detect_mod, "FLAG_FORM_FIRE_TIERS", ("likely", "possible"))
    assert find_secret_kind(strong) is not None
    assert find_secret_kind(weak) is not None


def test_flag_form_shipped_tier_is_likely_plus_possible() -> None:
    """Measured recommendation: 0 false positives, 7 misses -> 1 over 39 cases."""
    assert FLAG_FORM_FIRE_TIERS == ("likely", "possible")


def test_flag_form_is_outside_iter_assignments() -> None:
    """Structural invariant behind test_assign_differential_corpus.

    The flag form must never be produced by ``_iter_assignments``, or the
    legacy ``ASSIGN`` equivalence breaks by construction.
    """
    for command in FLAG_FORM_MUST_FIRE + FLAG_FORM_MUST_NOT_FIRE:
        assert _assign_name_and_len(command) == _legacy_assign_name_and_len(command)
    assert _assign_name_and_len(f"mysql --password {_GEN_MIXED_B}") == []
    # And the assignment form still wins its own shape.
    assert _assign_name_and_len(f"--api-key={_GEN_MIXED}") == [("api-key", len(_GEN_MIXED))]


def test_flag_form_hook_denies_argv_credential() -> None:
    assert sg.find_finding(f"mysql --password {_GEN_MIXED_B} -u root") is not None
    assert sg.find_finding(f"pgcli --password {_GEN_WEAK_PW} -h db") is not None
    # ka-routed usage is still allowed end to end.
    assert sg.find_finding("ka run --secret GOOGLE_API_KEY -- ./deploy.sh") is None


def test_flag_form_blowup_under_one_second() -> None:
    """Flat name class: a nested one backtracks catastrophically here."""
    unit = "-" + ("a" * 4000) + "_token"
    n = max(1, (256 * 1024) // len(unit))
    text = unit * n
    t0 = time.perf_counter()
    list(_iter_flag_values(text))
    assert time.perf_counter() - t0 < 1.0
