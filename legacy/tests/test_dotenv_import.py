"""Unit tests for the shared dotenv_import core (parsing, merge, offers)."""

from __future__ import annotations

from pathlib import Path

import pytest

from key_amnesia.dotenv_import import (
    commit_import,
    delete_or_rename_source,
    generate_or_merge_manifest,
    import_entries,
    offer_gitignore,
    parse_dotenv,
)


def test_parse_dotenv_basic(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text(
        "\n".join(
            [
                "# a comment line",
                "",
                "OPENAI_API_KEY=sk-abc123",
                "export DB_PASSWORD=p@ss w0rd",
                'QUOTED="hello world"',
                "SINGLE='single quoted'",
                "WITH_COMMENT=value # trailing comment",
                "not a valid line",
            ]
        ),
        encoding="utf-8",
    )
    entries = parse_dotenv(env)
    assert entries == {
        "OPENAI_API_KEY": "sk-abc123",
        "DB_PASSWORD": "p@ss w0rd",
        "QUOTED": "hello world",
        "SINGLE": "single quoted",
        "WITH_COMMENT": "value",
    }


def test_parse_dotenv_empty_file(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("", encoding="utf-8")
    assert parse_dotenv(env) == {}


def test_import_entries_default_skips_collision() -> None:
    existing = {"NAME": "old-value"}
    imported, skipped = import_entries({"NAME": "new-value", "OTHER": "x"}, existing)
    assert imported == ["OTHER"]
    assert skipped == ["NAME"]
    # Default is skip — never a silent overwrite.
    assert existing["NAME"] == "old-value"
    assert existing["OTHER"] == "x"


def test_import_entries_overwrite_via_callback() -> None:
    existing = {"NAME": "old-value"}
    imported, skipped = import_entries(
        {"NAME": "new-value"}, existing, on_collision=lambda name: "overwrite"
    )
    assert imported == ["NAME"]
    assert skipped == []
    assert existing["NAME"] == "new-value"


def test_import_entries_no_collisions() -> None:
    existing: dict[str, str] = {}
    imported, skipped = import_entries({"A": "1", "B": "2"}, existing)
    assert imported == ["A", "B"]
    assert skipped == []
    assert existing == {"A": "1", "B": "2"}


def test_generate_manifest_creates_minimal_entries(tmp_path: Path) -> None:
    manifest = generate_or_merge_manifest(["API_KEY", "DB_PASSWORD"], tmp_path)
    assert manifest == tmp_path / "amnesia.toml"
    text = manifest.read_text(encoding="utf-8")
    assert "[secrets.API_KEY]" in text
    assert "[secrets.DB_PASSWORD]" in text
    assert 'env = "API_KEY"' in text
    assert "required = true" in text
    assert 'description = ""' in text
    assert "[[secret]]" not in text
    assert 'name = "API_KEY"' not in text


def test_generate_manifest_merges_without_duplicating(tmp_path: Path) -> None:
    manifest_path = tmp_path / "amnesia.toml"
    manifest_path.write_text(
        '[secrets.EXISTING]\nrequired = true\ndescription = ""\nenv = "EXISTING"\n',
        encoding="utf-8",
    )
    generate_or_merge_manifest(["EXISTING", "NEW_ONE"], tmp_path)
    text = manifest_path.read_text(encoding="utf-8")
    assert text.count('env = "EXISTING"') == 1
    assert text.count('env = "NEW_ONE"') == 1
    assert "[secrets.EXISTING]" in text
    assert "[secrets.NEW_ONE]" in text


def test_generate_manifest_noop_when_all_present(tmp_path: Path) -> None:
    manifest_path = tmp_path / "amnesia.toml"
    original = '[secrets.A]\nrequired = true\ndescription = ""\nenv = "A"\n'
    manifest_path.write_text(original, encoding="utf-8")
    generate_or_merge_manifest(["A"], tmp_path)
    assert manifest_path.read_text(encoding="utf-8") == original


def test_generate_manifest_merges_onto_legacy_without_duplicating(tmp_path: Path) -> None:
    manifest_path = tmp_path / "amnesia.toml"
    manifest_path.write_text(
        '[[secret]]\nname = "LEGACY"\nrequired = true\ndescription = ""\nenv = "LEGACY"\n',
        encoding="utf-8",
    )
    generate_or_merge_manifest(["LEGACY", "NEW"], tmp_path)
    text = manifest_path.read_text(encoding="utf-8")
    assert text.count("LEGACY") >= 1
    assert "[secrets.NEW]" in text
    # Did not append a second LEGACY block.
    assert "[secrets.LEGACY]" not in text


def test_offer_gitignore_added_on_yes(tmp_path: Path) -> None:
    added = offer_gitignore(tmp_path, ask=lambda: True)
    assert added is True
    text = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert ".env*" in text.splitlines()


def test_offer_gitignore_declined(tmp_path: Path) -> None:
    added = offer_gitignore(tmp_path, ask=lambda: False)
    assert added is False
    assert not (tmp_path / ".gitignore").exists()


def test_offer_gitignore_never_silent_even_with_existing_file(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    asked = {"called": False}

    def ask() -> bool:
        asked["called"] = True
        return True

    added = offer_gitignore(tmp_path, ask=ask)
    assert asked["called"] is True
    assert added is True
    text = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert "node_modules/" in text
    assert ".env*" in text.splitlines()


def test_offer_gitignore_noop_if_already_covers_env(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(".env*\n", encoding="utf-8")
    asked = {"called": False}

    def ask() -> bool:
        asked["called"] = True
        return True

    added = offer_gitignore(tmp_path, ask=ask)
    assert added is False
    assert asked["called"] is False


def test_delete_or_rename_deletes_on_double_confirm(tmp_path: Path) -> None:
    f = tmp_path / ".env"
    f.write_text("A=1\n", encoding="utf-8")
    outcome = delete_or_rename_source(
        f,
        confirm_delete=lambda: True,
        confirm_delete_again=lambda: True,
        confirm_rename=lambda: (_ for _ in ()).throw(AssertionError("should not be asked")),
    )
    assert outcome == "deleted"
    assert not f.exists()


def test_delete_or_rename_keeps_on_declined_double_confirm(tmp_path: Path) -> None:
    f = tmp_path / ".env"
    f.write_text("A=1\n", encoding="utf-8")
    outcome = delete_or_rename_source(
        f,
        confirm_delete=lambda: True,
        confirm_delete_again=lambda: False,
        confirm_rename=lambda: (_ for _ in ()).throw(AssertionError("should not be asked")),
    )
    assert outcome == "kept"
    assert f.exists()


def test_delete_or_rename_renames_when_delete_declined(tmp_path: Path) -> None:
    f = tmp_path / ".env"
    f.write_text("A=1\n", encoding="utf-8")
    outcome = delete_or_rename_source(
        f,
        confirm_delete=lambda: False,
        confirm_delete_again=lambda: (_ for _ in ()).throw(AssertionError("should not be asked")),
        confirm_rename=lambda: True,
    )
    assert outcome == "renamed"
    assert not f.exists()
    assert (tmp_path / ".env.imported").exists()
    assert (tmp_path / ".env.imported").read_text(encoding="utf-8") == "A=1\n"


def test_delete_or_rename_keeps_when_both_declined(tmp_path: Path) -> None:
    f = tmp_path / ".env"
    f.write_text("A=1\n", encoding="utf-8")
    outcome = delete_or_rename_source(
        f,
        confirm_delete=lambda: False,
        confirm_delete_again=lambda: (_ for _ in ()).throw(AssertionError("should not be asked")),
        confirm_rename=lambda: False,
    )
    assert outcome == "kept"
    assert f.exists()


def test_commit_import_save_failure_leaves_both_sources(tmp_path: Path) -> None:
    a = tmp_path / ".env"
    b = tmp_path / ".env.local"
    a.write_text("A=one\n", encoding="utf-8")
    b.write_text("B=two\n", encoding="utf-8")
    secrets: dict[str, str] = {}

    def boom() -> None:
        raise RuntimeError("save failed")

    with pytest.raises(RuntimeError, match="save failed"):
        commit_import(
            [a, b],
            secrets,
            on_collision=None,
            on_missing="skip",
            commit_vault=boom,
            confirm_delete=lambda _p: True,
            confirm_delete_again=lambda _p: True,
            confirm_rename=lambda _p: True,
            gitignore_ask=lambda: True,
            project_root=tmp_path,
        )
    assert a.exists()
    assert b.exists()
    assert not (tmp_path / ".env.imported").exists()
    assert not (tmp_path / ".env.local.imported").exists()
    assert not (tmp_path / ".gitignore").exists()
    assert not (tmp_path / "amnesia.toml").exists()


def test_commit_import_saves_then_deletes(tmp_path: Path) -> None:
    a = tmp_path / ".env"
    a.write_text("A=one\n", encoding="utf-8")
    secrets: dict[str, str] = {}
    committed = {"n": 0}

    def commit() -> None:
        committed["n"] += 1
        assert a.exists()

    result = commit_import(
        [a],
        secrets,
        on_collision=None,
        on_missing="error",
        commit_vault=commit,
        confirm_delete=lambda _p: True,
        confirm_delete_again=lambda _p: True,
        confirm_rename=lambda _p: True,
        gitignore_ask=lambda: True,
        project_root=tmp_path,
    )
    assert committed["n"] == 1
    assert result.imported == ["A"]
    assert result.path_outcomes[str(a)] == "deleted"
    assert not a.exists()
    assert result.gitignore_added is True
    assert (tmp_path / ".gitignore").read_text(encoding="utf-8").splitlines()[-1] == ".env*"
    assert result.manifest_path == tmp_path / "amnesia.toml"


def test_commit_import_missing_error_raises(tmp_path: Path) -> None:
    missing = tmp_path / "nope.env"
    with pytest.raises(FileNotFoundError):
        commit_import(
            [missing],
            {},
            on_missing="error",
            commit_vault=lambda: (_ for _ in ()).throw(AssertionError("no commit")),
            confirm_delete=lambda _p: False,
            confirm_delete_again=lambda _p: False,
            confirm_rename=lambda _p: False,
            gitignore_ask=lambda: False,
            project_root=tmp_path,
        )


def test_commit_import_missing_skip(tmp_path: Path) -> None:
    missing = tmp_path / "nope.env"
    result = commit_import(
        [missing],
        {},
        on_missing="skip",
        commit_vault=lambda: (_ for _ in ()).throw(AssertionError("no commit")),
        confirm_delete=lambda _p: False,
        confirm_delete_again=lambda _p: False,
        confirm_rename=lambda _p: False,
        gitignore_ask=lambda: False,
        project_root=tmp_path,
    )
    assert result.path_outcomes[str(missing)] == "missing"
    assert result.imported == []
