"""End-to-end coverage of ``mesh init``.

Deliberately does not use the ``env``/``cli_env`` fixtures from
``tests/e2e/conftest.py`` -- those pre-supply a contact, a database, and
a template, which is exactly the state ``mesh init`` exists to create.
Every test here starts from the bare, empty ``tmp_path`` that
``tests/conftest.py``'s autouse ``_isolated_cwd_and_env`` fixture already
chdirs into.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.db.nodes import NodeRepository
from meshprovision.db.ods import OdsDatabase
from tests.e2e.conftest import db_fingerprint, invoke

if TYPE_CHECKING:
    from click.testing import CliRunner

pytestmark = pytest.mark.e2e

_BARE_ENV: dict[str, str] = {"COLUMNS": "200", "NO_COLOR": "1"}


def test_creates_env_template_and_database_in_an_empty_directory(
    runner: CliRunner, tmp_path: Path
) -> None:
    result = invoke(runner, ["init", "--yes", "--contact", "ops@example.org"], _BARE_ENV)

    assert result.exit_code == 0
    assert (tmp_path / ".env").is_file()
    assert (tmp_path / "config" / "template.yaml").is_file()
    assert (tmp_path / "data" / "nodes_db.ods").is_file()
    assert "MESHPROVISION_CONTACT=ops@example.org" in (tmp_path / ".env").read_text(
        encoding="utf-8"
    )


def test_prompts_interactively_for_the_contact(runner: CliRunner, tmp_path: Path) -> None:
    # mesh init confirms each missing artifact individually (env, then
    # template, then database) rather than with one combined banner
    # confirm -- unlike the auto-offer path, this is already an explicit
    # request.
    result = invoke(
        runner, ["--interactive", "init"], _BARE_ENV, input="y\nops@example.org\ny\ny\n"
    )

    assert result.exit_code == 0, result.output
    assert "MESHPROVISION_CONTACT=ops@example.org" in (tmp_path / ".env").read_text(
        encoding="utf-8"
    )


def test_run_twice_never_rewrites_an_existing_file(runner: CliRunner, tmp_path: Path) -> None:
    invoke(runner, ["init", "--yes", "--contact", "ops@example.org"], _BARE_ENV)
    before = {
        path: db_fingerprint(path)
        for path in (
            tmp_path / ".env",
            tmp_path / "config" / "template.yaml",
            tmp_path / "data" / "nodes_db.ods",
        )
    }

    result = invoke(runner, ["init", "--yes", "--contact", "someone-else@example.org"], _BARE_ENV)

    assert result.exit_code == 0
    assert "already complete" in result.output
    for path, fingerprint in before.items():
        assert db_fingerprint(path) == fingerprint


def test_honors_db_path_and_template_path_overrides(runner: CliRunner, tmp_path: Path) -> None:
    env = dict(_BARE_ENV)
    db_path = tmp_path / "custom" / "db.ods"
    template_path = tmp_path / "custom" / "tpl.yaml"
    env["MESHPROVISION_DB_PATH"] = str(db_path)
    env["MESHPROVISION_TEMPLATE_PATH"] = str(template_path)

    result = invoke(runner, ["init", "--yes", "--contact", "ops@example.org"], env)

    assert result.exit_code == 0
    assert db_path.is_file()
    assert template_path.is_file()
    assert not (tmp_path / "data" / "nodes_db.ods").exists()


def test_honors_an_explicit_env_file(runner: CliRunner, tmp_path: Path) -> None:
    explicit = tmp_path / "custom.env"

    args = ["--env-file", str(explicit), "init", "--yes", "--contact", "ops@example.org"]
    result = invoke(runner, args, _BARE_ENV)

    assert result.exit_code == 0
    assert explicit.is_file()
    assert not (tmp_path / ".env").exists()


def test_json_lists_the_created_paths(runner: CliRunner, tmp_path: Path) -> None:
    result = invoke(runner, ["init", "--yes", "--contact", "ops@example.org", "--json"], _BARE_ENV)

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert len(payload["created"]) == 3
    assert payload["declined"] == []


def test_non_interactive_without_a_contact_exits_five(runner: CliRunner, tmp_path: Path) -> None:
    result = invoke(runner, ["init", "--yes"], _BARE_ENV)

    assert result.exit_code == 5
    assert not (tmp_path / ".env").exists()


def test_creates_an_empty_database_not_the_fake_example_rows(
    runner: CliRunner, tmp_path: Path, repo_root: Path
) -> None:
    result = invoke(runner, ["init", "--yes", "--contact", "ops@example.org"], _BARE_ENV)
    assert result.exit_code == 0

    db_path = tmp_path / "data" / "nodes_db.ods"
    db = OdsDatabase(db_path)
    db.load()
    nodes = NodeRepository(db)
    assert nodes.all() == ()

    example_path = repo_root / "data" / "nodes_db.example.ods"
    assert db_path.read_bytes() != example_path.read_bytes()


def test_init_then_db_verify_succeeds(runner: CliRunner, tmp_path: Path) -> None:
    invoke(runner, ["init", "--yes", "--contact", "ops@example.org"], _BARE_ENV)

    result = invoke(runner, ["db", "verify"], _BARE_ENV)

    assert result.exit_code == 0
    assert "OK" in result.output


def test_declining_one_artifact_leaves_only_it_uncreated(runner: CliRunner, tmp_path: Path) -> None:
    # mesh init confirms env, template, database individually; decline
    # only the template.
    result = invoke(
        runner, ["--interactive", "init"], _BARE_ENV, input="y\nops@example.org\nn\ny\n"
    )

    assert result.exit_code == 0, result.output
    assert (tmp_path / ".env").is_file()
    assert not (tmp_path / "config" / "template.yaml").exists()
    assert (tmp_path / "data" / "nodes_db.ods").is_file()


def test_reprompts_after_a_whitespace_only_contact_answer(
    runner: CliRunner, tmp_path: Path
) -> None:
    # A truly blank line is re-prompted by click.prompt() itself (it
    # loops internally when the raw value is exactly ""), so this
    # exercises meshprovision's own retry loop instead: a whitespace-only
    # answer is non-empty as far as click is concerned, reaches
    # validate_contact, and is rejected there.
    result = invoke(
        runner,
        ["--interactive", "init"],
        _BARE_ENV,
        input="y\n   \nops@example.org\ny\ny\n",
    )

    assert result.exit_code == 0, result.output
    assert "MESHPROVISION_CONTACT=ops@example.org" in (tmp_path / ".env").read_text(
        encoding="utf-8"
    )


def test_declining_every_artifact_creates_nothing_and_skips_next_steps(
    runner: CliRunner, tmp_path: Path
) -> None:
    result = invoke(runner, ["--interactive", "init"], _BARE_ENV, input="n\nn\nn\n")

    assert result.exit_code == 0, result.output
    assert "Next steps:" not in result.output
    assert not (tmp_path / ".env").exists()
    assert not (tmp_path / "config" / "template.yaml").exists()
    assert not (tmp_path / "data" / "nodes_db.ods").exists()


def test_gives_up_after_three_invalid_contact_answers(runner: CliRunner, tmp_path: Path) -> None:
    result = invoke(runner, ["--interactive", "init"], _BARE_ENV, input="y\n \n \n \n")

    assert result.exit_code == 2, result.output
    assert not (tmp_path / ".env").exists()


def test_already_complete_json_lists_only_present_paths(runner: CliRunner, tmp_path: Path) -> None:
    invoke(runner, ["init", "--yes", "--contact", "ops@example.org"], _BARE_ENV)

    result = invoke(runner, ["init", "--json"], _BARE_ENV)

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["created"] == []
    assert len(payload["present"]) == 3
