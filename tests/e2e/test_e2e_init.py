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

import dotenv
import pytest

from meshprovision.db.nodes import NodeRepository
from meshprovision.db.ods import OdsDatabase
from tests.conftest import WIDE_TERMINAL_COLUMNS
from tests.e2e.conftest import db_fingerprint, invoke

if TYPE_CHECKING:
    from click.testing import CliRunner

pytestmark = pytest.mark.e2e

_BARE_ENV: dict[str, str] = {"COLUMNS": WIDE_TERMINAL_COLUMNS, "NO_COLOR": "1"}


def test_creates_env_template_and_database_in_an_empty_directory(
    runner: CliRunner, tmp_path: Path
) -> None:
    result = invoke(runner, ["init", "--yes", "--contact", "d0hanzibi+ops@gmail.com"], _BARE_ENV)

    assert result.exit_code == 0
    assert (tmp_path / ".env").is_file()
    assert (tmp_path / "config" / "template.yaml").is_file()
    assert (tmp_path / "data" / "nodes_db.ods").is_file()
    assert "MESHPROVISION_CONTACT=d0hanzibi+ops@gmail.com" in (tmp_path / ".env").read_text(
        encoding="utf-8"
    )


def test_prompts_interactively_for_the_contact(runner: CliRunner, tmp_path: Path) -> None:
    # mesh init confirms each missing artifact individually (env, then
    # template, then database) rather than with one combined banner
    # confirm -- unlike the auto-offer path, this is already an explicit
    # request.
    result = invoke(
        runner, ["--interactive", "init"], _BARE_ENV, input="y\nd0hanzibi+ops@gmail.com\ny\ny\n"
    )

    assert result.exit_code == 0, result.output
    assert "MESHPROVISION_CONTACT=d0hanzibi+ops@gmail.com" in (tmp_path / ".env").read_text(
        encoding="utf-8"
    )


def test_run_twice_never_rewrites_an_existing_file(runner: CliRunner, tmp_path: Path) -> None:
    invoke(runner, ["init", "--yes", "--contact", "d0hanzibi+ops@gmail.com"], _BARE_ENV)
    before = {
        path: db_fingerprint(path)
        for path in (
            tmp_path / ".env",
            tmp_path / "config" / "template.yaml",
            tmp_path / "data" / "nodes_db.ods",
        )
    }

    result = invoke(
        runner, ["init", "--yes", "--contact", "d0hanzibi+someone-else@gmail.com"], _BARE_ENV
    )

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

    result = invoke(runner, ["init", "--yes", "--contact", "d0hanzibi+ops@gmail.com"], env)

    assert result.exit_code == 0
    assert db_path.is_file()
    assert template_path.is_file()
    assert not (tmp_path / "data" / "nodes_db.ods").exists()


def test_honors_an_explicit_env_file(runner: CliRunner, tmp_path: Path) -> None:
    explicit = tmp_path / "custom.env"

    args = ["--env-file", str(explicit), "init", "--yes", "--contact", "d0hanzibi+ops@gmail.com"]
    result = invoke(runner, args, _BARE_ENV)

    assert result.exit_code == 0
    assert explicit.is_file()
    assert not (tmp_path / ".env").exists()


def test_json_lists_the_created_paths(runner: CliRunner, tmp_path: Path) -> None:
    result = invoke(
        runner, ["init", "--yes", "--contact", "d0hanzibi+ops@gmail.com", "--json"], _BARE_ENV
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert len(payload["created"]) == 3
    assert payload["declined"] == []
    assert set(payload) == {"created", "present", "declined", "notes"}
    assert sorted(payload["created"]) == sorted(
        str(tmp_path / name) for name in (".env", "config/template.yaml", "data/nodes_db.ods")
    )


def test_json_paths_are_absolute_when_already_present(runner: CliRunner, tmp_path: Path) -> None:
    invoke(runner, ["init", "--yes", "--contact", "d0hanzibi+ops@gmail.com"], _BARE_ENV)

    result = invoke(runner, ["init", "--json"], _BARE_ENV)

    assert result.exit_code == 0
    assert all(Path(path).is_absolute() for path in json.loads(result.stdout)["present"])


def test_non_interactive_without_a_contact_exits_five(runner: CliRunner, tmp_path: Path) -> None:
    result = invoke(runner, ["init", "--yes"], _BARE_ENV)

    assert result.exit_code == 5
    assert not (tmp_path / ".env").exists()


def test_creates_an_empty_database_not_the_fake_example_rows(
    runner: CliRunner, tmp_path: Path, repo_root: Path
) -> None:
    result = invoke(runner, ["init", "--yes", "--contact", "d0hanzibi+ops@gmail.com"], _BARE_ENV)
    assert result.exit_code == 0

    db_path = tmp_path / "data" / "nodes_db.ods"
    db = OdsDatabase(db_path)
    db.load()
    nodes = NodeRepository(db)
    assert nodes.all() == ()

    example_path = repo_root / "data" / "nodes_db.example.ods"
    assert db_path.read_bytes() != example_path.read_bytes()


def test_init_then_db_verify_succeeds(runner: CliRunner, tmp_path: Path) -> None:
    invoke(runner, ["init", "--yes", "--contact", "d0hanzibi+ops@gmail.com"], _BARE_ENV)

    result = invoke(runner, ["db", "verify"], _BARE_ENV)

    assert result.exit_code == 0
    assert "OK" in result.output


def test_declining_one_artifact_leaves_only_it_uncreated(runner: CliRunner, tmp_path: Path) -> None:
    # mesh init confirms env, template, database individually; decline
    # only the template.
    result = invoke(
        runner, ["--interactive", "init"], _BARE_ENV, input="y\nd0hanzibi+ops@gmail.com\nn\ny\n"
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
        input="y\n   \nd0hanzibi+ops@gmail.com\ny\ny\n",
    )

    assert result.exit_code == 0, result.output
    assert "MESHPROVISION_CONTACT=d0hanzibi+ops@gmail.com" in (tmp_path / ".env").read_text(
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


def test_a_placeholder_contact_is_refused_and_nothing_is_created(
    runner: CliRunner, tmp_path: Path
) -> None:
    result = invoke(runner, ["init", "--yes", "--contact", "ops@example.org"], _BARE_ENV)

    assert result.exit_code == 2, result.output
    assert "Contact 'ops@example.org' is a placeholder" in result.stderr
    assert not (tmp_path / ".env").exists()


def test_already_complete_json_lists_only_present_paths(runner: CliRunner, tmp_path: Path) -> None:
    invoke(runner, ["init", "--yes", "--contact", "d0hanzibi+ops@gmail.com"], _BARE_ENV)

    result = invoke(runner, ["init", "--json"], _BARE_ENV)

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["created"] == []
    assert len(payload["present"]) == 3
    assert payload["declined"] == []
    assert payload["notes"] == []


def test_a_contact_with_backslashes_is_written_so_it_reads_back_unchanged(
    runner: CliRunner, tmp_path: Path
) -> None:
    """A backslash in ``--contact`` used to crash init (re.error) or smuggle in a second line."""
    contact = "https://github.com/d0hanzibi/\\d?a=\\nMESHPROVISION_DB_PATH=/tmp/other.ods"

    result = invoke(runner, ["init", "--yes", "--contact", contact], _BARE_ENV)

    assert result.exit_code == 0, result.output
    loaded = dotenv.dotenv_values(tmp_path / ".env")
    assert loaded["MESHPROVISION_CONTACT"] == contact
    assert "MESHPROVISION_DB_PATH" not in loaded


@pytest.mark.parametrize("missing", [None, "template"], ids=["complete", "template-missing"])
def test_a_contact_given_with_an_existing_env_is_reported_ignored(
    runner: CliRunner, tmp_path: Path, missing: str | None
) -> None:
    invoke(runner, ["init", "--yes", "--contact", "d0hanzibi+ops@gmail.com"], _BARE_ENV)
    if missing == "template":
        (tmp_path / "config" / "template.yaml").unlink()
    before = (tmp_path / ".env").read_text(encoding="utf-8")

    result = invoke(
        runner, ["init", "--yes", "--contact", "d0hanzibi+someone-else@gmail.com"], _BARE_ENV
    )

    assert result.exit_code == 0
    assert "--contact ignored: .env already exists" in result.stderr
    assert (tmp_path / ".env").read_text(encoding="utf-8") == before


def test_created_paths_are_shown_relative_and_never_wrapped(
    runner: CliRunner, tmp_path: Path
) -> None:
    deep = Path("a-directory-name-long-enough", "to-pass-the-console-width", "template.yaml")
    env = {**_BARE_ENV, "COLUMNS": "30", "MESHPROVISION_TEMPLATE_PATH": str(tmp_path / deep)}

    result = invoke(runner, ["init", "--yes", "--contact", "d0hanzibi+ops@gmail.com"], env)

    assert result.exit_code == 0
    created = [line for line in result.stderr.splitlines() if line.startswith("Created ")]
    assert created == [f"Created {Path('.env')}", f"Created {deep}", "Created data/nodes_db.ods"]
