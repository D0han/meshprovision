"""End-to-end coverage of the automatic first-run setup offer.

Unlike ``mesh init`` (tested in ``test_e2e_init.py``), this exercises the
offer as it fires from an *ordinary* command -- ``mesh db verify`` here,
chosen because it needs both the template and the database, so it
exercises every artifact. Deliberately does not use the ``env``/``cli_env``
fixtures, which pre-supply everything the wizard exists to create.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from tests.e2e.conftest import invoke

if TYPE_CHECKING:
    from click.testing import CliRunner

pytestmark = pytest.mark.e2e

_BARE_ENV: dict[str, str] = {"COLUMNS": "200", "NO_COLOR": "1"}


def test_wizard_fires_on_an_interactive_first_run_and_the_command_then_succeeds(
    runner: CliRunner, tmp_path: Path
) -> None:
    result = invoke(
        runner, ["--interactive", "db", "verify"], _BARE_ENV, input="y\nops@example.org\n"
    )

    assert result.exit_code == 0, result.output
    assert (tmp_path / ".env").is_file()
    assert (tmp_path / "config" / "template.yaml").is_file()
    assert (tmp_path / "data" / "nodes_db.ods").is_file()
    assert "OK" in result.output


def test_wizard_does_not_fire_for_a_subcommand_help_request(
    runner: CliRunner, tmp_path: Path
) -> None:
    result = invoke(runner, ["--interactive", "db", "verify", "--help"], _BARE_ENV)

    assert result.exit_code == 0
    assert not (tmp_path / ".env").exists()
    assert not (tmp_path / "config" / "template.yaml").exists()
    assert not (tmp_path / "data" / "nodes_db.ods").exists()


def test_wizard_does_not_fire_for_group_help(runner: CliRunner, tmp_path: Path) -> None:
    result = invoke(runner, ["--interactive", "db", "-h"], _BARE_ENV)

    assert result.exit_code == 0
    assert not (tmp_path / ".env").exists()


def test_wizard_does_not_fire_for_root_help(runner: CliRunner, tmp_path: Path) -> None:
    result = invoke(runner, ["--interactive", "--help"], _BARE_ENV)

    assert result.exit_code == 0
    assert not (tmp_path / ".env").exists()


def test_wizard_does_not_fire_non_interactively(runner: CliRunner, tmp_path: Path) -> None:
    # db verify opens the database before loading the template, so the
    # unchanged, pre-existing "database not found" error (exit 4) is what
    # surfaces -- the point of this test is that nothing was created, not
    # which specific error came back.
    result = invoke(runner, ["db", "verify"], _BARE_ENV)

    assert result.exit_code == 4
    assert not (tmp_path / ".env").exists()
    assert not (tmp_path / "config" / "template.yaml").exists()
    assert not (tmp_path / "data" / "nodes_db.ods").exists()


def test_declining_the_wizard_falls_through_to_the_original_error(
    runner: CliRunner, tmp_path: Path
) -> None:
    result = invoke(runner, ["--interactive", "db", "verify"], _BARE_ENV, input="n\n")

    assert result.exit_code != 0
    assert not (tmp_path / ".env").exists()
    assert not (tmp_path / "config" / "template.yaml").exists()
    assert not (tmp_path / "data" / "nodes_db.ods").exists()
    assert "mesh init" in result.output


def test_wizard_does_not_fire_when_setup_is_already_complete(
    runner: CliRunner, env: dict[str, str]
) -> None:
    result = invoke(runner, ["db", "verify"], env)

    assert result.exit_code == 0
    assert "No meshprovision setup found" not in result.output


def test_wizard_does_not_double_run_for_mesh_init_itself(runner: CliRunner, tmp_path: Path) -> None:
    result = invoke(runner, ["init", "--yes", "--contact", "ops@example.org"], _BARE_ENV)

    assert result.exit_code == 0
    assert result.output.count("Created ") == 3


def test_wizard_writes_the_env_relative_to_the_cwd(runner: CliRunner, tmp_path: Path) -> None:
    result = invoke(
        runner, ["--interactive", "db", "verify"], _BARE_ENV, input="y\nops@example.org\n"
    )

    assert result.exit_code == 0, result.output
    env_text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "MESHPROVISION_CONTACT=ops@example.org" in env_text
