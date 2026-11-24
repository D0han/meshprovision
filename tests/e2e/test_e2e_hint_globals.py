"""A command a hint names carries the file options this invocation was given.

Run literally, a bare ``mesh db restore --known-good`` from a run with
``--db-path ex.ods`` would restore the default database instead; each
hint below must name the same ``--db-path``/``--template-path``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.db.nodes import NodeRecord
from tests.conftest import WIDE_TERMINAL_COLUMNS
from tests.e2e.conftest import invoke

if TYPE_CHECKING:
    from collections.abc import Callable

    from click.testing import CliRunner

pytestmark = pytest.mark.e2e


def _without_db_path(env: dict[str, str]) -> dict[str, str]:
    return {key: value for key, value in env.items() if key != "MESHPROVISION_DB_PATH"}


def test_a_missing_database_hint_names_its_db_path(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    missing = tmp_path / "missing.ods"

    result = invoke(runner, ["--db-path", str(missing), "db", "verify"], _without_db_path(env))

    assert result.exit_code != 0
    assert f"`mesh --db-path {missing} init`" in result.stderr


def test_a_known_good_restore_hint_names_its_db_path(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    other = _without_db_path(env)
    assert invoke(runner, ["--db-path", str(db_path), "db", "verify"], other).exit_code == 0
    db_path.write_bytes(b"not a zip file at all")

    result = invoke(runner, ["--db-path", str(db_path), "db", "verify"], other)

    assert result.exit_code == 4
    assert f"mesh --db-path {db_path} db restore --known-good" in result.stderr


def test_a_failed_restore_hint_lists_the_backups_of_its_db_path(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], tmp_path: Path
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    bad_backup = tmp_path / "not-an-ods-file.ods"
    bad_backup.write_text("not a zip file", encoding="utf-8")

    result = invoke(
        runner,
        ["--db-path", str(db_path), "db", "restore", str(bad_backup), "--yes"],
        _without_db_path(env),
    )

    assert result.exit_code == 4
    assert f"`mesh --db-path {db_path} db backup --list`" in " ".join(result.stderr.split())


def test_init_next_steps_name_its_db_path(runner: CliRunner, tmp_path: Path) -> None:
    database = tmp_path / "fleet.ods"
    env = {"COLUMNS": WIDE_TERMINAL_COLUMNS, "NO_COLOR": "1"}

    result = invoke(
        runner,
        ["--db-path", str(database), "init", "--yes", "--contact", "d0hanzibi+ops@gmail.com"],
        env,
    )

    assert result.exit_code == 0, result.output
    assert f"mesh --db-path {database} db verify" in result.stderr
    assert f"mesh --db-path {database} template validate" in result.stderr


def test_a_missing_template_hint_names_its_template_path(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    missing = tmp_path / "nope.yaml"
    env = {key: value for key, value in env.items() if key != "MESHPROVISION_TEMPLATE_PATH"}

    result = invoke(runner, ["--template-path", str(missing), "template", "validate"], env)

    assert result.exit_code == 2
    assert f"`mesh --template-path {missing} init`" in result.stderr


def test_a_path_from_the_environment_is_not_repeated(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    env = {**env, "MESHPROVISION_DB_PATH": str(tmp_path / "missing.ods")}

    result = invoke(runner, ["db", "verify"], env)

    assert result.exit_code != 0
    assert "Run `mesh init` to create an empty database" in result.stderr


def test_a_missing_env_file_hint_quotes_its_path(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    missing = tmp_path / "my env"

    result = invoke(runner, ["--env-file", str(missing), "db", "verify"], env)

    assert result.exit_code == 2
    assert f"`mesh --env-file '{missing}' init`" in result.stderr
