"""``mesh``'s documented "CLI flag > env var > .env > default" precedence.

The layering logic itself (``load_settings``) is thoroughly unit-tested
in ``tests/unit/test_settings.py`` as a pure function. What's untested
anywhere else is the *wiring*: that ``cli/main.py``'s ``--log-level``/
``--db-path``/``--template-path`` click options actually reach
``build_settings`` under the names it expects, through a real ``mesh``
invocation, and actually beat a real conflicting environment variable
and a real conflicting ``.env`` file.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.db import ods
from tests.e2e.conftest import invoke

if TYPE_CHECKING:
    from collections.abc import Callable

    from click.testing import CliRunner

pytestmark = pytest.mark.e2e


def test_log_level_flag_beats_environ_beats_dotenv_through_the_real_cli(
    runner: CliRunner, env: dict[str, str], write_template: Callable[..., Path], tmp_path: Path
) -> None:
    """All three layers set to different values; the CLI flag must win.

    ``configure_logging`` (``cli/common.py``) sets the root logger's
    level as its one observable side effect, which is checked directly
    here rather than scraped from log output -- ``CliRunner`` invokes
    in-process, so the real root logger is the one just configured.
    """
    dotenv_path = tmp_path / "precedence.env"
    dotenv_path.write_text("MESHPROVISION_LOG_LEVEL=WARNING\n")
    env["MESHPROVISION_LOG_LEVEL"] = "ERROR"
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template())

    result = invoke(
        runner,
        ["--env-file", str(dotenv_path), "--log-level", "debug", "template", "validate"],
        env,
    )

    assert result.exit_code == 0
    assert logging.getLogger().level == logging.DEBUG


def test_environ_beats_dotenv_through_the_real_cli_when_no_flag_is_passed(
    runner: CliRunner, env: dict[str, str], write_template: Callable[..., Path], tmp_path: Path
) -> None:
    """Same two lower layers, no ``--log-level`` flag: environ must still win.

    Isolates the ``environ > .env`` half of the chain from the
    CLI-flag-wins case above, through the same real ``--env-file``
    plumbing.
    """
    dotenv_path = tmp_path / "precedence.env"
    dotenv_path.write_text("MESHPROVISION_LOG_LEVEL=WARNING\n")
    env["MESHPROVISION_LOG_LEVEL"] = "ERROR"
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template())

    result = invoke(runner, ["--env-file", str(dotenv_path), "template", "validate"], env)

    assert result.exit_code == 0
    assert logging.getLogger().level == logging.ERROR


def test_dotenv_via_explicit_env_file_is_honored_absent_any_higher_layer(
    runner: CliRunner, env: dict[str, str], write_template: Callable[..., Path], tmp_path: Path
) -> None:
    """``--env-file`` itself must be read, not just accepted and ignored.

    No ``MESHPROVISION_LOG_LEVEL`` in the environment and no
    ``--log-level`` flag: the ``.env`` file passed via ``--env-file`` is
    the only source, so its value must be the one that lands. Uses
    ``ERROR`` rather than ``WARNING`` deliberately -- ``WARNING`` is now
    the built-in default, so asserting it here would pass even if
    ``--env-file`` were silently ignored.
    """
    dotenv_path = tmp_path / "precedence.env"
    dotenv_path.write_text("MESHPROVISION_LOG_LEVEL=ERROR\n")
    del env["MESHPROVISION_LOG_LEVEL"]
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template())

    result = invoke(runner, ["--env-file", str(dotenv_path), "template", "validate"], env)

    assert result.exit_code == 0
    assert logging.getLogger().level == logging.ERROR


def test_db_path_and_template_path_flags_beat_conflicting_env_vars(
    runner: CliRunner,
    env: dict[str, str],
    write_template: Callable[..., Path],
    tmp_path: Path,
) -> None:
    """Path-typed flags need their own proof: ``click.Path`` wiring differs from ``Choice``.

    ``env`` already points ``MESHPROVISION_DB_PATH``/
    ``MESHPROVISION_TEMPLATE_PATH`` at one pair of files; here a second,
    distinct pair is passed via ``--db-path``/``--template-path`` and
    must be the pair actually used, proven via each command's own
    ``--json`` echo of the resolved path.
    """
    flagged_db_path = tmp_path / "flagged.ods"
    ods.write_database(flagged_db_path, nodes=[], keys=[], backup=False)
    flagged_template_path = write_template(path=tmp_path / "flagged-template.yaml")

    result = invoke(
        runner,
        [
            "--db-path",
            str(flagged_db_path),
            "--template-path",
            str(flagged_template_path),
            "template",
            "validate",
            "--json",
        ],
        env,
    )

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["template_path"] == str(flagged_template_path)

    backup_dir = tmp_path / "backups"
    backup_result = invoke(
        runner,
        [
            "--db-path",
            str(flagged_db_path),
            "db",
            "backup",
            "--backup-dir",
            str(backup_dir),
            "--json",
        ],
        env,
    )

    assert backup_result.exit_code == 0
    backup_document = json.loads(backup_result.stdout)
    assert backup_document["source"] == str(flagged_db_path)
