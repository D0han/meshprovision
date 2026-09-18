"""Smoke coverage of the ``mesh`` console-script surface.

Covers ``--help``/``--version``, every subcommand's own ``--help``, an
unknown subcommand, and the non-interactive confirmation refusal that
guards ``mesh provision`` from ever silently applying a plan.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.cli.admin import admin_bootstrap
from meshprovision.cli.provision import provision
from tests.e2e.conftest import FakeMeshInterface, db_fingerprint, invoke

if TYPE_CHECKING:
    from click.testing import CliRunner

    from tests.e2e.conftest import DeviceBus

pytestmark = pytest.mark.e2e


def test_help_lists_every_subcommand(runner: CliRunner, env: dict[str, str]) -> None:
    result = invoke(runner, ["--help"], env)
    assert result.exit_code == 0
    for name in ("provision", "status", "admin", "db", "init"):
        assert name in result.output


def test_version_prints_package_version(runner: CliRunner, env: dict[str, str]) -> None:
    result = invoke(runner, ["--version"], env)
    assert result.exit_code == 0
    assert "mesh 0.1.0" in result.output


@pytest.mark.parametrize(
    "args",
    [
        ["provision", "--help"],
        ["status", "--help"],
        ["admin", "--help"],
        ["admin", "bootstrap", "--help"],
        ["adopt", "--help"],
        ["db", "--help"],
        ["init", "--help"],
    ],
)
def test_subcommand_help_exits_zero(
    runner: CliRunner, env: dict[str, str], args: list[str]
) -> None:
    result = invoke(runner, args, env)
    assert result.exit_code == 0


def test_unknown_subcommand_exits_two(runner: CliRunner, env: dict[str, str]) -> None:
    result = invoke(runner, ["not-a-real-command"], env)
    assert result.exit_code == 2


@pytest.mark.parametrize(
    "args",
    [
        ["db", "verify", "--help"],
        ["provision", "--help"],
        ["admin", "bootstrap", "--help"],
        ["adopt", "--help"],
        ["db", "backup", "--help"],
        ["template", "validate", "--help"],
    ],
)
def test_help_output_never_leaks_docstring_sections_or_rst(
    runner: CliRunner, env: dict[str, str], args: list[str]
) -> None:
    result = invoke(runner, args, env)
    assert result.exit_code == 0
    for marker in ("Args:", "Raises:", "Returns:", ":class:", "``"):
        assert marker not in result.output


def test_commands_table_still_lists_a_readable_short_help(
    runner: CliRunner, env: dict[str, str]
) -> None:
    result = invoke(runner, ["--help"], env)
    assert "Database integrity and backup helpers" in result.output


def test_provision_without_yes_or_interactive_refuses_non_interactively(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    bus.use(FakeMeshInterface("deadbe01"))
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0"], env)

    assert result.exit_code == 5
    assert "non-interactive" in result.stderr
    assert "confirmation" in result.stderr.lower() or "required" in result.stderr.lower()
    assert db_fingerprint(db_path) == before


def test_missing_database_file_exits_four_with_hint(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    env = dict(env)
    env["MESHPROVISION_DB_PATH"] = str(tmp_path / "does-not-exist.ods")

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 4
    assert "nodes_db.example.ods" in result.stderr


def test_provision_and_bootstrap_share_an_identical_transport_surface() -> None:
    shared = {
        "port",
        "ble_address",
        "ble_scan",
        "host",
        "interface",
        "timeout",
        "ble_scan_timeout",
        "dry_run",
        "yes",
        "allow_lockdown",
        "force_regenerate_key",
        "no_reconnect",
        "json_output",
    }
    for command in (provision, admin_bootstrap):
        assert shared <= {param.name for param in command.params}


def test_adopt_help_lists_the_from_backup_surface(runner: CliRunner, env: dict[str, str]) -> None:
    result = invoke(runner, ["adopt", "--help"], env)
    assert result.exit_code == 0
    for flag in ("--from-backup", "--node-id", "--no-lookup", "--no-channel-psk"):
        assert flag in result.output
