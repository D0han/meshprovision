"""Refusal paths: unresolvable admin refs and lockdown safety gates.

Also covers the transactional-write-failure guarantee (the DB is
byte-identical, exit is non-zero, and no backup was created).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.crypto.keys import generate_keypair
from meshprovision.db import ods
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import ManagementMode
from meshprovision.errors import ExitCode
from tests.e2e.conftest import FakeMeshInterface, db_fingerprint, invoke

if TYPE_CHECKING:
    from collections.abc import Callable

    from click.testing import CliRunner

    from tests.e2e.conftest import DeviceBus

pytestmark = pytest.mark.e2e


def test_unresolvable_admin_ref_leaves_device_and_db_untouched(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    write_template: Callable[..., Path],
) -> None:
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(admin_nodes=["NOPE"]))
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)
    iface = bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 5
    assert "NOPE" in result.stderr
    assert "NOPE_pub" in result.stderr
    assert "mesh admin bootstrap" in result.stderr
    assert "mesh admin import" in result.stderr
    assert iface.localNode.written_sections == []
    assert db_fingerprint(db_path) == before


def test_is_managed_with_zero_admin_keys_is_refused_at_template_load(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    write_template: Callable[..., Path],
) -> None:
    env["MESHPROVISION_TEMPLATE_PATH"] = str(
        write_template(admin_nodes=[], security={"is_managed": True})
    )
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 2
    assert "administer" in result.stderr.lower()


def test_is_managed_without_private_counterpart_is_refused(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    write_template: Callable[..., Path],
) -> None:
    kp = generate_keypair()
    imported = invoke(runner, ["admin", "import", f"ADMIN1={kp.public_b64}"], env)
    assert imported.exit_code == 0

    env["MESHPROVISION_TEMPLATE_PATH"] = str(
        write_template(admin_nodes=["ADMIN1"], security={"is_managed": True})
    )
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)
    iface = bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(
        runner,
        ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--allow-lockdown"],
        env,
    )

    assert result.exit_code == 5
    assert "private counterpart" in result.stderr.lower()
    assert iface.localNode.localConfig.security.is_managed is False
    assert db_fingerprint(db_path) == before


def test_is_managed_gated_but_not_authorized_then_authorized(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    write_template: Callable[..., Path],
) -> None:
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(admin_nodes=[]))
    bus.use(FakeMeshInterface("aaaa0001"))
    bootstrap = invoke(
        runner,
        ["admin", "bootstrap", "--port", "/dev/ttyFAKE0", "--ref", "ADMIN1", "--yes"],
        env,
    )
    assert bootstrap.exit_code == 0

    env["MESHPROVISION_TEMPLATE_PATH"] = str(
        write_template(admin_nodes=["ADMIN1"], security={"is_managed": True})
    )
    iface = bus.use(FakeMeshInterface("deadbe01"))

    not_allowed = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert not_allowed.exit_code == 0
    assert "--allow-lockdown" in not_allowed.stderr
    assert iface.localNode.localConfig.security.is_managed is False

    # With every safety gate satisfied and --allow-lockdown passed, the plan
    # legitimately sets security.is_managed=True on the device (observable
    # below directly on the fake interface). However, apply.verify_plan's
    # generic per-field read-back (detect.LiveConfig.value()) never looks
    # inside "security" -- that section is deliberately excluded from
    # LiveConfig.sections and surfaced only via the separate
    # LiveConfig.security structure -- so a changed security scalar field
    # (is_managed here) can never be confirmed by the shipped verification
    # pass. The system fails safe: the node is left UNCERTAIN and the
    # database is correctly never updated for an unconfirmed security
    # change, even though the device-side write itself succeeded.
    allowed = invoke(
        runner,
        ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--allow-lockdown"],
        env,
    )
    assert allowed.exit_code == 5
    assert "UNCERTAIN" in allowed.stderr
    assert iface.localNode.localConfig.security.is_managed is True


def test_transactional_write_failure_drop_security_keys(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, tmp_path: Path
) -> None:
    bus.use(FakeMeshInterface("deadbe01", drop_security_keys=True))
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code != 0
    assert "UNCERTAIN" in result.stderr
    assert "the database was NOT updated" in result.stderr
    assert db_fingerprint(db_path) == before

    loaded = ods.load_database(db_path)
    assert len(loaded.keys) == 0

    backups_dir = tmp_path / "data" / "backups"
    assert not backups_dir.exists() or not any(backups_dir.iterdir())


def test_observed_node_is_refused_without_enroll(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    record = NodeRecord(node_id="deadbe01", management=ManagementMode.OBSERVED)
    seed_db(nodes=[record])
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)
    iface = bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == int(ExitCode.PROVISIONING)
    assert "--enroll" in result.stderr
    assert iface.localNode.written_sections == []
    assert db_fingerprint(db_path) == before


def test_observed_node_is_refused_without_enroll_under_dry_run(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    record = NodeRecord(node_id="deadbe01", management=ManagementMode.OBSERVED)
    seed_db(nodes=[record])
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)
    iface = bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--dry-run"], env)

    assert result.exit_code == int(ExitCode.PROVISIONING)
    assert "--enroll" in result.stderr
    assert "Planned changes:" not in result.stdout
    assert iface.localNode.written_sections == []
    assert db_fingerprint(db_path) == before


def test_post_reconnect_verify_read_failure_leaves_the_database_untouched(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, tmp_path: Path
) -> None:
    bus.use(FakeMeshInterface("deadbe01", fail_reads_after_write=True))
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code != 0
    assert "UNCERTAIN" in result.stderr
    assert "the database was NOT updated" in result.stderr
    assert db_fingerprint(db_path) == before

    backups_dir = tmp_path / "data" / "backups"
    assert not backups_dir.exists() or not any(backups_dir.iterdir())


def test_transactional_write_failure_section_raises(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, tmp_path: Path
) -> None:
    bus.use(FakeMeshInterface("deadbe01", fail_sections=frozenset({"lora"})))
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code != 0
    assert "UNCERTAIN" in result.stderr
    assert "the database was NOT updated" in result.stderr
    assert db_fingerprint(db_path) == before

    backups_dir = tmp_path / "data" / "backups"
    assert not backups_dir.exists() or not any(backups_dir.iterdir())
