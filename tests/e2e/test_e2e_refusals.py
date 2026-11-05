"""Refusal paths: unresolvable admin refs and lockdown safety gates.

Also covers the transactional-write-failure guarantee (the DB is
byte-identical, exit is non-zero, and no backup was created).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.crypto.keys import generate_keypair
from meshprovision.db import backups, ods
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
    # below directly on the fake interface) -- and verify_plan reads the
    # real post-write value back from LiveConfig.security (the same way
    # _verify_key_material/_verify_admin_keys already did), so the write is
    # correctly confirmed and persisted, not left UNCERTAIN.
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)
    allowed = invoke(
        runner,
        ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--allow-lockdown"],
        env,
    )
    assert allowed.exit_code == 0
    assert "UNCERTAIN" not in allowed.stderr
    assert iface.localNode.localConfig.security.is_managed is True
    assert db_fingerprint(db_path) != before


def test_transactional_write_failure_drop_security_keys(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, tmp_path: Path
) -> None:
    bus.use(FakeMeshInterface("deadbe01", drop_security_keys=True))
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == ExitCode.PROVISIONING
    assert "UNCERTAIN" in result.stderr
    assert "the database was NOT updated" in result.stderr
    assert db_fingerprint(db_path) == before

    loaded = ods.load_database(db_path)
    assert len(loaded.keys) == 0

    # No *timestamped* backup was created -- the write never got far
    # enough to call atomic_write()'s pre-write backup+replace. The
    # earlier read (inside open_database) does refresh the known-good
    # safety copy, per load_database()'s own contract -- that is
    # expected, not a leak of this refused write.
    backups_dir = backups.backup_dir_for(db_path)
    assert not any(backups_dir.glob(f"{db_path.stem}-*{db_path.suffix}"))


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

    assert result.exit_code == ExitCode.PROVISIONING
    assert "UNCERTAIN" in result.stderr
    assert "the database was NOT updated" in result.stderr
    assert db_fingerprint(db_path) == before

    # No *timestamped* backup was created -- the write never got far
    # enough to call atomic_write()'s pre-write backup+replace. The
    # earlier read (inside open_database) does refresh the known-good
    # safety copy, per load_database()'s own contract -- that is
    # expected, not a leak of this refused write.
    backups_dir = backups.backup_dir_for(db_path)
    assert not any(backups_dir.glob(f"{db_path.stem}-*{db_path.suffix}"))


def test_write_failure_mid_plan_stops_and_never_writes_security(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, tmp_path: Path
) -> None:
    iface = bus.use(FakeMeshInterface("deadbe01", fail_sections=frozenset({"lora"})))
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)
    before_security = bytes(iface.security.SerializeToString())

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == ExitCode.PROVISIONING
    assert "UNCERTAIN" in result.stderr
    assert "the database was NOT updated" in result.stderr
    assert db_fingerprint(db_path) == before

    # The failing section is the last thing written to the device, and
    # nothing after it (security included) was ever sent.
    assert iface.localNode.written_sections[-1] == "lora"
    assert "security" not in iface.localNode.written_sections
    assert bytes(iface.security.SerializeToString()) == before_security

    # write_section's snapshot-restore means the failed write never left
    # the in-memory config mutated, so an in-place read-back never shows
    # a contradictory "confirmed" line for the section that failed.
    assert iface.localNode.localConfig.lora.region == 0
    assert "lora.region: confirmed" not in result.stderr

    # No *timestamped* backup was created -- the write never got far
    # enough to call atomic_write()'s pre-write backup+replace. The
    # earlier read (inside open_database) does refresh the known-good
    # safety copy, per load_database()'s own contract -- that is
    # expected, not a leak of this refused write.
    backups_dir = backups.backup_dir_for(db_path)
    assert not any(backups_dir.glob(f"{db_path.stem}-*{db_path.suffix}"))


def _serial_api_on(iface: FakeMeshInterface) -> FakeMeshInterface:
    iface.localNode.localConfig.security.serial_enabled = True
    return iface


@pytest.mark.parametrize("extra", [[], ["--dry-run"]], ids=["apply", "dry-run"])
def test_switching_the_serial_api_off_over_serial_is_refused_before_any_write(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    write_template: Callable[..., Path],
    extra: list[str],
) -> None:
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(security={"serial_enabled": False}))
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)
    iface = bus.use(_serial_api_on(FakeMeshInterface("deadbe01")))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes", *extra], env)

    assert result.exit_code == ExitCode.PROVISIONING
    assert "switches off the serial API this run is connected over" in result.stderr
    assert iface.localNode.written_sections == []
    assert iface.localNode.transaction_calls == []
    assert iface.localNode.localConfig.security.serial_enabled is True
    assert db_fingerprint(db_path) == before


def test_switching_the_serial_api_off_over_tcp_is_applied_with_a_warning(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    write_template: Callable[..., Path],
) -> None:
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(security={"serial_enabled": False}))
    iface = bus.use(_serial_api_on(FakeMeshInterface("deadbe01")))

    result = invoke(runner, ["provision", "--host", "192.168.1.50", "--yes"], env)

    assert result.exit_code == 0
    assert "switches off the serial (USB) API" in result.stderr
    assert iface.localNode.localConfig.security.serial_enabled is False


def test_a_serial_api_already_off_is_not_refused_over_serial(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    write_template: Callable[..., Path],
) -> None:
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(security={"serial_enabled": False}))
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--dry-run"], env)

    assert result.exit_code == 0
    assert "serial API" not in result.stderr


def test_a_repeater_role_is_refused_before_any_write_where_the_firmware_replaces_it(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    write_template: Callable[..., Path],
) -> None:
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(device={"role": "REPEATER"}))
    iface = bus.use(FakeMeshInterface("deadbe01", firmware_version="2.7.26.54e0d8d"))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == ExitCode.PROVISIONING
    assert "device.role REPEATER" in result.stderr
    assert iface.localNode.written_sections == []


def test_a_known_only_mode_is_refused_before_any_write_where_the_firmware_ignores_the_client(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    write_template: Callable[..., Path],
) -> None:
    env["MESHPROVISION_TEMPLATE_PATH"] = str(
        write_template(device={"rebroadcast_mode": "KNOWN_ONLY"})
    )
    iface = bus.use(FakeMeshInterface("deadbe01", firmware_version="2.8.3.51ac6ea"))
    # A 2.8 device has its region before mesh provision runs: EU_868.
    iface.localNode.localConfig.lora.region = 3

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == ExitCode.PROVISIONING
    assert "device.rebroadcast_mode KNOWN_ONLY" in result.stderr
    assert iface.localNode.written_sections == []
