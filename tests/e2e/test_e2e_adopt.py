"""``mesh adopt``: strictly read-only device inventory, recorded as observed."""

from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.db import ods
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import ManagementMode
from tests.e2e.conftest import FakeMeshInterface, db_fingerprint, invoke

if TYPE_CHECKING:
    from collections.abc import Callable

    from click.testing import CliRunner

    from meshprovision.crypto.keys import KeyPair
    from tests.e2e.conftest import DeviceBus

pytestmark = pytest.mark.e2e

_BASE64_KEY_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")


def test_adopt_never_writes_to_the_device(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    admin_kp = keypair_factory()
    iface = bus.use(FakeMeshInterface("deadbe01", short_name="AB01", long_name="Adopted Node 01"))
    iface.localNode.localConfig.security.admin_key.append(admin_kp.public)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert iface.localNode.written_sections == []


def test_fresh_adopt_persists_an_observed_record(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    bus.use(FakeMeshInterface("deadbe01", short_name="AB01", long_name="Adopted Node 01"))

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes = [NodeRecord.from_row(row) for row in loaded.nodes]
    assert len(nodes) == 1
    node = nodes[0]
    assert node.node_id == "deadbe01"
    assert node.management is ManagementMode.OBSERVED
    assert node.short_name == "AB01"
    assert node.long_name == "Adopted Node 01"
    assert node.hw_model == "RAK4631"
    assert node.firmware_version == "2.7.11"


def test_dry_run_writes_nothing_to_the_database(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--dry-run"], env)

    assert result.exit_code == 0
    assert db_fingerprint(db_path) == before
    assert "deadbe01" in result.stderr


def test_refuses_a_template_managed_node_without_force(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    record = NodeRecord(node_id="deadbe01", management=ManagementMode.TEMPLATE)
    db_path = seed_db(nodes=[record])
    before = db_fingerprint(db_path)
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code != 0
    assert db_fingerprint(db_path) == before
    assert "--force" in result.stderr


def test_force_re_adopts_and_demotes_with_explicit_confirmation(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    record = NodeRecord(node_id="deadbe01", management=ManagementMode.TEMPLATE)
    seed_db(nodes=[record])
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--force"], env)

    assert result.exit_code == 0

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    persisted = NodeRecord.from_row(loaded.nodes[0])
    assert persisted.management is ManagementMode.OBSERVED


def test_unregistered_admin_key_default_hides_material(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    admin_kp = keypair_factory()
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(admin_kp.public)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert not _BASE64_KEY_RE.search(result.stdout)
    assert not _BASE64_KEY_RE.search(result.stderr)


def test_unregistered_admin_key_show_admin_keys_prints_import_command(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    admin_kp = keypair_factory()
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(admin_kp.public)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--show-admin-keys"], env)

    assert result.exit_code == 0
    assert "mesh admin import" in result.stderr
    assert base64.b64encode(admin_kp.public).decode("ascii") in result.stderr


def test_adopt_then_enroll_round_trip(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    bus.use(FakeMeshInterface("deadbe01"))

    adopted = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert adopted.exit_code == 0

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    observed = NodeRecord.from_row(loaded.nodes[0])
    assert observed.management is ManagementMode.OBSERVED

    enrolled = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--enroll"], env)
    assert enrolled.exit_code == 0

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    managed = NodeRecord.from_row(loaded.nodes[0])
    assert managed.management is ManagementMode.TEMPLATE
