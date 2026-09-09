"""``mesh adopt``: strictly read-only device inventory, recorded as observed."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.crypto.keys import encode_key
from meshprovision.db import ods
from meshprovision.db.keys import KeyRecord
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import ManagementMode
from meshprovision.errors import ExitCode
from tests.e2e.conftest import FakeMeshInterface, db_fingerprint, invoke

if TYPE_CHECKING:
    from collections.abc import Callable

    import respx
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


def test_show_admin_keys_never_crashes_on_a_malformed_length_admin_key(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
) -> None:
    """Regression test: a malformed admin key must degrade, never crash the command.

    detect.py applies no length check when reading security.admin_key
    off the device, so a device reporting a corrupted (non-32-byte)
    admin key is reachable in practice. crypto.keys.encode_key()
    validates length and raises on a mismatch -- --show-admin-keys must
    catch that per key, not let it abort the whole report.
    """
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(b"\x01\x02\x03")

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--show-admin-keys"], env)

    assert result.exit_code == 0
    assert "cannot render an import command" in result.stderr
    assert "mesh admin import" not in result.stderr


def test_adopt_recognizes_a_pre_imported_friends_admin_key(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    friend_kp = keypair_factory()
    import_result = invoke(
        runner,
        ["admin", "import", f"FRIEND={base64.b64encode(friend_kp.public).decode()}"],
        env,
    )
    assert import_result.exit_code == 0

    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(friend_kp.public)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["admin_keys"][0]["refs"] == ["FRIEND_pub"]

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    assert NodeRecord.from_row(loaded.nodes[0]).authorized_admin_keys == ("FRIEND_pub",)


def test_adopt_discover_then_import_then_reconcile_a_friends_admin_key(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    friend_kp = keypair_factory()
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(friend_kp.public)

    first = invoke(
        runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json", "--show-admin-keys"], env
    )
    assert first.exit_code == 0
    first_doc = json.loads(first.stdout)
    assert first_doc["admin_keys"][0]["refs"] == []
    revealed_b64 = first_doc["admin_keys"][0]["material"]
    assert base64.b64decode(revealed_b64) == friend_kp.public

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    assert NodeRecord.from_row(loaded.nodes[0]).authorized_admin_keys == ()

    import_result = invoke(runner, ["admin", "import", f"FRIEND={revealed_b64}"], env)
    assert import_result.exit_code == 0

    bus.use(iface)
    second = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
    assert second.exit_code == 0
    assert json.loads(second.stdout)["admin_keys"][0]["refs"] == ["FRIEND_pub"]

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    assert NodeRecord.from_row(loaded.nodes[0]).authorized_admin_keys == ("FRIEND_pub",)


def test_adopt_zero_admin_keys_is_clean(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    bus.use(FakeMeshInterface("deadbe01", short_name="MT01", long_name="Meshtastic MT01"))

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["admin_keys"] == []
    assert document["warnings"] == []

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    assert NodeRecord.from_row(loaded.nodes[0]).authorized_admin_keys == ()


def test_adopt_single_unregistered_admin_key_reports_one_present_zero_recognized(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    stray_kp = keypair_factory()
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(stray_kp.public)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert len(document["admin_keys"]) == 1
    assert document["admin_keys"][0]["refs"] == []

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    assert NodeRecord.from_row(loaded.nodes[0]).authorized_admin_keys == ()


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


def test_status_surfaces_management_across_a_mixed_fleet(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    template_node = NodeRecord(
        node_id="aaaa0001",
        management=ManagementMode.TEMPLATE,
        short_name="MT01",
        long_name="Meshtastic MT01",
    )
    observed_node = NodeRecord(
        node_id="bbbb0002",
        management=ManagementMode.OBSERVED,
        short_name="OB02",
        long_name="Observed Node 02",
    )
    seed_db(nodes=[template_node, observed_node])

    bus.use(FakeMeshInterface("cccc0003"))
    adopted = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert adopted.exit_code == 0
    enrolled = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--enroll"], env)
    assert enrolled.exit_code == 0

    with mock_sources(nodes={}):
        status_doc = json.loads(invoke(runner, ["status", "--json"], env).stdout)
    by_id = {n["node_id"]: n for n in status_doc["nodes"]}
    assert set(by_id) == {"aaaa0001", "bbbb0002", "cccc0003"}
    for node in by_id.values():
        assert set(node["database"]) == {
            "short_name",
            "long_name",
            "role",
            "region",
            "management",
        }
    assert by_id["aaaa0001"]["database"]["management"] == "template"
    assert by_id["bbbb0002"]["database"]["management"] == "observed"
    assert by_id["cccc0003"]["database"]["management"] == "template"

    with mock_sources(nodes={}):
        table = invoke(runner, ["status"], env)
    assert table.exit_code == 0
    assert "observed" in table.stdout

    verify_result = invoke(runner, ["db", "verify", "--json"], env)
    verify_doc = json.loads(verify_result.stdout)
    assert verify_result.exit_code == 0, verify_doc["problems"]
    assert verify_doc["node_count"] == 3
    assert "nodes" not in verify_doc


def test_adopt_json_output_reports_the_expected_fields(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    bus.use(FakeMeshInterface("deadbe01", short_name="AB01", long_name="Adopted Node 01"))

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["node_id"] == "deadbe01"
    assert document["existing_management"] is None
    assert document["ble_pin_captured"] is False
    assert isinstance(document["warnings"], list)


def test_adopt_warns_on_a_duplicate_name_and_folds_it_into_json_warnings(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    seed_db(nodes=[NodeRecord(node_id="cafe0001", short_name="AB01", long_name="Adopted Node 01")])
    bus.use(FakeMeshInterface("deadbe01", short_name="AB01", long_name="Adopted Node 01"))

    text_result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert text_result.exit_code == 0
    assert "short_name 'AB01'" in text_result.stderr
    assert "long_name 'Adopted Node 01'" in text_result.stderr
    assert "cafe0001" in text_result.stderr

    json_result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
    assert json_result.exit_code == 0
    document = json.loads(json_result.stdout)
    assert any("short_name 'AB01'" in warning for warning in document["warnings"])
    assert any("long_name 'Adopted Node 01'" in warning for warning in document["warnings"])


def test_adopt_warns_on_a_duplicate_admin_key_already_registered_on_another_node(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """Exact raw-material comparison against another node's registered admin key ref."""
    shared_kp = keypair_factory()
    pub, priv = KeyRecord.for_keypair("OTHER", shared_kp)
    seed_db(
        nodes=[NodeRecord(node_id="cafe0001", authorized_admin_keys=("OTHER_pub",))],
        keys=[pub, priv],
    )
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(shared_kp.public)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert any("cafe0001" in w and "CVE-2025-52464" in w for w in document["warnings"])


def test_adopt_warns_on_a_duplicate_admin_key_previously_observed_unregistered(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """Exact-material comparison against another node's never-imported observed key.

    The scenario the fix exists for: two vendor-cloned devices, neither
    key ever registered in the Keys sheet.
    """
    cloned_kp = keypair_factory()
    seed_db(
        nodes=[
            NodeRecord(
                node_id="cafe0001",
                unregistered_admin_keys=(encode_key(cloned_kp.public),),
            )
        ]
    )
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(cloned_kp.public)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert any("cafe0001" in w and "CVE-2025-52464" in w for w in document["warnings"])


def test_adopt_does_not_warn_about_its_own_previously_persisted_fingerprint(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """A re-adopt of the same node must never flag itself as a duplicate."""
    kp = keypair_factory()
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(kp.public)

    first = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
    assert first.exit_code == 0
    assert not any("CVE-2025-52464" in w for w in json.loads(first.stdout)["warnings"])

    bus.use(iface)
    second = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
    assert second.exit_code == 0
    assert not any("CVE-2025-52464" in w for w in json.loads(second.stdout)["warnings"])


def test_declining_the_adopt_prompt_writes_nothing(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)
    iface = bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["--interactive", "adopt", "--port", "/dev/ttyFAKE0"], env, input="n\n")

    assert result.exit_code == int(ExitCode.INTERRUPTED)
    assert "Aborted." in result.stderr
    assert iface.localNode.written_sections == []
    assert db_fingerprint(db_path) == before


@dataclass(frozen=True)
class _FleetSpec:
    node_id: str
    short_name: str
    long_name: str
    firmware: str
    admin_key: str | None
    fits_pattern: bool


_FLEET_SPECS: tuple[_FleetSpec, ...] = (
    _FleetSpec("10000001", "MT01", "Meshtastic MT01", "2.7.11", None, True),
    _FleetSpec("10000002", "MT02", "Meshtastic MT02", "2.7.11", "a", True),
    _FleetSpec("10000003", "RTR3", "East Ridge Repeater", "2.7.11", "a", False),
    _FleetSpec("10000004", "MT04", "Meshtastic MT04", "2.4.0", None, True),
    _FleetSpec("10000005", "GW05", "Garage Gateway", "2.5.0", "b", False),
    _FleetSpec("10000006", "MT06", "Meshtastic MT06", "2.6.10", "b", True),
    _FleetSpec("20000abc", "HM", "", "2.6.11", None, False),
    _FleetSpec("20000def", "MT08", "Meshtastic MT08", "2.7.5", "a", True),
    _FleetSpec("30001111", "NODE9", "Backyard Sensor Node", "2.3.11", "c", False),
    _FleetSpec("30002222", "MT10", "Meshtastic MT10", "2.7.11", "a", True),
    _FleetSpec("4a5b6c7d", "EDGE", "Edge Case Node", "2.6.9", None, False),
    _FleetSpec("deadffff", "MT12", "Meshtastic MT12", "2.7.11", None, True),
)


def test_fleet_adopt_heterogeneous_batch(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    kp_a = keypair_factory()
    kp_b = keypair_factory()
    kp_c = keypair_factory()
    key_lookup = {"a": kp_a.public, "b": kp_b.public, "c": kp_c.public}

    pub_a, priv_a = KeyRecord.for_keypair("FRIENDA", kp_a)
    seed_db(nodes=[], keys=[pub_a, priv_a])

    fleet_results: dict[str, dict[str, object]] = {}
    for spec in _FLEET_SPECS:
        iface = FakeMeshInterface(
            spec.node_id,
            short_name=spec.short_name,
            long_name=spec.long_name,
            firmware_version=spec.firmware,
        )
        if spec.admin_key is not None:
            iface.localNode.localConfig.security.admin_key.append(key_lookup[spec.admin_key])
        bus.use(iface)
        result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
        assert result.exit_code == 0
        fleet_results[spec.node_id] = json.loads(result.stdout)

    for spec in _FLEET_SPECS:
        assert fleet_results[spec.node_id]["node_id"] == spec.node_id
        assert fleet_results[spec.node_id]["existing_management"] is None

    for spec in _FLEET_SPECS:
        has_warning = any(
            "does not match the configured pattern" in w
            for w in fleet_results[spec.node_id]["warnings"]
        )
        assert has_warning == (not spec.fits_pattern)

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes = {row["node_id"]: NodeRecord.from_row(row) for row in loaded.nodes}
    assert set(nodes) == {spec.node_id for spec in _FLEET_SPECS}
    assert len(nodes) == len(_FLEET_SPECS)
    assert all(n.management is ManagementMode.OBSERVED for n in nodes.values())
    for spec in _FLEET_SPECS:
        assert nodes[spec.node_id].short_name == spec.short_name
        assert nodes[spec.node_id].long_name == spec.long_name
        assert nodes[spec.node_id].firmware_version == spec.firmware

    for spec in _FLEET_SPECS:
        if spec.admin_key == "a":
            assert nodes[spec.node_id].authorized_admin_keys == ("FRIENDA_pub",)
        else:
            assert nodes[spec.node_id].authorized_admin_keys == ()

    verify_result = invoke(runner, ["db", "verify", "--json"], env)
    verify_doc = json.loads(verify_result.stdout)
    assert verify_result.exit_code == 0, verify_doc["problems"]
    assert verify_doc["node_count"] == 12
    assert verify_doc["key_count"] == 2
    assert verify_doc["problems"] == []

    before = db_fingerprint(Path(env["MESHPROVISION_DB_PATH"]))
    with mock_sources(nodes={}):
        status_result = invoke(runner, ["status", "--json"], env)
    assert status_result.exit_code == 0
    assert db_fingerprint(Path(env["MESHPROVISION_DB_PATH"])) == before
    assert len(json.loads(status_result.stdout)["nodes"]) == 12

    assert fleet_results["10000005"]["firmware_vulnerable"] is True
    assert fleet_results["10000006"]["firmware_vulnerable"] is True
    assert fleet_results["10000001"]["firmware_vulnerable"] is False
    assert fleet_results["10000004"]["firmware_vulnerable"] is False


def test_adopt_batch_flags_only_the_vulnerable_firmware_nodes(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    specs = [
        ("aaaa0001", "2.4.9"),
        ("bbbb0002", "2.5.0"),
        ("cccc0003", "2.6.10"),
        ("dddd0004", "2.6.11"),
        ("eeee0005", "2.7.11"),
    ]
    reports: dict[str, dict[str, object]] = {}
    for node_id, firmware in specs:
        bus.use(FakeMeshInterface(node_id, firmware_version=firmware))
        result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
        assert result.exit_code == 0
        reports[node_id] = json.loads(result.stdout)

    assert reports["aaaa0001"]["firmware_vulnerable"] is False
    assert reports["bbbb0002"]["firmware_vulnerable"] is True
    assert reports["cccc0003"]["firmware_vulnerable"] is True
    assert reports["dddd0004"]["firmware_vulnerable"] is False
    assert reports["eeee0005"]["firmware_vulnerable"] is False
    assert reports["aaaa0001"]["firmware_vulnerable"] != reports["bbbb0002"]["firmware_vulnerable"]

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes = {row["node_id"]: NodeRecord.from_row(row) for row in loaded.nodes}
    assert set(nodes) == {n for n, _ in specs}
    assert all(n.management is ManagementMode.OBSERVED for n in nodes.values())
