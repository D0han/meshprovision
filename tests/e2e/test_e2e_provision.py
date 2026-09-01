"""Factory provisioning end to end, drift repair, and ``--dry-run``/``--json``.

Every assertion in this module that touches secret material asserts its
*absence* from stdout/stderr, per the project's secret-hygiene rule.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.crypto import weakkeys
from meshprovision.db import ods
from meshprovision.db.keys import KeyRecord
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import KeyType
from meshprovision.errors import ExitCode
from tests.e2e.conftest import FakeMeshInterface, db_fingerprint, invoke

if TYPE_CHECKING:
    from collections.abc import Callable

    from click.testing import CliRunner

    from meshprovision.crypto.keys import KeyPair
    from tests.e2e.conftest import DeviceBus

pytestmark = pytest.mark.e2e

_BASE64_KEY_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")
_SIX_DIGIT_RE = re.compile(r"(?<!\d)\d{6}(?!\d)")


def _assert_no_secrets(text: str) -> None:
    """Assert ``text`` contains no 44-char base64 blob and no bare 6-digit run."""
    assert not _BASE64_KEY_RE.search(text)
    assert not _SIX_DIGIT_RE.search(text)


def _scan_for_secrets(value: object) -> None:
    """Recursively scan a decoded JSON document for base64 keys or PINs."""
    if isinstance(value, str):
        _assert_no_secrets(value)
    elif isinstance(value, dict):
        for v in value.values():
            _scan_for_secrets(v)
    elif isinstance(value, list):
        for item in value:
            _scan_for_secrets(item)


def test_factory_provisioning_end_to_end(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    iface = bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert "FACTORY" in result.stderr

    assert iface.localNode.localConfig.lora.region == 3  # EU_868
    assert iface.localNode.localConfig.lora.hop_limit == 3
    assert iface.localNode.localConfig.bluetooth.mode == 1  # FIXED_PIN

    public_key = bytes(iface.localNode.localConfig.security.public_key)
    private_key = bytes(iface.localNode.localConfig.security.private_key)
    assert len(public_key) == 32
    assert any(b != 0 for b in public_key)
    assert len(private_key) == 32

    assert iface.localNode.written_sections[-1] == "security"

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes = [NodeRecord.from_row(row) for row in loaded.nodes]
    assert len(nodes) == 1
    node = nodes[0]
    assert node.node_id == "deadbe01"
    assert node.short_name == "MT00"
    assert node.long_name == "Meshtastic MT00"
    assert node.hw_model == "RAK4631"
    assert node.firmware_version == "2.7.11"
    assert node.ble_pin is not None
    assert re.fullmatch(r"\d{6}", node.ble_pin.get_secret_value())
    assert node.first_added_ts is not None
    assert node.last_updated_ts is not None
    assert node.authorized_admin_keys == ()

    keys = [KeyRecord.from_row(row) for row in loaded.keys]
    assert len(keys) == 2
    by_ref = {k.key_ref: k for k in keys}
    assert set(by_ref) == {"deadbe01_pub", "deadbe01_priv"}
    assert by_ref["deadbe01_pub"].material() == public_key
    assert by_ref["deadbe01_priv"].material() == private_key

    _assert_no_secrets(result.stdout)
    _assert_no_secrets(result.stderr)


def test_provision_reports_a_failed_database_save_as_divergence(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, monkeypatch: pytest.MonkeyPatch
) -> None:
    iface = bus.use(FakeMeshInterface("deadbe01"))

    def _raise(*args: object, **kwargs: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(ods, "write_database", _raise)

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == int(ExitCode.DB)
    assert "written and verified on the device" in result.stderr
    assert "disagree" in result.stderr

    assert iface.localNode.localConfig.lora.region == 3  # EU_868
    assert iface.localNode.written_sections[-1] == "security"

    monkeypatch.undo()
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    assert loaded.nodes == ()

    _assert_no_secrets(result.stderr)


def test_declining_the_apply_prompt_aborts_before_any_write(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    iface = bus.use(FakeMeshInterface("deadbe01"))
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)

    # --interactive is mandatory here: CliRunner's stdin is not a TTY, so the
    # prompt would otherwise become a NonInteractiveError instead of a decline.
    result = invoke(
        runner, ["--interactive", "provision", "--port", "/dev/ttyFAKE0"], env, input="n\n"
    )

    assert result.exit_code == int(ExitCode.INTERRUPTED)
    assert "Aborted." in result.stderr
    assert iface.localNode.written_sections == []
    assert bytes(iface.localNode.localConfig.security.public_key) == b""
    assert db_fingerprint(db_path) == before


def test_zero_admin_keys_is_a_valid_outcome_never_repaired(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    bus.use(FakeMeshInterface("deadbe01"))

    first = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert first.exit_code == 0

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    node = NodeRecord.from_row(loaded.nodes[0])
    assert node.authorized_admin_keys == ()

    second = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert second.exit_code == 0
    assert "No changes needed." in second.stderr


def test_drift_repair_renames_back_and_updates_role(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    kp = keypair_factory()
    node_record = NodeRecord(
        node_id="deadbe01",
        short_name="MT07",
        long_name="Meshtastic MT07",
        hw_model="RAK4631",
        role="ROUTER",
        region="EU_868",
    )
    pub_record, priv_record = KeyRecord.for_keypair("deadbe01", kp)
    seed_db(nodes=[node_record], keys=[pub_record, priv_record])

    iface = bus.use(FakeMeshInterface("deadbe01", short_name="be01"))
    iface.localNode.localConfig.security.public_key = kp.public
    iface.localNode.localConfig.security.private_key = kp.private.reveal()
    iface.localNode.localConfig.device.role = 2  # ROUTER

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert "Drift detected:" in result.stderr
    assert re.search(r"name\.short_name: recorded=MT07, observed=be01", result.stderr)

    assert iface.user["shortName"] == "MT07"
    assert iface.localNode.localConfig.device.role == 0  # CLIENT (template default)

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    persisted = NodeRecord.from_row(loaded.nodes[0])
    assert persisted.role == "CLIENT"
    assert persisted.last_updated_ts is not None
    assert persisted.last_updated_ts != node_record.first_added_ts

    keys = {row["key_ref"]: row for row in loaded.keys}
    assert KeyRecord.from_row(keys["deadbe01_pub"]).material() == kp.public
    assert bytes(iface.localNode.localConfig.security.public_key) == kp.public


def test_repair_with_no_admin_nodes_template_preserves_existing_admin_keys(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    kp = keypair_factory()
    admin_kp = keypair_factory()
    node_record = NodeRecord(
        node_id="deadbe01",
        short_name="MT07",
        long_name="Meshtastic MT07",
        hw_model="RAK4631",
        role="ROUTER",
        region="EU_868",
        authorized_admin_keys=("ADMIN1_pub",),
    )
    pub_record, priv_record = KeyRecord.for_keypair("deadbe01", kp)
    admin_pub_record, admin_priv_record = KeyRecord.for_keypair("ADMIN1", admin_kp)
    seed_db(
        nodes=[node_record],
        keys=[pub_record, priv_record, admin_pub_record, admin_priv_record],
    )

    iface = bus.use(FakeMeshInterface("deadbe01", short_name="be01"))
    iface.localNode.localConfig.security.public_key = kp.public
    iface.localNode.localConfig.security.private_key = kp.private.reveal()
    iface.localNode.localConfig.security.admin_key.append(admin_kp.public)
    iface.localNode.localConfig.device.role = 2  # ROUTER

    # env's default template has admin_nodes: [] -- resolve_admin_keys therefore
    # has no opinion, and ChangePlan.to_record() must leave the node's existing
    # authorized_admin_keys untouched rather than wiping them.
    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert "Drift detected:" in result.stderr

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    persisted = NodeRecord.from_row(loaded.nodes[0])
    assert persisted.authorized_admin_keys == ("ADMIN1_pub",)


def test_revoked_live_admin_key_is_dropped_from_the_record(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    kp = keypair_factory()
    admin2_kp = keypair_factory()
    weak_public = weakkeys.SMALL_ORDER_POINTS[3]
    node_record = NodeRecord(
        node_id="deadbe01",
        short_name="MT07",
        long_name="Meshtastic MT07",
        hw_model="RAK4631",
        role="ROUTER",
        region="EU_868",
        authorized_admin_keys=("ADMIN1_pub", "ADMIN2_pub"),
    )
    pub_record, priv_record = KeyRecord.for_keypair("deadbe01", kp)
    admin2_pub, admin2_priv = KeyRecord.for_keypair("ADMIN2", admin2_kp)
    seed_db(
        nodes=[node_record],
        keys=[
            pub_record,
            priv_record,
            KeyRecord.from_material("ADMIN1", KeyType.ADMIN_PUBLIC, weak_public),
            admin2_pub,
            admin2_priv,
        ],
    )

    iface = bus.use(FakeMeshInterface("deadbe01", short_name="be01"))
    iface.localNode.localConfig.security.public_key = kp.public
    iface.localNode.localConfig.security.private_key = kp.private.reveal()
    iface.localNode.localConfig.security.admin_key.append(weak_public)
    iface.localNode.localConfig.security.admin_key.append(admin2_kp.public)
    iface.localNode.localConfig.device.role = 2  # ROUTER

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    _assert_no_secrets(result.stderr)

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    persisted = NodeRecord.from_row(loaded.nodes[0])
    assert persisted.authorized_admin_keys == ("ADMIN2_pub",)
    assert [bytes(k) for k in iface.localNode.localConfig.security.admin_key] == [admin2_kp.public]

    # The headline symptom: a second run must no longer report admin_keys drift
    # between the (now narrowed) row and the (now cleaned) device.
    second = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--dry-run"], env)

    assert second.exit_code == 0
    _assert_no_secrets(second.stderr)
    assert "admin_keys" not in second.stderr


def test_dry_run_writes_nothing(runner: CliRunner, env: dict[str, str], bus: DeviceBus) -> None:
    iface = bus.use(FakeMeshInterface("deadbe01"))
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--dry-run"], env)

    assert result.exit_code == 0
    assert result.stdout.strip() != ""
    assert iface.localNode.written_sections == []
    assert bytes(iface.localNode.localConfig.security.public_key) == b""
    assert db_fingerprint(db_path) == before


def test_json_plan_is_fully_redacted(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--dry-run", "--json"], env)

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert set(document) >= {"detection", "drifts", "plan"}
    assert document["plan"]["key_plan"]["regenerate"] is True
    assert document["plan"]["ble_pin_set"] is True

    _scan_for_secrets(document)
