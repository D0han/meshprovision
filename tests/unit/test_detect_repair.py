"""Tests for meshprovision.provisioning.detect and meshprovision.provisioning.repair."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from meshtastic.protobuf import localonly_pb2

from meshprovision.db.nodes import NodeRecord
from meshprovision.errors import DetectionError, PlanConflictError
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import detect, repair

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# classify decision table.
# ---------------------------------------------------------------------------


def test_classify_in_database(make_live) -> None:
    from meshprovision.config.template import load_template_text

    template = load_template_text("version: 1\n")
    live = make_live(template, short_name="CUST", long_name="Custom Name")
    record = NodeRecord(node_id="deadbe01")
    detection = detect.classify(live, db_entry=record)
    assert detection.state is detect.NodeState.PROVISIONED
    assert "in_database" in detection.reasons
    assert "factory_defaults_restored" not in detection.reasons


def test_classify_in_database_factory_defaults_restored_and_no_admin_keys(make_live) -> None:
    from meshprovision.config.template import load_template_text
    from tests.unit.conftest import make_security

    template = load_template_text("version: 1\n")
    live = make_live(
        template, short_name="be01", long_name="Meshtastic be01", security=make_security(empty=True)
    )
    record = NodeRecord(node_id="deadbe01")
    detection = detect.classify(live, db_entry=record)
    assert detection.state is detect.NodeState.PROVISIONED
    assert set(detection.reasons) == {"in_database", "factory_defaults_restored", "no_admin_keys"}


def test_classify_factory(factory_live) -> None:
    detection = detect.classify(factory_live, db_entry=None)
    assert detection.state is detect.NodeState.FACTORY
    assert set(detection.reasons) == {
        "not_in_database",
        "factory_default_names",
        "no_admin_keys",
    }


def test_classify_foreign_custom_names(make_live) -> None:
    from meshprovision.config.template import load_template_text
    from tests.unit.conftest import make_security

    template = load_template_text("version: 1\n")
    live = make_live(
        template, short_name="CUST", long_name="Custom", security=make_security(empty=True)
    )
    detection = detect.classify(live, db_entry=None)
    assert detection.state is detect.NodeState.FOREIGN
    assert set(detection.reasons) == {"not_in_database", "custom_names"}


def test_classify_foreign_admin_keys_present_with_factory_names(make_live, keypair_factory) -> None:
    from meshprovision.config.template import load_template_text
    from tests.unit.conftest import make_security

    template = load_template_text("version: 1\n")
    live = make_live(
        template,
        short_name="be01",
        long_name="Meshtastic be01",
        security=make_security(admin_keys=(keypair_factory().public,)),
    )
    detection = detect.classify(live, db_entry=None)
    assert detection.state is detect.NodeState.FOREIGN
    assert set(detection.reasons) == {"not_in_database", "admin_keys_present"}


def test_detection_summary_text(factory_live) -> None:
    detection = detect.classify(factory_live, db_entry=None)
    summary = detection.summary()
    assert "FACTORY" in summary
    assert factory_live.node_id.display in summary


# ---------------------------------------------------------------------------
# is_factory_short_name / is_factory_long_name.
# ---------------------------------------------------------------------------


def test_is_factory_short_name() -> None:
    node_id = NodeId.from_hex("deadbe01")
    assert detect.is_factory_short_name("", node_id) is True
    assert detect.is_factory_short_name("BE01", node_id) is True
    assert detect.is_factory_short_name("be01", node_id) is True
    assert detect.is_factory_short_name("ABCD", node_id) is True
    assert detect.is_factory_short_name("Custom", node_id) is False


def test_is_factory_long_name() -> None:
    node_id = NodeId.from_hex("deadbe01")
    assert detect.is_factory_long_name("", node_id) is True
    assert detect.is_factory_long_name("Meshtastic be01", node_id) is True
    assert detect.is_factory_long_name("Meshtastic ABCD", node_id) is True
    assert detect.is_factory_long_name("Custom Name", node_id) is False


# ---------------------------------------------------------------------------
# live_config_from_protobufs.
# ---------------------------------------------------------------------------


def test_live_config_from_protobufs_normalizes_enums_and_excludes_repeated_bytes() -> None:
    local_config = localonly_pb2.LocalConfig()
    local_config.device.role = 2  # ROUTER
    local_config.lora.region = 3  # EU_868
    local_config.security.public_key = bytes(range(32))
    local_config.security.private_key = bytes(range(32))
    local_config.security.admin_key.append(bytes(range(1, 33)))

    module_config = localonly_pb2.LocalModuleConfig()
    module_config.mqtt.enabled = True

    live = detect.live_config_from_protobufs(
        local_config, module_config, node_id=NodeId.from_hex("deadbe01")
    )
    assert live.value("device", "role") == "ROUTER"
    assert live.value("lora", "region") == "EU_868"
    assert "network" not in live.sections or "ipv4_config" not in live.sections.get("network", {})

    assert live.module_enabled["telemetry"] is None
    assert live.module_enabled["mqtt"] is True

    assert live.security.public_key == bytes(range(32))
    assert live.security.private_key is not None
    assert live.security.admin_keys == (bytes(range(1, 33)),)


def test_live_config_from_protobufs_empty_security_keys_become_none() -> None:
    local_config = localonly_pb2.LocalConfig()
    module_config = localonly_pb2.LocalModuleConfig()
    live = detect.live_config_from_protobufs(
        local_config, module_config, node_id=NodeId.from_hex("deadbe01")
    )
    assert live.security.public_key is None
    assert live.security.has_public_key is False


def test_live_security_repr_never_leaks_raw_bytes() -> None:
    local_config = localonly_pb2.LocalConfig()
    local_config.security.public_key = bytes(range(32))
    local_config.security.admin_key.append(bytes(range(1, 33)))
    module_config = localonly_pb2.LocalModuleConfig()
    live = detect.live_config_from_protobufs(
        local_config, module_config, node_id=NodeId.from_hex("deadbe01")
    )
    text = repr(live.security)
    assert "sha256:" in text
    assert bytes(range(32)).hex() not in text


def test_live_config_kind_of_unknown_raises() -> None:
    from meshprovision.provisioning.detect import LiveConfig

    live = LiveConfig(node_id=NodeId.from_hex("deadbe01"))
    with pytest.raises(PlanConflictError):
        live.kind_of("not_a_real_section")
    assert live.kind_of("device") == "config"
    assert live.kind_of("mqtt") == "module_config"


# ---------------------------------------------------------------------------
# read_live_config with a minimal fake interface.
# ---------------------------------------------------------------------------


class _FakeNode:
    def __init__(self) -> None:
        self.localConfig = localonly_pb2.LocalConfig()
        self.moduleConfig = localonly_pb2.LocalModuleConfig()


class _FakeIface:
    def __init__(self, *, my_info: bool = True, num: int = 0xDEADBE01) -> None:
        self.myInfo = SimpleNamespace(my_node_num=num) if my_info else None
        self.metadata = SimpleNamespace(hw_model="RAK4631", firmware_version="2.7.11")
        self.localNode = _FakeNode()
        self._user = {"shortName": "MT00", "longName": "Meshtastic MT00", "hwModel": "RAK4631"}
        self._info_fallback: dict[str, int] | None = None

    def getMyUser(self) -> dict[str, str]:  # noqa: N802 -- real MeshInterface method name
        return dict(self._user)

    def getMyNodeInfo(self) -> dict[str, int] | None:  # noqa: N802 -- real MeshInterface method name
        return self._info_fallback


def test_read_live_config_with_my_info() -> None:
    iface = _FakeIface()
    live = detect.read_live_config(iface)  # type: ignore[arg-type]
    assert live.node_id == NodeId.from_hex("deadbe01")
    assert live.short_name == "MT00"
    assert live.hw_model == "RAK4631"


def test_read_live_config_falls_back_to_get_my_node_info() -> None:
    iface = _FakeIface(my_info=False)
    iface._info_fallback = {"num": 0xDEADBE01}
    live = detect.read_live_config(iface)  # type: ignore[arg-type]
    assert live.node_id == NodeId.from_hex("deadbe01")


def test_read_live_config_detection_error_when_nothing_reported() -> None:
    iface = _FakeIface(my_info=False)
    iface._info_fallback = None
    with pytest.raises(DetectionError):
        detect.read_live_config(iface)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# repair.diff_record.
# ---------------------------------------------------------------------------


def test_diff_record_empty_recorded_value_is_never_drift(make_live) -> None:
    from meshprovision.config.template import load_template_text

    template = load_template_text("version: 1\n")
    live = make_live(template, short_name="CUSTOM", long_name="Custom Name")
    record = NodeRecord(node_id="deadbe01")  # blank short/long/hw/fw/role/region defaults
    drifts = repair.diff_record(live, record)
    names = {(d.kind, d.field) for d in drifts}
    assert (repair.DriftKind.NAME, "short_name") not in names
    assert (repair.DriftKind.NAME, "long_name") not in names
    assert (repair.DriftKind.HARDWARE, "hw_model") not in names


def test_diff_record_name_hardware_firmware_role_region_drift(make_live) -> None:
    from meshprovision.config.template import load_template_text

    template = load_template_text("version: 1\n")
    live = make_live(
        template,
        short_name="NEW1",
        long_name="New Name",
        hw_model="TBEAM",
        firmware_version="2.7.12",
    )
    record = NodeRecord(
        node_id="deadbe01",
        short_name="OLD1",
        long_name="Old Name",
        hw_model="RAK4631",
        firmware_version="2.7.11",
        role="ROUTER",
        region="US",
    )
    drifts = repair.diff_record(live, record)
    by_field = {d.field: d for d in drifts}
    assert by_field["short_name"].recorded == "OLD1"
    assert by_field["short_name"].observed == "NEW1"
    assert by_field["long_name"].recorded == "Old Name"
    assert by_field["hw_model"].recorded == "RAK4631"
    assert by_field["firmware_version"].recorded == "2.7.11"
    assert by_field["role"].recorded == "ROUTER"
    assert by_field["role"].observed == "CLIENT"
    assert by_field["region"].recorded == "US"
    assert by_field["region"].observed == "EU_868"

    fields_order = [d.field for d in drifts]
    assert fields_order.index("short_name") < fields_order.index("long_name")
    assert fields_order.index("hw_model") < fields_order.index("firmware_version")
    assert fields_order.index("firmware_version") < fields_order.index("role")
    assert fields_order.index("role") < fields_order.index("region")


def test_diff_record_admin_key_rendering_with_unknown_key(make_live, keypair_factory) -> None:
    from meshprovision.config.template import load_template_text
    from meshprovision.crypto import redact
    from tests.unit.conftest import make_security

    template = load_template_text("version: 1\n")
    kp1 = keypair_factory()
    kp2 = keypair_factory()
    live = make_live(
        template,
        security=make_security(admin_keys=(kp1.public, kp2.public)),
    )
    record = NodeRecord(node_id="deadbe01", authorized_admin_keys=("ADMIN1_pub",))
    admin_key_refs = {kp1.public: "ADMIN1_pub"}
    drifts = repair.diff_record(live, record, admin_key_refs=admin_key_refs)
    admin_drift = next(d for d in drifts if d.kind is repair.DriftKind.ADMIN_KEYS)
    assert admin_drift.recorded == "ADMIN1_pub"
    assert f"<unknown:{redact.fingerprint(kp2.public)}>" in admin_drift.observed


def test_diff_record_public_key_present_ref_always_derived_from_node_id(
    make_live, keypair_factory
) -> None:
    """Pin down that a live public key never trips the KEY_MATERIAL drift check.

    ``NodeRecord.public_key_ref`` is a derived property (``node_id + "_pub"``)
    that is never empty as long as ``node_id`` is set, so a device reporting a
    real public key never trips the check on that path.
    """
    from meshprovision.config.template import load_template_text
    from tests.unit.conftest import make_security

    template = load_template_text("version: 1\n")
    kp = keypair_factory()
    live = make_live(template, security=make_security(keypair=kp))
    record = NodeRecord(node_id="deadbe01")
    assert record.public_key_ref == "deadbe01_pub"
    drifts = repair.diff_record(live, record)
    assert not any(d.kind is repair.DriftKind.KEY_MATERIAL for d in drifts)


def test_drift_describe() -> None:
    drift = repair.Drift(
        kind=repair.DriftKind.RADIO, field="role", recorded="CLIENT", observed="ROUTER"
    )
    assert drift.describe() == "radio.role: recorded=CLIENT, observed=ROUTER"


def test_reconcile_record_preserves_ble_pin_and_timestamps(make_live) -> None:
    from meshprovision.config.template import load_template_text
    from meshprovision.provisioning.plan import PlanInputs, build_plan

    template = load_template_text("version: 1\n")
    live = make_live(template, short_name="NEW1", long_name="New Name")
    record = NodeRecord(node_id="deadbe01", ble_pin="012345")
    plan = build_plan(
        PlanInputs(
            live=live, template=template, db_entry=record, state=detect.NodeState.PROVISIONED
        )
    )
    reconciled = repair.reconcile_record(record, live, plan)
    assert reconciled.ble_pin is not None
    assert reconciled.ble_pin.get_secret_value() == "012345"
    assert reconciled.short_name == "NEW1"
