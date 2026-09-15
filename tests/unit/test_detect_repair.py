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


def test_classify_locked_node_with_factory_names_and_no_admin_keys_is_foreign(make_live) -> None:
    """Regression test: a factory-fresh device can never report is_managed=True.

    A node not in our database, with factory-default names and no
    readable admin keys (a partial/failed key rotation, for example) but
    security.is_managed=True must never be classified FACTORY -- it is
    locked by an admin key we don't have, and mesh provision's normal
    unauthenticated writeConfig path will not work against it.
    """
    from meshprovision.config.template import load_template_text
    from tests.unit.conftest import make_security

    template = load_template_text("version: 1\n")
    live = make_live(
        template,
        short_name="be01",
        long_name="Meshtastic be01",
        security=make_security(is_managed=True),
    )
    detection = detect.classify(live, db_entry=None)
    assert detection.state is detect.NodeState.FOREIGN
    assert set(detection.reasons) == {"not_in_database", "is_managed"}


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


def test_read_live_config_hw_model_unrecognized_preserves_raw_value() -> None:
    """An hw_model the enum table doesn't recognize must still be captured raw.

    Regression test: hw_model_raw exists specifically so a later
    unrecognized-vs-absent distinction (build_adoption_report's warning)
    is possible at all -- it must survive resolution failure, not just
    the successful case already covered by test_read_live_config_with_my_info.
    """
    iface = _FakeIface()
    iface._user["hwModel"] = "FUTURE_BOARD_9000"
    live = detect.read_live_config(iface)  # type: ignore[arg-type]
    assert live.hw_model == ""
    assert live.hw_model_raw == "FUTURE_BOARD_9000"


def test_read_live_config_hw_model_absent_leaves_raw_value_none() -> None:
    """A device reporting no hw_model at all must leave hw_model_raw None.

    Distinct from the unrecognized case above: None means "nothing to
    warn about," not "recognized as a known name."
    """
    iface = _FakeIface()
    iface._user["hwModel"] = ""
    iface.metadata.hw_model = None
    live = detect.read_live_config(iface)  # type: ignore[arg-type]
    assert live.hw_model == ""
    assert live.hw_model_raw is None


def test_read_live_config_falls_back_to_metadata_hw_model_when_user_absent() -> None:
    """No hwModel from getMyUser(), but iface.metadata.hw_model is set: must resolve from it.

    Regression guard distinct from the "absent" test above: that one
    only exercises the sub-path where metadata.hw_model is *also* None
    (hw_model_raw stays None). This exercises the actual "fall back to
    device metadata" behavior the else-branch exists for -- gutting the
    metadata->enum resolution entirely would still pass the "absent"
    test, since neither test alone pins down the successful-fallback
    case.
    """
    iface = _FakeIface()
    iface._user["hwModel"] = ""
    # iface.metadata.hw_model defaults to "RAK4631" in _FakeIface.__init__.
    live = detect.read_live_config(iface)  # type: ignore[arg-type]
    assert live.hw_model == "RAK4631"
    assert live.hw_model_raw == "RAK4631"


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


@pytest.mark.parametrize(
    ("live_kwargs", "record_kwargs"),
    [
        pytest.param(
            {"long_name": "Custom Long Name"}, {"long_name": "Custom Long Name"}, id="long_name"
        ),
        pytest.param({"hw_model": "RAK4631"}, {"hw_model": "RAK4631"}, id="hw_model"),
        pytest.param(
            {"firmware_version": "2.7.12"}, {"firmware_version": "2.7.12"}, id="firmware_version"
        ),
        pytest.param(
            {"section_overrides": {"device": {"role": "ROUTER"}}}, {"role": "ROUTER"}, id="role"
        ),
    ],
)
def test_diff_record_recorded_value_equal_to_live_is_never_drift(
    make_live, live_kwargs, record_kwargs
) -> None:
    """An already-correct node must report no drift at all.

    Distinct from the empty-recorded case above: here the ODS *does*
    carry a value for the field and it matches the device exactly. A
    regression at one of these call sites would make `mesh provision`
    report drift on every run against a node that is already correct --
    false-positive noise on a trust-relevant feature. One case per field
    so a single regressed call site is named, not just detected.
    """
    from meshprovision.config.template import load_template_text

    template = load_template_text("version: 1\n")
    live = make_live(template, **live_kwargs)
    record = NodeRecord(node_id="deadbe01", **record_kwargs)

    assert repair.diff_record(live, record) == ()


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
    public_keys = {"ADMIN1_pub": kp1.public}
    drifts = repair.diff_record(live, record, public_keys=public_keys)
    admin_drift = next(d for d in drifts if d.kind is repair.DriftKind.ADMIN_KEYS)
    assert admin_drift.recorded == "ADMIN1_pub"
    assert f"<unknown:{redact.fingerprint(kp2.public)}>" in admin_drift.observed


def test_diff_record_aliased_admin_key_is_not_drift(make_live, keypair_factory) -> None:
    from meshprovision.config.template import load_template_text
    from tests.unit.conftest import make_security

    template = load_template_text("version: 1\n")
    kp = keypair_factory()
    live = make_live(template, security=make_security(admin_keys=(kp.public,)))
    record = NodeRecord(node_id="deadbe01", authorized_admin_keys=("ADMIN1_pub",))
    for public_keys in (
        {"deadbe01_pub": kp.public, "ADMIN1_pub": kp.public},
        {"ADMIN1_pub": kp.public, "deadbe01_pub": kp.public},
    ):
        drifts = repair.diff_record(live, record, public_keys=public_keys)
        assert not any(d.kind is repair.DriftKind.ADMIN_KEYS for d in drifts), public_keys


def test_drift_describe() -> None:
    drift = repair.Drift(
        kind=repair.DriftKind.RADIO, field="role", recorded="CLIENT", observed="ROUTER"
    )
    assert drift.describe() == "radio.role: recorded=CLIENT, observed=ROUTER"


def test_repair_module_exposes_only_the_drift_api() -> None:
    assert set(repair.__all__) == {"Drift", "DriftKind", "diff_record"}
    for removed in ("build_repair_plan", "repair_node", "RepairReport", "reconcile_record"):
        assert not hasattr(repair, removed)
