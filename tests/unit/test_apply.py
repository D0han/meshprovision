"""Tests for meshprovision.provisioning.apply (no real device)."""

from __future__ import annotations

import base64

import pytest
from meshtastic.protobuf import localonly_pb2

from meshprovision.config.template import TemplateConfig, load_template_text
from meshprovision.crypto.keys import generate_keypair
from meshprovision.db.keys import KeyRepository
from meshprovision.db.nodes import NodeRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.errors import ConnectionBackendError, EnumMappingError, PlanConflictError
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import detect
from meshprovision.provisioning.apply import (
    ApplyOutcome,
    InPlaceSession,
    WriteResult,
    WriteStatus,
    apply_field,
    apply_plan,
    generate_ble_pin,
    persist_result,
    verify_plan,
    write_section,
)
from meshprovision.provisioning.plan import PlanInputs, SectionChange, build_plan
from tests.unit.conftest import make_security

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# generate_ble_pin.
# ---------------------------------------------------------------------------


def test_generate_ble_pin_with_injected_rng() -> None:
    pin = generate_ble_pin(rng=lambda _bound: 0)
    assert pin == "000000"
    assert len(pin) == 6
    assert pin.isdigit()


def test_generate_ble_pin_real_calls_are_six_digits() -> None:
    for _ in range(200):
        pin = generate_ble_pin()
        assert len(pin) == 6
        assert pin.isdigit()


# ---------------------------------------------------------------------------
# apply_field.
# ---------------------------------------------------------------------------


def _local_config() -> localonly_pb2.LocalConfig:
    return localonly_pb2.LocalConfig()


def test_apply_field_enum_by_name() -> None:
    msg = _local_config().device
    apply_field(msg, "role", "ROUTER")
    assert msg.role == 2


def test_apply_field_unknown_enum_name_raises() -> None:
    msg = _local_config().device
    with pytest.raises(EnumMappingError) as exc_info:
        apply_field(msg, "role", "NOT_A_ROLE")
    assert exc_info.value.known


def test_apply_field_numeric_string_into_int_field() -> None:
    msg = _local_config().lora
    apply_field(msg, "hop_limit", "5")
    assert msg.hop_limit == 5


def test_apply_field_bad_numeric_string_raises() -> None:
    msg = _local_config().lora
    with pytest.raises(PlanConflictError):
        apply_field(msg, "hop_limit", "not-a-number")


def test_apply_field_bool_int_float_str_bytes() -> None:
    msg = _local_config().lora
    apply_field(msg, "tx_enabled", False)
    assert msg.tx_enabled is False
    apply_field(msg, "hop_limit", 4)
    assert msg.hop_limit == 4
    apply_field(msg, "frequency_offset", 1.5)
    assert msg.frequency_offset == pytest.approx(1.5)

    security_msg = _local_config().security
    apply_field(security_msg, "public_key", bytes(range(32)))
    assert bytes(security_msg.public_key) == bytes(range(32))


def test_apply_field_unknown_field_raises() -> None:
    msg = _local_config().device
    with pytest.raises(PlanConflictError):
        apply_field(msg, "not_a_real_field", "x")


def test_apply_field_unsupported_type_raises() -> None:
    msg = _local_config().device
    with pytest.raises(PlanConflictError):
        apply_field(msg, "role", object())


def test_write_section_unknown_section_raises() -> None:
    iface = _FakeIfaceForApply()
    change = SectionChange(section="not_a_real_section", kind="config", changes=())
    with pytest.raises(PlanConflictError):
        write_section(iface, change)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# A minimal fake interface for write/verify tests.
# ---------------------------------------------------------------------------


class _FakeLocalNode:
    def __init__(self, iface: _FakeIfaceForApply) -> None:
        self._iface = iface
        self.localConfig = localonly_pb2.LocalConfig()
        self.moduleConfig = localonly_pb2.LocalModuleConfig()
        self.written_sections: list[str] = []

    def writeConfig(self, section: str) -> None:  # noqa: N802 -- real MeshInterface method name
        self.written_sections.append(section)

    def setOwner(  # noqa: N802 -- real MeshInterface method name
        self,
        long_name: str | None = None,
        short_name: str | None = None,
        **_kw: object,
    ) -> None:
        if short_name is not None:
            self._iface.user["shortName"] = short_name
        if long_name is not None:
            self._iface.user["longName"] = long_name


class _FakeIfaceForApply:
    def __init__(self) -> None:
        from types import SimpleNamespace

        self.myInfo = SimpleNamespace(my_node_num=0xDEADBE01)
        self.metadata = SimpleNamespace(hw_model="RAK4631", firmware_version="2.7.11")
        self.user: dict[str, str] = {"shortName": "MT00", "longName": "Meshtastic MT00"}
        self.localNode = _FakeLocalNode(self)

    def getMyUser(self) -> dict[str, str]:  # noqa: N802 -- real MeshInterface method name
        return dict(self.user)

    def getPublicKey(self) -> str | None:  # noqa: N802 -- real MeshInterface method name
        raw = bytes(self.localNode.localConfig.security.public_key)
        return base64.b64encode(raw).decode("ascii") if raw else None


# ---------------------------------------------------------------------------
# verify_plan.
# ---------------------------------------------------------------------------


def _template() -> TemplateConfig:
    return load_template_text("version: 1\n")


def test_verify_plan_all_matching_confirmed(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)

    # Build a "live_after" identical to the plan's desired state.
    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(empty=True),
    )
    results = verify_plan(plan, live_after, keypair=None)
    non_key_results = [r for r in results if r.field not in ("public_key", "admin_key")]
    assert all(r.status == WriteStatus.CONFIRMED for r in non_key_results)


def test_verify_plan_mismatch_unconfirmed_with_expected_actual(make_live) -> None:
    template = _template()
    template2 = template.model_copy(
        update={"device": template.device.model_copy(update={"role": "ROUTER"})}
    )
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live, template=template2, db_entry=None, state=detect.NodeState.FACTORY
    )
    plan = build_plan(inputs)

    live_after = make_live(
        template2,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        section_overrides={"device": {"role": "CLIENT"}},
        security=make_security(empty=True),
    )
    results = verify_plan(plan, live_after, keypair=None)
    role_result = next(r for r in results if r.field == "role")
    assert role_result.status == WriteStatus.UNCONFIRMED
    assert role_result.expected == "ROUTER"
    assert role_result.actual == "CLIENT"


def test_verify_plan_secret_field_expected_actual_redacted(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        ble_pin="123456",
    )
    plan = build_plan(inputs)

    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(empty=True),
        section_overrides={"bluetooth": {}},
    )
    results = verify_plan(plan, live_after, keypair=None)
    pin_result = next((r for r in results if r.field == "fixed_pin"), None)
    assert pin_result is not None
    assert pin_result.status == WriteStatus.UNCONFIRMED
    assert pin_result.expected == "<redacted>"
    assert pin_result.actual == "<redacted>"


def test_verify_plan_name_truncated_confirmed(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        desired_short_name="ABCDE",
    )
    plan = build_plan(inputs)
    live_after = make_live(
        template,
        short_name="ABCD",
        long_name=plan.name_change.desired_long_name,
        security=make_security(empty=True),
    )
    results = verify_plan(plan, live_after, keypair=None)
    short_result = next(r for r in results if r.field == "short_name")
    assert short_result.status == WriteStatus.CONFIRMED
    assert "truncated" in short_result.message


def test_verify_plan_key_confirmed_needs_both_agree(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(keypair=kp),
    )
    results = verify_plan(plan, live_after, keypair=kp, device_public_key=kp.public_b64)
    key_result = next(r for r in results if r.field == "public_key")
    assert key_result.status == WriteStatus.CONFIRMED


def test_verify_plan_key_mismatch_unconfirmed_with_fingerprints(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()
    other_kp = generate_keypair()

    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(keypair=other_kp),
    )
    results = verify_plan(plan, live_after, keypair=kp, device_public_key=other_kp.public_b64)
    key_result = next(r for r in results if r.field == "public_key")
    assert key_result.status == WriteStatus.UNCONFIRMED
    assert key_result.expected is not None and key_result.expected.startswith("sha256:")
    assert key_result.actual is not None and key_result.actual.startswith("sha256:")


def test_verify_plan_key_none_device_public_key_confirmed_with_note(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(keypair=kp),
    )
    results = verify_plan(plan, live_after, keypair=kp, device_public_key=None)
    key_result = next(r for r in results if r.field == "public_key")
    assert key_result.status == WriteStatus.CONFIRMED
    assert "NodeDB cross-check unavailable" in key_result.message


def test_verify_plan_admin_keys_compared_sorted(make_live, make_admin_key) -> None:
    admin1 = make_admin_key("ADMIN1")
    template = _template().model_copy(update={"admin_nodes": ("ADMIN1",)})
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin1,),
    )
    plan = build_plan(inputs)

    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(admin_keys=(admin1.public,)),
    )
    results = verify_plan(plan, live_after, keypair=None)
    admin_result = next(r for r in results if r.field == "admin_key")
    assert admin_result.status == WriteStatus.CONFIRMED


# ---------------------------------------------------------------------------
# ApplyOutcome.
# ---------------------------------------------------------------------------


def test_apply_outcome_properties() -> None:
    ok_result = WriteResult("device", WriteStatus.CONFIRMED, "confirmed")
    outcome = ApplyOutcome(node_id=_node_id(), results=(ok_result,), dry_run=False)
    assert outcome.ok is True
    assert outcome.uncertain is False
    assert outcome.may_update_database is True
    assert outcome.exit_code == 0
    assert outcome.failures() == ()
    assert outcome.describe() == ("device: confirmed -- confirmed",)


def test_apply_outcome_uncertain_and_failures() -> None:
    bad_result = WriteResult("security", WriteStatus.UNCONFIRMED, "mismatch", field="public_key")
    outcome = ApplyOutcome(node_id=_node_id(), results=(bad_result,), dry_run=False)
    assert outcome.uncertain is True
    assert outcome.ok is False
    assert outcome.may_update_database is False
    assert outcome.exit_code != 0
    assert outcome.failures() == (bad_result,)
    with pytest.raises(Exception):  # noqa: B017
        outcome.raise_if_uncertain()


def test_apply_outcome_dry_run_never_updates_database_even_if_ok() -> None:
    ok_result = WriteResult("device", WriteStatus.SKIPPED, "dry run")
    outcome = ApplyOutcome(node_id=_node_id(), results=(ok_result,), dry_run=True)
    assert outcome.ok is True
    assert outcome.may_update_database is False


def _node_id() -> NodeId:
    return NodeId.from_hex("deadbe01")


# ---------------------------------------------------------------------------
# apply_plan / persist_result, over InPlaceSession + fake interface.
# ---------------------------------------------------------------------------


def test_apply_plan_regenerate_without_keypair_raises_before_write(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    assert plan.key_plan.regenerate is True

    iface = _FakeIfaceForApply()
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    with pytest.raises(PlanConflictError):
        apply_plan(plan, session, keypair=None)
    assert iface.localNode.written_sections == []


def test_apply_plan_dry_run_never_writes(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    iface = _FakeIfaceForApply()
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp, dry_run=True)
    assert outcome.dry_run is True
    assert iface.localNode.written_sections == []
    assert all(r.status == WriteStatus.SKIPPED for r in outcome.results)


def test_apply_plan_success_confirmed_and_persist_result(tmp_path, make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    iface = _FakeIfaceForApply()
    # An in-place session re-reads from the SAME iface, so the write must be
    # reflected there for verification to succeed -- write_section() does
    # this by mutating iface.localNode.localConfig directly.
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    assert outcome.dry_run is False
    assert outcome.verified is True
    assert outcome.ok is True, outcome.describe()
    assert outcome.record is not None

    db_path = tmp_path / "db.ods"
    db = OdsDatabase.create(db_path)
    nodes = NodeRepository(db)
    keys = KeyRepository(db)
    persisted = persist_result(outcome, nodes=nodes, keys=keys, keypair=kp)
    assert persisted is True
    assert nodes.exists("deadbe01")
    assert keys.find("deadbe01_pub") is not None
    assert keys.find("deadbe01_priv") is not None


class _RefreshFailsSession:
    """A session whose reconnect never succeeds -- pins the lost-reconnect path."""

    def __init__(self, iface: _FakeIfaceForApply) -> None:
        self._iface = iface

    @property
    def interface(self) -> _FakeIfaceForApply:
        return self._iface

    def describe(self) -> str:
        return "fake (refresh always fails)"

    def refresh(self) -> _FakeIfaceForApply:
        raise ConnectionBackendError("link dropped", transport="serial")


def test_apply_plan_reports_uncertain_when_the_reconnect_fails(tmp_path, make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    iface = _FakeIfaceForApply()
    session = _RefreshFailsSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    assert outcome.dry_run is False
    assert outcome.verified is True
    assert outcome.uncertain is True
    assert outcome.may_update_database is False

    verify_results = [r for r in outcome.results if r.section == "<verify>"]
    assert len(verify_results) == 1
    assert verify_results[0].status == WriteStatus.FAILED
    assert verify_results[0].message == "Could not reconnect to verify the writes"

    db_path = tmp_path / "db.ods"
    db = OdsDatabase.create(db_path)
    nodes = NodeRepository(db)
    keys = KeyRepository(db)
    mtime_before = db_path.stat().st_mtime_ns
    persisted = persist_result(outcome, nodes=nodes, keys=keys, keypair=kp)
    assert persisted is False
    assert db_path.stat().st_mtime_ns == mtime_before
    assert nodes.exists("deadbe01") is False


def test_persist_result_refuses_on_uncertain_outcome(tmp_path) -> None:
    bad_result = WriteResult("security", WriteStatus.UNCONFIRMED, "mismatch", field="public_key")
    outcome = ApplyOutcome(node_id=_node_id(), results=(bad_result,), dry_run=False, record=None)

    db_path = tmp_path / "db.ods"
    db = OdsDatabase.create(db_path)
    nodes = NodeRepository(db)
    keys = KeyRepository(db)

    mtime_before = db_path.stat().st_mtime_ns
    persisted = persist_result(outcome, nodes=nodes, keys=keys)
    assert persisted is False
    assert db_path.stat().st_mtime_ns == mtime_before
    assert nodes.exists("deadbe01") is False
