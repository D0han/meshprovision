"""Tests for build_plan's security planning: is_managed lockdown, node keypair, signing policy."""

from __future__ import annotations

import pytest

from meshprovision.db.nodes import NodeRecord
from meshprovision.errors import (
    AdminKeyRotationRefusedError,
    LockdownRefusedError,
)
from meshprovision.provisioning import detect
from meshprovision.provisioning.plan import (
    ChangePlan,
    PlanInputs,
    PlanWarningCode,
    build_plan,
)
from tests.unit.conftest import make_security, with_admin_and_lockdown

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# is_managed refusals.
# ---------------------------------------------------------------------------


def test_lockdown_no_admin_keys_refused(make_live, template) -> None:
    template2 = with_admin_and_lockdown(template, "ADMIN1")
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live, template=template2, db_entry=None, state=detect.NodeState.FACTORY, admin_keys=()
    )
    with pytest.raises(LockdownRefusedError) as exc_info:
        build_plan(inputs)
    assert exc_info.value.reason == "no_admin_keys"


def test_lockdown_no_private_counterpart_refused(make_live, template, make_admin_key) -> None:
    admin = make_admin_key("ADMIN1", has_private=False)
    template2 = with_admin_and_lockdown(template, "ADMIN1")
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin,),
    )
    with pytest.raises(LockdownRefusedError) as exc_info:
        build_plan(inputs)
    assert exc_info.value.reason == "no_private_counterpart"


def test_lockdown_refused_when_private_counterpart_does_not_match(
    make_live, template, make_admin_key
) -> None:
    admin = make_admin_key("ADMIN1", has_private=False, private_mismatch=True, audit_ok=True)
    template2 = with_admin_and_lockdown(template, "ADMIN1")
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin,),
    )
    with pytest.raises(LockdownRefusedError) as exc_info:
        build_plan(inputs)
    assert exc_info.value.reason == "private_key_mismatch"


def test_lockdown_weak_admin_key_refused(make_live, template, make_admin_key) -> None:
    admin = make_admin_key("ADMIN1", audit_ok=False)
    template2 = with_admin_and_lockdown(template, "ADMIN1")
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin,),
    )
    with pytest.raises(LockdownRefusedError) as exc_info:
        build_plan(inputs)
    assert exc_info.value.reason == "weak_admin_key"
    assert admin.key_ref in str(exc_info.value)


def test_lockdown_positive_gates_but_not_allowed(make_live, template, make_admin_key) -> None:
    admin = make_admin_key("ADMIN1", has_private=True, audit_ok=True)
    template2 = with_admin_and_lockdown(template, "ADMIN1")
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin,),
        allow_lockdown=False,
    )
    plan = build_plan(inputs)
    assert plan.lockdown.enable is False
    assert plan.lockdown.reason == "allow_lockdown_not_set"
    assert any(w.code == "lockdown_not_authorized" for w in plan.warnings)
    assert plan.lockdown.gates["explicit_intent"] is False


def test_lockdown_stays_enabled_without_allow_lockdown_when_already_locked(
    make_live, template, make_admin_key
) -> None:
    admin = make_admin_key("ADMIN1", has_private=True, audit_ok=True)
    template2 = with_admin_and_lockdown(template, "ADMIN1")
    live = make_live(template2, security=make_security(is_managed=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin,),
        allow_lockdown=False,
    )
    plan = build_plan(inputs)
    assert plan.lockdown.enable is True
    assert plan.lockdown.reason == "already_locked"
    assert not any(w.code == "lockdown_not_authorized" for w in plan.warnings)
    security_section = plan.section("security")
    if security_section is not None:
        assert not any(c.field == "is_managed" for c in security_section.changes)
    # gates must be a real mapping here, not None -- to_json_dict() (the
    # mesh provision --json path) unconditionally does dict(lockdown.gates).
    assert dict(plan.lockdown.gates) == {
        "has_admin_keys": True,
        "has_private_counterpart": True,
        "audit_clean": True,
        "explicit_intent": False,
    }
    assert plan.to_json_dict()["lockdown"]["gates"] == dict(plan.lockdown.gates)


def test_lockdown_authorized(make_live, template, make_admin_key) -> None:
    admin = make_admin_key("ADMIN1", has_private=True, audit_ok=True)
    template2 = with_admin_and_lockdown(template, "ADMIN1")
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin,),
        allow_lockdown=True,
    )
    plan = build_plan(inputs)
    assert plan.lockdown.enable is True
    assert plan.lockdown.reason == "authorized"
    security_section = plan.section("security")
    assert security_section is not None
    is_managed_change = next(c for c in security_section.changes if c.field == "is_managed")
    assert is_managed_change.desired is True
    # gates must be a real mapping here, not None -- to_json_dict() (the
    # mesh provision --json path) unconditionally does dict(lockdown.gates).
    assert dict(plan.lockdown.gates) == {
        "has_admin_keys": True,
        "has_private_counterpart": True,
        "audit_clean": True,
        "explicit_intent": True,
    }
    assert plan.to_json_dict()["lockdown"]["gates"] == dict(plan.lockdown.gates)


def test_lockdown_template_opt_out(make_live, template) -> None:
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    assert plan.lockdown.reason == "template_opt_out"


# ---------------------------------------------------------------------------
# Node keypair decisions.
# ---------------------------------------------------------------------------


def test_force_regenerate_key(make_live, template, keypair) -> None:
    live = make_live(template, security=make_security(keypair=keypair))
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        force_regenerate_key=True,
    )
    plan = build_plan(inputs)
    assert plan.key_plan.regenerate is True
    assert plan.key_plan.regenerate_reason == "forced"
    assert plan.key_plan.adopt_device_key is False


def test_missing_key_material(make_live, template) -> None:
    live = make_live(template, security=make_security(empty=True))
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    inputs = PlanInputs(
        live=live, template=template, db_entry=record, state=detect.NodeState.PROVISIONED
    )
    plan = build_plan(inputs)
    assert plan.key_plan.regenerate is True
    assert plan.key_plan.regenerate_reason == "missing_key_material"
    assert plan.key_plan.adopt_device_key is False


def test_missing_key_material_public_present_private_absent(make_live, template, keypair) -> None:
    """EITHER half missing must trigger regeneration, not only both at once.

    The gate is ``not has_public_key or not has_private_key`` -- an
    ``and`` here would only regenerate when both halves are absent,
    silently accepting a node with a public key but no usable private
    counterpart.
    """
    live = make_live(
        template, security=detect.LiveSecurity(public_key=keypair.public, private_key=None)
    )
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    inputs = PlanInputs(
        live=live, template=template, db_entry=record, state=detect.NodeState.PROVISIONED
    )
    plan = build_plan(inputs)
    assert plan.key_plan.regenerate is True
    assert plan.key_plan.regenerate_reason == "missing_key_material"
    assert plan.key_plan.adopt_device_key is False


def test_missing_key_material_private_present_public_absent(make_live, template, keypair) -> None:
    live = make_live(
        template, security=detect.LiveSecurity(public_key=None, private_key=keypair.private)
    )
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    inputs = PlanInputs(
        live=live, template=template, db_entry=record, state=detect.NodeState.PROVISIONED
    )
    plan = build_plan(inputs)
    assert plan.key_plan.regenerate is True
    assert plan.key_plan.regenerate_reason == "missing_key_material"
    assert plan.key_plan.adopt_device_key is False


def test_node_key_compromised_with_reason(make_live, template, keypair) -> None:
    live = make_live(template, security=make_security(keypair=keypair))
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        node_key_compromised=True,
        node_key_reason="all_zero",
    )
    plan = build_plan(inputs)
    assert plan.key_plan.regenerate is True
    assert plan.key_plan.regenerate_reason == "all_zero"
    assert plan.key_plan.adopt_device_key is False


def test_node_key_compromised_empty_reason_defaults(make_live, template, keypair) -> None:
    live = make_live(template, security=make_security(keypair=keypair))
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        node_key_compromised=True,
        node_key_reason="",
    )
    plan = build_plan(inputs)
    assert plan.key_plan.regenerate_reason == "weak_key_audit"


def test_db_public_key_differs_adopts_device_key(
    make_live, template, keypair, keypair_factory
) -> None:
    other = keypair_factory()
    live = make_live(template, security=make_security(keypair=keypair))
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        db_public_key=other.public,
    )
    plan = build_plan(inputs)
    assert plan.key_plan.regenerate is False
    assert plan.key_plan.adopt_device_key is True
    assert any(w.code == "device_key_differs_from_db" for w in plan.warnings)
    assert any("#7449" in w.message for w in plan.warnings)
    # adopt_device_key alone must not pull in a "security" section: nothing
    # in write_section acts on it, so including one would be a zero-field
    # writeConfig("security") for no reason -- exactly the write firmware
    # issue #7449 (cited in this same warning) says can silently discard
    # the key this plan exists to preserve. See Round 35's plan-apply
    # review, Finding 3.
    assert not any(section.section == "security" for section in plan.sections)
    assert plan.key_plan.is_empty is False  # the run still has work to do
    assert plan.is_empty is False


def test_no_recorded_key_captures_the_devices_keypair(make_live, template, keypair) -> None:
    """A node with no recorded key and a valid live keypair gets it captured.

    Before the first-capture branch existed, this fell through to the old
    no-op ``else`` branch.
    """
    live = make_live(template, security=make_security(keypair=keypair))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FOREIGN,
        db_public_key=None,
    )
    plan = build_plan(inputs)

    assert plan.key_plan.adopt_device_key is True
    assert plan.key_plan.regenerate is False
    assert plan.key_plan.regenerate_reason == ""
    assert not any(section.section == "security" for section in plan.sections)
    assert plan.key_plan.is_empty is False


def test_first_capture_refuses_with_capture_reason_when_key_is_registered_elsewhere(
    make_live, template, keypair
) -> None:
    live = make_live(template, security=make_security(keypair=keypair))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FOREIGN,
        db_public_key=None,
        node_key_admin_refs=("ADMIN1_pub",),
    )

    with pytest.raises(AdminKeyRotationRefusedError) as excinfo:
        build_plan(inputs)

    assert excinfo.value.reason == "capture"
    assert excinfo.value.admin_refs == ("ADMIN1_pub",)
    assert "has no recorded key" in excinfo.value.message


# ---------------------------------------------------------------------------
# Admin-key rotation refusal (D1=B / D2): no flag overrides this.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind",
    [
        "forced",
        "factory",
        "missing_key_material",
        "node_key_compromised",
        "adopt",
        "pending_key_recovered",
    ],
)
def test_admin_key_rotation_refused_for_every_key_changing_branch(
    make_live, template, keypair, keypair_factory, kind: str
) -> None:
    """D2: every branch that changes the node's key refuses when it backs an admin ref.

    No flag exists to relax this -- see ``AdminKeyRotationRefusedError``'s
    docstring. ``"factory"`` is easy to miss: FACTORY is a regenerate
    branch too, and D2 says "always", not "every regenerate branch except
    FACTORY".
    """
    admin_refs = ("aaaa0001_pub",)

    if kind == "forced":
        live = make_live(template, node_id="aaaa0001", security=make_security(keypair=keypair))
        record = NodeRecord(
            node_id="aaaa0001", short_name=live.short_name, long_name=live.long_name
        )
        inputs = PlanInputs(
            live=live,
            template=template,
            db_entry=record,
            state=detect.NodeState.PROVISIONED,
            force_regenerate_key=True,
            node_key_admin_refs=admin_refs,
        )
        expected_reason = "forced"
    elif kind == "factory":
        live = make_live(template, node_id="aaaa0001", security=make_security(empty=True))
        inputs = PlanInputs(
            live=live,
            template=template,
            db_entry=None,
            state=detect.NodeState.FACTORY,
            node_key_admin_refs=admin_refs,
        )
        expected_reason = "factory_key_presumed_compromised"
    elif kind == "missing_key_material":
        live = make_live(template, node_id="aaaa0001", security=make_security(empty=True))
        record = NodeRecord(
            node_id="aaaa0001", short_name=live.short_name, long_name=live.long_name
        )
        inputs = PlanInputs(
            live=live,
            template=template,
            db_entry=record,
            state=detect.NodeState.PROVISIONED,
            node_key_admin_refs=admin_refs,
        )
        expected_reason = "missing_key_material"
    elif kind == "node_key_compromised":
        live = make_live(template, node_id="aaaa0001", security=make_security(keypair=keypair))
        record = NodeRecord(
            node_id="aaaa0001", short_name=live.short_name, long_name=live.long_name
        )
        inputs = PlanInputs(
            live=live,
            template=template,
            db_entry=record,
            state=detect.NodeState.PROVISIONED,
            node_key_compromised=True,
            node_key_reason="node_key_compromised",
            node_key_admin_refs=admin_refs,
        )
        expected_reason = "node_key_compromised"
    elif kind == "adopt":
        other = keypair_factory()
        live = make_live(template, node_id="aaaa0001", security=make_security(keypair=keypair))
        record = NodeRecord(
            node_id="aaaa0001", short_name=live.short_name, long_name=live.long_name
        )
        inputs = PlanInputs(
            live=live,
            template=template,
            db_entry=record,
            state=detect.NodeState.PROVISIONED,
            db_public_key=other.public,
            node_key_admin_refs=admin_refs,
        )
        expected_reason = "adopt"
    else:
        assert kind == "pending_key_recovered"
        live = make_live(template, node_id="aaaa0001", security=make_security(keypair=keypair))
        record = NodeRecord(
            node_id="aaaa0001", short_name=live.short_name, long_name=live.long_name
        )
        inputs = PlanInputs(
            live=live,
            template=template,
            db_entry=record,
            state=detect.NodeState.PROVISIONED,
            pending_keypair_recovered=True,
            node_key_admin_refs=admin_refs,
        )
        expected_reason = "pending_key_recovered"

    with pytest.raises(AdminKeyRotationRefusedError) as excinfo:
        build_plan(inputs)

    assert excinfo.value.reason == expected_reason
    assert excinfo.value.admin_refs == admin_refs


def test_admin_key_rotation_gate_is_a_no_op_without_admin_refs(
    make_live, template, keypair, keypair_factory
) -> None:
    """``node_key_admin_refs=()`` -- today's #7449 adopt accommodation is untouched.

    Guards against the gate becoming unconditional: an ordinary
    (non-admin-bearing) node's #7449 adopt must keep working exactly as
    before, with no raise.
    """
    other = keypair_factory()
    live = make_live(template, security=make_security(keypair=keypair))
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        db_public_key=other.public,
    )
    plan = build_plan(inputs)
    assert plan.key_plan.adopt_device_key is True
    assert any(w.code == "device_key_differs_from_db" for w in plan.warnings)


def test_packet_signature_policy_diffed_against_template(make_live, template, keypair) -> None:
    live = make_live(
        template,
        firmware_version="2.8.0",
        security=make_security(
            keypair=keypair, packet_signature_policy="PACKET_SIGNATURE_POLICY_COMPATIBLE"
        ),
    )
    opinionated_template = template.model_copy(
        update={
            "security": template.security.model_copy(
                update={"packet_signature_policy": "PACKET_SIGNATURE_POLICY_STRICT"}
            )
        }
    )
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    inputs = PlanInputs(
        live=live,
        template=opinionated_template,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
    )

    plan = build_plan(inputs)

    security = plan.section("security")
    assert security is not None
    change = next(c for c in security.changes if c.field == "packet_signature_policy")
    assert change.current == "PACKET_SIGNATURE_POLICY_COMPATIBLE"
    assert change.desired == "PACKET_SIGNATURE_POLICY_STRICT"
    assert change.reason == "template"
    assert all(w.code != PlanWarningCode.FIELD_UNSUPPORTED_BY_FIRMWARE for w in plan.warnings)


def _policy_plan(
    make_live, template, keypair, *, firmware_version: str, live_policy: str, desired_policy: str
) -> ChangePlan:
    """Build a PROVISIONED plan diffing ``packet_signature_policy`` on the given firmware."""
    live = make_live(
        template,
        firmware_version=firmware_version,
        security=make_security(keypair=keypair, packet_signature_policy=live_policy),
    )
    opinionated_template = template.model_copy(
        update={
            "security": template.security.model_copy(
                update={"packet_signature_policy": desired_policy}
            )
        }
    )
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    return build_plan(
        PlanInputs(
            live=live,
            template=opinionated_template,
            db_entry=record,
            state=detect.NodeState.PROVISIONED,
        )
    )


def _assert_policy_not_planned(plan: ChangePlan) -> None:
    security = plan.section("security")
    planned = {c.field for c in security.changes} if security is not None else set()
    assert "packet_signature_policy" not in planned


def test_packet_signature_policy_skipped_with_warning_on_pre_2_8_firmware(
    make_live, template, keypair
) -> None:
    """Pre-2.8 firmware drops the field, so the write could never verify.

    Planning it anyway left the node unrecordable (read-back mismatch on
    every run), so the change is dropped and surfaced as a warning.
    """
    plan = _policy_plan(
        make_live,
        template,
        keypair,
        firmware_version="2.7.15",
        live_policy="PACKET_SIGNATURE_POLICY_COMPATIBLE",
        desired_policy="PACKET_SIGNATURE_POLICY_STRICT",
    )

    _assert_policy_not_planned(plan)
    gated = [w for w in plan.warnings if w.code == PlanWarningCode.FIELD_UNSUPPORTED_BY_FIRMWARE]
    assert len(gated) == 1
    assert gated[0].section == "security"
    assert gated[0].field == "packet_signature_policy"
    assert "firmware '2.7.15' predates 2.8" in gated[0].message
    assert (
        "(PACKET_SIGNATURE_POLICY_COMPATIBLE -> PACKET_SIGNATURE_POLICY_STRICT)" in gated[0].message
    )


@pytest.mark.parametrize(
    ("firmware_version", "reason"),
    [
        ("", "the device reported no firmware version"),
        ("unknown", "firmware version 'unknown' could not be parsed"),
    ],
)
def test_packet_signature_policy_skipped_with_warning_when_firmware_version_unknown(
    make_live, template, keypair, firmware_version: str, reason: str
) -> None:
    plan = _policy_plan(
        make_live,
        template,
        keypair,
        firmware_version=firmware_version,
        live_policy="PACKET_SIGNATURE_POLICY_COMPATIBLE",
        desired_policy="PACKET_SIGNATURE_POLICY_BALANCED",
    )

    _assert_policy_not_planned(plan)
    gated = [w for w in plan.warnings if w.code == PlanWarningCode.FIELD_UNSUPPORTED_BY_FIRMWARE]
    assert len(gated) == 1
    assert reason in gated[0].message


def test_packet_signature_policy_matching_live_value_on_pre_2_8_firmware_is_silent(
    make_live, template, keypair
) -> None:
    """``COMPATIBLE`` is what pre-2.8 firmware always reads back: nothing to do, nothing to warn."""
    plan = _policy_plan(
        make_live,
        template,
        keypair,
        firmware_version="2.7.15",
        live_policy="PACKET_SIGNATURE_POLICY_COMPATIBLE",
        desired_policy="PACKET_SIGNATURE_POLICY_COMPATIBLE",
    )

    _assert_policy_not_planned(plan)
    assert all(w.code != PlanWarningCode.FIELD_UNSUPPORTED_BY_FIRMWARE for w in plan.warnings)


def test_packet_signature_policy_omitted_from_diff_when_template_leaves_it_none(
    make_live, template, keypair
) -> None:
    """``None`` (the default) must not generate a field change at all.

    Mirrors how ``serial_enabled``/``debug_log_api_enabled`` stay out of
    the diff entirely when the template doesn't set them -- even though
    the live device reports a concrete, non-default policy.
    """
    live = make_live(
        template,
        security=make_security(
            keypair=keypair, packet_signature_policy="PACKET_SIGNATURE_POLICY_STRICT"
        ),
    )
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    inputs = PlanInputs(
        live=live, template=template, db_entry=record, state=detect.NodeState.PROVISIONED
    )

    plan = build_plan(inputs)

    security = plan.section("security")
    if security is not None:
        assert all(c.field != "packet_signature_policy" for c in security.changes)
