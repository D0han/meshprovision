"""Tests for build_plan's admin-key planning (meshprovision.provisioning.plan_admin_keys)."""

from __future__ import annotations

import json

import pytest

from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import ManagementMode
from meshprovision.errors import (
    AdminKeyCapacityError,
    LockdownRefusedError,
)
from meshprovision.provisioning import detect
from meshprovision.provisioning.plan import (
    PlanInputs,
    build_plan,
)
from tests.unit.conftest import make_security, with_admin_and_lockdown

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Admin keys 0/1/2/3.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("n", [0, 1, 2, 3])
def test_admin_keys_valid_counts(make_live, template, make_admin_key, n: int) -> None:
    refs = ["ADMIN1", "ADMIN2", "ADMIN3"][:n]
    template2 = template.model_copy(update={"admin_nodes": tuple(refs)})
    admin_keys = tuple(make_admin_key(ref) for ref in refs)

    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=admin_keys,
    )
    plan = build_plan(inputs)

    if n == 0:
        assert plan.key_plan.change_admin_keys is False
        assert plan.key_plan.desired_admin_keys == ()
        assert plan.key_plan.desired_admin_key_refs == ()
        assert not any(w.code == "live_admin_key_rejected" for w in plan.warnings)
    else:
        assert plan.key_plan.desired_admin_keys == tuple(k.public for k in admin_keys)
        assert plan.key_plan.desired_admin_key_refs == tuple(f"{r}_pub" for r in refs)
        assert plan.key_plan.change_admin_keys is True
        record = plan.to_record()
        assert record.authorized_admin_keys == tuple(f"{r}_pub" for r in refs)


def test_to_record_keeps_recorded_hw_model_when_live_reports_unmapped(make_live, template) -> None:
    """Regression test for Round 35's weakkey-drift review, Finding 2.

    live.hw_model == "" paired with hw_model_raw means the device
    reported a model this build's enum table doesn't recognize -- not
    "no hardware model" -- so to_record must not erase an already-
    recorded value with it.
    """
    live = make_live(
        template, security=make_security(empty=True), hw_model="", hw_model_raw="FUTURE_BOARD_9000"
    )
    record = NodeRecord(
        node_id="deadbe01",
        short_name=live.short_name,
        long_name=live.long_name,
        hw_model="RAK4631",
    )
    inputs = PlanInputs(
        live=live, template=template, db_entry=record, state=detect.NodeState.PROVISIONED
    )
    plan = build_plan(inputs)

    assert plan.to_record().hw_model == "RAK4631"


def test_to_record_keeps_recorded_firmware_and_hw_model_when_live_reports_neither(
    make_live, template
) -> None:
    """Regression test for Round 37 Aspect 1 Finding 9.

    A blank live firmware_version (detect.py's no-metadata sentinel) and a
    blank hw_model with hw_model_raw=None (also no metadata, distinct from
    the unrecognized-enum case above) must both be treated as "no new
    information," not persisted over an already-recorded value.
    """
    live = make_live(
        template,
        security=make_security(empty=True),
        hw_model="",
        hw_model_raw=None,
        firmware_version="",
    )
    record = NodeRecord(
        node_id="deadbe01",
        short_name=live.short_name,
        long_name=live.long_name,
        hw_model="HELTEC_V3",
        firmware_version="2.7.1",
    )
    inputs = PlanInputs(
        live=live, template=template, db_entry=record, state=detect.NodeState.PROVISIONED
    )
    plan = build_plan(inputs)

    to_record = plan.to_record()
    assert to_record.hw_model == "HELTEC_V3"
    assert to_record.firmware_version == "2.7.1"


def test_admin_nodes_empty_never_strips_live_keys(make_live, template, keypair_factory) -> None:
    kp1, kp2 = keypair_factory(), keypair_factory()
    live = make_live(template, security=make_security(admin_keys=(kp1.public, kp2.public)))
    record = NodeRecord(node_id="deadbe01", authorized_admin_keys=("X_pub", "Y_pub"))
    inputs = PlanInputs(
        live=live, template=template, db_entry=record, state=detect.NodeState.PROVISIONED
    )
    plan = build_plan(inputs)

    assert plan.key_plan.desired_admin_keys == (kp1.public, kp2.public)
    assert plan.key_plan.change_admin_keys is False
    to_record = plan.to_record()
    assert to_record.authorized_admin_keys == ("X_pub", "Y_pub")


def test_admin_key_ordering_difference_is_not_drift(make_live, template, make_admin_key) -> None:
    admin1 = make_admin_key("ADMIN1")
    admin2 = make_admin_key("ADMIN2")
    template2 = template.model_copy(update={"admin_nodes": ("ADMIN1", "ADMIN2")})
    live = make_live(template2, security=make_security(admin_keys=(admin2.public, admin1.public)))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin1, admin2),
    )
    plan = build_plan(inputs)
    assert plan.key_plan.change_admin_keys is False


# ---------------------------------------------------------------------------
# Live admin keys absent from a non-empty template.admin_nodes (revocation).
# ---------------------------------------------------------------------------


def test_live_admin_key_absent_from_template_is_revoked_with_warning(
    make_live, template, make_admin_key, keypair_factory
) -> None:
    admin1 = make_admin_key("ADMIN1")
    friend = keypair_factory()
    template2 = template.model_copy(update={"admin_nodes": ("ADMIN1",)})
    live = make_live(template2, security=make_security(admin_keys=(admin1.public, friend.public)))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin1,),
    )
    plan = build_plan(inputs)

    assert plan.key_plan.revoked_admin_fingerprints == ("live-admin[1]",)
    assert any(w.code == "live_admin_key_revoked" for w in plan.warnings)
    assert (
        "security.admin_key: revoke [live-admin[1]] (not in template.admin_nodes)"
        in plan.describe()
    )
    document = json.loads(json.dumps(plan.to_json_dict()))
    assert document["key_plan"]["revoked_admin_fingerprints"] == ["live-admin[1]"]


def test_live_admin_key_named_in_template_is_not_revoked(
    make_live, template, make_admin_key
) -> None:
    admin1 = make_admin_key("ADMIN1")
    template2 = template.model_copy(update={"admin_nodes": ("ADMIN1",)})
    live = make_live(template2, security=make_security(admin_keys=(admin1.public,)))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin1,),
    )
    plan = build_plan(inputs)

    assert plan.key_plan.revoked_admin_fingerprints == ()
    assert not any(w.code == "live_admin_key_revoked" for w in plan.warnings)


def test_weak_key_removal_does_not_also_count_as_revoked(
    make_live, template, make_admin_key, keypair_factory
) -> None:
    admin1 = make_admin_key("ADMIN1")
    weak = keypair_factory()
    other = keypair_factory()
    template2 = template.model_copy(update={"admin_nodes": ("ADMIN1",)})
    live = make_live(template2, security=make_security(admin_keys=(weak.public, other.public)))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin1,),
        rejected_admin_keys=frozenset({weak.public}),
    )
    plan = build_plan(inputs)

    assert plan.key_plan.removed_admin_fingerprints == ("live-admin[0]",)
    assert plan.key_plan.revoked_admin_fingerprints == ("live-admin[1]",)


def test_empty_admin_nodes_never_revokes_live_keys(make_live, template, keypair_factory) -> None:
    kp1, kp2 = keypair_factory(), keypair_factory()
    live = make_live(template, security=make_security(admin_keys=(kp1.public, kp2.public)))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)

    assert plan.key_plan.revoked_admin_fingerprints == ()
    assert not any(w.code == "live_admin_key_revoked" for w in plan.warnings)
    assert set(plan.key_plan.desired_admin_keys) == {kp1.public, kp2.public}


def test_rejected_admin_key_removed_with_positional_label(
    make_live, template, keypair_factory
) -> None:
    kp1, kp2 = keypair_factory(), keypair_factory()
    live = make_live(template, security=make_security(admin_keys=(kp1.public, kp2.public)))
    record = NodeRecord(node_id="deadbe01")
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        rejected_admin_keys=frozenset({kp1.public}),
    )
    plan = build_plan(inputs)
    assert plan.key_plan.removed_admin_fingerprints == ("live-admin[0]",)
    assert any(w.code == "live_admin_key_rejected" for w in plan.warnings)
    assert plan.key_plan.change_admin_keys is True


def test_revoked_live_key_ref_is_dropped_from_the_record(
    make_live, template, keypair_factory
) -> None:
    kp1, kp2 = keypair_factory(), keypair_factory()
    live = make_live(template, security=make_security(admin_keys=(kp1.public, kp2.public)))
    record = NodeRecord(node_id="deadbe01", authorized_admin_keys=("ADMIN1_pub", "ADMIN2_pub"))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        rejected_admin_keys=frozenset({kp1.public}),
        removed_admin_key_refs=("ADMIN1_pub",),
    )
    plan = build_plan(inputs)

    assert plan.key_plan.change_admin_keys is True
    assert plan.key_plan.removed_admin_fingerprints == ("live-admin[0]",)
    assert plan.key_plan.desired_admin_key_refs == ()
    assert plan.key_plan.rejected_admin_key_refs == ()
    assert plan.to_record().authorized_admin_keys == ("ADMIN2_pub",)


def test_named_admin_refs_win_over_removed_refs(make_live, template, make_admin_key) -> None:
    admin1 = make_admin_key("ADMIN1")
    template2 = template.model_copy(update={"admin_nodes": ("ADMIN1",)})
    live = make_live(template2, security=make_security(empty=True))
    record = NodeRecord(node_id="deadbe01", authorized_admin_keys=("OLD_pub",))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        admin_keys=(admin1,),
        removed_admin_key_refs=("OLD_pub",),
    )
    plan = build_plan(inputs)

    assert plan.key_plan.desired_admin_key_refs == ("ADMIN1_pub",)
    assert plan.to_record().authorized_admin_keys == ("ADMIN1_pub",)


def test_removing_every_recorded_ref_empties_the_record(
    make_live, template, keypair_factory
) -> None:
    kp1 = keypair_factory()
    live = make_live(template, security=make_security(admin_keys=(kp1.public,)))
    record = NodeRecord(node_id="deadbe01", authorized_admin_keys=("ADMIN1_pub",))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        rejected_admin_keys=frozenset({kp1.public}),
        removed_admin_key_refs=("ADMIN1_pub",),
    )
    plan = build_plan(inputs)

    assert plan.to_record().authorized_admin_keys == ()


def test_removed_ref_absent_from_baseline_is_a_no_op(make_live, template, keypair_factory) -> None:
    kp1 = keypair_factory()
    live = make_live(template, security=make_security(admin_keys=(kp1.public,)))
    record = NodeRecord(node_id="deadbe01", authorized_admin_keys=("ADMIN1_pub",))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        rejected_admin_keys=frozenset({kp1.public}),
        removed_admin_key_refs=("ADMIN1_pub",),
    )
    plan = build_plan(inputs)

    other = NodeRecord(node_id="deadbe01", authorized_admin_keys=("OTHER_pub",))
    assert plan.to_record(existing=other).authorized_admin_keys == ("OTHER_pub",)


def test_removed_admin_key_refs_surface_in_json_and_repr(
    make_live, template, keypair_factory
) -> None:
    kp1 = keypair_factory()
    live = make_live(template, security=make_security(admin_keys=(kp1.public,)))
    record = NodeRecord(node_id="deadbe01", authorized_admin_keys=("ADMIN1_pub",))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        rejected_admin_keys=frozenset({kp1.public}),
        removed_admin_key_refs=("ADMIN1_pub",),
    )
    plan = build_plan(inputs)

    key_plan_json = plan.to_json_dict()["key_plan"]
    assert isinstance(key_plan_json, dict)
    assert key_plan_json["removed_admin_key_refs"] == ["ADMIN1_pub"]
    assert "removed_admin_key_refs=('ADMIN1_pub',)" in repr(plan.key_plan)


def test_admin_key_capacity_exceeded_raises(make_live, template, make_admin_key) -> None:
    refs = ["ADMIN1", "ADMIN2", "ADMIN3", "ADMIN4"]
    admin_keys = tuple(make_admin_key(ref) for ref in refs)
    template2 = template.model_copy(update={"admin_nodes": ("ADMIN1", "ADMIN2", "ADMIN3")})
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=admin_keys,
    )
    with pytest.raises(AdminKeyCapacityError):
        build_plan(inputs)


# ---------------------------------------------------------------------------
# Resolved admin keys that fail the weak-key audit.
# ---------------------------------------------------------------------------


def test_weak_resolved_admin_key_is_never_authorized_without_lockdown(
    make_live, template, make_admin_key
) -> None:
    admin = make_admin_key("ADMIN1", audit_ok=False, audit_summary="small_order: known bad point")
    template2 = template.model_copy(update={"admin_nodes": ("ADMIN1",)})
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin,),
    )
    plan = build_plan(inputs)

    assert plan.key_plan.desired_admin_keys == ()
    assert plan.key_plan.desired_admin_key_refs == ()
    assert plan.key_plan.rejected_admin_key_refs == ("ADMIN1_pub",)

    rejections = [w for w in plan.warnings if w.code == "resolved_admin_key_rejected"]
    assert len(rejections) == 1
    assert "ADMIN1_pub" in rejections[0].message
    assert "small_order: known bad point" in rejections[0].message
    assert "security.admin_key: refuse [ADMIN1_pub] (weak-key audit)" in plan.describe()
    document = json.loads(json.dumps(plan.to_json_dict()))
    assert document["key_plan"]["rejected_admin_key_refs"] == ["ADMIN1_pub"]


def test_weak_resolved_admin_key_partially_filters_keys_and_refs_in_lockstep(
    make_live, template, make_admin_key
) -> None:
    weak = make_admin_key("WEAK", audit_ok=False)
    good = make_admin_key("GOOD", audit_ok=True)
    template2 = template.model_copy(update={"admin_nodes": ("WEAK", "GOOD")})
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(weak, good),
    )
    plan = build_plan(inputs)

    assert plan.key_plan.desired_admin_keys == (good.public,)
    assert plan.key_plan.desired_admin_key_refs == ("GOOD_pub",)
    assert plan.key_plan.rejected_admin_key_refs == ("WEAK_pub",)
    assert plan.key_plan.change_admin_keys is True

    rejections = [w for w in plan.warnings if w.code == "resolved_admin_key_rejected"]
    assert len(rejections) == 1
    assert "WEAK_pub" in rejections[0].message


def test_all_weak_resolved_admin_keys_under_lockdown_report_weak_not_empty(
    make_live, template, make_admin_key
) -> None:
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
    assert "ADMIN1_pub" in str(exc_info.value)


def test_partially_weak_resolved_admin_keys_under_lockdown_name_only_the_weak_ref(
    make_live, template, make_admin_key
) -> None:
    weak = make_admin_key("WEAK", audit_ok=False)
    good = make_admin_key("GOOD", audit_ok=True)
    template2 = with_admin_and_lockdown(template, "WEAK", "GOOD")
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(weak, good),
    )
    with pytest.raises(LockdownRefusedError) as exc_info:
        build_plan(inputs)
    assert exc_info.value.reason == "weak_admin_key"
    message = str(exc_info.value)
    assert "WEAK_pub" in message
    assert "GOOD_pub" not in message
    assert message.count("WEAK_pub") == 1


def test_weak_admin_key_outranks_private_key_mismatch(make_live, template, make_admin_key) -> None:
    admin = make_admin_key("ADMIN1", audit_ok=False, has_private=False, private_mismatch=True)
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


def test_to_record_clears_admin_keys_when_every_ref_was_rejected(
    make_live, template, make_admin_key, keypair
) -> None:
    admin = make_admin_key("ADMIN1", audit_ok=False)
    template2 = template.model_copy(update={"admin_nodes": ("ADMIN1",)})
    live = make_live(template2, security=make_security(keypair=keypair))
    record = NodeRecord(
        node_id="deadbe01",
        short_name=live.short_name,
        long_name=live.long_name,
        authorized_admin_keys=("ADMIN1_pub",),
    )
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        admin_keys=(admin,),
    )
    new_record = build_plan(inputs).to_record()
    assert new_record.authorized_admin_keys == ()


def test_to_record_graduates_an_observed_node_to_template_management(
    make_live, template, keypair
) -> None:
    live = make_live(template, security=make_security(keypair=keypair))
    record = NodeRecord(
        node_id="deadbe01",
        short_name=live.short_name,
        long_name=live.long_name,
        management=ManagementMode.OBSERVED,
    )
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        admin_keys=(),
        db_public_key=None,
    )
    new_record = build_plan(inputs).to_record()
    assert new_record.management is ManagementMode.TEMPLATE


def test_to_record_leaves_an_already_template_node_as_template(
    make_live, template, keypair
) -> None:
    live = make_live(template, security=make_security(keypair=keypair))
    record = NodeRecord(
        node_id="deadbe01",
        short_name=live.short_name,
        long_name=live.long_name,
        management=ManagementMode.TEMPLATE,
    )
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        admin_keys=(),
        db_public_key=None,
    )
    new_record = build_plan(inputs).to_record()
    assert new_record.management is ManagementMode.TEMPLATE


def test_admin_key_capacity_counts_keys_before_the_audit_filter(
    make_live, template, make_admin_key
) -> None:
    from meshprovision.errors import MAX_ADMIN_KEYS

    refs = [f"ADMIN{i}" for i in range(MAX_ADMIN_KEYS + 1)]
    admin_keys = tuple(make_admin_key(ref, audit_ok=(i != 0)) for i, ref in enumerate(refs))
    template2 = template.model_copy(update={"admin_nodes": tuple(refs[:MAX_ADMIN_KEYS])})
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=admin_keys,
    )
    with pytest.raises(AdminKeyCapacityError) as exc_info:
        build_plan(inputs)
    assert exc_info.value.count == MAX_ADMIN_KEYS + 1


def test_live_weak_admin_key_is_both_removed_and_refused(
    make_live, template, make_admin_key, keypair_factory
) -> None:
    compromised = keypair_factory()
    admin = make_admin_key("ADMIN1", public=compromised.public, audit_ok=False)
    template2 = template.model_copy(update={"admin_nodes": ("ADMIN1",)})
    live = make_live(template2, security=make_security(admin_keys=(compromised.public,)))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=NodeRecord(node_id="deadbe01"),
        state=detect.NodeState.PROVISIONED,
        admin_keys=(admin,),
        rejected_admin_keys=frozenset({compromised.public}),
    )
    plan = build_plan(inputs)

    assert plan.key_plan.removed_admin_fingerprints == ("live-admin[0]",)
    assert plan.key_plan.rejected_admin_key_refs == ("ADMIN1_pub",)
    assert plan.key_plan.desired_admin_keys == ()
    assert plan.key_plan.change_admin_keys is True
    codes = {w.code for w in plan.warnings}
    assert {"live_admin_key_rejected", "resolved_admin_key_rejected"} <= codes


# ---------------------------------------------------------------------------
# --allow-weak-admin-key: overriding the resolved-admin-key audit.
# ---------------------------------------------------------------------------


def test_allow_weak_admin_key_on_a_live_weak_key_reports_no_removal(
    make_live, template, make_admin_key, keypair_factory
) -> None:
    compromised = keypair_factory()
    admin = make_admin_key("ADMIN1", public=compromised.public, audit_ok=False)
    template2 = template.model_copy(update={"admin_nodes": ("ADMIN1",)})
    live = make_live(template2, security=make_security(admin_keys=(compromised.public,)))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=NodeRecord(node_id="deadbe01"),
        state=detect.NodeState.PROVISIONED,
        admin_keys=(admin,),
        rejected_admin_keys=frozenset({compromised.public}),
        allow_weak_admin_key=True,
    )
    plan = build_plan(inputs)

    assert plan.key_plan.change_admin_keys is False
    assert plan.key_plan.removed_admin_fingerprints == ()
    assert plan.key_plan.revoked_admin_fingerprints == ()
    assert plan.key_plan.desired_admin_keys == (compromised.public,)
    codes = {w.code for w in plan.warnings}
    assert "live_admin_key_rejected" not in codes
    assert "resolved_admin_key_forced" in codes
    assert not any("will be removed" in warning.message for warning in plan.warnings)
    assert not any("security.admin_key" in line for line in plan.describe())


def test_allow_weak_admin_key_authorizes_the_weak_key_without_lockdown(
    make_live, template, make_admin_key
) -> None:
    admin = make_admin_key("ADMIN1", audit_ok=False, audit_summary="small_order: known bad point")
    template2 = template.model_copy(update={"admin_nodes": ("ADMIN1",)})
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin,),
        allow_weak_admin_key=True,
    )
    plan = build_plan(inputs)

    assert plan.key_plan.desired_admin_keys == (admin.public,)
    assert plan.key_plan.desired_admin_key_refs == ("ADMIN1_pub",)
    assert plan.key_plan.rejected_admin_key_refs == ()

    forced = [w for w in plan.warnings if w.code == "resolved_admin_key_forced"]
    assert len(forced) == 1
    assert "ADMIN1_pub" in forced[0].message
    assert "small_order: known bad point" in forced[0].message
    assert not [w for w in plan.warnings if w.code == "resolved_admin_key_rejected"]


def test_allow_weak_admin_key_does_not_relax_the_lockdown_gate(
    make_live, template, make_admin_key
) -> None:
    admin = make_admin_key("ADMIN1", audit_ok=False)
    template2 = with_admin_and_lockdown(template, "ADMIN1")
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin,),
        allow_weak_admin_key=True,
    )
    with pytest.raises(LockdownRefusedError) as exc_info:
        build_plan(inputs)
    assert exc_info.value.reason == "weak_admin_key"
    assert "ADMIN1_pub" in str(exc_info.value)


def test_allow_weak_admin_key_defaults_to_false_and_still_rejects(
    make_live, template, make_admin_key
) -> None:
    admin = make_admin_key("ADMIN1", audit_ok=False)
    template2 = template.model_copy(update={"admin_nodes": ("ADMIN1",)})
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin,),
    )
    assert inputs.allow_weak_admin_key is False
    plan = build_plan(inputs)

    assert plan.key_plan.desired_admin_key_refs == ()
    assert plan.key_plan.rejected_admin_key_refs == ("ADMIN1_pub",)
    assert [w.code for w in plan.warnings if w.code.startswith("resolved_admin_key")] == [
        "resolved_admin_key_rejected"
    ]


def test_allow_weak_admin_key_forces_only_the_weak_key_of_a_mixed_set(
    make_live, template, make_admin_key
) -> None:
    weak = make_admin_key("WEAK", audit_ok=False)
    good = make_admin_key("GOOD", audit_ok=True)
    template2 = template.model_copy(update={"admin_nodes": ("WEAK", "GOOD")})
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(weak, good),
        allow_weak_admin_key=True,
    )
    plan = build_plan(inputs)

    assert plan.key_plan.desired_admin_keys == (weak.public, good.public)
    assert plan.key_plan.desired_admin_key_refs == ("WEAK_pub", "GOOD_pub")
    assert plan.key_plan.rejected_admin_key_refs == ()

    forced = [w for w in plan.warnings if w.code == "resolved_admin_key_forced"]
    assert len(forced) == 1
    assert "WEAK_pub" in forced[0].message
    assert "GOOD_pub" not in forced[0].message


def test_allow_weak_admin_key_never_authorizes_a_non_overridable_weak_key(
    make_live, template, make_admin_key
) -> None:
    """ALL_ZERO/SMALL_ORDER stay rejected under --allow-weak-admin-key (S4/D4).

    Unlike a merely heuristic-weak key, a structurally degenerate key
    (audit_overridable=False) is not authorized by the flag: it goes to
    rejected_admin_key_refs with a resolved_admin_key_rejected warning,
    never resolved_admin_key_forced.
    """
    admin = make_admin_key(
        "ADMIN1",
        audit_ok=False,
        audit_overridable=False,
        audit_summary="small_order: known bad point",
    )
    template2 = template.model_copy(update={"admin_nodes": ("ADMIN1",)})
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin,),
        allow_weak_admin_key=True,
    )
    plan = build_plan(inputs)

    assert plan.key_plan.desired_admin_keys == ()
    assert plan.key_plan.desired_admin_key_refs == ()
    assert plan.key_plan.rejected_admin_key_refs == ("ADMIN1_pub",)

    codes = [w.code for w in plan.warnings if w.code.startswith("resolved_admin_key")]
    assert codes == ["resolved_admin_key_rejected"]
    rejection = next(w for w in plan.warnings if w.code == "resolved_admin_key_rejected")
    assert "ADMIN1_pub" in rejection.message
    assert "cannot override" in rejection.message


def test_allow_weak_admin_key_forces_the_overridable_key_but_not_the_non_overridable_one(
    make_live, template, make_admin_key
) -> None:
    """A mixed set under the flag: BLOCKLIST-only is forced, SMALL_ORDER-shaped stays refused."""
    overridable = make_admin_key("BLOCKLISTED", audit_ok=False, audit_overridable=True)
    non_overridable = make_admin_key("DEGENERATE", audit_ok=False, audit_overridable=False)
    good = make_admin_key("GOOD", audit_ok=True)
    template2 = template.model_copy(update={"admin_nodes": ("BLOCKLISTED", "DEGENERATE", "GOOD")})
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(overridable, non_overridable, good),
        allow_weak_admin_key=True,
    )
    plan = build_plan(inputs)

    assert set(plan.key_plan.desired_admin_key_refs) == {"BLOCKLISTED_pub", "GOOD_pub"}
    assert plan.key_plan.rejected_admin_key_refs == ("DEGENERATE_pub",)

    forced = [w for w in plan.warnings if w.code == "resolved_admin_key_forced"]
    assert len(forced) == 1
    assert "BLOCKLISTED_pub" in forced[0].message

    rejected = [w for w in plan.warnings if w.code == "resolved_admin_key_rejected"]
    assert len(rejected) == 1
    assert "DEGENERATE_pub" in rejected[0].message
