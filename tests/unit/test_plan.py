"""Tests for meshprovision.provisioning.plan."""

from __future__ import annotations

import json

import pytest

from meshprovision.config.template import TemplateConfig, load_template_text
from meshprovision.db.nodes import NodeRecord
from meshprovision.errors import AdminKeyCapacityError, LockdownRefusedError
from meshprovision.provisioning import detect
from meshprovision.provisioning.plan import (
    SECTION_ORDER,
    PlanInputs,
    build_plan,
)
from tests.unit.conftest import make_security

pytestmark = pytest.mark.unit


@pytest.fixture
def template():
    return load_template_text("version: 1\n")


def _with_admin_and_lockdown(template: TemplateConfig, *refs: str) -> TemplateConfig:
    """Build a template variant with the given admin refs and ``is_managed=True``."""
    security = template.security.model_copy(update={"is_managed": True})
    return template.model_copy(update={"admin_nodes": tuple(refs), "security": security})


# ---------------------------------------------------------------------------
# Factory node.
# ---------------------------------------------------------------------------


def test_factory_node_plan(make_live, template) -> None:
    live = make_live(
        template, short_name="be01", long_name="Meshtastic be01", security=make_security(empty=True)
    )
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        ble_pin="012345",
    )
    plan = build_plan(inputs)

    assert plan.is_new is True
    assert plan.key_plan.regenerate is True
    assert plan.key_plan.regenerate_reason == "factory_key_presumed_compromised"
    assert plan.key_plan.adopt_device_key is False
    assert plan.ble_pin_set is True

    bluetooth = plan.section("bluetooth")
    assert bluetooth is not None
    pin_change = next(c for c in bluetooth.changes if c.field == "fixed_pin")
    assert pin_change.secret is True
    assert pin_change.describe() == "<redacted> -> <redacted>"
    assert pin_change.to_json_dict()["current"] == "<redacted>"
    assert pin_change.to_json_dict()["desired"] == "<redacted>"

    section_names = [s.section for s in plan.sections]
    expected_config_order = [s for s in SECTION_ORDER if s not in ("bluetooth", "security")]
    present_config = [s for s in section_names if s in expected_config_order]
    assert present_config == [s for s in expected_config_order if s in section_names]
    assert "security" not in section_names or section_names[-1] == "security"
    if "bluetooth" in section_names and "security" in section_names:
        assert section_names.index("bluetooth") < section_names.index("security")

    security_section = plan.section("security")
    assert security_section is not None
    assert security_section.reboots_device is True


def test_reboots_device_on_region_change(make_live, template) -> None:
    live = make_live(
        template,
        section_overrides={"lora": {"region": "US"}},
        security=make_security(empty=True),
        short_name="be01",
        long_name="Meshtastic be01",
    )
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    assert plan.reboots_device is True
    assert any(w.code == "region_change_reboots" for w in plan.warnings)


# ---------------------------------------------------------------------------
# Already-correct node.
# ---------------------------------------------------------------------------


def test_already_correct_node_plan_is_empty(make_live, template, keypair) -> None:
    live = make_live(template, security=make_security(keypair=keypair))
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        admin_keys=(),
        db_public_key=None,
    )
    plan = build_plan(inputs)

    assert plan.is_empty is True
    assert plan.sections == ()
    assert plan.key_plan.is_empty is True
    assert plan.warnings == ()
    assert plan.describe() == ()
    assert plan.summary() == "0 sections, 0 fields"


# ---------------------------------------------------------------------------
# Drift repair.
# ---------------------------------------------------------------------------


def test_drift_repair_targets_database_names(make_live, template, keypair) -> None:
    live = make_live(
        template,
        short_name="be01",
        long_name="Meshtastic be01",
        security=make_security(keypair=keypair),
        section_overrides={"device": {"role": "ROUTER"}, "lora": {"region": "US"}},
    )
    record = NodeRecord(
        node_id="deadbe01",
        short_name="MT99",
        long_name="Meshtastic MT99",
        role="CLIENT",
        region="EU_868",
    )
    inputs = PlanInputs(
        live=live, template=template, db_entry=record, state=detect.NodeState.PROVISIONED
    )
    plan = build_plan(inputs)

    assert plan.name_change.desired_short_name == "MT99"
    assert plan.name_change.desired_long_name == "Meshtastic MT99"

    device_section = plan.section("device")
    assert device_section is not None
    assert any(c.field == "role" for c in device_section.changes)

    lora_section = plan.section("lora")
    assert lora_section is not None
    assert any(c.field == "region" for c in lora_section.changes)

    assert plan.key_plan.regenerate is False


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


def test_admin_nodes_empty_never_strips_live_keys(make_live, template, keypair_factory) -> None:
    kp1, kp2 = keypair_factory(), keypair_factory()
    live = make_live(template, security=make_security(admin_keys=(kp1.public, kp2.public)))
    record = NodeRecord(node_id="deadbe01", authorized_admin_keys=("X_pub", "Y_pub"))
    inputs = PlanInputs(
        live=live, template=template, db_entry=record, state=detect.NodeState.PROVISIONED
    )
    plan = build_plan(inputs)

    assert plan.key_plan.desired_admin_keys == tuple(sorted((kp1.public, kp2.public))) or set(
        plan.key_plan.desired_admin_keys
    ) == {kp1.public, kp2.public}
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
    template2 = _with_admin_and_lockdown(template, "ADMIN1")
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
    template2 = _with_admin_and_lockdown(template, "WEAK", "GOOD")
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
    template2 = _with_admin_and_lockdown(template, "ADMIN1")
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
    template2 = _with_admin_and_lockdown(template, "ADMIN1")
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


# ---------------------------------------------------------------------------
# is_managed refusals.
# ---------------------------------------------------------------------------


def test_lockdown_no_admin_keys_refused(make_live, template) -> None:
    template2 = _with_admin_and_lockdown(template, "ADMIN1")
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live, template=template2, db_entry=None, state=detect.NodeState.FACTORY, admin_keys=()
    )
    with pytest.raises(LockdownRefusedError) as exc_info:
        build_plan(inputs)
    assert exc_info.value.reason == "no_admin_keys"


def test_lockdown_no_private_counterpart_refused(make_live, template, make_admin_key) -> None:
    admin = make_admin_key("ADMIN1", has_private=False)
    template2 = _with_admin_and_lockdown(template, "ADMIN1")
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
    template2 = _with_admin_and_lockdown(template, "ADMIN1")
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
    template2 = _with_admin_and_lockdown(template, "ADMIN1")
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
    template2 = _with_admin_and_lockdown(template, "ADMIN1")
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


def test_lockdown_authorized(make_live, template, make_admin_key) -> None:
    admin = make_admin_key("ADMIN1", has_private=True, audit_ok=True)
    template2 = _with_admin_and_lockdown(template, "ADMIN1")
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


def test_missing_key_material(make_live, template) -> None:
    live = make_live(template, security=make_security(empty=True))
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    inputs = PlanInputs(
        live=live, template=template, db_entry=record, state=detect.NodeState.PROVISIONED
    )
    plan = build_plan(inputs)
    assert plan.key_plan.regenerate is True
    assert plan.key_plan.regenerate_reason == "missing_key_material"


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


# ---------------------------------------------------------------------------
# Other.
# ---------------------------------------------------------------------------


def test_admin_channel_enabled_forced_false(make_live, template, keypair) -> None:
    live = make_live(template, security=make_security(keypair=keypair, admin_channel_enabled=True))
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    inputs = PlanInputs(
        live=live, template=template, db_entry=record, state=detect.NodeState.PROVISIONED
    )
    plan = build_plan(inputs)
    security = plan.section("security")
    assert security is not None
    change = next(c for c in security.changes if c.field == "admin_channel_enabled")
    assert change.desired is False
    assert change.reason == "forced"


def test_foreign_state_adds_warning(make_live, template, keypair) -> None:
    live = make_live(template, security=make_security(keypair=keypair))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FOREIGN)
    plan = build_plan(inputs)
    assert any(w.code == "foreign_node" for w in plan.warnings)


def test_over_long_desired_short_name_warns_not_raises(make_live, template, keypair) -> None:
    live = make_live(template, security=make_security(keypair=keypair))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.PROVISIONED,
        desired_short_name="TOOLONGNAME",
    )
    plan = build_plan(inputs)
    assert any(w.code == "name_truncation_risk" and w.field == "short_name" for w in plan.warnings)


def test_module_diffing_unknown_module_warns(make_live, template) -> None:
    template2 = template.model_copy(update={"enabled_options": ("totally_custom_thing",)})
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live, template=template2, db_entry=None, state=detect.NodeState.FACTORY
    )
    plan = build_plan(inputs)
    assert any(
        w.code == "unknown_module" and w.section == "totally_custom_thing" for w in plan.warnings
    )


def test_module_diffing_telemetry_has_no_enabled_field(make_live, template) -> None:
    template2 = template.model_copy(update={"enabled_options": ("telemetry",)})
    live = make_live(template2, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live, template=template2, db_entry=None, state=detect.NodeState.FACTORY
    )
    plan = build_plan(inputs)
    assert any(
        w.code == "module_has_no_enabled_field" and w.section == "telemetry" for w in plan.warnings
    )


def test_values_equal_bool_vs_int_and_float_tolerance() -> None:
    from meshprovision.provisioning.plan import values_equal

    assert values_equal(True, 1) is False
    assert values_equal(1.0000000001, 1.0) is True
    assert values_equal(1, 1) is True
    assert values_equal("a", "a") is True


def test_values_equal_string_never_coerced_to_float() -> None:
    from meshprovision.provisioning.plan import values_equal

    assert values_equal("1.5", 1.5) is False
    assert values_equal(1.5, "1.5") is False


# ---------------------------------------------------------------------------
# Determinism.
# ---------------------------------------------------------------------------


def test_determinism_byte_identical_json(make_live, template, keypair) -> None:
    live = make_live(
        template,
        short_name="OLD1",
        section_overrides={"device": {"role": "ROUTER"}},
        security=make_security(keypair=keypair),
    )
    record = NodeRecord(node_id="deadbe01", short_name="NEW1", long_name=live.long_name)
    inputs = PlanInputs(
        live=live, template=template, db_entry=record, state=detect.NodeState.PROVISIONED
    )
    plan1 = build_plan(inputs)
    plan2 = build_plan(inputs)
    assert json.dumps(plan1.to_json_dict(), sort_keys=False) == json.dumps(
        plan2.to_json_dict(), sort_keys=False
    )


# ---------------------------------------------------------------------------
# Redaction.
# ---------------------------------------------------------------------------


def test_plan_inputs_repr_redacts_secrets(make_live, template) -> None:
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        ble_pin="998877",
        db_public_key=b"x" * 32,
    )
    text = repr(inputs)
    assert "998877" not in text
    assert ("x" * 32) not in text
    assert "<redacted>" in text


def test_key_plan_repr_redacts_admin_keys() -> None:
    from meshprovision.provisioning.plan_admin_keys import KeyPlan

    kp = KeyPlan(desired_admin_keys=(b"\x01" * 32,))
    text = repr(kp)
    assert (b"\x01" * 32).hex() not in text
    assert "<redacted>" in text


def test_resolved_admin_key_repr_shows_fingerprint_only(make_admin_key) -> None:
    admin = make_admin_key("ADMIN1")
    text = repr(admin)
    assert admin.public.hex() not in text
    assert admin.fingerprint in text


# ---------------------------------------------------------------------------
# to_record.
# ---------------------------------------------------------------------------


def test_to_record_builds_new_node_when_db_entry_none(make_live, template, keypair) -> None:
    live = make_live(template, security=make_security(keypair=keypair))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    record = plan.to_record()
    assert record.node_id == "deadbe01"
    assert record.hw_model == live.hw_model
    assert record.firmware_version == live.firmware_version
    assert record.role == template.device.role
    assert record.region == template.lora.region


def test_to_record_sets_ble_pin_only_when_set(make_live, template) -> None:
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        ble_pin="098765",
    )
    plan = build_plan(inputs)
    record = plan.to_record()
    assert record.ble_pin is not None
    assert record.ble_pin.get_secret_value() == "098765"


def test_to_record_never_clears_admin_keys_when_desired_empty(make_live, template, keypair) -> None:
    live = make_live(template, security=make_security(keypair=keypair))
    record = NodeRecord(
        node_id="deadbe01",
        short_name=live.short_name,
        long_name=live.long_name,
        authorized_admin_keys=("PRE_pub",),
    )
    inputs = PlanInputs(
        live=live, template=template, db_entry=record, state=detect.NodeState.PROVISIONED
    )
    plan = build_plan(inputs)
    new_record = plan.to_record()
    assert new_record.authorized_admin_keys == ("PRE_pub",)
