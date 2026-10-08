"""Tests for meshprovision.provisioning.plan."""

from __future__ import annotations

import json

import pytest

from meshprovision.db.nodes import NodeRecord
from meshprovision.provisioning import detect
from meshprovision.provisioning.plan import (
    SECTION_ORDER,
    ChangePlan,
    FieldChange,
    PlanInputs,
    PlanWarningCode,
    build_plan,
)
from tests.unit.conftest import make_security

pytestmark = pytest.mark.unit


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
    expected_config_order = [
        s for s in SECTION_ORDER if s not in ("bluetooth", "default_channel", "security")
    ]
    present_config = [s for s in section_names if s in expected_config_order]
    assert present_config == [s for s in expected_config_order if s in section_names]
    assert section_names[-1] == "security"
    assert section_names.index("bluetooth") < section_names.index("security")

    security_section = plan.section("security")
    assert security_section is not None
    assert security_section.reboots_device is True


@pytest.mark.parametrize(
    ("live_enabled", "expected"),
    [(False, (False, True)), (True, None)],
    ids=["bluetooth-off", "bluetooth-on"],
)
def test_ble_pin_plan_turns_bluetooth_on(
    make_live, template, live_enabled: bool, expected: tuple[bool, bool] | None
) -> None:
    """A fixed PIN is useless on a radio whose Bluetooth stays off."""
    live = make_live(
        template,
        section_overrides={
            "bluetooth": {"enabled": live_enabled, "mode": "FIXED_PIN", "fixed_pin": 12345}
        },
    )
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        ble_pin="012345",
    )

    bluetooth = build_plan(inputs).section("bluetooth")

    changes = bluetooth.changes if bluetooth is not None else ()
    enabled = {(c.current, c.desired) for c in changes if c.field == "enabled"}
    assert enabled == ({expected} if expected is not None else set())


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


def test_non_reboot_lora_field_change_does_not_claim_reboot(make_live, template) -> None:
    """A lora field outside {region, modem_preset} must not spuriously reboot.

    Only region/modem_preset changes reboot the device -- e.g. hop_limit
    must not set reboots_device.
    """
    live = make_live(
        template,
        section_overrides={"lora": {"hop_limit": 5}},
        security=make_security(empty=True),
        short_name="be01",
        long_name="Meshtastic be01",
    )
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)

    lora_section = plan.section("lora")
    assert lora_section is not None
    assert any(c.field == "hop_limit" for c in lora_section.changes)
    assert lora_section.reboots_device is False
    assert not any(w.code == "region_change_reboots" for w in plan.warnings)


def test_position_section_normal_field_is_diffed(make_live, template) -> None:
    """A changed position field is diffed normally, with no field skipped.

    ``position.fixed_latitude``/``fixed_longitude``/``fixed_altitude`` no
    longer exist on the template model at all (rejected at load time by
    ``PositionSection``'s before-validator), so ``_diff_section`` has no
    fixed-position skip left to exercise -- this only pins that an
    ordinary position field still gets diffed.
    """
    template2 = template.model_copy(
        update={
            "position": template.position.model_copy(
                update={
                    "position_broadcast_secs": 900,
                    "fixed_position": True,
                }
            )
        }
    )
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live, template=template2, db_entry=None, state=detect.NodeState.FACTORY
    )
    plan = build_plan(inputs)

    position_section = plan.section("position")
    assert position_section is not None
    fields = {c.field for c in position_section.changes}
    assert "position_broadcast_secs" in fields


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
        db_public_key=keypair.public,
    )
    plan = build_plan(inputs)

    assert plan.is_empty is True
    assert plan.sections == ()
    assert plan.key_plan.is_empty is True
    assert plan.warnings == ()
    assert plan.describe() == ()
    assert plan.summary() == "0 sections, 0 fields"


# ---------------------------------------------------------------------------
# is_unmessagable / is_licensed.
# ---------------------------------------------------------------------------


def test_is_unmessagable_from_template_wins_over_live(make_live, template) -> None:
    live = make_live(template, is_unmessagable=False, security=make_security(empty=True))
    template2 = template.model_copy(update={"is_unmessagable": True})
    inputs = PlanInputs(
        live=live, template=template2, db_entry=None, state=detect.NodeState.FACTORY
    )
    plan = build_plan(inputs)

    assert plan.name_change.current_is_unmessagable is False
    assert plan.name_change.desired_is_unmessagable is True
    assert plan.name_change.is_unmessagable_changed is True


def test_is_unmessagable_none_in_template_falls_back_to_live(make_live, template) -> None:
    live = make_live(template, is_unmessagable=True, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)

    assert plan.name_change.current_is_unmessagable is True
    assert plan.name_change.desired_is_unmessagable is True
    assert plan.name_change.is_unmessagable_changed is False


def test_is_licensed_always_echoed_from_live_with_no_template_control(make_live, template) -> None:
    live = make_live(template, is_licensed=True, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)

    assert plan.name_change.current_is_licensed is True
    assert plan.name_change.desired_is_licensed is True


def _is_unmessagable_only_plan(make_live, template, keypair) -> ChangePlan:
    """Build a PROVISIONED plan whose only change is ``is_unmessagable`` False -> True."""
    live = make_live(template, is_unmessagable=False, security=make_security(keypair=keypair))
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    inputs = PlanInputs(
        live=live,
        template=template.model_copy(update={"is_unmessagable": True}),
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        admin_keys=(),
        db_public_key=keypair.public,
    )
    return build_plan(inputs)


def test_is_unmessagable_only_plan_is_previewed_in_describe_and_summary(
    make_live, template, keypair
) -> None:
    """A flag-only owner change is non-empty, so ``--dry-run`` must show it.

    Previously ``describe()`` was empty and ``summary()`` read "0 sections,
    0 fields" for a plan that still issues ``setOwner`` and reboots.
    """
    plan = _is_unmessagable_only_plan(make_live, template, keypair)

    assert plan.is_empty is False
    assert plan.sections == ()
    assert plan.describe() == ("owner.is_unmessagable: False -> True",)
    assert plan.summary() == "0 sections, 0 fields, owner: 1 field"


def test_is_unmessagable_change_is_in_the_json_plan(make_live, template, keypair) -> None:
    plan = _is_unmessagable_only_plan(make_live, template, keypair)

    name_change = plan.to_json_dict()["name_change"]

    assert isinstance(name_change, dict)
    assert name_change["current_is_unmessagable"] is False
    assert name_change["desired_is_unmessagable"] is True


def test_summary_owner_count_includes_name_changes(make_live, template, keypair) -> None:
    """Names and the flag share the owner phase, so one count covers all three."""
    live = make_live(template, is_unmessagable=False, security=make_security(keypair=keypair))
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    inputs = PlanInputs(
        live=live,
        template=template.model_copy(update={"is_unmessagable": True}),
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        admin_keys=(),
        db_public_key=keypair.public,
        desired_short_name="MT99",
    )

    plan = build_plan(inputs)

    assert plan.summary() == "0 sections, 0 fields, owner: 2 fields"


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


def test_serial_and_debug_log_api_enabled_diffed_against_template(
    make_live, template, keypair
) -> None:
    """template.security.serial_enabled/debug_log_api_enabled must actually be diffed.

    Both fields default to None ("leave the device alone") and are never
    set to a concrete value anywhere else in this test suite, so the
    `if template_sec.serial_enabled is not None:` branches in
    plan_security.plan_security_section (and the matching apply.py verify-readback)
    had zero coverage before this test -- a field-name typo or a
    comparison bug in either path would have gone undetected end to end.
    """
    live = make_live(
        template,
        security=make_security(keypair=keypair, serial_enabled=False, debug_log_api_enabled=False),
    )
    opinionated_template = template.model_copy(
        update={
            "security": template.security.model_copy(
                update={"serial_enabled": True, "debug_log_api_enabled": True}
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
    serial_change = next(c for c in security.changes if c.field == "serial_enabled")
    assert serial_change.current is False
    assert serial_change.desired is True
    assert serial_change.reason == "template"
    debug_change = next(c for c in security.changes if c.field == "debug_log_api_enabled")
    assert debug_change.current is False
    assert debug_change.desired is True
    assert debug_change.reason == "template"


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


def test_telemetry_new_fields_are_diffed(make_live, template) -> None:
    template2 = template.model_copy(
        update={
            "telemetry": template.telemetry.model_copy(update={"device_telemetry_enabled": True})
        }
    )
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live, template=template2, db_entry=None, state=detect.NodeState.FACTORY
    )
    plan = build_plan(inputs)

    telemetry_section = plan.section("telemetry")
    assert telemetry_section is not None
    change = next(c for c in telemetry_section.changes if c.field == "device_telemetry_enabled")
    assert change.current is None
    assert change.desired is True


def test_neighbor_info_section_is_diffed_like_telemetry(make_live, template) -> None:
    template2 = template.model_copy(
        update={
            "neighbor_info": template.neighbor_info.model_copy(
                update={"enabled": True, "update_interval": 14400}
            )
        }
    )
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live, template=template2, db_entry=None, state=detect.NodeState.FACTORY
    )
    plan = build_plan(inputs)

    neighbor_info_section = plan.section("neighbor_info")
    assert neighbor_info_section is not None
    assert neighbor_info_section.kind == detect.SectionKind.MODULE_CONFIG
    fields = {c.field for c in neighbor_info_section.changes}
    assert fields == {"enabled", "update_interval"}


def test_default_channel_section_is_diffed(make_live, template) -> None:
    template2 = template.model_copy(
        update={
            "default_channel": template.default_channel.model_copy(
                update={"position_precision": 12, "is_muted": True}
            )
        }
    )
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live, template=template2, db_entry=None, state=detect.NodeState.FACTORY
    )
    plan = build_plan(inputs)

    section = plan.section("default_channel")
    assert section is not None
    assert section.kind == detect.SectionKind.CHANNEL
    fields = {c.field: c.desired for c in section.changes}
    assert fields == {"position_precision": 12, "is_muted": True}
    assert any(w.code == "default_channel_reboot_unknown" for w in plan.warnings)


def test_default_channel_section_no_change_when_already_matching(make_live, template) -> None:
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)

    assert plan.section("default_channel") is None
    assert not any(w.code == "default_channel_reboot_unknown" for w in plan.warnings)


def test_default_channel_section_sorts_before_security(make_live, make_admin_key, template) -> None:
    admin = make_admin_key("ADMIN1", has_private=True, audit_ok=True)
    template2 = template.model_copy(
        update={
            "admin_nodes": ("ADMIN1",),
            "default_channel": template.default_channel.model_copy(
                update={"position_precision": 12}
            ),
            "security": template.security.model_copy(update={"is_managed": True}),
        }
    )
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template2,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin,),
        allow_lockdown=True,
    )
    plan = build_plan(inputs)

    section_names = [s.section for s in plan.sections]
    assert "default_channel" in section_names
    assert section_names.index("default_channel") < section_names.index("security")
    assert section_names[-1] == "security"


_PRIMARY_CHANNEL_UNAVAILABLE_MESSAGE = (
    "default_channel not changed: the device reports no enabled primary channel (index 0), "
    "and a channel write would replace the whole channel. Enable the primary channel on the "
    "device, or remove default_channel from the template."
)


def test_default_channel_is_skipped_with_a_warning_when_no_primary_channel_is_enabled(
    make_live, template
) -> None:
    """A templated default_channel against an absent/DISABLED channel 0 is left out of the plan.

    Planned, it would only be refused by apply's pre-send check -- after
    every earlier section was already committed, and stopping the run
    before ``security``. Skipping it here keeps --dry-run, --json and the
    real run in agreement, and lets the rest of the plan apply.
    """
    template2 = template.model_copy(
        update={
            "default_channel": template.default_channel.model_copy(
                update={"position_precision": 13, "is_muted": False}
            )
        }
    )
    live = make_live(template, security=make_security(empty=True), primary_channel_enabled=False)
    inputs = PlanInputs(
        live=live, template=template2, db_entry=None, state=detect.NodeState.FACTORY
    )

    plan = build_plan(inputs)

    assert plan.section("default_channel") is None
    assert plan.section("security") is not None
    channel_warnings = [w for w in plan.warnings if w.section == "default_channel"]
    assert [(w.code, w.message) for w in channel_warnings] == [
        (PlanWarningCode.PRIMARY_CHANNEL_UNAVAILABLE, _PRIMARY_CHANNEL_UNAVAILABLE_MESSAGE)
    ]
    document = plan.to_json_dict()
    assert "default_channel" not in [s["section"] for s in document["sections"]]
    assert "primary_channel_unavailable" in [w["code"] for w in document["warnings"]]


def test_no_primary_channel_warning_when_the_template_sets_no_default_channel(
    make_live, template
) -> None:
    """A device without a primary channel is fine when the template doesn't touch it."""
    live = make_live(template, security=make_security(empty=True), primary_channel_enabled=False)
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)

    plan = build_plan(inputs)

    assert plan.section("default_channel") is None
    assert not any(w.section == "default_channel" for w in plan.warnings)


def test_values_equal_bool_vs_int_and_float_tolerance() -> None:
    from meshprovision.provisioning.plan import values_equal

    assert values_equal(True, 1) is False
    assert values_equal(1.0000000001, 1.0) is True
    assert values_equal(1, 1) is True
    assert values_equal("a", "a") is True


def test_values_equal_float_tolerance_boundary() -> None:
    """Pins down the abs_tol=1e-9 boundary.

    Within it (even near zero, where rel_tol alone would never match) is
    equal; meaningfully beyond it is not.
    """
    from meshprovision.provisioning.plan import values_equal

    assert values_equal(1.0, 1.001) is False
    # Near zero, rel_tol is powerless (relative to ~0); only abs_tol=1e-9
    # can make this pair equal.
    assert values_equal(0.0, 5e-10) is True
    assert values_equal(0.0, 5e-9) is False


def test_values_equal_string_never_coerced_to_float() -> None:
    from meshprovision.provisioning.plan import values_equal

    assert values_equal("1.5", 1.5) is False
    assert values_equal(1.5, "1.5") is False


def test_values_equal_tolerates_protobuf_float32_quantization() -> None:
    """A value round-tripped through a real protobuf ``TYPE_FLOAT`` field.

    ``power.adc_multiplier_override``/``lora.frequency_offset`` are 32-bit
    protobuf floats, so a device can only ever report float32 precision --
    4.9 comes back as 4.900000095367432. The old rel_tol=1e-9 rejected
    this as a mismatch, which meant the write always verified UNCONFIRMED
    and the database was never updated. See Round 35's plan-apply review.
    """
    from meshtastic.protobuf import config_pb2

    from meshprovision.provisioning.plan import values_equal

    power = config_pb2.Config.PowerConfig()
    power.adc_multiplier_override = 4.9
    quantized = power.adc_multiplier_override
    assert quantized != 4.9  # sanity: the quantization is real, not a no-op

    assert values_equal(quantized, 4.9) is True
    # A genuine mismatch at the same magnitude must still be rejected.
    assert values_equal(quantized, 5.1) is False


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


def test_field_change_repr_redacts_secret() -> None:
    """A ``secret=True`` FieldChange's repr must never leak its raw value.

    Guards specifically against the BLE PIN FieldChange -- a regression
    dropping this redaction would leak a raw PIN into any log line or
    traceback that reprs a FieldChange, with no test failure to catch it.
    """
    change = FieldChange(
        section="bluetooth", field="fixed_pin", current=0, desired=998877, secret=True
    )
    text = repr(change)
    assert "998877" not in text
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
