"""Tests for meshprovision.provisioning.plan_firmware and how the plan uses it."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from meshprovision.config.template import TemplateConfig, load_template_text
from meshprovision.errors import PlanConflictError
from meshprovision.provisioning import detect, plan_firmware
from meshprovision.provisioning.detect import LiveChannel
from meshprovision.provisioning.plan import (
    ChangePlan,
    FieldChange,
    PlanInputs,
    PlanWarningCode,
    build_plan,
)
from tests.unit.conftest import live_config_from_template, make_security

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[2]
_CONFIGURATION = (_ROOT / "docs" / "configuration.md").read_text(encoding="utf-8")
_EXAMPLE = (_ROOT / "src" / "meshprovision" / "examples" / "template.example.yaml").read_text(
    encoding="utf-8"
)

_DEFAULT_PRIMARY = LiveChannel(index=0, default_key=True, position_precision=12)
"""A stock LongFast primary: the default key, no name, sharing a position."""

_PRIVATE_PRIMARY = LiveChannel(index=0, name="ours", position_precision=12)

_FIRMWARE_2_8 = "2.8.3.51ac6ea"


def _template(body: str) -> TemplateConfig:
    return load_template_text("version: 1\n" + body)


def _plan(
    template: TemplateConfig,
    *,
    channels: tuple[LiveChannel, ...] = (_DEFAULT_PRIMARY,),
    sections: dict[str, dict[str, object]] | None = None,
    firmware: str = _FIRMWARE_2_8,
) -> ChangePlan:
    live = live_config_from_template(
        template,
        firmware_version=firmware,
        security=make_security(),
        section_overrides=sections,
        channels=channels,
    )
    return build_plan(PlanInputs(live=live, template=template, state=detect.NodeState.PROVISIONED))


def _boot_warnings(plan: ChangePlan) -> list[tuple[str | None, str | None]]:
    return [
        (w.section, w.field)
        for w in plan.warnings
        if w.code == PlanWarningCode.INTERVAL_RAISED_AT_BOOT
    ]


def _change(plan: ChangePlan, section: str, field: str) -> FieldChange:
    change = plan.section(section)
    assert change is not None
    return next(c for c in change.changes if c.field == field)


def test_a_low_position_interval_on_a_default_channel_plans_the_template_value() -> None:
    template = _template("position:\n  position_broadcast_secs: 900\n")

    plan = _plan(template, sections={"position": {"position_broadcast_secs": 7200}})

    change = _change(plan, "position", "position_broadcast_secs")
    assert (change.desired, change.firmware_value) == (900, 3600)
    assert _boot_warnings(plan) == [("position", "position_broadcast_secs")]
    assert "position.position_broadcast_secs: 7200 -> 900 (the firmware holds 3600)" in (
        plan.describe()
    )
    assert change.to_json_dict()["firmware_value"] == 3600


def test_a_node_already_at_the_boot_minimum_needs_no_change_but_still_warns() -> None:
    template = _template("position:\n  position_broadcast_secs: 900\n")

    plan = _plan(template, sections={"position": {"position_broadcast_secs": 3600}})

    assert plan.section("position") is None
    assert _boot_warnings(plan) == [("position", "position_broadcast_secs")]


def test_a_private_channel_raises_nothing() -> None:
    template = _template("position:\n  position_broadcast_secs: 900\n")

    plan = _plan(
        template,
        channels=(_PRIVATE_PRIMARY,),
        sections={"position": {"position_broadcast_secs": 3600}},
    )

    change = _change(plan, "position", "position_broadcast_secs")
    assert change.firmware_value is None
    assert _boot_warnings(plan) == []


def test_a_router_gets_the_router_minimums() -> None:
    template = _template(
        "device:\n  role: ROUTER\nposition:\n  position_broadcast_secs: 900\n"
        "telemetry:\n  device_update_interval: 600\n"
    )

    adjustments = plan_firmware.firmware_adjustments(
        PlanInputs(
            live=live_config_from_template(template, channels=(_DEFAULT_PRIMARY,)),
            template=template,
        )
    )

    assert {(a.section, a.field): a.value for a in adjustments} == {
        ("position", "position_broadcast_secs"): 43200,
        ("telemetry", "device_update_interval"): 43200,
    }


def test_zero_is_the_firmware_default_and_is_never_raised() -> None:
    template = _template(
        "position:\n  position_broadcast_secs: 0\n  broadcast_smart_minimum_interval_secs: 0\n"
        "telemetry:\n  device_update_interval: 0\n"
    )

    assert _boot_warnings(_plan(template)) == []


def test_a_default_secondary_raises_telemetry_but_not_the_position_interval() -> None:
    template = _template(
        "position:\n  position_broadcast_secs: 900\ntelemetry:\n  environment_update_interval: 60\n"
    )

    plan = _plan(template, channels=(_PRIVATE_PRIMARY, LiveChannel(index=1, default_key=True)))

    assert _boot_warnings(plan) == [("telemetry", "environment_update_interval")]


def test_the_first_channel_sharing_a_position_decides_the_position_minimum() -> None:
    template = _template("position:\n  broadcast_smart_minimum_interval_secs: 60\n")
    unshared_primary = LiveChannel(index=0, name="ours")
    shared_default = LiveChannel(index=1, default_key=True, position_precision=13)

    plan = _plan(template, channels=(unshared_primary, shared_default))

    assert _boot_warnings(plan) == [("position", "broadcast_smart_minimum_interval_secs")]


def test_a_primary_sharing_no_position_before_or_after_raises_no_position_minimum() -> None:
    template = _template(
        "position:\n  position_broadcast_secs: 900\ndefault_channel:\n  position_precision: 0\n"
    )

    plan = _plan(template, channels=(LiveChannel(index=0, default_key=True),))

    assert _boot_warnings(plan) == []


@pytest.mark.parametrize(
    ("preset", "expected"),
    [
        pytest.param("LONG_FAST", [("telemetry", "device_update_interval")], id="its-preset"),
        pytest.param("MEDIUM_FAST", [], id="another-preset"),
    ],
)
def test_a_channel_named_after_a_preset_is_default_only_on_that_preset(
    preset: str, expected: list[tuple[str, str]]
) -> None:
    template = _template(
        f"lora:\n  modem_preset: {preset}\ntelemetry:\n  device_update_interval: 600\n"
    )
    named = LiveChannel(index=0, name="LongFast", default_key=True)

    assert _boot_warnings(_plan(template, channels=(named,))) == expected


@pytest.mark.parametrize(
    ("lora", "firmware", "raised"),
    [
        pytest.param({"channel_num": 5}, _FIRMWARE_2_8, False, id="channel-num-2.8"),
        pytest.param({"channel_num": 5}, "2.7.26.54e0d8d", True, id="channel-num-2.7"),
        pytest.param({"channel_num": 5}, "", True, id="channel-num-unknown"),
        pytest.param({"override_frequency": 869.5}, _FIRMWARE_2_8, False, id="override-2.8"),
        pytest.param({"override_frequency": 869.5}, "2.7.26", False, id="override-2.7.26"),
        pytest.param({"override_frequency": 869.5}, "2.7.19", True, id="override-2.7.19"),
    ],
)
def test_the_telemetry_minimum_follows_each_firmwares_boot_check(
    lora: dict[str, object], firmware: str, raised: bool
) -> None:
    template = _template("telemetry:\n  device_update_interval: 600\n")

    warnings = _boot_warnings(_plan(template, sections={"lora": lora}, firmware=firmware))

    assert warnings == ([("telemetry", "device_update_interval")] if raised else [])


def test_a_primary_that_stops_sharing_after_the_commit_still_counts_as_sharing() -> None:
    template = _template(
        "position:\n  position_broadcast_secs: 900\ndefault_channel:\n  position_precision: 0\n"
    )
    live = live_config_from_template(
        template,
        firmware_version=_FIRMWARE_2_8,
        section_overrides={"position": {"position_broadcast_secs": 7200}},
        default_channel_overrides={"position_precision": 12},
        channels=(_DEFAULT_PRIMARY,),
    )

    plan = build_plan(PlanInputs(live=live, template=template, state=detect.NodeState.PROVISIONED))

    assert _change(plan, "position", "position_broadcast_secs").firmware_value == 3600


def test_the_example_template_is_above_every_boot_minimum() -> None:
    template = load_template_text(_EXAMPLE)

    assert _boot_warnings(_plan(template)) == []


def test_the_boot_check_firmware_floors() -> None:
    assert (
        plan_firmware.BOOT_SLOT_CHECK_MIN_FIRMWARE,
        plan_firmware.BOOT_PRESET_CHECK_MIN_FIRMWARE,
    ) == ((2, 8, 0), (2, 7, 20))


def test_the_boot_minimums() -> None:
    assert (1800, 43200, 3600, 43200, 300, frozenset({"ROUTER", "ROUTER_LATE"})) == (
        plan_firmware.TELEMETRY_INTERVAL_FLOOR_SECS,
        plan_firmware.TELEMETRY_INTERVAL_FLOOR_ROUTER_SECS,
        plan_firmware.POSITION_BROADCAST_FLOOR_SECS,
        plan_firmware.POSITION_BROADCAST_FLOOR_ROUTER_SECS,
        plan_firmware.SMART_MINIMUM_INTERVAL_FLOOR_SECS,
        plan_firmware.BOOT_FLOOR_ROUTER_ROLES,
    )


def test_the_repeater_firmware_floor() -> None:
    assert plan_firmware.REPEATER_REPLACED_MIN_FIRMWARE == (2, 7, 11)


def test_the_known_only_firmware_floor() -> None:
    assert plan_firmware.KNOWN_ONLY_DROPS_LOCAL_ADMIN_MIN_FIRMWARE == (2, 8, 0)


def _flat(text: str) -> str:
    return " ".join(text.split())


@pytest.mark.parametrize(
    "phrase",
    [
        pytest.param(
            f"telemetry interval below {plan_firmware.TELEMETRY_INTERVAL_FLOOR_SECS} s "
            f"({plan_firmware.TELEMETRY_INTERVAL_FLOOR_ROUTER_SECS} s",
            id="telemetry",
        ),
        pytest.param(
            f"`position_broadcast_secs` below {plan_firmware.POSITION_BROADCAST_FLOOR_SECS} s "
            f"({plan_firmware.POSITION_BROADCAST_FLOOR_ROUTER_SECS} s",
            id="position",
        ),
        pytest.param(
            f"`broadcast_smart_minimum_interval_secs` below "
            f"{plan_firmware.SMART_MINIMUM_INTERVAL_FLOOR_SECS} s",
            id="smart-minimum",
        ),
        pytest.param(
            "`REPEATER` only on firmware before "
            + ".".join(str(part) for part in plan_firmware.REPEATER_REPLACED_MIN_FIRMWARE),
            id="repeater",
        ),
        pytest.param(
            "`KNOWN_ONLY` only on firmware before "
            + ".".join(
                str(part) for part in plan_firmware.KNOWN_ONLY_DROPS_LOCAL_ADMIN_MIN_FIRMWARE
            ),
            id="known-only",
        ),
        pytest.param(f'"never" ({plan_firmware.MAX_INTERVAL_SECS} s)', id="never"),
        pytest.param(
            f"keeps at most {plan_firmware.PUBLIC_CHANNEL_MAX_POSITION_PRECISION} bits "
            "(about 700 m)",
            id="public-precision",
        ),
    ],
)
def test_the_configuration_docs_state_each_boot_minimum(phrase: str) -> None:
    pattern = r"(?<![0-9A-Za-z.])" + re.escape(_flat(phrase)) + r"(?![0-9])"

    assert len(re.findall(pattern, _flat(_CONFIGURATION))) == 1


@pytest.mark.parametrize(
    ("firmware", "refused"),
    [
        pytest.param("2.7.10.94d4bdf", False, id="older"),
        pytest.param("2.7.11.ee68575", True, id="first-replacing"),
        pytest.param("2.8.2.4c89b69", True, id="newer"),
        pytest.param("", True, id="unknown"),
    ],
)
def test_a_repeater_role_is_refused_where_the_firmware_replaces_it(
    firmware: str, refused: bool
) -> None:
    template = _template("device:\n  role: REPEATER\n")
    live = live_config_from_template(
        template, firmware_version=firmware, section_overrides={"device": {"role": "CLIENT"}}
    )
    inputs = PlanInputs(live=live, template=template, state=detect.NodeState.PROVISIONED)

    if refused:
        with pytest.raises(PlanConflictError, match=r"store_forward\.is_server") as exc_info:
            build_plan(inputs)
        assert exc_info.value.field == "device.role"
    else:
        assert _change(build_plan(inputs), "device", "role").desired == "REPEATER"


def test_a_repeater_role_already_on_the_device_is_not_written_and_not_refused() -> None:
    template = _template("device:\n  role: REPEATER\n")
    live = live_config_from_template(template, firmware_version="2.8.2")

    plan = build_plan(PlanInputs(live=live, template=template, state=detect.NodeState.PROVISIONED))

    assert plan.section("device") is None


def _known_only_warned(plan: ChangePlan) -> bool:
    return PlanWarningCode.KNOWN_ONLY_IGNORES_CLIENT in [w.code for w in plan.warnings]


@pytest.mark.parametrize(
    ("firmware", "refused"),
    [
        pytest.param("2.7.26.54e0d8d", False, id="older"),
        pytest.param("2.8.0.47db0e3", True, id="first-dropping"),
        pytest.param("2.8.3.51ac6ea", True, id="newer"),
        pytest.param("", True, id="unknown"),
    ],
)
def test_a_known_only_mode_is_refused_where_the_firmware_ignores_the_client(
    firmware: str, refused: bool
) -> None:
    template = _template("device:\n  rebroadcast_mode: KNOWN_ONLY\n")
    live = live_config_from_template(
        template,
        firmware_version=firmware,
        section_overrides={"device": {"rebroadcast_mode": "ALL"}},
    )
    inputs = PlanInputs(live=live, template=template, state=detect.NodeState.PROVISIONED)

    if refused:
        with pytest.raises(PlanConflictError, match="KNOWN_ONLY") as exc_info:
            build_plan(inputs)
        assert exc_info.value.field == "device.rebroadcast_mode"
    else:
        plan = build_plan(inputs)
        assert _change(plan, "device", "rebroadcast_mode").desired == "KNOWN_ONLY"
        assert _known_only_warned(plan)


def test_a_known_only_mode_already_on_older_firmware_is_not_written_but_warned() -> None:
    template = _template("device:\n  rebroadcast_mode: KNOWN_ONLY\n")
    live = live_config_from_template(template, firmware_version="2.7.26.54e0d8d")

    plan = build_plan(PlanInputs(live=live, template=template, state=detect.NodeState.PROVISIONED))

    assert plan.section("device") is None
    assert _known_only_warned(plan)


def test_another_rebroadcast_mode_gets_no_known_only_warning() -> None:
    template = _template("device:\n  rebroadcast_mode: LOCAL_ONLY\n")
    live = live_config_from_template(
        template,
        firmware_version="2.7.26.54e0d8d",
        section_overrides={"device": {"rebroadcast_mode": "ALL"}},
    )

    plan = build_plan(PlanInputs(live=live, template=template, state=detect.NodeState.PROVISIONED))

    assert not _known_only_warned(plan)


@pytest.mark.parametrize(
    ("live_region", "ignore_mqtt", "warned"),
    [
        pytest.param("US", "false", True, id="region-change"),
        pytest.param("EU_868", "false", False, id="same-region"),
        pytest.param("US", "true", False, id="template-wants-true"),
    ],
)
def test_a_region_change_warns_that_the_firmware_sets_ignore_mqtt(
    live_region: str, ignore_mqtt: str, warned: bool
) -> None:
    template = _template(f"lora:\n  region: EU_868\n  ignore_mqtt: {ignore_mqtt}\n")

    plan = _plan(template, sections={"lora": {"region": live_region, "ignore_mqtt": True}})

    codes = [w.code for w in plan.warnings]
    assert (PlanWarningCode.REGION_CHANGE_SETS_IGNORE_MQTT in codes) is warned
    lora = plan.section("lora")
    planned = {c.field for c in lora.changes} if lora is not None else set()
    # The firmware sets true itself on this run; the next run writes false.
    assert ("ignore_mqtt" in planned) is (live_region == "EU_868" and ignore_mqtt == "false")


def _role_warning(plan: ChangePlan) -> str | None:
    return next(
        (w.message for w in plan.warnings if w.code == PlanWarningCode.ROLE_DEFAULTS_REWRITE),
        None,
    )


@pytest.mark.parametrize(
    ("role", "named"),
    [
        pytest.param("ROUTER", ("device.rebroadcast_mode", "is_unmessagable"), id="router"),
        pytest.param(
            "ROUTER",
            ("power.ls_secs", "power.wait_bluetooth_secs", "display.screen_on_secs"),
            id="router-power-display",
        ),
        pytest.param("CLIENT_HIDDEN", ("device.node_info_broadcast_secs",), id="client-hidden"),
        pytest.param(
            "CLIENT_HIDDEN",
            ("device.rebroadcast_mode (to LOCAL_ONLY)", "neighbor_info.update_interval"),
            id="client-hidden-local-only",
        ),
    ],
)
def test_a_role_change_warns_what_the_role_defaults_reset(role: str, named: tuple[str]) -> None:
    template = _template(f"device:\n  role: {role}\n")

    message = _role_warning(_plan(template, sections={"device": {"role": "CLIENT"}}))

    assert message is not None
    assert all(name in message for name in named)


def test_no_role_change_no_role_warning() -> None:
    assert _role_warning(_plan(_template("device:\n  role: ROUTER\n"))) is None


def test_a_role_change_accepts_the_role_default_over_this_runs_device_fields() -> None:
    template = _template("device:\n  role: ROUTER\n  rebroadcast_mode: ALL\n")

    plan = _plan(
        template, sections={"device": {"role": "CLIENT", "rebroadcast_mode": "LOCAL_ONLY"}}
    )

    change = _change(plan, "device", "rebroadcast_mode")
    assert (change.desired, change.firmware_value) == ("ALL", "CORE_PORTNUMS_ONLY")
    assert _change(plan, "device", "role").firmware_value is None


@pytest.mark.parametrize(
    ("live", "desired", "firmware"),
    [
        pytest.param(None, False, True, id="unreported"),
        pytest.param(True, True, True, id="already-as-the-role-sets"),
    ],
)
def test_a_role_change_to_router_accepts_the_firmwares_is_unmessagable(
    live: bool | None, desired: bool, firmware: bool | None
) -> None:
    template = _template("is_unmessagable: false\ndevice:\n  role: ROUTER\n")
    live_config = live_config_from_template(
        template, is_unmessagable=live, section_overrides={"device": {"role": "CLIENT"}}
    )

    plan = build_plan(
        PlanInputs(live=live_config, template=template, state=detect.NodeState.PROVISIONED)
    )

    name = plan.name_change
    assert (name.desired_is_unmessagable, name.firmware_is_unmessagable) == (desired, firmware)
    assert name.is_unmessagable_changed is (live is None)


_PUBLIC_PRIMARY = LiveChannel(index=0, default_key=True, position_precision=12, public_key=True)


@pytest.mark.parametrize(
    ("channel", "firmware", "capped"),
    [
        pytest.param(_PUBLIC_PRIMARY, "2.8.2.4c89b69", True, id="public-2.8"),
        pytest.param(_PUBLIC_PRIMARY, "", True, id="public-unknown-firmware"),
        pytest.param(_PUBLIC_PRIMARY, "2.7.26.54e0d8d", False, id="public-2.7"),
        pytest.param(_PRIVATE_PRIMARY, "2.8.2.4c89b69", False, id="private"),
    ],
)
def test_a_precise_position_on_a_public_primary_is_capped(
    channel: LiveChannel, firmware: str, capped: bool
) -> None:
    template = _template("default_channel:\n  position_precision: 16\n")
    live = live_config_from_template(
        template,
        firmware_version=firmware,
        default_channel_overrides={"position_precision": 12},
        channels=(channel,),
    )

    plan = build_plan(PlanInputs(live=live, template=template, state=detect.NodeState.PROVISIONED))

    change = _change(plan, "default_channel", "position_precision")
    assert change.firmware_value == (15 if capped else None)
    codes = [w.code for w in plan.warnings]
    assert (PlanWarningCode.POSITION_PRECISION_CAPPED in codes) is capped


def test_a_precision_at_the_cap_is_kept_and_not_warned_about() -> None:
    template = _template("default_channel:\n  position_precision: 15\n")
    live = live_config_from_template(
        template,
        firmware_version="2.8.2",
        default_channel_overrides={"position_precision": 12},
        channels=(_PUBLIC_PRIMARY,),
    )

    plan = build_plan(PlanInputs(live=live, template=template, state=detect.NodeState.PROVISIONED))

    assert _change(plan, "default_channel", "position_precision").firmware_value is None
    assert PlanWarningCode.POSITION_PRECISION_CAPPED not in [w.code for w in plan.warnings]


def test_a_public_primary_already_at_the_cap_needs_no_channel_write() -> None:
    template = _template("default_channel:\n  position_precision: 16\n")
    live = live_config_from_template(
        template,
        firmware_version="2.8.2",
        default_channel_overrides={"position_precision": 15},
        channels=(_PUBLIC_PRIMARY,),
    )

    plan = build_plan(PlanInputs(live=live, template=template, state=detect.NodeState.PROVISIONED))

    assert plan.section("default_channel") is None


def test_the_public_channel_precision_cap() -> None:
    assert (
        plan_firmware.PUBLIC_CHANNEL_MAX_POSITION_PRECISION,
        plan_firmware.POSITION_PRECISION_CLAMP_MIN_FIRMWARE,
    ) == (15, (2, 8, 0))
