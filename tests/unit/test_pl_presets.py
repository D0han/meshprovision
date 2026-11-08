"""The seven EU_868 presets a Polish mesh uses, end to end through template, plan and health."""

from __future__ import annotations

import pytest

from meshprovision.config.template import load_template_text
from meshprovision.health.rules import PRESET_AIRTIME_MS
from meshprovision.provisioning import detect
from meshprovision.provisioning.detect import LiveChannel
from meshprovision.provisioning.plan import ChangePlan, PlanInputs, PlanWarningCode, build_plan
from meshprovision.provisioning.plan_firmware import PRESET_CHANNEL_NAMES
from tests.unit.conftest import live_config_from_template, make_security

pytestmark = pytest.mark.unit

PL_PRESETS = (
    "LONG_FAST",
    "LONG_MODERATE",
    "LONG_SLOW",
    "MEDIUM_SLOW",
    "MEDIUM_FAST",
    "SHORT_SLOW",
    "SHORT_FAST",
)

FIRMWARES = ("2.6.13.0561f2c", "2.7.26.54e0d8d", "2.8.3.51ac6ea")


def _plan(preset: str, firmware: str, live_preset: str, channel_name: str = "") -> ChangePlan:
    template = load_template_text(
        f"version: 1\nlora:\n  region: EU_868\n  modem_preset: {preset}\n"
        "telemetry:\n  device_update_interval: 600\n"
    )
    live = live_config_from_template(
        template,
        firmware_version=firmware,
        security=make_security(),
        section_overrides={"lora": {"modem_preset": live_preset}},
        channels=(LiveChannel(index=0, name=channel_name, default_key=True),),
    )
    return build_plan(PlanInputs(live=live, template=template, state=detect.NodeState.PROVISIONED))


@pytest.mark.parametrize("firmware", FIRMWARES)
@pytest.mark.parametrize("preset", PL_PRESETS)
def test_each_pl_preset_is_planned_on_every_supported_firmware(preset: str, firmware: str) -> None:
    other = "MEDIUM_FAST" if preset == "LONG_FAST" else "LONG_FAST"

    plan = _plan(preset, firmware, live_preset=other)

    lora = plan.section("lora")
    assert lora is not None
    assert [(c.field, c.current, c.desired) for c in lora.changes] == [
        ("modem_preset", other, preset)
    ]
    assert lora.reboots_device is (not firmware.startswith("2.8"))
    (moved,) = [w for w in plan.warnings if w.code == PlanWarningCode.REGION_CHANGE_REBOOTS]
    assert moved.message.startswith("Changing lora.modem_preset moves the radio")


@pytest.mark.parametrize("preset", PL_PRESETS)
def test_a_primary_named_after_each_pl_preset_is_a_default_channel(preset: str) -> None:
    plan = _plan(
        preset, "2.8.3.51ac6ea", live_preset=preset, channel_name=PRESET_CHANNEL_NAMES[preset]
    )

    assert [(w.section, w.field) for w in plan.warnings if w.code == "interval_raised_at_boot"] == [
        ("telemetry", "device_update_interval")
    ]


@pytest.mark.parametrize("preset", PL_PRESETS)
def test_each_pl_preset_has_a_health_airtime(preset: str) -> None:
    assert PRESET_AIRTIME_MS[preset] > 0
