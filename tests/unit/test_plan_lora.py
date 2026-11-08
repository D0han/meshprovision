"""Tests for meshprovision.provisioning.plan_lora and how the plan uses it."""

from __future__ import annotations

import pytest

from meshprovision.config.template import TemplateConfig, load_template_text
from meshprovision.errors import PlanConflictError
from meshprovision.provisioning import detect, plan_lora
from meshprovision.provisioning.detect import LiveChannel
from meshprovision.provisioning.plan import ChangePlan, PlanInputs, build_plan
from tests.unit.conftest import live_config_from_template, make_security

pytestmark = pytest.mark.unit

_DEFAULT_PRIMARY = LiveChannel(index=0, default_key=True, position_precision=12)

_FIRMWARE_2_8 = "2.8.3.51ac6ea"


def _template(body: str) -> TemplateConfig:
    return load_template_text("version: 1\n" + body)


def _plan(
    template: TemplateConfig,
    *,
    sections: dict[str, dict[str, object]] | None = None,
    firmware: str = _FIRMWARE_2_8,
) -> ChangePlan:
    live = live_config_from_template(
        template,
        firmware_version=firmware,
        security=make_security(),
        section_overrides=sections,
        channels=(_DEFAULT_PRIMARY,),
    )
    return build_plan(PlanInputs(live=live, template=template, state=detect.NodeState.PROVISIONED))


_WRITES_LORA = {"lora": {"hop_limit": 5}}
"""A live ``lora`` section that differs from every template here, so the plan writes it."""

_CUSTOM = {"bandwidth": 125, "spread_factor": 11, "coding_rate": 5}
"""A node's own radio parameters, set in the Meshtastic app."""


@pytest.mark.parametrize(
    ("lora", "firmware"),
    [
        pytest.param(
            "region: EU_866\n  modem_preset: LITE_FAST", "2.7.26.54e0d8d", id="EU_866-2.7"
        ),
        pytest.param("region: EU_N_868\n  modem_preset: NARROW_SLOW", "", id="EU_N_868-unknown"),
        pytest.param("region: ANZ_433", "2.6.13.0561f2c", id="ANZ_433-2.6"),
        pytest.param("region: KZ_863", "2.7.0.705515a", id="KZ_863-2.7.0"),
        pytest.param("region: BR_902", "2.7.3.cf574c7", id="BR_902-2.7.3"),
    ],
)
def test_a_region_without_a_frequency_plan_on_this_firmware_is_refused(
    lora: str, firmware: str
) -> None:
    template = _template(f"lora:\n  {lora}\n")

    with pytest.raises(PlanConflictError, match=r"transmits on 902-928 MHz") as exc_info:
        _plan(template, sections=_WRITES_LORA, firmware=firmware)

    assert exc_info.value.field == "lora.region"
    assert f"this device reports {firmware or 'no firmware version'}" in str(exc_info.value)


def test_a_region_newer_firmware_dropped_is_refused_there() -> None:
    template = _template("lora:\n  region: UA_868\n")

    with pytest.raises(PlanConflictError, match=r"firmware 2\.8\.0 and later have no") as exc_info:
        _plan(template, sections=_WRITES_LORA)

    assert exc_info.value.field == "lora.region"
    assert _plan(template, sections=_WRITES_LORA, firmware="2.7.26.54e0d8d").section("lora")


@pytest.mark.parametrize(
    ("lora", "firmware"),
    [
        pytest.param("region: EU_866\n  modem_preset: LITE_FAST", "2.8.0.47db0e3", id="EU_866-2.8"),
        pytest.param("region: ANZ_433", "2.7.0.195b7cc", id="ANZ_433-2.7.0"),
        pytest.param("region: BR_902", "2.7.4.c1f4f79", id="BR_902-2.7.4"),
        pytest.param("region: EU_868", "", id="EU_868-unknown"),
    ],
)
def test_a_region_this_firmware_has_a_plan_for_is_planned(lora: str, firmware: str) -> None:
    template = _template(f"lora:\n  {lora}\n")

    assert _plan(template, sections=_WRITES_LORA, firmware=firmware).section("lora") is not None


@pytest.mark.parametrize(
    ("preset", "firmware", "refused"),
    [
        pytest.param("LONG_TURBO", "2.7.16.a597230", True, id="long-turbo-2.7.16"),
        pytest.param("LONG_TURBO", "2.7.17.83c6161", False, id="long-turbo-2.7.17"),
        pytest.param("MEDIUM_TURBO", "2.7.26.54e0d8d", True, id="medium-turbo-2.7"),
        pytest.param("MEDIUM_TURBO", "2.8.0.47db0e3", False, id="medium-turbo-2.8"),
        pytest.param("MEDIUM_TURBO", "", True, id="medium-turbo-unknown"),
        pytest.param("SHORT_TURBO", "2.6.13.0561f2c", False, id="short-turbo-2.6"),
        pytest.param("LONG_FAST", "", False, id="long-fast-unknown"),
    ],
)
def test_a_preset_this_firmware_has_no_parameters_for_is_refused(
    preset: str, firmware: str, refused: bool
) -> None:
    template = _template(f"lora:\n  region: US\n  modem_preset: {preset}\n")

    if not refused:
        assert _plan(template, sections=_WRITES_LORA, firmware=firmware).section("lora")
        return
    with pytest.raises(PlanConflictError, match=r'"Invalid"') as exc_info:
        _plan(template, sections=_WRITES_LORA, firmware=firmware)
    assert exc_info.value.field == "lora.modem_preset"


def test_a_preset_is_not_checked_without_use_preset() -> None:
    template = _template("lora:\n  region: US\n  use_preset: false\n  modem_preset: MEDIUM_TURBO\n")

    plan = _plan(
        template, sections={"lora": {**_CUSTOM, "hop_limit": 5}}, firmware="2.7.26.54e0d8d"
    )

    assert plan.section("lora") is not None


def test_nothing_is_refused_without_a_lora_write() -> None:
    template = _template("lora:\n  region: EU_866\n  modem_preset: LITE_FAST\n")

    plan = _plan(template, firmware="2.7.26.54e0d8d")

    assert plan.section("lora") is None


def test_the_firmware_boundaries() -> None:
    assert plan_lora.PRESET_MIN_FIRMWARE["LONG_TURBO"] == (2, 7, 17)
    assert set(plan_lora.PRESET_MIN_FIRMWARE.values()) == {(2, 7, 17), (2, 8, 0)}
    assert {
        name: version
        for name, version in plan_lora.REGION_MIN_FIRMWARE.items()
        if version < (2, 8, 0)
    } == {
        "ANZ_433": (2, 7, 0),
        "KZ_433": (2, 7, 1),
        "KZ_863": (2, 7, 1),
        "NP_865": (2, 7, 4),
        "BR_902": (2, 7, 4),
    }
    assert dict(plan_lora.REGION_REMOVED_FIRMWARE) == {"UA_868": (2, 8, 0)}


@pytest.mark.parametrize(
    ("lora", "firmware"),
    [
        pytest.param("channel_num: 2", _FIRMWARE_2_8, id="long-fast-2-on-2.8"),
        pytest.param("modem_preset: LONG_MODERATE\n  channel_num: 3", "", id="long-mod-3-unknown"),
    ],
)
def test_a_channel_num_above_the_slot_count_is_refused_on_2_8(lora: str, firmware: str) -> None:
    template = _template(f"lora:\n  {lora}\n")

    with pytest.raises(PlanConflictError, match=r"frequency slot\(s\) in EU_868") as exc_info:
        _plan(template, sections=_WRITES_LORA, firmware=firmware)

    assert exc_info.value.field == "lora.channel_num"


@pytest.mark.parametrize(
    "lora",
    [
        pytest.param("channel_num: 1", id="long-fast-1"),
        pytest.param("channel_num: 0", id="long-fast-0"),
        pytest.param("modem_preset: LONG_SLOW\n  channel_num: 2", id="long-slow-2"),
        pytest.param("use_preset: false\n  channel_num: 9", id="no-preset"),
    ],
)
def test_a_channel_num_within_the_slot_count_is_planned(lora: str) -> None:
    template = _template(f"lora:\n  {lora}\n")

    plan = _plan(template, sections={"lora": {**_CUSTOM, "channel_num": 0}})

    assert not any(w.code == "channel_num_wraps" for w in plan.warnings)


def test_a_channel_num_above_the_slot_count_wraps_before_2_8() -> None:
    template = _template("lora:\n  channel_num: 3\n")

    plan = _plan(template, sections=_WRITES_LORA, firmware="2.7.26.54e0d8d")

    (warning,) = [w for w in plan.warnings if w.code == "channel_num_wraps"]
    assert (warning.section, warning.field) == ("lora", "channel_num")
    assert "above the 1 frequency slot(s) LONG_FAST has in EU_868" in warning.message
    assert "uses slot 1" in warning.message
    assert plan.section("lora") is not None


def _moved(plan: ChangePlan) -> list[str]:
    return [w.message for w in plan.warnings if w.code == "region_change_reboots"]


@pytest.mark.parametrize(
    ("lora", "live", "named"),
    [
        pytest.param(
            "modem_preset: LONG_MODERATE\n  channel_num: 2",
            {"channel_num": 0},
            "lora.channel_num",
            id="slot-of-two",
        ),
        pytest.param(
            "frequency_offset: 1500.0",
            {"frequency_offset": 0.0},
            "lora.frequency_offset",
            id="offset",
        ),
        pytest.param("region: EU_868", {"region": "EU_433"}, "lora.region", id="region"),
        pytest.param(
            "modem_preset: SHORT_FAST",
            {"use_preset": False, "modem_preset": "LONG_FAST", **_CUSTOM},
            "lora.use_preset, lora.modem_preset",
            id="preset-and-use-preset",
        ),
    ],
)
def test_a_change_that_moves_the_radio_is_named(
    lora: str, live: dict[str, object], named: str
) -> None:
    template = _template(f"lora:\n  {lora}\n")

    (message,) = _moved(_plan(template, sections={"lora": live}))

    assert message.startswith(f"Changing {named} moves the radio")


@pytest.mark.parametrize(
    ("lora", "live"),
    [
        pytest.param("channel_num: 1", {"channel_num": 0}, id="single-slot"),
        pytest.param("hop_limit: 4", {"hop_limit": 3}, id="hop-limit"),
    ],
)
def test_a_lora_change_that_keeps_the_radio_where_it_is_is_not_named(
    lora: str, live: dict[str, object]
) -> None:
    template = _template(f"lora:\n  {lora}\n")

    plan = _plan(template, sections={"lora": live})

    assert plan.section("lora") is not None
    assert _moved(plan) == []
