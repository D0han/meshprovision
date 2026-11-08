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
    custom = {"bandwidth": 125, "spread_factor": 11, "coding_rate": 5, "hop_limit": 5}

    plan = _plan(template, sections={"lora": custom}, firmware="2.7.26.54e0d8d")

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
