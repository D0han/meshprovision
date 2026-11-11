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
    channels: tuple[LiveChannel, ...] = (_DEFAULT_PRIMARY,),
) -> ChangePlan:
    live = live_config_from_template(
        template,
        firmware_version=firmware,
        security=make_security(),
        section_overrides=sections,
        channels=channels,
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
        pytest.param("region: KZ_433", "2.7.0.705515a", id="KZ_433-2.7.0"),
        pytest.param("region: KZ_863", "2.7.0.705515a", id="KZ_863-2.7.0"),
        pytest.param("region: NP_865", "2.7.3.cf574c7", id="NP_865-2.7.3"),
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
        pytest.param("region: KZ_433", "2.7.1.f35ca81", id="KZ_433-2.7.1"),
        pytest.param("region: KZ_863", "2.7.1.f35ca81", id="KZ_863-2.7.1"),
        pytest.param("region: NP_865", "2.7.4.c1f4f79", id="NP_865-2.7.4"),
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
    ("live", "desired", "wraps"),
    [
        pytest.param(0, 1, False, id="0-1"),
        pytest.param(1, 2, True, id="1-2"),
    ],
)
def test_a_live_preset_wider_than_the_band_has_long_fasts_slot_before_2_8(
    live: int, desired: int, wraps: bool
) -> None:
    """2.6 and 2.7 run LONG_FAST's parameters for a 500 kHz preset in EU_868: one slot."""
    template = _template(f"lora:\n  modem_preset: null\n  channel_num: {desired}\n")

    plan = _plan(
        template,
        sections={"lora": {"modem_preset": "SHORT_TURBO", "channel_num": live}},
        firmware="2.7.26.54e0d8d",
    )

    assert plan.section("lora") is not None
    assert _moved(plan) == []
    wrapped = [w.message for w in plan.warnings if w.code == "channel_num_wraps"]
    assert bool(wrapped) is wraps
    if wraps:
        assert "above the 1 frequency slot(s) SHORT_TURBO has in EU_868" in wrapped[0]
        assert "uses slot 1" in wrapped[0]


def test_a_turbo_node_moved_into_eu_868_has_long_fasts_slot_before_2_8() -> None:
    """A US node on SHORT_TURBO moved to EU_868 with channel_num 2: one slot, so it wraps."""
    template = _template("lora:\n  modem_preset: null\n  channel_num: 2\n")

    plan = _plan(
        template,
        sections={"lora": {"region": "US", "modem_preset": "SHORT_TURBO", "channel_num": 0}},
        firmware="2.7.26.54e0d8d",
    )

    assert plan.section("lora") is not None
    (wrapped,) = [w.message for w in plan.warnings if w.code == "channel_num_wraps"]
    assert "above the 1 frequency slot(s) SHORT_TURBO has in EU_868" in wrapped
    (message,) = _moved(plan)
    assert message.startswith("Changing lora.region, lora.channel_num moves the radio")


def test_a_preset_without_a_slot_in_the_region_leaves_the_slot_unchecked_on_2_8() -> None:
    """SHORT_TURBO is wider than EU_N_868's slots: no count, so the slot counts as moved."""
    template = _template("lora:\n  region: EU_N_868\n  modem_preset: null\n  channel_num: 1\n")

    plan = _plan(template, sections={"lora": {"modem_preset": "SHORT_TURBO", "channel_num": 0}})

    assert plan.section("lora") is not None
    (message,) = _moved(plan)
    assert message.startswith("Changing lora.channel_num moves the radio")


@pytest.mark.parametrize(
    ("lora", "live", "named"),
    [
        pytest.param(
            "modem_preset: LONG_MODERATE\n  channel_num: 1",
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


@pytest.mark.parametrize(
    ("live", "firmware", "reboots"),
    [
        pytest.param({"region": "EU_433"}, "2.7.26.54e0d8d", True, id="region-2.7"),
        pytest.param({"region": "EU_433"}, _FIRMWARE_2_8, False, id="region-2.8"),
        pytest.param({"tx_power": 20}, "2.6.13.0561f2c", True, id="tx-power-2.6"),
        pytest.param({"channel_num": 1}, "", True, id="channel-num-unknown"),
        pytest.param({"hop_limit": 5}, "2.7.26.54e0d8d", False, id="hop-limit-2.7"),
    ],
)
def test_the_lora_sections_own_reboot_follows_the_firmware(
    live: dict[str, object], firmware: str, reboots: bool
) -> None:
    template = _template("lora:\n  tx_power: 27\n  channel_num: 0\n")

    section = _plan(template, sections={"lora": live}, firmware=firmware).section("lora")

    assert section is not None
    assert section.reboots_device is reboots


@pytest.mark.parametrize(
    ("field", "live"),
    [
        pytest.param("use_preset", {"use_preset": False, **_CUSTOM}, id="use_preset"),
        pytest.param("region", {"region": "EU_433"}, id="region"),
        pytest.param("modem_preset", {"modem_preset": "SHORT_FAST"}, id="modem_preset"),
        pytest.param("tx_power", {"tx_power": 20}, id="tx_power"),
        pytest.param("frequency_offset", {"frequency_offset": 100.0}, id="frequency_offset"),
        pytest.param("channel_num", {"channel_num": 1}, id="channel_num"),
        pytest.param(
            "sx126x_rx_boosted_gain", {"sx126x_rx_boosted_gain": True}, id="rx_boosted_gain"
        ),
    ],
)
@pytest.mark.parametrize(
    ("firmware", "reboots"), [("2.7.26.54e0d8d", True), (_FIRMWARE_2_8, False)], ids=["2.7", "2.8"]
)
def test_each_radio_parameter_alone_reboots_firmware_before_2_8(
    field: str, live: dict[str, object], firmware: str, reboots: bool
) -> None:
    """AdminModule's "no lora radio parameters change" list, field by field (2.6.13-2.7.26)."""
    template = _template(
        "lora:\n  tx_power: 27\n  channel_num: 0\n  frequency_offset: 0.0\n"
        "  sx126x_rx_boosted_gain: false\n"
    )

    section = _plan(template, sections={"lora": live}, firmware=firmware).section("lora")

    assert section is not None
    assert [c.field for c in section.changes] == [field]
    assert section.reboots_device is reboots


def _named(name: str) -> tuple[LiveChannel, ...]:
    return (LiveChannel(index=0, name=name, position_precision=12),)


def _slot_warnings(plan: ChangePlan) -> list[str]:
    return [w.message for w in plan.warnings if w.code == "primary_name_moves_slot"]


@pytest.mark.parametrize(
    ("preset", "name", "chosen", "default"),
    [
        pytest.param("LONG_MODERATE", "Krakow", 1, 2, id="long-mod-krakow"),
        pytest.param("LONG_SLOW", "Polska", 2, 1, id="long-slow-polska"),
    ],
)
def test_a_primary_name_off_the_default_slot_is_warned(
    preset: str, name: str, chosen: int, default: int
) -> None:
    template = _template(f"lora:\n  modem_preset: {preset}\n")

    plan = _plan(template, channels=_named(name))

    (warning,) = [w for w in plan.warnings if w.code == "primary_name_moves_slot"]
    assert (warning.section, warning.field) == ("lora", "channel_num")
    frequency = {1: "869.4625 MHz", 2: "869.5875 MHz"}
    assert warning.message == (
        f'The primary channel is named "{name}", which puts {preset} on slot {chosen} '
        f"({frequency[chosen]}) of the 2 frequency slots it has in EU_868; {preset} nodes "
        f"with an unnamed primary channel use slot {default} ({frequency[default]}), so "
        "this node and those nodes cannot hear each other. Set lora.channel_num "
        f"{default} in the template to join them, or {chosen} to keep this slot; either "
        "clears this warning."
    )


@pytest.mark.parametrize(
    "firmware", ["2.6.13.0561f2c", "2.7.26.54e0d8d", _FIRMWARE_2_8, "", "not-a-version"]
)
def test_the_primary_name_slot_is_warned_on_every_firmware(firmware: str) -> None:
    template = _template("lora:\n  modem_preset: LONG_MODERATE\n")

    plan = _plan(template, firmware=firmware, channels=_named("Krakow"))

    assert len(_slot_warnings(plan)) == 1


@pytest.mark.parametrize(
    ("lora", "live", "channels"),
    [
        pytest.param("modem_preset: LONG_MODERATE", None, _named("Polska"), id="same-slot"),
        pytest.param("modem_preset: LONG_SLOW", None, _named("Krakow"), id="same-slot-ls"),
        pytest.param("modem_preset: LONG_MODERATE", None, (_DEFAULT_PRIMARY,), id="unnamed"),
        pytest.param("modem_preset: LONG_MODERATE", None, (), id="no-primary"),
        pytest.param("modem_preset: LONG_FAST", None, _named("Krakow"), id="one-slot"),
        pytest.param(
            "modem_preset: LONG_MODERATE\n  channel_num: 1", None, _named("Krakow"), id="cn-1"
        ),
        pytest.param(
            "modem_preset: LONG_MODERATE\n  channel_num: 2", None, _named("Krakow"), id="cn-2"
        ),
        pytest.param(
            "modem_preset: LONG_MODERATE", {"channel_num": 2}, _named("Krakow"), id="live-cn-2"
        ),
        pytest.param(
            "modem_preset: LONG_MODERATE",
            {"override_frequency": 869.5},
            _named("Krakow"),
            id="override-frequency",
        ),
        pytest.param(
            "use_preset: false\n  modem_preset: LONG_MODERATE",
            {"use_preset": False, **_CUSTOM},
            _named("Krakow"),
            id="no-preset",
        ),
    ],
)
def test_a_primary_name_that_does_not_pick_another_slot_is_not_warned(
    lora: str, live: dict[str, object] | None, channels: tuple[LiveChannel, ...]
) -> None:
    template = _template(f"lora:\n  {lora}\n")

    plan = _plan(template, sections={"lora": live} if live else None, channels=channels)

    assert _slot_warnings(plan) == []


@pytest.mark.parametrize(
    ("firmware", "warned"),
    [pytest.param("2.7.26.54e0d8d", False, id="2.7-wraps"), (_FIRMWARE_2_8, True)],
)
def test_a_live_channel_num_above_the_slot_count_leaves_the_slot_to_the_name_on_2_8(
    firmware: str, warned: bool
) -> None:
    """2.7 wraps 3 to slot 1 itself; a 2.8 write replaces it with the name's slot."""
    template = _template("lora:\n  modem_preset: LONG_MODERATE\n")

    plan = _plan(
        template,
        sections={"lora": {"channel_num": 3}},
        firmware=firmware,
        channels=_named("Krakow"),
    )

    assert bool(_slot_warnings(plan)) is warned


def test_a_preset_change_under_a_named_primary_warns_twice() -> None:
    template = _template("lora:\n  modem_preset: LONG_MODERATE\n")

    plan = _plan(
        template, sections={"lora": {"modem_preset": "LONG_FAST"}}, channels=_named("Mesh")
    )

    assert len(_slot_warnings(plan)) == 1
    (moved,) = _moved(plan)
    assert moved.startswith("Changing lora.modem_preset moves the radio")


@pytest.mark.parametrize(
    ("preset", "live", "desired", "channels", "firmware", "moves"),
    [
        pytest.param("LONG_MODERATE", 0, 2, (_DEFAULT_PRIMARY,), _FIRMWARE_2_8, False, id="lm-0-2"),
        pytest.param("LONG_MODERATE", 2, 0, (_DEFAULT_PRIMARY,), _FIRMWARE_2_8, False, id="lm-2-0"),
        pytest.param("LONG_MODERATE", 0, 1, (_DEFAULT_PRIMARY,), _FIRMWARE_2_8, True, id="lm-0-1"),
        pytest.param("LONG_SLOW", 0, 1, (_DEFAULT_PRIMARY,), "2.6.13.0561f2c", False, id="ls-0-1"),
        pytest.param("LONG_SLOW", 1, 2, (_DEFAULT_PRIMARY,), _FIRMWARE_2_8, True, id="ls-1-2"),
        pytest.param(
            "LONG_MODERATE", 0, 1, _named("Krakow"), _FIRMWARE_2_8, False, id="krakow-0-1"
        ),
        pytest.param("LONG_MODERATE", 0, 2, _named("Krakow"), _FIRMWARE_2_8, True, id="krakow-0-2"),
        pytest.param(
            "LONG_MODERATE", 3, 1, (_DEFAULT_PRIMARY,), "2.7.26.54e0d8d", False, id="wrap"
        ),
        pytest.param(
            "LONG_MODERATE", 3, 2, (_DEFAULT_PRIMARY,), _FIRMWARE_2_8, False, id="2.8-3-2"
        ),
        pytest.param("LONG_MODERATE", 0, 2, (), _FIRMWARE_2_8, True, id="no-primary"),
    ],
)
def test_a_channel_num_change_moves_the_radio_only_off_its_slot(
    preset: str,
    live: int,
    desired: int,
    channels: tuple[LiveChannel, ...],
    firmware: str,
    moves: bool,
) -> None:
    """0 leaves the slot to the primary's name: LongMod picks 2, LongSlow 1, "Krakow" 1."""
    template = _template(f"lora:\n  modem_preset: {preset}\n  channel_num: {desired}\n")

    plan = _plan(
        template, sections={"lora": {"channel_num": live}}, firmware=firmware, channels=channels
    )

    assert plan.section("lora") is not None
    assert bool(_moved(plan)) is moves
