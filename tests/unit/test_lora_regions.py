"""Tests for meshprovision.lora_regions and the template checks built on it."""

from __future__ import annotations

import pytest

from meshprovision import lora_regions
from meshprovision.config.template import TemplateConfig
from meshprovision.enums import modem_preset_table, region_table
from meshprovision.errors import TemplateValidationError

pytestmark = pytest.mark.unit

EU_868_PRESETS = (
    "LONG_FAST",
    "LONG_MODERATE",
    "LONG_SLOW",
    "MEDIUM_SLOW",
    "MEDIUM_FAST",
    "SHORT_SLOW",
    "SHORT_FAST",
)
"""The presets firmware 2.8 runs in EU_868 (``PRESETS_EU_868``)."""


def test_every_region_code_has_a_plan_or_a_reason() -> None:
    covered = {*lora_regions.REGION_BANDS, *lora_regions.UNUSABLE_REGIONS, "UA_868", "UNSET"}

    assert covered == set(region_table().name_to_value)


def test_every_region_runs_only_known_presets() -> None:
    known = set(modem_preset_table().name_to_value)

    for band in lora_regions.REGION_BANDS.values():
        assert band.presets <= known
        assert band.default_preset in band.presets


@pytest.mark.parametrize("preset", EU_868_PRESETS)
def test_eu_868_runs_its_seven_presets(preset: str) -> None:
    assert lora_regions.preset_problem("EU_868", preset) is None


@pytest.mark.parametrize(
    ("preset", "expected"),
    [
        ("SHORT_TURBO", "firmware 2.8 runs LONG_FAST in its place"),
        ("LONG_TURBO", "firmware 2.8 runs LONG_FAST in its place"),
        ("MEDIUM_TURBO", "firmware 2.8 runs LONG_FAST in its place"),
        ("TINY_FAST", "firmware 2.8 runs LONG_FAST in its place"),
        ("TINY_SLOW", "firmware 2.8 runs LONG_FAST in its place"),
        ("LITE_FAST", "switches the node to EU_866 (865.6-867.6 MHz, 2.5 % duty cycle"),
        ("LITE_SLOW", "switches the node to EU_866 (865.6-867.6 MHz, 2.5 % duty cycle"),
        ("NARROW_FAST", "switches the node to EU_N_868 (869.4-869.65 MHz, 10 % duty cycle)"),
        ("NARROW_SLOW", "switches the node to EU_N_868 (869.4-869.65 MHz, 10 % duty cycle)"),
        ("VERY_LONG_SLOW", "was deprecated in firmware 2.5"),
    ],
)
def test_eu_868_refuses_every_other_preset_with_the_reason(preset: str, expected: str) -> None:
    problem = lora_regions.preset_problem("EU_868", preset)

    assert problem is not None
    assert expected in problem


def test_a_region_swap_is_named_from_each_eu_sibling() -> None:
    assert str(lora_regions.preset_problem("EU_866", "LONG_FAST")).endswith(
        "switches the node to EU_868 (869.4-869.65 MHz, 10 % duty cycle), or drops the lora "
        "write when it also changes the region, and firmware before 2.8 has no frequency plan "
        "for EU_866"
    )
    assert str(lora_regions.preset_problem("EU_N_868", "MEDIUM_FAST")).endswith(
        "firmware before 2.8 has no frequency plan for EU_N_868"
    )
    assert str(lora_regions.preset_problem("EU_868", "LITE_FAST")).endswith(
        "and older firmware has no radio parameters for it"
    )
    assert lora_regions.preset_problem("US", "LITE_FAST") == (
        "is not one of US's presets (LONG_FAST, LONG_MODERATE, LONG_SLOW, LONG_TURBO, "
        "MEDIUM_FAST, MEDIUM_SLOW, MEDIUM_TURBO, SHORT_FAST, SHORT_SLOW, SHORT_TURBO): "
        "firmware 2.8 runs LONG_FAST in its place, and older firmware cannot run it there "
        "either"
    )


def test_a_region_without_a_plan_here_checks_only_unusable_presets() -> None:
    assert lora_regions.preset_problem("UA_868", "SHORT_TURBO") is None
    assert lora_regions.preset_problem("UA_868", "VERY_LONG_SLOW") is not None


def test_djb2_is_the_firmwares_hash() -> None:
    """US LongFast lands in slot 20, as the firmware simulator logged (906.875 MHz)."""
    assert lora_regions.djb2("LongFast") == 130429955
    assert lora_regions.djb2("LongFast") % 104 + 1 == 20
    assert lora_regions.djb2("") == 5381


@pytest.mark.parametrize("preset", EU_868_PRESETS)
def test_the_template_accepts_each_eu_868_preset(preset: str) -> None:
    assert TemplateConfig(lora={"modem_preset": preset}).lora.modem_preset == preset


@pytest.mark.parametrize("preset", ["SHORT_TURBO", "LITE_FAST", "NARROW_SLOW", "VERY_LONG_SLOW"])
def test_the_template_refuses_a_preset_its_region_does_not_run(preset: str) -> None:
    with pytest.raises(TemplateValidationError) as exc_info:
        TemplateConfig(lora={"region": "EU_868", "modem_preset": preset})

    assert exc_info.value.field == "lora.modem_preset"
    assert str(exc_info.value).startswith(f"lora.modem_preset {preset} ")


def test_the_template_ignores_the_preset_without_use_preset() -> None:
    template = TemplateConfig(lora={"use_preset": False, "modem_preset": "SHORT_TURBO"})

    assert template.lora.modem_preset == "SHORT_TURBO"


def test_the_template_takes_a_sibling_preset_with_its_own_region() -> None:
    assert TemplateConfig(lora={"region": "EU_866", "modem_preset": "LITE_FAST"}).lora.region == (
        "EU_866"
    )


@pytest.mark.parametrize("region", ["EU_874", "EU_917"])
def test_the_template_refuses_a_region_no_firmware_has_a_plan_for(region: str) -> None:
    with pytest.raises(TemplateValidationError, match="902-928 MHz") as exc_info:
        TemplateConfig(lora={"region": region})

    assert exc_info.value.field == "lora.region"


@pytest.mark.parametrize(
    ("lora", "warned"),
    [
        ({"modem_preset": "LONG_SLOW"}, True),
        ({"modem_preset": "LONG_SLOW", "use_preset": False}, False),
        ({"modem_preset": "LONG_MODERATE"}, False),
    ],
)
def test_long_slow_loads_with_a_deprecation_warning(lora: dict[str, object], warned: bool) -> None:
    warnings = TemplateConfig(lora=lora).collect_warnings()

    deprecated = [w for w in warnings if w.code == "preset_deprecated"]
    assert bool(deprecated) is warned
    if warned:
        assert deprecated[0].field == "lora.modem_preset"
        assert "deprecated since firmware 2.7" in deprecated[0].message


@pytest.mark.parametrize(
    ("region", "preset", "on_2_8", "before_2_8"),
    [
        ("EU_868", "LONG_FAST", 1, 1),
        ("EU_868", "SHORT_SLOW", 1, 1),
        ("EU_868", "LONG_MODERATE", 2, 2),
        ("EU_868", "LONG_SLOW", 2, 2),
        ("EU_866", "LITE_FAST", 4, None),
        ("EU_N_868", "NARROW_SLOW", 3, None),
        ("US", "LONG_FAST", 104, 104),
        ("KZ_433", "LONG_FAST", 7, 6),
        ("LORA_24", "LONG_FAST", 103, 102),
    ],
)
def test_the_frequency_slot_count_follows_each_firmware(
    region: str, preset: str, on_2_8: int, before_2_8: int | None
) -> None:
    """2.8 rounds and pads (``frequencySlotCount``); 2.6 and 2.7 round down."""
    assert lora_regions.frequency_slot_count(region, preset, firmware_2_8=True) == on_2_8
    if before_2_8 is not None:
        assert lora_regions.frequency_slot_count(region, preset, firmware_2_8=False) == (before_2_8)


def test_a_region_without_a_plan_here_has_no_slot_count() -> None:
    assert lora_regions.frequency_slot_count("UA_868", "LONG_FAST", firmware_2_8=False) is None


@pytest.mark.parametrize(
    ("region", "preset", "channel_num", "default"),
    [
        ("EU_868", "LONG_FAST", 0, True),
        ("EU_868", "LONG_FAST", 1, True),
        ("EU_868", "LONG_FAST", 7, True),
        ("EU_868", "LONG_SLOW", 2, False),
        ("EU_868", "LONG_MODERATE", 1, False),
        ("EU_868", "LONG_MODERATE", 2, True),
        ("UA_868", "LONG_FAST", 1, None),
    ],
)
def test_the_default_slot_at_boot_is_the_preset_names(
    region: str, preset: str, channel_num: int, default: bool | None
) -> None:
    assert lora_regions.boot_uses_default_slot(region, preset, channel_num) is default


@pytest.mark.parametrize(
    ("preset", "name", "slot"),
    [
        ("LONG_MODERATE", "", 2),
        ("LONG_MODERATE", "LongMod", 2),
        ("LONG_SLOW", "", 1),
        ("LONG_MODERATE", "Polska", 2),
        ("LONG_MODERATE", "Krakow", 1),
        ("LONG_MODERATE", "Mesh", 1),
        ("LONG_MODERATE", "Gamma", 1),
        ("LONG_MODERATE", "Alpha", 2),
        ("LONG_MODERATE", "A", 1),
        ("LONG_MODERATE", "B", 2),
        ("LONG_SLOW", "Polska", 2),
        ("LONG_FAST", "Krakow", 1),
    ],
)
@pytest.mark.parametrize("firmware_2_8", [True, False], ids=["2.8", "before-2.8"])
def test_the_primary_channel_name_picks_the_slot(
    preset: str, name: str, slot: int, firmware_2_8: bool
) -> None:
    """``hash(name) % 2 + 1`` on every firmware; no name hashes the preset's own."""
    assert lora_regions.name_slot("EU_868", preset, name, firmware_2_8=firmware_2_8) == slot


def test_a_region_with_a_slot_of_its_own_ignores_the_name_on_2_8() -> None:
    assert lora_regions.name_slot("EU_N_868", "NARROW_SLOW", "Krakow", firmware_2_8=True) == 1
    assert lora_regions.name_slot("UA_868", "LONG_FAST", "Krakow", firmware_2_8=False) is None


@pytest.mark.parametrize(
    ("region", "preset", "slot", "hz"),
    [
        ("EU_868", "LONG_MODERATE", 1, 869_462_500),
        ("EU_868", "LONG_SLOW", 2, 869_587_500),
        ("EU_868", "LONG_FAST", 1, 869_525_000),
        ("US", "LONG_FAST", 20, 906_875_000),
        ("EU_866", "LITE_FAST", 1, 865_700_000),
        ("EU_866", "LITE_FAST", 2, 866_300_000),
        ("EU_N_868", "NARROW_SLOW", 1, 869_441_650),
        ("UA_868", "LONG_FAST", 1, None),
    ],
)
def test_the_frequency_of_a_slot(region: str, preset: str, slot: int, hz: int | None) -> None:
    """Padding before each slot, spacing between slots (2.8.3 ``applyModemConfig``)."""
    assert lora_regions.slot_frequency_hz(region, preset, slot) == hz


@pytest.mark.parametrize(
    ("region", "limit"),
    [
        ("EU_868", "10 %"),
        ("EU_866", "2.5 % (10 % for ROUTER and ROUTER_LATE)"),
        ("UA_868", "1 %"),
        ("US", None),
    ],
)
def test_the_duty_cycle_limit_of_a_region(region: str, limit: str | None) -> None:
    assert lora_regions.duty_cycle_limit(region) == limit


@pytest.mark.parametrize(
    ("lora", "warned"),
    [
        ({"override_duty_cycle": True}, True),
        ({"override_duty_cycle": False}, False),
        ({"override_duty_cycle": True, "region": "US"}, False),
    ],
)
def test_overriding_a_duty_cycle_limit_loads_with_a_warning(
    lora: dict[str, object], warned: bool
) -> None:
    warnings = [
        w for w in TemplateConfig(lora=lora).collect_warnings() if w.code == "duty_cycle_overridden"
    ]

    assert bool(warnings) is warned
    if warned:
        assert warnings[0].field == "lora.override_duty_cycle"
        assert "EU_868's duty-cycle limit of 10 %" in warnings[0].message
