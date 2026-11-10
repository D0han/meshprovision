"""LoRa regions and modem presets as the firmware defines them.

A leaf module (stdlib only), so that both the template validator and the
pure plan modules can tell which presets a region runs, how many
frequency slots a preset has there, and which slot a node takes, without
importing ``meshtastic`` or each other.

The region rows are those of ``meshtastic/firmware`` 2.8.3 (``master`` at
51ac6ea, ``RadioInterface.cpp`` ``RDEF`` and the ``RegionProfile`` they
use), identical at 2.8.0; the preset bandwidths are ``modemPresetToParams``
(``MeshRadio.h``). Frequencies are kept in whole Hz so that slot counts are
exact. Nothing here was tried on a device.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from fractions import Fraction
from math import floor
from types import MappingProxyType
from typing import Final

__all__ = [
    "DEPRECATED_PRESETS",
    "PRESET_CHANNEL_NAMES",
    "REGION_BANDS",
    "UNKNOWN_PRESET_NAME",
    "UNUSABLE_PRESETS",
    "UNUSABLE_REGIONS",
    "RegionBand",
    "boot_uses_default_slot",
    "djb2",
    "duty_cycle_limit",
    "frequency_slot_count",
    "preset_problem",
]

_STD_PRESETS: Final[frozenset[str]] = frozenset(
    {
        "LONG_FAST",
        "LONG_SLOW",
        "MEDIUM_SLOW",
        "MEDIUM_FAST",
        "SHORT_SLOW",
        "SHORT_FAST",
        "LONG_MODERATE",
        "SHORT_TURBO",
        "LONG_TURBO",
        "MEDIUM_TURBO",
    }
)
_EU_868_PRESETS: Final[frozenset[str]] = frozenset(
    {
        "LONG_FAST",
        "LONG_SLOW",
        "MEDIUM_SLOW",
        "MEDIUM_FAST",
        "SHORT_SLOW",
        "SHORT_FAST",
        "LONG_MODERATE",
    }
)
_LITE_PRESETS: Final[frozenset[str]] = frozenset({"LITE_FAST", "LITE_SLOW"})
_NARROW_PRESETS: Final[frozenset[str]] = frozenset({"NARROW_FAST", "NARROW_SLOW"})
_TINY_PRESETS: Final[frozenset[str]] = frozenset({"TINY_FAST", "TINY_SLOW"})


@dataclass(frozen=True, slots=True)
class RegionBand:
    """One region's frequency plan (a ``RegionInfo`` row and its ``RegionProfile``).

    Attributes:
        start_hz: The band's lower edge.
        end_hz: The band's upper edge.
        duty_cycle: The duty-cycle limit, in percent (100 for none).
        presets: The presets the region runs (``RegionProfile::presets``).
        default_preset: The preset the firmware runs in place of another.
        spacing_hz: The gap between slots, and at the band's start.
        padding_hz: The gap on each side of a slot.
        override_slot: A slot fixed by the region (1-based), or 0 when
            the primary channel's name picks it.
        wide: Whether this is a 2.4 GHz region, with wider bandwidths.
    """

    start_hz: int
    end_hz: int
    duty_cycle: float
    presets: frozenset[str]
    default_preset: str = "LONG_FAST"
    spacing_hz: int = 0
    padding_hz: int = 0
    override_slot: int = 0
    wide: bool = False


def _std(start_hz: int, end_hz: int, duty_cycle: float = 100) -> RegionBand:
    return RegionBand(start_hz, end_hz, duty_cycle, _STD_PRESETS)


def _ham(start_hz: int, end_hz: int, override_slot: int, *, tiny: bool) -> RegionBand:
    return RegionBand(
        start_hz,
        end_hz,
        100,
        _TINY_PRESETS if tiny else _NARROW_PRESETS,
        default_preset="TINY_FAST" if tiny else "NARROW_SLOW",
        padding_hz=2_200 if tiny else 18_750,
        override_slot=override_slot,
    )


REGION_BANDS: Final[Mapping[str, RegionBand]] = MappingProxyType(
    {
        "US": _std(902_000_000, 928_000_000),
        "EU_433": _std(433_000_000, 434_000_000, 10),
        "EU_868": RegionBand(869_400_000, 869_650_000, 10, _EU_868_PRESETS),
        "EU_866": RegionBand(
            865_600_000,
            867_600_000,
            2.5,
            _LITE_PRESETS,
            default_preset="LITE_FAST",
            spacing_hz=400_000,
            padding_hz=37_500,
        ),
        "EU_N_868": RegionBand(
            869_400_000,
            869_650_000,
            10,
            _NARROW_PRESETS,
            default_preset="NARROW_SLOW",
            padding_hz=10_400,
            override_slot=1,
        ),
        "CN": _std(470_000_000, 510_000_000),
        "JP": _std(920_500_000, 923_500_000),
        "ANZ": _std(915_000_000, 928_000_000),
        "ANZ_433": _std(433_050_000, 434_790_000),
        "RU": _std(868_700_000, 869_200_000),
        "KR": _std(920_000_000, 923_000_000),
        "TW": _std(920_000_000, 925_000_000),
        "IN": _std(865_000_000, 867_000_000),
        "NZ_865": _std(864_000_000, 868_000_000),
        "TH": _std(920_000_000, 925_000_000, 10),
        "UA_433": _std(433_000_000, 434_700_000, 10),
        "MY_433": _std(433_000_000, 435_000_000),
        "MY_919": _std(919_000_000, 924_000_000),
        "SG_923": _std(917_000_000, 925_000_000),
        "PH_433": _std(433_000_000, 434_700_000),
        "PH_868": _std(868_000_000, 869_400_000),
        "PH_915": _std(915_000_000, 918_000_000),
        "KZ_433": _std(433_075_000, 434_775_000),
        "KZ_863": _std(863_000_000, 868_000_000),
        "NP_865": _std(865_000_000, 868_000_000),
        "BR_902": _std(902_000_000, 907_500_000),
        "ITU1_2M": _ham(144_000_000, 146_000_000, 26, tiny=True),
        "ITU2_2M": _ham(144_000_000, 148_000_000, 51, tiny=True),
        "ITU3_2M": _ham(144_000_000, 148_000_000, 33, tiny=True),
        "ITU2_125CM": _ham(220_000_000, 225_000_000, 37, tiny=False),
        "ITU1_70CM": _ham(430_000_000, 440_000_000, 37, tiny=False),
        "ITU2_70CM": _ham(420_000_000, 450_000_000, 137, tiny=False),
        "ITU3_70CM": _ham(430_000_000, 450_000_000, 37, tiny=False),
        "LORA_24": RegionBand(2_400_000_000, 2_483_500_000, 100, _STD_PRESETS, wide=True),
    }
)
"""Every region firmware 2.8 has a frequency plan for, by name.

``UA_868`` is gone from 2.8 (it was there up to 2.7.26, with a 1 % duty
cycle); ``EU_874`` and ``EU_917`` have a region code but no plan in any
firmware (see :data:`UNUSABLE_REGIONS`). ``EU_866``'s duty cycle is 10 %
for ``ROUTER`` and ``ROUTER_LATE`` (``getEffectiveDutyCycle``), and ``TH``'s
was 100 % before 2.7.21."""

_PRESET_BANDWIDTH_HZ: Final[Mapping[str, tuple[int, int]]] = MappingProxyType(
    {
        "SHORT_TURBO": (500_000, 1_625_000),
        "SHORT_FAST": (250_000, 812_500),
        "SHORT_SLOW": (250_000, 812_500),
        "MEDIUM_FAST": (250_000, 812_500),
        "MEDIUM_SLOW": (250_000, 812_500),
        "MEDIUM_TURBO": (500_000, 1_625_000),
        "LONG_TURBO": (500_000, 1_625_000),
        "LONG_MODERATE": (125_000, 406_250),
        "LONG_SLOW": (125_000, 406_250),
        "LITE_FAST": (125_000, 125_000),
        "LITE_SLOW": (125_000, 125_000),
        "NARROW_FAST": (62_500, 62_500),
        "NARROW_SLOW": (62_500, 62_500),
        "TINY_FAST": (15_600, 15_600),
        "TINY_SLOW": (15_600, 15_600),
    }
)
"""Each preset's bandwidth, in Hz, and on a 2.4 GHz region; any other runs ``LONG_FAST``'s."""

_LONG_FAST_BANDWIDTH_HZ: Final[tuple[int, int]] = (250_000, 812_500)

PRESET_CHANNEL_NAMES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "SHORT_TURBO": "ShortTurbo",
        "SHORT_SLOW": "ShortSlow",
        "SHORT_FAST": "ShortFast",
        "MEDIUM_SLOW": "MediumSlow",
        "MEDIUM_FAST": "MediumFast",
        "MEDIUM_TURBO": "MediumTurbo",
        "LONG_SLOW": "LongSlow",
        "LONG_FAST": "LongFast",
        "LONG_TURBO": "LongTurbo",
        "LONG_MODERATE": "LongMod",
        "LITE_FAST": "LiteFast",
        "LITE_SLOW": "LiteSlow",
        "NARROW_FAST": "NarrowFast",
        "NARROW_SLOW": "NarrowSlow",
        "TINY_FAST": "TinyFast",
        "TINY_SLOW": "TinySlow",
    }
)
"""Each modem preset's channel name (``DisplayFormatters::getModemPresetDisplayName``)."""

UNKNOWN_PRESET_NAME: Final[str] = "Invalid"
"""The name the firmware gives a preset it has no name for."""

UNUSABLE_PRESETS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "VERY_LONG_SLOW": (
            "was deprecated in firmware 2.5 and no firmware from 2.6 on runs it: 2.6 and 2.7 "
            'run LONG_FAST\'s radio parameters under the channel name "Invalid", and 2.8 runs '
            "the region's default preset"
        ),
    }
)
"""Presets no supported firmware runs, with the reason."""

DEPRECATED_PRESETS: Final[Mapping[str, str]] = MappingProxyType(
    {"LONG_SLOW": "is deprecated since firmware 2.7 (still run by 2.6 through 2.8)"}
)
"""Presets the firmware still runs but marks deprecated (``config.proto``)."""

UNUSABLE_REGIONS: Final[Mapping[str, str]] = MappingProxyType(
    dict.fromkeys(
        ("EU_874", "EU_917"),
        "has a region code but no frequency plan in any firmware from 2.6 to 2.8.3: "
        "2.6 and 2.7 transmit on 902-928 MHz with it, and 2.8 refuses it",
    )
)
"""Regions no supported firmware runs, with the reason."""

_OLD_REGION_DUTY_CYCLES: Final[Mapping[str, float]] = MappingProxyType({"UA_868": 1})
"""The duty-cycle limit, in percent, of a region only firmware before 2.8 has."""

_EU_SIBLINGS: Final[tuple[str, ...]] = ("EU_868", "EU_866", "EU_N_868")
"""The regions firmware 2.8 swaps between for a preset of another (``regionSwapForPreset``)."""


def djb2(text: str) -> int:
    """Return the firmware's 32-bit djb2 hash of ``text`` (``RadioInterface.cpp`` ``hash``).

    Args:
        text: The string, hashed as its UTF-8 bytes.

    Returns:
        The hash, from 0 to 2**32 - 1.
    """
    value = 5381
    for byte in text.encode("utf-8"):
        value = (value * 33 + byte) & 0xFFFFFFFF
    return value


def _mhz(hz: int) -> str:
    return f"{hz / 1_000_000:g}"


def _band_text(name: str) -> str:
    band = REGION_BANDS[name]
    duty = (
        f"{band.duty_cycle:g} % duty cycle for all but ROUTER and ROUTER_LATE"
        if name == "EU_866"
        else f"{band.duty_cycle:g} % duty cycle"
    )
    return f"{_mhz(band.start_hz)}-{_mhz(band.end_hz)} MHz, {duty}"


def preset_problem(region: str, preset: str) -> str | None:
    """Tell why no firmware runs ``preset`` as asked in ``region``.

    Firmware 2.8 runs only a region's own presets: for another it runs the
    region's default in its place (``checkOrClampConfigLora``) or, between
    ``EU_868``, ``EU_866`` and ``EU_N_868``, switches to the sibling region
    that has the preset (``regionSwapForPreset``), unless the same write
    changes the region, which it then drops whole (``AdminModule``
    set_config lora). Older firmware cannot run those presets there either:
    it falls back to ``LONG_FAST`` when the bandwidth is wider than the band
    (the turbo presets on ``EU_868``), runs ``LONG_FAST``'s parameters for a
    preset it has none for, and has no frequency plan for ``EU_866`` and
    ``EU_N_868`` at all.

    Args:
        region: The region name.
        preset: The preset name.

    Returns:
        The reason, to follow ``lora.modem_preset <preset>``, or ``None``
        when the region runs the preset or is unknown here.
    """
    if preset in UNUSABLE_PRESETS:
        return UNUSABLE_PRESETS[preset]
    band = REGION_BANDS.get(region)
    if band is None or preset in band.presets:
        return None
    if region in _EU_SIBLINGS:
        sibling = next(
            (name for name in _EU_SIBLINGS if preset in REGION_BANDS[name].presets), None
        )
        if sibling is not None:
            older = (
                "older firmware has no radio parameters for it"
                if region == "EU_868"
                else f"firmware before 2.8 has no frequency plan for {region}"
            )
            return (
                f"belongs to region {sibling}: with region {region}, firmware 2.8 switches "
                f"the node to {sibling} ({_band_text(sibling)}), or drops the lora write when "
                f"it also changes the region, and {older}"
            )
    return (
        f"is not one of {region}'s presets ({', '.join(sorted(band.presets))}): firmware "
        f"2.8 runs {band.default_preset} in its place, and older firmware cannot run it "
        "there either"
    )


def frequency_slot_count(region: str, preset: str, *, firmware_2_8: bool) -> int | None:
    """Return how many frequency slots ``preset`` has in ``region``.

    ``channel_num`` 1 to this count picks a slot; 0 lets the firmware pick
    one. Firmware 2.8 rounds the count and leaves room for the region's
    spacing and padding (``RadioInterface::frequencySlotCount``); older
    firmware rounds down, with neither (``applyModemConfig``, 2.6.13 and
    2.7.26, whose regions all have the same band edges as 2.8's).

    Args:
        region: The region name.
        preset: The preset name.
        firmware_2_8: Whether to count as firmware 2.8 does.

    Returns:
        The count, or ``None`` for a region without a plan here.
    """
    band = REGION_BANDS.get(region)
    if band is None:
        return None
    narrow, wide = _PRESET_BANDWIDTH_HZ.get(preset, _LONG_FAST_BANDWIDTH_HZ)
    bandwidth = wide if band.wide else narrow
    span = band.end_hz - band.start_hz
    if not firmware_2_8:
        return span // bandwidth
    slots = Fraction(span + band.spacing_hz, band.spacing_hz + 2 * band.padding_hz + bandwidth)
    return floor(slots + Fraction(1, 2))


def boot_uses_default_slot(region: str, preset: str, channel_num: int) -> bool | None:
    """Tell whether firmware 2.8 counts ``channel_num`` as the default slot at boot.

    ``NodeDB::loadFromDisk`` runs ``RadioInterface::clampConfigLora`` before
    it loads the channels, so the channel name that check hashes is the
    preset's own (``Channels::getName`` of a channel with no name), whatever
    the primary channel is called. ``channel_num`` 0, the region's own slot,
    the preset name's slot, and one above the slot count (which the check
    replaces with that slot) count as default (``checkOrClampConfigLora``,
    2.8.0 and 2.8.3).

    Args:
        region: The region name.
        preset: The preset name.
        channel_num: The stored ``channel_num``.

    Returns:
        Whether the slot is the default one, or ``None`` for a region
        without a plan here.
    """
    band = REGION_BANDS.get(region)
    slots = frequency_slot_count(region, preset, firmware_2_8=True)
    if band is None or not slots:
        return None
    if channel_num == 0 or channel_num > slots:
        return True
    if band.override_slot > 0:
        return channel_num == band.override_slot
    name = PRESET_CHANNEL_NAMES.get(preset, UNKNOWN_PRESET_NAME)
    return channel_num - 1 == djb2(name) % slots


def duty_cycle_limit(region: str) -> str | None:
    """Return a region's duty-cycle limit as text, or ``None`` when it has none.

    The firmware stops sending once its own transmissions over the last
    hour pass that share, unless ``lora.override_duty_cycle`` is set
    (``Router::send``, 2.6.13 through 2.8.3).

    Args:
        region: The region name.

    Returns:
        For example ``"10 %"``; ``EU_866``'s depends on the role.
    """
    band = REGION_BANDS.get(region)
    limit = band.duty_cycle if band is not None else _OLD_REGION_DUTY_CYCLES.get(region)
    if limit is None or limit >= 100:
        return None
    if region == "EU_866":
        return f"{limit:g} % (10 % for ROUTER and ROUTER_LATE)"
    return f"{limit:g} %"
