"""LoRa writes the device's firmware could not run as the template asks.

The template validator already refuses a preset its region does not run
(:mod:`meshprovision.lora_regions`); what is left needs the device's
firmware version: a region or preset older firmware has no plan or radio
parameters for (:func:`lora_firmware_refusal`).

Pure, like :mod:`~meshprovision.provisioning.plan`: no I/O, no device
access, and nothing from ``meshtastic``. The version boundaries were read
in the firmware source at every release tag from 2.6.0 to 2.7.26 and at
2.8.0 and 2.8.3; nothing here was tried on a device.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from meshprovision.errors import PlanConflictError
from meshprovision.firmware import parse_firmware_version

if TYPE_CHECKING:
    from meshprovision.provisioning.plan_types import PlanInputs

__all__ = [
    "PRESET_MIN_FIRMWARE",
    "REGION_MIN_FIRMWARE",
    "REGION_REMOVED_FIRMWARE",
    "lora_firmware_refusal",
]

_TWO_EIGHT: Final[tuple[int, int, int]] = (2, 8, 0)

PRESET_MIN_FIRMWARE: Final[Mapping[str, tuple[int, int, int]]] = MappingProxyType(
    {
        "LONG_TURBO": (2, 7, 17),
        "LITE_FAST": _TWO_EIGHT,
        "LITE_SLOW": _TWO_EIGHT,
        "NARROW_FAST": _TWO_EIGHT,
        "NARROW_SLOW": _TWO_EIGHT,
        "TINY_FAST": _TWO_EIGHT,
        "TINY_SLOW": _TWO_EIGHT,
        "MEDIUM_TURBO": _TWO_EIGHT,
    }
)
"""The first firmware with radio parameters for each preset newer than 2.6.

Every other preset has them from 2.6.0 on. ``LONG_TURBO`` is unknown up
to 2.7.16; ``LITE_*`` and ``NARROW_*`` are names without parameters from
2.7.23 to 2.7.26; ``TINY_*`` and ``MEDIUM_TURBO`` are 2.8's."""

REGION_MIN_FIRMWARE: Final[Mapping[str, tuple[int, int, int]]] = MappingProxyType(
    {
        "ANZ_433": (2, 7, 0),
        "KZ_433": (2, 7, 1),
        "KZ_863": (2, 7, 1),
        "NP_865": (2, 7, 4),
        "BR_902": (2, 7, 4),
        **dict.fromkeys(
            (
                "EU_866",
                "EU_N_868",
                "ITU1_2M",
                "ITU2_2M",
                "ITU3_2M",
                "ITU2_125CM",
                "ITU1_70CM",
                "ITU2_70CM",
                "ITU3_70CM",
            ),
            _TWO_EIGHT,
        ),
    }
)
"""The first firmware with a frequency plan for each region newer than 2.6.

Every other region has one from 2.6.0 on (``RadioInterface.cpp``
``regions``). ``EU_866`` and ``EU_N_868`` have a region code but no plan
at 2.7.26."""

REGION_REMOVED_FIRMWARE: Final[Mapping[str, tuple[int, int, int]]] = MappingProxyType(
    {"UA_868": _TWO_EIGHT}
)
"""The first firmware without a frequency plan for a region older ones have."""

_PLANLESS_REGION_FREQUENCIES: Final[str] = "902-928 MHz"
"""Where firmware before 2.8 transmits with a region it has no plan for (``UNSET``'s row)."""


def _floor_text(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def _region_problem(region: str, version: tuple[int, int, int] | None) -> str | None:
    """Tell why the firmware has no frequency plan for ``region``, or ``None``."""
    first = REGION_MIN_FIRMWARE.get(region)
    if first is not None and (version is None or version < first):
        return (
            f"firmware before {_floor_text(first)} has no frequency plan for it and transmits "
            f"on {_PLANLESS_REGION_FREQUENCIES} with it"
        )
    removed = REGION_REMOVED_FIRMWARE.get(region)
    if removed is not None and (version is None or version >= removed):
        return (
            f"firmware {_floor_text(removed)} and later have no frequency plan for it: they "
            "drop a lora write that sets it, and move a node that has it to EU_868 at boot"
        )
    return None


def _preset_problem(preset: str, version: tuple[int, int, int] | None) -> str | None:
    """Tell why the firmware has no radio parameters for ``preset``, or ``None``."""
    first = PRESET_MIN_FIRMWARE.get(preset)
    if first is None or (version is not None and version >= first):
        return None
    return (
        f"firmware before {_floor_text(first)} has no radio parameters for it: it runs "
        'LONG_FAST\'s and names a primary channel without a name of its own "Invalid", so '
        "the node no longer hears the default LongFast channel"
    )


def lora_firmware_refusal(inputs: PlanInputs, *, writes_lora: bool) -> PlanConflictError | None:
    """Refuse writing a region or preset the device's firmware cannot run.

    Firmware without a frequency plan for the template's region falls back
    to ``UNSET``'s (902-928 MHz) and, as the region code is set, keeps
    transmitting there (``initRegion``, ``RadioLibInterface::send``, 2.6.13
    and 2.7.26): outside the band that is legal in Poland, and off the
    mesh. Firmware without radio parameters for the template's preset runs
    ``LONG_FAST``'s under the channel name ``"Invalid"``
    (``modemPresetToParams``, ``DisplayFormatters``). An unparseable
    firmware version is refused too: only a version known to have the
    region or preset is safe.

    Args:
        inputs: The plan inputs.
        writes_lora: Whether the plan writes the ``lora`` section.

    Returns:
        The refusal, or ``None``.
    """
    if not writes_lora:
        return None
    lora = inputs.template.lora
    version = parse_firmware_version(inputs.live.firmware_version)
    reported = inputs.live.firmware_version or "no firmware version"
    problem = _region_problem(lora.region, version)
    if problem is not None:
        return PlanConflictError(
            f"lora.region {lora.region}: {problem} (this device reports {reported}).",
            field="lora.region",
            hint="Update this node's firmware first, or set another region in the template.",
        )
    preset = lora.modem_preset
    if not lora.use_preset or preset is None:
        return None
    problem = _preset_problem(preset, version)
    if problem is None:
        return None
    return PlanConflictError(
        f"lora.modem_preset {preset}: {problem} (this device reports {reported}).",
        field="lora.modem_preset",
        hint="Update this node's firmware first, or set another preset in the template.",
    )
