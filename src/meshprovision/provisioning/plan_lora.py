"""LoRa writes the device's firmware could not run as the template asks.

The template validator already refuses a preset its region does not run
(:mod:`meshprovision.lora_regions`); what is left needs the device's
firmware version: a region or preset older firmware has no plan or radio
parameters for, or a ``channel_num`` firmware 2.8 replaces
(:func:`lora_firmware_refusal`), and one older firmware wraps
(:func:`channel_num_wrap_warning`). :func:`radio_move_warning` tells the
operator that a ``lora`` change takes the node off its current frequency
or modem settings, and :func:`lora_write_reboots` whether the ``lora``
write alone would reboot the device.

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
from meshprovision.lora_regions import frequency_slot_count
from meshprovision.provisioning.plan_warnings import PlanWarning, PlanWarningCode

if TYPE_CHECKING:
    from meshprovision.provisioning.plan_types import FieldChange, PlanInputs

__all__ = [
    "PRESET_MIN_FIRMWARE",
    "RADIO_MOVING_FIELDS",
    "REGION_MIN_FIRMWARE",
    "REGION_REMOVED_FIRMWARE",
    "channel_num_wrap_warning",
    "lora_firmware_refusal",
    "lora_write_reboots",
    "radio_move_warning",
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

RADIO_MOVING_FIELDS: Final[tuple[str, ...]] = (
    "region",
    "modem_preset",
    "use_preset",
    "channel_num",
    "frequency_offset",
)
"""The template ``lora`` fields whose change moves the radio (``applyModemConfig``)."""

_REBOOTING_LORA_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "use_preset",
        "region",
        "modem_preset",
        "tx_power",
        "frequency_offset",
        "channel_num",
        "sx126x_rx_boosted_gain",
    }
)
"""The template ``lora`` fields whose change reboots firmware before 2.8 (``AdminModule``)."""

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


def _slots(inputs: PlanInputs, *, firmware_2_8: bool) -> tuple[int, int, str] | None:
    """Return the template's ``channel_num``, its slot count and the preset, if out of range.

    Only for a ``channel_num`` the template sets, with ``use_preset``: the
    template's preset, else the device's.
    """
    lora = inputs.template.lora
    channel_num = lora.channel_num
    if not lora.use_preset or not channel_num:
        return None
    preset = str(lora.modem_preset or inputs.live.value("lora", "modem_preset"))
    slots = frequency_slot_count(lora.region, preset, firmware_2_8=firmware_2_8)
    if slots is None or channel_num <= slots:
        return None
    return channel_num, slots, preset


def _channel_num_problem(
    inputs: PlanInputs, version: tuple[int, int, int] | None
) -> PlanConflictError | None:
    """Refuse a ``channel_num`` above the slot count on firmware 2.8 or an unknown one.

    Firmware 2.8 replaces it with the slot the channel name picks, or
    drops the whole ``lora`` write when the region changes with it
    (``checkOrClampConfigLora``, ``AdminModule`` set_config lora).
    """
    if version is not None and version < _TWO_EIGHT:
        return None
    found = _slots(inputs, firmware_2_8=True)
    if found is None:
        return None
    channel_num, slots, preset = found
    region = inputs.template.lora.region
    return PlanConflictError(
        f"lora.channel_num {channel_num}: {preset} has {slots} frequency slot(s) in "
        f"{region}, and firmware 2.8 replaces a higher channel_num with a slot of its own "
        "(or drops the lora write when the region changes too) (this device reports "
        f"{inputs.live.firmware_version or 'no firmware version'}), so the write could "
        "never be verified.",
        field="lora.channel_num",
        hint=f"Use 0 (the firmware picks the slot) or 1 to {slots} in the template.",
    )


def channel_num_wrap_warning(inputs: PlanInputs) -> PlanWarning | None:
    """Warn that firmware before 2.8 wraps a ``channel_num`` above the slot count.

    It keeps the value but tunes to slot ``(channel_num - 1) % slots + 1``
    (``applyModemConfig``, 2.6.13 and 2.7.26).

    Args:
        inputs: The plan inputs.

    Returns:
        A ``channel_num_wraps`` warning for a parseable version below 2.8
        and an out-of-range ``channel_num``; else ``None``.
    """
    version = parse_firmware_version(inputs.live.firmware_version)
    if version is None or version >= _TWO_EIGHT:
        return None
    found = _slots(inputs, firmware_2_8=False)
    if found is None:
        return None
    channel_num, slots, preset = found
    return PlanWarning(
        PlanWarningCode.CHANNEL_NUM_WRAPS,
        f"lora.channel_num {channel_num} is above the {slots} frequency slot(s) {preset} "
        f"has in {inputs.template.lora.region}: this firmware keeps it but uses slot "
        f"{(channel_num - 1) % slots + 1}, and firmware 2.8 replaces it. Use 0 or 1 to "
        f"{slots} in the template.",
        section="lora",
        field="channel_num",
    )


def lora_firmware_refusal(inputs: PlanInputs, *, writes_lora: bool) -> PlanConflictError | None:
    """Refuse writing a region or preset the device's firmware cannot run.

    Firmware without a frequency plan for the template's region falls back
    to ``UNSET``'s (902-928 MHz) and, as the region code is set, keeps
    transmitting there (``initRegion``, ``RadioLibInterface::send``, 2.6.13
    and 2.7.26): outside the band that is legal in Poland, and off the
    mesh. Firmware without radio parameters for the template's preset runs
    ``LONG_FAST``'s under the channel name ``"Invalid"``
    (``modemPresetToParams``, ``DisplayFormatters``). Firmware 2.8 does
    not keep a ``channel_num`` above the preset's slot count in the region
    (:func:`_channel_num_problem`). An unparseable firmware version is
    refused too: only a version known to have the region or preset, and
    to keep the ``channel_num``, is safe.

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
    problem = _preset_problem(preset, version) if lora.use_preset and preset else None
    if problem is not None:
        return PlanConflictError(
            f"lora.modem_preset {preset}: {problem} (this device reports {reported}).",
            field="lora.modem_preset",
            hint="Update this node's firmware first, or set another preset in the template.",
        )
    return _channel_num_problem(inputs, version)


def radio_move_warning(inputs: PlanInputs, changes: tuple[FieldChange, ...]) -> PlanWarning | None:
    """Warn that a ``lora`` change moves the radio off its frequency or modem settings.

    A change of :data:`RADIO_MOVING_FIELDS` does, except a ``channel_num``
    change alone where the preset has a single frequency slot in the
    region (every 250 kHz preset in ``EU_868``).

    Args:
        inputs: The plan inputs.
        changes: The ``lora`` section's field changes.

    Returns:
        A ``region_change_reboots`` warning (the code name predates the
        wording) naming the changed fields, or ``None``.
    """
    moved = [c.field for c in changes if c.field in RADIO_MOVING_FIELDS]
    if moved == ["channel_num"]:
        lora = inputs.template.lora
        preset = str(lora.modem_preset or inputs.live.value("lora", "modem_preset"))
        version = parse_firmware_version(inputs.live.firmware_version)
        firmware_2_8 = version is None or version >= _TWO_EIGHT
        if frequency_slot_count(lora.region, preset, firmware_2_8=firmware_2_8) == 1:
            return None
    if not moved:
        return None
    return PlanWarning(
        PlanWarningCode.REGION_CHANGE_REBOOTS,
        f"Changing {', '.join(f'lora.{name}' for name in moved)} moves the radio to other "
        "frequencies or modem settings: the node stops hearing nodes that keep the old ones.",
        section="lora",
    )


def lora_write_reboots(inputs: PlanInputs, changes: tuple[FieldChange, ...]) -> bool:
    """Tell whether the ``lora`` write alone, outside a settings transaction, reboots.

    ``AdminModule`` set_config lora reboots unless no radio parameter
    changed (2.6.13, 2.7.2, 2.7.26; of the template's fields those in
    :data:`_REBOOTING_LORA_FIELDS`); 2.8.0 and later apply every ``lora``
    change live. An unparseable firmware version counts as older firmware.

    Args:
        inputs: The plan inputs.
        changes: The ``lora`` section's field changes.

    Returns:
        Whether the write reboots the device.
    """
    version = parse_firmware_version(inputs.live.firmware_version)
    if version is not None and version >= _TWO_EIGHT:
        return False
    return any(c.field in _REBOOTING_LORA_FIELDS for c in changes)
