"""LoRa writes the device's firmware could not run as the template asks.

The template validator already refuses a preset its region does not run
(:mod:`meshprovision.lora_regions`); what is left needs the device's
firmware version: a region or preset older firmware has no plan or radio
parameters for, a device preset the template leaves that the region does
not run, or a ``channel_num`` firmware 2.8 replaces
(:func:`lora_firmware_refusal`), and one older firmware wraps
(:func:`channel_num_wrap_warning`). :func:`radio_move_warning` tells the
operator that a ``lora`` change takes the node off its current frequency
or modem settings, :func:`primary_name_slot_warning` that the primary
channel's name keeps it off the slot of the preset's other nodes, and
:func:`lora_write_reboots` whether the ``lora`` write alone would reboot
the device.

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
from meshprovision.lora_regions import (
    REGION_BANDS,
    frequency_slot_count,
    name_slot,
    preset_problem,
    preset_swap_region,
    slot_frequency_hz,
)
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
    "primary_name_slot_warning",
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
    template's preset, else the device's, where it has a slot.
    """
    lora = inputs.template.lora
    channel_num = lora.channel_num
    if not lora.use_preset or not channel_num:
        return None
    preset = str(lora.modem_preset or inputs.live.value("lora", "modem_preset"))
    slots = frequency_slot_count(lora.region, preset, firmware_2_8=firmware_2_8)
    if not slots or channel_num <= slots:
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


def _live_preset_problem(
    inputs: PlanInputs, version: tuple[int, int, int] | None
) -> PlanConflictError | None:
    """Refuse a device preset the template's region cannot run, where the template leaves it.

    Only on firmware 2.8 or an unknown one: 2.8 drops a ``lora`` write
    that changes the region to one the preset does not fit (``AdminModule``
    set_config lora), and clamps the preset to the region at boot, so a
    node already in the region on a preset (live ``use_preset`` true)
    cannot report another; one with ``use_preset`` false can keep a stored
    preset, which a local write then clamps to the region's default (or
    switches to the sibling region that runs it): a radio move the plan
    does not predict, so it is refused too. Older firmware runs
    ``LONG_FAST`` for a preset wider than the band and reports it
    (``applyModemConfig``); the slot checks count the stored preset's slots
    then, which for ``EU_868`` is the one ``LONG_FAST`` has too.
    """
    lora = inputs.template.lora
    if lora.modem_preset or not lora.use_preset:
        return None
    if version is not None and version < _TWO_EIGHT:
        return None
    live = inputs.live.value("lora", "modem_preset")
    problem = preset_problem(lora.region, str(live)) if live else None
    if problem is None:
        return None
    reported = inputs.live.firmware_version or "no firmware version"
    outcome = "so the write could never be verified"
    band = REGION_BANDS.get(lora.region)
    if inputs.live.value("lora", "region") != lora.region:
        problem = (
            f"is not one of {lora.region}'s presets: firmware 2.8 drops a lora write that "
            "changes the region to one the preset does not fit"
        )
    elif band is not None and preset_swap_region(lora.region, str(live)) is None:
        problem = (
            f"is not one of {lora.region}'s presets: firmware 2.8 clamps it to the region's "
            f"default, {band.default_preset}"
        )
        outcome = "a radio move this plan cannot verify"
    return PlanConflictError(
        f"lora.modem_preset {live}, which the template leaves to the device, {problem} "
        f"(this device reports {reported}), {outcome}.",
        field="lora.modem_preset",
        hint=f"Set lora.modem_preset in the template to one of {lora.region}'s presets.",
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


def _explicit_slot(channel_num: object, slots: int, *, firmware_2_8: bool) -> int | None:
    """Return the slot a stored ``channel_num`` picks itself, or ``None`` when the name does.

    0 leaves the slot to the primary channel's name; 1 to ``slots`` is
    that slot; above ``slots`` firmware before 2.8 wraps it
    (``applyModemConfig``), and a 2.8 write replaces it with the name's
    slot (``checkOrClampConfigLora``; 2.8 clamps it at boot too, so a
    device on 2.8 should not report one). Anything but an ``int`` counts
    as 0.
    """
    if not isinstance(channel_num, int) or channel_num <= 0:
        return None
    if channel_num <= slots:
        return channel_num
    return None if firmware_2_8 else (channel_num - 1) % slots + 1


def _slot_text(region: str, preset: str, slot: int) -> str:
    """Return ``"slot N (F MHz)"``, or ``"slot N"`` for a region without a plan here."""
    hz = slot_frequency_hz(region, preset, slot)
    if hz is None:
        return f"slot {slot}"
    return f"slot {slot} ({hz // 1_000_000}.{hz % 1_000_000:06d}".rstrip("0").rstrip(".") + " MHz)"


def primary_name_slot_warning(inputs: PlanInputs) -> PlanWarning | None:
    """Warn that the primary channel's name puts the preset on another slot than the default.

    Where a preset has more than one frequency slot (``LONG_MODERATE`` and
    ``LONG_SLOW`` in ``EU_868``) and ``channel_num`` leaves the choice to
    the firmware, the primary channel's name picks the slot
    (:func:`~meshprovision.lora_regions.name_slot`); a node whose name
    picks another slot than an unnamed primary does is off the slot the
    preset's other nodes use. Raised whenever the node is in that state
    once the plan is applied, as the template cannot name the channel; a
    ``channel_num`` in the template clears it. A ``lora.override_frequency``
    on the device leaves no slot to warn about.

    Args:
        inputs: The plan inputs; the template's ``lora`` values win over
            the live ones, as they will once the plan is applied.

    Returns:
        A ``primary_name_moves_slot`` warning, or ``None``.
    """
    live = inputs.live
    lora = inputs.template.lora
    primary = next((c for c in live.channels if c.index == 0), None)
    if not lora.use_preset or primary is None or not primary.name:
        return None
    if live.value("lora", "override_frequency"):
        return None
    preset = str(lora.modem_preset or live.value("lora", "modem_preset"))
    version = parse_firmware_version(live.firmware_version)
    firmware_2_8 = version is None or version >= _TWO_EIGHT
    slots = frequency_slot_count(lora.region, preset, firmware_2_8=firmware_2_8)
    channel_num = (
        lora.channel_num if lora.channel_num is not None else live.value("lora", "channel_num")
    )
    if (
        slots is None
        or slots < 2
        or _explicit_slot(channel_num, slots, firmware_2_8=firmware_2_8) is not None
    ):
        return None
    chosen = name_slot(lora.region, preset, primary.name, firmware_2_8=firmware_2_8)
    default = name_slot(lora.region, preset, "", firmware_2_8=firmware_2_8)
    if chosen is None or default is None or chosen == default:
        return None
    return PlanWarning(
        PlanWarningCode.PRIMARY_NAME_MOVES_SLOT,
        f'The primary channel is named "{primary.name}", which puts {preset} on '
        f"{_slot_text(lora.region, preset, chosen)} of the {slots} frequency slots it has in "
        f"{lora.region}; {preset} nodes with an unnamed primary channel use "
        f"{_slot_text(lora.region, preset, default)}, so this node and those nodes cannot "
        f"hear each other. Set lora.channel_num {default} in the template to join them, or "
        f"{chosen} to keep this slot; either clears this warning.",
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
    (``modemPresetToParams``, ``DisplayFormatters``). Where the template
    leaves the preset to the device, firmware 2.8 does not run one the
    template's region has not (:func:`_live_preset_problem`), and it does
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
    return _live_preset_problem(inputs, version) or _channel_num_problem(inputs, version)


def _keeps_slot(inputs: PlanInputs, changes: tuple[FieldChange, ...]) -> bool:
    """Tell whether the ``channel_num`` change leaves the node on its frequency slot.

    Always where the preset has a single slot in the region (every 250 kHz
    preset in ``EU_868``); with ``use_preset`` and more slots, when the old
    and the new value pick the same slot (:func:`_explicit_slot`; 0 leaves
    it to the primary channel's name,
    :func:`~meshprovision.lora_regions.name_slot`), as ``LONG_MODERATE``'s
    0 and 2 do with an unnamed primary. Without a primary channel the name
    is unknown, and without a slot count (a region without a plan here, or
    a preset wider than its slots on 2.8) so is the slot: it counts as
    moved.
    """
    lora = inputs.template.lora
    preset = str(lora.modem_preset or inputs.live.value("lora", "modem_preset"))
    version = parse_firmware_version(inputs.live.firmware_version)
    firmware_2_8 = version is None or version >= _TWO_EIGHT
    slots = frequency_slot_count(lora.region, preset, firmware_2_8=firmware_2_8)
    if slots == 1:
        return True
    primary = next((c for c in inputs.live.channels if c.index == 0), None)
    if not slots or not lora.use_preset or primary is None:
        return False
    named = name_slot(lora.region, preset, primary.name, firmware_2_8=firmware_2_8)
    change = next(c for c in changes if c.field == "channel_num")
    before, after = (
        _explicit_slot(value, slots, firmware_2_8=firmware_2_8) or named
        for value in (change.current, change.desired)
    )
    return before == after


def radio_move_warning(inputs: PlanInputs, changes: tuple[FieldChange, ...]) -> PlanWarning | None:
    """Warn that a ``lora`` change moves the radio off its frequency or modem settings.

    A change of :data:`RADIO_MOVING_FIELDS` does, except a ``channel_num``
    change alone that keeps the slot (:func:`_keeps_slot`).

    Args:
        inputs: The plan inputs.
        changes: The ``lora`` section's field changes.

    Returns:
        A ``region_change_reboots`` warning (the code name predates the
        wording) naming the changed fields, or ``None``.
    """
    moved = [c.field for c in changes if c.field in RADIO_MOVING_FIELDS]
    if not moved or (moved == ["channel_num"] and _keeps_slot(inputs, changes)):
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
