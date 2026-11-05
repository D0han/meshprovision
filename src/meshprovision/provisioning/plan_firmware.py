"""Values the firmware stores in place of the planned ones, and writes it refuses.

Some template values are written as asked but held differently once the
plan is applied: the firmware raises telemetry and position intervals to
a minimum at every boot while the node is on a default channel
(``NodeDB::NodeDB``), sets ``lora.ignore_mqtt`` when the region
changes, and holds ``lora.tx_power`` at most at the region's limit. A
plain verify would then report a mismatch and, for the boot minimums,
the node would never converge. :func:`firmware_adjustments` predicts
each such value from the plan inputs alone, so
:mod:`~meshprovision.provisioning.plan` can plan the template value, tell
the operator, and let :mod:`~meshprovision.provisioning.readback` accept
the firmware's value too. The template is never rewritten. A role the
firmware replaces on every write is refused instead
(:func:`replaced_role_refusal`), and so are a rebroadcast mode in which
the firmware stops listening to this client (:func:`local_admin_refusal`)
and a custom modem the template cannot describe
(:func:`custom_modem_refusal`).

Pure, like :mod:`~meshprovision.provisioning.plan`: no I/O, no device
access, and nothing from ``meshtastic``. Firmware references are to
``meshtastic/firmware`` 2.8.3 (``master`` at 51ac6ea) unless a version is
named; nothing here was tried on a device.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from meshprovision.errors import PlanConflictError
from meshprovision.firmware import parse_firmware_version
from meshprovision.provisioning.plan_warnings import PlanWarning, PlanWarningCode

if TYPE_CHECKING:
    from meshprovision.provisioning.detect_types import LiveChannel
    from meshprovision.provisioning.plan_types import PlanInputs

__all__ = [
    "BOOT_FLOOR_ROUTER_ROLES",
    "BOOT_PRESET_CHECK_MIN_FIRMWARE",
    "BOOT_SLOT_CHECK_MIN_FIRMWARE",
    "CUSTOM_MODEM_FIELDS",
    "KNOWN_ONLY_DROPS_LOCAL_ADMIN_MIN_FIRMWARE",
    "MAX_INTERVAL_SECS",
    "POSITION_BROADCAST_FLOOR_ROUTER_SECS",
    "POSITION_BROADCAST_FLOOR_SECS",
    "POSITION_PRECISION_CLAMP_MIN_FIRMWARE",
    "PRESET_CHANNEL_NAMES",
    "PUBLIC_CHANNEL_MAX_POSITION_PRECISION",
    "REGION_POWER_LIMITS_DBM",
    "REPEATER_REPLACED_MIN_FIRMWARE",
    "ROLE_DEFAULT_FIELDS",
    "SMART_MINIMUM_INTERVAL_FLOOR_SECS",
    "TELEMETRY_INTERVAL_FIELDS",
    "TELEMETRY_INTERVAL_FLOOR_ROUTER_SECS",
    "TELEMETRY_INTERVAL_FLOOR_SECS",
    "FirmwareAdjustment",
    "custom_modem_refusal",
    "firmware_adjustments",
    "known_only_warning",
    "local_admin_refusal",
    "replaced_role_refusal",
    "role_change_warning",
]

TELEMETRY_INTERVAL_FLOOR_SECS: Final[int] = 30 * 60
"""``min_default_telemetry_interval_secs`` for every role but the routers (``Default.h``)."""

TELEMETRY_INTERVAL_FLOOR_ROUTER_SECS: Final[int] = 12 * 3600
"""``min_default_telemetry_interval_secs`` for :data:`BOOT_FLOOR_ROUTER_ROLES` (2.7.21+)."""

POSITION_BROADCAST_FLOOR_SECS: Final[int] = 3600
"""``min_default_broadcast_interval_secs`` for every role but the routers (2.7.18+)."""

POSITION_BROADCAST_FLOOR_ROUTER_SECS: Final[int] = 12 * 3600
"""``min_default_broadcast_interval_secs`` for :data:`BOOT_FLOOR_ROUTER_ROLES` (2.7.21+)."""

SMART_MINIMUM_INTERVAL_FLOOR_SECS: Final[int] = 5 * 60
"""``min_default_broadcast_smart_minimum_interval_secs`` (2.7.18+)."""

BOOT_SLOT_CHECK_MIN_FIRMWARE: Final[tuple[int, int, int]] = (2, 8, 0)
"""First firmware whose boot telemetry check sees the frequency slot (``loadFromDisk``)."""

BOOT_PRESET_CHECK_MIN_FIRMWARE: Final[tuple[int, int, int]] = (2, 7, 20)
"""First firmware whose boot telemetry check needs the preset (``hasDefaultChannel``)."""

REPEATER_REPLACED_MIN_FIRMWARE: Final[tuple[int, int, int]] = (2, 7, 11)
"""First firmware storing ``CLIENT`` for a ``REPEATER`` role (``AdminModule``; not at 2.7.10)."""

KNOWN_ONLY_DROPS_LOCAL_ADMIN_MIN_FIRMWARE: Final[tuple[int, int, int]] = (2, 8, 0)
"""First firmware that ignores the connected client under ``KNOWN_ONLY`` (``Router``)."""

_KNOWN_ONLY: Final[str] = "KNOWN_ONLY"

CUSTOM_MODEM_FIELDS: Final[tuple[str, ...]] = ("bandwidth", "spread_factor", "coding_rate")
"""The ``LoRaConfig`` radio parameters the firmware uses when ``use_preset`` is off."""

BOOT_FLOOR_ROUTER_ROLES: Final[frozenset[str]] = frozenset({"ROUTER", "ROUTER_LATE"})
"""The roles ``IF_ROUTER`` (``Default.h``) gives the higher floors."""

TELEMETRY_INTERVAL_FIELDS: Final[tuple[str, ...]] = (
    "device_update_interval",
    "environment_update_interval",
    "air_quality_interval",
    "power_update_interval",
    "health_update_interval",
)
"""The telemetry intervals ``NodeDB::NodeDB`` raises on a default channel."""

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

PUBLIC_CHANNEL_MAX_POSITION_PRECISION: Final[int] = 15
"""``MAX_POSITION_PRECISION_PUBLIC_KEY`` (``PositionPrecision.h``): about 700 m."""

POSITION_PRECISION_CLAMP_MIN_FIRMWARE: Final[tuple[int, int, int]] = (2, 8, 0)
"""First firmware that stores the public-channel precision cap (``handleSetChannel``)."""

MAX_INTERVAL_SECS: Final[int] = 2**31 - 1
"""``MAX_INTERVAL`` (``Default.h``): ``INT32_MAX``, the firmware's "never"."""

ROLE_DEFAULT_FIELDS: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "ROUTER": (
            "device.rebroadcast_mode",
            "is_unmessagable",
            "position.gps_update_interval",
            "position.position_broadcast_secs",
            "power.ls_secs",
            "power.min_wake_secs",
            "power.sds_secs",
            "power.wait_bluetooth_secs",
            "display.screen_on_secs",
            "the telemetry intervals",
            "neighbor_info.update_interval",
            "paxcounter.paxcounter_update_interval",
            "on power-saving builds power.is_power_saving",
        ),
        "ROUTER_LATE": ("is_unmessagable", "telemetry.device_update_interval"),
        "REPEATER": ("device.rebroadcast_mode", "is_unmessagable", "display.screen_on_secs"),
        "SENSOR": (
            "is_unmessagable",
            "telemetry.device_update_interval",
            "telemetry.environment_measurement_enabled",
            "telemetry.environment_update_interval",
        ),
        "TRACKER": ("is_unmessagable", "telemetry.device_update_interval"),
        "LOST_AND_FOUND": (
            "position.position_broadcast_smart_enabled",
            "position.position_broadcast_secs",
        ),
        "TAK": (
            "device.node_info_broadcast_secs",
            "position.position_broadcast_smart_enabled",
            "position.position_broadcast_secs",
            "position.position_flags",
            "telemetry.device_update_interval",
        ),
        "TAK_TRACKER": (
            "is_unmessagable",
            "device.node_info_broadcast_secs",
            "the position broadcast settings",
            "telemetry.device_update_interval",
        ),
        "CLIENT_HIDDEN": (
            "device.rebroadcast_mode (to LOCAL_ONLY)",
            "device.node_info_broadcast_secs",
            "position.position_broadcast_smart_enabled",
            "position.position_broadcast_secs",
            "neighbor_info.update_interval",
            "the telemetry device, environment, air quality and health intervals",
        ),
    }
)
"""What ``NodeDB::installRoleDefaults`` resets when a role is newly set (2.7.26, 2.8.3).

``ROUTER`` runs ``initConfigIntervals`` and ``initModuleConfigIntervals``
(the position, power and display intervals, every telemetry interval,
``neighbor_info`` and ``paxcounter``); ``CLIENT_HIDDEN`` sets its intervals to
:data:`MAX_INTERVAL_SECS`, the firmware's "never". ``REPEATER``'s are those
of 2.6.13 through 2.7.10, the firmware that keeps the role (see
:func:`replaced_role_refusal`). 2.6.13 leaves ``telemetry.device_update_interval``
alone for ``ROUTER_LATE``, ``SENSOR`` and ``TRACKER``."""

_ROLE_DEFAULT_VALUES: Final[Mapping[str, Mapping[tuple[str, str], object]]] = MappingProxyType(
    {
        "ROUTER": {
            ("device", "rebroadcast_mode"): "CORE_PORTNUMS_ONLY",
            ("owner", "is_unmessagable"): True,
        },
        "ROUTER_LATE": {("owner", "is_unmessagable"): True},
        "REPEATER": {
            ("device", "rebroadcast_mode"): "CORE_PORTNUMS_ONLY",
            ("owner", "is_unmessagable"): True,
        },
        "SENSOR": {("owner", "is_unmessagable"): True},
        "TRACKER": {("owner", "is_unmessagable"): True},
        "TAK": {("device", "node_info_broadcast_secs"): 24 * 3600},
        "TAK_TRACKER": {
            ("owner", "is_unmessagable"): True,
            ("device", "node_info_broadcast_secs"): 24 * 3600,
        },
        "CLIENT_HIDDEN": {
            ("device", "rebroadcast_mode"): "LOCAL_ONLY",
            ("device", "node_info_broadcast_secs"): MAX_INTERVAL_SECS,
        },
    }
)
"""The role defaults that overwrite what this run sends before or with the role.

The owner write goes first and ``device`` carries the role, so these are
the template values a role change can replace for good on its own run;
sections written after ``device`` send the template's values again."""

REGION_POWER_LIMITS_DBM: Final[Mapping[str, int]] = MappingProxyType(
    {
        "US": 30,
        "EU_433": 10,
        "EU_868": 27,
        "EU_866": 27,
        "EU_N_868": 27,
        "CN": 19,
        "JP": 13,
        "ANZ": 30,
        "ANZ_433": 14,
        "RU": 20,
        "KR": 23,
        "TW": 27,
        "IN": 30,
        "NZ_865": 36,
        "TH": 27,
        "UA_433": 10,
        "UA_868": 14,
        "MY_433": 20,
        "MY_919": 27,
        "SG_923": 20,
        "PH_433": 10,
        "PH_868": 14,
        "PH_915": 24,
        "KZ_433": 10,
        "KZ_863": 30,
        "NP_865": 30,
        "BR_902": 30,
        "ITU1_2M": 30,
        "ITU2_2M": 30,
        "ITU3_2M": 30,
        "ITU2_125CM": 30,
        "ITU1_70CM": 30,
        "ITU2_70CM": 30,
        "ITU3_70CM": 30,
        "LORA_24": 10,
    }
)
"""Each region's ``power_limit``, in dBm (``RadioInterface.cpp`` ``RDEF``).

The same at 2.7.26, 2.8.0 and 2.8.3 for every region those versions share
(``UA_868`` exists up to 2.7.26; the ``EU_866``, ``EU_N_868``, ``PH_868``
and ``ITU`` regions are 2.8's). 2.7.2 had 12 for ``EU_433`` and 16 for
``TH``."""

_NO_PRESET_NAME: Final[str] = "Custom"
"""The channel name the firmware uses when ``use_preset`` is off."""

_UNKNOWN_PRESET_NAME: Final[str] = "Invalid"
"""The name the firmware gives a preset it has no name for."""


@dataclass(frozen=True, slots=True)
class FirmwareAdjustment:
    """One planned field the firmware will hold at another value.

    Attributes:
        section: The template section, for example ``"position"``.
        field: The field within it.
        value: What the firmware stores in place of the template value.
        warning: The plan warning that tells the operator so; ``None``
            when :func:`role_change_warning` covers it.
    """

    section: str
    field: str
    value: object
    warning: PlanWarning | None = None


def _preset_channel_name(inputs: PlanInputs) -> str:
    """Return the channel name the firmware compares a default channel's name with.

    Args:
        inputs: The plan inputs; the template's ``lora`` values win over
            the live ones, as they will once the plan is applied.

    Returns:
        The planned preset's name, ``"Custom"`` without a preset.
    """
    lora = inputs.template.lora
    if not lora.use_preset:
        return _NO_PRESET_NAME
    preset = lora.modem_preset or inputs.live.value("lora", "modem_preset")
    return PRESET_CHANNEL_NAMES.get(str(preset), _UNKNOWN_PRESET_NAME)


def _is_default_channel(channel: LiveChannel, preset_name: str) -> bool:
    """Apply ``Channels::isDefaultChannel``: the default key and the preset's name.

    An empty name stands for the preset's name (``Channels::getName``).
    """
    return channel.default_key and (channel.name or preset_name) == preset_name


def _planned_precision(inputs: PlanInputs, channel: LiveChannel) -> int:
    """Return a channel's position precision once ``default_channel`` is written.

    Args:
        inputs: The plan inputs.
        channel: The channel.

    Returns:
        The template's ``default_channel.position_precision`` for an
        enabled primary channel (index 0) when the template sets one,
        else the channel's own.
    """
    desired = inputs.template.default_channel.position_precision
    if channel.index == 0 and desired is not None and inputs.live.default_channel:
        return desired
    return channel.position_precision


def _telemetry_floor_applies(inputs: PlanInputs, preset_name: str) -> bool:
    """Tell whether the boot-time telemetry check sees a default channel.

    From 2.8.0 ``NodeDB::loadFromDisk`` runs ``RadioInterface::clampConfigLora``
    before the check, so ``Channels::hasDefaultChannel`` needs the preset,
    no ``override_frequency`` and the preset's frequency slot (``channel_num``
    0 is taken as that slot; a non-zero one the firmware would count too is
    not recognised). At 2.7.20 to 2.7.26 the slot is not computed yet at
    boot (its initial value is "default"), so ``channel_num`` does not
    matter; before 2.7.20 the check is ``isDefaultChannel`` on the primary
    alone, with no preset or frequency condition. An unparseable version
    ignores ``channel_num``: predicting a floor the firmware does not apply
    only adds a value the verify also accepts.
    """
    live = inputs.live
    lora = inputs.template.lora
    if not any(_is_default_channel(c, preset_name) for c in live.channels):
        return False
    version = parse_firmware_version(live.firmware_version)
    if version is not None and version < BOOT_PRESET_CHECK_MIN_FIRMWARE:
        return True
    if not lora.use_preset or live.value("lora", "override_frequency"):
        return False
    if version is None or version < BOOT_SLOT_CHECK_MIN_FIRMWARE:
        return True
    channel_num = (
        lora.channel_num if lora.channel_num is not None else live.value("lora", "channel_num")
    )
    return not channel_num


def _boot_floors(inputs: PlanInputs) -> dict[tuple[str, str], int]:
    """Return the minimum the firmware raises each interval to at boot.

    ``NodeDB::NodeDB`` (read in the source at 2.7.26, 2.8.0, 2.8.2 and
    2.8.3): the telemetry intervals while a channel is a default channel
    (see :func:`_telemetry_floor_applies`), the position intervals while
    the first channel that shares a position is a default channel. A
    channel counts as sharing when its live or its planned precision is
    non-zero: ``default_channel`` may be written after the commit's reboot.

    Args:
        inputs: The plan inputs, as the node will be after this plan.

    Returns:
        ``{(section, field): floor}``; empty when no floor applies.
    """
    live = inputs.live
    preset_name = _preset_channel_name(inputs)
    router = inputs.template.device.role in BOOT_FLOOR_ROUTER_ROLES
    floors: dict[tuple[str, str], int] = {}

    if _telemetry_floor_applies(inputs, preset_name):
        telemetry_floor = (
            TELEMETRY_INTERVAL_FLOOR_ROUTER_SECS if router else TELEMETRY_INTERVAL_FLOOR_SECS
        )
        floors.update(
            dict.fromkeys(
                (("telemetry", name) for name in TELEMETRY_INTERVAL_FIELDS), telemetry_floor
            )
        )

    sharing = next(
        (c for c in live.channels if c.position_precision or _planned_precision(inputs, c)),
        None,
    )
    if sharing is not None and _is_default_channel(sharing, preset_name):
        floors[("position", "position_broadcast_secs")] = (
            POSITION_BROADCAST_FLOOR_ROUTER_SECS if router else POSITION_BROADCAST_FLOOR_SECS
        )
        floors[("position", "broadcast_smart_minimum_interval_secs")] = (
            SMART_MINIMUM_INTERVAL_FLOOR_SECS
        )
    return floors


def _boot_floor_adjustments(inputs: PlanInputs) -> tuple[FirmwareAdjustment, ...]:
    """Return an adjustment per template interval below its boot floor.

    0 is never raised (it means "the firmware's default",
    ``Default::getConfiguredOrMinimumValue``).
    """
    template = inputs.template
    models = {"telemetry": template.telemetry, "position": template.position}
    adjustments: list[FirmwareAdjustment] = []
    for (section, field), floor in _boot_floors(inputs).items():
        desired = getattr(models[section], field)
        if desired is None or not 0 < desired < floor:
            continue
        warning = PlanWarning(
            PlanWarningCode.INTERVAL_RAISED_AT_BOOT,
            f"{section}.{field} {desired} is below the firmware's minimum of {floor} s on a "
            f"default channel: the node holds {floor} after every boot, and the verify "
            f"accepts that. Set 0 or at least {floor} in the template to clear this warning.",
            section=section,
            field=field,
        )
        adjustments.append(FirmwareAdjustment(section, field, floor, warning))
    return tuple(adjustments)


def _precision_adjustments(inputs: PlanInputs) -> tuple[FirmwareAdjustment, ...]:
    """Return the primary channel's capped position precision, if it is capped.

    ``AdminModule::handleSetChannel`` (2.8.0 and 2.8.3; not at 2.7.26)
    stores at most :data:`PUBLIC_CHANNEL_MAX_POSITION_PRECISION` for a
    channel anyone can decrypt. Older firmware keeps the value, which the
    verify accepts too; an unparseable version counts as 2.8.
    """
    desired = inputs.template.default_channel.position_precision
    primary = next((c for c in inputs.live.channels if c.index == 0), None)
    version = parse_firmware_version(inputs.live.firmware_version)
    if (
        desired is None
        or desired <= PUBLIC_CHANNEL_MAX_POSITION_PRECISION
        or primary is None
        or not primary.public_key
        or (version is not None and version < POSITION_PRECISION_CLAMP_MIN_FIRMWARE)
    ):
        return ()
    cap = PUBLIC_CHANNEL_MAX_POSITION_PRECISION
    warning = PlanWarning(
        PlanWarningCode.POSITION_PRECISION_CAPPED,
        f"default_channel.position_precision {desired} is above {cap}, the most firmware "
        f"2.8 keeps on a channel anyone can decrypt: the node holds {cap}, and the verify "
        "accepts that.",
        section="default_channel",
        field="position_precision",
    )
    return (FirmwareAdjustment("default_channel", "position_precision", cap, warning),)


def _region_change_adjustments(inputs: PlanInputs) -> tuple[FirmwareAdjustment, ...]:
    """Return the ``lora.ignore_mqtt`` adjustment of a region change, if any.

    ``AdminModule`` set_config lora sets ``ignore_mqtt`` when the new
    region has a duty-cycle limit (EU_868 among them): on every region
    change from 2.8.0, on the first region set before, overwriting what
    this run sends. A template ``ignore_mqtt: false`` is set by the next
    run, when the region no longer changes.
    """
    lora = inputs.template.lora
    if lora.ignore_mqtt is not False or _keeps_region(inputs):
        return ()
    warning = PlanWarning(
        PlanWarningCode.REGION_CHANGE_SETS_IGNORE_MQTT,
        f"Changing lora.region to {lora.region} makes the firmware set lora.ignore_mqtt to "
        "true when that region has a duty-cycle limit (EU_868 among them): run "
        "`mesh provision` again afterwards to set the template's false.",
        section="lora",
        field="ignore_mqtt",
    )
    return (FirmwareAdjustment("lora", "ignore_mqtt", True, warning),)


def _tx_power_adjustments(inputs: PlanInputs) -> tuple[FirmwareAdjustment, ...]:
    """Return the ``lora.tx_power`` the firmware stores in place of the template's, if any.

    ``RadioInterface::applyModemConfig`` (2.7.2 through 2.8.3) stores the
    region's :data:`REGION_POWER_LIMITS_DBM` limit for a ``tx_power`` of 0
    and, unless the owner is licensed, for one above that limit; a region
    change applies it to a ``tx_power`` the template leaves alone too. A
    region with no known limit predicts nothing.
    """
    lora = inputs.template.lora
    limit = REGION_POWER_LIMITS_DBM.get(lora.region)
    if (
        lora.tx_power is None
        or limit is None
        or (lora.tx_power != 0 and (lora.tx_power <= limit or inputs.live.is_licensed))
    ):
        return ()
    reason = (
        "0 means the region's limit"
        if lora.tx_power == 0
        else f"{lora.tx_power} dBm is above the limit of {lora.region}"
    )
    warning = PlanWarning(
        PlanWarningCode.TX_POWER_LIMITED_BY_REGION,
        f"lora.tx_power {reason}: the node holds {limit} dBm, and the verify accepts that. "
        f"Set at most {limit} in the template to clear this warning.",
        section="lora",
        field="tx_power",
    )
    return (FirmwareAdjustment("lora", "tx_power", limit, warning),)


def _keeps_region(inputs: PlanInputs) -> bool:
    """Tell whether the plan leaves the live LoRa region as it is."""
    return str(inputs.live.value("lora", "region")) == inputs.template.lora.region


def replaced_role_refusal(inputs: PlanInputs, *, writes_device: bool) -> PlanConflictError | None:
    """Refuse writing a ``REPEATER`` role to firmware that stores ``CLIENT`` instead.

    Every ``device`` write sends the role, and firmware
    :data:`REPEATER_REPLACED_MIN_FIRMWARE` and later replace ``REPEATER``
    on each one (``AdminModule`` set_config device, 2.7.11 through 2.8.3),
    making a store-and-forward client a server as they do, so the write
    could never be verified. An unparseable firmware version
    is refused too: only a version known to be older keeps the role.

    Args:
        inputs: The plan inputs.
        writes_device: Whether the plan writes the ``device`` section.

    Returns:
        The refusal, or ``None``.
    """
    if not writes_device or inputs.template.device.role != "REPEATER":
        return None
    version = parse_firmware_version(inputs.live.firmware_version)
    if version is not None and version < REPEATER_REPLACED_MIN_FIRMWARE:
        return None
    floor = ".".join(str(part) for part in REPEATER_REPLACED_MIN_FIRMWARE)
    return PlanConflictError(
        f"device.role REPEATER: firmware {floor} and later store CLIENT in its place, and "
        "turn store_forward.is_server on when store and forward is enabled "
        f"(this device reports {inputs.live.firmware_version or 'no firmware version'}), so "
        "the write could never be verified.",
        field="device.role",
        hint="Use ROUTER, or CLIENT, for this node in the template.",
    )


def local_admin_refusal(inputs: PlanInputs, *, writes_device: bool) -> PlanConflictError | None:
    """Refuse writing ``rebroadcast_mode: KNOWN_ONLY`` to firmware that then ignores this client.

    Under ``KNOWN_ONLY`` the firmware drops every packet whose sender has
    no user record in its node database (``Router`` ``perhapsDecode``),
    and what the connected client sends comes from node 0, which has
    none. From :data:`KNOWN_ONLY_DROPS_LOCAL_ADMIN_MIN_FIRMWARE` on such a
    packet is dropped whole (``dispatchReceived``, 2.8.0 through 2.8.3;
    seen in the firmware simulator at 2.8.3): once the mode is stored, the
    node takes no admin message over USB, BLE or TCP, so the verify could
    not read the node back and no later run can undo it. 2.7.2 through
    2.7.26 make the same check but still hand the client's packet to the
    modules (the simulator at 2.6.13 and 2.7.26 still answers). An
    unparseable firmware version is refused too.

    Args:
        inputs: The plan inputs.
        writes_device: Whether the plan writes the ``device`` section.

    Returns:
        The refusal, or ``None``.
    """
    if not writes_device or inputs.template.device.rebroadcast_mode != _KNOWN_ONLY:
        return None
    version = parse_firmware_version(inputs.live.firmware_version)
    if version is not None and version < KNOWN_ONLY_DROPS_LOCAL_ADMIN_MIN_FIRMWARE:
        return None
    floor = ".".join(str(part) for part in KNOWN_ONLY_DROPS_LOCAL_ADMIN_MIN_FIRMWARE)
    return PlanConflictError(
        f"device.rebroadcast_mode KNOWN_ONLY: firmware {floor} and later then ignore every "
        "admin message from the connected client (this device reports "
        f"{inputs.live.firmware_version or 'no firmware version'}), so the node could no "
        "longer be configured or verified over USB, BLE or TCP.",
        field="device.rebroadcast_mode",
        hint="Use another rebroadcast_mode, such as LOCAL_ONLY, for this node in the template.",
    )


def custom_modem_refusal(inputs: PlanInputs, *, writes_lora: bool) -> PlanConflictError | None:
    """Refuse sending ``use_preset: false`` with a radio parameter of 0.

    With ``use_preset`` off the firmware takes the radio parameters of
    :data:`CUSTOM_MODEM_FIELDS` from the ``lora`` section, which the
    template cannot set: a ``lora`` write sends the device's own, and a
    node on a preset normally holds 0 for each. 0 is no usable value
    (``RadioInterface::applyModemConfig``): in the firmware simulator a
    ``lora`` section with bandwidth 0 crashed 2.6.13 and stopped 2.7.26,
    and 2.8.3 replaced it. Refused on every firmware version.

    Args:
        inputs: The plan inputs.
        writes_lora: Whether the plan writes the ``lora`` section.

    Returns:
        The refusal, or ``None``.
    """
    if not writes_lora or inputs.template.lora.use_preset:
        return None
    unset = [name for name in CUSTOM_MODEM_FIELDS if not inputs.live.value("lora", name)]
    if not unset:
        return None
    return PlanConflictError(
        "lora.use_preset false: the template cannot set the bandwidth, spread factor or "
        f"coding rate, and this node holds 0 (or nothing) for {', '.join(unset)}, which the "
        "firmware would use or replace with a default of its own, not settings you chose (a "
        "lora section with bandwidth 0 crashed firmware 2.6 and 2.7 in the simulator).",
        field="lora.use_preset",
        hint=(
            "Keep use_preset true in the template, or set this node's own radio parameters "
            "in the Meshtastic app first."
        ),
    )


def known_only_warning(inputs: PlanInputs) -> PlanWarning | None:
    """Warn that ``KNOWN_ONLY`` locks this client out once the firmware is upgraded.

    Firmware older than :data:`KNOWN_ONLY_DROPS_LOCAL_ADMIN_MIN_FIRMWARE`
    keeps taking admin messages in that mode; newer firmware does not
    (see :func:`local_admin_refusal`).

    Args:
        inputs: The plan inputs.

    Returns:
        A ``known_only_ignores_client`` warning when the template sets
        ``KNOWN_ONLY`` and the device reports an older, parseable firmware
        version; else ``None``.
    """
    version = parse_firmware_version(inputs.live.firmware_version)
    if (
        inputs.template.device.rebroadcast_mode != _KNOWN_ONLY
        or version is None
        or version >= KNOWN_ONLY_DROPS_LOCAL_ADMIN_MIN_FIRMWARE
    ):
        return None
    floor = ".".join(str(part) for part in KNOWN_ONLY_DROPS_LOCAL_ADMIN_MIN_FIRMWARE)
    return PlanWarning(
        PlanWarningCode.KNOWN_ONLY_IGNORES_CLIENT,
        f"device.rebroadcast_mode KNOWN_ONLY: firmware {floor} and later ignore every admin "
        "message from the connected client in this mode. Set another mode before upgrading "
        "this node's firmware, or it can no longer be configured over USB, BLE or TCP.",
        section="device",
        field="rebroadcast_mode",
    )


def _changes_role(inputs: PlanInputs) -> bool:
    """Tell whether the plan sets a role the device does not have yet."""
    return str(inputs.live.value("device", "role")) != inputs.template.device.role


def _role_change_adjustments(inputs: PlanInputs) -> tuple[FirmwareAdjustment, ...]:
    """Return the role defaults that replace this run's own template values.

    ``AdminModule`` set_config device runs ``installRoleDefaults`` after
    storing the device section whenever the role changes, overwriting the
    owner's ``is_unmessagable`` written just before and the device fields
    sent with the role. Only template-set fields are adjusted.
    """
    if not _changes_role(inputs):
        return ()
    template = inputs.template
    values = {
        ("device", "rebroadcast_mode"): template.device.rebroadcast_mode,
        ("device", "node_info_broadcast_secs"): template.device.node_info_broadcast_secs,
        ("owner", "is_unmessagable"): template.is_unmessagable,
    }
    defaults = _ROLE_DEFAULT_VALUES.get(template.device.role, {})
    return tuple(
        FirmwareAdjustment(section, field, value)
        for (section, field), value in defaults.items()
        if values[(section, field)] is not None and values[(section, field)] != value
    )


def role_change_warning(inputs: PlanInputs) -> PlanWarning | None:
    """Warn that a role change makes the firmware reset settings to the role's defaults.

    Args:
        inputs: The plan inputs.

    Returns:
        A ``role_defaults_rewrite`` warning naming what the firmware resets
        for the new role, when the plan changes the role to one that has
        defaults (:data:`ROLE_DEFAULT_FIELDS`); else ``None``.
    """
    role = inputs.template.device.role
    if not _changes_role(inputs) or role not in ROLE_DEFAULT_FIELDS:
        return None
    return PlanWarning(
        PlanWarningCode.ROLE_DEFAULTS_REWRITE,
        f"Changing device.role to {role} makes the firmware reset "
        f"{', '.join(ROLE_DEFAULT_FIELDS[role])} to the role's defaults. Sections this run "
        "writes after device keep the template's values, and the verify accepts the role's "
        "own where the role replaced them; run `mesh provision` again afterwards to set "
        "the template's values everywhere.",
        section="device",
        field="role",
    )


def firmware_adjustments(inputs: PlanInputs) -> tuple[FirmwareAdjustment, ...]:
    """Predict every template value the node will hold differently after this plan.

    Args:
        inputs: The plan inputs.

    Returns:
        The adjustments, sorted by section and field name.
    """
    adjustments = (
        *_boot_floor_adjustments(inputs),
        *_region_change_adjustments(inputs),
        *_tx_power_adjustments(inputs),
        *_role_change_adjustments(inputs),
        *_precision_adjustments(inputs),
    )
    return tuple(sorted(adjustments, key=lambda a: (a.section, a.field)))
