"""Writes the firmware refuses or would act on unexpectedly, and the warning before one.

The refusal half of :mod:`~meshprovision.provisioning.plan_firmware`, which
re-exports every public name here: a role the firmware replaces on every
write (:func:`replaced_role_refusal`), a rebroadcast mode in which the
firmware stops listening to this client (:func:`local_admin_refusal`,
and :func:`known_only_warning` before a firmware that would), and a
custom modem the template cannot describe (:func:`custom_modem_refusal`).

Pure, like :mod:`~meshprovision.provisioning.plan`: no I/O, no device
access, and nothing from ``meshtastic``. Firmware references are to
``meshtastic/firmware`` 2.8.3 (``master`` at 51ac6ea) unless a version is
named; nothing here was tried on a device.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from meshprovision.errors import PlanConflictError
from meshprovision.firmware import parse_firmware_version
from meshprovision.provisioning.plan_warnings import PlanWarning, PlanWarningCode

if TYPE_CHECKING:
    from meshprovision.provisioning.plan_types import PlanInputs

__all__ = [
    "CUSTOM_MODEM_FIELDS",
    "KNOWN_ONLY_DROPS_LOCAL_ADMIN_MIN_FIRMWARE",
    "REPEATER_REPLACED_MIN_FIRMWARE",
    "custom_modem_refusal",
    "known_only_warning",
    "local_admin_refusal",
    "replaced_role_refusal",
]

REPEATER_REPLACED_MIN_FIRMWARE: Final[tuple[int, int, int]] = (2, 7, 11)
"""First firmware storing ``CLIENT`` for a ``REPEATER`` role (``AdminModule``; not at 2.7.10)."""

KNOWN_ONLY_DROPS_LOCAL_ADMIN_MIN_FIRMWARE: Final[tuple[int, int, int]] = (2, 8, 0)
"""First firmware that ignores the connected client under ``KNOWN_ONLY`` (``Router``)."""

_KNOWN_ONLY: Final[str] = "KNOWN_ONLY"

CUSTOM_MODEM_FIELDS: Final[tuple[str, ...]] = ("bandwidth", "spread_factor", "coding_rate")
"""The ``LoRaConfig`` radio parameters the firmware uses when ``use_preset`` is off."""


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
