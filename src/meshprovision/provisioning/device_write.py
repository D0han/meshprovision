"""Device writers: one protobuf config section, or the primary channel, per call.

Split out of :mod:`meshprovision.provisioning.apply` for size, with no change
in behavior: :func:`write_section` (one config or module-config section, via
``Node.writeConfig``), :func:`write_default_channel` (the index-0 channel's
module settings, via ``Node.writeChannel(0)``), the per-field converter they
share (:func:`apply_field`), the BLE-PIN generator (:func:`generate_ble_pin`),
and :data:`DEVICE_EXCEPTIONS`, the broad-but-explicit tuple every device-write
site catches. :mod:`meshprovision.provisioning.apply` sequences these writes,
verifies them, and re-exports every public name here unchanged; it remains the
only caller.

Secret hygiene and exception discipline are as documented in
:mod:`meshprovision.provisioning.apply`: nothing here logs a key or a PIN, and
every catch converts to a :class:`~meshprovision.errors.ProvisioningError`
subclass.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Final

from meshprovision.crypto.keys import KeyPair
from meshprovision.db.schema import BLE_PIN_LENGTH
from meshprovision.errors import EnumMappingError, PlanConflictError, ProvisioningError
from meshprovision.provisioning import connection, detect
from meshprovision.provisioning.plan import SectionChange
from meshprovision.provisioning.plan_admin_keys import KeyPlan

if TYPE_CHECKING:
    from meshtastic.mesh_interface import MeshInterface

__all__ = [
    "DEVICE_EXCEPTIONS",
    "apply_field",
    "generate_ble_pin",
    "write_default_channel",
    "write_section",
]

_logger = logging.getLogger(__name__)

DEVICE_EXCEPTIONS: Final[tuple[type[BaseException], ...]] = (
    OSError,
    ValueError,
    TypeError,
    RuntimeError,
    SystemExit,
)
"""Broad-but-explicit tuple caught around every device write.

``SystemExit`` is deliberate: ``meshtastic.util.our_exit()`` calls
``sys.exit(1)``, and ``Node.writeConfig``/``Node.setOwner`` call it on an
unknown section name or an empty name (verified in meshtastic 2.7.11
``util.py``). Catching it here and converting it to a
:class:`~meshprovision.errors.ProvisioningError` is what stops the
library from killing the ``mesh`` process mid-provision.
Every call site also catches
:func:`~meshprovision.provisioning.connection.device_io_errors`, the
shared tuple of library exception types (including a BLE write failure,
``BLEInterface.BLEError``/``BleakError``) a device read/write can raise
besides ``OSError`` & co. That function does its own lazy, cached
import, so a serial/TCP-only run never loads ``bleak`` or
``meshtastic.ble_interface`` (see its docstring). ``SystemExit`` is *not*
part of ``device_io_errors()``: it is caught here, at write time, via
this tuple instead, and deliberately stays out of
:meth:`~meshprovision.provisioning.connection.BLEBackend.connect`'s own
catch tuple, since no connect path meshprovision uses can reach
``our_exit()``.
"""


def generate_ble_pin(*, rng: Callable[[int], int] = secrets.randbelow) -> str:
    """Generate a fresh 6-digit BLE pairing PIN.

    Uses :func:`secrets.randbelow` by default, never the ``random``
    module (this is what a BLE fixed PIN is: a shared secret an attacker
    within range could otherwise brute-force offline if it were
    predictable). The caller passes the result into
    ``PlanInputs.ble_pin`` so that
    :func:`meshprovision.provisioning.plan.build_plan` stays a pure,
    deterministic function of its inputs -- the PIN is generated here,
    once, by the caller, not re-derived inside the pure planning layer.

    Args:
        rng: A function from an exclusive upper bound to a random ``int``
            in ``[0, bound)``. Overridable for deterministic tests.

    Returns:
        A plain ``str`` of exactly :data:`~meshprovision.db.schema.BLE_PIN_LENGTH`
        digits, including any leading zeros. Never logged; the caller
        wraps it in a ``SecretStr``/``SecretBytes`` immediately.
    """
    return "".join(str(rng(10)) for _ in range(BLE_PIN_LENGTH))


def _set_field(message: Any, field: str, value: object) -> None:
    """``setattr`` a validated field value, converting protobuf's own rejection.

    protobuf raises a bare ``ValueError``/``TypeError`` from its generated
    ``__setattr__`` for a value :func:`apply_field` already accepted as
    the right Python type but that is out of the field's own range (an
    unbounded template integer, for example) or otherwise not assignable
    -- neither exception is a :class:`~meshprovision.errors.MeshprovisionError`,
    so left uncaught it would propagate out of :func:`apply_plan` entirely
    rather than degrading to a per-section :class:`WriteResult`.

    Args:
        message: The protobuf message to set ``field`` on.
        field: The field's name on ``message``.
        value: The already-type-selected value to assign.

    Raises:
        PlanConflictError: If protobuf itself rejects ``value`` for
            ``field``.
    """
    try:
        setattr(message, field, value)
    except (ValueError, TypeError) as exc:
        raise PlanConflictError(
            f"Field {field!r} rejected value {value!r}: {exc}", field=field
        ) from exc


def apply_field(message: Any, field: str, value: object) -> None:
    """Apply one field change onto a live protobuf config-section message.

    Args:
        message: A protobuf config or module-config section message (for
            example ``iface.localNode.localConfig.lora``).
        field: The field's name on ``message``.
        value: The desired value: a ``str`` enum-member name for an enum
            field, a numeric string for an integer field, or a plain
            ``bool``/``int``/``float``/``str``/``bytes`` otherwise.

    Raises:
        PlanConflictError: If ``field`` does not exist on ``message``,
            ``value`` is of a type this function does not know how to
            apply, or protobuf itself rejects an otherwise-well-typed
            value (for example an out-of-range integer).
        EnumMappingError: If ``field`` is an enum field and ``value`` is a
            ``str`` that does not name a known enum member.
    """
    from google.protobuf.descriptor import FieldDescriptor

    descriptor = message.DESCRIPTOR.fields_by_name.get(field)
    if descriptor is None:
        raise PlanConflictError(
            f"Unknown field {field!r} on {message.DESCRIPTOR.full_name}", field=field
        )

    if descriptor.type == FieldDescriptor.TYPE_ENUM and isinstance(value, str):
        enum_value = descriptor.enum_type.values_by_name.get(value)
        if enum_value is None:
            known = tuple(v.name for v in descriptor.enum_type.values)
            raise EnumMappingError(
                f"Unknown value {value!r} for enum field {field!r}",
                enum_name=field,
                value=value,
                known=known,
            )
        _set_field(message, field, enum_value.number)
        return

    int_field_types = (
        FieldDescriptor.TYPE_INT32,
        FieldDescriptor.TYPE_INT64,
        FieldDescriptor.TYPE_UINT32,
        FieldDescriptor.TYPE_UINT64,
        FieldDescriptor.TYPE_SINT32,
        FieldDescriptor.TYPE_SINT64,
        FieldDescriptor.TYPE_FIXED32,
        FieldDescriptor.TYPE_FIXED64,
        FieldDescriptor.TYPE_SFIXED32,
        FieldDescriptor.TYPE_SFIXED64,
    )
    if isinstance(value, bool):
        _set_field(message, field, value)
        return
    if isinstance(value, str) and descriptor.type in int_field_types:
        stripped = value.strip()
        if not (stripped.lstrip("-").isdigit()):
            raise PlanConflictError(
                f"Field {field!r} expects an integer, got {value!r}", field=field
            )
        _set_field(message, field, int(stripped))
        return
    if isinstance(value, int | float | str):
        _set_field(message, field, value)
        return
    if isinstance(value, bytes | bytearray):
        _set_field(message, field, bytes(value))
        return

    raise PlanConflictError(
        f"Cannot apply value of type {type(value).__name__} to field {field!r}", field=field
    )


def write_section(
    iface: MeshInterface,
    change: SectionChange,
    *,
    key_plan: KeyPlan | None = None,
    keypair: KeyPair | None = None,
) -> None:
    """Write one config or module-config section to the device.

    Args:
        iface: The connected interface to write through.
        change: The section's field changes to apply.
        key_plan: The plan's key decisions, consulted only when
            ``change.section == "security"``.
        keypair: The freshly generated keypair, required when
            ``key_plan.regenerate`` is set.

    Raises:
        PlanConflictError: If ``change.section`` is not a known config or
            module-config section name, or a field within it cannot be
            applied.
        EnumMappingError: If a field within ``change`` is an enum field
            whose desired value does not name a known enum member --
            propagated straight from :func:`apply_field`.
        ProvisioningError: If the device write itself fails (including a
            ``SystemExit`` raised by ``meshtastic.util.our_exit()``,
            converted here rather than allowed to kill the process).

    On any failure the section's in-memory message is restored to its
    pre-call state (a snapshot taken before any field is applied), so an
    in-place read-back (``--no-reconnect``) never reports an unwritten
    value as confirmed.
    """
    is_config = change.section in detect.CONFIG_SECTIONS
    is_module = change.section in detect.MODULE_SECTIONS
    if not is_config and not is_module:
        raise PlanConflictError(f"Unknown config section {change.section!r}", field=change.section)

    root = iface.localNode.localConfig if is_config else iface.localNode.moduleConfig
    msg = getattr(root, change.section)
    snapshot = type(msg)()
    snapshot.CopyFrom(msg)

    ok = False
    try:
        for field_change in change.changes:
            apply_field(msg, field_change.field, field_change.desired)

        if change.section == "security" and key_plan is not None:
            if key_plan.regenerate:
                if keypair is None:
                    raise PlanConflictError(
                        "Plan requires a fresh keypair but none was supplied",
                        field="security.private_key",
                    )
                msg.private_key = keypair.private.reveal()
                msg.public_key = keypair.public
            if key_plan.change_admin_keys:
                del msg.admin_key[:]
                msg.admin_key.extend(key_plan.desired_admin_keys)

        try:
            iface.localNode.writeConfig(change.section)
        except (*DEVICE_EXCEPTIONS, *connection.device_io_errors()) as exc:
            raise ProvisioningError(
                f"Failed to write config section {change.section!r}: {exc}"
            ) from exc
        ok = True
    finally:
        if not ok:
            msg.CopyFrom(snapshot)

    _logger.info("Wrote config section %s (%d fields)", change.section, len(change.changes))


def write_default_channel(iface: MeshInterface, change: SectionChange) -> None:
    """Write the primary (index-0) channel's module settings to the device.

    A completely different admin message than :func:`write_section`'s
    ``writeConfig()`` -- ``default_channel`` lives on
    ``iface.localNode.channels[0].settings.module_settings``, written via
    ``Node.writeChannel(0)``/``AdminMessage.set_channel``. Never wrapped in
    the settings transaction :func:`apply_plan` opens for config/module
    sections.

    Args:
        iface: The connected interface to write through.
        change: The section's field changes to apply. Must be the
            ``"default_channel"`` section.

    Raises:
        ProvisioningError: If the device write itself fails.
        PlanConflictError: Before any device write, if the primary
            channel is unavailable or disabled, or a field within
            ``change`` cannot be applied (propagated from
            :func:`apply_field`).

    On any failure the section's in-memory message is restored to its
    pre-call state (a snapshot taken before any field is applied), so an
    in-place read-back (``--no-reconnect``) never reports an unwritten
    value as confirmed -- the same contract :func:`write_section` offers.
    """
    from meshtastic.protobuf import channel_pb2

    # Refused before any I/O, so apply_plan never counts it as attempted.
    # writeChannel(0) sends the whole channel: a DISABLED one (the role the
    # library gives a channel the device never reported, and what detect
    # reads as "no settings") would be overwritten with a near-empty one.
    channel = iface.localNode.getChannelByChannelIndex(0)
    if channel is None:
        raise PlanConflictError(
            "Primary channel (index 0) is not available on this device", field="default_channel"
        )
    if channel.role == channel_pb2.Channel.Role.DISABLED:
        raise PlanConflictError(
            "Primary channel (index 0) is disabled on this device; refusing to write "
            "default_channel",
            field="default_channel",
        )

    msg = channel.settings.module_settings
    snapshot = type(msg)()
    snapshot.CopyFrom(msg)
    ok = False
    try:
        for field_change in change.changes:
            apply_field(msg, field_change.field, field_change.desired)
        try:
            iface.localNode.writeChannel(0)
        except (*DEVICE_EXCEPTIONS, *connection.device_io_errors()) as exc:
            raise ProvisioningError(f"Failed to write default_channel: {exc}") from exc
        ok = True
    finally:
        if not ok:
            msg.CopyFrom(snapshot)

    _logger.info("Wrote default_channel (%d fields)", len(change.changes))
