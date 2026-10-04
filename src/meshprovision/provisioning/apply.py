"""Transactional plan execution against a live device, and the ODS write gate.

This module is the only place in the project that *writes* protobuf
config to a device (:mod:`meshprovision.provisioning.detect` is the only
place that *reads* one). :func:`apply_plan` executes a
:class:`~meshprovision.provisioning.plan.ChangePlan` with a
write-then-read-back-verify guarantee: every section written is
re-confirmed from a fresh reconnect before the ``Nodes``/``Keys`` sheets
are ever touched, and :func:`persist_result` is the single gate that
decides whether the ODS may be updated at all -- it refuses outright when
any write is left in an uncertain state.

This module also owns the BLE-PIN generator (:func:`generate_ble_pin`),
since a PIN is provisioning-time-generated secret material with the same
write-then-verify lifecycle as an admin key.

**Session management and outcome types** (``WriteStatus``,
``WriteResult``, ``ApplyOutcome``, the ``DeviceSession`` protocol,
``ReconnectingSession``, ``InPlaceSession``) live in
:mod:`meshprovision.provisioning.apply_session` -- this module imports
and re-exports every one of them via ``__all__`` unchanged, so a caller
may still import any of them from here.

Secret hygiene: nothing in this module ever logs, prints, or otherwise
renders raw key bytes, base64 key strings, or a BLE PIN. Every
human-facing representation of a secret field goes through
:func:`meshprovision.crypto.redact.fingerprint` first; ``WriteResult``
and :class:`~meshprovision.errors.WriteVerificationError` document
``expected``/``actual`` as always-redacted strings.

Exception discipline: the only broad ``except`` in this module is
:data:`_DEVICE_EXCEPTIONS` plus
:func:`~meshprovision.provisioning.connection.device_io_errors`, which
exists specifically because ``meshtastic.util.our_exit()`` -- called by
``Node.writeConfig`` and ``Node.setOwner`` on a bad section name or an
empty name -- raises ``SystemExit``, and letting that propagate would
kill the ``mesh`` process mid-provision. ``device_io_errors()`` adds the
library exception types a device read/write can raise besides
``OSError`` & co, including a BLE write failure
(``BLEInterface.BLEError``/``BleakError``), which otherwise escapes as a
raw traceback since it is not an ``OSError`` subclass. Every catch
converts to a :class:`~meshprovision.errors.ProvisioningError` subclass
or a ``WriteResult``; nothing here ever does a bare ``except Exception``.
"""

from __future__ import annotations

import hmac
import logging
import secrets
import time
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime
from typing import TYPE_CHECKING, Any, Final

from meshprovision.crypto import redact
from meshprovision.crypto.keys import KeyPair
from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRepository
from meshprovision.db.schema import BLE_PIN_LENGTH, KeyOrigin
from meshprovision.errors import (
    AtomicWriteError,
    ConnectionBackendError,
    DbConcurrentModificationError,
    DetectionError,
    EnumMappingError,
    PlanConflictError,
    ProvisioningError,
)
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import connection, detect
from meshprovision.provisioning.apply_session import (
    DEFAULT_RECONNECT_ATTEMPTS,
    DEFAULT_SETTLE_SECONDS,
    ApplyOutcome,
    DeviceSession,
    InPlaceSession,
    ReconnectingSession,
    WriteResult,
    WriteStatus,
)
from meshprovision.provisioning.plan import ChangePlan, SectionChange
from meshprovision.provisioning.plan_admin_keys import KeyPlan
from meshprovision.provisioning.readback import verify_plan

if TYPE_CHECKING:
    from meshtastic.mesh_interface import MeshInterface

__all__ = [
    "DEFAULT_RECONNECT_ATTEMPTS",
    "DEFAULT_SETTLE_SECONDS",
    "ApplyOutcome",
    "DeviceSession",
    "InPlaceSession",
    "ReconnectingSession",
    "WriteResult",
    "WriteStatus",
    "apply_field",
    "apply_plan",
    "generate_ble_pin",
    "persist_result",
    "write_default_channel",
    "write_section",
]

_logger = logging.getLogger(__name__)

_DEVICE_EXCEPTIONS: Final[tuple[type[BaseException], ...]] = (
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
besides ``OSError`` & co. That function does its own lazy import, since
importing ``meshtastic``/``bleak`` at module level would violate this
layer's protobuf-confinement rule for every *other* module that is not
``detect.py``/``apply.py``/``connection.py``. ``SystemExit`` is *not*
part of ``device_io_errors()``: it is caught here, at write time, via
this tuple instead, and deliberately stays out of
:meth:`~meshprovision.provisioning.connection.BLEBackend.connect`'s own
catch tuple, since no connect path meshprovision uses can reach
``our_exit()``.
"""

_VERIFY_READBACK_EXCEPTIONS: Final[tuple[type[BaseException], ...]] = (
    DetectionError,
    *_DEVICE_EXCEPTIONS,
)
""":data:`_DEVICE_EXCEPTIONS` plus :class:`DetectionError`, for the one
read-back site (:func:`apply_plan`'s post-write verify) that can also
fail to *parse* what a successful reconnect read. Kept as its own
homogeneous, unbounded tuple so it star-unpacks cleanly alongside
:func:`~meshprovision.provisioning.connection.device_io_errors` -- mypy
does not accept a tuple literal that mixes a bare exception name with a
starred unpack of a runtime-computed tuple.
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
        except (*_DEVICE_EXCEPTIONS, *connection.device_io_errors()) as exc:
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
        except (*_DEVICE_EXCEPTIONS, *connection.device_io_errors()) as exc:
            raise ProvisioningError(f"Failed to write default_channel: {exc}") from exc
        ok = True
    finally:
        if not ok:
            msg.CopyFrom(snapshot)

    _logger.info("Wrote default_channel (%d fields)", len(change.changes))


def _confirmed_name(results: Sequence[WriteResult], field: str) -> str | None:
    """Find the truncated name a CONFIRMED ``owner`` write actually landed as.

    ``persist_result`` must record what firmware confirmed is really on
    the device, not what the plan wanted -- a name write that firmware
    silently truncated is reported CONFIRMED (see
    :func:`~meshprovision.provisioning.readback._verify_name`)
    since the write genuinely succeeded, but the plan's own *desired*
    value is longer than what the device actually holds. Persisting the
    desired value instead of the confirmed one would make the next run
    re-diff against a name the device doesn't have, re-plan the same
    rewrite, get truncated again, and never converge.

    Args:
        results: The verified write results from
            :func:`~meshprovision.provisioning.readback.verify_plan`.
        field: ``"short_name"`` or ``"long_name"``.

    Returns:
        The truncated name actually confirmed on the device, or ``None``
        when this field's write was an exact match (or wasn't part of the
        plan at all) -- callers fall back to the plan's desired value in
        that case.
    """
    for result in results:
        if result.section == "owner" and result.field == field and result.actual is not None:
            return result.actual
    return None


def _run_name_phase(iface: MeshInterface, plan: ChangePlan) -> WriteResult | None:
    """Execute the name (owner) phase of a plan.

    Always passes ``is_licensed=plan.name_change.desired_is_licensed``
    (which always equals the device's current live value -- see
    :class:`~meshprovision.provisioning.plan_types.NameChange`) so this
    write never resets it to ``Node.setOwner``'s own ``False`` default.
    ``is_unmessagable`` is passed through unconditionally too;
    ``Node.setOwner`` only touches the device's value when it is not
    ``None``, so this is a no-op whenever neither the template nor the
    live device has ever set one.

    Args:
        iface: The connected interface to write through.
        plan: The plan whose ``name_change`` should be applied.

    Returns:
        A :class:`WriteResult` describing a failure, or ``None`` when the
        name phase was empty or succeeded (verification happens later,
        in :func:`~meshprovision.provisioning.readback.verify_plan`).
    """
    if plan.name_change.is_empty:
        return None

    try:
        iface.localNode.setOwner(
            long_name=plan.name_change.desired_long_name,
            short_name=plan.name_change.desired_short_name,
            is_licensed=plan.name_change.desired_is_licensed,
            is_unmessagable=plan.name_change.desired_is_unmessagable,
        )
    except (*_DEVICE_EXCEPTIONS, *connection.device_io_errors()) as exc:
        return WriteResult("owner", WriteStatus.FAILED, f"Failed to set owner: {exc}")
    return None


def _backend_error_detail(exc: ConnectionBackendError) -> str:
    """Render a single-line detail string for a failed reconnect, including any hint.

    ``str(exc)`` alone drops the hint (see ``MeshprovisionError.__str__``),
    and ``user_message`` isn't right here either -- it inserts a newline
    before the hint, which would break the CLI's one-line
    ``label: FAILED -- message`` rendering.

    Args:
        exc: The reconnect failure to describe.

    Returns:
        ``f"{exc} (hint: {exc.hint})"`` when a hint is set, else ``str(exc)``.
    """
    if exc.hint:
        return f"{exc} (hint: {exc.hint})"
    return str(exc)


def _identity_mismatch(plan: ChangePlan, got: NodeId) -> WriteResult:
    """Build the ``FAILED`` result for a reconnect that answered as a different node.

    Scope note: this is an accidental-swap detector, not an
    authentication control. A node number is not a credential --
    :mod:`meshprovision.provisioning.plan`'s admin-key-identity checks
    (``node_key_admin_refs``) are what refuse a *deliberate* impostor
    that reports the expected node number. This check only catches the
    device physically answering the reconnect being a different one than
    the plan was built for (a bench "unplug, plug next" mixup, or a
    serial path re-enumerating onto a different device).

    Args:
        plan: The plan being applied.
        got: The node id the reconnected device actually reported.

    Returns:
        A ``"<verify>"`` :class:`WriteResult` with
        :attr:`WriteStatus.FAILED`.
    """
    return WriteResult(
        "<verify>",
        WriteStatus.FAILED,
        f"reconnected to a different node ({got.display}) than this plan was built for "
        f"({plan.node_id.display}); stopped",
    )


def _skip_unwritten(sections: Iterable[str], reason: str) -> list[WriteResult]:
    """Record each of ``sections`` as never sent to the device.

    Only for sections no write was ever attempted for -- a section that
    may have reached the device is never reported "not written" (see
    :func:`_unconfirmed_after_failed_commit`).

    Args:
        sections: Section names (``"owner"`` for the name phase).
        reason: Why they were not written, completing ``"not written: ..."``.

    Returns:
        One :attr:`WriteStatus.SKIPPED` result per section, in order.
    """
    return [WriteResult(s, WriteStatus.SKIPPED, f"not written: {reason}") for s in sections]


def _unconfirmed_after_failed_commit(
    plan: ChangePlan, results: Sequence[WriteResult], attempted: Sequence[str]
) -> list[WriteResult]:
    """Report everything sent before a failed commit as uncertain, never as unwritten.

    The commit may have landed even though it raised (the bytes may have
    left the host). Nothing is re-read either: an open transaction holds
    its writes in memory only, so a reconnect could read back values a
    reboot then discards.

    Args:
        plan: The plan being applied.
        results: The results recorded so far; a section that already has
            one (its own write failed) is not reported twice.
        attempted: The sections whose write was sent, in order.

    Returns:
        One :attr:`WriteStatus.UNCONFIRMED` result per sent section with
        no result yet, the owner phase first.
    """
    recorded = {r.section for r in results}
    sent = ([] if plan.name_change.is_empty else ["owner"]) + list(attempted)
    return [
        WriteResult(
            section,
            WriteStatus.UNCONFIRMED,
            "sent outside the settings transaction; not verified because the commit failed"
            if section == "default_channel"
            else "sent inside the settings transaction, but the commit failed; "
            "the device may or may not have saved it",
        )
        for section in sent
        if section not in recorded
    ]


def _possible_node_renumber(
    plan: ChangePlan, live_after: detect.LiveConfig, *, keypair: KeyPair | None
) -> WriteResult | None:
    """Give the unverified firmware-2.8 node-renumber case its own diagnostic.

    Firmware 2.8 may derive a node's number from its public key
    (unverified against source -- see the project's firmware-2.8 notes).
    If that is true, a key regeneration on the *same* physical device can
    make the final-verify reconnect land on a new node number that looks
    exactly like a device swap to :func:`_identity_mismatch`. This
    function narrows that case: the device the reconnect actually
    answered from holds the private key this process just generated, a
    secret that exists nowhere else. That is strong evidence it is the
    same device, just reporting a new number -- so the message tells the
    operator that, instead of sending them hunting for a swap that never
    happened.

    This is diagnostic text only. It does not weaken the refusal: either
    way the database is not updated, and re-keying a database row to a
    new node id is never done automatically.

    Args:
        plan: The plan being applied.
        live_after: The freshly re-read live configuration from the
            device that answered the reconnect.
        keypair: The freshly generated keypair, when the plan regenerated
            one.

    Returns:
        The distinct ``"<verify>"`` :class:`WriteResult` when the
        evidence matches; otherwise ``None`` (the caller falls back to
        :func:`_identity_mismatch`'s ordinary message).
    """
    if not (
        plan.key_plan.regenerate
        and keypair is not None
        and live_after.security.private_key is not None
        and hmac.compare_digest(live_after.security.private_key.reveal(), keypair.private.reveal())
    ):
        return None
    return WriteResult(
        "<verify>",
        WriteStatus.FAILED,
        f"the device now reports node {live_after.node_id.display} but holds the keypair "
        "this run generated. Its node number appears to have changed (firmware 2.8+ "
        "derives it from the public key); stopped; the database was NOT updated",
    )


def apply_plan(
    plan: ChangePlan,
    session: DeviceSession,
    *,
    keypair: KeyPair | None = None,
    dry_run: bool = False,
    settle_seconds: float = DEFAULT_SETTLE_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    on_reconnect: Callable[[], None] | None = None,
) -> ApplyOutcome:
    """Execute a change plan against a live device with a write-then-verify guarantee.

    Never raises for a verification mismatch: the caller inspects
    :attr:`ApplyOutcome.exit_code`, :attr:`ApplyOutcome.may_update_database`,
    or :meth:`ApplyOutcome.failures`. It does propagate a lost reconnect
    as an uncertain outcome (never as an exception) -- a device that
    cannot be re-read is by definition unverified, and the ODS must not
    be written.

    Writes the owner (name) phase and every non-``security``,
    non-``default_channel`` section inside one settings transaction
    (``beginSettingsTransaction()`` / ``commitSettingsTransaction()``),
    opened only when there is something to write in it -- a plan whose
    only sections are ``security``/``default_channel`` writes them
    directly, with no transaction at all. This mirrors the upstream
    meshtastic CLI: an untransacted ``writeConfig`` implicitly saves and
    reboots the device after *every* section, not only ones this project
    models as ``reboots_device``, so wrapping these writes in one
    transaction means only the commit reboots the device, once.
    The transaction is committed exactly once, unconditionally, even when
    a section failed partway through (:attr:`SectionChange.reboots_device`
    plays no role in this any more -- it remains a plan-rendering/display
    field only). ``default_channel`` is never part of this transaction at
    all, regardless of session kind: :func:`write_default_channel` sends
    ``AdminMessage.set_channel`` via ``Node.writeChannel()``, structurally
    unrelated to ``begin``/``commitSettingsTransaction()`` (which only
    ever affect ``writeConfig``). When :attr:`DeviceSession.reads_back` is
    ``True`` (the normal, reconnecting session), ``default_channel`` and
    ``security`` are both deferred past the commit, written in that order
    on a freshly reconnected interface -- this reuses the *existing*
    post-commit reconnect+identity-check that otherwise exists solely to
    gate the deferred ``security`` write; no new reconnect is invented for
    ``default_channel``. This is the conservative choice given
    ``writeChannel``'s reboot behavior is unverified against real
    firmware: if it does trigger an unexpected reboot, every config/module
    field has already safely landed (the transaction already committed),
    and the reboot is caught by the same reconnect+identity-check machinery
    ``security`` already relies on. When ``reads_back`` is ``False``
    (``InPlaceSession``/``--no-reconnect``), both ``default_channel`` and
    ``security`` are written in their natural :data:`~meshprovision.
    provisioning.plan.SECTION_ORDER` position within the single untransacted
    loop instead (``default_channel`` still never touches the transaction
    itself, it just runs in the same pass): a non-reconnecting session
    cannot safely commit and then send further writes to a device that may
    still be rebooting from that commit, since ``InPlaceSession.refresh()``
    cannot wait out a real reboot or obtain a fresh handle.

    Stops on the first failure: once the name phase or any section fails
    to write, every remaining section (``default_channel``/``security``
    included) is recorded :attr:`WriteStatus.SKIPPED` and never sent to
    the device -- a ``default_channel`` failure cascades into ``security``
    being skipped the same way any other section's failure does. This is
    what enforces :data:`~meshprovision.provisioning.plan.SECTION_ORDER`'s
    documented invariant -- without it, a later section (not only
    ``security``) could still land after an earlier one failed, including
    one that locks the node against further management. The final verify
    pass only checks sections that were actually attempted (see
    :func:`~meshprovision.provisioning.readback.verify_plan`'s
    ``attempted_sections``).

    Every way this function returns early still accounts for each part of
    the plan that never reached the device: those sections (and the owner
    phase) are recorded SKIPPED with a "not written: ..." message, so the
    caller can list exactly what was not written. A failed
    ``beginSettingsTransaction()`` skips the owner phase and every section.
    A stop after the commit (a failed mid-plan reconnect or identity check)
    skips whatever was deferred past it -- ``default_channel`` as well as
    ``security``. Sections already committed by then carry no result of
    their own; the ``"<verify>"`` failure stands for them. A failed
    ``commitSettingsTransaction()`` is the exception: everything already
    sent is recorded :attr:`WriteStatus.UNCONFIRMED` (the commit may or may
    not have landed), anything deferred is SKIPPED, and nothing is re-read
    -- an open transaction holds its writes in memory only, so a read-back
    could confirm values a reboot then loses.

    Every reconnect (the one mid-plan refresh right after committing the
    transaction, when ``default_channel``/``security`` remain to be
    written on a reconnecting session, and the final verify) also confirms
    the device that answered is still the same node the plan was built
    for, via :func:`~meshprovision.provisioning.detect.read_node_id`. That
    mid-plan refresh -- and the identity check that follows it -- is gated
    purely on whether a ``security`` section is present and the session
    reads back (see ``defer_security`` below); ``default_channel`` rides
    along on that same gate rather than having one of its own. So it is
    skipped entirely when the plan has no ``security`` section at all
    (even if it has a ``default_channel`` one -- that case writes
    ``default_channel`` untransacted, in its natural
    :data:`~meshprovision.provisioning.plan.SECTION_ORDER` position,
    with no deferral and no extra reconnect), on a non-reconnecting
    session, or when an earlier failure already means both
    ``default_channel`` and ``security`` will be skipped. A mismatch is an
    unconditional, unbypassable hard stop: nothing further is written, no
    result claims a confirmed write, and
    :attr:`ApplyOutcome.may_update_database` is ``False``. There is no
    legitimate workflow where the connected node's id changes mid-run --
    ``ReconnectingSession`` exists only to re-read the same device -- and
    this scope is deliberately narrow: it catches an *accidental* swap
    (a bench mixup, a serial path re-enumerating), not a deliberate
    impostor that reports the expected node number, which is
    :mod:`~meshprovision.provisioning.plan`'s admin-key-identity gate's
    territory, not this one's.

    Args:
        plan: The change plan to execute.
        session: The device session to write and re-read through.
        keypair: The freshly generated keypair, required when
            ``plan.key_plan.regenerate`` is set. The caller may also pass
            the device's own already-existing keypair when
            ``plan.key_plan.adopt_device_key`` is set instead -- this
            function never writes or verifies it (nothing changed on the
            device to verify against), but the same value flows through
            to :func:`persist_result`, which does record it.
        dry_run: When ``True``, no device writes are attempted; every
            result is :attr:`WriteStatus.SKIPPED`.
        settle_seconds: Pause before the one mid-plan reconnect (after
            committing the settings transaction, before ``security``),
            and again before the final verification reconnect.
        sleep: Sleep function, injectable for tests.
        on_reconnect: Called right before each ``session.refresh()`` --
            covers the quiet several-second window during which a reboot
            reconnect happens, so a caller with a CLI context can warn an
            operator not to unplug or swap the device while it waits.
            ``apply.py`` has no CLI context of its own, so this stays a
            plain callback.

    Returns:
        The full :class:`ApplyOutcome`.

    Raises:
        PlanConflictError: If ``plan.key_plan.regenerate`` is set but
            ``keypair`` is ``None``. Raised before any write is attempted.
    """
    if plan.key_plan.regenerate and keypair is None:
        raise PlanConflictError(
            "Plan requires a fresh keypair but none was supplied", field="security.private_key"
        )

    if plan.is_empty:
        # Nothing to write or verify -- but a real (non-dry-run) apply of an
        # empty plan still counts as a successful, certain outcome, so the
        # caller's persist_result can refresh the ODS's last_updated_ts.
        return ApplyOutcome(
            node_id=plan.node_id,
            results=(),
            dry_run=dry_run,
            verified=False,
            record=None if dry_run else plan.to_record(),
        )

    if dry_run:
        skipped: list[WriteResult] = []
        if not plan.name_change.is_empty:
            skipped.append(WriteResult("owner", WriteStatus.SKIPPED, "dry run"))
        for change in plan.sections:
            skipped.append(WriteResult(change.section, WriteStatus.SKIPPED, "dry run"))
        return ApplyOutcome(
            node_id=plan.node_id, results=tuple(skipped), dry_run=True, verified=False
        )

    results: list[WriteResult] = []
    attempted: list[str] = []
    stop_reason: str | None = None
    iface = session.interface

    security_section = plan.section("security")
    channel_section = plan.section("default_channel")
    non_security_sections = tuple(
        s for s in plan.sections if s.section not in ("security", "default_channel")
    )
    needs_transaction = (not plan.name_change.is_empty) or any(
        not s.is_empty for s in non_security_sections
    )

    if needs_transaction:
        try:
            iface.localNode.beginSettingsTransaction()
        except (*_DEVICE_EXCEPTIONS, *connection.device_io_errors()) as exc:
            results.append(
                WriteResult(
                    "<verify>", WriteStatus.FAILED, f"Could not begin a settings transaction: {exc}"
                )
            )
            results.extend(
                _skip_unwritten(
                    [
                        *([] if plan.name_change.is_empty else ["owner"]),
                        *(s.section for s in plan.sections),
                    ],
                    "could not begin a settings transaction",
                )
            )
            return ApplyOutcome(
                node_id=plan.node_id,
                results=tuple(results),
                dry_run=False,
                verified=True,
                security_attempted=False,
            )

    # Only a reconnecting session defers `security` to its own write,
    # after the transaction commits -- see this function's docstring for
    # why a non-reconnecting session (InPlaceSession/--no-reconnect) must
    # keep it inside the one transaction instead. Short-circuits before
    # ever touching `session.reads_back` when there's no transaction (a
    # security-only plan) or no `security` section at all.
    defer_security = needs_transaction and security_section is not None and session.reads_back
    sections_to_write = non_security_sections if defer_security else plan.sections
    # What a reconnecting session holds back until after the commit, in write order.
    deferred = (
        tuple(s.section for s in (channel_section, security_section) if s is not None)
        if defer_security
        else ()
    )

    commit_exc: BaseException | None = None
    body_finished = False
    try:
        name_failure = _run_name_phase(iface, plan)
        if name_failure is not None:
            results.append(name_failure)
            stop_reason = "the owner (name) write failed"

        for change in sections_to_write:
            if stop_reason is not None:
                # SECTION_ORDER's invariant ("security is always last") is
                # enforced here: once anything upstream has failed, nothing
                # further is written -- security included, since it is not
                # the only section that can restrict later management (e.g.
                # serial_enabled). A re-run always re-plans fresh from the
                # device, so stopping loses no correctness, only progress on
                # a run that is already uncertain.
                results.append(
                    WriteResult(
                        change.section,
                        WriteStatus.SKIPPED,
                        f"not written: stopped because {stop_reason}",
                    )
                )
                continue

            try:
                if change.section == "default_channel":
                    write_default_channel(iface, change)
                else:
                    write_section(iface, change, key_plan=plan.key_plan, keypair=keypair)
            except (PlanConflictError, EnumMappingError) as exc:
                # Pre-I/O failure: apply_field rejected the plan before any
                # device write was attempted, so this section was never even
                # sent. PlanConflictError is a ProvisioningError subclass, so
                # this arm must come first.
                results.append(
                    WriteResult(change.section, WriteStatus.FAILED, f"not written: {exc}")
                )
                stop_reason = f"{change.section} could not be written"
                continue
            except ProvisioningError as exc:
                # The write call itself failed -- the bytes may have left the
                # host, so this section IS counted as attempted.
                attempted.append(change.section)
                results.append(
                    WriteResult(
                        change.section,
                        WriteStatus.FAILED,
                        f"{exc} (the device may or may not have applied it)",
                    )
                )
                stop_reason = f"the {change.section} write failed"
                continue

            attempted.append(change.section)
        body_finished = True
    finally:
        # Unconditional once opened, even when a section above failed
        # partway through: an untransacted write saves (and reboots) after
        # every section, so a transaction left open would otherwise leave
        # whatever already reached the device un-persisted.
        if needs_transaction:
            try:
                iface.localNode.commitSettingsTransaction()
            except (*_DEVICE_EXCEPTIONS, *connection.device_io_errors()) as exc:
                commit_exc = exc
                if not body_finished:
                    # Another exception is already propagating and wins;
                    # without this the commit failure would vanish.
                    _logger.warning("Could not commit the settings transaction: %s", exc)

    if commit_exc is not None:
        results.append(
            WriteResult(
                "<verify>",
                WriteStatus.FAILED,
                f"Could not commit the settings transaction: {commit_exc}",
            )
        )
        results.extend(_unconfirmed_after_failed_commit(plan, results, attempted))
        results.extend(
            _skip_unwritten(
                deferred, "stopped because the settings transaction could not be committed"
            )
        )
        return ApplyOutcome(
            node_id=plan.node_id,
            results=tuple(results),
            dry_run=False,
            verified=True,
            # In-place, security was written inside the transaction.
            security_attempted="security" in attempted,
        )

    if defer_security:
        if stop_reason is not None:
            results.extend(_skip_unwritten(deferred, f"stopped because {stop_reason}"))
        else:
            # The commit above is what actually reboots the device (not any
            # individual section write any more) -- this is the one mid-plan
            # reconnect, covering that reboot before `security` is sent.
            sleep(settle_seconds)
            if on_reconnect is not None:
                on_reconnect()
            try:
                iface = session.refresh()
            except ConnectionBackendError as exc:
                results.append(
                    WriteResult(
                        "<verify>",
                        WriteStatus.FAILED,
                        "Could not reconnect after committing settings to continue the "
                        f"plan: {_backend_error_detail(exc)}; stopped",
                    )
                )
                results.extend(
                    _skip_unwritten(
                        deferred,
                        "stopped because the device could not be reconnected after "
                        "committing settings",
                    )
                )
                return ApplyOutcome(
                    node_id=plan.node_id,
                    results=tuple(results),
                    dry_run=False,
                    verified=True,
                    security_attempted=False,
                )

            # Confirm the device that answered this reconnect is still the
            # one this plan was built for, before `security` -- the freshly
            # generated keypair and admin keys -- is ever sent. Unconditional:
            # no override flag, per this project's rule for identity-sensitive
            # operations (see this function's docstring).
            try:
                got = detect.read_node_id(iface)
            except (*_VERIFY_READBACK_EXCEPTIONS, *connection.device_io_errors()) as exc:
                results.append(
                    WriteResult(
                        "<verify>",
                        WriteStatus.FAILED,
                        "reconnected, but could not confirm the node's identity before "
                        f"continuing: {exc}; stopped",
                    )
                )
                results.extend(
                    _skip_unwritten(
                        deferred,
                        "stopped because the node's identity could not be confirmed after "
                        "reconnecting",
                    )
                )
                return ApplyOutcome(
                    node_id=plan.node_id,
                    results=tuple(results),
                    dry_run=False,
                    verified=True,
                    security_attempted=False,
                )
            if got != plan.node_id:
                results.append(_identity_mismatch(plan, got))
                results.extend(
                    _skip_unwritten(deferred, "stopped after reconnecting to a different node")
                )
                return ApplyOutcome(
                    node_id=plan.node_id,
                    results=tuple(results),
                    dry_run=False,
                    verified=True,
                    security_attempted=False,
                )

            # default_channel also shares this reconnect rather than getting
            # its own: it lands here, immediately before security, so a
            # channel-write failure cascades into security being SKIPPED via
            # the same stop_reason mechanism every other section already uses.
            if channel_section is not None:
                try:
                    write_default_channel(iface, channel_section)
                except (PlanConflictError, EnumMappingError) as exc:
                    results.append(
                        WriteResult("default_channel", WriteStatus.FAILED, f"not written: {exc}")
                    )
                    stop_reason = "default_channel could not be written"
                except ProvisioningError as exc:
                    attempted.append("default_channel")
                    results.append(
                        WriteResult(
                            "default_channel",
                            WriteStatus.FAILED,
                            f"{exc} (the device may or may not have applied it)",
                        )
                    )
                    stop_reason = "the default_channel write failed"
                else:
                    attempted.append("default_channel")

            if stop_reason is not None:
                results.extend(_skip_unwritten(["security"], f"stopped because {stop_reason}"))
            else:
                assert security_section is not None  # noqa: S101 -- defer_security already guards this
                try:
                    write_section(iface, security_section, key_plan=plan.key_plan, keypair=keypair)
                except (PlanConflictError, EnumMappingError) as exc:
                    results.append(
                        WriteResult("security", WriteStatus.FAILED, f"not written: {exc}")
                    )
                    stop_reason = "security could not be written"
                except ProvisioningError as exc:
                    attempted.append("security")
                    results.append(
                        WriteResult(
                            "security",
                            WriteStatus.FAILED,
                            f"{exc} (the device may or may not have applied it)",
                        )
                    )
                    stop_reason = "the security write failed"
                else:
                    attempted.append("security")

    security_attempted = "security" in attempted

    sleep(settle_seconds)
    if on_reconnect is not None:
        on_reconnect()
    try:
        fresh_iface = session.refresh()
    except ConnectionBackendError as exc:
        results.append(
            WriteResult(
                "<verify>",
                WriteStatus.FAILED,
                f"Could not reconnect to verify the writes: {_backend_error_detail(exc)}",
            )
        )
        return ApplyOutcome(
            node_id=plan.node_id,
            results=tuple(results),
            dry_run=False,
            verified=True,
            security_attempted=security_attempted,
        )

    try:
        live_after = detect.read_live_config(fresh_iface)
        device_pub = fresh_iface.getPublicKey()
    except (*_VERIFY_READBACK_EXCEPTIONS, *connection.device_io_errors()) as exc:
        results.append(
            WriteResult(
                "<verify>",
                WriteStatus.FAILED,
                f"Reconnected, but could not read back the device state to verify: {exc}",
            )
        )
        return ApplyOutcome(
            node_id=plan.node_id,
            results=tuple(results),
            dry_run=False,
            verified=True,
            security_attempted=security_attempted,
        )

    if live_after.node_id != plan.node_id:
        # Never run verify_plan against another device: its comparisons
        # would be meaningless, and a CONFIRMED line would be actively
        # misleading. 3b: when this run generated a keypair that the
        # reconnected device -- despite the different node number --
        # actually holds, that is the unverified firmware-2.8
        # node-renumber case, not a swap; give it a distinct message, but
        # the refusal to persist is identical either way.
        results.append(
            _possible_node_renumber(plan, live_after, keypair=keypair)
            or _identity_mismatch(plan, live_after.node_id)
        )
        return ApplyOutcome(
            node_id=plan.node_id,
            results=tuple(results),
            dry_run=False,
            verified=True,
            security_attempted=security_attempted,
        )

    results.extend(
        verify_plan(
            plan,
            live_after,
            keypair=keypair,
            device_public_key=device_pub,
            attempted_sections=frozenset(attempted),
            read_back=session.reads_back,
        )
    )

    outcome = ApplyOutcome(
        node_id=plan.node_id,
        results=tuple(results),
        dry_run=False,
        verified=True,
        security_attempted=security_attempted,
    )
    if outcome.uncertain or not outcome.ok:
        _logger.warning(
            "Node %s left in an UNCERTAIN STATE: %s",
            plan.node_id.display,
            ", ".join(
                f"{r.section}.{r.field}" if r.field else r.section for r in outcome.failures()
            ),
        )
        return outcome

    fingerprint = redact.fingerprint(keypair.public) if keypair is not None else None
    return ApplyOutcome(
        node_id=plan.node_id,
        results=outcome.results,
        dry_run=False,
        verified=True,
        public_key_fingerprint=fingerprint,
        security_attempted=security_attempted,
        record=plan.to_record(
            confirmed_short_name=_confirmed_name(outcome.results, "short_name"),
            confirmed_long_name=_confirmed_name(outcome.results, "long_name"),
        ),
    )


def persist_result(
    outcome: ApplyOutcome,
    *,
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair | None = None,
    origin: KeyOrigin,
    admin_key_refs: Sequence[str] = (),
    now: datetime | None = None,
) -> bool:
    """The single gate deciding whether an apply outcome may update the ODS.

    Args:
        outcome: The result of :func:`apply_plan`.
        nodes: The node repository to upsert into.
        keys: The key repository to upsert into. Must share the same
            :class:`~meshprovision.db.ods.OdsDatabase` session as
            ``nodes`` -- this is what makes the final :meth:`save` atomic
            across both sheets.
        keypair: The freshly generated keypair, when one was confirmed on
            the device (``key_plan.regenerate``); or the device's own
            already-existing keypair, when the plan adopted it instead of
            overwriting it (``key_plan.adopt_device_key``, firmware issue
            #7449). Either way, ``keys`` is updated to match what the
            device now holds.
        origin: How ``keypair``'s material came to be recorded -- computed
            by the caller (see ``cli/provision.py``'s ``_node_key_origin``).
            Required even when ``keypair`` is ``None`` (unused in that
            case), so every caller is forced to compute it rather than
            accidentally defaulting.
        admin_key_refs: Unused directly here (the confirmed record's
            ``authorized_admin_keys`` already reflects the plan); kept as
            part of this function's documented signature for callers that
            want to pass it through for logging/audit purposes.
        now: Timestamp to record. Defaults to the current time.

    Returns:
        ``True`` if the database was updated and saved; ``False`` if the
        outcome was in an uncertain state and nothing was written. The
        two failure modes are deliberately different shapes: an uncertain
        outcome is a *refusal* the caller renders (see
        ``cli/provision.py``'s "UNCERTAIN state" message), while a failed
        save is an *error*, because by then the device has already
        changed and the database has not.

    Raises:
        AtomicWriteError: If saving the database fails after the device
            write was already confirmed. Raised in place of the
            underlying filesystem error -- including a bare ``OSError``
            from serializing into the temp file, which ``atomic_write``
            does not itself wrap -- so the operator is told that the
            device and the database now disagree for this node, rather
            than only that a file could not be written.
    """
    del admin_key_refs
    if not outcome.may_update_database or outcome.record is None:
        _logger.warning(
            "Skipping database update for %s: node is in an uncertain state",
            outcome.node_id.display,
        )
        return False

    if keypair is not None:
        public_record, private_record = KeyRecord.for_keypair(
            outcome.record.node_id, keypair, origin=origin, created_ts=now
        )
        keys.upsert(public_record)
        keys.upsert(private_record)

    # Captured before the upsert below, which would otherwise always find
    # a row (the one it is about to write) -- this is what lets the
    # save-failure hint tell a first provision/bootstrap (no prior row)
    # apart from an already-provisioned node's key change.
    had_row = nodes.find(outcome.record.node_id) is not None
    nodes.upsert(outcome.record, now=now)
    try:
        nodes.db.save()
    except (AtomicWriteError, OSError) as exc:
        if isinstance(exc, DbConcurrentModificationError):
            opening = (
                "The database file changed on disk since mesh read it (close/save it in "
                "LibreOffice first)"
            )
        else:
            opening = "Fix the write problem (free space, permissions)"
        hint = (
            f"{opening} and re-run "
            "`mesh provision` for this node: the next run re-reads the device's "
            "live configuration and rewrites the row. Because that row was never "
            "saved, a node `mesh adopt` first recorded is still marked observed -- "
            "pass --enroll again on the re-run."
        )
        if keypair is not None and had_row:
            hint = (
                f"{hint} This run also generated a new node keypair that was never "
                "recorded; the next `mesh provision` re-reads the device's key and "
                "records it (it will be reported as differing from the Keys sheet -- "
                "expected here)."
            )
        elif keypair is not None:
            hint = (
                f"{hint} This run also generated a new node keypair that was never "
                "recorded, and a later run will not adopt a device key the database "
                "has never seen -- pass --force-regenerate-key on the re-run to put "
                "a recorded key back on the device."
            )
        raise AtomicWriteError(
            f"Node {outcome.node_id.display} was written and verified on the "
            f"device, but the database could not be saved ({exc}); the device and "
            "the database now disagree for this node.",
            path=str(nodes.db.path),
            hint=hint,
        ) from exc
    return True
