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

Secret hygiene: nothing in this module ever logs, prints, or otherwise
renders raw key bytes, base64 key strings, or a BLE PIN. Every
human-facing representation of a secret field goes through
:func:`meshprovision.crypto.redact.fingerprint` first; :class:`WriteResult`
and :class:`~meshprovision.errors.WriteVerificationError` document
``expected``/``actual`` as always-redacted strings.

Exception discipline: the only broad ``except`` in this module is
:data:`_DEVICE_EXCEPTIONS`, which exists specifically because
``meshtastic.util.our_exit()`` -- called by ``Node.writeConfig`` and
``Node.setOwner`` on a bad section name or an empty name -- raises
``SystemExit``, and letting that propagate would kill the ``mesh``
process mid-provision. Every catch converts to a
:class:`~meshprovision.errors.ProvisioningError` subclass or a
:class:`WriteResult`; nothing here ever does a bare ``except Exception``.
"""

from __future__ import annotations

import logging
import secrets
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final, Protocol

from meshprovision.crypto import redact
from meshprovision.crypto.keys import KeyPair, decode_key
from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRecord, NodeRepository
from meshprovision.db.schema import BLE_PIN_LENGTH
from meshprovision.errors import (
    AtomicWriteError,
    ConnectionBackendError,
    ConnectionFailedError,
    DetectionError,
    EnumMappingError,
    ExitCode,
    KeyMaterialError,
    PlanConflictError,
    ProvisioningError,
    WriteVerificationError,
)
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import detect
from meshprovision.provisioning.connection import ConnectionBackend, close_interface
from meshprovision.provisioning.plan import ChangePlan, SectionChange, values_equal
from meshprovision.provisioning.plan_admin_keys import KeyPlan

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
    "verify_plan",
    "write_section",
]

_logger = logging.getLogger(__name__)

DEFAULT_SETTLE_SECONDS: Final[float] = 5.0
"""Pause, in seconds, after a reboot-triggering write before re-reading."""

DEFAULT_RECONNECT_ATTEMPTS: Final[int] = 3
"""Default number of reconnect attempts :class:`ReconnectingSession` makes."""

_RECONNECT_BACKOFF: Final[float] = 2.0
"""Base backoff, in seconds, between reconnect attempts (multiplied by attempt number)."""

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
:class:`~meshtastic.mesh_interface.MeshInterface.MeshInterfaceError` is
added at each call site via a lazy import, since importing ``meshtastic``
at module level would violate this layer's protobuf-confinement rule for
every *other* module that is not ``detect.py``/``apply.py``.
"""


class WriteStatus(StrEnum):
    """Outcome of one write-and-verify step."""

    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"
    """Written, but the post-write read-back did not match -- uncertain state."""
    FAILED = "failed"
    """The write call itself raised -- uncertain state."""
    SKIPPED = "skipped"
    """Dry-run, or nothing to do for this section."""


@dataclass(frozen=True, slots=True)
class WriteResult:
    """The outcome of writing (and, unless skipped, verifying) one field or section.

    Attributes:
        section: Name of the config or module-config section this result
            belongs to (or ``"owner"`` for the name phase, or
            ``"<verify>"`` for a whole-plan verification failure such as
            a lost reconnect).
        status: The outcome of this write.
        message: Human-readable, already-redacted description.
        field: Name of the specific field, when this result is about one
            field rather than a whole section.
        expected: Already-redacted, human-readable representation of the
            intended value, when relevant. Never raw key material.
        actual: Already-redacted, human-readable representation of the
            value read back from the device, when relevant. Never raw
            key material.
    """

    section: str
    status: WriteStatus
    message: str
    field: str | None = None
    expected: str | None = None
    actual: str | None = None

    @property
    def ok(self) -> bool:
        """Whether this result represents a successful (or skipped) write.

        Returns:
            ``True`` if :attr:`status` is :attr:`WriteStatus.CONFIRMED`
            or :attr:`WriteStatus.SKIPPED`.
        """
        return self.status in (WriteStatus.CONFIRMED, WriteStatus.SKIPPED)

    def as_error(self) -> WriteVerificationError:
        """Build the :class:`~meshprovision.errors.WriteVerificationError` for this result.

        Returns:
            A :class:`~meshprovision.errors.WriteVerificationError`
            carrying this result's already-redacted ``expected``/
            ``actual`` strings.
        """
        return WriteVerificationError(
            self.message,
            section=self.section,
            field=self.field,
            expected=self.expected,
            actual=self.actual,
        )


@dataclass(frozen=True, slots=True)
class ApplyOutcome:
    """The full outcome of one :func:`apply_plan` call.

    Attributes:
        node_id: The node the plan was applied to.
        results: Every :class:`WriteResult` produced, in execution order.
        dry_run: Whether this outcome came from a dry run (no device
            writes were attempted).
        verified: Whether a verification pass was actually run (``False``
            for a dry run or an empty plan, where there was nothing to
            verify; ``True`` whenever a real device write was attempted).
        public_key_fingerprint: A redacted fingerprint of the public key
            confirmed on the device, when a key was written and verified.
        record: The :class:`~meshprovision.db.nodes.NodeRecord` to
            persist, set only when :attr:`may_update_database` is
            ``True``.
    """

    node_id: NodeId
    results: tuple[WriteResult, ...]
    dry_run: bool = False
    verified: bool = True
    public_key_fingerprint: str | None = None
    record: NodeRecord | None = None

    @property
    def ok(self) -> bool:
        """Whether every result in :attr:`results` succeeded (or was skipped).

        Returns:
            ``True`` if every :class:`WriteResult` is :attr:`WriteResult.ok`.
        """
        return all(result.ok for result in self.results)

    @property
    def uncertain(self) -> bool:
        """Whether any write was left in an uncertain state.

        Returns:
            ``True`` if any result's status is
            :attr:`WriteStatus.UNCONFIRMED` or :attr:`WriteStatus.FAILED`.
        """
        return any(
            result.status in (WriteStatus.UNCONFIRMED, WriteStatus.FAILED)
            for result in self.results
        )

    @property
    def may_update_database(self) -> bool:
        """Whether :func:`persist_result` is allowed to write the ODS.

        Returns:
            ``True`` when this outcome is not uncertain, every result is
            ok, and it did not come from a dry run.
        """
        return (not self.uncertain) and self.ok and (not self.dry_run)

    @property
    def exit_code(self) -> int:
        """The process exit code the ``mesh`` console script should return.

        Returns:
            :attr:`~meshprovision.errors.ExitCode.OK` when :attr:`ok`;
            otherwise :attr:`~meshprovision.errors.ExitCode.PROVISIONING`.
        """
        return int(ExitCode.OK) if self.ok else int(ExitCode.PROVISIONING)

    def failures(self) -> tuple[WriteResult, ...]:
        """Return every result that did not succeed.

        Returns:
            The subset of :attr:`results` for which :attr:`WriteResult.ok`
            is ``False``, in their original order.
        """
        return tuple(result for result in self.results if not result.ok)

    def describe(self) -> tuple[str, ...]:
        """Render every result as one operator-facing line.

        Returns:
            One already-redacted line per entry of :attr:`results`, for
            example ``"security.public_key: unconfirmed -- mismatch"``.
        """
        lines: list[str] = []
        for result in self.results:
            label = f"{result.section}.{result.field}" if result.field else result.section
            line = f"{label}: {result.status.value}"
            if result.message:
                line = f"{line} -- {result.message}"
            lines.append(line)
        return tuple(lines)


class DeviceSession(Protocol):
    """Structural protocol for a live connection :func:`apply_plan` can drive.

    Deliberately a ``Protocol``: e2e tests satisfy this with a fake
    session wrapping a fake ``MeshInterface``, with no inheritance
    required.
    """

    @property
    def interface(self) -> MeshInterface:
        """The currently-open interface."""
        ...

    def describe(self) -> str:
        """Return a one-line, operator-facing description of this session."""
        ...

    def refresh(self) -> MeshInterface:
        """Return an interface whose config was read fresh from the device.

        Returns:
            The refreshed interface.
        """
        ...


@dataclass(slots=True)
class ReconnectingSession:
    """The honest read-back session: closes and reopens the connection to verify.

    A fresh :meth:`refresh` performs the full config handshake, so
    ``localNode.localConfig`` genuinely comes from the device rather than
    from the in-memory copy :func:`apply_plan` just wrote -- this is what
    makes the write-then-read-back guarantee meaningful for issue #7449
    (a restored key silently discarded on reboot).

    Deliberately does not use
    :func:`meshprovision.provisioning.connection.connected` -- that
    context manager closes the interface on exit, and this session must
    own the connection's lifecycle across multiple opens.

    Attributes:
        backend: The connection backend to (re)connect through.
        settle_seconds: Pause before each reconnect attempt.
        attempts: Number of reconnect attempts to make.
        sleep: Sleep function, injectable for tests.
    """

    backend: ConnectionBackend
    _iface: MeshInterface | None = None
    settle_seconds: float = DEFAULT_SETTLE_SECONDS
    attempts: int = DEFAULT_RECONNECT_ATTEMPTS
    sleep: Callable[[float], None] = time.sleep

    def open(self) -> MeshInterface:
        """Open the initial connection.

        Returns:
            The connected interface.

        Raises:
            ConnectionFailedError: If the connection attempt fails.
        """
        self._iface = self.backend.connect()
        return self._iface

    @property
    def interface(self) -> MeshInterface:
        """The currently-open interface.

        Returns:
            The interface from the most recent :meth:`open`/:meth:`refresh`.

        Raises:
            ProvisioningError: If :meth:`open` has not been called yet.
        """
        if self._iface is None:
            raise ProvisioningError("ReconnectingSession has not been opened; call open() first.")
        return self._iface

    def describe(self) -> str:
        """Return a one-line, operator-facing description of this session.

        Returns:
            :meth:`ConnectionBackend.describe` of :attr:`backend`.
        """
        return self.backend.describe()

    def refresh(self) -> MeshInterface:
        """Close, settle, and reconnect, retrying up to :attr:`attempts` times.

        Returns:
            The freshly (re)connected interface.

        Raises:
            ConnectionFailedError: If every reconnect attempt fails.
        """
        if self._iface is not None:
            close_interface(self._iface)
            self._iface = None
        self.sleep(self.settle_seconds)

        last_error: ConnectionFailedError | None = None
        for attempt in range(1, self.attempts + 1):
            try:
                self._iface = self.backend.connect()
                return self._iface
            except ConnectionBackendError as exc:
                last_error = (
                    exc
                    if isinstance(exc, ConnectionFailedError)
                    else ConnectionFailedError(
                        str(exc), transport=self.backend.transport, target=self.backend.target
                    )
                )
                if attempt < self.attempts:
                    self.sleep(_RECONNECT_BACKOFF * attempt)
        assert last_error is not None  # noqa: S101 -- loop always sets it before exhausting
        raise last_error

    def close(self) -> None:
        """Close the current connection, if one is open."""
        if self._iface is not None:
            close_interface(self._iface)
            self._iface = None

    def __enter__(self) -> ReconnectingSession:
        """Open the connection and return this session.

        Returns:
            ``self``.
        """
        self.open()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        """Close the connection.

        Args:
            exc_type: Unused; part of the context-manager protocol.
            exc: Unused; part of the context-manager protocol.
            tb: Unused; part of the context-manager protocol.
        """
        del exc_type, exc, tb
        self.close()


@dataclass(slots=True)
class InPlaceSession:
    """A session that never reconnects -- verifies against the in-memory interface.

    This provides a **weaker** guarantee than :class:`ReconnectingSession`:
    it re-reads whatever ``iface.localNode.localConfig`` currently holds
    in memory, which for a real device may still reflect the write this
    process just made rather than what actually persisted across a
    reboot (issue #7449). It exists for the e2e fake ``MeshInterface``
    (whose ``writeConfig`` updates its own ``localConfig`` synchronously,
    so there is nothing to reconnect to) and for a documented
    ``--no-reconnect`` escape hatch that operators should use only when
    they understand this tradeoff.

    Attributes:
        iface: The already-connected interface to use for every read and
            write.
    """

    iface: MeshInterface

    @property
    def interface(self) -> MeshInterface:
        """The wrapped interface.

        Returns:
            :attr:`iface`.
        """
        return self.iface

    def describe(self) -> str:
        """Return a one-line, operator-facing description of this session.

        Returns:
            A fixed string noting the weaker verification guarantee.
        """
        return "in-place session (no reconnect -- weaker verification)"

    def refresh(self) -> MeshInterface:
        """Return the same interface, unchanged.

        Returns:
            :attr:`iface`, without closing or reopening anything.
        """
        return self.iface


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
    """
    is_config = change.section in detect.CONFIG_SECTIONS
    is_module = change.section in detect.MODULE_SECTIONS
    if not is_config and not is_module:
        raise PlanConflictError(f"Unknown config section {change.section!r}", field=change.section)

    from meshtastic.mesh_interface import MeshInterface as _MeshInterface

    root = iface.localNode.localConfig if is_config else iface.localNode.moduleConfig
    msg = getattr(root, change.section)

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
    except (*_DEVICE_EXCEPTIONS, _MeshInterface.MeshInterfaceError) as exc:
        raise ProvisioningError(
            f"Failed to write config section {change.section!r}: {exc}"
        ) from exc

    _logger.info("Wrote config section %s (%d fields)", change.section, len(change.changes))


def _render_value(value: object, *, secret: bool) -> str:
    """Render a plan/live value as an already-redacted, human-readable string.

    Args:
        value: The value to render.
        secret: Whether this field is secret (per
            :attr:`~meshprovision.provisioning.plan.FieldChange.secret`).

    Returns:
        The literal ``"<redacted>"`` when ``secret`` is ``True``;
        otherwise ``str(value)``.
    """
    if secret:
        return "<redacted>"
    return str(value)


def _verify_name(live: detect.LiveConfig, desired: str | None, *, field: str) -> WriteResult | None:
    """Verify one name field (``short_name``/``long_name``) against its desired value.

    Args:
        live: The freshly re-read live configuration.
        desired: The name the plan intended to write, or ``None`` if this
            name was not part of the plan.
        field: ``"short_name"`` or ``"long_name"``.

    Returns:
        ``None`` when ``desired`` is ``None`` (nothing to verify);
        otherwise the :class:`WriteResult` for this name.
    """
    if desired is None:
        return None
    actual = live.short_name if field == "short_name" else live.long_name
    if actual == desired:
        return WriteResult("owner", WriteStatus.CONFIRMED, "confirmed", field=field)
    if desired.startswith(actual) and len(actual.encode("utf-8")) < len(desired.encode("utf-8")):
        return WriteResult(
            "owner",
            WriteStatus.CONFIRMED,
            f"firmware truncated the name to {len(actual.encode('utf-8'))} bytes",
            field=field,
            expected=desired,
            actual=actual,
        )
    return WriteResult(
        "owner",
        WriteStatus.UNCONFIRMED,
        "name did not match after write",
        field=field,
        expected=desired,
        actual=actual,
    )


def _confirmed_name(results: Sequence[WriteResult], field: str) -> str | None:
    """Find the truncated name a CONFIRMED ``owner`` write actually landed as.

    ``persist_result`` must record what firmware confirmed is really on
    the device, not what the plan wanted -- a name write that firmware
    silently truncated is reported CONFIRMED (see :func:`_verify_name`)
    since the write genuinely succeeded, but the plan's own *desired*
    value is longer than what the device actually holds. Persisting the
    desired value instead of the confirmed one would make the next run
    re-diff against a name the device doesn't have, re-plan the same
    rewrite, get truncated again, and never converge.

    Args:
        results: The verified write results from :func:`verify_plan`.
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


def _verify_key_material(
    plan: ChangePlan,
    live_after: detect.LiveConfig,
    *,
    keypair: KeyPair | None,
    device_public_key: object,
) -> WriteResult | None:
    """Verify the node's own keypair, per the firmware issue #7449 requirement.

    Runs for both ``key_plan.regenerate`` (a freshly written keypair must
    actually have taken) and ``key_plan.adopt_device_key`` (the keypair
    ``persist_result`` is about to record as the device's own must still
    genuinely be on the device after this run's writes and reboot --
    #7449 is exactly "a restored key can silently fail to persist", and an
    unrelated section write earlier in this same plan can still trigger
    that reboot). A key write is confirmed only when both the fresh
    ``LocalConfig`` read and the independent NodeDB view
    (``iface.getPublicKey()``) agree with ``keypair.public``.

    Args:
        plan: The executed plan.
        live_after: The freshly re-read live configuration.
        keypair: The keypair to confirm -- freshly generated when
            ``regenerate`` is set, or the device's pre-existing keypair
            (as read before this run's writes) when ``adopt_device_key``
            is set.
        device_public_key: The raw value of ``iface.getPublicKey()``: a
            base64 ``str`` (the common case -- it is produced by
            ``google.protobuf.json_format.MessageToDict``), raw
            ``bytes``, or ``None`` when the NodeDB entry is not yet
            repopulated.

    Returns:
        ``None`` when the plan neither regenerated nor adopted a key;
        otherwise the :class:`WriteResult` for ``security.public_key``.
    """
    if keypair is None or not (plan.key_plan.regenerate or plan.key_plan.adopt_device_key):
        return None

    local_config_ok = live_after.security.public_key == keypair.public

    nodedb_available = device_public_key is not None
    nodedb_bytes: bytes | None = None
    nodedb_decode_error: str | None = None
    if isinstance(device_public_key, bytes | bytearray):
        nodedb_bytes = bytes(device_public_key)
    elif isinstance(device_public_key, str):
        try:
            nodedb_bytes = decode_key(device_public_key, field="NodeDB public key")
        except KeyMaterialError as exc:
            nodedb_decode_error = exc.reason
    nodedb_ok = nodedb_bytes is not None and nodedb_bytes == keypair.public

    if local_config_ok and (nodedb_ok or not nodedb_available):
        note = "" if nodedb_available else " (NodeDB cross-check unavailable)"
        return WriteResult(
            "security", WriteStatus.CONFIRMED, f"public key confirmed{note}", field="public_key"
        )

    if nodedb_decode_error is not None:
        # Distinct from "decoded fine but genuinely differs" below -- the
        # NodeDB value never became comparable at all.
        actual_repr = f"<NodeDB value did not decode: {nodedb_decode_error}>"
    else:
        actual_bytes = nodedb_bytes if nodedb_bytes is not None else live_after.security.public_key
        actual_repr = redact.fingerprint(actual_bytes) if actual_bytes is not None else "<absent>"
    return WriteResult(
        "security",
        WriteStatus.UNCONFIRMED,
        "public key mismatch after write",
        field="public_key",
        expected=redact.fingerprint(keypair.public),
        actual=actual_repr,
    )


def _verify_admin_keys(plan: ChangePlan, live_after: detect.LiveConfig) -> WriteResult | None:
    """Verify the device's authorized admin keys against the plan's intent.

    Args:
        plan: The executed plan.
        live_after: The freshly re-read live configuration.

    Returns:
        ``None`` when the plan did not change admin keys; otherwise the
        :class:`WriteResult` for ``security.admin_key``.
    """
    if not plan.key_plan.change_admin_keys:
        return None

    desired = sorted(plan.key_plan.desired_admin_keys)
    actual = sorted(live_after.security.admin_keys)
    if desired == actual:
        return WriteResult(
            "security",
            WriteStatus.CONFIRMED,
            f"{len(actual)} admin key(s) confirmed",
            field="admin_key",
        )
    expected_fps = ", ".join(redact.fingerprint(k) for k in desired)
    actual_fps = ", ".join(redact.fingerprint(k) for k in actual)
    return WriteResult(
        "security",
        WriteStatus.UNCONFIRMED,
        f"admin key set mismatch: expected {len(desired)}, got {len(actual)}",
        field="admin_key",
        expected=expected_fps or "<none>",
        actual=actual_fps or "<none>",
    )


def verify_plan(
    plan: ChangePlan,
    live_after: detect.LiveConfig,
    *,
    keypair: KeyPair | None,
    device_public_key: object = None,
) -> tuple[WriteResult, ...]:
    """Compare a freshly re-read device state against a plan's intent.

    This is the read-back half of the transactional write guarantee: it
    never writes anything, only compares.

    Args:
        plan: The executed plan.
        live_after: The freshly re-read live configuration (obtained
            through :meth:`DeviceSession.refresh`, never the in-memory
            copy the write phase used).
        keypair: The freshly generated keypair, when the plan regenerated
            one.
        device_public_key: The raw value of ``iface.getPublicKey()``, as
            documented on :func:`_verify_key_material`.

    Returns:
        One :class:`WriteResult` per verified field/section, covering the
        name phase, every ordinary field change, and (when relevant) the
        key-material and admin-key checks.
    """
    results: list[WriteResult] = []

    short_result = _verify_name(live_after, plan.name_change.desired_short_name, field="short_name")
    if short_result is not None:
        results.append(short_result)
    long_result = _verify_name(live_after, plan.name_change.desired_long_name, field="long_name")
    if long_result is not None:
        results.append(long_result)

    for change in plan.sections:
        for field_change in change.changes:
            if change.section == "security":
                # LiveConfig.sections/module_sections deliberately exclude
                # "security" (its content lives in LiveConfig.security
                # instead -- see that field's docstring), so the generic
                # value() lookup below always returns None here and every
                # security scalar field (is_managed, serial_enabled,
                # debug_log_api_enabled, admin_channel_enabled) would
                # otherwise report UNCONFIRMED even on a fully successful
                # write. Read the real post-write value the same way
                # _verify_key_material/_verify_admin_keys already do.
                actual = getattr(live_after.security, field_change.field, None)
            else:
                actual = live_after.value(change.section, field_change.field)
            if values_equal(actual, field_change.desired):
                results.append(
                    WriteResult(
                        change.section, WriteStatus.CONFIRMED, "confirmed", field=field_change.field
                    )
                )
            else:
                results.append(
                    WriteResult(
                        change.section,
                        WriteStatus.UNCONFIRMED,
                        "value mismatch after write",
                        field=field_change.field,
                        expected=_render_value(field_change.desired, secret=field_change.secret),
                        actual=_render_value(actual, secret=field_change.secret),
                    )
                )

    key_result = _verify_key_material(
        plan, live_after, keypair=keypair, device_public_key=device_public_key
    )
    if key_result is not None:
        results.append(key_result)

    admin_result = _verify_admin_keys(plan, live_after)
    if admin_result is not None:
        results.append(admin_result)

    return tuple(results)


def _run_name_phase(iface: MeshInterface, plan: ChangePlan) -> WriteResult | None:
    """Execute the name (owner) phase of a plan.

    Args:
        iface: The connected interface to write through.
        plan: The plan whose ``name_change`` should be applied.

    Returns:
        A :class:`WriteResult` describing a failure, or ``None`` when the
        name phase was empty or succeeded (verification happens later,
        in :func:`verify_plan`).
    """
    if plan.name_change.is_empty:
        return None

    from meshtastic.mesh_interface import MeshInterface as _MeshInterface

    try:
        iface.localNode.setOwner(
            long_name=plan.name_change.desired_long_name,
            short_name=plan.name_change.desired_short_name,
        )
    except (*_DEVICE_EXCEPTIONS, _MeshInterface.MeshInterfaceError) as exc:
        return WriteResult("owner", WriteStatus.FAILED, f"Failed to set owner: {exc}")
    return None


def apply_plan(
    plan: ChangePlan,
    session: DeviceSession,
    *,
    keypair: KeyPair | None = None,
    dry_run: bool = False,
    settle_seconds: float = DEFAULT_SETTLE_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
) -> ApplyOutcome:
    """Execute a change plan against a live device with a write-then-verify guarantee.

    Never raises for a verification mismatch: the caller inspects
    :attr:`ApplyOutcome.exit_code`, :attr:`ApplyOutcome.may_update_database`,
    or :meth:`ApplyOutcome.failures`. It does propagate a lost reconnect
    as an uncertain outcome (never as an exception) -- a device that
    cannot be re-read is by definition unverified, and the ODS must not
    be written.

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
        settle_seconds: Pause after a reboot-triggering write, and again
            before the final verification reconnect.
        sleep: Sleep function, injectable for tests.

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
    iface = session.interface

    name_failure = _run_name_phase(iface, plan)
    if name_failure is not None:
        results.append(name_failure)

    last_index = len(plan.sections) - 1
    for index, change in enumerate(plan.sections):
        try:
            write_section(iface, change, key_plan=plan.key_plan, keypair=keypair)
        except (ProvisioningError, EnumMappingError) as exc:
            results.append(WriteResult(change.section, WriteStatus.FAILED, str(exc)))
            continue
        if change.reboots_device and index < last_index:
            # A section besides the last (always "security", written last
            # precisely to avoid a self-inflicted lockout, see
            # SECTION_ORDER) just rebooted the device -- the sections
            # still to come must be written against a fresh connection,
            # or they would silently write into (or read back from) a
            # stale, possibly-dead handle. Mirrors the same
            # sleep-then-refresh sequence used below for the final verify
            # pass. The last section's own reboot needs no sleep here:
            # the unconditional sleep+refresh right below already covers
            # it, so sleeping here too would just double the wait for
            # the same reboot.
            sleep(settle_seconds)
            try:
                iface = session.refresh()
            except ConnectionBackendError:
                results.append(
                    WriteResult(
                        "<verify>",
                        WriteStatus.FAILED,
                        "Could not reconnect after a reboot-triggering write to continue the plan",
                    )
                )
                return ApplyOutcome(
                    node_id=plan.node_id, results=tuple(results), dry_run=False, verified=True
                )

    sleep(settle_seconds)
    try:
        fresh_iface = session.refresh()
    except ConnectionBackendError:
        results.append(
            WriteResult("<verify>", WriteStatus.FAILED, "Could not reconnect to verify the writes")
        )
        return ApplyOutcome(
            node_id=plan.node_id, results=tuple(results), dry_run=False, verified=True
        )

    from meshtastic.mesh_interface import MeshInterface as _MeshInterface

    try:
        live_after = detect.read_live_config(fresh_iface)
        device_pub = fresh_iface.getPublicKey()
    except (DetectionError, *_DEVICE_EXCEPTIONS, _MeshInterface.MeshInterfaceError) as exc:
        results.append(
            WriteResult(
                "<verify>",
                WriteStatus.FAILED,
                f"Reconnected, but could not read back the device state to verify: {exc}",
            )
        )
        return ApplyOutcome(
            node_id=plan.node_id, results=tuple(results), dry_run=False, verified=True
        )

    results.extend(verify_plan(plan, live_after, keypair=keypair, device_public_key=device_pub))

    outcome = ApplyOutcome(
        node_id=plan.node_id, results=tuple(results), dry_run=False, verified=True
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
            outcome.record.node_id, keypair, created_ts=now
        )
        keys.upsert(public_record)
        keys.upsert(private_record)

    nodes.upsert(outcome.record, now=now)
    try:
        nodes.db.save()
    except (AtomicWriteError, OSError) as exc:
        hint = (
            "Fix the write problem (free space, permissions) and re-run "
            "`mesh provision` for this node: the next run re-reads the device's "
            "live configuration and rewrites the row. Because that row was never "
            "saved, a node `mesh adopt` first recorded is still marked observed -- "
            "pass --enroll again on the re-run."
        )
        if keypair is not None:
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
