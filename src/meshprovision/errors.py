"""Exception hierarchy and process exit-code mapping for meshprovision.

Every error the project raises deliberately (as opposed to an unexpected
bug) is a subclass of :class:`MeshprovisionError`. The hierarchy branches
by failure domain -- configuration, data sources, the ODS database,
device provisioning, and cryptography -- and each branch root carries the
:class:`ExitCode` the ``mesh`` console script should return when that
branch escapes uncaught. :func:`exit_code_for` is the single mapping the
CLI's top-level error boundary uses to turn *any* exception (including
``KeyboardInterrupt`` and ``SystemExit``) into a process exit code.

This module is a leaf: it imports nothing from the rest of the package,
so every other module in the project can depend on it without risking an
import cycle.

Secret hygiene: the crypto branch of this hierarchy (:class:`CryptoError`
and its subclasses) never carries raw key material. Fields such as
``fingerprint`` are pre-redacted digest strings (for example
``"sha256:ab12..."``) produced by ``meshprovision.crypto.redact``; nothing
in this module accepts or stores key bytes.
"""

from __future__ import annotations

from enum import IntEnum
from typing import ClassVar, Final, Literal

__all__ = [
    "MAX_ADMIN_KEYS",
    "AdminKeyCapacityError",
    "AdminKeyError",
    "AdminRefUnresolvedError",
    "AdoptionRefusedError",
    "AmbiguousDeviceError",
    "AtomicWriteError",
    "CacheError",
    "ConfigError",
    "ConnectionBackendError",
    "ConnectionFailedError",
    "CryptoError",
    "DataSourceError",
    "DatabaseLockedError",
    "DbError",
    "DbIntegrityError",
    "DbValidationError",
    "DetectionError",
    "DeviceNotFoundError",
    "DuplicateNodeError",
    "EnumMappingError",
    "ExitCode",
    "HttpError",
    "InvalidResponseError",
    "KeyMaterialError",
    "KeyNotFoundError",
    "KeyVerificationError",
    "LockdownRefusedError",
    "MeshprovisionError",
    "MissingContactError",
    "NameCapacityError",
    "NamePatternError",
    "NamespaceExhaustedError",
    "NodeIdError",
    "NodeNotEnrolledError",
    "NodeNotFoundError",
    "NonInteractiveError",
    "PlanConflictError",
    "ProvisioningError",
    "RateLimitError",
    "SchemaError",
    "SettingsError",
    "TemplateValidationError",
    "UnsupportedTransportError",
    "WeakKeyError",
    "WeakKeySeverity",
    "WriteVerificationError",
    "exit_code_for",
]


class ExitCode(IntEnum):
    """Process exit codes used by the ``mesh`` console script.

    Each branch of the :class:`MeshprovisionError` hierarchy sets its
    ``exit_code`` class attribute to one of these members, and
    :func:`exit_code_for` reads it back off the raised exception's type.
    """

    OK = 0
    ERROR = 1
    CONFIG = 2
    DATASOURCE = 3
    DB = 4
    PROVISIONING = 5
    CRYPTO = 6
    STATUS_DEGRADED = 7
    INTERRUPTED = 130


WeakKeySeverity = Literal["warning", "critical"]
"""Severity of a weak-key finding: ``"warning"`` or ``"critical"``."""

MAX_ADMIN_KEYS: Final[int] = 3
"""Firmware capacity of ``config.security.admin_key`` (a ``repeated bytes``
field limited to three entries by the Meshtastic firmware)."""

ADMIN_REF_HINT: Final = (
    "Register the admin key first with `mesh admin bootstrap` (provisions a device and "
    "records it as an admin) or `mesh admin import <REF>=<BASE64>` (registers a public "
    "key you already hold)."
)

ENROLL_HINT: Final = (
    "Re-run with --enroll to bring this node under mesh provision's template "
    "management. Until then it is left exactly as mesh adopt recorded it."
)

FORCE_ADOPT_HINT: Final = (
    "Pass --force to re-adopt it anyway. This demotes it to observed, and "
    "mesh provision will not manage it again until it is re-enrolled with --enroll."
)

MISSING_CONTACT_MESSAGE: Final = (
    "MESHPROVISION_CONTACT is not set. lorastats.pl requires identifiable contact "
    "information in the User-Agent header of every request."
)
MISSING_CONTACT_HINT: Final = (
    "Set MESHPROVISION_CONTACT in your .env file to your own email address or URL. "
    "There is deliberately no default: lorastats.pl bans IP addresses that send "
    "missing, dummy or third-party contact details."
)


class MeshprovisionError(Exception):
    """Root of the meshprovision exception hierarchy.

    Attributes:
        message: Human-readable description of what went wrong.
        hint: Optional actionable suggestion for resolving the error,
            shown to the operator alongside ``message`` but kept out of
            ``str(exc)`` so log lines stay single-purpose.
    """

    exit_code: ClassVar[int] = ExitCode.ERROR

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message)
        self.message = message
        self.hint = hint

    @property
    def user_message(self) -> str:
        r"""Full operator-facing text: the message, plus the hint if set.

        Returns:
            ``message`` alone, or ``f"{message}\nHint: {hint}"`` when a
            hint is present.
        """
        if self.hint:
            return f"{self.message}\nHint: {self.hint}"
        return self.message

    def __str__(self) -> str:
        """Return the bare message, without the hint.

        Returns:
            The value of ``self.message``.
        """
        return self.message


# ---------------------------------------------------------------------------
# Configuration branch
# ---------------------------------------------------------------------------


class ConfigError(MeshprovisionError):
    """Base class for configuration and settings failures."""

    exit_code: ClassVar[int] = ExitCode.CONFIG


class SettingsError(ConfigError):
    """A required setting is missing, malformed, or otherwise invalid."""


class MissingContactError(ConfigError):
    """``MESHPROVISION_CONTACT`` is unset or whitespace-only.

    lorastats.pl requires identifiable contact information in every
    request's ``User-Agent`` header and bans IPs that omit it, so there is
    deliberately no default value for this setting.
    """

    def __init__(
        self,
        message: str = MISSING_CONTACT_MESSAGE,
        *,
        hint: str | None = MISSING_CONTACT_HINT,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description; defaults to the standard
                missing-contact message.
            hint: Actionable suggestion; defaults to the standard
                missing-contact hint.
        """
        super().__init__(message, hint=hint)


class TemplateValidationError(ConfigError):
    """A provisioning template failed validation.

    Attributes:
        field: Name of the offending template field, when known.
    """

    def __init__(
        self,
        message: str,
        *,
        field: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            field: Name of the offending template field, when known.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.field = field


class NamePatternError(TemplateValidationError):
    """A rendered name pattern overflows its firmware byte limit.

    Attributes:
        pattern: The offending name pattern.
        rendered: The rendered name that overflowed, when known.
        byte_length: UTF-8 byte length of the rendered name, when known.
        limit: The firmware byte limit that was exceeded, when known.
    """

    def __init__(
        self,
        message: str,
        *,
        pattern: str,
        rendered: str | None = None,
        byte_length: int | None = None,
        limit: int | None = None,
        field: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            pattern: The offending name pattern.
            rendered: The rendered name that overflowed, when known.
            byte_length: UTF-8 byte length of the rendered name, when known.
            limit: The firmware byte limit that was exceeded, when known.
            field: Name of the offending template field, when known.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, field=field, hint=hint)
        self.pattern = pattern
        self.rendered = rendered
        self.byte_length = byte_length
        self.limit = limit


class NameCapacityError(TemplateValidationError):
    """A name pattern's namespace capacity is below the configured floor.

    Attributes:
        pattern: The offending name pattern.
        capacity: The computed namespace capacity
            (``alphabet_size ** suffix_slots``).
        floor: The configured minimum capacity, when known.
    """

    def __init__(
        self,
        message: str,
        *,
        pattern: str,
        capacity: int,
        floor: int | None = None,
        field: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            pattern: The offending name pattern.
            capacity: The computed namespace capacity.
            floor: The configured minimum capacity, when known.
            field: Name of the offending template field, when known.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, field=field, hint=hint)
        self.pattern = pattern
        self.capacity = capacity
        self.floor = floor


# ---------------------------------------------------------------------------
# Data-source branch
# ---------------------------------------------------------------------------


class DataSourceError(MeshprovisionError):
    """Base class for failures fetching data from loranet.pl or lorastats.pl."""

    exit_code: ClassVar[int] = ExitCode.DATASOURCE


class HttpError(DataSourceError):
    """An HTTP request to a data source failed.

    Attributes:
        url: The request URL.
        status_code: The HTTP status code returned, when available.
        source: Name of the data source (``"loranet"``, ``"lorastats"``),
            when known.
    """

    def __init__(
        self,
        message: str,
        *,
        url: str,
        status_code: int | None = None,
        source: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            url: The request URL.
            status_code: The HTTP status code returned, when available.
            source: Name of the data source, when known.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.url = url
        self.status_code = status_code
        self.source = source


class RateLimitError(HttpError):
    """A data source rejected a request for exceeding its rate limit.

    Attributes:
        retry_after: Seconds to wait before retrying, when the source
            supplied one.
    """

    def __init__(
        self,
        message: str,
        *,
        url: str,
        status_code: int | None = None,
        source: str | None = None,
        retry_after: float | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            url: The request URL.
            status_code: The HTTP status code returned, when available.
            source: Name of the data source, when known.
            retry_after: Seconds to wait before retrying, when supplied.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, url=url, status_code=status_code, source=source, hint=hint)
        self.retry_after = retry_after


class InvalidResponseError(HttpError):
    """A data source responded with a body that could not be parsed as expected.

    Used for the lorastats "soft 404" case: an invalid region path still
    returns HTTP 200 with an HTML body instead of the expected JSON.

    Attributes:
        content_type: The response's ``Content-Type`` header, when known.
    """

    def __init__(
        self,
        message: str,
        *,
        url: str,
        status_code: int | None = None,
        source: str | None = None,
        content_type: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            url: The request URL.
            status_code: The HTTP status code returned, when available.
            source: Name of the data source, when known.
            content_type: The response's ``Content-Type`` header, when known.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, url=url, status_code=status_code, source=source, hint=hint)
        self.content_type = content_type


class NodeNotFoundError(DataSourceError):
    """A requested node id was not present in a data source's response.

    Attributes:
        node_id: The node id that was not found, in its display form.
        source: Name of the data source that was queried.
    """

    def __init__(
        self,
        message: str,
        *,
        node_id: str,
        source: str,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            node_id: The node id that was not found, in its display form.
            source: Name of the data source that was queried.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.node_id = node_id
        self.source = source


class CacheError(DataSourceError):
    """The on-disk HTTP response cache could not be read or written.

    Attributes:
        path: Path to the offending cache file, when known.
    """

    def __init__(
        self,
        message: str,
        *,
        path: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            path: Path to the offending cache file, when known.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.path = path


# ---------------------------------------------------------------------------
# Database branch
# ---------------------------------------------------------------------------


class DbError(MeshprovisionError):
    """Base class for failures reading or writing the ODS database."""

    exit_code: ClassVar[int] = ExitCode.DB


class SchemaError(DbError):
    """The ODS database's structure does not match the expected schema.

    Attributes:
        sheet: Name of the offending sheet, when known.
        column: Name of the offending column, when known.
    """

    def __init__(
        self,
        message: str,
        *,
        sheet: str | None = None,
        column: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            sheet: Name of the offending sheet, when known.
            column: Name of the offending column, when known.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.sheet = sheet
        self.column = column


class DbValidationError(DbError):
    """A cell's value failed re-validation against its column's content rules.

    Attributes:
        sheet: Name of the sheet containing the offending cell.
        row: 1-indexed row number of the offending cell.
        column: Name of the offending column.
        value: The offending cell value, when known.
    """

    def __init__(
        self,
        message: str,
        *,
        sheet: str,
        row: int,
        column: str,
        value: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            sheet: Name of the sheet containing the offending cell.
            row: 1-indexed row number of the offending cell.
            column: Name of the offending column.
            value: The offending cell value, when known.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.sheet = sheet
        self.row = row
        self.column = column
        self.value = value


class DbIntegrityError(DbError):
    """A cached derived value disagrees with its recomputed value.

    Raised when a cell holding a formula's cached result (for example a
    ``key_ref`` label) disagrees with the value recomputed from its
    source column -- catching both a stale LibreOffice cache and a
    hand-edit that broke a formula.

    Attributes:
        sheet: Name of the offending sheet, when known.
        cell: Cell reference of the offending cell, when known.
    """

    def __init__(
        self,
        message: str,
        *,
        sheet: str | None = None,
        cell: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            sheet: Name of the offending sheet, when known.
            cell: Cell reference of the offending cell, when known.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.sheet = sheet
        self.cell = cell


class DuplicateNodeError(DbError):
    """A node id already exists in the database.

    Attributes:
        node_id: The duplicate node id, in its display form.
        sheet: Name of the sheet containing the duplicate.
    """

    def __init__(
        self,
        message: str,
        *,
        node_id: str,
        sheet: str = "Nodes",
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            node_id: The duplicate node id, in its display form.
            sheet: Name of the sheet containing the duplicate.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.node_id = node_id
        self.sheet = sheet


class KeyNotFoundError(DbError):
    """A key reference could not be resolved in the ``Keys`` sheet.

    Attributes:
        key_ref: The unresolved key reference.
    """

    def __init__(
        self,
        message: str,
        *,
        key_ref: str,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            key_ref: The unresolved key reference.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.key_ref = key_ref


class AtomicWriteError(DbError):
    """The atomic write-and-replace of the database file failed.

    Also covers a failure to create or acquire the sidecar write-lock
    file used by :func:`meshprovision.db.locking.exclusive_lock` -- a
    filesystem failure (read-only filesystem, missing parent,
    permissions) is a different condition from lock contention and is
    never reported as :class:`DatabaseLockedError`.

    Attributes:
        path: Path to the database file being written.
    """

    def __init__(
        self,
        message: str,
        *,
        path: str,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            path: Path to the database file being written.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.path = path


class DatabaseLockedError(DbError):
    """Another process holds the node database's write lock.

    Raised by :func:`meshprovision.db.locking.exclusive_lock` when a
    ``flock`` acquisition times out against its deadline -- a distinct
    condition from :class:`AtomicWriteError`, which covers a failure to
    even create the lock file. Read-only commands never raise this: only
    a writer takes the lock.

    Attributes:
        path: Path to the database file whose lock could not be acquired.
        holder_pid: The pid recorded in the lock file, when one could be
            read. Advisory only: a holder killed between acquiring the
            lock and recording its pid leaves this ``None``.
    """

    def __init__(
        self,
        message: str,
        *,
        path: str,
        holder_pid: int | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            path: Path to the database file whose lock could not be
                acquired.
            holder_pid: The pid recorded in the lock file, when known.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.path = path
        self.holder_pid = holder_pid


# ---------------------------------------------------------------------------
# Provisioning branch
# ---------------------------------------------------------------------------


class ProvisioningError(MeshprovisionError):
    """Base class for failures provisioning or communicating with a device."""

    exit_code: ClassVar[int] = ExitCode.PROVISIONING


class ConnectionBackendError(ProvisioningError):
    """Base class for transport-level connection failures.

    Attributes:
        transport: Name of the transport (``"serial"``, ``"ble"``,
            ``"tcp"``), when known.
    """

    def __init__(
        self,
        message: str,
        *,
        transport: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            transport: Name of the transport, when known.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.transport = transport


class DeviceNotFoundError(ConnectionBackendError):
    """No device could be found on the requested transport.

    Attributes:
        target: The port, address, or host that was requested, when known.
    """

    def __init__(
        self,
        message: str,
        *,
        transport: str | None = None,
        target: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            transport: Name of the transport, when known.
            target: The port, address, or host that was requested.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, transport=transport, hint=hint)
        self.target = target


class AmbiguousDeviceError(ConnectionBackendError):
    """More than one candidate device was found and none was specified.

    Attributes:
        candidates: The candidate ports/addresses found.
    """

    def __init__(
        self,
        message: str,
        *,
        transport: str | None = None,
        candidates: tuple[str, ...] = (),
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            transport: Name of the transport, when known.
            candidates: The candidate ports/addresses found.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, transport=transport, hint=hint)
        self.candidates = candidates


class ConnectionFailedError(ConnectionBackendError):
    """A connection to a specific device was attempted and failed.

    Attributes:
        target: The port, address, or host that was targeted, when known.
    """

    def __init__(
        self,
        message: str,
        *,
        transport: str | None = None,
        target: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            transport: Name of the transport, when known.
            target: The port, address, or host that was targeted.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, transport=transport, hint=hint)
        self.target = target


class UnsupportedTransportError(ConnectionBackendError):
    """The requested transport name is not one of ``serial``/``ble``/``tcp``.

    Attributes:
        transport: The unsupported transport name that was requested.
    """

    def __init__(
        self,
        message: str,
        *,
        transport: str,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            transport: The unsupported transport name that was requested.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, transport=transport, hint=hint)


class NonInteractiveError(ProvisioningError):
    """An interactive prompt was required but the run is non-interactive.

    Raised when stdin is not a TTY (or ``--non-interactive`` was passed)
    and the CLI would otherwise have prompted the operator.

    Attributes:
        prompt: Description of the prompt that could not be shown.
    """

    def __init__(
        self,
        message: str,
        *,
        prompt: str,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            prompt: Description of the prompt that could not be shown.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.prompt = prompt


class DetectionError(ProvisioningError):
    """A connected node's provisioning state could not be determined."""


class NodeNotEnrolledError(ProvisioningError):
    """A node recorded by ``mesh adopt`` was not enrolled with ``--enroll``.

    Attributes:
        node_id: The node's id, for display.
    """

    def __init__(
        self,
        message: str,
        *,
        node_id: str,
        hint: str | None = ENROLL_HINT,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            node_id: The node's id, for display.
            hint: Actionable suggestion; defaults to pointing at --enroll.
        """
        super().__init__(message, hint=hint)
        self.node_id = node_id


class AdoptionRefusedError(ProvisioningError):
    """``mesh adopt`` refused to overwrite a template-managed node's record.

    Attributes:
        node_id: The node's id, for display.
    """

    def __init__(
        self,
        message: str,
        *,
        node_id: str,
        hint: str | None = FORCE_ADOPT_HINT,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            node_id: The node's id, for display.
            hint: Actionable suggestion; defaults to pointing at --force.
        """
        super().__init__(message, hint=hint)
        self.node_id = node_id


class PlanConflictError(ProvisioningError):
    """A change plan conflicts with itself or with the live device state.

    Attributes:
        field: Name of the conflicting field, when known.
    """

    def __init__(
        self,
        message: str,
        *,
        field: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            field: Name of the conflicting field, when known.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.field = field


class WriteVerificationError(ProvisioningError):
    """A post-write read-back did not match the intended configuration.

    Per firmware issue #7449, a written value (including keys) can fail
    to persist across a reboot, so every write is verified by reading it
    back. When this error is raised, the caller must skip the
    corresponding ODS write and the process must exit non-zero.

    ``expected`` and ``actual`` are always human-readable, already-redacted
    representations (for example a redacted fingerprint string) -- never
    raw cryptographic material. Route any key material through
    ``meshprovision.crypto.redact`` before constructing this error.

    Attributes:
        section: Name of the config section that failed verification.
        field: Name of the specific field that failed verification, when
            known.
        expected: Redacted, human-readable representation of the intended
            value, when known.
        actual: Redacted, human-readable representation of the value read
            back from the device, when known.
    """

    def __init__(
        self,
        message: str,
        *,
        section: str,
        field: str | None = None,
        expected: str | None = None,
        actual: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            section: Name of the config section that failed verification.
            field: Name of the specific field that failed verification.
            expected: Redacted, human-readable representation of the
                intended value. Never raw key material.
            actual: Redacted, human-readable representation of the value
                read back from the device. Never raw key material.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.section = section
        self.field = field
        self.expected = expected
        self.actual = actual


class NamespaceExhaustedError(ProvisioningError):
    """No unused name remains in a name pattern's namespace.

    Attributes:
        pattern: The name pattern whose namespace is exhausted.
        capacity: The computed namespace capacity
            (``alphabet_size ** suffix_slots``).
    """

    def __init__(
        self,
        message: str,
        *,
        pattern: str,
        capacity: int,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            pattern: The name pattern whose namespace is exhausted.
            capacity: The computed namespace capacity.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.pattern = pattern
        self.capacity = capacity


class AdminKeyError(ProvisioningError):
    """Base class for admin-key custody failures."""


class AdminRefUnresolvedError(AdminKeyError):
    """An ``admin_nodes`` reference does not resolve to a Keys sheet entry.

    Attributes:
        ref: The unresolved admin node reference.
    """

    def __init__(
        self,
        message: str,
        *,
        ref: str,
        hint: str | None = ADMIN_REF_HINT,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            ref: The unresolved admin node reference.
            hint: Actionable suggestion; defaults to pointing at the two
                admin bootstrap commands.
        """
        super().__init__(message, hint=hint)
        self.ref = ref


class AdminKeyCapacityError(AdminKeyError):
    """More admin keys were requested than the firmware supports.

    Attributes:
        count: The number of admin keys requested.
        limit: The firmware's admin key capacity.
    """

    def __init__(
        self,
        message: str,
        *,
        count: int,
        limit: int = MAX_ADMIN_KEYS,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            count: The number of admin keys requested.
            limit: The firmware's admin key capacity.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.count = count
        self.limit = limit


class LockdownRefusedError(AdminKeyError):
    """``is_managed=true`` was requested without a satisfied safety gate.

    Attributes:
        reason: Which safety-gate condition was not satisfied.
    """

    def __init__(
        self,
        message: str,
        *,
        reason: str,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            reason: Which safety-gate condition was not satisfied.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.reason = reason


# ---------------------------------------------------------------------------
# Crypto branch
# ---------------------------------------------------------------------------


class CryptoError(MeshprovisionError):
    """Base class for key-generation, key-audit and key-verification failures."""

    exit_code: ClassVar[int] = ExitCode.CRYPTO


class KeyMaterialError(CryptoError):
    """Key material is malformed (wrong length, bad encoding, etc.).

    This error never carries raw key bytes -- only a textual ``reason``
    and, where relevant, the expected and actual byte lengths.

    Attributes:
        reason: Human-readable description of what is wrong with the key
            material.
        expected_length: Expected byte length, when known.
        actual_length: Actual byte length encountered, when known.
    """

    def __init__(
        self,
        message: str,
        *,
        reason: str,
        expected_length: int | None = None,
        actual_length: int | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            reason: Human-readable description of what is wrong with the
                key material. Never raw key bytes.
            expected_length: Expected byte length, when known.
            actual_length: Actual byte length encountered, when known.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.reason = reason
        self.expected_length = expected_length
        self.actual_length = actual_length


class WeakKeyError(CryptoError):
    """A key failed the CVE-2025-52464 weak-key audit.

    This error never carries raw key bytes. ``fingerprint``, when
    present, is a redacted digest string such as ``"sha256:ab12..."``
    produced by ``meshprovision.crypto.redact`` -- never the key itself.

    Attributes:
        reason: Human-readable description of why the key is considered
            weak (structural defect, firmware-window presumption,
            cross-node duplicate, etc.).
        node_id: The affected node id, in its display form, when known.
        key_ref: The affected key reference in the ``Keys`` sheet, when
            known.
        severity: ``"warning"`` or ``"critical"``.
        fingerprint: Redacted digest string identifying the key, when
            known. Never raw key material.
    """

    def __init__(
        self,
        message: str,
        *,
        reason: str,
        node_id: str | None = None,
        key_ref: str | None = None,
        severity: WeakKeySeverity = "critical",
        fingerprint: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            reason: Human-readable description of why the key is
                considered weak.
            node_id: The affected node id, in its display form.
            key_ref: The affected key reference in the ``Keys`` sheet.
            severity: ``"warning"`` or ``"critical"``.
            fingerprint: Redacted digest string identifying the key.
                Never raw key material.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.reason = reason
        self.node_id = node_id
        self.key_ref = key_ref
        self.severity = severity
        self.fingerprint = fingerprint


class KeyVerificationError(CryptoError):
    """A device's public key could not be verified against custody records.

    Per firmware issue #7449, a written key can silently fail to persist
    across a reboot, so this error signals that the device's reported
    public key does not match what custody records expect.

    Attributes:
        key_ref: The key reference being verified, when known.
        node_id: The affected node id, in its display form, when known.
    """

    def __init__(
        self,
        message: str,
        *,
        key_ref: str | None = None,
        node_id: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            key_ref: The key reference being verified, when known.
            node_id: The affected node id, in its display form, when known.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.key_ref = key_ref
        self.node_id = node_id


# ---------------------------------------------------------------------------
# Standalone leaves
# ---------------------------------------------------------------------------


class NodeIdError(MeshprovisionError):
    """A value could not be parsed or constructed as a valid node id.

    Attributes:
        raw: The offending raw value, when known.
    """

    def __init__(
        self,
        message: str,
        *,
        raw: str | int | None = None,
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            raw: The offending raw value, when known.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.raw = raw


class EnumMappingError(MeshprovisionError):
    """A name or numeric value could not be mapped in a protobuf enum table.

    Attributes:
        enum_name: Name of the enum table (``"role"``, ``"hw_model"``,
            ``"region"``).
        value: The name or value that could not be mapped.
        known: The set of known names in the table, for error reporting.
    """

    def __init__(
        self,
        message: str,
        *,
        enum_name: str,
        value: str | int,
        known: tuple[str, ...] = (),
        hint: str | None = None,
    ) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of what went wrong.
            enum_name: Name of the enum table.
            value: The name or value that could not be mapped.
            known: The set of known names in the table, for error
                reporting.
            hint: Optional actionable suggestion for resolving the error.
        """
        super().__init__(message, hint=hint)
        self.enum_name = enum_name
        self.value = value
        self.known = known


# ---------------------------------------------------------------------------
# Exit-code mapping
# ---------------------------------------------------------------------------


def exit_code_for(exc: BaseException) -> int:
    """Map an exception to the process exit code the CLI should return.

    Args:
        exc: The exception the CLI's top-level handler caught.

    Returns:
        ``int(type(exc).exit_code)`` for a :class:`MeshprovisionError`;
        :attr:`ExitCode.INTERRUPTED` for a ``KeyboardInterrupt``; the
        ``SystemExit`` code when it is an ``int`` (else
        :attr:`ExitCode.ERROR`); and :attr:`ExitCode.ERROR` for anything
        else.
    """
    if isinstance(exc, MeshprovisionError):
        return int(type(exc).exit_code)
    if isinstance(exc, KeyboardInterrupt):
        return int(ExitCode.INTERRUPTED)
    if isinstance(exc, SystemExit):
        if isinstance(exc.code, int):
            return exc.code
        return int(ExitCode.ERROR)
    return int(ExitCode.ERROR)
