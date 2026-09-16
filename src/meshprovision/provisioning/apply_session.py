"""Device-session management and write-outcome types for :mod:`~meshprovision.provisioning.apply`.

Split out of ``apply.py`` (which was 3x the project's ~400-line typical
file size) along the same seam already used for
:mod:`~meshprovision.provisioning.plan`/
:mod:`~meshprovision.provisioning.plan_types`: everything here --
:class:`WriteStatus`, :class:`WriteResult`, :class:`ApplyOutcome`, the
:class:`DeviceSession` protocol, :class:`ReconnectingSession`, and
:class:`InPlaceSession` -- is self-contained, with no dependency on
``apply.py``'s field-writing/verification logic (:func:`~meshprovision.
provisioning.apply.apply_field`, :func:`~meshprovision.provisioning.
apply.write_section`, :func:`~meshprovision.provisioning.apply.
verify_plan`, :func:`~meshprovision.provisioning.apply.apply_plan`,
:func:`~meshprovision.provisioning.apply.persist_result`); only the
reverse dependency exists. ``apply.py`` imports every name defined here
and re-exports it in its own ``__all__`` unchanged, so no external
caller needs to change which module it imports from.

Secret hygiene: same invariant as ``apply.py`` -- nothing here ever
logs, prints, or otherwise renders raw key bytes, base64 key strings,
or a BLE PIN. :class:`WriteResult` documents ``expected``/``actual`` as
always-redacted strings, a contract enforced by ``apply.py``'s callers,
not by this module itself.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Protocol

from meshprovision.db.nodes import NodeRecord
from meshprovision.errors import (
    ConnectionBackendError,
    ConnectionFailedError,
    ExitCode,
    ProvisioningError,
    WriteVerificationError,
)
from meshprovision.nodeid import NodeId
from meshprovision.provisioning.connection import ConnectionBackend, close_interface

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
]

DEFAULT_SETTLE_SECONDS: Final[float] = 5.0
"""Pause, in seconds, after a reboot-triggering write before re-reading."""

DEFAULT_RECONNECT_ATTEMPTS: Final[int] = 3
"""Default number of reconnect attempts :class:`ReconnectingSession` makes."""

_RECONNECT_BACKOFF: Final[float] = 2.0
"""Base backoff, in seconds, between reconnect attempts (multiplied by attempt number)."""


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
    """The full outcome of one :func:`~meshprovision.provisioning.apply.apply_plan` call.

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
        """Whether ``persist_result`` is allowed to write the ODS.

        See :func:`meshprovision.provisioning.apply.persist_result`.

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
    """Structural protocol for a live connection ``apply_plan`` can drive.

    See :func:`meshprovision.provisioning.apply.apply_plan`.

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
    from the in-memory copy :func:`~meshprovision.provisioning.apply.apply_plan`
    just wrote -- this is what makes the write-then-read-back guarantee
    meaningful for issue #7449 (a restored key silently discarded on
    reboot).

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
