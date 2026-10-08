"""Tests for meshprovision.provisioning.apply_session (WriteResult, ApplyOutcome, sessions)."""

from __future__ import annotations

import pytest

from meshprovision.errors import (
    ConnectionFailedError,
    ExitCode,
    ProvisioningError,
    UnsupportedTransportError,
    WriteVerificationError,
)
from meshprovision.provisioning import apply_session as apply_session_module
from meshprovision.provisioning.apply import ApplyOutcome, ReconnectingSession
from meshprovision.provisioning.apply_session import (
    DEFAULT_SETTLE_SECONDS,
    InPlaceSession,
    WriteResult,
    WriteStatus,
)
from tests.unit.apply_fakes import (
    FakeIfaceForApply,
    fake_node_id,
)

pytestmark = pytest.mark.unit


def test_write_result_as_error_carries_the_redacted_fields_through() -> None:
    """`WriteResult.as_error()` -- `__all__`-exported public API, unused internally.

    `cli/provision.py` reimplements similar rendering inline for its own
    CLI-specific message formatting, but this convenience method for
    library consumers wanting a proper typed exception from a
    `WriteResult` had zero test coverage.
    """
    result = WriteResult(
        "security",
        WriteStatus.UNCONFIRMED,
        "admin key set mismatch: expected 1, got 0",
        field="admin_key",
        expected="sha256:aaaa",
        actual="<none>",
    )

    error = result.as_error()

    assert isinstance(error, WriteVerificationError)
    assert error.section == "security"
    assert error.field == "admin_key"
    assert error.expected == "sha256:aaaa"
    assert error.actual == "<none>"
    assert "admin key set mismatch" in str(error)


# ---------------------------------------------------------------------------
# ApplyOutcome.
# ---------------------------------------------------------------------------


def test_apply_outcome_properties() -> None:
    ok_result = WriteResult("device", WriteStatus.CONFIRMED, "confirmed")
    outcome = ApplyOutcome(node_id=fake_node_id(), results=(ok_result,), dry_run=False)
    assert outcome.ok is True
    assert outcome.uncertain is False
    assert outcome.may_update_database is True
    assert outcome.exit_code == 0
    assert outcome.failures() == ()
    assert outcome.describe() == ("device: confirmed -- confirmed",)


def test_apply_outcome_uncertain_and_failures() -> None:
    bad_result = WriteResult("security", WriteStatus.UNCONFIRMED, "mismatch", field="public_key")
    outcome = ApplyOutcome(node_id=fake_node_id(), results=(bad_result,), dry_run=False)
    assert outcome.uncertain is True
    assert outcome.ok is False
    assert outcome.may_update_database is False
    assert outcome.exit_code == int(ExitCode.PROVISIONING)
    assert outcome.failures() == (bad_result,)


def test_apply_outcome_dry_run_never_updates_database_even_if_ok() -> None:
    ok_result = WriteResult("device", WriteStatus.SKIPPED, "dry run")
    outcome = ApplyOutcome(node_id=fake_node_id(), results=(ok_result,), dry_run=True)
    assert outcome.ok is True
    assert outcome.may_update_database is False


# ---------------------------------------------------------------------------
# DeviceSession.reads_back.
# ---------------------------------------------------------------------------


def test_reconnecting_session_reads_back_is_true() -> None:
    session = ReconnectingSession(backend=object())  # type: ignore[arg-type]
    assert session.reads_back is True


def test_in_place_session_reads_back_is_false() -> None:
    session = InPlaceSession(FakeIfaceForApply())  # type: ignore[arg-type]
    assert session.reads_back is False


# ---------------------------------------------------------------------------
# ReconnectingSession.refresh() -- the real retry-with-backoff logic, not a
# hand-rolled fake session double.
# ---------------------------------------------------------------------------


class _FakeReconnectBackend:
    """A ConnectionBackend double: connect() replays a scripted outcome sequence."""

    def __init__(self, outcomes: list[object]) -> None:
        self._outcomes = list(outcomes)
        self.connect_calls = 0

    @property
    def transport(self) -> str:
        return "serial"

    @property
    def target(self) -> str:
        return "/dev/ttyFAKE"

    def describe(self) -> str:
        return "fake"

    def connect(self) -> object:
        outcome = self._outcomes[self.connect_calls]
        self.connect_calls += 1
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class _FakeIfaceForReconnect:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_reconnecting_session_interface_raises_before_open() -> None:
    """Reading `.interface` before `open()`/`refresh()` must raise, not return None-ish garbage.

    Untested caller-error guard: every existing test always calls
    `open()` or `refresh()` first, so this branch had zero coverage.
    """
    backend = _FakeReconnectBackend([_FakeIfaceForReconnect()])
    session = ReconnectingSession(backend=backend, sleep=lambda _: None)  # type: ignore[arg-type]

    with pytest.raises(ProvisioningError):
        _ = session.interface


def test_reconnecting_session_refresh_succeeds_on_first_attempt() -> None:
    iface = _FakeIfaceForReconnect()
    backend = _FakeReconnectBackend([iface])
    sleeps: list[float] = []
    session = ReconnectingSession(backend=backend, sleep=sleeps.append)  # type: ignore[arg-type]

    result = session.refresh()

    assert result is iface
    assert backend.connect_calls == 1
    assert sleeps == [DEFAULT_SETTLE_SECONDS]


def test_reconnecting_session_refresh_retries_then_succeeds() -> None:
    iface = _FakeIfaceForReconnect()
    fail1 = ConnectionFailedError("nope", transport="serial", target="/dev/ttyFAKE")
    fail2 = ConnectionFailedError("still nope", transport="serial", target="/dev/ttyFAKE")
    backend = _FakeReconnectBackend([fail1, fail2, iface])
    sleeps: list[float] = []
    session = ReconnectingSession(
        backend=backend,  # type: ignore[arg-type]
        attempts=3,
        sleep=sleeps.append,
    )

    result = session.refresh()

    assert result is iface
    assert backend.connect_calls == 3
    assert sleeps == [
        DEFAULT_SETTLE_SECONDS,
        apply_session_module._RECONNECT_BACKOFF * 1,
        apply_session_module._RECONNECT_BACKOFF * 2,
    ]


def test_reconnecting_session_refresh_exhausts_all_attempts_and_raises() -> None:
    fail = ConnectionFailedError("nope", transport="serial", target="/dev/ttyFAKE")
    backend = _FakeReconnectBackend([fail, fail, fail])
    sleeps: list[float] = []
    session = ReconnectingSession(
        backend=backend,  # type: ignore[arg-type]
        attempts=3,
        sleep=sleeps.append,
    )

    with pytest.raises(ConnectionFailedError):
        session.refresh()

    assert backend.connect_calls == 3
    # No backoff sleep after the last (3rd) attempt -- only 2 retries follow attempts 1-2.
    assert sleeps == [
        DEFAULT_SETTLE_SECONDS,
        apply_session_module._RECONNECT_BACKOFF * 1,
        apply_session_module._RECONNECT_BACKOFF * 2,
    ]


def test_reconnecting_session_refresh_wraps_non_connectionfailed_backend_error() -> None:
    backend = _FakeReconnectBackend([UnsupportedTransportError("no ble", transport="ble")])
    session = ReconnectingSession(
        backend=backend,  # type: ignore[arg-type]
        attempts=1,
        sleep=lambda _: None,
    )

    with pytest.raises(ConnectionFailedError) as exc_info:
        session.refresh()

    assert exc_info.value.transport == "serial"
    assert "no ble" in str(exc_info.value)


def test_reconnecting_session_refresh_closes_the_existing_interface_first() -> None:
    old_iface = _FakeIfaceForReconnect()
    new_iface = _FakeIfaceForReconnect()
    backend = _FakeReconnectBackend([new_iface])
    session = ReconnectingSession(backend=backend, sleep=lambda _: None)  # type: ignore[arg-type]
    session._iface = old_iface  # type: ignore[assignment]

    result = session.refresh()

    assert old_iface.closed is True
    assert result is new_iface
