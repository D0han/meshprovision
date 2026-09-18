"""Tests for meshprovision.provisioning.connection.close_interface.

Not "pure" like test_connection_select.py -- this exercises the daemon
thread + join(timeout=) machinery that bounds a hung ``iface.close()``
(see :data:`meshprovision.provisioning.connection.DEFAULT_CLOSE_TIMEOUT`
for why it exists: a confirmed reentrancy bug in meshtastic 2.7.11's
``BLEInterface``).
"""

from __future__ import annotations

import logging
import threading
import time

import pytest

from meshprovision.provisioning.connection import close_interface

pytestmark = pytest.mark.unit


class _ImmediateIface:
    """A fake interface whose close() returns right away."""

    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _HangingIface:
    """A fake interface whose close() never returns within the test.

    Blocks on a never-set :class:`threading.Event` rather than
    ``time.sleep`` -- the root ``tests/conftest.py`` monkeypatches
    ``time.sleep`` to a no-op for every test (to keep the suite fast), which
    would make a ``time.sleep``-based fake return instantly instead of
    hanging. ``Event.wait()`` is unaffected and genuinely blocks, standing
    in for the real bug's ``write_gatt_char`` coroutine that never
    resolves at all.
    """

    def __init__(self) -> None:
        self.started = threading.Event()
        self._never = threading.Event()

    def close(self) -> None:
        self.started.set()
        self._never.wait()


class _RaisingIface:
    """A fake interface whose close() raises one of the swallowed errors."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def close(self) -> None:
        raise self._exc


def test_close_interface_returns_promptly_for_a_fast_close() -> None:
    iface = _ImmediateIface()
    started = time.monotonic()

    close_interface(iface, timeout=1.0)  # type: ignore[arg-type]

    assert iface.closed is True
    assert time.monotonic() - started < 1.0


def test_close_interface_does_not_block_past_its_timeout(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A close() that hangs forever must not block the caller past `timeout`."""
    iface = _HangingIface()
    timeout = 0.1
    started = time.monotonic()

    with caplog.at_level(logging.WARNING, logger="meshprovision.provisioning.connection"):
        close_interface(iface, timeout=timeout)  # type: ignore[arg-type]

    elapsed = time.monotonic() - started
    # Generous bound: this must return close to `timeout`, not anywhere
    # near the fake's 5s hang.
    assert elapsed < 2.0
    assert iface.started.is_set()
    assert any("did not complete" in record.message for record in caplog.records)


@pytest.mark.parametrize("exc", [OSError("boom"), AttributeError("boom"), RuntimeError("boom")])
def test_close_interface_swallows_the_documented_exceptions(
    exc: BaseException, caplog: pytest.LogCaptureFixture
) -> None:
    """Matches close_interface's pre-existing contract: never re-raise these."""
    iface = _RaisingIface(exc)

    with caplog.at_level(logging.DEBUG, logger="meshprovision.provisioning.connection"):
        close_interface(iface, timeout=1.0)  # type: ignore[arg-type]

    assert any("Failed to close MeshInterface cleanly" in r.message for r in caplog.records)
