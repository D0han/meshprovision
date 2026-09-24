"""Self-tests for the e2e fixtures themselves (see ``tests/e2e/conftest.py``).

Proves that :meth:`~tests.e2e.conftest.DeviceBus.then` -- the hook that
lets a test serve a different device on a later ``connect()`` -- actually
behaves as designed. Several later batches (S1, C37-1, C37-2, A3 4b, E3,
...) depend on this hook; if it silently didn't advance ``current`` or
didn't record ``served``, their "the impostor received no writes" and
"the reconnect sees a different device" assertions would be meaningless.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from meshprovision.errors import ConnectionFailedError
from meshprovision.provisioning.connection import SerialBackend
from tests.e2e.conftest import FakeMeshInterface

if TYPE_CHECKING:
    from tests.e2e.conftest import DeviceBus

pytestmark = pytest.mark.e2e


def test_device_bus_then_serves_devices_in_connect_order(bus: DeviceBus) -> None:
    a = bus.use(FakeMeshInterface("aaaa0001"))
    b = FakeMeshInterface("cafe0002")
    bus.then(a, b)

    backend = SerialBackend("/dev/ttyFAKE0")
    served = [backend.connect() for _ in range(3)]

    assert [iface.myInfo.my_node_num for iface in served] == [
        a.myInfo.my_node_num,
        a.myInfo.my_node_num,
        b.myInfo.my_node_num,
    ]
    assert bus.served == ["aaaa0001", "aaaa0001", "cafe0002"]


def test_device_bus_then_with_a_queued_none_raises_and_records_none(bus: DeviceBus) -> None:
    a = bus.use(FakeMeshInterface("aaaa0001"))
    bus.then(None)

    backend = SerialBackend("/dev/ttyFAKE0")
    first = backend.connect()
    assert first.myInfo.my_node_num == a.myInfo.my_node_num

    with pytest.raises(ConnectionFailedError):
        backend.connect()

    assert bus.served == ["aaaa0001", None]
