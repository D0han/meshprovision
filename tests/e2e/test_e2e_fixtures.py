"""Self-tests for the e2e fixtures themselves (see ``tests/e2e/conftest.py``).

Proves that :meth:`~tests.e2e.conftest.DeviceBus.then` -- the hook that
lets a test serve a different device on a later ``connect()`` -- actually
behaves as designed. Several later batches (S1, C37-1, C37-2, A3 4b, E3,
...) depend on this hook; if it silently didn't advance ``current`` or
didn't record ``served``, their "the impostor received no writes" and
"the reconnect sees a different device" assertions would be meaningless.

Also proves the staged-vs-persisted split between
:class:`~tests.e2e.conftest.FakeConnection` (the host's staged, per-
connection view) and :class:`~tests.e2e.conftest.FakeMeshInterface` (the
device's own persisted state): a host-side mutation that never reaches
``writeConfig`` must stay invisible to the next connection, a persisted
write must be visible to it, a simulated device-side failure must be
logged but not persisted, a write through a closed connection must raise,
and firmware issue #7449's key-drop must only ever clear the device's
persisted copy, never a connection's own staged one.
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


def test_fake_connection_staged_change_without_writeconfig_is_invisible_to_next() -> None:
    device = FakeMeshInterface("deadbe01")
    connection = device.connect()

    connection.localNode.localConfig.lora.hop_limit = 7

    assert device.localNode.localConfig.lora.hop_limit == 0
    next_connection = device.connect()
    assert next_connection.localNode.localConfig.lora.hop_limit == 0


def test_fake_connection_writeconfig_persists_and_is_visible_to_the_next_connection() -> None:
    device = FakeMeshInterface("deadbe01")
    connection = device.connect()

    connection.localNode.localConfig.lora.hop_limit = 7
    connection.localNode.writeConfig("lora")

    assert device.localNode.localConfig.lora.hop_limit == 7
    next_connection = device.connect()
    assert next_connection.localNode.localConfig.lora.hop_limit == 7


def test_fake_connection_writeconfig_rejects_what_the_real_library_rejects() -> None:
    device = FakeMeshInterface("deadbe01")
    connection = device.connect()

    with pytest.raises(SystemExit):
        connection.localNode.writeConfig("statusmessage")

    assert device.localNode.written_sections == []
    assert device.localNode.transaction_calls == []


def test_fake_connection_fail_sections_logs_the_attempt_but_does_not_persist() -> None:
    device = FakeMeshInterface("deadbe01", fail_sections=frozenset({"lora"}))
    connection = device.connect()
    connection.localNode.localConfig.lora.hop_limit = 7

    with pytest.raises(RuntimeError):
        connection.localNode.writeConfig("lora")

    assert device.localNode.written_sections == ["lora"]
    assert device.localNode.localConfig.lora.hop_limit == 0


def test_fake_connection_writeconfig_after_close_raises_oserror() -> None:
    device = FakeMeshInterface("deadbe01")
    connection = device.connect()
    connection.close()

    with pytest.raises(OSError):
        connection.localNode.writeConfig("lora")


def test_fake_connection_drop_security_keys_clears_persisted_not_staged() -> None:
    device = FakeMeshInterface("deadbe01", drop_security_keys=True)
    connection = device.connect()
    connection.localNode.localConfig.security.public_key = b"\x01" * 32
    connection.localNode.localConfig.security.private_key = b"\x02" * 32

    connection.localNode.writeConfig("security")

    assert device.localNode.localConfig.security.public_key == b""
    assert device.localNode.localConfig.security.private_key == b""
    assert connection.localNode.localConfig.security.public_key == b"\x01" * 32
    assert connection.getPublicKey() is not None


def test_fake_connection_writeconfig_inside_a_transaction_does_not_persist_until_commit() -> None:
    """The gap the settings-transaction design needs the fakes to close.

    Before `beginSettingsTransaction`/`commitSettingsTransaction` existed
    on these fakes, every `writeConfig` persisted unconditionally and
    immediately -- there was no way to express "written, but not yet
    committed". `apply_plan` now relies on exactly that distinction for a
    reconnecting session: every non-security section is written and
    buffered, and only the commit actually reboots the (real) device. A
    section whose `writeConfig` fails inside the transaction (`bluetooth`
    here) is dropped, not buffered -- the attempt is still logged, but
    nothing from it reaches the commit.
    """
    device = FakeMeshInterface("deadbe01", fail_sections=frozenset({"bluetooth"}))
    connection = device.connect()

    connection.localNode.beginSettingsTransaction()
    connection.localNode.localConfig.lora.hop_limit = 7
    connection.localNode.writeConfig("lora")
    connection.localNode.localConfig.bluetooth.fixed_pin = 123456
    with pytest.raises(RuntimeError):
        connection.localNode.writeConfig("bluetooth")

    # Buffered, not yet persisted -- even this SAME connection's writeConfig
    # call left the device's own persisted config untouched.
    assert device.localNode.localConfig.lora.hop_limit == 0
    next_connection = device.connect()
    assert next_connection.localNode.localConfig.lora.hop_limit == 0

    connection.localNode.commitSettingsTransaction()

    # lora was buffered and committed; bluetooth failed and was never
    # buffered, so the commit has nothing of it to persist.
    assert device.localNode.localConfig.lora.hop_limit == 7
    assert device.localNode.localConfig.bluetooth.fixed_pin == 0
    later_connection = device.connect()
    assert later_connection.localNode.localConfig.lora.hop_limit == 7

    assert device.localNode.transaction_calls == ["<begin>", "lora", "bluetooth", "<commit>"]
    assert device.localNode.written_sections == ["lora", "bluetooth"]
