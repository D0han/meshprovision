"""Tests for meshprovision.provisioning.connection.select_backend (pure)."""

from __future__ import annotations

import pytest

from meshprovision.errors import (
    AmbiguousDeviceError,
    DeviceNotFoundError,
    NonInteractiveError,
    UnsupportedTransportError,
)
from meshprovision.provisioning import connection, discovery
from meshprovision.provisioning.connection import (
    BLEBackend,
    ConnectionRequest,
    DiscoveryResult,
    SerialBackend,
    TCPBackend,
    backend_for,
    select_backend,
)

pytestmark = pytest.mark.unit


def _serial_ports(*devices: str) -> tuple[discovery.SerialPortInfo, ...]:
    return tuple(discovery.SerialPortInfo(device=d) for d in devices)


def _ble_devices(*addresses: str) -> tuple[discovery.BleDeviceInfo, ...]:
    return tuple(discovery.BleDeviceInfo(address=a) for a in addresses)


# ---------------------------------------------------------------------------
# Explicit target flags.
# ---------------------------------------------------------------------------


def test_explicit_port_wins() -> None:
    backend = select_backend(ConnectionRequest(port="/dev/ttyUSB0"))
    assert isinstance(backend, SerialBackend)
    assert backend.port == "/dev/ttyUSB0"


def test_explicit_ble_address() -> None:
    backend = select_backend(ConnectionRequest(ble_address="AA:BB:CC:DD:EE:FF"))
    assert isinstance(backend, BLEBackend)
    assert backend.address == "AA:BB:CC:DD:EE:FF"


def test_explicit_host_without_port() -> None:
    backend = select_backend(ConnectionRequest(host="192.168.1.50"))
    assert isinstance(backend, TCPBackend)
    assert backend.host == "192.168.1.50"
    assert backend.port == discovery.DEFAULT_TCP_PORT


def test_explicit_host_with_port_suffix() -> None:
    backend = select_backend(ConnectionRequest(host="192.168.1.50:1234"))
    assert isinstance(backend, TCPBackend)
    assert backend.port == 1234


def test_explicit_host_ipv6_literal() -> None:
    backend = select_backend(ConnectionRequest(host="[::1]:4403"))
    assert isinstance(backend, TCPBackend)
    assert backend.host == "::1"


def test_two_explicit_targets_is_ambiguous() -> None:
    with pytest.raises(AmbiguousDeviceError) as exc_info:
        select_backend(ConnectionRequest(port="/dev/ttyUSB0", host="192.168.1.50"))
    assert "port" in exc_info.value.candidates
    assert "host" in exc_info.value.candidates


# ---------------------------------------------------------------------------
# Forced interfaces.
# ---------------------------------------------------------------------------


def test_forced_serial_zero_candidates_raises_not_found() -> None:
    with pytest.raises(DeviceNotFoundError):
        select_backend(ConnectionRequest(interface="serial"))


def test_forced_serial_one_candidate_auto_uses() -> None:
    result = DiscoveryResult(serial_ports=_serial_ports("/dev/ttyUSB0"))
    backend = select_backend(ConnectionRequest(interface="serial"), result)
    assert isinstance(backend, SerialBackend)
    assert backend.port == "/dev/ttyUSB0"


def test_forced_serial_many_candidates_ambiguous_even_with_chooser() -> None:
    result = DiscoveryResult(serial_ports=_serial_ports("/dev/ttyUSB0", "/dev/ttyUSB1"))
    with pytest.raises(AmbiguousDeviceError):
        select_backend(
            ConnectionRequest(interface="serial"), result, chooser=lambda _summaries, _prompt: 0
        )


def test_forced_ble_zero_candidates_raises_not_found() -> None:
    with pytest.raises(DeviceNotFoundError):
        select_backend(ConnectionRequest(interface="ble"))


def test_forced_ble_one_candidate_auto_uses() -> None:
    result = DiscoveryResult(ble_devices=_ble_devices("AA:BB:CC:DD:EE:FF"))
    backend = select_backend(ConnectionRequest(interface="ble"), result)
    assert isinstance(backend, BLEBackend)


def test_forced_ble_many_candidates_ambiguous() -> None:
    result = DiscoveryResult(ble_devices=_ble_devices("AA:AA", "BB:BB"))
    with pytest.raises(AmbiguousDeviceError):
        select_backend(
            ConnectionRequest(interface="ble"), result, chooser=lambda _summaries, _prompt: 0
        )


def test_forced_tcp_without_host_raises() -> None:
    with pytest.raises(DeviceNotFoundError):
        select_backend(ConnectionRequest(interface="tcp"))


def test_forced_tcp_with_host() -> None:
    backend = select_backend(ConnectionRequest(interface="tcp", host="192.168.1.50"))
    assert isinstance(backend, TCPBackend)


def test_unsupported_interface_string() -> None:
    with pytest.raises(UnsupportedTransportError):
        select_backend(ConnectionRequest(interface="carrier-pigeon"))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Auto mode.
# ---------------------------------------------------------------------------


def test_auto_one_serial_port() -> None:
    result = DiscoveryResult(serial_ports=_serial_ports("/dev/ttyUSB0"))
    backend = select_backend(ConnectionRequest(), result)
    assert isinstance(backend, SerialBackend)


def test_auto_several_ports_non_interactive_raises() -> None:
    result = DiscoveryResult(serial_ports=_serial_ports("/dev/ttyUSB0", "/dev/ttyUSB1"))
    with pytest.raises(NonInteractiveError) as exc_info:
        select_backend(ConnectionRequest(non_interactive=True), result)
    assert exc_info.value.prompt


def test_auto_several_ports_interactive_chooser_returns_second() -> None:
    result = DiscoveryResult(serial_ports=_serial_ports("/dev/ttyUSB0", "/dev/ttyUSB1"))
    backend = select_backend(
        ConnectionRequest(non_interactive=False), result, chooser=lambda _summaries, _prompt: 1
    )
    assert isinstance(backend, SerialBackend)
    assert backend.port == "/dev/ttyUSB1"


def test_auto_chooser_out_of_range_raises_ambiguous() -> None:
    result = DiscoveryResult(serial_ports=_serial_ports("/dev/ttyUSB0", "/dev/ttyUSB1"))
    with pytest.raises(AmbiguousDeviceError):
        select_backend(
            ConnectionRequest(non_interactive=False), result, chooser=lambda _summaries, _prompt: 99
        )


def test_auto_zero_serial_one_ble() -> None:
    result = DiscoveryResult(ble_devices=_ble_devices("AA:BB:CC:DD:EE:FF"))
    backend = select_backend(ConnectionRequest(), result)
    assert isinstance(backend, BLEBackend)


def test_auto_zero_both_raises_with_hint() -> None:
    with pytest.raises(DeviceNotFoundError) as exc_info:
        select_backend(ConnectionRequest())
    hint = exc_info.value.hint or ""
    assert "--host" in hint
    assert "--ble-scan" in hint
    assert "--port" in hint


# ---------------------------------------------------------------------------
# backend_for / describe / target / close_interface / connected.
# ---------------------------------------------------------------------------


def test_backend_for_all_transports() -> None:
    assert isinstance(backend_for("serial", "/dev/ttyUSB0"), SerialBackend)
    assert isinstance(backend_for("ble", "AA:BB"), BLEBackend)
    tcp = backend_for("tcp", "host:1234")
    assert isinstance(tcp, TCPBackend)
    assert tcp.port == 1234


def test_backend_for_unsupported_raises() -> None:
    with pytest.raises(UnsupportedTransportError):
        backend_for("carrier-pigeon", "x")  # type: ignore[arg-type]


def test_backend_describe_and_target() -> None:
    serial = SerialBackend("/dev/ttyUSB0")
    assert serial.transport == "serial"
    assert serial.target == "/dev/ttyUSB0"
    assert serial.describe() == "serial /dev/ttyUSB0"

    ble = BLEBackend("AA:BB:CC:DD:EE:FF")
    assert ble.transport == "ble"
    assert ble.describe() == "ble AA:BB:CC:DD:EE:FF"

    tcp = TCPBackend("::1", 4403)
    assert tcp.transport == "tcp"
    assert tcp.target == "[::1]:4403"
    assert tcp.describe() == "tcp [::1]:4403"


def test_close_interface_swallows_oserror() -> None:
    class _BadIface:
        def close(self) -> None:
            raise OSError("boom")

    connection.close_interface(_BadIface())  # must not raise


def test_connected_closes_interface_even_when_body_raises() -> None:
    closed = []

    class _FakeIface:
        def close(self) -> None:
            closed.append(True)

    class _FakeBackend:
        transport = "serial"
        target = "/dev/ttyUSB0"

        def describe(self) -> str:
            return "fake"

        def connect(self) -> _FakeIface:
            return _FakeIface()

    with pytest.raises(RuntimeError), connection.connected(_FakeBackend()):  # type: ignore[arg-type]
        raise RuntimeError("boom")

    assert closed == [True]
