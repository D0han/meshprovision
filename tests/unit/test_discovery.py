"""Tests for meshprovision.provisioning.discovery (pure parts only)."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from meshprovision.errors import ConnectionBackendError
from meshprovision.provisioning import discovery
from meshprovision.provisioning.discovery import (
    BleDeviceInfo,
    SerialPortInfo,
    TcpTarget,
    discover_serial_ports,
    is_valid_hostname,
    parse_tcp_target,
    validate_tcp_host,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# parse_tcp_target.
# ---------------------------------------------------------------------------


def test_parse_tcp_target_bare_host() -> None:
    target = parse_tcp_target("host")
    assert target.host == "host"
    assert target.port == discovery.DEFAULT_TCP_PORT


def test_parse_tcp_target_host_and_port() -> None:
    target = parse_tcp_target("host:1234")
    assert target.host == "host"
    assert target.port == 1234


def test_parse_tcp_target_ipv4() -> None:
    target = parse_tcp_target("192.168.1.50")
    assert target.host == "192.168.1.50"


def test_parse_tcp_target_bracketed_ipv6_with_port() -> None:
    target = parse_tcp_target("[::1]:4403")
    assert target.host == "::1"
    assert target.port == 4403


def test_parse_tcp_target_bare_ipv6() -> None:
    target = parse_tcp_target("::1")
    assert target.host == "::1"
    assert target.port == discovery.DEFAULT_TCP_PORT


@pytest.mark.parametrize("value", ["host:notaport", "host:99999", "host:0"])
def test_parse_tcp_target_invalid_port_raises(value: str) -> None:
    with pytest.raises(ConnectionBackendError):
        parse_tcp_target(value)


def test_parse_tcp_target_empty_host_raises() -> None:
    with pytest.raises(ConnectionBackendError):
        parse_tcp_target("")


def test_parse_tcp_target_invalid_hostname_raises() -> None:
    with pytest.raises(ConnectionBackendError):
        parse_tcp_target("not a valid host!!")


# ---------------------------------------------------------------------------
# is_valid_hostname / validate_tcp_host.
# ---------------------------------------------------------------------------


def test_is_valid_hostname_valid_labels() -> None:
    assert is_valid_hostname("example.com") is True
    assert is_valid_hostname("a-b.c") is True


def test_is_valid_hostname_64_char_label_invalid() -> None:
    label = "a" * 64
    assert is_valid_hostname(label) is False


def test_is_valid_hostname_63_char_label_valid() -> None:
    label = "a" * 63
    assert is_valid_hostname(label) is True


def test_is_valid_hostname_254_char_name_invalid() -> None:
    name = ".".join(["a" * 50] * 5)
    assert len(name) > 253
    assert is_valid_hostname(name) is False


def test_is_valid_hostname_trailing_dot() -> None:
    assert is_valid_hostname("example.com.") is True


def test_validate_tcp_host_bracketed_ipv6() -> None:
    assert validate_tcp_host("[::1]") == "::1"


def test_validate_tcp_host_invalid_raises() -> None:
    with pytest.raises(ConnectionBackendError):
        validate_tcp_host("not a host!!")


# ---------------------------------------------------------------------------
# Value objects.
# ---------------------------------------------------------------------------


def test_serial_port_info_properties() -> None:
    info = SerialPortInfo(device="/dev/ttyUSB0", description="CP2102", vid=0x10C4, pid=0xEA60)
    assert info.vid_pid == "10c4:ea60"
    assert info.vendor == "Silicon Labs CP210x"
    assert info.is_likely_meshtastic is True
    assert "/dev/ttyUSB0" in info.summary()
    assert "10c4:ea60" in info.summary()

    unknown = SerialPortInfo(device="/dev/ttyUSB1", vid=0xFFFF, pid=0x0001)
    assert unknown.vendor is None
    assert unknown.is_likely_meshtastic is False

    no_vid = SerialPortInfo(device="/dev/ttyUSB2")
    assert no_vid.vid_pid is None
    assert no_vid.summary() == "/dev/ttyUSB2"


def test_ble_device_info_summary() -> None:
    info = BleDeviceInfo(address="AA:BB:CC:DD:EE:FF", name="Meshtastic_1234", rssi=-63)
    summary = info.summary()
    assert "AA:BB:CC:DD:EE:FF" in summary
    assert "Meshtastic_1234" in summary
    assert "-63" in summary

    unknown = BleDeviceInfo(address="11:22:33:44:55:66")
    assert "(unknown)" in unknown.summary()


def test_tcp_target_str() -> None:
    assert str(TcpTarget("192.168.1.50", 4403)) == "192.168.1.50:4403"
    assert str(TcpTarget("::1", 4403)) == "[::1]:4403"
    assert TcpTarget("host", 1).summary() == str(TcpTarget("host", 1))


# ---------------------------------------------------------------------------
# discover_serial_ports, with pyserial.tools.list_ports.comports monkeypatched.
# ---------------------------------------------------------------------------


@dataclass
class _FakeListPortInfo:
    device: str
    description: str | None = "n/a"
    vid: int | None = None
    pid: int | None = None
    manufacturer: str | None = None
    product: str | None = None
    serial_number: str | None = None


def test_discover_serial_ports_excludes_debug_probes_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    excluded_vid = next(iter(discovery.EXCLUDED_VIDS))
    fake_ports = [
        _FakeListPortInfo(device="/dev/ttyACM0", vid=excluded_vid, pid=1),
        _FakeListPortInfo(device="/dev/ttyUSB0", vid=0x239A, pid=2),
    ]
    monkeypatch.setattr(discovery.list_ports, "comports", lambda: fake_ports)

    result = discover_serial_ports()
    devices = {info.device for info in result}
    assert "/dev/ttyACM0" not in devices
    assert "/dev/ttyUSB0" in devices


def test_discover_serial_ports_include_all_keeps_debug_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    excluded_vid = next(iter(discovery.EXCLUDED_VIDS))
    fake_ports = [_FakeListPortInfo(device="/dev/ttyACM0", vid=excluded_vid, pid=1)]
    monkeypatch.setattr(discovery.list_ports, "comports", lambda: fake_ports)

    result = discover_serial_ports(include_all=True)
    assert any(info.device == "/dev/ttyACM0" for info in result)


def test_discover_serial_ports_none_vid_never_dropped(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_ports = [_FakeListPortInfo(device="/dev/ttyS0", vid=None, pid=None)]
    monkeypatch.setattr(discovery.list_ports, "comports", lambda: fake_ports)

    result = discover_serial_ports()
    assert any(info.device == "/dev/ttyS0" for info in result)


def test_discover_serial_ports_sorts_likely_first_then_alphabetical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_ports = [
        _FakeListPortInfo(device="/dev/ttyZZZ", vid=None),
        _FakeListPortInfo(device="/dev/ttyAAA", vid=0x239A),
        _FakeListPortInfo(device="/dev/ttyBBB", vid=0x303A),
    ]
    monkeypatch.setattr(discovery.list_ports, "comports", lambda: fake_ports)

    result = discover_serial_ports()
    assert [info.device for info in result] == ["/dev/ttyAAA", "/dev/ttyBBB", "/dev/ttyZZZ"]


def test_discover_serial_ports_oserror_raises_connection_backend_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise() -> None:
        raise OSError("boom")

    monkeypatch.setattr(discovery.list_ports, "comports", _raise)
    with pytest.raises(ConnectionBackendError):
        discover_serial_ports()
