"""Tests for meshprovision.provisioning.connection.select_backend (pure)."""

from __future__ import annotations

import errno
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from meshprovision.errors import (
    AmbiguousDeviceError,
    ConnectionFailedError,
    DeviceNotFoundError,
    NonInteractiveError,
    UnsupportedTransportError,
)
from meshprovision.provisioning import connection, discovery
from meshprovision.provisioning.connection import (
    TRANSPORTS,
    BLEBackend,
    ConnectionRequest,
    DiscoveryResult,
    SerialBackend,
    TCPBackend,
    Transport,
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


def test_forced_serial_with_explicit_port_skips_discovery() -> None:
    """Use --port directly, bypassing discovery_result.

    --interface serial --port <X> must use <X> directly, never touching
    discovery_result -- even when discovery would report zero or several
    candidates.
    """
    result = DiscoveryResult(serial_ports=_serial_ports("/dev/ttyUSB0", "/dev/ttyUSB1"))
    backend = select_backend(ConnectionRequest(interface="serial", port="/dev/ttyEXPLICIT"), result)
    assert isinstance(backend, SerialBackend)
    assert backend.port == "/dev/ttyEXPLICIT"


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


def test_forced_ble_with_explicit_address_skips_discovery() -> None:
    """Use --ble-address directly, bypassing discovery_result.

    --interface ble --ble-address <X> must use <X> directly, never
    touching discovery_result -- even when discovery would report zero or
    several candidates.
    """
    result = DiscoveryResult(ble_devices=_ble_devices("AA:AA", "BB:BB"))
    backend = select_backend(ConnectionRequest(interface="ble", ble_address="EXPLICIT:AA"), result)
    assert isinstance(backend, BLEBackend)
    assert backend.address == "EXPLICIT:AA"


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


def test_auto_zero_serial_several_ble_interactive_chooser_returns_second() -> None:
    result = DiscoveryResult(ble_devices=_ble_devices("AA:AA", "BB:BB"))
    backend = select_backend(
        ConnectionRequest(non_interactive=False), result, chooser=lambda _summaries, _prompt: 1
    )
    assert isinstance(backend, BLEBackend)
    assert backend.address == "BB:BB"


def test_auto_zero_serial_several_ble_non_interactive_raises() -> None:
    result = DiscoveryResult(ble_devices=_ble_devices("AA:AA", "BB:BB"))
    with pytest.raises(NonInteractiveError):
        select_backend(ConnectionRequest(non_interactive=True), result)


def test_auto_zero_both_raises_with_hint() -> None:
    with pytest.raises(DeviceNotFoundError) as exc_info:
        select_backend(ConnectionRequest())
    hint = exc_info.value.hint or ""
    assert "--host" in hint
    assert "--ble-scan" in hint
    assert "--port" in hint


# ---------------------------------------------------------------------------
# describe / target / close_interface / connected.
# ---------------------------------------------------------------------------


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


def test_transports_values_match_the_click_choice_wiring() -> None:
    """Guards the exact regression Click 8.4.2 would otherwise cause.

    click.Choice(list(TRANSPORTS)) would match/display by each member's
    ``.name`` (``SERIAL``) rather than ``.value`` (``serial``), silently
    breaking every documented ``-i/--transport`` invocation -- the CLI
    layer must instead build its Choice from ``[t.value for t in
    TRANSPORTS]``. This pins the plain-string values themselves, in the
    order cli/provision.py's ``--interface`` help text documents them.
    """
    assert [t.value for t in TRANSPORTS] == ["serial", "ble", "tcp"]
    for value in ("serial", "ble", "tcp"):
        assert Transport(value).value == value


# ---------------------------------------------------------------------------
# Backend.connect() error mapping (impure -- patches the underlying
# meshtastic interface constructors rather than Backend.connect() itself).
# ---------------------------------------------------------------------------


def test_serial_backend_connect_wraps_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    import meshtastic.serial_interface as serial_mod

    def failing_init(self: object, **kwargs: object) -> None:
        raise OSError("no such device")

    monkeypatch.setattr(serial_mod.SerialInterface, "__init__", failing_init)

    backend = SerialBackend("/dev/ttyUSB0")
    with pytest.raises(ConnectionFailedError) as exc_info:
        backend.connect()
    assert exc_info.value.transport == "serial"
    assert exc_info.value.target == "/dev/ttyUSB0"
    assert exc_info.value.hint


@pytest.mark.skipif(sys.platform == "win32", reason="termios is POSIX-only")
@pytest.mark.parametrize(
    ("error_number", "hint_fragment"),
    [(errno.ENOTTY, "not a serial device"), (errno.EIO, "dialout")],
    ids=["enotty", "eio"],
)
def test_serial_backend_connect_wraps_termios_error(
    monkeypatch: pytest.MonkeyPatch, error_number: int, hint_fragment: str
) -> None:
    import termios

    import meshtastic.serial_interface as serial_mod

    def failing_init(self: object, **kwargs: object) -> None:
        raise termios.error(error_number, "termios failure")

    monkeypatch.setattr(serial_mod.SerialInterface, "__init__", failing_init)

    with pytest.raises(ConnectionFailedError) as exc_info:
        SerialBackend("/dev/ttyUSB0").connect()
    assert isinstance(exc_info.value.__cause__, termios.error)
    assert exc_info.value.exit_code == ConnectionFailedError.exit_code
    assert exc_info.value.hint is not None
    assert hint_fragment in exc_info.value.hint


@pytest.mark.skipif(sys.platform == "win32", reason="meshtastic skips termios on Windows")
def test_serial_backend_connect_on_a_regular_file_raises_connection_failed(
    tmp_path: Path,
) -> None:
    """The real meshtastic SerialInterface on a non-tty path: termios.error(ENOTTY), no hardware."""
    not_a_port = tmp_path / "not-a-port"
    not_a_port.write_bytes(b"")

    with pytest.raises(ConnectionFailedError) as exc_info:
        SerialBackend(str(not_a_port), timeout=2).connect()
    assert exc_info.value.target == str(not_a_port)
    assert exc_info.value.hint is not None
    assert "not a serial device" in exc_info.value.hint


def test_tcp_backend_connect_wraps_valueerror(monkeypatch: pytest.MonkeyPatch) -> None:
    import meshtastic.tcp_interface as tcp_mod

    def failing_init(self: object, **kwargs: object) -> None:
        raise ValueError("bad hostname")

    monkeypatch.setattr(tcp_mod.TCPInterface, "__init__", failing_init)

    backend = TCPBackend("bogus.invalid")
    with pytest.raises(ConnectionFailedError) as exc_info:
        backend.connect()
    assert exc_info.value.transport == "tcp"
    assert exc_info.value.hint


def test_ble_backend_connect_wraps_every_device_io_error(
    request: pytest.FixtureRequest,
    device_io_error: Callable[[], BaseException],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Connect must catch every type ``device_io_errors()`` names -- except ``SystemExit``.

    ``SystemExit`` deliberately stays out of connect's catch tuple: all
    three connect sites (serial, TCP, BLE) exclude it, and the only
    ``our_exit()`` reachable at connect is ``serial_interface``'s
    no-``devPath`` port-discovery path, which meshprovision never takes
    (it always passes an explicit target). This id is a strict xfail,
    not a skip, so a future regression that starts catching it here would
    be caught, not silently ignored.
    """
    if request.node.callspec.params["device_io_error"] == "system_exit":
        request.applymarker(
            pytest.mark.xfail(
                strict=True,
                reason=(
                    "connect deliberately does not catch SystemExit: no connect "
                    "path with an explicit target calls our_exit"
                ),
            )
        )

    import meshtastic.ble_interface as ble_mod

    exc = device_io_error()

    def failing_init(self: object, **kwargs: object) -> None:
        raise exc

    monkeypatch.setattr(ble_mod.BLEInterface, "__init__", failing_init)

    backend = BLEBackend("AA:BB:CC:DD:EE:FF")
    with pytest.raises(ConnectionFailedError) as exc_info:
        backend.connect()
    assert exc_info.value.transport == "ble"
    assert exc_info.value.target == "AA:BB:CC:DD:EE:FF"
    assert exc_info.value.hint
    assert exc_info.value.__cause__ is exc


def test_ble_backend_connect_import_failure_raises_unsupported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "meshtastic.ble_interface", None)

    backend = BLEBackend("AA:BB:CC:DD:EE:FF")
    with pytest.raises(UnsupportedTransportError):
        backend.connect()


# ---------------------------------------------------------------------------
# device_io_errors() -- the shared source of truth for connect and write.
# ---------------------------------------------------------------------------


def test_device_io_errors_includes_ble_types() -> None:
    from bleak.exc import BleakError
    from meshtastic.ble_interface import BLEInterface
    from meshtastic.mesh_interface import MeshInterface

    connection.device_io_errors.cache_clear()
    try:
        errors = connection.device_io_errors()
        assert MeshInterface.MeshInterfaceError in errors
        assert BLEInterface.BLEError in errors
        assert BleakError in errors
    finally:
        connection.device_io_errors.cache_clear()


def test_device_io_errors_degrades_gracefully_without_ble(monkeypatch: pytest.MonkeyPatch) -> None:
    from meshtastic.mesh_interface import MeshInterface

    monkeypatch.setitem(sys.modules, "meshtastic.ble_interface", None)
    connection.device_io_errors.cache_clear()
    try:
        errors = connection.device_io_errors()
        assert errors == (MeshInterface.MeshInterfaceError,)
    finally:
        connection.device_io_errors.cache_clear()


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
