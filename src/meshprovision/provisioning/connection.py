"""Transport selection and connection for Meshtastic devices.

This module is split into three layers that never blur together:

1. **Discovery** (:mod:`meshprovision.provisioning.discovery`) does I/O
   and makes no decisions -- it just reports what it found.
2. **Selection** (:func:`select_backend`, below) makes every decision and
   does no I/O -- it turns operator flags plus an already-computed
   :class:`DiscoveryResult` into exactly one :class:`ConnectionBackend`.
   This is what makes it unit-testable with hand-built
   :class:`DiscoveryResult` objects and zero mocking of ``pyserial``,
   ``bleak``, or ``meshtastic``.
3. **Connection** (each backend's ``connect()``) opens the device and
   makes no decisions.

:func:`select_backend` never calls a discovery function itself -- callers
(the CLI) run discovery and BLE scanning explicitly, then pass the result
in. That separation is an invariant the unit tests assert.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Protocol, TypeAlias

from meshprovision.errors import (
    AmbiguousDeviceError,
    ConnectionFailedError,
    DeviceNotFoundError,
    NonInteractiveError,
    UnsupportedTransportError,
)
from meshprovision.provisioning import discovery

if TYPE_CHECKING:
    from meshtastic.mesh_interface import MeshInterface

__all__ = [
    "DEFAULT_CONNECT_TIMEOUT",
    "TRANSPORTS",
    "BLEBackend",
    "ConnectionBackend",
    "ConnectionRequest",
    "DiscoveryResult",
    "SerialBackend",
    "TCPBackend",
    "Transport",
    "backend_for",
    "close_interface",
    "connected",
    "select_backend",
]

_logger = logging.getLogger(__name__)


class Transport(StrEnum):
    """The three supported connection transports."""

    SERIAL = "serial"
    BLE = "ble"
    TCP = "tcp"


TRANSPORTS: Final[tuple[Transport, ...]] = (Transport.SERIAL, Transport.BLE, Transport.TCP)
"""Every supported transport, in the order `--interface` documents them."""

DEFAULT_CONNECT_TIMEOUT: Final[int] = 300
"""Default connect timeout, in seconds -- matches meshtastic's own default."""

Chooser: TypeAlias = Callable[[Sequence[str], str], int]
"""An interactive chooser: given candidate summaries and a prompt, returns
the chosen index. Supplied by the CLI layer; never called when
:attr:`ConnectionRequest.non_interactive` is set."""


class ConnectionBackend(Protocol):
    """Structural protocol satisfied by every connection backend.

    Deliberately a ``Protocol`` with no shared base class: this is what
    lets e2e tests inject a fake device by handing over any object that
    satisfies this shape, with no inheritance required.
    """

    @property
    def transport(self) -> Transport:
        """The transport this backend connects over."""
        ...

    @property
    def target(self) -> str:
        """Operator-facing identifier of the device: port, address, or host:port."""
        ...

    def describe(self) -> str:
        """Return a one-line, operator-facing description of this backend.

        Returns:
            For example ``"serial /dev/ttyUSB0"``.
        """
        ...

    def connect(self) -> MeshInterface:
        """Open the device and return a live ``MeshInterface``.

        Returns:
            The connected interface.

        Raises:
            ConnectionFailedError: If the connection attempt fails.
        """
        ...


@dataclass(frozen=True, slots=True)
class SerialBackend:
    """Connects to a device over a serial (USB) port.

    Attributes:
        port: The OS device path, for example ``"/dev/ttyUSB0"``.
        timeout: Connect timeout, in seconds.
    """

    port: str
    timeout: int = DEFAULT_CONNECT_TIMEOUT

    @property
    def transport(self) -> Transport:
        """Always ``"serial"``."""
        return Transport.SERIAL

    @property
    def target(self) -> str:
        """Alias of :attr:`port`."""
        return self.port

    def describe(self) -> str:
        """Return a one-line description of this backend.

        Returns:
            For example ``"serial /dev/ttyUSB0"``.
        """
        return f"serial {self.port}"

    def connect(self) -> MeshInterface:
        """Open a serial connection.

        Returns:
            The connected interface.

        Raises:
            ConnectionFailedError: If the connection attempt fails.
        """
        from meshtastic.mesh_interface import MeshInterface
        from meshtastic.serial_interface import SerialInterface

        try:
            return SerialInterface(devPath=self.port, timeout=self.timeout)
        except (OSError, ValueError, RuntimeError, MeshInterface.MeshInterfaceError) as exc:
            raise ConnectionFailedError(
                f"Failed to connect over serial to {self.port}: {exc}",
                transport="serial",
                target=self.port,
                hint=(
                    "Check the cable, that the device is not already open in another "
                    "program, and that your user is in the 'dialout' group."
                ),
            ) from exc


@dataclass(frozen=True, slots=True)
class BLEBackend:
    """Connects to a device over BLE.

    Attributes:
        address: The BLE address (platform-dependent form).
        timeout: Connect timeout, in seconds.
    """

    address: str
    timeout: int = DEFAULT_CONNECT_TIMEOUT

    @property
    def transport(self) -> Transport:
        """Always ``"ble"``."""
        return Transport.BLE

    @property
    def target(self) -> str:
        """Alias of :attr:`address`."""
        return self.address

    def describe(self) -> str:
        """Return a one-line description of this backend.

        Returns:
            For example ``"ble AA:BB:CC:DD:EE:FF"``.
        """
        return f"ble {self.address}"

    def connect(self) -> MeshInterface:
        """Open a BLE connection.

        Returns:
            The connected interface.

        Raises:
            UnsupportedTransportError: If BLE support is unavailable.
            ConnectionFailedError: If the connection attempt fails.
        """
        discovery.require_ble()
        try:
            from meshtastic.ble_interface import BLEInterface
        except ImportError as exc:
            raise UnsupportedTransportError(
                "BLE support is not available.",
                transport="ble",
                hint=discovery.BLE_UNAVAILABLE_HINT,
            ) from exc
        from meshtastic.mesh_interface import MeshInterface

        try:
            return BLEInterface(address=self.address, timeout=self.timeout)
        except (OSError, ValueError, RuntimeError, MeshInterface.MeshInterfaceError) as exc:
            raise ConnectionFailedError(
                f"Failed to connect over BLE to {self.address}: {exc}",
                transport="ble",
                target=self.address,
                hint=(
                    "Ensure the device is powered on, in range, and not already "
                    "connected from another program."
                ),
            ) from exc


@dataclass(frozen=True, slots=True)
class TCPBackend:
    """Connects to a device over TCP.

    Attributes:
        host: The target host: a hostname, IPv4 literal, or bare IPv6
            literal.
        port: The target TCP port.
        timeout: Connect timeout, in seconds.
    """

    host: str
    port: int = discovery.DEFAULT_TCP_PORT
    timeout: int = DEFAULT_CONNECT_TIMEOUT

    @property
    def transport(self) -> Transport:
        """Always ``"tcp"``."""
        return Transport.TCP

    @property
    def target(self) -> str:
        """``"host:port"`` (bracketed for an IPv6 host)."""
        return str(discovery.TcpTarget(self.host, self.port))

    def describe(self) -> str:
        """Return a one-line description of this backend.

        Returns:
            For example ``"tcp 192.168.1.50:4403"``.
        """
        return f"tcp {self.target}"

    def connect(self) -> MeshInterface:
        """Open a TCP connection.

        Returns:
            The connected interface.

        Raises:
            ConnectionFailedError: If the connection attempt fails.
        """
        from meshtastic.mesh_interface import MeshInterface
        from meshtastic.tcp_interface import TCPInterface

        try:
            return TCPInterface(hostname=self.host, portNumber=self.port, timeout=self.timeout)
        except (OSError, ValueError, RuntimeError, MeshInterface.MeshInterfaceError) as exc:
            raise ConnectionFailedError(
                f"Failed to connect over TCP to {self.target}: {exc}",
                transport="tcp",
                target=self.target,
                hint="Check the host is reachable and the Meshtastic API port is open.",
            ) from exc


@dataclass(frozen=True, slots=True)
class ConnectionRequest:
    """Operator-supplied connection intent, before any device is resolved.

    Attributes:
        interface: Forces a transport when set. Forcing turns every
            ambiguity into a hard error rather than a prompt, which is
            what makes ``mesh provision --interface tcp --host ...``
            cron-safe.
        port: An explicit serial port path.
        ble_address: An explicit BLE address.
        ble_scan: Whether the CLI should run a BLE scan before calling
            :func:`select_backend`. Consumed by the CLI layer only --
            :func:`select_backend` itself never scans.
        host: An explicit TCP host (optionally ``host:port``).
        non_interactive: When ``True``, an ambiguous auto-selection that
            would otherwise prompt raises :class:`NonInteractiveError`
            instead. The CLI defaults this to ``True`` when stdin is not
            a TTY.
        timeout: Connect timeout, in seconds, passed through to whichever
            backend is selected.
    """

    interface: Transport | None = None
    port: str | None = None
    ble_address: str | None = None
    ble_scan: bool = False
    host: str | None = None
    non_interactive: bool = True
    timeout: int = DEFAULT_CONNECT_TIMEOUT


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    """Immutable snapshot of what discovery found, for :func:`select_backend`.

    Attributes:
        serial_ports: Serial ports found by
            :func:`meshprovision.provisioning.discovery.discover_serial_ports`.
        ble_devices: BLE devices found by
            :func:`meshprovision.provisioning.discovery.discover_ble_devices`,
            or an empty tuple if no scan was run.
    """

    serial_ports: tuple[discovery.SerialPortInfo, ...] = ()
    ble_devices: tuple[discovery.BleDeviceInfo, ...] = ()


_EMPTY_DISCOVERY: Final[DiscoveryResult] = DiscoveryResult()
"""Shared empty :class:`DiscoveryResult`, used as ``select_backend``'s default."""


def _count_explicit_targets(request: ConnectionRequest) -> tuple[str, ...]:
    """Return the names of every explicit target flag set on ``request``.

    Args:
        request: The connection request to inspect.

    Returns:
        A tuple of flag names (``"port"``, ``"ble_address"``, ``"host"``)
        among those that are not ``None``, in that order.
    """
    return tuple(
        name
        for name, value in (
            ("port", request.port),
            ("ble_address", request.ble_address),
            ("host", request.host),
        )
        if value is not None
    )


def _select_forced_serial(
    request: ConnectionRequest, discovery_result: DiscoveryResult
) -> ConnectionBackend:
    """Resolve a backend when ``--interface serial`` was forced.

    Args:
        request: The connection request.
        discovery_result: Previously-run discovery results.

    Returns:
        A :class:`SerialBackend`.

    Raises:
        DeviceNotFoundError: If no serial port was requested and none was
            found.
        AmbiguousDeviceError: If no serial port was requested and more
            than one was found.
    """
    if request.port is not None:
        return SerialBackend(request.port, timeout=request.timeout)
    ports = discovery_result.serial_ports
    if len(ports) == 0:
        raise DeviceNotFoundError(
            "No serial device found.", transport="serial", hint="Pass --port explicitly."
        )
    if len(ports) == 1:
        return SerialBackend(ports[0].device, timeout=request.timeout)
    raise AmbiguousDeviceError(
        "Multiple serial ports found; pass --port to choose.",
        transport="serial",
        candidates=tuple(port.device for port in ports),
        hint="Pass --port to choose.",
    )


def _select_forced_ble(
    request: ConnectionRequest, discovery_result: DiscoveryResult
) -> ConnectionBackend:
    """Resolve a backend when ``--interface ble`` was forced.

    Args:
        request: The connection request.
        discovery_result: Previously-run discovery results.

    Returns:
        A :class:`BLEBackend`.

    Raises:
        DeviceNotFoundError: If no BLE address was requested and none was
            found.
        AmbiguousDeviceError: If no BLE address was requested and more
            than one was found.
    """
    if request.ble_address is not None:
        return BLEBackend(request.ble_address, timeout=request.timeout)
    devices = discovery_result.ble_devices
    if len(devices) == 0:
        raise DeviceNotFoundError(
            "No BLE device found.", transport="ble", hint="Pass --ble-address explicitly."
        )
    if len(devices) == 1:
        return BLEBackend(devices[0].address, timeout=request.timeout)
    raise AmbiguousDeviceError(
        "Multiple BLE devices found; pass --ble-address to choose.",
        transport="ble",
        candidates=tuple(device.address for device in devices),
        hint="Pass --ble-address to choose.",
    )


def _select_forced_tcp(request: ConnectionRequest) -> ConnectionBackend:
    """Resolve a backend when ``--interface tcp`` was forced.

    Args:
        request: The connection request.

    Returns:
        A :class:`TCPBackend`.

    Raises:
        DeviceNotFoundError: If ``--host`` was not given.
    """
    if request.host is None:
        raise DeviceNotFoundError("No TCP host specified.", transport="tcp", hint="Pass --host.")
    target = discovery.parse_tcp_target(request.host)
    return TCPBackend(target.host, port=target.port, timeout=request.timeout)


def _select_forced(
    request: ConnectionRequest, discovery_result: DiscoveryResult
) -> ConnectionBackend:
    """Resolve a backend when ``request.interface`` forces a transport.

    Args:
        request: The connection request. ``request.interface`` must not
            be ``None``.
        discovery_result: Previously-run discovery results.

    Returns:
        The resolved backend.

    Raises:
        UnsupportedTransportError: If ``request.interface`` is not one of
            :data:`TRANSPORTS`.
    """
    if request.interface == "serial":
        return _select_forced_serial(request, discovery_result)
    if request.interface == "ble":
        return _select_forced_ble(request, discovery_result)
    if request.interface == "tcp":
        return _select_forced_tcp(request)
    raise UnsupportedTransportError(
        f"Unsupported transport: {request.interface!r}", transport=str(request.interface)
    )


def _select_auto(
    request: ConnectionRequest,
    discovery_result: DiscoveryResult,
    chooser: Chooser | None,
) -> ConnectionBackend:
    """Resolve a backend with no explicit flags: serial first, then BLE.

    Args:
        request: The connection request.
        discovery_result: Previously-run discovery results.
        chooser: Interactive chooser, or ``None`` when unavailable.

    Returns:
        The resolved backend.

    Raises:
        NonInteractiveError: If more than one candidate was found and no
            interactive chooser is usable.
        AmbiguousDeviceError: If a chooser returned an out-of-range index.
        DeviceNotFoundError: If no serial or BLE device was found at all.
    """
    ports = discovery_result.serial_ports
    if len(ports) == 1:
        return SerialBackend(ports[0].device, timeout=request.timeout)
    if len(ports) > 1:
        return _choose_one(
            [port.summary() for port in ports],
            request,
            chooser,
            transport=Transport.SERIAL,
            build=lambda index: SerialBackend(ports[index].device, timeout=request.timeout),
        )

    devices = discovery_result.ble_devices
    if len(devices) == 1:
        return BLEBackend(devices[0].address, timeout=request.timeout)
    if len(devices) > 1:
        return _choose_one(
            [device.summary() for device in devices],
            request,
            chooser,
            transport=Transport.BLE,
            build=lambda index: BLEBackend(devices[index].address, timeout=request.timeout),
        )

    raise DeviceNotFoundError(
        "No serial or BLE device found.",
        hint=(
            "No serial or BLE device found. Pass --host <ip> for TCP, --ble-scan to scan "
            "for BLE devices, or --port <path>."
        ),
    )


def _choose_one(
    summaries: list[str],
    request: ConnectionRequest,
    chooser: Chooser | None,
    *,
    transport: Transport,
    build: Callable[[int], ConnectionBackend],
) -> ConnectionBackend:
    """Prompt for (or refuse to prompt for) one choice among several candidates.

    Args:
        summaries: One-line summary per candidate, in display order.
        request: The connection request (consulted for
            ``non_interactive``).
        chooser: Interactive chooser, or ``None`` when unavailable.
        transport: The transport these candidates belong to, for error
            reporting.
        build: Builds the backend from a chosen index.

    Returns:
        The backend built from the chosen index.

    Raises:
        NonInteractiveError: If ``request.non_interactive`` is set, or no
            ``chooser`` is available.
        AmbiguousDeviceError: If ``chooser`` returned an out-of-range
            index.
    """
    prompt = f"Select a {transport} device"
    if request.non_interactive or chooser is None:
        raise NonInteractiveError(
            f"Multiple {transport} candidates found; a selection is required.",
            prompt=prompt,
            hint=(
                f"Pass --{'port' if transport == 'serial' else 'ble-address'}, or run "
                "without --non-interactive on a TTY."
            ),
        )
    index = chooser(summaries, prompt)
    if not (0 <= index < len(summaries)):
        raise AmbiguousDeviceError(
            f"Chooser returned out-of-range index {index}.",
            transport=transport,
            candidates=tuple(summaries),
        )
    return build(index)


def select_backend(
    request: ConnectionRequest,
    discovery_result: DiscoveryResult = _EMPTY_DISCOVERY,
    *,
    chooser: Chooser | None = None,
) -> ConnectionBackend:
    """Choose exactly one :class:`ConnectionBackend`, with no I/O.

    Pure decision function: it never calls a discovery function itself,
    consuming only whatever ``discovery_result`` already holds. Selection
    priority:

    0. If more than one of ``port``/``ble_address``/``host`` is set,
       that is always an error, regardless of ``interface``.
    1. ``request.interface`` set: it forces the transport and turns
       every ambiguity into a hard error rather than a prompt.
    2. No ``interface``, but an explicit target flag is set: honoured in
       priority order ``port`` > ``ble_address`` > ``host``.
    3. Auto mode: serial first (one port auto-uses it; zero falls
       through to BLE, then to TCP-only failure; more than one prompts,
       or errors when non-interactive).

    Args:
        request: The operator's connection intent.
        discovery_result: Previously-run discovery results. Defaults to
            an empty result (as if no discovery had been run).
        chooser: Interactive chooser used only in auto mode when more
            than one candidate is found and ``request.non_interactive``
            is ``False``.

    Returns:
        The single resolved :class:`ConnectionBackend`.

    Raises:
        AmbiguousDeviceError: If multiple target flags are set, or if
            multiple candidates are found and cannot be disambiguated.
        DeviceNotFoundError: If a forced transport (or auto mode) finds
            no candidate device.
        NonInteractiveError: If disambiguation would require a prompt but
            none is available.
        UnsupportedTransportError: If ``request.interface`` names a
            transport outside :data:`TRANSPORTS`.
    """
    explicit = _count_explicit_targets(request)
    if len(explicit) > 1:
        raise AmbiguousDeviceError(
            "Pass only one of --port, --ble-address, --host.", candidates=explicit
        )

    if request.interface is not None:
        return _select_forced(request, discovery_result)

    if request.port is not None:
        return SerialBackend(request.port, timeout=request.timeout)
    if request.ble_address is not None:
        return BLEBackend(request.ble_address, timeout=request.timeout)
    if request.host is not None:
        target = discovery.parse_tcp_target(request.host)
        return TCPBackend(target.host, port=target.port, timeout=request.timeout)

    return _select_auto(request, discovery_result, chooser)


def backend_for(
    transport: Transport, target: str, *, timeout: int = DEFAULT_CONNECT_TIMEOUT
) -> ConnectionBackend:
    """Build a backend directly from an already-known transport and target.

    Useful for callers (tests, scripted flows) that already know exactly
    which device to use and want to skip :func:`select_backend` entirely.

    Args:
        transport: The transport to connect over.
        target: The port, BLE address, or TCP host (optionally
            ``host:port``) to connect to.
        timeout: Connect timeout, in seconds.

    Returns:
        The corresponding backend.

    Raises:
        UnsupportedTransportError: If ``transport`` is not one of
            :data:`TRANSPORTS`.
        ConnectionBackendError: If ``transport`` is ``"tcp"`` and
            ``target`` fails TCP-target parsing.
    """
    if transport == "serial":
        return SerialBackend(target, timeout=timeout)
    if transport == "ble":
        return BLEBackend(target, timeout=timeout)
    if transport == "tcp":
        parsed = discovery.parse_tcp_target(target)
        return TCPBackend(parsed.host, port=parsed.port, timeout=timeout)
    raise UnsupportedTransportError(
        f"Unsupported transport: {transport!r}", transport=str(transport)
    )


def close_interface(iface: MeshInterface) -> None:
    """Close a ``MeshInterface``, never masking a caller's real error.

    Intended for use in a ``finally`` block (see :func:`connected`):
    logs at DEBUG on failure rather than raising, so a close-time problem
    never hides whatever exception was already propagating.

    Args:
        iface: The interface to close.
    """
    try:
        iface.close()
    except (OSError, AttributeError, RuntimeError):
        _logger.debug("Failed to close MeshInterface cleanly.", exc_info=True)


@contextlib.contextmanager
def connected(backend: ConnectionBackend) -> Iterator[MeshInterface]:
    """Context manager: connect, yield the interface, always close it.

    Args:
        backend: The backend to connect through.

    Yields:
        The live, connected interface.

    Raises:
        ConnectionFailedError: If ``backend.connect()`` fails. Closing is
            not attempted in that case, since no interface was obtained.
    """
    iface = backend.connect()
    try:
        yield iface
    finally:
        close_interface(iface)
