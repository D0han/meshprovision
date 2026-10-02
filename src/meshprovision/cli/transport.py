"""Device-connection/transport setup shared by ``provision``/``adopt``/``admin``.

Split out of :mod:`meshprovision.cli.provision` (1485 lines) because the
transport-selection flags, backend resolution, and device-session
management here are not specific to the ``provision`` command -- ``mesh
adopt`` and ``mesh admin bootstrap`` depend on them too.
"""

from __future__ import annotations

import contextlib
import dataclasses
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, TypeVar

import click

from meshprovision.cli.progress import heartbeat
from meshprovision.errors import DeviceNotFoundError
from meshprovision.provisioning import connection, discovery
from meshprovision.provisioning.apply_session import (
    DeviceSession,
    InPlaceSession,
    ReconnectingSession,
)

if TYPE_CHECKING:
    from meshtastic.mesh_interface import MeshInterface

    from meshprovision.cli.common import CliContext

__all__ = [
    "TransportOptions",
    "connected_with_progress",
    "device_session",
    "resolve_backend",
    "transport_options",
]

F = TypeVar("F", bound=Callable[..., Any])


def _backend_timeout(backend: connection.ConnectionBackend) -> float:
    """Best-effort connect timeout for a backend, for heartbeat display only.

    Every concrete backend (:class:`~meshprovision.provisioning.
    connection.SerialBackend`/``BLEBackend``/``TCPBackend``) carries its
    own ``timeout`` field, but :class:`~meshprovision.provisioning.
    connection.ConnectionBackend` is a bare structural ``Protocol`` with
    no such member, so a test double need not declare one. Falls back to
    :data:`~meshprovision.provisioning.connection.DEFAULT_CONNECT_TIMEOUT`
    -- this value is purely cosmetic (the heartbeat's "``/ Ns``" label);
    it never enforces anything itself.

    Args:
        backend: The backend about to be connected.

    Returns:
        ``backend.timeout`` if present, else the default connect timeout.
    """
    return float(getattr(backend, "timeout", connection.DEFAULT_CONNECT_TIMEOUT))


def _discover_ble_devices_with_progress(
    ctx: CliContext, *, timeout: float
) -> tuple[discovery.BleDeviceInfo, ...]:
    """Scan for BLE devices with a heartbeat ticking through the wait.

    Args:
        ctx: The shared CLI context.
        timeout: The scan duration, in seconds (``--ble-scan-timeout``).

    Returns:
        The discovered devices, per
        :func:`~meshprovision.provisioning.discovery.discover_ble_devices`.
    """
    with heartbeat(ctx, "scanning", timeout=timeout):
        return discovery.discover_ble_devices(timeout=timeout)


@dataclass(frozen=True, slots=True)
class TransportOptions:
    """Operator-supplied transport-selection flags, before resolution.

    Attributes:
        interface: Forces a transport (``"serial"``, ``"ble"``, or
            ``"tcp"``) when set, from ``--interface``.
        port: An explicit serial port path, from ``--port``.
        ble_address: An explicit BLE address, from ``--ble-address``.
        ble_scan: Whether to run a BLE scan before selection, from
            ``--ble-scan``.
        host: An explicit TCP host, from ``--host``.
        timeout: Connect timeout, in seconds, from ``--timeout``.
        ble_scan_timeout: BLE scan duration, in seconds, from
            ``--ble-scan-timeout``.
    """

    interface: connection.Transport | None = None
    port: str | None = None
    ble_address: str | None = None
    ble_scan: bool = False
    host: str | None = None
    timeout: int = connection.DEFAULT_CONNECT_TIMEOUT
    ble_scan_timeout: float = discovery.DEFAULT_BLE_SCAN_TIMEOUT


_TRANSPORT_OPTIONS: Final = (
    click.option(
        "--port", default=None, metavar="PATH", help="Explicit serial port, e.g. /dev/ttyUSB0."
    ),
    click.option("--ble-address", default=None, metavar="ADDR", help="Explicit BLE address."),
    click.option("--ble-scan", is_flag=True, default=False, help="Force BLE and scan for devices."),
    click.option(
        "--host", default=None, metavar="HOST[:PORT]", help="Explicit TCP host to connect to."
    ),
    click.option(
        "--interface",
        type=click.Choice([t.value for t in connection.TRANSPORTS], case_sensitive=False),
        default=None,
        help="Force a transport, turning ambiguity into a hard error.",
    ),
    click.option(
        "--timeout",
        type=click.IntRange(min=1),
        default=connection.DEFAULT_CONNECT_TIMEOUT,
        show_default=True,
        help="Connect timeout, in seconds.",
    ),
    click.option(
        "--ble-scan-timeout",
        type=click.FloatRange(min=0.1),
        default=discovery.DEFAULT_BLE_SCAN_TIMEOUT,
        show_default=True,
        help="BLE scan duration, in seconds.",
    ),
)


def transport_options(func: F) -> F:
    """Apply the seven shared transport-selection options to a command.

    Declared once and shared by ``mesh provision`` and ``mesh admin
    bootstrap``: the two commands' transport surface must not drift, and
    the option names correspond 1:1 to :class:`TransportOptions`'s fields.

    Args:
        func: The command function to decorate.

    Returns:
        ``func`` with every transport option attached, in help order.
    """
    for option in reversed(_TRANSPORT_OPTIONS):
        func = option(func)
    return func


def resolve_backend(ctx: CliContext, opts: TransportOptions) -> connection.ConnectionBackend:
    """Resolve exactly one connection backend from transport flags.

    Discovery is owned by this function (never by
    :func:`meshprovision.provisioning.connection.select_backend`, which
    performs no I/O itself) -- that separation is an invariant the
    provisioning layer's own unit tests assert.

    Priority, matching ``--port`` > ``--ble-address``/``--ble-scan`` >
    ``--host`` > auto: any explicit target flag skips discovery entirely;
    a forced ``--interface`` runs only that transport's discovery and
    turns ambiguity into a hard error (cron-safe); ``--ble-scan`` alone
    forces BLE but keeps ambiguity interactive; full auto tries serial
    first, then offers an interactive BLE scan and a TCP host prompt when
    nothing is found (skipped entirely when non-interactive).

    Args:
        ctx: The shared CLI context (consulted for ``non_interactive``,
            ``chooser``, and interactive prompts).
        opts: The operator's transport-selection flags.

    Returns:
        The single resolved connection backend.

    Raises:
        AmbiguousDeviceError: If multiple candidates are found and cannot
            be disambiguated.
        DeviceNotFoundError: If no candidate device can be found at all.
        NonInteractiveError: If disambiguation would require a prompt but
            none is available.
        UnsupportedTransportError: If ``opts.interface`` names an
            unsupported transport, or BLE support (``bleak``) is
            unavailable.
    """
    request = connection.ConnectionRequest(
        interface=opts.interface,
        port=opts.port,
        ble_address=opts.ble_address,
        ble_scan=opts.ble_scan,
        host=opts.host,
        non_interactive=ctx.non_interactive,
        timeout=opts.timeout,
    )

    explicit_target = opts.port is not None or opts.ble_address is not None or opts.host is not None
    if explicit_target:
        return connection.select_backend(request, connection.DiscoveryResult(), chooser=ctx.chooser)

    if opts.interface == "serial":
        serial_ports = discovery.discover_serial_ports()
        return connection.select_backend(
            request, connection.DiscoveryResult(serial_ports=serial_ports), chooser=ctx.chooser
        )

    if opts.interface == "ble":
        ctx.info("Scanning for BLE devices...")
        ble_devices = _discover_ble_devices_with_progress(ctx, timeout=opts.ble_scan_timeout)
        return connection.select_backend(
            request, connection.DiscoveryResult(ble_devices=ble_devices), chooser=ctx.chooser
        )

    if opts.interface == "tcp":
        return connection.select_backend(request, connection.DiscoveryResult(), chooser=ctx.chooser)

    if opts.ble_scan:
        ctx.info("Scanning for BLE devices...")
        ble_devices = _discover_ble_devices_with_progress(ctx, timeout=opts.ble_scan_timeout)
        if not ble_devices:
            raise DeviceNotFoundError(
                "No BLE device found.",
                transport="ble",
                hint="Pass --ble-address, or --host <ip> for TCP.",
            )
        return connection.select_backend(
            request,
            connection.DiscoveryResult(serial_ports=(), ble_devices=ble_devices),
            chooser=ctx.chooser,
        )

    # Full auto: serial first.
    ports = discovery.discover_serial_ports()
    if len(ports) == 1:
        ctx.info(f"Using the only serial port found: {ports[0].summary()}")
        return connection.select_backend(
            request, connection.DiscoveryResult(serial_ports=ports), chooser=ctx.chooser
        )
    if len(ports) > 1:
        return connection.select_backend(
            request, connection.DiscoveryResult(serial_ports=ports), chooser=ctx.chooser
        )

    # No serial device at all: offer BLE, then a TCP host prompt, when interactive.
    scanned_ble: tuple[discovery.BleDeviceInfo, ...] = ()
    if not ctx.non_interactive and ctx.confirm(
        "No serial device found. Scan for BLE devices?", default=True
    ):
        ble_devices = _discover_ble_devices_with_progress(ctx, timeout=opts.ble_scan_timeout)
        scanned_ble = ble_devices
    if scanned_ble:
        return connection.select_backend(
            request, connection.DiscoveryResult(ble_devices=scanned_ble), chooser=ctx.chooser
        )
    if not ctx.non_interactive:
        host = ctx.prompt("TCP host to connect to (blank to give up)", default="")
        if host:
            request = dataclasses.replace(request, host=host)
            return connection.select_backend(request, connection.DiscoveryResult(), chooser=None)
    return connection.select_backend(request, connection.DiscoveryResult(), chooser=ctx.chooser)


@contextlib.contextmanager
def device_session(
    ctx: CliContext, backend: connection.ConnectionBackend, *, no_reconnect: bool = False
) -> Iterator[DeviceSession]:
    """Open a device connection and yield a session :func:`apply.apply_plan` can drive.

    Args:
        ctx: The shared CLI context, used to print progress.
        backend: The resolved connection backend to open.
        no_reconnect: When ``True``, yields an
            :class:`~meshprovision.provisioning.apply.InPlaceSession`
            (weaker write-verification guarantee -- see firmware issue
            #7449) instead of a full
            :class:`~meshprovision.provisioning.apply.ReconnectingSession`.

    Yields:
        The open device session.

    Raises:
        ConnectionFailedError: If the connection attempt fails.
    """
    ctx.info(f"Connecting over {backend.describe()}...")
    if no_reconnect:
        ctx.warn(
            "--no-reconnect: writes are verified against the in-memory interface only "
            "(weaker guarantee; see firmware issue #7449)."
        )
    session = ReconnectingSession(backend=backend)
    with heartbeat(ctx, "connecting", timeout=_backend_timeout(backend)):
        session.open()
    ctx.info("Connected.")
    try:
        if no_reconnect:
            yield InPlaceSession(session.interface)
        else:
            yield session
    finally:
        ctx.info("Disconnecting...")
        session.close()


@contextlib.contextmanager
def connected_with_progress(
    ctx: CliContext, backend: connection.ConnectionBackend
) -> Iterator[MeshInterface]:
    """Connect once, with progress output, and always close on exit.

    The read-only sibling of :func:`device_session`: like
    :func:`meshprovision.provisioning.connection.connected`, but prints a
    "Connecting over ..." line and ticks a :func:`~meshprovision.cli.
    progress.heartbeat` while the (potentially multi-minute, entirely
    silent) ``backend.connect()`` call is in flight. Used by ``mesh
    adopt``, which -- unlike :func:`device_session` -- must never open a
    :class:`~meshprovision.provisioning.apply.ReconnectingSession`: it is
    strictly read-only against the device.

    Args:
        ctx: The shared CLI context, used to print progress.
        backend: The resolved connection backend to open.

    Yields:
        The connected interface.

    Raises:
        ConnectionFailedError: If the connection attempt fails.
    """
    ctx.info(f"Connecting over {backend.describe()}...")
    with heartbeat(ctx, "connecting", timeout=_backend_timeout(backend)):
        iface = backend.connect()
    ctx.info("Connected. Reading live config...")
    try:
        yield iface
    finally:
        ctx.info("Disconnecting...")
        connection.close_interface(iface)
