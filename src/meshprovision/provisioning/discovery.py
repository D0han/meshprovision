"""Pure device discovery: serial ports, BLE devices, and TCP target parsing.

This module performs I/O only in the form of the scan itself (enumerating
serial ports, or running a bounded-time BLE scan) and never makes a
transport decision -- that is :func:`meshprovision.provisioning.
connection.select_backend`'s job, and keeping the two separate is what
lets ``select_backend`` be unit-tested with zero mocking of ``pyserial``,
``bleak``, or ``meshtastic``.

This module deliberately imports nothing from ``meshtastic`` or from
:mod:`meshprovision.provisioning.connection` -- the dependency direction
is strictly ``connection.py -> discovery.py``, never the reverse.

``pyserial`` is imported at module scope because it is a hard dependency
of ``meshtastic``, which is itself a hard dependency of this project, so
importing it costs nothing and never needs to be optional. ``bleak`` is
different: it is only imported lazily, inside :func:`discover_ble_devices`,
so that this module (and therefore anything that imports it, including
``connection.py``) always imports cleanly even on a machine where BLE
support is broken or intentionally unavailable.
"""

from __future__ import annotations

import asyncio
import importlib.util
import ipaddress
import logging
import re
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final

from serial.tools import list_ports
from serial.tools.list_ports_common import ListPortInfo

from meshprovision.errors import ConnectionBackendError, UnsupportedTransportError

_logger = logging.getLogger(__name__)

__all__ = [
    "BLE_UNAVAILABLE_HINT",
    "DEFAULT_BLE_SCAN_TIMEOUT",
    "DEFAULT_TCP_PORT",
    "EXCLUDED_VIDS",
    "LIKELY_VIDS",
    "MAX_PORT",
    "MESHTASTIC_BLE_SERVICE_UUID",
    "BleDeviceInfo",
    "SerialPortInfo",
    "TcpTarget",
    "ble_available",
    "discover_ble_devices",
    "discover_serial_ports",
    "is_valid_hostname",
    "parse_tcp_target",
    "require_ble",
    "validate_tcp_host",
]

DEFAULT_TCP_PORT: Final[int] = 4403
"""Default port for the Meshtastic TCP API."""

MAX_PORT: Final[int] = 65535
"""Largest valid TCP port number."""

DEFAULT_BLE_SCAN_TIMEOUT: Final[float] = 10.0
"""Default duration, in seconds, of a BLE scan."""

MESHTASTIC_BLE_SERVICE_UUID: Final[str] = "6ba1b218-15a8-461f-9fa8-5dcae273eafd"
"""The BLE GATT service UUID advertised by Meshtastic devices."""

BLE_UNAVAILABLE_HINT: Final[str] = (
    "BLE support needs the 'bleak' package. Install it with: pip install 'meshprovision[ble]'"
)
"""Actionable hint shown whenever BLE support is requested but unavailable."""

LIKELY_VIDS: Final[MappingProxyType[int, str]] = MappingProxyType(
    {
        0x239A: "Adafruit",
        0x303A: "Espressif",
        0x10C4: "Silicon Labs CP210x",
        0x1A86: "QinHeng CH34x",
        0x0403: "FTDI",
        0x2E8A: "Raspberry Pi",
    }
)
"""USB vendor IDs likely to be Meshtastic-capable boards, for ranking only.

meshtastic's own ``findPorts()`` whitelists only Adafruit (``0x239a``) and
Espressif (``0x303a``) and otherwise returns everything not blacklisted.
This table deliberately also covers the CP210x/CH34x/FTDI USB-UART
bridges that most Meshtastic boards actually ship with, so
:attr:`SerialPortInfo.is_likely_meshtastic` is a ranking hint used to sort
likely candidates first -- it is never used to filter results.
"""

EXCLUDED_VIDS: Final[frozenset[int]] = frozenset({0x1366, 0x1915, 0x0483, 0x04B4, 0x0925})
"""USB vendor IDs of debug probes, excluded by default (not Meshtastic
devices): SEGGER (``0x1366``), Nordic (``0x1915``), ST-Link (``0x0483``),
Cypress (``0x04b4``), and Lakeview (``0x0925``) -- the same blacklist
``meshtastic.util`` uses internally."""

_HOSTNAME_LABEL_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$")
_MAX_HOSTNAME_LENGTH: Final[int] = 253
_MAX_HOSTNAME_LABEL_LENGTH: Final[int] = 63


@dataclass(frozen=True, slots=True)
class SerialPortInfo:
    """One serial port found during enumeration.

    Attributes:
        device: The OS device path, for example ``"/dev/ttyUSB0"``.
        description: Human-readable port description, or ``""`` when the
            OS/driver did not supply one (pyserial's own placeholder
            ``"n/a"`` is normalized to ``""``).
        vid: USB vendor id, when the port is USB-backed.
        pid: USB product id, when the port is USB-backed.
        manufacturer: USB manufacturer string, when available.
        product: USB product string, when available.
        serial_number: USB serial number string, when available.
    """

    device: str
    description: str = ""
    vid: int | None = None
    pid: int | None = None
    manufacturer: str | None = None
    product: str | None = None
    serial_number: str | None = None

    @property
    def vid_pid(self) -> str | None:
        """Colon-separated lowercase hex VID:PID.

        Returns:
            For example ``"239a:80f2"``, or ``None`` if either ``vid`` or
            ``pid`` is unknown.
        """
        if self.vid is None or self.pid is None:
            return None
        return f"{self.vid:04x}:{self.pid:04x}"

    @property
    def vendor(self) -> str | None:
        """Vendor name looked up from :data:`LIKELY_VIDS`.

        Returns:
            The vendor name, or ``None`` if ``vid`` is unknown or not in
            :data:`LIKELY_VIDS`.
        """
        if self.vid is None:
            return None
        return LIKELY_VIDS.get(self.vid)

    @property
    def is_likely_meshtastic(self) -> bool:
        """Whether this port's VID is a likely Meshtastic USB-UART bridge.

        This is a ranking hint, never a filter -- see :data:`LIKELY_VIDS`.

        Returns:
            ``True`` if ``vid`` is a key of :data:`LIKELY_VIDS`.
        """
        return self.vid is not None and self.vid in LIKELY_VIDS

    def summary(self) -> str:
        """Render a one-line, operator-facing description of this port.

        Returns:
            For example
            ``"/dev/ttyUSB0  (10c4:ea60 Silicon Labs CP210x) CP2102 USB to UART"``.
        """
        parts = [self.device]
        vid_pid = self.vid_pid
        if vid_pid is not None:
            vendor = self.vendor
            tag = f"({vid_pid} {vendor})" if vendor else f"({vid_pid})"
            parts.append(tag)
        if self.description:
            parts.append(self.description)
        return "  ".join(parts)


@dataclass(frozen=True, slots=True)
class BleDeviceInfo:
    """One BLE device found during a scan.

    Attributes:
        address: The BLE address (platform-dependent form: a MAC address
            on Linux/Windows, a UUID on macOS).
        name: The advertised device name, when available.
        rssi: Received signal strength, in dBm, when available.
    """

    address: str
    name: str | None = None
    rssi: int | None = None

    def summary(self) -> str:
        """Render a one-line, operator-facing description of this device.

        Returns:
            For example ``"AA:BB:CC:DD:EE:FF  Meshtastic_1234  (-63 dBm)"``.
        """
        parts = [self.address, self.name or "(unknown)"]
        if self.rssi is not None:
            parts.append(f"({self.rssi} dBm)")
        return "  ".join(parts)


@dataclass(frozen=True, slots=True)
class TcpTarget:
    """A validated TCP host and port for the Meshtastic TCP API.

    Attributes:
        host: The normalized host: a hostname, an IPv4 literal, or a bare
            (un-bracketed) IPv6 literal.
        port: The TCP port.
    """

    host: str
    port: int = DEFAULT_TCP_PORT

    def summary(self) -> str:
        """Render a one-line, operator-facing description of this target.

        Returns:
            Same text as :meth:`__str__`.
        """
        return str(self)

    def __str__(self) -> str:
        """Render as ``host:port``, bracketing an IPv6 host.

        Returns:
            For example ``"192.168.1.50:4403"`` or ``"[::1]:4403"``.
        """
        if ":" in self.host:
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"


def _normalize_description(description: str | None) -> str:
    """Normalize pyserial's ``description`` field.

    Args:
        description: The raw value from ``ListPortInfo.description``.

    Returns:
        ``""`` when ``description`` is ``None`` or pyserial's own
        ``"n/a"`` placeholder; otherwise ``description`` unchanged.
    """
    if description is None or description == "n/a":
        return ""
    return description


def _to_serial_port_info(port: ListPortInfo) -> SerialPortInfo:
    """Convert one pyserial ``ListPortInfo`` into a :class:`SerialPortInfo`.

    Args:
        port: The pyserial port record.

    Returns:
        The corresponding :class:`SerialPortInfo`.
    """
    return SerialPortInfo(
        device=port.device,
        description=_normalize_description(port.description),
        vid=port.vid,
        pid=port.pid,
        manufacturer=port.manufacturer,
        product=port.product,
        serial_number=port.serial_number,
    )


def discover_serial_ports(*, include_all: bool = False) -> tuple[SerialPortInfo, ...]:
    """Enumerate connected serial ports.

    Args:
        include_all: When ``False`` (the default), ports whose USB vendor
            id is a known debug-probe id (:data:`EXCLUDED_VIDS`) are
            dropped. A port whose vendor id is unknown (``None``) is
            never dropped, regardless of this flag.

    Returns:
        Serial ports sorted with likely Meshtastic devices
        (:attr:`SerialPortInfo.is_likely_meshtastic`) first, then
        alphabetically by device path.

    Raises:
        ConnectionBackendError: If the OS-level port enumeration fails.
    """
    try:
        ports = list_ports.comports()
    except OSError as exc:
        raise ConnectionBackendError(
            f"Could not enumerate serial ports: {exc}", transport="serial"
        ) from exc

    infos = [_to_serial_port_info(port) for port in ports]
    if not include_all:
        infos = [info for info in infos if info.vid is None or info.vid not in EXCLUDED_VIDS]
    result = tuple(sorted(infos, key=lambda info: (not info.is_likely_meshtastic, info.device)))
    _logger.debug("Serial enumeration found %d port(s) (include_all=%s).", len(result), include_all)
    return result


def ble_available() -> bool:
    """Check whether the optional ``bleak`` package is importable.

    Deliberately does not import ``bleak`` itself -- only checks whether
    it *could* be imported -- so this module keeps importing cleanly on a
    machine without it.

    Returns:
        ``True`` if ``bleak`` is installed.
    """
    return importlib.util.find_spec("bleak") is not None


def require_ble() -> None:
    """Raise if BLE support is unavailable.

    Raises:
        UnsupportedTransportError: If :func:`ble_available` is ``False``,
            with :data:`BLE_UNAVAILABLE_HINT` as the hint.
    """
    if not ble_available():
        raise UnsupportedTransportError(
            "BLE support is not available.", transport="ble", hint=BLE_UNAVAILABLE_HINT
        )


def discover_ble_devices(
    *,
    timeout: float = DEFAULT_BLE_SCAN_TIMEOUT,
    service_uuid: str | None = MESHTASTIC_BLE_SERVICE_UUID,
) -> tuple[BleDeviceInfo, ...]:
    """Scan for nearby BLE devices.

    Note:
        This function calls ``asyncio.run`` internally and therefore must
        not be invoked from inside an already-running event loop.

    Args:
        timeout: Scan duration, in seconds.
        service_uuid: When given, only devices advertising this GATT
            service UUID are returned (case-insensitive comparison).
            Defaults to :data:`MESHTASTIC_BLE_SERVICE_UUID`. Pass
            ``None`` to return every discovered device.

    Returns:
        Discovered devices sorted by strongest signal first (devices with
        an unknown RSSI sort last), then by address.

    Raises:
        UnsupportedTransportError: If ``bleak`` is not installed, or is
            installed but fails to import.
        ConnectionBackendError: If the scan itself fails.
    """
    require_ble()
    try:
        import bleak
        from bleak.exc import BleakError
    except ImportError as exc:
        raise UnsupportedTransportError(
            "BLE support is not available.", transport="ble", hint=BLE_UNAVAILABLE_HINT
        ) from exc

    kwargs: dict[str, Any] = {"return_adv": True}
    if service_uuid is not None:
        kwargs["service_uuids"] = [service_uuid]

    _logger.debug("BLE scan starting (timeout=%ss, service_uuid=%s).", timeout, service_uuid)
    started = time.monotonic()
    try:
        result = asyncio.run(bleak.BleakScanner.discover(timeout=timeout, **kwargs))
    except (TimeoutError, BleakError, OSError, RuntimeError) as exc:
        raise ConnectionBackendError(f"BLE scan failed: {exc}", transport="ble") from exc
    elapsed = time.monotonic() - started

    wanted_uuid = service_uuid.lower() if service_uuid is not None else None
    devices: list[BleDeviceInfo] = []
    for device, adv in result.values():
        if wanted_uuid is not None:
            advertised = {uuid.lower() for uuid in (adv.service_uuids or ())}
            if wanted_uuid not in advertised:
                continue
        devices.append(
            BleDeviceInfo(
                address=device.address,
                name=device.name or adv.local_name,
                rssi=adv.rssi,
            )
        )

    devices.sort(key=lambda d: (-(d.rssi if d.rssi is not None else -999), d.address))
    _logger.debug(
        "BLE scan finished in %.1fs: %d raw device(s), %d matching service_uuid.",
        elapsed,
        len(result),
        len(devices),
    )
    return tuple(devices)


def is_valid_hostname(value: str) -> bool:
    """Check whether ``value`` is a syntactically valid DNS hostname.

    Pure syntax check: performs no DNS resolution.

    Args:
        value: The candidate hostname.

    Returns:
        ``True`` if ``value`` (after stripping one trailing dot) is
        non-empty, at most 253 characters, and every dot-separated label
        is 1-63 ASCII characters matching
        ``^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$``.
    """
    candidate = value[:-1] if value.endswith(".") else value
    if not candidate or len(candidate) > _MAX_HOSTNAME_LENGTH:
        return False
    labels = candidate.split(".")
    return all(
        1 <= len(label) <= _MAX_HOSTNAME_LABEL_LENGTH and _HOSTNAME_LABEL_RE.match(label)
        for label in labels
    )


def validate_tcp_host(host: str) -> str:
    """Validate and normalize a TCP host: an IP literal or a hostname.

    Args:
        host: The candidate host, optionally bracketed (``"[::1]"``).

    Returns:
        The normalized host: stripped, and with a bracketed IPv6 literal
        un-bracketed.

    Raises:
        ConnectionBackendError: If ``host`` is neither a valid IP address
            nor a syntactically valid hostname.
    """
    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        if not is_valid_hostname(candidate):
            raise ConnectionBackendError(
                f"{host!r} is not a valid hostname or IP address.", transport="tcp"
            ) from None
    return candidate


def _parse_port(raw: str) -> int:
    """Parse and validate a TCP port string.

    Args:
        raw: The candidate port string.

    Returns:
        The parsed port number.

    Raises:
        ConnectionBackendError: If ``raw`` is not all-ASCII-digits, or the
            parsed value is outside ``[1, MAX_PORT]``.
    """
    if not raw or not raw.isascii() or not raw.isdigit():
        raise ConnectionBackendError(f"Invalid TCP port: {raw!r}", transport="tcp")
    port = int(raw)
    if not (1 <= port <= MAX_PORT):
        raise ConnectionBackendError(
            f"TCP port out of range [1, {MAX_PORT}]: {port}", transport="tcp"
        )
    return port


def parse_tcp_target(value: str, *, default_port: int = DEFAULT_TCP_PORT) -> TcpTarget:
    """Parse a ``--host``-style value into a validated :class:`TcpTarget`.

    Accepts a bare hostname or IPv4 literal, ``host:port``, a bracketed
    IPv6 literal with an optional port (``[::1]`` or ``[::1]:4403``), and
    a bare (un-bracketed) IPv6 literal, which is detected with
    :func:`ipaddress.ip_address` before any ``:``-splitting is attempted
    -- this is what lets a multi-colon IPv6 address avoid being
    misinterpreted as ``host:port``.

    Args:
        value: The raw value to parse.
        default_port: Port to use when ``value`` does not specify one.

    Returns:
        The parsed, validated :class:`TcpTarget`.

    Raises:
        ConnectionBackendError: If ``value`` is empty, malformed, names
            an invalid host, or names an invalid port.
    """
    token = value.strip()
    if not token:
        raise ConnectionBackendError(f"{value!r} is not a valid TCP target.", transport="tcp")

    if token.startswith("["):
        closing = token.find("]")
        if closing == -1:
            raise ConnectionBackendError(
                f"{value!r} is not a valid TCP target: unterminated '['.", transport="tcp"
            )
        host = validate_tcp_host(token[1:closing])
        remainder = token[closing + 1 :]
        if not remainder:
            return TcpTarget(host, default_port)
        if remainder.startswith(":"):
            return TcpTarget(host, _parse_port(remainder[1:]))
        raise ConnectionBackendError(
            f"{value!r} is not a valid TCP target: unexpected trailing text.", transport="tcp"
        )

    try:
        ipaddress.ip_address(token)
    except ValueError:
        pass
    else:
        return TcpTarget(validate_tcp_host(token), default_port)

    if ":" in token:
        host_part, _, port_part = token.rpartition(":")
        return TcpTarget(validate_tcp_host(host_part), _parse_port(port_part))

    return TcpTarget(validate_tcp_host(token), default_port)
