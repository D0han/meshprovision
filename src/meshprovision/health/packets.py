"""Parse lorastats ``PacketReports`` and ``PacketsParsed`` rows and their payload texts. Pure.

``/API/{region}/PacketReports/JSON?fromNode=<hex>`` lists every reception
of a node's packets: one row per packet per gateway that uplinked it
(``Time``, ``Gateway``, ``FromNode``, ``PacketId``, ``SNR``, ``RSSI``,
``HopLimit``, ``RelayNode``). ``/API/{region}/PacketsParsed/JSON`` lists
the packets lorastats could decode, once each (``Time``, ``PacketId``,
``HopStart``, ``PortNum``, ``Payload``) -- only a subset of them, so
anything taken from it is a sample. Both are untrusted, loosely typed
JSON: a row that cannot be used is skipped and counted, never raised, and
every value is range-checked. ``Time`` is a naive Europe/Warsaw time (an
offset is honoured when given), see
:func:`~meshprovision.datasources.models.parse_iso8601`.

``Payload`` is lorastats' own rendering of the decoded packet, not the
protobuf, so its parsers below accept only the shapes seen from lorastats
and return ``None`` for anything else:

- telemetry (port 67): comma-separated readings such as ``"5.93% ChUtil,
  0.03% AirUtilTx, 90% Bat"`` or ``"167305 rx, 1129 tx, 252 relay, 84
  kB"`` (unknown readings are ignored, an empty payload is no reading);
- position (port 3): ``"52.379648° N, 16.950886° E"``;
- node info (port 4): ``"<short>, <long>, <Role>"``, the long name may
  itself contain commas;
- neighbour info (port 71): one neighbour's hex node id.

This module imports nothing that reads files or the network (no
``httpx``, ``pathlib``, :mod:`meshprovision.cache` or
:mod:`meshprovision.db`); ``tests/unit/test_import_contracts.py`` holds it
to that.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from meshprovision.datasources.models import coerce_float, coerce_int, coerce_str, parse_iso8601
from meshprovision.enums import role_table
from meshprovision.errors import NodeIdError
from meshprovision.nodeid import NodeId

__all__ = [
    "FUTURE_SKEW_SECONDS",
    "PORT_NEIGHBORINFO",
    "PORT_NODEINFO",
    "PORT_POSITION",
    "PORT_TELEMETRY",
    "DecodedPacket",
    "NodeInfo",
    "Reception",
    "Telemetry",
    "parse_decoded",
    "parse_neighbor",
    "parse_nodeinfo",
    "parse_position",
    "parse_receptions",
    "parse_telemetry",
]

PORT_POSITION: Final[int] = 3
"""``PortNum`` of a position packet."""

PORT_NODEINFO: Final[int] = 4
"""``PortNum`` of a node-info packet."""

PORT_TELEMETRY: Final[int] = 67
"""``PortNum`` of a telemetry packet."""

PORT_NEIGHBORINFO: Final[int] = 71
"""``PortNum`` of a neighbour-info packet."""

FUTURE_SKEW_SECONDS: Final[float] = 300.0
"""How far ahead of the clock a row's ``Time`` may be; a later one is skipped."""

_MAX_HOPS: Final[int] = 7
"""The largest hop limit/start Meshtastic allows."""

_MAX_BYTE: Final[int] = 255
_MAX_SNR_DB: Final[float] = 50.0
_MAX_RSSI: Final[int] = 255
_MAX_PORT: Final[int] = 1023
_MAX_PAYLOAD_CHARS: Final[int] = 512
_MAX_COUNTER: Final[int] = 2**32 - 1
_MAX_PERCENT: Final[float] = 100.0
_MAX_BATTERY: Final[int] = 101
"""Meshtastic reports 101 for a node on external power."""
_MAX_VOLTS: Final[float] = 10.0
_MAX_LATITUDE: Final[float] = 90.0
_MAX_LONGITUDE: Final[float] = 180.0

_PACKET_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{1,8}\Z")
_NUMBER: Final[str] = r"(\d{1,10}(?:\.\d{1,6})?)"
_TELEMETRY_READINGS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("channel_utilization", re.compile(rf"^{_NUMBER}% ChUtil\Z")),
    ("air_util_tx", re.compile(rf"^{_NUMBER}% AirUtilTx\Z")),
    ("battery", re.compile(r"^(\d{1,3})% Bat\Z")),
    ("voltage", re.compile(rf"^{_NUMBER} ?V\Z")),
    ("rx", re.compile(r"^(\d{1,10}) rx\Z")),
    ("tx", re.compile(r"^(\d{1,10}) tx\Z")),
    ("relayed", re.compile(r"^(\d{1,10}) relay\Z")),
)
"""``(field, pattern)`` for each telemetry reading lorastats renders."""

_POSITION_RE: Final[re.Pattern[str]] = re.compile(rf"^{_NUMBER}° ([NS]), {_NUMBER}° ([EW])\Z")
_CAMEL_BOUNDARY_RE: Final[re.Pattern[str]] = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


@dataclass(frozen=True, slots=True)
class Reception:
    """One gateway's reception of one of the node's packets (a ``PacketReports`` row).

    Attributes:
        time: When the gateway heard it, unix epoch seconds.
        gateway: The uplinking gateway's canonical hex id.
        packet_id: The packet id, lowercase hex.
        snr: SNR in dB, when given.
        rssi: RSSI exactly as lorastats gives it (a positive number; see
            the module docs of :mod:`meshprovision.health.metrics`), when given.
        hop_limit: The hop limit left when it was heard, when given.
        relay: The last byte of the node that transmitted it last, when given.
    """

    time: float
    gateway: str
    packet_id: str
    snr: float | None
    rssi: int | None
    hop_limit: int | None
    relay: int | None


@dataclass(frozen=True, slots=True)
class DecodedPacket:
    """One packet lorastats decoded (a ``PacketsParsed`` row).

    Attributes:
        time: When it was first heard, unix epoch seconds.
        packet_id: The packet id, lowercase hex.
        hop_start: The hop limit the sender gave it (its configured hop
            limit), when given.
        port: Its ``PortNum``, when given.
        payload: lorastats' rendering of its content, ``""`` when none.
    """

    time: float
    packet_id: str
    hop_start: int | None
    port: int | None
    payload: str


@dataclass(frozen=True, slots=True)
class Telemetry:
    """The readings of one telemetry payload; ``None`` for each one it did not carry.

    Attributes:
        battery: Battery level percentage (101 = external power).
        voltage: Battery voltage.
        channel_utilization: Channel utilization percentage.
        air_util_tx: Transmit air utilization percentage.
        rx: Packets received since boot (local stats).
        tx: Packets sent since boot (local stats).
        relayed: Packets relayed since boot (local stats).
    """

    battery: int | None = None
    voltage: float | None = None
    channel_utilization: float | None = None
    air_util_tx: float | None = None
    rx: int | None = None
    tx: int | None = None
    relayed: int | None = None


@dataclass(frozen=True, slots=True)
class NodeInfo:
    """The names and role of one node-info payload.

    Attributes:
        short_name: The short name, terminal-safe.
        long_name: The long name, terminal-safe.
        role: The canonical ``Role`` enum name, or ``None`` when unknown.
    """

    short_name: str
    long_name: str
    role: str | None


def _ranged_int(value: object, low: int, high: int) -> int | None:
    """Coerce ``value`` to an int within ``low..high``, else ``None``."""
    number = coerce_int(value)
    return number if number is not None and low <= number <= high else None


def _ranged_float(value: object, low: float, high: float) -> float | None:
    """Coerce ``value`` to a finite float within ``low..high``, else ``None``."""
    number = coerce_float(value)
    return number if number is not None and low <= number <= high else None


def _row_time(row: Mapping[str, object], now: float) -> float | None:
    """Return a row's ``Time`` as epoch seconds, ``None`` when missing or in the future."""
    parsed = parse_iso8601(row.get("Time"))
    if parsed is None:
        return None
    epoch = parsed.timestamp()
    return epoch if epoch <= now + FUTURE_SKEW_SECONDS else None


def _packet_id(value: object) -> str | None:
    """Return a packet id in canonical lowercase hex, else ``None``."""
    if not isinstance(value, str):
        return None
    token = value.strip().lower()
    return token if _PACKET_ID_RE.match(token) else None


def _hex_id(value: object) -> NodeId | None:
    """Return the node id a hex string names, else ``None`` (also for a non-string)."""
    if not isinstance(value, str):
        return None
    try:
        return NodeId.from_hex(value)
    except NodeIdError:
        return None


def parse_receptions(
    rows: Sequence[object], node: NodeId, *, now: float
) -> tuple[tuple[Reception, ...], int]:
    """Parse ``PacketReports`` rows for ``node``.

    A row is skipped when it is not an object, is from another node, or
    lacks a usable ``Time`` (missing, or more than
    :data:`FUTURE_SKEW_SECONDS` in the future), ``Gateway`` or
    ``PacketId``; a repeated ``(PacketId, Gateway)`` pair is kept once.
    An out-of-range ``SNR``, ``RSSI``, ``HopLimit`` or ``RelayNode`` is
    kept as ``None``.

    Args:
        rows: The decoded JSON array.
        node: The node asked about.
        now: The current time, epoch seconds.

    Returns:
        The receptions, in input order, and how many rows were skipped
        (repeats not counted).
    """
    receptions: list[Reception] = []
    seen: set[tuple[str, str]] = set()
    skipped = 0
    for row in rows:
        reception = _parse_reception(row, node, now) if isinstance(row, dict) else None
        if reception is None:
            skipped += 1
            continue
        key = (reception.packet_id, reception.gateway)
        if key not in seen:
            seen.add(key)
            receptions.append(reception)
    return tuple(receptions), skipped


def _parse_reception(row: Mapping[str, object], node: NodeId, now: float) -> Reception | None:
    """Parse one ``PacketReports`` row, or ``None`` when it cannot be used."""
    if _hex_id(row.get("FromNode")) != node:
        return None
    time = _row_time(row, now)
    packet_id = _packet_id(row.get("PacketId"))
    gateway = _hex_id(row.get("Gateway"))
    if time is None or packet_id is None or gateway is None:
        return None
    return Reception(
        time=time,
        gateway=gateway.hex,
        packet_id=packet_id,
        snr=_ranged_float(row.get("SNR"), -_MAX_SNR_DB, _MAX_SNR_DB),
        rssi=_ranged_int(row.get("RSSI"), 0, _MAX_RSSI),
        hop_limit=_ranged_int(row.get("HopLimit"), 0, _MAX_HOPS),
        relay=_ranged_int(row.get("RelayNode"), 0, _MAX_BYTE),
    )


def parse_decoded(
    rows: Sequence[object], node: NodeId, *, now: float
) -> tuple[tuple[DecodedPacket, ...], int]:
    """Parse ``PacketsParsed`` rows for ``node``.

    Skipped like :func:`parse_receptions` (``Gateway`` is not needed); a
    repeated ``PacketId`` is kept once. An out-of-range ``HopStart`` or
    ``PortNum`` is kept as ``None``; a payload that is not a string, or
    is longer than 512 characters, as ``""``.

    Args:
        rows: The decoded JSON array.
        node: The node asked about.
        now: The current time, epoch seconds.

    Returns:
        The decoded packets, in input order, and how many rows were
        skipped (repeats not counted).
    """
    packets: list[DecodedPacket] = []
    seen: set[str] = set()
    skipped = 0
    for row in rows:
        packet = _parse_decoded(row, node, now) if isinstance(row, dict) else None
        if packet is None:
            skipped += 1
            continue
        if packet.packet_id not in seen:
            seen.add(packet.packet_id)
            packets.append(packet)
    return tuple(packets), skipped


def _parse_decoded(row: Mapping[str, object], node: NodeId, now: float) -> DecodedPacket | None:
    """Parse one ``PacketsParsed`` row, or ``None`` when it cannot be used."""
    if _hex_id(row.get("FromNode")) != node:
        return None
    time = _row_time(row, now)
    packet_id = _packet_id(row.get("PacketId"))
    if time is None or packet_id is None:
        return None
    payload = row.get("Payload")
    text = payload if isinstance(payload, str) and len(payload) <= _MAX_PAYLOAD_CHARS else ""
    return DecodedPacket(
        time=time,
        packet_id=packet_id,
        hop_start=_ranged_int(row.get("HopStart"), 0, _MAX_HOPS),
        port=_ranged_int(row.get("PortNum"), 0, _MAX_PORT),
        payload=text,
    )


def parse_telemetry(text: str) -> Telemetry | None:
    """Parse a telemetry payload.

    Args:
        text: The payload, for example ``"5.93% ChUtil, 0.03% AirUtilTx, 90% Bat"``.

    Returns:
        The readings it carries, or ``None`` when it carries none this
        parser knows. A reading out of range (a percentage above 100, a
        battery above 101, a voltage above 10 V) is left out.
    """
    found: dict[str, float] = {}
    for token in text.split(","):
        for field_name, pattern in _TELEMETRY_READINGS:
            match = pattern.match(token.strip())
            if match is not None and field_name not in found:
                found[field_name] = float(match.group(1))
                break
    telemetry = Telemetry(
        battery=_reading_int(found.get("battery"), _MAX_BATTERY),
        voltage=_reading_float(found.get("voltage"), _MAX_VOLTS),
        channel_utilization=_reading_float(found.get("channel_utilization"), _MAX_PERCENT),
        air_util_tx=_reading_float(found.get("air_util_tx"), _MAX_PERCENT),
        rx=_reading_int(found.get("rx"), _MAX_COUNTER),
        tx=_reading_int(found.get("tx"), _MAX_COUNTER),
        relayed=_reading_int(found.get("relayed"), _MAX_COUNTER),
    )
    return None if telemetry == Telemetry() else telemetry


def _reading_float(value: float | None, high: float) -> float | None:
    """Keep a parsed reading within ``0..high``."""
    return value if value is not None and value <= high else None


def _reading_int(value: float | None, high: int) -> int | None:
    """Keep a parsed integer reading within ``0..high``."""
    return int(value) if value is not None and value <= high else None


def parse_position(text: str) -> tuple[float, float] | None:
    """Parse a position payload.

    Args:
        text: The payload, for example ``"52.379648° N, 16.950886° E"``.

    Returns:
        ``(latitude, longitude)`` in signed decimal degrees, or ``None``
        when it does not parse, is out of range, or is exactly ``0, 0``
        (no fix).
    """
    match = _POSITION_RE.match(text.strip())
    if match is None:
        return None
    latitude = float(match.group(1)) * (-1 if match.group(2) == "S" else 1)
    longitude = float(match.group(3)) * (-1 if match.group(4) == "W" else 1)
    if not (math.fabs(latitude) <= _MAX_LATITUDE and math.fabs(longitude) <= _MAX_LONGITUDE):
        return None
    if latitude == 0.0 and longitude == 0.0:
        return None
    return latitude, longitude


def parse_nodeinfo(text: str) -> NodeInfo | None:
    """Parse a node-info payload.

    Args:
        text: The payload, for example ``"D0h5, D0h5 | FW+ https://x, ClientMute"``.

    Returns:
        The names (the first part is the short name, the last the role,
        everything between the long name) and the role as a canonical
        ``Role`` name (``None`` when it is not one), or ``None`` when the
        payload has fewer than three parts (the long name is then blank)
        or a blank name.
    """
    parts = [part.strip() for part in text.split(", ")]
    short_name = coerce_str(parts[0])
    long_name = coerce_str(", ".join(parts[1:-1]))
    if short_name is None or long_name is None:
        return None
    role_text = _CAMEL_BOUNDARY_RE.sub("_", parts[-1]).upper()
    return NodeInfo(
        short_name=short_name, long_name=long_name, role=role_table().try_name(role_text)
    )


def parse_neighbor(text: str) -> NodeId | None:
    """Parse a neighbour-info payload: one neighbour's hex node id.

    Args:
        text: The payload.

    Returns:
        The neighbour's id, or ``None`` when it is not a hex node id.
    """
    return _hex_id(text)
