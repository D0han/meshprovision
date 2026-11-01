"""Parse lorastats ``PacketsRaw`` rows into receptions, advertised keys and routes. Pure.

``/API/{region}/PacketsRaw/JSON`` lists every gateway's uplink of every
packet in a region: ``{"Time", "Gateway", "Data"}``, where ``Data`` is the
base64 ``MeshPacket`` protobuf the gateway sent to MQTT. One row carries
everything the region-wide views need: who sent the packet, its hop
start and hop limit, the last byte of the node that transmitted it last
(``relay_node``), and the gateway's SNR/RSSI. A packet that travelled
unencrypted (the default channel) also carries its decoded payload, of
which three ports are read, each with its own protobuf (never a text
rendering):

- node info (port 4) -- the node's ``User``: its public key, short name,
  hardware model and role;
- traceroute (port 70) -- the ids of the nodes a route discovery passed;
- neighbour info (port 71) -- the neighbours a node reports.

The rows are untrusted: a row that cannot be used is skipped and counted,
never raised, and every value is range-checked (an out-of-range one is
kept as ``None``). ``Time`` is a naive Europe/Warsaw time (an offset is
honoured when given), see
:func:`~meshprovision.datasources.models.parse_iso8601`. A packet heard
by several gateways is several receptions but one packet: its payload is
read once, from its first decoded row (a gateway without the channel's
key uplinks the same packet encrypted).

A public key is kept in memory only, for the key audit; nothing here
persists, logs or prints one.

This module imports nothing that reads files or the network (no
``httpx``, ``pathlib``, :mod:`meshprovision.cache` or
:mod:`meshprovision.db`); ``tests/unit/test_import_contracts.py`` holds it
to that.
"""

from __future__ import annotations

import base64
import binascii
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from google.protobuf.message import DecodeError
from meshtastic.protobuf import mesh_pb2, portnums_pb2

from meshprovision.datasources.models import parse_iso8601
from meshprovision.enums import hw_model_table, role_table
from meshprovision.errors import NodeIdError
from meshprovision.health.packets import FUTURE_SKEW_SECONDS
from meshprovision.nodeid import NODE_ID_MAX, NodeId
from meshprovision.termsafe import terminal_safe

__all__ = [
    "PUBLIC_KEY_BYTES",
    "RAW_DATA_MAX_CHARS",
    "AdvertisedKey",
    "NeighborObservation",
    "ParsedRaw",
    "RawReception",
    "RouteObservation",
    "parse_raw",
]

RAW_DATA_MAX_CHARS: Final[int] = 1024
"""The longest ``Data`` read: a ``MeshPacket`` is at most about 350 base64 characters."""

PUBLIC_KEY_BYTES: Final[int] = 32
"""The length of a Meshtastic (X25519) public key."""

_MAX_HOPS: Final[int] = 7
_MAX_BYTE: Final[int] = 255
_MAX_SNR_DB: Final[float] = 50.0
_MIN_RSSI_DBM: Final[int] = -200
_MAX_NAME_CHARS: Final[int] = 64


@dataclass(frozen=True, slots=True)
class RawReception:
    """One gateway's uplink of one packet (a ``PacketsRaw`` row).

    Attributes:
        time: When the gateway heard it, unix epoch seconds.
        gateway: The uplinking gateway.
        origin: The node that sent the packet.
        packet_id: The packet id.
        relay: The last byte of the node that transmitted it last
            (``relay_node``), or ``None`` when not given (older firmware).
        hop_start: The hop limit the sender gave it, or ``None`` when not
            given (firmware before 2.3).
        hop_limit: The hop limit left when the gateway heard it.
        snr: The gateway's SNR in dB, when given.
        rssi: The gateway's RSSI in dBm as sent (negative), when given.
        port: The decoded ``PortNum``, or ``None`` for an encrypted packet.
    """

    time: float
    gateway: NodeId
    origin: NodeId
    packet_id: int
    relay: int | None
    hop_start: int | None
    hop_limit: int | None
    snr: float | None
    rssi: int | None
    port: int | None

    @property
    def hops_taken(self) -> int | None:
        """How many hops the packet had taken when the gateway heard it.

        Returns:
            ``hop_start - hop_limit`` when both are known and the limit is
            not above the start, else ``None``.
        """
        if self.hop_start is None or self.hop_limit is None or self.hop_limit > self.hop_start:
            return None
        return self.hop_start - self.hop_limit

    @property
    def is_relayed(self) -> bool:
        """Whether another node transmitted it last (its relay byte is not the origin's).

        Returns:
            ``True`` when the relay byte is known and differs from the
            origin's last byte.
        """
        return self.relay is not None and self.relay != self.origin.num & _MAX_BYTE

    @property
    def is_direct(self) -> bool:
        """Whether the gateway heard the origin itself.

        Strict: the relay byte is the origin's *and* no hop was taken (a
        relay whose byte collides with the origin's has taken hops).

        Returns:
            ``True`` for a direct reception.
        """
        return (
            self.relay is not None
            and self.relay == self.origin.num & _MAX_BYTE
            and self.hops_taken in (0, None)
        )


@dataclass(frozen=True, slots=True)
class AdvertisedKey:
    """The public key a node advertised in a node-info packet.

    Attributes:
        time: When the packet was first heard, unix epoch seconds.
        node: The node that sent it.
        public_key: The 32-byte public key. In memory only: never
            persisted, logged or printed.
        short_name: Its short name, terminal-safe and at most 64 characters
            (cut after escaping), when given.
        hw_model: Its canonical ``HardwareModel`` name, when known.
        role: Its canonical ``Role`` name, when known.
    """

    time: float
    node: NodeId
    public_key: bytes
    short_name: str | None
    hw_model: str | None
    role: str | None


@dataclass(frozen=True, slots=True)
class RouteObservation:
    """A run of nodes a traceroute passed, in order (each next to the one before).

    Attributes:
        time: When the packet was first heard, unix epoch seconds.
        path: At least two node ids.
    """

    time: float
    path: tuple[NodeId, ...]


@dataclass(frozen=True, slots=True)
class NeighborObservation:
    """The neighbours a node reported in a neighbour-info packet.

    Attributes:
        time: When the packet was first heard, unix epoch seconds.
        node: The reporting node.
        neighbors: The neighbours it named.
    """

    time: float
    node: NodeId
    neighbors: tuple[NodeId, ...]


@dataclass(frozen=True, slots=True)
class ParsedRaw:
    """Everything read from one ``PacketsRaw`` answer.

    Attributes:
        receptions: Every usable reception, in input order, each
            ``(gateway, origin, packet id)`` once.
        keys: The public keys advertised, one per node-info packet.
        routes: The traceroute paths.
        neighbors: The neighbour reports.
        skipped: Rows that could not be used (repeats not counted).
        bad_keys: Node-info packets whose public key was not 32 bytes long.
    """

    receptions: tuple[RawReception, ...] = ()
    keys: tuple[AdvertisedKey, ...] = ()
    routes: tuple[RouteObservation, ...] = ()
    neighbors: tuple[NeighborObservation, ...] = ()
    skipped: int = 0
    bad_keys: int = 0


@dataclass(slots=True)
class _Collector:
    """The mutable state of one :func:`parse_raw` call."""

    receptions: list[RawReception]
    keys: list[AdvertisedKey]
    routes: list[RouteObservation]
    neighbors: list[NeighborObservation]
    seen: set[tuple[int, int, int]]
    packets: set[tuple[int, int]]
    skipped: int = 0
    bad_keys: int = 0


def parse_raw(rows: Sequence[object], *, now: float) -> ParsedRaw:
    """Parse ``PacketsRaw`` rows.

    A row is skipped when it is not an object; its ``Time`` is missing or
    more than :data:`~meshprovision.health.packets.FUTURE_SKEW_SECONDS` in
    the future; its ``Gateway`` is not a real node's hex id; its ``Data`` is not
    valid base64 of at most :data:`RAW_DATA_MAX_CHARS` characters or not a
    ``MeshPacket``; or the packet has no sender (``from`` 0 or broadcast)
    or no id. A repeated ``(gateway, from, id)`` is kept once, not counted
    as skipped.

    Args:
        rows: The decoded JSON array.
        now: The current time, epoch seconds.

    Returns:
        The receptions and the decoded extras.
    """
    state = _Collector([], [], [], [], set(), set())
    for row in rows:
        parsed = _parse_row(row, now) if isinstance(row, dict) else None
        if parsed is None:
            state.skipped += 1
            continue
        reception, packet = parsed
        key = (reception.gateway.num, reception.origin.num, reception.packet_id)
        if key in state.seen:
            continue
        state.seen.add(key)
        state.receptions.append(reception)
        packet_key = (reception.origin.num, reception.packet_id)
        if reception.port is not None and packet_key not in state.packets:
            state.packets.add(packet_key)
            _collect_extras(state, reception, packet)
    return ParsedRaw(
        receptions=tuple(state.receptions),
        keys=tuple(state.keys),
        routes=tuple(state.routes),
        neighbors=tuple(state.neighbors),
        skipped=state.skipped,
        bad_keys=state.bad_keys,
    )


def _parse_row(
    row: Mapping[str, object], now: float
) -> tuple[RawReception, mesh_pb2.MeshPacket] | None:
    """Parse one row into its reception and packet, or ``None`` when it cannot be used."""
    parsed_time = parse_iso8601(row.get("Time"))
    time = None if parsed_time is None else parsed_time.timestamp()
    gateway = _hex_id(row.get("Gateway"))
    packet = _packet(row.get("Data"))
    if time is None or time > now + FUTURE_SKEW_SECONDS or gateway is None or packet is None:
        return None
    origin = _node(getattr(packet, "from"))
    if origin is None or packet.id == 0:
        return None
    rssi = packet.rx_rssi if _MIN_RSSI_DBM <= packet.rx_rssi < 0 else None
    snr = packet.rx_snr if math.isfinite(packet.rx_snr) else None
    if snr is not None and (abs(snr) > _MAX_SNR_DB or (snr == 0 and rssi is None)):
        snr = None
    decoded = packet.WhichOneof("payload_variant") == "decoded"
    reception = RawReception(
        time=time,
        gateway=gateway,
        origin=origin,
        packet_id=packet.id,
        relay=packet.relay_node if 0 < packet.relay_node <= _MAX_BYTE else None,
        hop_start=packet.hop_start if 0 < packet.hop_start <= _MAX_HOPS else None,
        hop_limit=packet.hop_limit if packet.hop_limit <= _MAX_HOPS else None,
        snr=snr,
        rssi=rssi,
        port=packet.decoded.portnum if decoded else None,
    )
    return reception, packet


def _packet(data: object) -> mesh_pb2.MeshPacket | None:
    """Decode a row's ``Data``, or ``None`` when it is not a base64 ``MeshPacket``."""
    if not isinstance(data, str) or len(data) > RAW_DATA_MAX_CHARS:
        return None
    try:
        return mesh_pb2.MeshPacket.FromString(base64.b64decode(data, validate=True))
    except (binascii.Error, ValueError, DecodeError):
        return None


def _hex_id(value: object) -> NodeId | None:
    """Return the real node a hex string names, else ``None`` (also for a non-string)."""
    if not isinstance(value, str):
        return None
    try:
        return _node(NodeId.from_hex(value).num)
    except NodeIdError:
        return None


def _node(num: int) -> NodeId | None:
    """Return a real node's id: not 0 and not the broadcast address."""
    return NodeId.from_int(num) if 0 < num < NODE_ID_MAX else None


def _collect_extras(
    state: _Collector, reception: RawReception, packet: mesh_pb2.MeshPacket
) -> None:
    """Read the node-info, traceroute or neighbour-info payload of a packet's first decoded row."""
    payload = packet.decoded.payload
    try:
        if reception.port == portnums_pb2.NODEINFO_APP:
            _collect_key(state, reception, mesh_pb2.User.FromString(payload))
        elif reception.port == portnums_pb2.TRACEROUTE_APP:
            state.routes.extend(
                _routes(reception, packet, mesh_pb2.RouteDiscovery.FromString(payload))
            )
        elif reception.port == portnums_pb2.NEIGHBORINFO_APP:
            report = _neighbors(reception, mesh_pb2.NeighborInfo.FromString(payload))
            if report is not None:
                state.neighbors.append(report)
    except DecodeError:
        return


def _collect_key(state: _Collector, reception: RawReception, user: mesh_pb2.User) -> None:
    """Keep the public key of a node-info packet that names its own sender."""
    if user.id and user.id.lower() != reception.origin.display:
        return
    if not user.public_key:
        return
    if len(user.public_key) != PUBLIC_KEY_BYTES:
        state.bad_keys += 1
        return
    short_name = user.short_name.strip()
    state.keys.append(
        AdvertisedKey(
            time=reception.time,
            node=reception.origin,
            public_key=bytes(user.public_key),
            short_name=terminal_safe(short_name)[:_MAX_NAME_CHARS] if short_name else None,
            hw_model=hw_model_table().try_name(user.hw_model),
            role=role_table().try_name(user.role),
        )
    )


def _routes(
    reception: RawReception, packet: mesh_pb2.MeshPacket, discovery: mesh_pb2.RouteDiscovery
) -> list[RouteObservation]:
    """Split a traceroute's path into runs of known nodes.

    A request on its way is ``from`` followed by the relays that added
    themselves. A reply (``request_id`` set) carries the forward route
    from the requester (its ``to``) to the replying destination (its
    ``from``). A hop that did not record itself appears as the broadcast
    address and breaks the path.
    """
    hops = [*discovery.route]
    if packet.decoded.request_id:
        ids = [packet.to, *hops, getattr(packet, "from")]
    else:
        ids = [getattr(packet, "from"), *hops]
    runs: list[list[NodeId]] = [[]]
    for num in ids:
        node = _node(num)
        if node is None:
            runs.append([])
        else:
            runs[-1].append(node)
    return [RouteObservation(reception.time, tuple(run)) for run in runs if len(run) >= 2]


def _neighbors(
    reception: RawReception, report: mesh_pb2.NeighborInfo
) -> NeighborObservation | None:
    """Read a neighbour report that names its own sender (or no one)."""
    if report.node_id and report.node_id != reception.origin.num:
        return None
    named = (_node(neighbor.node_id) for neighbor in report.neighbors)
    neighbors = tuple(node for node in named if node is not None and node != reception.origin)
    if not neighbors:
        return None
    return NeighborObservation(reception.time, reception.origin, neighbors)
