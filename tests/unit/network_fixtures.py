"""Builders of lorastats ``PacketsRaw`` rows, shaped exactly like the real answers.

Imported by the ``mesh network`` test modules. A plain module (not
``test_*``), so pytest never collects it. Every row is
``{"Time", "Gateway", "Data"}`` with ``Data`` a base64 ``MeshPacket``, as
lorastats.pl sends them; node ids, names and keys are made up.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Final

from meshtastic.protobuf import mesh_pb2, portnums_pb2

from meshprovision.datasources.lorastats_packets import since_param

BROADCAST: Final[int] = 0xFFFFFFFF
NOW: Final[float] = datetime(2026, 10, 20, 21, 0, tzinfo=UTC).timestamp()
"""The tests' clock: 2026-10-20 21:00 UTC (23:00 in Warsaw)."""

T0: Final[float] = datetime(2026, 10, 20, 20, 15, tzinfo=UTC).timestamp()
"""A reception time in the hour before :data:`NOW`."""


def packet(
    origin: int,
    packet_id: int,
    *,
    relay: int | None = None,
    hop_start: int = 3,
    hop_limit: int = 3,
    snr: float = 6.5,
    rssi: int = -90,
    to: int = BROADCAST,
    port: int | None = None,
    payload: bytes = b"",
    request_id: int = 0,
    encrypted: bytes = b"\x01\x02\x03",
) -> mesh_pb2.MeshPacket:
    """Build one ``MeshPacket`` as a gateway uplinks it.

    Args:
        origin: The sender (``from``).
        packet_id: The packet id.
        relay: The relay byte; defaults to the origin's own last byte (heard directly).
        hop_start: The hop start.
        hop_limit: The hop limit left.
        snr: The gateway's SNR.
        rssi: The gateway's RSSI (negative dBm; 0 = not given).
        to: The destination.
        port: A decoded port; ``None`` for an encrypted packet.
        payload: The decoded payload.
        request_id: The decoded ``request_id`` (a reply when set).
        encrypted: The encrypted bytes, for an encrypted packet.

    Returns:
        The packet.
    """
    built = mesh_pb2.MeshPacket()
    setattr(built, "from", origin)
    built.to = to
    built.id = packet_id
    built.hop_start = hop_start
    built.hop_limit = hop_limit
    built.relay_node = origin & 0xFF if relay is None else relay
    built.rx_snr = snr
    built.rx_rssi = rssi
    if port is None:
        built.encrypted = encrypted
    else:
        built.decoded.portnum = port
        built.decoded.payload = payload
        built.decoded.request_id = request_id
    return built


def row(
    built: mesh_pb2.MeshPacket, *, gateway: str = "bbad0594", time: float = T0
) -> dict[str, object]:
    """Wrap a packet as one ``PacketsRaw`` row.

    Args:
        built: The packet.
        gateway: The uplinking gateway's hex id.
        time: When it was heard, epoch seconds (rendered as naive Warsaw time).

    Returns:
        ``{"Time", "Gateway", "Data"}``.
    """
    data = base64.b64encode(built.SerializeToString()).decode("ascii")
    return {"Time": since_param(time), "Gateway": gateway, "Data": data}


def node_info(
    node: int,
    key: bytes,
    *,
    short_name: str = "AB12",
    hw_model: int = 43,
    role: int = 2,
    user_id: str | None = None,
) -> tuple[int, bytes]:
    """Build a node-info port and payload.

    Args:
        node: The node (its ``User.id`` is ``!<hex>`` unless ``user_id`` is given).
        key: The public key.
        short_name: The short name.
        hw_model: The ``HardwareModel`` number (43 = HELTEC_V3).
        role: The ``Role`` number (2 = ROUTER).
        user_id: The ``User.id`` to send instead.

    Returns:
        ``(port, payload)``.
    """
    user = mesh_pb2.User(
        id=f"!{node:08x}" if user_id is None else user_id,
        long_name="Long Name",
        short_name=short_name,
        hw_model=hw_model,
        role=role,
        public_key=key,
    )
    return portnums_pb2.NODEINFO_APP, user.SerializeToString()


def traceroute(route: list[int]) -> tuple[int, bytes]:
    """Build a traceroute port and payload.

    Args:
        route: The node ids the route discovery recorded.

    Returns:
        ``(port, payload)``.
    """
    return portnums_pb2.TRACEROUTE_APP, mesh_pb2.RouteDiscovery(route=route).SerializeToString()


def neighbor_info(node: int, neighbors: list[int]) -> tuple[int, bytes]:
    """Build a neighbour-info port and payload.

    Args:
        node: The reporting node (``node_id``; 0 leaves it unset).
        neighbors: The neighbours' ids.

    Returns:
        ``(port, payload)``.
    """
    report = mesh_pb2.NeighborInfo(
        node_id=node, neighbors=[mesh_pb2.Neighbor(node_id=n, snr=5.0) for n in neighbors]
    )
    return portnums_pb2.NEIGHBORINFO_APP, report.SerializeToString()
