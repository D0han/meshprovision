"""Builders of lorastats ``PacketsRaw`` rows, shaped exactly like the real answers.

Imported by the ``mesh network`` test modules. A plain module (not
``test_*``), so pytest never collects it. Every row is
``{"Time", "Gateway", "Data"}`` with ``Data`` a base64 ``MeshPacket``, as
lorastats.pl sends them; node ids, names and keys are made up.
"""

from __future__ import annotations

import base64
import hashlib
import zlib
from datetime import UTC, datetime
from typing import Final

from meshtastic.protobuf import mesh_pb2, portnums_pb2

from meshprovision.crypto.known_bad_keys import SMALL_ORDER_POINTS
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


# A synthetic "mini region": three gateways, our nodes, and every case the views tell apart.
G1, G2, G3 = "6a000071", "6a000072", "6a000073"
OURS_ONE = "d0000a01"
"""Ours: heard only through the router, its only first hop."""
OURS_TWO = "d00000bc"
"""Ours: its relay byte 0xbc collides with an outsider's; the radio picks the outsider."""
OURS_RELAY = "d0000c03"
"""Ours: the only first hop of one outsider."""
ROUTER = "c0ffee61"
"""An outsider router: the only first hop of our first node and of two outsiders."""
MUTE = "9a000061"
"""A CLIENT_MUTE node with the router's byte: never a candidate."""
COLLIDER = "bb0000bc"
"""The outsider behind relay byte 0xbc."""
AMBIGUOUS = ("e10000e4", "e20000e4", "e30000e4")
"""Three nodes behind relay byte 0xe4, indistinguishable by radio."""
ORIGINS = ("a1000011", "a2000012", "a3000013", "a4000014", "a5000015")
CLONES = ("c1000001", "c2000002")
HANDOVER = ("4a000001", "4a000002")
MIGRATION_OLD = "11110001"
WEAK = "5e000001"


def _key(label: str) -> bytes:
    """A made-up 32-byte public key that passes the weak-key audit."""
    return hashlib.sha256(label.encode()).digest()


KEY_OURS_ONE: Final[bytes] = _key("ours")
KEY_ROUTER: Final[bytes] = _key("router")
KEY_CLONE: Final[bytes] = _key("clone")
KEY_HANDOVER: Final[bytes] = _key("handover")
KEY_MIGRATION: Final[bytes] = _key("migration")
MIGRATION_NEW: Final[str] = f"{zlib.crc32(KEY_MIGRATION):08x}"
"""The migrated node's key-derived id (firmware 2.8)."""


class _Rows:
    """Collects rows with fresh packet ids."""

    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []
        self._next = 1

    def send(
        self,
        origin: str,
        heard: list[tuple[str, int | None, int, float, int]],
        *,
        time: float,
        port: tuple[int, bytes] | None = None,
    ) -> None:
        """Add one packet, heard as ``(gateway, relay byte, hops taken, snr, rssi)`` each."""
        number = int(origin, 16)
        for gateway, relay, hops, snr, rssi in heard:
            built = packet(
                number,
                self._next,
                relay=relay,
                hop_start=3,
                hop_limit=3 - hops,
                snr=snr,
                rssi=rssi,
                port=None if port is None else port[0],
                payload=b"" if port is None else port[1],
            )
            self.rows.append(row(built, gateway=gateway, time=time))
        self._next += 1


def _traffic(rows: _Rows, now: float) -> None:
    """Every traffic case of the mini region, in the last two hours."""
    at = now - 3600
    for index in range(6):
        rows.send(OURS_ONE, [(G1, 0x61, 1, -8.0, -110)], time=at + index)
    for index in range(3):
        rows.send(OURS_ONE, [(G3, 0xE4, 2, 2.0, -95)], time=at + 10 + index)
    for origin in ORIGINS[:2]:
        for index in range(25):
            rows.send(origin, [(G1, 0x61, 1, -8.0, -110), (G2, 0x61, 1, 4.0, -80)], time=at + index)
    for index in range(5):
        rows.send(ROUTER, [(G1, None, 0, -8.0, -110), (G2, None, 0, 4.0, -80)], time=at + index)
        rows.send(OURS_TWO, [(G2, None, 0, 8.0, -70)], time=at + index)
        rows.send(COLLIDER, [(G1, None, 0, -10.0, -112)], time=at + index)
        rows.send(OURS_RELAY, [(G3, None, 0, 6.0, -85)], time=at + index)
    for index in range(25):
        rows.send(ORIGINS[2], [(G3, 0x03, 1, 6.0, -85)], time=at + index)
    for index in range(10):
        rows.send(ORIGINS[3], [(G1, 0xBC, 1, -10.0, -112)], time=at + index)
    for node in AMBIGUOUS:
        for index in range(3):
            rows.send(node, [(G3, None, 0, 2.0, -95)], time=at + index)
    for index in range(8):
        rows.send(ORIGINS[4], [(G3, 0xE4, 1, 2.0, -95)], time=at + index)
    rows.send(MUTE, [(G3, None, 0, 1.0, -99)], time=at)


def _node_infos(rows: _Rows, now: float) -> None:
    """Every key case of the mini region, heard directly at the first gateway."""

    def advertise(node: str, key: bytes, when: float, short: str, role: int = 0) -> None:
        info = node_info(int(node, 16), key, short_name=short, role=role)
        heard = (G1, 0x61, 1, -8.0, -110) if node == OURS_ONE else (G1, None, 0, 1.0, -100)
        rows.send(node, [heard], time=when, port=info)

    advertise(OURS_ONE, KEY_OURS_ONE, now - 3000, "Our1")
    advertise(ROUTER, KEY_ROUTER, now - 3000, "Rtr", role=2)
    advertise(MUTE, _key("mute"), now - 3000, "Mute", role=1)
    for node in CLONES:
        advertise(node, KEY_CLONE, now - 2000, "Cl" + node[1])
    advertise(HANDOVER[0], KEY_HANDOVER, now - 5 * 3600, "Old")
    advertise(HANDOVER[1], KEY_HANDOVER, now - 1800, "New")
    advertise(MIGRATION_OLD, KEY_MIGRATION, now - 6 * 3600, "Mig")
    advertise(MIGRATION_NEW, KEY_MIGRATION, now - 1200, "Mig")
    advertise(WEAK, SMALL_ORDER_POINTS[1], now - 1500, "Weak")


def mini_region(now: float) -> list[dict[str, object]]:
    """Build the mini region's ``PacketsRaw`` rows, all within the last six hours of ``now``.

    Args:
        now: The current time, epoch seconds.

    Returns:
        The rows.
    """
    rows = _Rows()
    _traffic(rows, now)
    _node_infos(rows, now)
    return rows.rows


def mini_region_nodes(now: float) -> list[dict[str, object]]:
    """Build the mini region's ``Nodes`` rows (lorastats' node list).

    Args:
        now: The current time, epoch seconds.

    Returns:
        The rows: the router and the mute node, both seen recently.
    """
    seen = since_param(now - 600)
    return [
        {"NodeId": ROUTER, "ShortName": "Rtr", "Role": 2, "LastSeen": seen},
        {"NodeId": MUTE, "ShortName": "Mute", "Role": 1, "LastSeen": seen},
    ]
