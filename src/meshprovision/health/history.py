"""A node's health history: hourly buckets and sparse series built from lorastats rows. Pure.

lorastats keeps packet reports for only a day or two, so ``mesh health``
keeps its own compact history per node, for
:data:`HISTORY_RETENTION_SECONDS` (30 days): never the raw rows, only what
the metrics need.

- :class:`HourBucket` -- per UTC hour: receptions, packets, direct
  receptions, receptions per gateway, per relay byte, per hop count and
  per 1 dB SNR step, an RSSI sum/min/max, and the decoded packets per
  port and per ``HopStart``. A bucket exists for every hour lorastats was
  asked about and still keeps (an hour with no reception then has an empty
  bucket, a *silent* hour); an hour nobody asked about has none (unknown).
- sparse series -- telemetry readings, local-stats counters, positions,
  the latest node info, neighbours (port 71), boot times and gateway
  checks.

**Idempotent merging.** A refresh asks lorastats for everything since the
start of the hour of the previous refresh (see :func:`replace_from`), so
the hours it answers for are complete, and :func:`merge` *replaces* every
hour the new data speaks for (and the series points in those hours)
instead of adding to it. Re-running a refresh, or two processes doing the
same refresh, never counts a reception twice.

This module imports nothing that reads files or the network (no
``httpx``, ``pathlib``, :mod:`meshprovision.cache` or
:mod:`meshprovision.db`); ``tests/unit/test_import_contracts.py`` holds it
to that.
"""

from __future__ import annotations

import dataclasses
import math
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final, Protocol, TypeVar

from meshprovision.health.packets import (
    PORT_NEIGHBORINFO,
    PORT_NODEINFO,
    PORT_POSITION,
    PORT_TELEMETRY,
    DecodedPacket,
    Reception,
    parse_neighbor,
    parse_nodeinfo,
    parse_position,
    parse_telemetry,
)
from meshprovision.nodeid import NodeId

__all__ = [
    "ASSUMED_LORASTATS_RETENTION_SECONDS",
    "HISTORY_RETENTION_SECONDS",
    "HOUR_SECONDS",
    "MAX_BOOTS",
    "MAX_GATEWAYS_PER_HOUR",
    "MAX_GATEWAY_CHECKS",
    "MAX_NEIGHBORS",
    "MAX_POSITIONS",
    "MAX_RELAYS_PER_HOUR",
    "MAX_SERIES_POINTS",
    "SNR_BIN_MAX",
    "SNR_BIN_MIN",
    "GatewayCheck",
    "HourBucket",
    "LocalStatsPoint",
    "NodeHistory",
    "NodeInfoSeen",
    "PositionPoint",
    "TelemetryPoint",
    "floor_hour",
    "merge",
    "prune",
    "replace_from",
    "summarize",
    "with_boot",
    "with_gateway_check",
]


class _Timed(Protocol):
    """Anything with a ``time``: a series point or a gateway check."""

    @property
    def time(self) -> float:
        """When it happened, epoch seconds."""
        ...


_T = TypeVar("_T", bound=_Timed)
_K = TypeVar("_K", int, str)

HOUR_SECONDS: Final[int] = 3600

HISTORY_RETENTION_SECONDS: Final[float] = 30 * 24 * 3600
"""How long anything is kept: 30 days."""

ASSUMED_LORASTATS_RETENTION_SECONDS: Final[float] = 24 * 3600
"""How far back lorastats is assumed to still hold every report (it keeps
about a day or two). An hour this recent with no report is recorded as
silent; an older one without a report stays unknown."""

FUTURE_SKEW_SECONDS: Final[float] = 300.0
"""How far ahead of the clock a stored time may be; anything later is dropped."""

MAX_GATEWAYS_PER_HOUR: Final[int] = 64
"""Most gateways kept per hour (those with the most receptions)."""

MAX_RELAYS_PER_HOUR: Final[int] = 64
"""Most relay bytes kept per hour (those with the most receptions)."""

SNR_BIN_MIN: Final[int] = -30
"""SNR steps below this are counted in this one."""

SNR_BIN_MAX: Final[int] = 20
"""SNR steps above this are counted in this one."""

MAX_SERIES_POINTS: Final[int] = 4320
"""Most telemetry or local-stats points kept: one every 10 minutes for 30 days."""

MAX_POSITIONS: Final[int] = 720
"""Most position points kept; a position equal to the previous one is not kept."""

MAX_NEIGHBORS: Final[int] = 64
"""Most neighbours kept (the most recently reported)."""

MAX_BOOTS: Final[int] = 64
"""Most boot times kept (the newest)."""

MAX_GATEWAY_CHECKS: Final[int] = 720
"""Most gateway checks kept (the newest)."""

_BYTE_MASK: Final[int] = 0xFF
_EMPTY: Final[Mapping[int, int]] = MappingProxyType({})
_EMPTY_STR: Final[Mapping[str, int]] = MappingProxyType({})
_EMPTY_TIMES: Final[Mapping[str, float]] = MappingProxyType({})


@dataclass(frozen=True, slots=True)
class HourBucket:
    """What lorastats reported about a node's packets in one UTC hour.

    Attributes:
        hour: The hour's start, unix epoch seconds (a multiple of 3600).
        receptions: Receptions (one packet heard by one gateway).
        packets: Distinct packets, each counted in the hour it was first heard.
        direct: Receptions whose last transmitter was the node itself.
        gateways: Receptions per gateway hex id.
        relays: Receptions per relay byte, direct ones excluded.
        hops: Receptions per hop count (``HopStart - HopLimit``), only
            for packets lorastats decoded.
        snr: Receptions per whole-dB SNR step (floored, clamped to
            :data:`SNR_BIN_MIN`..:data:`SNR_BIN_MAX`).
        rssi: ``(sum, count, min, max)`` of lorastats' RSSI values, or
            ``None`` when none was given.
        ports: Decoded packets per ``PortNum``.
        hop_starts: Decoded packets per ``HopStart``.
    """

    hour: int
    receptions: int = 0
    packets: int = 0
    direct: int = 0
    gateways: Mapping[str, int] = field(default_factory=lambda: _EMPTY_STR)
    relays: Mapping[int, int] = field(default_factory=lambda: _EMPTY)
    hops: Mapping[int, int] = field(default_factory=lambda: _EMPTY)
    snr: Mapping[int, int] = field(default_factory=lambda: _EMPTY)
    rssi: tuple[int, int, int, int] | None = None
    ports: Mapping[int, int] = field(default_factory=lambda: _EMPTY)
    hop_starts: Mapping[int, int] = field(default_factory=lambda: _EMPTY)


@dataclass(frozen=True, slots=True)
class TelemetryPoint:
    """One device-metrics telemetry payload.

    Attributes:
        time: When it was heard, epoch seconds.
        battery: Battery level percentage (101 = external power).
        voltage: Battery voltage.
        channel_utilization: Channel utilization percentage.
        air_util_tx: Transmit air utilization percentage.
    """

    time: float
    battery: int | None = None
    voltage: float | None = None
    channel_utilization: float | None = None
    air_util_tx: float | None = None


@dataclass(frozen=True, slots=True)
class LocalStatsPoint:
    """One local-stats telemetry payload: counters since the node booted.

    Attributes:
        time: When it was heard, epoch seconds.
        rx: Packets received.
        tx: Packets sent.
        relayed: Packets relayed.
    """

    time: float
    rx: int | None = None
    tx: int | None = None
    relayed: int | None = None


@dataclass(frozen=True, slots=True)
class PositionPoint:
    """One position payload.

    Attributes:
        time: When it was heard, epoch seconds.
        latitude: Decimal degrees.
        longitude: Decimal degrees.
    """

    time: float
    latitude: float
    longitude: float


@dataclass(frozen=True, slots=True)
class NodeInfoSeen:
    """The newest node-info payload.

    Attributes:
        time: When it was heard, epoch seconds.
        short_name: The short name.
        long_name: The long name.
        role: The canonical ``Role`` name, when known.
    """

    time: float
    short_name: str
    long_name: str
    role: str | None


@dataclass(frozen=True, slots=True)
class GatewayCheck:
    """One look at what the node uplinked as an MQTT gateway.

    Attributes:
        time: When it was asked, epoch seconds.
        window_seconds: How far back it was asked about.
        receptions: Reports it uplinked in that window.
        nodes: Distinct nodes those reports were from.
    """

    time: float
    window_seconds: float
    receptions: int
    nodes: int


@dataclass(frozen=True, slots=True)
class NodeHistory:
    """Everything kept about one node.

    Attributes:
        node: The node.
        fetched_at: When lorastats was last asked about it, epoch seconds.
        last_heard: The newest reception time ever seen, epoch seconds.
        hours: The hour buckets, oldest first, one per hour.
        telemetry: Device-metrics points, oldest first.
        local_stats: Local-stats points, oldest first.
        positions: Position points, oldest first.
        nodeinfo: The newest node info, when any.
        neighbors: Neighbour hex id -> when it was last reported.
        boots: Boot times (lorastats' ``LastBoot``), oldest first.
        gateway_checks: Gateway checks, oldest first.
    """

    node: NodeId
    fetched_at: float | None = None
    last_heard: float | None = None
    hours: tuple[HourBucket, ...] = ()
    telemetry: tuple[TelemetryPoint, ...] = ()
    local_stats: tuple[LocalStatsPoint, ...] = ()
    positions: tuple[PositionPoint, ...] = ()
    nodeinfo: NodeInfoSeen | None = None
    neighbors: Mapping[str, float] = field(default_factory=lambda: _EMPTY_TIMES)
    boots: tuple[float, ...] = ()
    gateway_checks: tuple[GatewayCheck, ...] = ()


def floor_hour(epoch: float) -> int:
    """Return the start of the UTC hour ``epoch`` falls in.

    Args:
        epoch: Unix epoch seconds.

    Returns:
        The hour's start, epoch seconds.
    """
    return int(epoch // HOUR_SECONDS) * HOUR_SECONDS


def replace_from(history: NodeHistory, *, now: float) -> int | None:
    """Return from when the next refresh must ask lorastats, or ``None`` for everything.

    Args:
        history: The node's history.
        now: The current time, epoch seconds.

    Returns:
        The start of the hour of the previous refresh (of ``now`` when
        that lies in the future), or ``None`` when there was none.
    """
    if history.fetched_at is None:
        return None
    return floor_hour(min(history.fetched_at, now))


def _top(counts: Mapping[_K, int], limit: int) -> Mapping[_K, int]:
    """Keep the ``limit`` largest counts (ties: the smaller key)."""
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return MappingProxyType(dict(ranked[:limit]))


def _snr_bin(snr: float) -> int:
    """Return the clamped whole-dB step of an SNR value."""
    return min(max(math.floor(snr), SNR_BIN_MIN), SNR_BIN_MAX)


def _hops(reception: Reception, decoded: Mapping[str, DecodedPacket]) -> int | None:
    """Return how many hops a reception took, when its packet was decoded."""
    packet = decoded.get(reception.packet_id)
    if packet is None or packet.hop_start is None or reception.hop_limit is None:
        return None
    taken = packet.hop_start - reception.hop_limit
    return taken if taken >= 0 else None


def _bucket(
    hour: int,
    receptions: Sequence[Reception],
    first_heard: Mapping[str, int],
    decoded: Mapping[str, DecodedPacket],
    own_byte: int,
) -> HourBucket:
    """Aggregate one hour's receptions and decoded packets."""
    relays: Counter[int] = Counter()
    hops: Counter[int] = Counter()
    rssi = [r.rssi for r in receptions if r.rssi is not None]
    direct = 0
    for reception in receptions:
        if reception.relay == own_byte:
            direct += 1
        elif reception.relay is not None:
            relays[reception.relay] += 1
        taken = _hops(reception, decoded)
        if taken is not None:
            hops[taken] += 1
    in_hour = [packet for packet in decoded.values() if floor_hour(packet.time) == hour]
    return HourBucket(
        hour=hour,
        receptions=len(receptions),
        packets=sum(1 for first in first_heard.values() if first == hour),
        direct=direct,
        gateways=_top(Counter(r.gateway for r in receptions), MAX_GATEWAYS_PER_HOUR),
        relays=_top(relays, MAX_RELAYS_PER_HOUR),
        hops=MappingProxyType(dict(sorted(hops.items()))),
        snr=MappingProxyType(
            dict(sorted(Counter(_snr_bin(r.snr) for r in receptions if r.snr is not None).items()))
        ),
        rssi=(sum(rssi), len(rssi), min(rssi), max(rssi)) if rssi else None,
        ports=MappingProxyType(
            dict(sorted(Counter(p.port for p in in_hour if p.port is not None).items()))
        ),
        hop_starts=MappingProxyType(
            dict(sorted(Counter(p.hop_start for p in in_hour if p.hop_start is not None).items()))
        ),
    )


def summarize(
    node: NodeId,
    receptions: Iterable[Reception],
    decoded: Iterable[DecodedPacket],
    *,
    since: int | None,
    fetched_at: float,
) -> NodeHistory:
    """Build the history one refresh contributes.

    Rows before ``since`` are left out: they belong to hours the history
    already has complete. Every hour from ``since`` up to the hour of
    ``fetched_at`` that starts after ``fetched_at -``
    :data:`ASSUMED_LORASTATS_RETENTION_SECONDS` gets a bucket, an empty
    one when nothing was heard; older hours only when something was.
    Without ``since`` (a node's first refresh) empty buckets start only at
    the hour of its oldest reception, and there are none without any: how
    far back lorastats really keeps its reports is not known.

    Args:
        node: The node.
        receptions: Its parsed ``PacketReports`` rows.
        decoded: Its parsed ``PacketsParsed`` rows.
        since: The start of the hour this refresh asked from, or ``None``
            when it asked for everything.
        fetched_at: When lorastats was asked, epoch seconds.

    Returns:
        The refresh's history: ``fetched_at`` set, buckets and series
        from the rows.
    """
    start = float("-inf") if since is None else since
    kept = [r for r in receptions if r.time >= start]
    packets = {p.packet_id: p for p in decoded if p.time >= start}
    first_heard: dict[str, int] = {}
    for reception in sorted(kept, key=lambda r: r.time):
        first_heard.setdefault(reception.packet_id, floor_hour(reception.time))
    by_hour: dict[int, list[Reception]] = {}
    for reception in kept:
        by_hour.setdefault(floor_hour(reception.time), []).append(reception)
    for packet in packets.values():
        by_hour.setdefault(floor_hour(packet.time), [])
    first_silent = floor_hour(fetched_at - ASSUMED_LORASTATS_RETENTION_SECONDS) + HOUR_SECONDS
    if since is not None:
        first_silent = max(first_silent, since)
    elif kept:
        first_silent = max(first_silent, floor_hour(min(r.time for r in kept)))
    else:
        first_silent = floor_hour(fetched_at) + HOUR_SECONDS
    for hour in range(first_silent, floor_hour(fetched_at) + 1, HOUR_SECONDS):
        by_hour.setdefault(hour, [])
    own_byte = node.num & _BYTE_MASK
    return dataclasses.replace(
        _series(node, packets.values()),
        fetched_at=fetched_at,
        last_heard=max((r.time for r in kept), default=None),
        hours=tuple(
            _bucket(hour, by_hour[hour], first_heard, packets, own_byte) for hour in sorted(by_hour)
        ),
    )


def _series(node: NodeId, packets: Iterable[DecodedPacket]) -> NodeHistory:
    """Build the telemetry/local-stats/position/node-info/neighbour series of decoded packets."""
    telemetry: list[TelemetryPoint] = []
    local_stats: list[LocalStatsPoint] = []
    positions: list[PositionPoint] = []
    nodeinfo: NodeInfoSeen | None = None
    neighbors: dict[str, float] = {}
    for packet in sorted(packets, key=lambda p: p.time):
        if packet.port == PORT_TELEMETRY:
            reading = parse_telemetry(packet.payload)
            if reading is None:
                continue
            point = TelemetryPoint(
                packet.time,
                reading.battery,
                reading.voltage,
                reading.channel_utilization,
                reading.air_util_tx,
            )
            if point != TelemetryPoint(packet.time):
                telemetry.append(point)
            stats = LocalStatsPoint(packet.time, reading.rx, reading.tx, reading.relayed)
            if stats != LocalStatsPoint(packet.time):
                local_stats.append(stats)
        elif packet.port == PORT_POSITION:
            position = parse_position(packet.payload)
            if position is not None:
                positions.append(PositionPoint(packet.time, *position))
        elif packet.port == PORT_NODEINFO:
            info = parse_nodeinfo(packet.payload)
            if info is not None:
                nodeinfo = NodeInfoSeen(packet.time, info.short_name, info.long_name, info.role)
        elif packet.port == PORT_NEIGHBORINFO:
            neighbor = parse_neighbor(packet.payload)
            if neighbor is not None:
                neighbors[neighbor.hex] = packet.time
    return NodeHistory(
        node=node,
        telemetry=tuple(telemetry),
        local_stats=tuple(local_stats),
        positions=tuple(positions),
        nodeinfo=nodeinfo,
        neighbors=MappingProxyType(neighbors),
    )


def _outside(points: Iterable[_T], hours: frozenset[int]) -> list[_T]:
    """Keep the points whose hour is not one of ``hours``."""
    return [p for p in points if floor_hour(p.time) not in hours]


def merge(old: NodeHistory, new: NodeHistory) -> NodeHistory:
    """Merge a refresh's history into the stored one.

    Every hour ``new`` has a bucket for replaces the stored hour, and the
    stored series points in those hours are replaced by ``new``'s; other
    hours and points are kept. Node info, neighbours, boots and gateway
    checks are combined (the newest wins). Merging the same refresh twice
    gives the same result as merging it once.

    Args:
        old: The stored history.
        new: The refresh's history (from :func:`summarize`).

    Returns:
        The merged history, not yet pruned (see :func:`prune`).
    """
    replaced = frozenset(bucket.hour for bucket in new.hours)
    hours = {bucket.hour: bucket for bucket in old.hours if bucket.hour not in replaced}
    hours.update((bucket.hour, bucket) for bucket in new.hours)
    neighbors = dict(old.neighbors)
    for key, seen in new.neighbors.items():
        neighbors[key] = max(seen, neighbors.get(key, seen))
    infos = [info for info in (old.nodeinfo, new.nodeinfo) if info is not None]
    return NodeHistory(
        node=old.node,
        fetched_at=_max_optional(old.fetched_at, new.fetched_at),
        last_heard=_max_optional(old.last_heard, new.last_heard),
        hours=tuple(hours[hour] for hour in sorted(hours)),
        telemetry=_by_time([*_outside(old.telemetry, replaced), *new.telemetry]),
        local_stats=_by_time([*_outside(old.local_stats, replaced), *new.local_stats]),
        positions=_by_time([*_outside(old.positions, replaced), *new.positions]),
        nodeinfo=max(infos, key=lambda info: info.time) if infos else None,
        neighbors=MappingProxyType(neighbors),
        boots=tuple(sorted({*old.boots, *new.boots})),
        gateway_checks=_by_time([*old.gateway_checks, *new.gateway_checks]),
    )


def _max_optional(first: float | None, second: float | None) -> float | None:
    """Return the larger of two optional values."""
    values = [value for value in (first, second) if value is not None]
    return max(values) if values else None


def _by_time(points: Iterable[_T]) -> tuple[_T, ...]:
    """Sort points by time, keeping the last one given for a repeated time."""
    by_time = {p.time: p for p in points}
    return tuple(by_time[time] for time in sorted(by_time))


def with_boot(history: NodeHistory, boot: float) -> NodeHistory:
    """Record a boot time (lorastats' ``LastBoot``); a known one is not repeated.

    Args:
        history: The node's history.
        boot: The boot time, epoch seconds.

    Returns:
        The history with the boot time recorded.
    """
    return dataclasses.replace(history, boots=tuple(sorted({*history.boots, boot})))


def with_gateway_check(history: NodeHistory, check: GatewayCheck) -> NodeHistory:
    """Record a gateway check.

    Args:
        history: The node's history.
        check: The check.

    Returns:
        The history with the check recorded.
    """
    return dataclasses.replace(history, gateway_checks=_by_time([*history.gateway_checks, check]))


def prune(history: NodeHistory, *, now: float) -> NodeHistory:
    """Drop what is older than the retention or in the future, and apply every cap.

    Args:
        history: The history to bound.
        now: The current time, epoch seconds.

    Returns:
        The history with only hours and points from the last
        :data:`HISTORY_RETENTION_SECONDS` up to
        :data:`FUTURE_SKEW_SECONDS` ahead of ``now``, at most
        :data:`MAX_SERIES_POINTS` telemetry and local-stats points,
        :data:`MAX_POSITIONS` positions (a repeat of the previous position
        dropped), :data:`MAX_NEIGHBORS` neighbours, :data:`MAX_BOOTS` boots
        and :data:`MAX_GATEWAY_CHECKS` checks, the newest kept.
    """
    oldest = now - HISTORY_RETENTION_SECONDS
    newest = now + FUTURE_SKEW_SECONDS

    def current(time: float) -> bool:
        return oldest <= time <= newest

    neighbors = sorted(
        ((key, seen) for key, seen in history.neighbors.items() if current(seen)),
        key=lambda item: (-item[1], item[0]),
    )[:MAX_NEIGHBORS]
    nodeinfo = history.nodeinfo
    return NodeHistory(
        node=history.node,
        fetched_at=history.fetched_at,
        last_heard=history.last_heard,
        hours=tuple(b for b in history.hours if floor_hour(oldest) <= b.hour <= floor_hour(newest)),
        telemetry=tuple(p for p in history.telemetry if current(p.time))[-MAX_SERIES_POINTS:],
        local_stats=tuple(p for p in history.local_stats if current(p.time))[-MAX_SERIES_POINTS:],
        positions=_distinct_positions(p for p in history.positions if current(p.time))[
            -MAX_POSITIONS:
        ],
        nodeinfo=nodeinfo if nodeinfo is not None and current(nodeinfo.time) else None,
        neighbors=MappingProxyType(dict(sorted(neighbors))),
        boots=tuple(b for b in history.boots if current(b))[-MAX_BOOTS:],
        gateway_checks=tuple(c for c in history.gateway_checks if current(c.time))[
            -MAX_GATEWAY_CHECKS:
        ],
    )


def _distinct_positions(points: Iterable[PositionPoint]) -> tuple[PositionPoint, ...]:
    """Drop each position equal to the one before it."""
    kept: list[PositionPoint] = []
    for point in points:
        if not kept or (kept[-1].latitude, kept[-1].longitude) != (
            point.latitude,
            point.longitude,
        ):
            kept.append(point)
    return tuple(kept)
