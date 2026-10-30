"""Health metrics of one node over a window of its history. Pure.

Every metric states its sample: the hours lorastats was asked about
(``covered_hours``), the receptions, the decoded packets. What each one
can and cannot tell:

- **Receptions and gateways** count lorastats ``PacketReports`` rows: one
  per packet per MQTT gateway that uplinked it. A gateway that hears a
  packet over MQTT instead of radio cannot be told apart, so "heard by"
  means "uplinked by".
- **Direct receptions** are those whose last transmitter (``RelayNode``,
  the last byte of its id) is the node itself. Another node with the same
  last byte relaying it counts as direct too (1 in 256 per relay).
- **Hops** (``HopStart - HopLimit``) need the packet's ``HopStart``, which
  only decoded packets carry (``PacketsParsed``, a few percent of the
  receptions in practice), so the hop counts are a sample; the share is
  given as ``decoded_share``.
- **Relays** are counted by last byte; a byte is attributed to a node of
  ours only when exactly one has it, and even then it is a likely match,
  not a certainty.
- **RSSI** is shown as lorastats gives it: a positive number that rises
  with SNR in the data seen so far (as ``RSSI + 256`` would), so it is not
  converted to dBm and no rule uses it.
- **Packets per hour**, telemetry and position counts come from the
  decoded subset or from receptions, so they are lower bounds.
- **Battery trend** is a least-squares slope over the telemetry battery
  readings in the window (external power and 0% left out); the newest
  external-power reading is kept apart (``battery_powered_time``).

This module imports nothing that reads files or the network (no
``httpx``, ``pathlib``, :mod:`meshprovision.cache` or
:mod:`meshprovision.db`); ``tests/unit/test_import_contracts.py`` holds it
to that.
"""

from __future__ import annotations

import itertools
import statistics
from collections import Counter
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final

from meshprovision.health.history import (
    HOUR_SECONDS,
    GatewayCheck,
    HourBucket,
    LocalStatsPoint,
    NodeHistory,
    NodeInfoSeen,
    PositionPoint,
    TelemetryPoint,
    floor_hour,
)
from meshprovision.health.packets import PORT_POSITION, PORT_TELEMETRY
from meshprovision.nodeid import NodeId

__all__ = [
    "BATTERY_TREND_MIN_POINTS",
    "BATTERY_TREND_MIN_SPAN_HOURS",
    "MAX_RELAYS_LISTED",
    "BatteryTrend",
    "NodeMetrics",
    "RelayShare",
    "compute_metrics",
    "quantile",
]

BATTERY_TREND_MIN_POINTS: Final[int] = 6
"""Fewest battery readings a trend is computed from."""

BATTERY_TREND_MIN_SPAN_HOURS: Final[float] = 12.0
"""Shortest time the battery readings of a trend must span."""

MAX_RELAYS_LISTED: Final[int] = 5
"""Most relay bytes listed per node (by receptions)."""

_BYTE_MASK: Final[int] = 0xFF
_POWERED: Final[int] = 100
"""A battery level above this means external power."""
_SECONDS_PER_DAY: Final[float] = 86400.0
_NO_COUNTS: Final[Mapping[int, int]] = MappingProxyType({})


@dataclass(frozen=True, slots=True)
class RelayShare:
    """How many of a node's relayed receptions came through one relay byte.

    Attributes:
        byte: The relay's last id byte.
        receptions: Receptions through it.
        share: ``receptions`` over every relayed (not direct) reception.
        candidates: The other nodes of ours whose id ends in ``byte``.
    """

    byte: int
    receptions: int
    share: float
    candidates: tuple[NodeId, ...]


@dataclass(frozen=True, slots=True)
class BatteryTrend:
    """The battery readings of a window and how fast they change.

    Attributes:
        latest: The newest battery reading, percent.
        latest_time: When it was heard, epoch seconds.
        points: How many readings the trend uses.
        span_hours: The time they span.
        slope_per_day: Percentage points per day, or ``None`` with fewer
            than :data:`BATTERY_TREND_MIN_POINTS` readings or a span under
            :data:`BATTERY_TREND_MIN_SPAN_HOURS`.
    """

    latest: int
    latest_time: float
    points: int
    span_hours: float
    slope_per_day: float | None


@dataclass(frozen=True, slots=True)
class NodeMetrics:
    """One node's health metrics over a window.

    Attributes:
        node: The node.
        days: The window, in days.
        window_start: Its start, epoch seconds.
        now: Its end, epoch seconds.
        covered_hours: Hours of the window lorastats was asked about.
        silent_hours: Covered hours without a reception.
        longest_silence_hours: The longest run of consecutive silent hours.
        last_heard: The newest reception ever recorded, epoch seconds.
        receptions: Receptions in the window.
        packets: Distinct packets in the window.
        packets_per_hour: ``packets / covered_hours``.
        direct: Direct receptions.
        gateways: ``(gateway hex, receptions)`` of every gateway, most first.
        gateway_count: Distinct gateways, the node itself included when it
            uplinks itself (see :attr:`other_gateway_count`).
        uplinks_itself: Whether the node is among its own gateways (it is
            an MQTT gateway).
        hops: Receptions per hop count (decoded packets only).
        hop_samples: Receptions with a hop count.
        hop_start: The most common ``HopStart`` (configured hop limit).
        hop_start_samples: Decoded packets with a ``HopStart``.
        snr_median: The median whole-dB SNR step.
        snr_low: The 10th-percentile SNR step.
        snr_samples: Receptions with an SNR.
        rssi_mean: The mean raw lorastats RSSI.
        relayed: Receptions through a relay (not direct, relay known).
        relays: The busiest relay bytes, at most :data:`MAX_RELAYS_LISTED`.
        ports: Decoded packets per ``PortNum``.
        decoded_packets: Decoded packets.
        telemetry_per_hour: Telemetry packets per covered hour (decoded,
            so a lower bound).
        positions_per_hour: Position packets per covered hour (likewise).
        battery: The battery readings and trend, when any.
        battery_powered_time: When the newest battery reading above 100
            (external power) in the window was heard, epoch seconds.
        channel_utilization: Mean channel utilization of the readings.
        air_util_tx: Mean transmit air utilization of the readings.
        latest_telemetry: The newest telemetry reading in the window.
        latest_local_stats: The newest local-stats counters in the window.
        position: The newest position in the window.
        nodeinfo: The newest node info.
        boots: Boot times in the window.
        neighbors: ``(hex id, last reported)`` in the window, newest first.
        gateway_check: The newest gateway check in the window.
    """

    node: NodeId
    days: int
    window_start: float
    now: float
    covered_hours: int = 0
    silent_hours: int = 0
    longest_silence_hours: int = 0
    last_heard: float | None = None
    receptions: int = 0
    packets: int = 0
    packets_per_hour: float | None = None
    direct: int = 0
    gateways: tuple[tuple[str, int], ...] = ()
    gateway_count: int = 0
    uplinks_itself: bool = False
    hops: Mapping[int, int] = field(default_factory=lambda: _NO_COUNTS)
    hop_samples: int = 0
    hop_start: int | None = None
    hop_start_samples: int = 0
    snr_median: int | None = None
    snr_low: int | None = None
    snr_samples: int = 0
    rssi_mean: float | None = None
    relayed: int = 0
    relays: tuple[RelayShare, ...] = ()
    ports: Mapping[int, int] = field(default_factory=lambda: _NO_COUNTS)
    decoded_packets: int = 0
    telemetry_per_hour: float | None = None
    positions_per_hour: float | None = None
    battery: BatteryTrend | None = None
    battery_powered_time: float | None = None
    channel_utilization: float | None = None
    air_util_tx: float | None = None
    latest_telemetry: TelemetryPoint | None = None
    latest_local_stats: LocalStatsPoint | None = None
    position: PositionPoint | None = None
    nodeinfo: NodeInfoSeen | None = None
    boots: tuple[float, ...] = ()
    neighbors: tuple[tuple[str, float], ...] = ()
    gateway_check: GatewayCheck | None = None

    @property
    def direct_share(self) -> float | None:
        """Direct receptions over all receptions, or ``None`` without any."""
        return self.direct / self.receptions if self.receptions else None

    @property
    def decoded_share(self) -> float | None:
        """Receptions with a hop count over all receptions, or ``None`` without any."""
        return self.hop_samples / self.receptions if self.receptions else None

    @property
    def hops_max(self) -> int | None:
        """The most hops any sampled reception took."""
        return max(self.hops) if self.hops else None

    @property
    def hops_median(self) -> int | None:
        """The median hop count of the sampled receptions."""
        return quantile(self.hops, 0.5)

    @property
    def other_gateway_count(self) -> int:
        """Distinct gateways besides the node itself (its own uplinks show nothing of its reach)."""
        return self.gateway_count - 1 if self.uplinks_itself else self.gateway_count

    @property
    def top_relay(self) -> RelayShare | None:
        """The busiest relay byte, when any."""
        return self.relays[0] if self.relays else None


def quantile(counts: Mapping[int, int], fraction: float) -> int | None:
    """Return the smallest value at or below which ``fraction`` of the samples lie.

    Args:
        counts: Samples per value.
        fraction: Between 0 and 1 (``0.5`` for the lower median).

    Returns:
        The value, or ``None`` without samples.
    """
    total = sum(counts.values())
    if not total:
        return None
    values = sorted(counts)
    cumulative = itertools.accumulate(counts[value] for value in values)
    return next(
        value for value, count in zip(values, cumulative, strict=True) if count >= fraction * total
    )


def _sum_counts(maps: Iterable[Mapping[int, int]]) -> Mapping[int, int]:
    """Add up per-value counts."""
    total: Counter[int] = Counter()
    for counts in maps:
        total.update(counts)
    return MappingProxyType(dict(sorted(total.items())))


def _longest_silence(buckets: Iterable[HourBucket]) -> int:
    """Return the longest run of consecutive covered hours without a reception."""
    longest = run = 0
    previous: int | None = None
    for bucket in buckets:
        consecutive = previous is not None and bucket.hour == previous + HOUR_SECONDS
        run = 0 if bucket.receptions else run + 1 if consecutive else 1
        longest = max(longest, run)
        previous = bucket.hour
    return longest


def _relays(
    buckets: Iterable[HourBucket], node: NodeId, fleet: Collection[NodeId]
) -> tuple[int, tuple[RelayShare, ...]]:
    """Return the relayed receptions and the busiest relay bytes."""
    counts: Counter[int] = Counter()
    for bucket in buckets:
        counts.update(bucket.relays)
    relayed = sum(counts.values())
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:MAX_RELAYS_LISTED]
    return relayed, tuple(
        RelayShare(
            byte=byte,
            receptions=count,
            share=count / relayed,
            candidates=tuple(sorted(m for m in fleet if m != node and m.num & _BYTE_MASK == byte)),
        )
        for byte, count in ranked
    )


def _battery(points: Iterable[TelemetryPoint]) -> BatteryTrend | None:
    """Return the battery readings' latest value and least-squares slope."""
    readings = [
        (p.time, p.battery) for p in points if p.battery is not None and 0 < p.battery <= _POWERED
    ]
    if not readings:
        return None
    latest_time, latest = readings[-1]
    span_hours = (readings[-1][0] - readings[0][0]) / HOUR_SECONDS
    slope = None
    if len(readings) >= BATTERY_TREND_MIN_POINTS and span_hours >= BATTERY_TREND_MIN_SPAN_HOURS:
        times = [time for time, _ in readings]
        levels = [float(level) for _, level in readings]
        slope = statistics.linear_regression(times, levels).slope * _SECONDS_PER_DAY
    return BatteryTrend(latest, latest_time, len(readings), span_hours, slope)


def _powered_time(points: Iterable[TelemetryPoint]) -> float | None:
    """Return when the newest external-power battery reading was heard, if any."""
    times = [p.time for p in points if p.battery is not None and p.battery > _POWERED]
    return max(times, default=None)


def _mean(values: Iterable[float | None]) -> float | None:
    """Return the mean of the known values, or ``None`` without any."""
    known = [value for value in values if value is not None]
    return statistics.fmean(known) if known else None


def compute_metrics(
    history: NodeHistory, *, now: float, days: int, fleet: Collection[NodeId] = ()
) -> NodeMetrics:
    """Compute a node's metrics over the last ``days`` days of its history.

    Args:
        history: The node's history.
        now: The window's end, epoch seconds.
        days: The window, in days.
        fleet: Our nodes, to attribute relay bytes to.

    Returns:
        The metrics; every count is 0 and every statistic ``None`` when the
        window holds nothing.
    """
    start = now - days * _SECONDS_PER_DAY
    first_hour = floor_hour(start)
    buckets = [b for b in history.hours if first_hour <= b.hour <= now]
    covered = len(buckets)
    receptions = sum(b.receptions for b in buckets)
    packets = sum(b.packets for b in buckets)
    gateways: Counter[str] = Counter()
    for bucket in buckets:
        gateways.update(bucket.gateways)
    hops = _sum_counts(b.hops for b in buckets)
    snr = _sum_counts(b.snr for b in buckets)
    ports = _sum_counts(b.ports for b in buckets)
    hop_starts = _sum_counts(b.hop_starts for b in buckets)
    rssi = [b.rssi for b in buckets if b.rssi is not None and b.rssi[1]]
    relayed, relays = _relays(buckets, history.node, fleet)

    def recent(time: float) -> bool:
        return start <= time <= now

    telemetry = [p for p in history.telemetry if recent(p.time)]
    local_stats = [p for p in history.local_stats if recent(p.time)]
    positions = [p for p in history.positions if recent(p.time)]
    checks = [c for c in history.gateway_checks if recent(c.time)]

    def per_hour(count: int) -> float | None:
        return count / covered if covered else None

    return NodeMetrics(
        node=history.node,
        days=days,
        window_start=start,
        now=now,
        covered_hours=covered,
        silent_hours=sum(1 for b in buckets if not b.receptions),
        longest_silence_hours=_longest_silence(buckets),
        last_heard=history.last_heard,
        receptions=receptions,
        packets=packets,
        packets_per_hour=per_hour(packets),
        direct=sum(b.direct for b in buckets),
        gateways=tuple(sorted(gateways.items(), key=lambda item: (-item[1], item[0]))),
        gateway_count=len(gateways),
        uplinks_itself=history.node.hex in gateways,
        hops=hops,
        hop_samples=sum(hops.values()),
        hop_start=max(hop_starts, key=lambda value: (hop_starts[value], value))
        if hop_starts
        else None,
        hop_start_samples=sum(hop_starts.values()),
        snr_median=quantile(snr, 0.5),
        snr_low=quantile(snr, 0.1),
        snr_samples=sum(snr.values()),
        rssi_mean=sum(r[0] for r in rssi) / sum(r[1] for r in rssi) if rssi else None,
        relayed=relayed,
        relays=relays,
        ports=ports,
        decoded_packets=sum(ports.values()),
        telemetry_per_hour=per_hour(ports.get(PORT_TELEMETRY, 0)),
        positions_per_hour=per_hour(ports.get(PORT_POSITION, 0)),
        battery=_battery(telemetry),
        battery_powered_time=_powered_time(telemetry),
        channel_utilization=_mean(p.channel_utilization for p in telemetry),
        air_util_tx=_mean(p.air_util_tx for p in telemetry),
        latest_telemetry=telemetry[-1] if telemetry else None,
        latest_local_stats=local_stats[-1] if local_stats else None,
        position=positions[-1] if positions else None,
        nodeinfo=history.nodeinfo,
        boots=tuple(b for b in history.boots if recent(b)),
        neighbors=tuple(
            sorted(
                ((key, seen) for key, seen in history.neighbors.items() if recent(seen)),
                key=lambda item: (-item[1], item[0]),
            )
        ),
        gateway_check=checks[-1] if checks else None,
    )
