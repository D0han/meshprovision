"""A region's traffic as compact hourly buckets: what the views need, never the raw rows. Pure.

A day of a busy region's raw packets is about 25 MB; the views need only
these counts per UTC hour (:class:`Traffic`), about 35 kB an hour. Each
packet belongs to the hour of its first reception, with all its
receptions. Keys are canonical hex node ids, and relay bytes (``1..255``).

- ``packets`` -- packets per origin;
- ``relayed`` -- per relay byte and gateway, the receptions another node
  transmitted last (:attr:`RawReception.is_relayed
  <meshprovision.network.rawpackets.RawReception.is_relayed>`), with
  their SNR/RSSI sums (:class:`Radio`);
- ``direct`` -- per origin and gateway, the strict direct receptions
  (:attr:`~meshprovision.network.rawpackets.RawReception.is_direct`), with
  their SNR/RSSI sums: the radio fingerprint a relay byte is matched
  against;
- ``last_hops`` -- per origin and relay byte, its relayed receptions, and
  how many of them had taken exactly one hop (the relay was the packet's
  first hop) (:class:`LastHop`);
- ``sole_relay`` -- per origin and relay byte, the packets whose every
  reception was relayed by that one byte;
- ``only_gateway`` -- per origin and gateway, the packets only that
  gateway uplinked;
- ``edges`` -- explicit links: consecutive nodes of a traceroute (``t``)
  and a node and each neighbour it reported (``n``);
- ``unrelayed`` -- receptions without a relay byte.

Sums, not medians, so that hours can be added up (:func:`combine`); the
means they give pick the same relay as medians for all but one byte of
the sample day.

**Idempotent merging**, as for a node's health history
(:mod:`meshprovision.health.history`): a refresh asks from the start of
the hour of the previous one, :func:`summarize` gives a bucket to every
hour that answer speaks for (an empty one for a silent hour), and
:func:`merge` *replaces* those hours.

This module imports nothing that reads files or the network (no
``httpx``, ``pathlib``, :mod:`meshprovision.cache` or
:mod:`meshprovision.db`); ``tests/unit/test_import_contracts.py`` holds it
to that.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final, TypeVar

from meshprovision.health.history import FUTURE_SKEW_SECONDS, answered_hours, floor_hour
from meshprovision.network.rawpackets import ParsedRaw, RawReception

__all__ = [
    "EDGE_NEIGHBOR",
    "EDGE_TRACEROUTE",
    "NETWORK_RETENTION_DAYS",
    "NETWORK_RETENTION_SECONDS",
    "LastHop",
    "Radio",
    "RegionHour",
    "Traffic",
    "combine",
    "merge",
    "prune",
    "summarize",
]

_K = TypeVar("_K", int, str, tuple[str, str, str])
_K2 = TypeVar("_K2", int, str)
_V = TypeVar("_V")

NETWORK_RETENTION_DAYS: Final[int] = 30
"""How many days of a region's traffic are kept."""

NETWORK_RETENTION_SECONDS: Final[float] = NETWORK_RETENTION_DAYS * 24 * 3600.0
""":data:`NETWORK_RETENTION_DAYS` in seconds."""

EDGE_TRACEROUTE: Final[str] = "t"
"""The source of an edge seen in a traceroute."""

EDGE_NEIGHBOR: Final[str] = "n"
"""The source of an edge seen in a neighbour report."""


@dataclass(frozen=True, slots=True)
class Radio:
    """Receptions at one gateway, with what is needed for their mean SNR and RSSI.

    Attributes:
        receptions: How many.
        measured: How many of them had both an SNR and an RSSI.
        snr_sum: The sum of those SNRs, dB.
        rssi_sum: The sum of those RSSIs, dBm.
    """

    receptions: int
    measured: int = 0
    snr_sum: float = 0.0
    rssi_sum: int = 0

    @property
    def mean_snr(self) -> float | None:
        """The mean SNR of the measured receptions, or ``None`` when there were none."""
        return self.snr_sum / self.measured if self.measured else None

    @property
    def mean_rssi(self) -> float | None:
        """The mean RSSI of the measured receptions, or ``None`` when there were none."""
        return self.rssi_sum / self.measured if self.measured else None

    def plus(self, other: Radio) -> Radio:
        """Add another gateway count.

        Args:
            other: The other count.

        Returns:
            The sum.
        """
        return Radio(
            self.receptions + other.receptions,
            self.measured + other.measured,
            self.snr_sum + other.snr_sum,
            self.rssi_sum + other.rssi_sum,
        )


@dataclass(frozen=True, slots=True)
class LastHop:
    """An origin's receptions relayed last by one relay byte.

    Attributes:
        receptions: How many.
        first_hop: How many of them had taken exactly one hop.
    """

    receptions: int
    first_hop: int = 0

    def plus(self, other: LastHop) -> LastHop:
        """Add another count.

        Args:
            other: The other count.

        Returns:
            The sum.
        """
        return LastHop(self.receptions + other.receptions, self.first_hop + other.first_hop)


def _empty() -> Mapping[Any, Any]:
    """Return an empty, immutable mapping (a field default)."""
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class Traffic:
    """A region's traffic over one hour or more (see the module docs for each field).

    Attributes:
        packets: Origin -> packets.
        relayed: Relay byte -> gateway -> relayed receptions.
        direct: Origin -> gateway -> strict direct receptions.
        last_hops: Origin -> relay byte -> relayed receptions.
        sole_relay: Origin -> relay byte -> packets relayed only by it.
        only_gateway: Origin -> gateway -> packets uplinked only by it.
        edges: ``(a, b, source)`` with ``a < b`` -> observations.
        unrelayed: Receptions without a relay byte.
    """

    packets: Mapping[str, int] = field(default_factory=_empty)
    relayed: Mapping[int, Mapping[str, Radio]] = field(default_factory=_empty)
    direct: Mapping[str, Mapping[str, Radio]] = field(default_factory=_empty)
    last_hops: Mapping[str, Mapping[int, LastHop]] = field(default_factory=_empty)
    sole_relay: Mapping[str, Mapping[int, int]] = field(default_factory=_empty)
    only_gateway: Mapping[str, Mapping[str, int]] = field(default_factory=_empty)
    edges: Mapping[tuple[str, str, str], int] = field(default_factory=_empty)
    unrelayed: int = 0


@dataclass(frozen=True, slots=True)
class RegionHour:
    """One UTC hour of a region's traffic.

    Attributes:
        hour: The hour's start, epoch seconds.
        traffic: What was heard in it (empty for a silent hour).
    """

    hour: int
    traffic: Traffic = field(default_factory=Traffic)


class _HourBuilder:
    """Collects one hour's counts while a refresh is summarized."""

    def __init__(self) -> None:
        self.packets: Counter[str] = Counter()
        self.relayed: defaultdict[int, dict[str, Radio]] = defaultdict(dict)
        self.direct: defaultdict[str, dict[str, Radio]] = defaultdict(dict)
        self.last_hops: defaultdict[str, dict[int, LastHop]] = defaultdict(dict)
        self.sole_relay: defaultdict[str, Counter[int]] = defaultdict(Counter)
        self.only_gateway: defaultdict[str, Counter[str]] = defaultdict(Counter)
        self.edges: Counter[tuple[str, str, str]] = Counter()
        self.unrelayed = 0

    def add_packet(self, receptions: list[RawReception]) -> None:
        """Count one packet and every reception of it."""
        origin = receptions[0].origin
        self.packets[origin.hex] += 1
        for reception in receptions:
            self._add_reception(reception)
        relays = {r.relay if r.is_relayed else None for r in receptions}
        if len(relays) == 1 and (relay := relays.pop()) is not None:
            self.sole_relay[origin.hex][relay] += 1
        gateways = {r.gateway.hex for r in receptions}
        if len(gateways) == 1:
            self.only_gateway[origin.hex][gateways.pop()] += 1

    def _add_reception(self, reception: RawReception) -> None:
        """Count one reception as relayed, direct, or without a relay byte."""
        origin, gateway = reception.origin.hex, reception.gateway.hex
        radio = _radio(reception)
        if reception.relay is None:
            self.unrelayed += 1
        elif reception.is_relayed:
            cells = self.relayed[reception.relay]
            cells[gateway] = cells[gateway].plus(radio) if gateway in cells else radio
            hops = self.last_hops[origin]
            hop = LastHop(1, int(reception.hops_taken == 1))
            hops[reception.relay] = (
                hops[reception.relay].plus(hop) if reception.relay in hops else hop
            )
        elif reception.is_direct:
            cells = self.direct[origin]
            cells[gateway] = cells[gateway].plus(radio) if gateway in cells else radio

    def add_edge(self, a: str, b: str, source: str) -> None:
        """Count one explicit link (in either direction)."""
        if a != b:
            low, high = sorted((a, b))
            self.edges[(low, high, source)] += 1

    def freeze(self) -> Traffic:
        """Return the counts as an immutable :class:`Traffic`."""
        return Traffic(
            packets=_frozen(self.packets),
            relayed=_frozen_nested(self.relayed),
            direct=_frozen_nested(self.direct),
            last_hops=_frozen_nested(self.last_hops),
            sole_relay=_frozen_nested(self.sole_relay),
            only_gateway=_frozen_nested(self.only_gateway),
            edges=_frozen(self.edges),
            unrelayed=self.unrelayed,
        )


def _radio(reception: RawReception) -> Radio:
    """Return one reception as a :class:`Radio` count."""
    if reception.snr is None or reception.rssi is None:
        return Radio(1)
    return Radio(1, 1, reception.snr, reception.rssi)


def _frozen(counts: Mapping[_K, _V]) -> Mapping[_K, _V]:
    """Freeze a mapping, sorted by key."""
    return MappingProxyType(dict(sorted(counts.items())))


def _frozen_nested(counts: Mapping[_K, Mapping[_K2, _V]]) -> Mapping[_K, Mapping[_K2, _V]]:
    """Freeze a mapping of mappings, sorted by key."""
    return MappingProxyType({key: _frozen(inner) for key, inner in sorted(counts.items())})


def summarize(parsed: ParsedRaw, *, since: int | None, fetched_at: float) -> tuple[RegionHour, ...]:
    """Build the hours one refresh contributes.

    A packet whose first reception is before ``since`` is left out with
    all its receptions (its hour is already complete), as is a route or
    neighbour report heard before it. Every hour the answer speaks for
    gets a bucket (see :func:`~meshprovision.health.history.answered_hours`),
    an empty one when nothing was heard.

    Args:
        parsed: The refresh's parsed rows.
        since: The start of the hour this refresh asked from, or ``None``
            when it asked for everything.
        fetched_at: When lorastats was asked, epoch seconds.

    Returns:
        One bucket per hour, oldest first.
    """
    start = float("-inf") if since is None else since
    builders: defaultdict[int, _HourBuilder] = defaultdict(_HourBuilder)
    by_packet: defaultdict[tuple[int, int], list[RawReception]] = defaultdict(list)
    for reception in parsed.receptions:
        by_packet[(reception.origin.num, reception.packet_id)].append(reception)
    for receptions in by_packet.values():
        first = min(r.time for r in receptions)
        if first >= start:
            builders[floor_hour(first)].add_packet(receptions)
    for route in parsed.routes:
        if route.time >= start:
            for a, b in zip(route.path, route.path[1:], strict=False):
                builders[floor_hour(route.time)].add_edge(a.hex, b.hex, EDGE_TRACEROUTE)
    for report in parsed.neighbors:
        if report.time >= start:
            for neighbor in report.neighbors:
                builders[floor_hour(report.time)].add_edge(
                    report.node.hex, neighbor.hex, EDGE_NEIGHBOR
                )
    oldest = min((r.time for r in parsed.receptions), default=None)
    hours = {hour: builder.freeze() for hour, builder in builders.items()}
    for hour in answered_hours(oldest, since=since, fetched_at=fetched_at):
        hours.setdefault(hour, Traffic())
    return tuple(RegionHour(hour, hours[hour]) for hour in sorted(hours))


def merge(old: Iterable[RegionHour], new: Iterable[RegionHour]) -> tuple[RegionHour, ...]:
    """Merge a refresh's hours into the stored ones: each new hour replaces the stored one.

    Merging the same refresh twice gives the same result as merging it once.

    Args:
        old: The stored hours.
        new: The refresh's hours (from :func:`summarize`).

    Returns:
        Every hour, oldest first.
    """
    hours = {bucket.hour: bucket for bucket in old}
    hours.update((bucket.hour, bucket) for bucket in new)
    return tuple(hours[hour] for hour in sorted(hours))


def prune(hours: Iterable[RegionHour], *, now: float) -> tuple[RegionHour, ...]:
    """Keep the hours within the retention, dropping any in the future.

    Args:
        hours: The hours.
        now: The current time, epoch seconds.

    Returns:
        The hours from that of ``now -`` :data:`NETWORK_RETENTION_SECONDS`
        up to that of ``now +`` the future skew, in their order.
    """
    oldest = floor_hour(now - NETWORK_RETENTION_SECONDS)
    newest = floor_hour(now + FUTURE_SKEW_SECONDS)
    return tuple(bucket for bucket in hours if oldest <= bucket.hour <= newest)


def combine(hours: Iterable[RegionHour]) -> Traffic:
    """Add up the traffic of several hours.

    Args:
        hours: The hours.

    Returns:
        Their summed traffic.
    """
    traffics = [bucket.traffic for bucket in hours]
    return Traffic(
        packets=_sum([t.packets for t in traffics], _add_int),
        relayed=_sum_nested([t.relayed for t in traffics], Radio.plus),
        direct=_sum_nested([t.direct for t in traffics], Radio.plus),
        last_hops=_sum_nested([t.last_hops for t in traffics], LastHop.plus),
        sole_relay=_sum_nested([t.sole_relay for t in traffics], _add_int),
        only_gateway=_sum_nested([t.only_gateway for t in traffics], _add_int),
        edges=_sum([t.edges for t in traffics], _add_int),
        unrelayed=sum(t.unrelayed for t in traffics),
    )


def _add_int(first: int, second: int) -> int:
    return first + second


def _sum(maps: Iterable[Mapping[_K, _V]], add: Callable[[_V, _V], _V]) -> Mapping[_K, _V]:
    """Add up mappings key by key."""
    total: dict[_K, _V] = {}
    for counts in maps:
        for key, value in counts.items():
            total[key] = add(total[key], value) if key in total else value
    return _frozen(total)


def _sum_nested(
    maps: Iterable[Mapping[_K, Mapping[_K2, _V]]], add: Callable[[_V, _V], _V]
) -> Mapping[_K, Mapping[_K2, _V]]:
    """Add up mappings of mappings key by key."""
    inner: defaultdict[_K, list[Mapping[_K2, _V]]] = defaultdict(list)
    for counts in maps:
        for key, value in counts.items():
            inner[key].append(value)
    return MappingProxyType({key: _sum(inner[key], add) for key in sorted(inner)})
