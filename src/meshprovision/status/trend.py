"""How a node's device metrics have changed, from its local health history.

Pure functions plus one read-only loader. ``mesh status`` draws the result as
an arrow after the ``Batt``/``Volt``/``ChUtil``/``AirTx`` readings: the newest
telemetry value is compared with the median of the values reported in the
:data:`BASELINE_WINDOW_SECONDS` before it or, when there are none, with the
previous reading if no reading was probably missed in between. Nothing here
writes the history.
"""

from __future__ import annotations

import statistics
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from itertools import pairwise
from typing import TYPE_CHECKING, Final

from meshprovision.health.history import TelemetryPoint
from meshprovision.health.store import HISTORY_DIRNAME, HistoryStore

if TYPE_CHECKING:
    from datetime import timedelta
    from pathlib import Path

    from meshprovision.nodeid import NodeId

__all__ = [
    "BASELINE_WINDOW_SECONDS",
    "MISSED_READING_FACTOR",
    "Change",
    "NodeTrends",
    "Trend",
    "load_trends",
    "metric_trend",
    "node_trends",
]


class Change(StrEnum):
    """The direction a metric moved."""

    UP = "up"
    DOWN = "down"
    FLAT = "flat"


@dataclass(frozen=True, slots=True)
class Trend:
    """How a metric moved and whether that is good for the node.

    Attributes:
        change: The direction it moved.
        good: ``True`` when the move is an improvement, ``False`` when it is
            a deterioration, ``None`` when it did not move.
    """

    change: Change
    good: bool | None = None


BASELINE_WINDOW_SECONDS: Final[float] = 6 * 3600.0
"""How far before the newest reading the baseline readings may lie."""

MISSED_READING_FACTOR: Final[float] = 1.5
"""How many typical gaps the previous reading may be away and still be the
reading just before the newest one (above that, a reading was probably missed
and the old value says little about what changed)."""

BATTERY_EPSILON: Final[float] = 2.0
"""Battery percentage points below which the level counts as unchanged."""

VOLTAGE_EPSILON: Final[float] = 0.05
"""Volts below which the voltage counts as unchanged."""

UTILIZATION_EPSILON: Final[float] = 1.0
"""Percentage points below which channel utilization counts as unchanged."""

AIR_UTIL_TX_EPSILON: Final[float] = 0.5
"""Percentage points below which transmit air utilization counts as unchanged."""

_EXTERNAL_POWER: Final[int] = 101
"""The battery level a node on external power reports (no discharge to follow)."""


@dataclass(frozen=True, slots=True)
class NodeTrends:
    """One node's metric trends; ``None`` where there is no baseline to compare.

    Attributes:
        battery: The battery level trend.
        voltage: The battery voltage trend.
        channel_utilization: The channel utilization trend.
        air_util_tx: The transmit air utilization trend.
    """

    battery: Trend | None = None
    voltage: Trend | None = None
    channel_utilization: Trend | None = None
    air_util_tx: Trend | None = None


def metric_trend(
    series: Iterable[tuple[float, float]],
    *,
    epsilon: float,
    higher_is_better: bool,
    expected_gap: float | None = None,
    window: float = BASELINE_WINDOW_SECONDS,
) -> Trend | None:
    """Compare the newest reading of a series with the ones before it.

    The baseline is the median of the earlier readings within ``window`` of
    the newest one. With none there, it is the previous reading, but only when
    it is at most :data:`MISSED_READING_FACTOR` typical gaps away -- the median
    gap between the earlier readings, else ``expected_gap`` -- so that no
    reading was probably missed in between.

    Args:
        series: ``(time, value)`` readings, in any order.
        epsilon: A change smaller than this (exclusive) is ``FLAT``.
        higher_is_better: Whether a rising value is an improvement.
        expected_gap: How often the node is expected to report, seconds, when
            the series itself is too short to tell.
        window: How far before the newest reading the baseline may reach.

    Returns:
        The trend of the newest value against the baseline; ``None`` when
        there is no usable baseline.
    """
    ordered = sorted(series)
    if len(ordered) < 2:
        return None
    newest_time, newest = ordered[-1]
    earlier = ordered[:-1]
    baseline = [value for time, value in earlier if newest_time - window <= time < newest_time]
    if not baseline:
        previous_time, previous = earlier[-1]
        if not _is_adjacent(newest_time - previous_time, [t for t, _ in earlier], expected_gap):
            return None
        baseline = [previous]
    change = newest - statistics.median(baseline)
    if abs(change) < epsilon:
        return Trend(Change.FLAT)
    rising = change > 0
    return Trend(Change.UP if rising else Change.DOWN, good=rising == higher_is_better)


def _is_adjacent(gap: float, earlier_times: Sequence[float], expected_gap: float | None) -> bool:
    """Tell whether no reading was probably missed within ``gap``."""
    gaps = [later - sooner for sooner, later in pairwise(earlier_times)]
    typical = statistics.median(gaps) if gaps else expected_gap
    return typical is not None and 0 < gap <= MISSED_READING_FACTOR * typical


def node_trends(points: Sequence[TelemetryPoint], expected_gap: float | None = None) -> NodeTrends:
    """Work out all four trends of a node from its telemetry points.

    Args:
        points: The node's device-metrics points.
        expected_gap: How often the node is expected to report, seconds.

    Returns:
        The trends; a battery of 0 or less is no reading and 101 (external
        power) says nothing about a discharge, so neither is compared.
    """
    battery = [
        (p.time, float(p.battery))
        for p in points
        if p.battery is not None and 0 < p.battery < _EXTERNAL_POWER
    ]
    voltage = [(p.time, p.voltage) for p in points if p.voltage is not None and p.voltage > 0]
    channel = [(p.time, p.channel_utilization) for p in points if p.channel_utilization is not None]
    air = [(p.time, p.air_util_tx) for p in points if p.air_util_tx is not None]
    return NodeTrends(
        battery=metric_trend(
            battery, epsilon=BATTERY_EPSILON, higher_is_better=True, expected_gap=expected_gap
        ),
        voltage=metric_trend(
            voltage, epsilon=VOLTAGE_EPSILON, higher_is_better=True, expected_gap=expected_gap
        ),
        channel_utilization=metric_trend(
            channel, epsilon=UTILIZATION_EPSILON, higher_is_better=False, expected_gap=expected_gap
        ),
        air_util_tx=metric_trend(
            air, epsilon=AIR_UTIL_TX_EPSILON, higher_is_better=False, expected_gap=expected_gap
        ),
    )


def load_trends(
    cache_dir: Path, expected_intervals: Mapping[NodeId, timedelta]
) -> dict[NodeId, NodeTrends]:
    """Read each node's trends from its health history file. Reads only.

    Args:
        cache_dir: The cache directory (the histories are in its ``health/``).
        expected_intervals: The nodes, each with its expected interval.

    Returns:
        The trends of every node; a missing or unreadable file is no history.
    """
    store = HistoryStore(cache_dir / HISTORY_DIRNAME)
    return {
        node_id: node_trends(store.load(node_id).telemetry, interval.total_seconds())
        for node_id, interval in expected_intervals.items()
    }
