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
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from itertools import pairwise
from typing import TYPE_CHECKING, Final

from meshprovision.health.history import TelemetryPoint
from meshprovision.health.store import HISTORY_DIRNAME, HistoryStore

if TYPE_CHECKING:
    from pathlib import Path

    from meshprovision.nodeid import NodeId
    from meshprovision.status.merge import MergedNode

__all__ = [
    "BASELINE_WINDOW_SECONDS",
    "MISSED_READING_FACTOR",
    "SAME_READING_SECONDS",
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

SAME_READING_SECONDS: Final[float] = 120.0
"""How close a history point may be to the shown reading and still be that reading."""

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


def node_trends(node: MergedNode, points: Sequence[TelemetryPoint]) -> NodeTrends:
    """Work out all four trends of a node: its shown readings against its history.

    The readings are the ones the status table shows, taken when the device
    last reported its metrics; the history points that are that reading
    (within :data:`SAME_READING_SECONDS`) or newer are left out of the baseline.

    Args:
        node: The merged node.
        points: The node's device-metrics points from its local history.

    Returns:
        The trends; none for a node whose metrics time is unknown, and none
        for a battery of 0 or less (no reading) or 101 (external power: no
        discharge to follow).
    """
    if node.last_device_metrics is None:
        return NodeTrends()
    time = node.last_device_metrics.timestamp()
    earlier = [p for p in points if p.time < time - SAME_READING_SECONDS]
    gap = node.cadence.interval.total_seconds()

    def trend(
        values: Sequence[tuple[float, float | None]],
        current: float | None,
        epsilon: float,
        *,
        higher_is_better: bool,
    ) -> Trend | None:
        if current is None:
            return None
        series = [(t, v) for t, v in values if v is not None]
        return metric_trend(
            [*series, (time, current)],
            epsilon=epsilon,
            higher_is_better=higher_is_better,
            expected_gap=gap,
        )

    battery = node.battery_level
    return NodeTrends(
        battery=trend(
            [(p.time, _battery_percent(p.battery)) for p in earlier],
            _battery_percent(battery),
            BATTERY_EPSILON,
            higher_is_better=True,
        ),
        voltage=trend(
            [(p.time, p.voltage) for p in earlier],
            node.voltage,
            VOLTAGE_EPSILON,
            higher_is_better=True,
        ),
        channel_utilization=trend(
            [(p.time, p.channel_utilization) for p in earlier],
            node.channel_utilization,
            UTILIZATION_EPSILON,
            higher_is_better=False,
        ),
        air_util_tx=trend(
            [(p.time, p.air_util_tx) for p in earlier],
            node.air_util_tx,
            AIR_UTIL_TX_EPSILON,
            higher_is_better=False,
        ),
    )


def _battery_percent(level: int | None) -> float | None:
    """Return a battery level that can be followed, else ``None`` (none, 0, external power)."""
    return float(level) if level is not None and 0 < level < _EXTERNAL_POWER else None


def load_trends(cache_dir: Path, nodes: Iterable[MergedNode]) -> dict[NodeId, NodeTrends]:
    """Read each node's trends from its health history file. Reads only.

    Args:
        cache_dir: The cache directory (the histories are in its ``health/``).
        nodes: The merged nodes.

    Returns:
        The trends of every node; a missing or unreadable file is no history.
    """
    store = HistoryStore(cache_dir / HISTORY_DIRNAME)
    return {node.node_id: node_trends(node, store.load(node.node_id).telemetry) for node in nodes}
