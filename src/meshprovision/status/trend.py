"""How a node's device metrics have changed, from its local health history.

Pure functions plus one read-only loader. ``mesh status`` draws the result as
an arrow after the ``Batt``/``Volt``/``ChUtil``/``AirTx`` readings: the newest
telemetry value is compared with the median of the values reported in the
:data:`BASELINE_WINDOW` before it. Nothing here writes the history.
"""

from __future__ import annotations

import statistics
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from meshprovision.health.history import TelemetryPoint
from meshprovision.health.store import HISTORY_DIRNAME, HistoryStore

if TYPE_CHECKING:
    from pathlib import Path

    from meshprovision.nodeid import NodeId

__all__ = [
    "BASELINE_WINDOW_SECONDS",
    "NodeTrends",
    "Trend",
    "load_trends",
    "metric_trend",
    "node_trends",
]


class Trend(StrEnum):
    """The direction a metric moved."""

    UP = "up"
    DOWN = "down"
    FLAT = "flat"


BASELINE_WINDOW_SECONDS: Final[float] = 48 * 3600.0
"""How far before the newest reading the baseline readings may lie.

Two days keeps a node that reports every 12 h (four readings) or every 24 h
(one reading) comparable, without comparing against last week's weather."""

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
    """One node's metric trends; ``None`` where there is no history to compare.

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
    window: float = BASELINE_WINDOW_SECONDS,
) -> Trend | None:
    """Compare the newest reading of a series with the ones before it.

    Args:
        series: ``(time, value)`` readings, in any order.
        epsilon: A change smaller than this (exclusive) is ``FLAT``.
        window: How far before the newest reading the baseline may reach.

    Returns:
        The direction of the newest value against the median of the earlier
        readings within ``window``; ``None`` when there is no earlier reading.
    """
    ordered = sorted(series)
    if len(ordered) < 2:
        return None
    newest_time, newest = ordered[-1]
    baseline = [value for time, value in ordered[:-1] if newest_time - window <= time < newest_time]
    if not baseline:
        return None
    change = newest - statistics.median(baseline)
    if abs(change) < epsilon:
        return Trend.FLAT
    return Trend.UP if change > 0 else Trend.DOWN


def node_trends(points: Sequence[TelemetryPoint]) -> NodeTrends:
    """Work out all four trends of a node from its telemetry points.

    Args:
        points: The node's device-metrics points.

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
        battery=metric_trend(battery, epsilon=BATTERY_EPSILON),
        voltage=metric_trend(voltage, epsilon=VOLTAGE_EPSILON),
        channel_utilization=metric_trend(channel, epsilon=UTILIZATION_EPSILON),
        air_util_tx=metric_trend(air, epsilon=AIR_UTIL_TX_EPSILON),
    )


def load_trends(cache_dir: Path, node_ids: Iterable[NodeId]) -> dict[NodeId, NodeTrends]:
    """Read each node's trends from its health history file. Reads only.

    Args:
        cache_dir: The cache directory (the histories are in its ``health/``).
        node_ids: The nodes.

    Returns:
        The trends of every node that has a history; a missing or unreadable
        file is no history.
    """
    store = HistoryStore(cache_dir / HISTORY_DIRNAME)
    return {node_id: node_trends(store.load(node_id).telemetry) for node_id in node_ids}
