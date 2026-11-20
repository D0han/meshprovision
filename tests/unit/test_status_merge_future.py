"""merge_observations ignores a source's times that lie ahead of the clock (a wrong clock)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from meshprovision.datasources.base import SOURCE_LORANET, SOURCE_LORASTATS
from meshprovision.datasources.models import NodeObservation
from meshprovision.nodeid import NodeId
from meshprovision.status.merge import Availability, merge_observations

pytestmark = pytest.mark.unit

NID = NodeId.from_hex("deadbe01")
NOW = datetime(2026, 8, 25, 12, 0, 0, tzinfo=UTC)


def _obs(source: str, **kwargs) -> NodeObservation:  # noqa: ANN003
    return NodeObservation(node_id=NID, source=source, observed_at=NOW, **kwargs)


def test_a_device_metrics_time_in_the_future_is_dropped_but_its_telemetry_kept() -> None:
    ahead = _obs(SOURCE_LORANET, battery_level=95, last_device_metrics=NOW + timedelta(days=1))
    older = _obs(SOURCE_LORASTATS, last_device_metrics=NOW - timedelta(hours=2))

    alone = merge_observations(NID, [ahead], now=NOW)
    both = merge_observations(NID, [ahead, older], now=NOW)

    assert (alone.battery_level, alone.last_device_metrics) == (95, None)
    assert (both.battery_level, both.last_device_metrics) == (95, older.last_device_metrics)


def test_a_device_metrics_time_up_to_5_minutes_ahead_still_counts() -> None:
    skewed = _obs(SOURCE_LORANET, battery_level=95, last_device_metrics=NOW + timedelta(minutes=5))

    merged = merge_observations(NID, [skewed], now=NOW)

    assert merged.last_device_metrics == skewed.last_device_metrics


def test_a_last_seen_more_than_5_minutes_ahead_is_ignored() -> None:
    """The 5 minutes docs/commands.md states, to the second (a 6-minute skew went unnoticed)."""
    skewed = _obs(SOURCE_LORANET, last_seen=NOW + timedelta(minutes=5, seconds=1))

    merged = merge_observations(NID, [skewed], now=NOW)

    assert (merged.last_seen, merged.availability) == (None, Availability.UNKNOWN)
