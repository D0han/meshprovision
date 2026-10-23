"""Metric trend arrows in ``mesh status`` and the hidden default columns."""

from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from meshprovision.health.history import TelemetryPoint
from meshprovision.health.store import HISTORY_DIRNAME, HistoryStore
from meshprovision.nodeid import NodeId
from meshprovision.status import render
from meshprovision.status.merge import MergedNode
from meshprovision.status.trend import (
    BASELINE_WINDOW_SECONDS,
    NodeTrends,
    Trend,
    load_trends,
    metric_trend,
    node_trends,
)
from tests.unit.test_status_detail import _A, _NOW, _cells, _headers, _report

pytestmark = pytest.mark.unit

_HOUR = 3600.0


def test_a_rising_value_is_up() -> None:
    assert metric_trend([(0, 50), (_HOUR, 60)], epsilon=2) is Trend.UP


def test_a_falling_value_is_down() -> None:
    assert metric_trend([(_HOUR, 40), (0, 50)], epsilon=2) is Trend.DOWN


def test_a_change_below_epsilon_is_flat_and_at_epsilon_is_not() -> None:
    assert metric_trend([(0, 50), (_HOUR, 51.9)], epsilon=2) is Trend.FLAT
    assert metric_trend([(0, 50), (_HOUR, 52)], epsilon=2) is Trend.UP


def test_the_baseline_is_the_median_of_the_earlier_readings() -> None:
    series = [(0, 10), (_HOUR, 80), (2 * _HOUR, 82), (3 * _HOUR, 81)]

    assert metric_trend(series, epsilon=2) is Trend.FLAT


def test_a_single_reading_has_no_trend() -> None:
    assert metric_trend([(0, 50)], epsilon=2) is None
    assert metric_trend([], epsilon=2) is None


def test_readings_older_than_the_window_are_no_baseline() -> None:
    assert metric_trend([(0, 50), (BASELINE_WINDOW_SECONDS + 1, 90)], epsilon=2) is None
    assert metric_trend([(0, 50), (BASELINE_WINDOW_SECONDS, 90)], epsilon=2) is Trend.UP


def test_node_trends_ignore_external_power_and_empty_batteries() -> None:
    points = [
        TelemetryPoint(time=0, battery=101, voltage=4.1, channel_utilization=5.0, air_util_tx=1.0),
        TelemetryPoint(
            time=_HOUR, battery=101, voltage=3.9, channel_utilization=9.0, air_util_tx=1.1
        ),
        TelemetryPoint(time=2 * _HOUR, battery=0, voltage=0.0),
    ]

    trends = node_trends(points)

    assert trends == NodeTrends(
        battery=None, voltage=Trend.DOWN, channel_utilization=Trend.UP, air_util_tx=Trend.FLAT
    )


def test_load_trends_reads_the_history_files_and_tolerates_none(tmp_path: Path) -> None:
    now = time.time()
    store = HistoryStore(tmp_path / HISTORY_DIRNAME)
    points = (
        TelemetryPoint(time=now - _HOUR, battery=80),
        TelemetryPoint(time=now - 60, battery=70),
    )
    store.update(_A, lambda history: replace(history, telemetry=points))
    other = NodeId.from_hex("979ed146")

    trends = load_trends(tmp_path, [_A, other])

    assert trends[_A].battery is Trend.DOWN
    assert trends[other] == NodeTrends()


def _node() -> MergedNode:
    return MergedNode(
        node_id=_A,
        battery_level=50,
        voltage=3.8,
        channel_utilization=10.0,
        air_util_tx=1.0,
        last_device_metrics=_NOW,
    )


def test_arrows_follow_the_readings_with_the_stated_colours() -> None:
    trends = {
        _A: NodeTrends(
            battery=Trend.UP,
            voltage=Trend.DOWN,
            channel_utilization=Trend.FLAT,
            air_util_tx=None,
        )
    }

    table = render.build_table(_report(_node()), trends=trends)

    cells: dict[str, Any] = {str(column.header): column._cells[0] for column in table.columns}
    assert str(cells["Batt"]).endswith("↑")
    assert str(cells["Volt"]).endswith("↓")
    assert str(cells["ChUtil"]).endswith("~")
    assert not str(cells["AirTx"]).endswith(("↑", "↓", "~"))
    styles = {
        header: [span.style for span in cells[header].spans][-1]
        for header in ("Batt", "Volt", "ChUtil")
    }
    assert styles == {"Batt": "green", "Volt": "red", "ChUtil": "yellow"}


def test_an_unknown_reading_gets_no_arrow() -> None:
    node = MergedNode(node_id=_A)
    trends = {_A: NodeTrends(battery=Trend.UP, voltage=Trend.UP)}

    table = render.build_table(_report(node), trends=trends)

    assert {str(column._cells[0]) for column in table.columns if column.header == "Batt"} == {"-"}


def test_hidden_columns_are_dropped_and_the_rest_keep_their_order() -> None:
    full = _headers(render.build_table(_report(_node())))
    table = render.build_table(_report(_node()), hidden=render.DEFAULT_HIDDEN_COLUMNS)

    assert _headers(table) == [h for h in full if h not in {"Node", "Mgmt"}]
    assert len(_cells(table, 0)) == len(full) - 2


def test_hidden_applies_on_top_of_brief() -> None:
    table = render.build_table(_report(_node()), brief=True, hidden=frozenset({"Node"}))

    assert "Node" not in _headers(table)
    assert "Short" in _headers(table)
