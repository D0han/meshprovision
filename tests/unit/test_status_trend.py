"""Metric trend arrows in ``mesh status`` and the hidden default columns."""

from __future__ import annotations

import time
from dataclasses import replace
from datetime import timedelta
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
    Change,
    NodeTrends,
    Trend,
    load_trends,
    metric_trend,
    node_trends,
)
from tests.unit.test_status_detail import _A, _NOW, _cells, _headers, _report

pytestmark = pytest.mark.unit

_HOUR = 3600.0


def _trend(series: list[tuple[float, float]], **kwargs: Any) -> Trend | None:
    kwargs.setdefault("higher_is_better", True)
    return metric_trend(series, epsilon=2, **kwargs)


def test_a_rising_value_is_up_and_good_when_higher_is_better() -> None:
    assert _trend([(0, 50), (_HOUR, 60)]) == Trend(Change.UP, good=True)


def test_a_rising_value_is_up_and_bad_when_lower_is_better() -> None:
    assert _trend([(0, 50), (_HOUR, 60)], higher_is_better=False) == Trend(Change.UP, good=False)


def test_a_falling_value_is_down_and_bad_or_good_by_the_same_rule() -> None:
    assert _trend([(0, 50), (_HOUR, 40)]) == Trend(Change.DOWN, good=False)
    assert _trend([(0, 50), (_HOUR, 40)], higher_is_better=False) == Trend(Change.DOWN, good=True)


def test_a_change_below_epsilon_is_flat_and_at_epsilon_is_not() -> None:
    assert _trend([(0, 50), (_HOUR, 51.9)]) == Trend(Change.FLAT, good=None)
    assert _trend([(0, 50), (_HOUR, 52)]) == Trend(Change.UP, good=True)


def test_the_baseline_is_the_median_of_the_last_six_hours() -> None:
    series = [(0, 10), (_HOUR, 80), (2 * _HOUR, 82), (3 * _HOUR, 81)]

    assert _trend(series) == Trend(Change.FLAT)


def test_readings_older_than_the_window_are_not_in_the_median() -> None:
    series = [(0, 10), (7 * _HOUR, 80), (8 * _HOUR, 82), (9 * _HOUR, 81)]

    assert _trend(series) == Trend(Change.FLAT)
    assert _trend([(0, 50), (BASELINE_WINDOW_SECONDS, 90)]) == Trend(Change.UP, good=True)


def test_a_single_reading_has_no_trend() -> None:
    assert _trend([(0, 50)]) is None
    assert _trend([]) is None


def test_the_previous_reading_is_the_baseline_when_none_was_probably_missed() -> None:
    # Readings every 8 h: nothing in the 6 h window, the gap is the usual one.
    series = [(0, 80), (8 * _HOUR, 60), (16 * _HOUR, 60)]

    assert _trend(series) == Trend(Change.FLAT)
    assert _trend([(0, 80), (8 * _HOUR, 70), (16 * _HOUR, 60)]) == Trend(Change.DOWN, good=False)


def test_readings_with_the_same_time_are_no_baseline() -> None:
    assert _trend([(_HOUR, 80), (_HOUR, 60)], expected_gap=_HOUR) is None


def test_the_previous_reading_is_not_used_after_a_probably_missed_one() -> None:
    series = [(0, 80), (8 * _HOUR, 70), (8 * _HOUR + 12.1 * _HOUR, 60)]

    assert _trend(series) is None


def test_the_missed_reading_limit_is_one_and_a_half_typical_gaps() -> None:
    at_limit = [(0, 80), (8 * _HOUR, 70), (20 * _HOUR, 60)]

    assert _trend(at_limit) == Trend(Change.DOWN, good=False)


def test_two_readings_use_the_expected_gap_to_judge_a_missed_one() -> None:
    series = [(0, 80), (8 * _HOUR, 60)]

    assert _trend(series, expected_gap=8 * _HOUR) == Trend(Change.DOWN, good=False)
    assert _trend(series, expected_gap=5 * _HOUR) is None
    assert _trend(series) is None


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
        battery=None,
        voltage=Trend(Change.DOWN, good=False),
        channel_utilization=Trend(Change.UP, good=False),
        air_util_tx=Trend(Change.FLAT),
    )


def test_node_trends_judge_each_metric_by_its_own_good_direction() -> None:
    points = [
        TelemetryPoint(time=0, battery=50, voltage=3.6, channel_utilization=5.0, air_util_tx=1.0),
        TelemetryPoint(
            time=_HOUR, battery=70, voltage=3.9, channel_utilization=2.0, air_util_tx=3.0
        ),
    ]

    assert node_trends(points) == NodeTrends(
        battery=Trend(Change.UP, good=True),
        voltage=Trend(Change.UP, good=True),
        channel_utilization=Trend(Change.DOWN, good=True),
        air_util_tx=Trend(Change.UP, good=False),
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

    trends = load_trends(tmp_path, {_A: timedelta(hours=1), other: timedelta(hours=1)})

    assert trends[_A].battery == Trend(Change.DOWN, good=False)
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


def test_arrows_show_the_direction_and_are_coloured_by_good_and_bad() -> None:
    trends = {
        _A: NodeTrends(
            battery=Trend(Change.UP, good=True),
            voltage=Trend(Change.DOWN, good=False),
            channel_utilization=Trend(Change.DOWN, good=True),
            air_util_tx=Trend(Change.UP, good=False),
        )
    }

    cells = _by_header(render.build_table(_report(_node()), trends=trends))

    assert _arrow(cells["Batt"]) == ("\u2191", "green")
    assert _arrow(cells["Volt"]) == ("\u2193", "red")
    assert _arrow(cells["ChUtil"]) == ("\u2193", "green")
    assert _arrow(cells["AirTx"]) == ("\u2191", "red")


def test_a_flat_reading_gets_a_yellow_tilde_and_no_trend_no_arrow() -> None:
    trends = {_A: NodeTrends(battery=Trend(Change.FLAT))}

    cells = _by_header(render.build_table(_report(_node()), trends=trends))

    assert _arrow(cells["Batt"]) == ("~", "yellow")
    assert not str(cells["Volt"]).endswith(("\u2191", "\u2193", "~"))


def _by_header(table: Any) -> dict[str, Any]:
    return {str(column.header): column._cells[0] for column in table.columns}


def _arrow(cell: Any) -> tuple[str, str]:
    span = cell.spans[-1]
    return cell.plain[span.start : span.end], str(span.style)


def test_an_unknown_reading_gets_no_arrow() -> None:
    node = MergedNode(node_id=_A)
    trends = {_A: NodeTrends(battery=Trend(Change.UP, good=True))}

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
