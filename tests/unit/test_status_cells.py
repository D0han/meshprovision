"""Tests for the per-cell coloring and the Metrics / Seen By / Uptime columns of ``mesh status``."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from rich.text import Text

from meshprovision.datasources.base import SOURCE_LORANET, SOURCE_LORASTATS
from meshprovision.datasources.models import NodeObservation
from meshprovision.nodeid import NodeId
from meshprovision.status import render
from meshprovision.status.merge import (
    SEEN_BY_WINDOWS,
    Availability,
    MergedNode,
    Thresholds,
    merge_observations,
)
from meshprovision.status.report import StatusReport

pytestmark = pytest.mark.unit

NID = NodeId.from_hex("deadbe01")
NOW = datetime(2026, 8, 25, 12, 0, 0, tzinfo=UTC)
SEEN_BY = "Seen By\n1d/7d/30d"


def _obs(source: str, **kwargs) -> NodeObservation:  # noqa: ANN003
    return NodeObservation(node_id=NID, source=source, observed_at=NOW, **kwargs)


def _cells(node: MergedNode) -> dict[str, Text]:
    report = StatusReport(generated_at=NOW, nodes=(node,), thresholds=Thresholds())
    table = render.build_table(report)
    cells = {str(column.header): next(iter(column.cells)) for column in table.columns}
    return {
        header: Text(cell) if isinstance(cell, str) else cell  # type: ignore[misc]
        for header, cell in cells.items()
    }


def _node(**kwargs) -> MergedNode:  # noqa: ANN003
    return MergedNode(node_id=NID, availability=Availability.ONLINE, **kwargs)


# ---------------------------------------------------------------------------
# merge: seen_by_counts, last_boot, last_device_metrics
# ---------------------------------------------------------------------------


def _seen(*ages: timedelta) -> dict[str, object]:
    return {
        "neighbor_count": len(ages),
        "seen_by_times": tuple(NOW - age for age in ages),
    }


def test_seen_by_windows_are_one_seven_and_thirty_days() -> None:
    assert (timedelta(days=1), timedelta(days=7), timedelta(days=30)) == SEEN_BY_WINDOWS


def test_seen_by_counts_use_inclusive_windows_against_now() -> None:
    ages = (
        timedelta(hours=1),
        timedelta(days=1),
        timedelta(days=1, seconds=1),
        timedelta(days=7),
        timedelta(days=7, seconds=1),
        timedelta(days=30),
        timedelta(days=30, seconds=1),
        timedelta(days=90),
    )
    obs = _obs(SOURCE_LORANET, **_seen(*ages))

    merged = merge_observations(NID, [obs], now=NOW)

    assert merged.seen_by_counts == (2, 4, 6)
    assert merged.neighbor_count == 8


def test_seen_by_counts_count_a_future_relay_in_every_window() -> None:
    obs = _obs(SOURCE_LORANET, **_seen(-timedelta(minutes=5)))

    assert merge_observations(NID, [obs], now=NOW).seen_by_counts == (1, 1, 1)


def test_seen_by_counts_are_zeroes_for_an_empty_seen_by_and_none_when_unreported() -> None:
    reported_empty = _obs(SOURCE_LORANET, **_seen())
    unreported = _obs(SOURCE_LORANET, battery_level=50)

    assert merge_observations(NID, [reported_empty], now=NOW).seen_by_counts == (0, 0, 0)
    assert merge_observations(NID, [unreported], now=NOW).seen_by_counts is None


def test_seen_by_counts_skip_a_source_that_reported_no_seen_by() -> None:
    lorastats = _obs(SOURCE_LORASTATS, last_seen=NOW)
    loranet = _obs(SOURCE_LORANET, **_seen(timedelta(hours=2)))

    merged = merge_observations(NID, [lorastats, loranet], now=NOW)

    assert merged.seen_by_counts == (1, 1, 1)


def test_last_boot_is_the_newest_any_source_reports() -> None:
    older = _obs(SOURCE_LORANET, last_boot=NOW - timedelta(days=3))
    newer = _obs(SOURCE_LORASTATS, last_boot=NOW - timedelta(days=1))

    assert merge_observations(NID, [older, newer], now=NOW).last_boot == NOW - timedelta(days=1)
    assert merge_observations(NID, [_obs(SOURCE_LORANET)], now=NOW).last_boot is None


def test_last_device_metrics_prefers_loranet_and_falls_back_to_lorastats() -> None:
    loranet = _obs(SOURCE_LORANET, last_device_metrics=NOW - timedelta(hours=1))
    lorastats = _obs(SOURCE_LORASTATS, last_device_metrics=NOW - timedelta(hours=9))

    both = merge_observations(NID, [lorastats, loranet], now=NOW)
    only_fallback = merge_observations(NID, [lorastats], now=NOW)

    assert both.last_device_metrics == NOW - timedelta(hours=1)
    assert only_fallback.last_device_metrics == NOW - timedelta(hours=9)


def test_telemetry_and_its_timestamp_follow_priority_when_the_fallback_was_seen_later() -> None:
    """The readings and their Metrics timestamp must all come from one source.

    The test above sets no last_seen, so priority and recency order
    coincide there; here the lower-priority lorastats was seen later.
    """
    loranet = _obs(
        SOURCE_LORANET,
        last_seen=NOW - timedelta(hours=3),
        last_device_metrics=NOW - timedelta(hours=3),
        uptime_seconds=100,
        **_seen(timedelta(hours=3)),
    )
    lorastats = _obs(
        SOURCE_LORASTATS,
        last_seen=NOW - timedelta(minutes=1),
        last_device_metrics=NOW - timedelta(days=5),
        uptime_seconds=999,
        **_seen(),
    )

    merged = merge_observations(NID, [lorastats, loranet], now=NOW)

    assert merged.last_device_metrics == NOW - timedelta(hours=3)
    assert merged.uptime_seconds == 100
    assert merged.neighbor_count == 1
    assert merged.seen_by_counts == (1, 1, 1)


def test_json_carries_the_new_fields_in_utc() -> None:
    obs = _obs(
        SOURCE_LORANET,
        **_seen(timedelta(hours=1), timedelta(days=3)),
        last_boot=datetime(2026, 8, 20, 6, 0, 0, tzinfo=UTC),
        last_device_metrics=datetime(2026, 8, 25, 10, 0, 0, tzinfo=UTC),
    )

    payload = merge_observations(NID, [obs], now=NOW).to_json_dict()

    assert payload["seen_by_counts"] == {"day": 1, "week": 2, "month": 2}
    assert payload["last_boot"] == "2026-08-20T06:00:00Z"
    assert payload["last_device_metrics"] == "2026-08-25T10:00:00Z"
    assert payload["neighbor_count"] == 2


def test_json_new_fields_are_null_when_unknown() -> None:
    payload = merge_observations(NID, [_obs(SOURCE_LORANET)], now=NOW).to_json_dict()

    assert payload["seen_by_counts"] is None
    assert payload["last_boot"] is None
    assert payload["last_device_metrics"] is None


# ---------------------------------------------------------------------------
# duration text
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("duration", "expected"),
    [
        (timedelta(seconds=59), "<1m"),
        (timedelta(minutes=1), "1m"),
        (timedelta(minutes=59, seconds=59), "59m"),
        (timedelta(hours=1), "1h 0m"),
        (timedelta(hours=5, minutes=12, seconds=40), "5h 12m"),
        (timedelta(hours=23, minutes=59), "23h 59m"),
        (timedelta(days=1), "1d 0h"),
        (timedelta(days=116, hours=14, minutes=30), "116d 14h"),
        (timedelta(seconds=-30), "<1m"),
    ],
)
def test_duration_text_shows_the_two_most_significant_units(
    duration: timedelta, expected: str
) -> None:
    assert render._duration_text(duration) == expected


# ---------------------------------------------------------------------------
# Uptime cell
# ---------------------------------------------------------------------------


def test_uptime_is_the_time_since_the_last_boot() -> None:
    cell = render._uptime_cell(_node(last_boot=NOW - timedelta(days=2, hours=5)), NOW)

    assert (cell.plain, cell.style) == ("2d 5h", "")


def test_uptime_never_falls_back_to_the_uptime_a_device_reported_with_its_metrics() -> None:
    node = _node(uptime_seconds=3600 * 30, last_device_metrics=NOW - timedelta(hours=3))

    cell = render._uptime_cell(node, NOW)

    assert (cell.plain, cell.style) == ("-", "grey50")


def test_uptime_is_a_gray_dash_when_nothing_is_known() -> None:
    cell = render._uptime_cell(_node(), NOW)

    assert (cell.plain, cell.style) == ("-", "grey50")


@pytest.mark.parametrize(
    ("uptime", "style"),
    [
        (timedelta(minutes=59, seconds=59), "bold dark_orange"),
        (timedelta(hours=1), ""),
    ],
    ids=["just-under-an-hour", "an-hour"],
)
def test_uptime_under_an_hour_is_a_warning(uptime: timedelta, style: str) -> None:
    cell = render._uptime_cell(_node(last_boot=NOW - uptime), NOW)

    assert cell.style == style


def test_uptime_of_an_offline_node_stops_at_last_seen_and_is_gray() -> None:
    node = MergedNode(
        node_id=NID,
        availability=Availability.OFFLINE,
        last_seen=NOW - timedelta(days=30),
        last_boot=NOW - timedelta(days=40),
    )

    cell = render._uptime_cell(node, NOW)

    assert (cell.plain, cell.style) == ("10d 0h", "grey50")


def test_a_recent_boot_of_a_stale_node_is_gray_not_a_warning() -> None:
    node = MergedNode(
        node_id=NID,
        availability=Availability.STALE,
        last_seen=NOW - timedelta(hours=3),
        last_boot=NOW - timedelta(hours=3, minutes=30),
    )

    cell = render._uptime_cell(node, NOW)

    assert (cell.plain, cell.style) == ("30m", "grey50")


def test_uptime_of_a_node_not_online_without_last_seen_runs_to_now_in_gray() -> None:
    node = MergedNode(
        node_id=NID, availability=Availability.UNKNOWN, last_boot=NOW - timedelta(days=2)
    )

    cell = render._uptime_cell(node, NOW)

    assert (cell.plain, cell.style) == ("2d 0h", "grey50")


def test_the_uptime_column_of_an_offline_node_stops_at_last_seen() -> None:
    node = MergedNode(
        node_id=NID,
        availability=Availability.OFFLINE,
        last_seen=NOW - timedelta(days=30),
        last_boot=NOW - timedelta(days=40),
    )

    cell = _cells(node)["Uptime"]

    assert (cell.plain, cell.style) == ("10d 0h", "grey50")


def test_uptime_is_a_gray_dash_when_the_metrics_show_a_reboot_after_last_boot() -> None:
    node = _node(
        last_boot=NOW - timedelta(days=10),
        uptime_seconds=600,
        last_device_metrics=NOW - timedelta(minutes=5),
    )

    cell = render._uptime_cell(node, NOW)

    assert (cell.plain, cell.style) == ("-", "grey50")


def test_a_contradicted_last_boot_is_a_dash_for_an_offline_node_too() -> None:
    node = MergedNode(
        node_id=NID,
        availability=Availability.OFFLINE,
        last_seen=NOW - timedelta(days=1),
        last_boot=NOW - timedelta(days=10),
        uptime_seconds=600,
        last_device_metrics=NOW - timedelta(days=1),
    )

    cell = render._uptime_cell(node, NOW)

    assert (cell.plain, cell.style) == ("-", "grey50")


@pytest.mark.parametrize(
    ("excess", "text"),
    [
        (timedelta(minutes=64), "10d 0h"),
        (timedelta(minutes=65), "10d 0h"),
        (timedelta(minutes=65, seconds=1), "-"),
    ],
    ids=["within-tolerance", "exactly-the-tolerance", "just-over"],
)
def test_last_boot_is_contradicted_only_beyond_65_minutes(excess: timedelta, text: str) -> None:
    metrics_at = NOW - timedelta(minutes=5)
    since_boot = metrics_at - (NOW - timedelta(days=10))
    node = _node(
        last_boot=NOW - timedelta(days=10),
        uptime_seconds=int((since_boot - excess).total_seconds()),
        last_device_metrics=metrics_at,
    )

    assert render._uptime_cell(node, NOW).plain == text


@pytest.mark.parametrize(
    "missing",
    ["uptime_seconds", "last_device_metrics"],
)
def test_last_boot_stands_when_the_metrics_cannot_contradict_it(missing: str) -> None:
    fields: dict[str, object] = {
        "last_boot": NOW - timedelta(days=10),
        "uptime_seconds": 600,
        "last_device_metrics": NOW - timedelta(minutes=5),
    }
    del fields[missing]

    cell = render._uptime_cell(_node(**fields), NOW)

    assert (cell.plain, cell.style) == ("10d 0h", "")


def test_an_uptime_longer_than_the_time_since_last_boot_does_not_contradict_it() -> None:
    node = _node(
        last_boot=NOW - timedelta(days=1),
        uptime_seconds=3600 * 24 * 30,
        last_device_metrics=NOW - timedelta(minutes=5),
    )

    assert render._uptime_cell(node, NOW).plain == "1d 0h"


# ---------------------------------------------------------------------------
# value flags
# ---------------------------------------------------------------------------

ALARM = "bold red"
WARN = "bold dark_orange"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        (-5, None),
        (0, None),
        (1, ALARM),
        (10, ALARM),
        (11, WARN),
        (20, WARN),
        (21, None),
        (100, None),
        (101, None),
    ],
)
def test_battery_flag(value: int | None, expected: str | None) -> None:
    assert render._battery_flag(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        (0.0, None),
        (3.3, ALARM),
        (3.31, WARN),
        (3.5, WARN),
        (3.51, None),
        (12.6, None),
    ],
)
def test_voltage_flag(value: float | None, expected: str | None) -> None:
    assert render._voltage_flag(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, None), (25.0, None), (25.1, WARN), (40.0, WARN), (40.1, ALARM)],
)
def test_channel_utilization_severity(value: float | None, expected: str | None) -> None:
    assert (
        render._severity(
            value,
            alarm=render.CHANNEL_UTILIZATION_ALARM_PERCENT,
            warn=render.CHANNEL_UTILIZATION_WARN_PERCENT,
            low_is_bad=False,
        )
        == expected
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, None), (5.0, None), (5.1, WARN), (10.0, WARN), (10.1, ALARM)],
)
def test_air_util_tx_severity(value: float | None, expected: str | None) -> None:
    assert (
        render._severity(
            value,
            alarm=render.AIR_UTIL_TX_ALARM_PERCENT,
            warn=render.AIR_UTIL_TX_WARN_PERCENT,
            low_is_bad=False,
        )
        == expected
    )


# ---------------------------------------------------------------------------
# table cells
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("age", "style"),
    [
        (timedelta(hours=3), "green"),
        (timedelta(hours=30), "yellow"),
        (timedelta(days=4), "dark_orange"),
        (timedelta(days=9), "red"),
    ],
)
def test_metric_cells_take_the_freshness_color_of_the_metrics_timestamp(
    age: timedelta, style: str
) -> None:
    node = _node(
        battery_level=80,
        voltage=4.0,
        channel_utilization=3.0,
        air_util_tx=1.0,
        last_device_metrics=NOW - age,
    )

    cells = _cells(node)

    for column in ("Metrics", "Batt", "Volt", "ChUtil", "AirTx"):
        assert cells[column].style == style, column


def test_metric_cells_are_gray_when_the_metrics_timestamp_is_unknown() -> None:
    node = _node(battery_level=80, voltage=4.0, channel_utilization=3.0, air_util_tx=1.0)

    cells = _cells(node)

    assert {cells[c].style for c in ("Metrics", "Batt", "Volt", "ChUtil", "AirTx")} == {"grey50"}
    assert cells["Metrics"].plain == "-"


def test_an_alarming_value_overrides_the_freshness_color_of_its_own_cell_only() -> None:
    node = _node(
        battery_level=5,
        voltage=3.0,
        channel_utilization=50.0,
        air_util_tx=6.0,
        last_device_metrics=NOW - timedelta(hours=1),
    )

    cells = _cells(node)

    assert cells["Batt"].style == ALARM
    assert cells["Volt"].style == ALARM
    assert cells["ChUtil"].style == ALARM
    assert cells["AirTx"].style == WARN
    assert cells["Metrics"].style == "green"


@pytest.mark.parametrize("level", [0, -5])
def test_a_battery_level_of_zero_or_less_is_no_reading(level: int) -> None:
    node = _node(battery_level=level, last_device_metrics=NOW - timedelta(hours=1))

    cell = _cells(node)["Batt"]

    assert (cell.plain, cell.style) == ("-", "grey50")


def test_a_one_percent_battery_is_an_alarm() -> None:
    node = _node(battery_level=1, last_device_metrics=NOW - timedelta(hours=1))

    cell = _cells(node)["Batt"]

    assert (cell.plain, cell.style) == ("1%", ALARM)


def test_a_powered_node_is_not_flagged_as_a_low_battery() -> None:
    node = _node(battery_level=101, last_device_metrics=NOW - timedelta(hours=1))

    cell = _cells(node)["Batt"]

    assert (cell.plain, cell.style) == ("powered", "green")


def test_the_metrics_cell_states_how_old_the_readings_are() -> None:
    node = _node(last_device_metrics=NOW - timedelta(hours=5))

    assert _cells(node)["Metrics"].plain == "5 hours ago"


@pytest.mark.parametrize(
    ("availability", "style"),
    [
        (Availability.ONLINE, "green"),
        (Availability.STALE, "yellow"),
        (Availability.OFFLINE, "red"),
        (Availability.UNKNOWN, "grey50"),
    ],
)
def test_the_status_cell_is_colored_by_availability(availability: Availability, style: str) -> None:
    node = MergedNode(node_id=NID, availability=availability)

    assert _cells(node)["Status"].style == style


@pytest.mark.parametrize(
    ("counts", "text", "style"),
    [
        (None, "-", "grey50"),
        ((0, 0, 0), "0/0/0", ALARM),
        ((0, 0, 4), "0/0/4", WARN),
        ((0, 2, 4), "0/2/4", ""),
        ((3, 3, 3), "3/3/3", ""),
    ],
    ids=["unknown", "never", "not-this-week", "quiet-today", "healthy"],
)
def test_seen_by_cell_shows_day_week_month_counts_and_flags_silence(
    counts: tuple[int, int, int] | None, text: str, style: str
) -> None:
    cell = _cells(_node(seen_by_counts=counts))[SEEN_BY]

    assert (cell.plain, cell.style) == (text, style)


def test_the_table_has_no_sources_column_and_no_row_style() -> None:
    node = _node(sources=(SOURCE_LORANET, SOURCE_LORASTATS), last_seen=NOW, age=timedelta(0))
    report = StatusReport(generated_at=NOW, nodes=(node,), thresholds=Thresholds())

    table = render.build_table(report)

    assert "Sources" not in [str(column.header) for column in table.columns]
    assert [row.style for row in table.rows] == [None]
