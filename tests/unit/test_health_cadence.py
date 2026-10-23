"""Health rules relative to each node's expected interval, at their boundaries."""

from __future__ import annotations

import dataclasses
import io
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from rich.console import Console

from meshprovision.cache.http import CachedHTTPClient
from meshprovision.health import render
from meshprovision.health.history import HOUR_SECONDS, HourBucket, NodeHistory
from meshprovision.health.metrics import BatteryTrend, NodeMetrics
from meshprovision.health.refresh import HealthRefresher
from meshprovision.health.report import HealthReport, assess_nodes, assess_status
from meshprovision.health.rules import (
    BATTERY_FRESH_SECONDS,
    REBOOTS_WARN,
    REBOOTS_WINDOW_DAYS,
    SILENCE_RUN_MISSED,
    SILENCE_WARN_HOURS,
    NodeContext,
    Verdict,
    assess,
)
from meshprovision.health.store import HISTORY_DIRNAME, HistoryStore
from meshprovision.nodeid import NodeId
from meshprovision.status.cadence import OFFLINE_MISSED, Cadence, CadenceSource
from meshprovision.status.merge import (
    Availability,
    MergedNode,
    Thresholds,
    node_thresholds,
    with_learned_cadence,
)
from meshprovision.status.report import StatusReport

pytestmark = pytest.mark.unit

_NODE = NodeId.from_hex("ab446357")
_NOW = 1_760_994_000.0
_H = 3600.0
_SIX_HOURLY = NodeContext(
    stale_after=13.5 * _H,
    offline_after=31.5 * _H,
    expected_interval=6 * _H,
    cadence_source="history",
)


def _m(**fields: object) -> NodeMetrics:
    base: dict[str, object] = {
        "node": _NODE,
        "days": 7,
        "window_start": _NOW - 7 * 86400,
        "now": _NOW,
        "covered_hours": 24,
        "last_heard": _NOW - 60,
    }
    base.update(fields)
    return NodeMetrics(**base)  # type: ignore[arg-type]


def _codes(metrics: NodeMetrics, context: NodeContext) -> dict[str, Verdict]:
    return {finding.code: finding.severity for finding in assess(metrics, context)[1]}


def test_the_constants_are_the_documented_ones() -> None:
    assert (SILENCE_RUN_MISSED, REBOOTS_WARN, REBOOTS_WINDOW_DAYS) == (OFFLINE_MISSED, 3, 7)


# ---------------------------------------------------------------------------
# Not heard: the node's own thresholds.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("age", "expected"),
    [
        (13.5 * _H, None),
        (13.5 * _H + 1, Verdict.WARN),
        (31.5 * _H, Verdict.WARN),
        (31.5 * _H + 1, Verdict.CRIT),
    ],
)
def test_silence_is_judged_against_the_node_thresholds(
    age: float, expected: Verdict | None
) -> None:
    codes = _codes(_m(last_heard=_NOW - age), _SIX_HOURLY)
    assert codes.get("silent") is expected


def test_a_silence_finding_names_the_expected_interval() -> None:
    _, findings = assess(_m(last_heard=_NOW - 20 * _H), _SIX_HOURLY)
    assert findings[0].text == "not heard for 20 h (expected every 6 h, learned from its history)"


@pytest.mark.parametrize(
    ("source", "suffix"),
    [
        ("override", " (expected every 3.5 h, as given)"),
        ("template", " (expected every 3.5 h, from the template)"),
        ("role", " (expected every 3.5 h, its role's default)"),
        (None, " (expected every 3.5 h)"),
    ],
)
def test_each_source_is_named(source: str | None, suffix: str) -> None:
    context = NodeContext(expected_interval=3.5 * _H, cadence_source=source)
    _, findings = assess(_m(last_heard=_NOW - 30 * _H), context)
    assert findings[0].text == "not heard for 30 h" + suffix


def test_without_an_expected_interval_nothing_is_added() -> None:
    _, findings = assess(_m(last_heard=_NOW - 30 * _H), NodeContext())
    assert findings[0].text == "not heard for 30 h"


@pytest.mark.parametrize(
    ("covered", "expected"),
    [(2, Verdict.UNKNOWN), (3, Verdict.WARN), (24, Verdict.WARN), (25, Verdict.CRIT)],
)
def test_never_heard_is_judged_by_the_covered_hours(covered: int, expected: Verdict) -> None:
    verdict, findings = assess(_m(last_heard=None, covered_hours=covered), NodeContext())
    assert (verdict, findings[0].code) == (expected, "never_heard")
    assert findings[0].text == f"lorastats never heard it in {covered} covered hours"


def test_never_heard_uses_the_node_thresholds() -> None:
    verdict, findings = assess(_m(last_heard=None, covered_hours=13), _SIX_HOURLY)
    assert verdict is Verdict.UNKNOWN
    assert findings[0].text.endswith("(expected every 6 h, learned from its history)")
    assert assess(_m(last_heard=None, covered_hours=14), _SIX_HOURLY)[0] is Verdict.WARN
    assert assess(_m(last_heard=None, covered_hours=32), _SIX_HOURLY)[0] is Verdict.CRIT


# ---------------------------------------------------------------------------
# Battery freshness: at least the node's stale threshold.
# ---------------------------------------------------------------------------


def _low_battery(age: float) -> NodeMetrics:
    return _m(battery=BatteryTrend(5, _NOW - age, 1, 0.0, None))


def test_a_battery_reading_is_judged_while_the_node_is_not_stale() -> None:
    slow = dataclasses.replace(_SIX_HOURLY, stale_after=54 * _H)
    assert _codes(_low_battery(54 * _H), slow).get("battery_low") is Verdict.CRIT
    assert "battery_low" not in _codes(_low_battery(54 * _H + 1), slow)


def test_the_battery_freshness_floor_holds_for_frequent_nodes() -> None:
    fast = dataclasses.replace(_SIX_HOURLY, stale_after=2 * _H)
    assert _codes(_low_battery(BATTERY_FRESH_SECONDS), fast).get("battery_low") is Verdict.CRIT
    assert "battery_low" not in _codes(_low_battery(BATTERY_FRESH_SECONDS + 1), fast)


# ---------------------------------------------------------------------------
# Silent runs: as long as the offline rule, at least 6 hours.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("interval", "warns_from"),
    [
        (None, SILENCE_WARN_HOURS),
        (1 * _H, SILENCE_WARN_HOURS),
        (3 * _H, 15),
        (3.1 * _H, 16),
        (6 * _H, 30),
    ],
)
def test_a_silent_run_warns_from_five_expected_intervals(
    interval: float | None, warns_from: int
) -> None:
    context = NodeContext(expected_interval=interval)
    assert "silent_hours" not in _codes(_m(longest_silence_hours=warns_from - 1), context)
    found = _codes(_m(longest_silence_hours=warns_from), context)
    assert found.get("silent_hours") is Verdict.WARN


def test_a_silent_run_finding_names_the_expected_interval() -> None:
    _, findings = assess(_m(longest_silence_hours=30), _SIX_HOURLY)
    texts = [finding.text for finding in findings if finding.code == "silent_hours"]
    assert texts == [
        "30 hours in a row without a reception (expected every 6 h, learned from its history)"
    ]


# ---------------------------------------------------------------------------
# Boots: per week of the window.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("days", "warns_from"), [(1, 3), (7, 3), (8, 4), (14, 6), (30, 13)])
def test_boots_warn_per_week_of_the_window(days: int, warns_from: int) -> None:
    def boots(count: int) -> NodeMetrics:
        return _m(days=days, boots=tuple(_NOW - i * 60 for i in range(count)))

    assert "reboots" not in _codes(boots(warns_from - 1), NodeContext())
    assert _codes(boots(warns_from), NodeContext()).get("reboots") is Verdict.WARN


# ---------------------------------------------------------------------------
# with_learned_cadence and assess_nodes.
# ---------------------------------------------------------------------------

_SEEN = datetime.fromtimestamp(_NOW, tz=UTC)


def _merged(age_hours: float, cadence: Cadence) -> MergedNode:
    thresholds = node_thresholds(Thresholds(), cadence)
    age = timedelta(hours=age_hours)
    return MergedNode(
        node_id=_NODE,
        sources=("loranet",),
        role="CLIENT",
        last_seen=_SEEN - age,
        age=age,
        cadence=cadence,
        thresholds=thresholds,
        availability=Availability.STALE,
    )


_ROLE = Cadence(timedelta(hours=3), CadenceSource.ROLE)


def test_a_learned_interval_replaces_the_role_default() -> None:
    node = with_learned_cadence(_merged(10, _ROLE), timedelta(hours=6), Thresholds())
    assert node.cadence == Cadence(timedelta(hours=6), CadenceSource.HISTORY)
    assert node.thresholds == Thresholds(
        stale_after=timedelta(hours=13.5), offline_after=timedelta(hours=31.5)
    )
    assert node.availability is Availability.ONLINE


def test_a_learned_interval_uses_the_floor() -> None:
    floor = Thresholds(stale_after=timedelta(hours=20), offline_after=timedelta(hours=40))
    node = with_learned_cadence(_merged(10, _ROLE), timedelta(hours=6), floor)
    assert node.thresholds == floor


def test_nothing_learned_keeps_the_node() -> None:
    node = _merged(10, _ROLE)
    assert with_learned_cadence(node, None, Thresholds()) is node


def test_an_override_is_never_replaced() -> None:
    node = _merged(10, Cadence(timedelta(hours=1), CadenceSource.OVERRIDE))
    assert with_learned_cadence(node, timedelta(hours=6), Thresholds()) is node


def test_an_unseen_node_stays_unknown() -> None:
    node = dataclasses.replace(
        _merged(10, _ROLE), last_seen=None, age=None, availability=Availability.UNKNOWN
    )
    learned = with_learned_cadence(node, timedelta(hours=6), Thresholds())
    assert learned.availability is Availability.UNKNOWN


def _six_hourly_history(newest_heard: float) -> NodeHistory:
    newest = int(newest_heard) // HOUR_SECONDS * HOUR_SECONDS
    return NodeHistory(
        node=_NODE,
        hours=tuple(
            HourBucket(newest - offset * HOUR_SECONDS, receptions=0 if offset % 6 else 3)
            for offset in reversed(range(48))
        ),
        last_heard=float(newest),
    )


def test_assess_nodes_judges_with_the_refreshed_history() -> None:
    history = _six_hourly_history(_NOW - 10 * _H)

    (health,) = assess_nodes(
        [_merged(10, _ROLE)], {_NODE: history}, fleet=[_NODE], now=_NOW, days=7
    )

    assert health.node.cadence == Cadence(timedelta(hours=6), CadenceSource.HISTORY)
    assert health.node.availability is Availability.ONLINE
    assert health.verdict is Verdict.OK


def test_assess_nodes_without_a_history_keeps_the_role_default() -> None:
    (health,) = assess_nodes([_merged(10, _ROLE)], {}, fleet=[_NODE], now=_NOW, days=7)

    assert health.node.cadence == _ROLE
    assert health.verdict is Verdict.WARN
    assert health.findings[0].text == "not heard for 10 h (expected every 3 h, its role's default)"


def test_assess_nodes_passes_the_floor() -> None:
    history = _six_hourly_history(_NOW - 10 * _H)
    floor = Thresholds(stale_after=timedelta(hours=1), offline_after=timedelta(hours=9))

    (health,) = assess_nodes(
        [_merged(10, _ROLE)], {_NODE: history}, fleet=[_NODE], now=_NOW, days=7, floor=floor
    )

    assert health.node.thresholds == Thresholds(
        stale_after=timedelta(hours=13.5), offline_after=timedelta(hours=31.5)
    )
    floor = Thresholds(stale_after=timedelta(hours=14), offline_after=timedelta(hours=40))
    (health,) = assess_nodes(
        [_merged(10, _ROLE)], {_NODE: history}, fleet=[_NODE], now=_NOW, days=7, floor=floor
    )
    assert health.node.thresholds == floor


def test_assess_nodes_judges_offline_by_the_learned_thresholds() -> None:
    history = _six_hourly_history(_NOW - 30 * _H)

    (health,) = assess_nodes(
        [_merged(30, _ROLE)], {_NODE: history}, fleet=[_NODE], now=_NOW, days=7
    )

    assert health.verdict is Verdict.WARN
    assert health.findings[0].code == "silent"


def test_assess_status_uses_the_report_floors(tmp_path: Path) -> None:
    now = time.time()
    store = HistoryStore(tmp_path / HISTORY_DIRNAME)
    store.update(_NODE, lambda _old: _six_hourly_history(now - 10 * _H))
    refresher = HealthRefresher(store, packets=None)  # type: ignore[arg-type]
    seen = datetime.fromtimestamp(now, tz=UTC) - timedelta(hours=10)
    node = dataclasses.replace(_merged(10, _ROLE), last_seen=seen)
    floor = Thresholds(stale_after=timedelta(hours=30), offline_after=timedelta(hours=40))
    report = StatusReport(generated_at=seen, nodes=(node,), thresholds=floor)
    client = CachedHTTPClient(cache_dir=tmp_path, user_agent="mp/1 (+t@example.invalid)")
    try:
        health = assess_status(report, refresher, client=client)
    finally:
        client.close()

    assert health.nodes[_NODE].node.cadence.source is CadenceSource.HISTORY
    assert health.nodes[_NODE].node.thresholds == floor


# ---------------------------------------------------------------------------
# Rendering: the Every column, the detailed line, the JSON keys.
# ---------------------------------------------------------------------------


def _report() -> HealthReport:
    history = _six_hourly_history(_NOW - 10 * _H)
    nodes = assess_nodes([_merged(10, _ROLE)], {_NODE: history}, fleet=[_NODE], now=_NOW, days=7)
    return HealthReport(generated_at=_SEEN, days=7, fetched=False, nodes=nodes)


def test_the_table_shows_the_expected_interval() -> None:
    table = render.build_table(_report())
    headers = [str(column.header) for column in table.columns]
    at = headers.index("Every")
    assert headers[at - 1] == "Last heard"
    assert str(table.columns[at]._cells[0]) == "6h"


def test_the_detail_names_the_interval_and_the_thresholds() -> None:
    buffer = io.StringIO()
    Console(file=buffer, width=250, color_system=None).print(render.build_detail(_report()))
    assert (
        "Expected every 6h (learned from its history): stale after 13h 30m, offline after 31h 30m"
        in buffer.getvalue()
    )


@pytest.mark.parametrize(
    ("source", "text"),
    [
        (CadenceSource.OVERRIDE, "--expected-interval"),
        (CadenceSource.TEMPLATE, "the template's node-info interval"),
        (CadenceSource.ROLE, "its role's node-info default"),
    ],
)
def test_the_detail_names_each_source(source: CadenceSource, text: str) -> None:
    node = _merged(1, Cadence(timedelta(hours=3), source))
    (health,) = assess_nodes([node], {}, fleet=[_NODE], now=_NOW, days=7)
    report = HealthReport(generated_at=_SEEN, days=7, fetched=False, nodes=(health,))
    buffer = io.StringIO()
    Console(file=buffer, width=250, color_system=None).print(render.build_detail(report))
    assert f"Expected every 3h ({text}): stale after 6h 45m, offline after 24h" in buffer.getvalue()


def test_the_json_carries_the_interval_and_the_thresholds() -> None:
    (node,) = render.health_to_json_dict(_report())["nodes"]  # type: ignore[misc]
    keys = list(node)
    at = keys.index("lorastats_region")
    assert keys[at + 1 : at + 5] == [
        "expected_interval_seconds",
        "expected_interval_source",
        "stale_after_seconds",
        "offline_after_seconds",
    ]
    assert (node["expected_interval_seconds"], node["expected_interval_source"]) == (
        21600,
        "history",
    )
    assert (node["stale_after_seconds"], node["offline_after_seconds"]) == (48600, 113400)
