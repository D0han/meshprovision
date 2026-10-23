"""Rendering a health report: the table, the detailed report and JSON."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime, timedelta
from types import MappingProxyType

import pytest
from rich.console import Console

from meshprovision.health import render
from meshprovision.health.history import GatewayCheck, LocalStatsPoint
from meshprovision.health.metrics import BatteryTrend, NodeMetrics, RelayShare
from meshprovision.health.refresh import RefreshFailure, RefreshOutcome
from meshprovision.health.report import HealthReport, NodeHealth
from meshprovision.health.rules import Advice, Finding, Importance, Verdict
from meshprovision.nodeid import NodeId
from meshprovision.status.merge import MergedNode, Thresholds
from meshprovision.status.report import SourceFailure, StatusReport

pytestmark = pytest.mark.unit

_A = NodeId.from_hex("ab446357")
_B = NodeId.from_hex("00000561")
_NOW = datetime(2026, 10, 20, 20, 0, tzinfo=UTC)
_T = _NOW.timestamp()


def _metrics(**fields: object) -> NodeMetrics:
    base: dict[str, object] = {"node": _A, "days": 7, "window_start": _T - 7 * 86400, "now": _T}
    base.update(fields)
    return NodeMetrics(**base)  # type: ignore[arg-type]


def _health(
    *,
    metrics: NodeMetrics | None = None,
    node: MergedNode | None = None,
    verdict: Verdict = Verdict.OK,
    findings: tuple[Finding, ...] = (),
    advice: tuple[Advice, ...] = (),
    importance: Importance | None = None,
) -> NodeHealth:
    return NodeHealth(
        node=node or MergedNode(node_id=_A, short_name="D0h5", long_name="Alpha"),
        metrics=metrics or _metrics(),
        verdict=verdict,
        findings=findings,
        importance=importance or Importance("low", 0),
        advice=advice,
        role="CLIENT",
        history_fetched_at=_T - 120,
    )


def _report(*nodes: NodeHealth, fetched: bool = True, **fields: object) -> HealthReport:
    return HealthReport(
        generated_at=_NOW,
        days=7,
        fetched=fetched,
        nodes=nodes,
        **fields,  # type: ignore[arg-type]
    )


def _text(renderable: object) -> str:
    buffer = io.StringIO()
    Console(file=buffer, width=250, color_system=None).print(renderable)
    return buffer.getvalue()


def _row(report: HealthReport) -> list[str]:
    table = render.build_table(report)
    return [str(column._cells[0]) for column in table.columns]


_FULL = _metrics(
    covered_hours=10,
    receptions=40,
    packets=10,
    packets_per_hour=1.0,
    direct=10,
    gateway_count=4,
    hops=MappingProxyType({1: 20, 3: 5}),
    hop_samples=25,
    hop_start=7,
    snr_median=6,
    relayed=30,
    relays=(RelayShare(0x61, 21, 0.7, (_B,)),),
    battery=BatteryTrend(80, _T - 600, 8, 20.0, -1.25),
)


def test_a_table_row_shows_each_metric() -> None:
    row = _row(_report(_health(metrics=_FULL)))

    assert row == [
        "!ab446357",
        "D0h5",
        "OK",
        "low",
        "-",
        "3h",
        "1.0",
        "4",
        "25%",
        "3/7",
        "6 dB",
        "0x61 70%",
        "80%",
        "-",
    ]


def test_an_empty_row_shows_dashes() -> None:
    node = MergedNode(node_id=_A)

    row = _row(_report(_health(node=node, verdict=Verdict.UNKNOWN)))

    assert row == [
        "!ab446357",
        "-",
        "UNKNOWN",
        "low",
        "-",
        "3h",
        "-",
        "-",
        "-",
        "-",
        "-",
        "-",
        "-",
        "-",
    ]


@pytest.mark.parametrize(
    ("fields", "cell"),
    [
        ({"hops": MappingProxyType({2: 1})}, "2/?"),
        ({"hop_start": 5}, "?/5"),
    ],
)
def test_a_hops_cell_marks_the_unknown_half(fields: dict[str, object], cell: str) -> None:
    assert _row(_report(_health(metrics=_metrics(**fields))))[9] == cell


@pytest.mark.parametrize(
    ("battery", "level", "cell"),
    [
        (None, 101, "powered"),
        (None, 100, "100%"),
        (None, 0, "-"),
        (BatteryTrend(42, _T, 1, 0.0, None), 90, "42%"),
    ],
)
def test_the_battery_cell_prefers_the_history(
    battery: BatteryTrend | None, level: int, cell: str
) -> None:
    node = MergedNode(node_id=_A, battery_level=level)

    assert _row(_report(_health(node=node, metrics=_metrics(battery=battery))))[12] == cell


def test_last_heard_is_the_newest_of_history_and_sources() -> None:
    node = MergedNode(node_id=_A, last_seen=_NOW - timedelta(hours=3))

    older_history = _row(_report(_health(node=node, metrics=_metrics(last_heard=_T - 86400))))
    newer_history = _row(_report(_health(node=node, metrics=_metrics(last_heard=_T - 60))))

    assert older_history[4] == "3 hours ago"
    assert newer_history[4] == "1 minute ago"


def test_reasons_show_two_findings_and_count_the_rest() -> None:
    findings = tuple(Finding(Verdict.WARN, f"c{i}", f"reason {i}\x1b[2J") for i in range(3))

    cell = _row(_report(_health(verdict=Verdict.WARN, findings=findings)))[13]

    assert cell.startswith("reason 0")
    assert "reason 1" in cell
    assert "reason 2" not in cell
    assert cell.endswith("(+1)")
    assert "\x1b" not in cell


def test_two_findings_have_no_remainder() -> None:
    findings = tuple(Finding(Verdict.WARN, f"c{i}", f"reason {i}") for i in range(2))

    assert _row(_report(_health(findings=findings)))[13] == "reason 0; reason 1"


def test_the_caption_counts_verdicts_and_names_the_window() -> None:
    report = _report(_health(), _health(verdict=Verdict.CRIT), fetched=False)

    caption = render.build_table(report).caption

    assert str(caption) == (
        "2 node(s): 1 ok, 0 warn, 1 crit, 0 unknown; window 7 d; history only, nothing fetched"
    )


def test_the_caption_reports_the_refresh_and_every_failure() -> None:
    refresh = RefreshOutcome(
        histories={},
        refreshed=(_A,),
        no_region=(_B,),
        failures=(RefreshFailure(_B, "rate limited"),),
        skipped_rows=3,
    )
    status = StatusReport(
        generated_at=_NOW,
        nodes=(),
        thresholds=Thresholds(),
        failures=(SourceFailure("loranet", "down"),),
    )
    report = _report(_health(), refresh=refresh, status=status, network_requests=4)

    caption = str(render.build_table(report).caption)

    assert caption.splitlines() == [
        "1 node(s): 1 ok, 0 warn, 0 crit, 0 unknown; window 7 d; history refreshed for 1 "
        "node(s), 4 request(s); 1 node(s) without lorastats data",
        "loranet: down",
        "!00000561: rate limited",
        "lorastats: 3 row(s) could not be used",
    ]


def test_a_refresh_without_unknown_nodes_or_skips_adds_nothing_more() -> None:
    report = _report(_health(), refresh=RefreshOutcome(histories={}), network_requests=0)

    assert str(render.build_table(report).caption).endswith(
        "history refreshed for 0 node(s), 0 request(s)"
    )


def _detail(health: NodeHealth) -> str:
    return _text(render.build_detail(_report(health)))


def test_the_detailed_report_has_every_section() -> None:
    metrics = _metrics(
        covered_hours=10,
        silent_hours=2,
        longest_silence_hours=1,
        receptions=40,
        packets=10,
        packets_per_hour=1.0,
        direct=10,
        gateways=(("32aca541", 30), ("db58ae50", 10)),
        gateway_count=2,
        uplinks_itself=True,
        hops=MappingProxyType({1: 20, 3: 5}),
        hop_samples=25,
        hop_start=7,
        hop_start_samples=9,
        snr_median=6,
        snr_low=-2,
        snr_samples=40,
        rssi_mean=170.4,
        relayed=30,
        relays=(RelayShare(0x61, 21, 0.7, (_B,)), RelayShare(0x19, 9, 0.3, ())),
        ports=MappingProxyType({3: 2, 67: 7, 99: 1}),
        decoded_packets=10,
        telemetry_per_hour=0.7,
        positions_per_hour=0.2,
        battery=BatteryTrend(80, _T - 600, 8, 20.0, -1.25),
        channel_utilization=3.5,
        air_util_tx=0.02,
        latest_local_stats=LocalStatsPoint(_T - 60, 100, 20, 5),
        boots=(_T - 7200,),
        neighbors=(("979ed146", _T - 3600),),
        gateway_check=GatewayCheck(_T - 60, 3600, 34, 24),
    )
    health = _health(
        metrics=metrics,
        verdict=Verdict.WARN,
        findings=(Finding(Verdict.WARN, "x", "a finding"),),
        advice=(Advice("y", "a suggestion"),),
        importance=Importance("high", 6, ("MQTT gateway", "only gateway for 1 of our nodes")),
    )

    text = _detail(health)

    for expected in (
        "!ab446357  D0h5  Alpha  role CLIENT",
        "Verdict: WARN\n  - warn: a finding",
        "Importance: high (score 6)\n  - MQTT gateway\n  - only gateway for 1 of our nodes",
        "Window: last 7 d; 10 of 168 hours covered, 2 silent (longest 1 in a row); history "
        "refreshed 2 minutes ago",
        "Traffic: 10 packets (1.0/h), 40 receptions, 25% direct",
        "Gateways (2): 32aca541 30, db58ae50 10; it uplinks its own packets (an MQTT gateway)",
        "Hops: 1:20 3:5 (25 receptions of decoded packets, 62% of all); hop limit 7 (HopStart "
        "of 9 decoded packets)",
        "SNR: median 6 dB, 10th percentile -2 dB (40 receptions); RSSI (raw lorastats value) "
        "mean 170",
        "Relays (30 relayed receptions): 0x61 70% (likely !00000561), 0x19 30%",
        "Decoded packets (10): position 2, telemetry 7, port 99 1; at least 0.7 telemetry and "
        "0.2 position packets an hour",
        "Battery: 80% (10 minutes ago), -1.2 points a day over 8 readings; channel utilization "
        "3.5%, transmit air utilization 0.02%",
        "Local stats (1 minute ago): 100 rx, 20 tx, 5 relayed since boot",
        "Boots in the window: ",
        "Neighbours: !979ed146 (1 hour ago)",
        "As a gateway (1 minute ago): uplinked 34 reports from 24 node(s) in the 60 minutes before",
        "Suggestions:\n  - a suggestion",
        "Limits: ",
    ):
        assert expected in text, expected


def test_the_detailed_report_leaves_out_what_is_unknown() -> None:
    text = _detail(_health(node=MergedNode(node_id=_A, battery_level=55)))

    assert "Hops: - (0 receptions of decoded packets, - of all); hop limit ?" in text
    assert "Battery: 55% (from mesh status)" in text
    assert "Gateways (0): -" in text
    for absent in (
        "Local stats",
        "Boots",
        "Neighbours",
        "As a gateway",
        "Suggestions",
        "uplinks its own packets",
    ):
        assert absent not in text


def test_a_battery_trend_without_a_slope_says_so() -> None:
    metrics = _metrics(battery=BatteryTrend(80, _T - 60, 2, 1.0, None))

    assert "80% (1 minute ago), no trend yet over 2 readings" in _detail(_health(metrics=metrics))


def test_the_detailed_report_is_terminal_safe() -> None:
    node = MergedNode(
        node_id=_A, short_name="A\x1b[2J", long_name="B\x9bC", lorastats_region="R\x07"
    )

    health = _health(
        node=node,
        findings=(Finding(Verdict.WARN, "x", "odd\x1b[31m"),),
        importance=Importance("low", 1, ("role X\x9bY",)),
    )

    text = _detail(health)

    assert not any(char in text for char in ("\x1b", "\x9b", "\x07"))


def test_render_console_prints_the_table_or_the_detail() -> None:
    buffer = io.StringIO()
    console = Console(file=buffer, width=250, color_system=None)

    render.render_console(_report(_health()), console=console, detail=False)
    render.render_console(_report(_health()), console=console, detail=True)

    output = buffer.getvalue()
    table_part, detail_part = output.split("!ab446357  D0h5")
    assert "Importance" in table_part
    assert "Verdict: OK" in detail_part


def test_json_names_each_node_and_carries_its_health() -> None:
    health = _health(
        metrics=_FULL,
        verdict=Verdict.WARN,
        findings=(Finding(Verdict.WARN, "single_gateway", "one gateway"),),
        advice=(Advice("hop_limit", "lower it"),),
        importance=Importance("medium", 3, ("MQTT gateway",), (_B,), (), ()),
    )
    refresh = RefreshOutcome(
        histories={}, refreshed=(_A,), failures=(RefreshFailure(_B, "429", "wait"),)
    )
    status = StatusReport(
        generated_at=_NOW,
        nodes=(),
        thresholds=Thresholds(),
        failures=(SourceFailure("loranet", "down", None),),
    )

    document = json.loads(
        render.render_json(_report(health, refresh=refresh, status=status, network_requests=5))
    )

    assert document["generated_at"] == "2026-10-20T20:00:00Z"
    assert (document["days"], document["fetched"], document["network_requests"]) == (7, True, 5)
    assert document["failures"] == [
        {"source": "loranet", "node": None, "message": "down", "hint": None},
        {"source": "lorastats", "node": "00000561", "message": "429", "hint": "wait"},
    ]
    assert document["refresh"] == {"refreshed": [_A.hex], "no_region": [], "skipped_rows": 0}
    (node,) = document["nodes"]
    assert list(node)[:5] == ["node_id", "display", "short_name", "long_name", "lorastats_region"]
    assert node["verdict"] == "warn"
    assert node["findings"] == [
        {"severity": "warn", "code": "single_gateway", "text": "one gateway"}
    ]
    assert node["suggestions"] == [{"code": "hop_limit", "text": "lower it"}]
    assert node["importance"]["uplinked"] == [_B.hex]
    assert node["history_fetched_at"] == "2026-10-20T19:58:00Z"
    metrics = node["metrics"]
    assert metrics["hops"] == {"1": 20, "3": 5}
    assert metrics["relays"] == [
        {"byte": 0x61, "receptions": 21, "share": 0.7, "candidates": [_B.hex]}
    ]
    assert metrics["battery"] == {
        "latest": 80,
        "time": "2026-10-20T19:50:00Z",
        "points": 8,
        "span_hours": 20.0,
        "slope_per_day": -1.25,
    }
    assert metrics["gateway_check"] is None


def test_json_without_fetching_has_no_refresh() -> None:
    document = render.health_to_json_dict(_report(_health(), fetched=False))

    assert document["refresh"] is None
    assert document["failures"] == []
