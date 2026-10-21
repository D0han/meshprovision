"""``mesh status --detail``: the brief table, appended health columns and JSON keys."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console
from rich.text import Text

from meshprovision.cache.http import CachedHTTPClient
from meshprovision.health import render as health_render
from meshprovision.health.metrics import NodeMetrics
from meshprovision.health.refresh import HealthRefresher, RefreshFailure, RefreshOutcome
from meshprovision.health.report import NodeHealth, StatusHealth, assess_status
from meshprovision.health.rules import Importance, Verdict
from meshprovision.health.store import HISTORY_DIRNAME, HistoryStore
from meshprovision.nodeid import NodeId
from meshprovision.status import render
from meshprovision.status.merge import MergedNode, Thresholds
from meshprovision.status.report import StatusReport
from tests.unit.test_health_refresh import _Packets

pytestmark = pytest.mark.unit

_A = NodeId.from_hex("ab446357")
_B = NodeId.from_hex("979ed146")
_NOW = datetime(2026, 10, 20, 20, 0, tzinfo=UTC)


def _report(*nodes: MergedNode) -> StatusReport:
    return StatusReport(generated_at=_NOW, nodes=nodes, thresholds=Thresholds())


def _headers(table: Any) -> list[str]:
    return [str(column.header) for column in table.columns]


def _cells(table: Any, row: int) -> list[str]:
    return [str(column._cells[row]) for column in table.columns]


def test_brief_keeps_the_essential_columns_in_order() -> None:
    table = render.build_table(_report(MergedNode(node_id=_A, short_name="A")), brief=True)

    assert _headers(table) == [
        "Node",
        "Short",
        "Status",
        "Last seen",
        "Batt",
        "Seen By\n1d/7d/30d",
        "Uptime",
    ]
    assert _cells(table, 0) == ["!ab446357", "A", "unknown", "never", "-", "-", "-"]
    assert set(_headers(table)) == render.BRIEF_COLUMNS


def test_extra_columns_are_appended_with_dashes_for_a_node_without_cells() -> None:
    extra = render.ExtraColumns(
        headers=(("One", "left"), ("Two", "right")),
        cells={_A: ("x", Text("y"))},
        caption=Text("extra line"),
    )
    report = _report(MergedNode(node_id=_A), MergedNode(node_id=_B))

    table = render.build_table(report, extra=extra)

    assert _headers(table)[-3:] == ["Uptime", "One", "Two"]
    assert _cells(table, 0)[-2:] == ["x", "y"]
    assert _cells(table, 1)[-2:] == ["-", "-"]
    assert str(table.caption).splitlines() == [report.summary(), "extra line"]


def test_brief_and_extra_combine() -> None:
    extra = render.ExtraColumns(headers=(("One", "left"),), cells={})

    table = render.build_table(_report(MergedNode(node_id=_A)), brief=True, extra=extra)

    assert _headers(table)[-2:] == ["Uptime", "One"]
    assert str(table.caption) == _report(MergedNode(node_id=_A)).summary()


def test_extra_caption_follows_the_empty_state_line() -> None:
    extra = render.ExtraColumns(headers=(), cells={}, caption=Text("more"))

    caption = str(render.build_table(_report(), extra=extra).caption)

    assert caption.splitlines()[0] == "No nodes in the database"
    assert caption.splitlines()[-1] == "more"


def test_render_console_passes_brief_and_extra_on() -> None:
    buffer = io.StringIO()
    extra = render.ExtraColumns(headers=(("Extra", "left"),), cells={})

    render.render_console(
        _report(MergedNode(node_id=_A)),
        console=Console(file=buffer, width=200, color_system=None),
        brief=True,
        extra=extra,
    )

    header = next(line for line in buffer.getvalue().splitlines() if "Node" in line)
    assert "Extra" in header
    assert "Mgmt" not in header


def _health(node: NodeId, verdict: Verdict) -> NodeHealth:
    now = _NOW.timestamp()
    metrics = NodeMetrics(
        node=node, days=7, window_start=now - 7 * 86400, now=now, covered_hours=3, gateway_count=2
    )
    return NodeHealth(
        node=MergedNode(node_id=node),
        metrics=metrics,
        verdict=verdict,
        findings=(),
        importance=Importance("low", 0),
        advice=(),
        role=None,
        history_fetched_at=None,
    )


def _status_health() -> StatusHealth:
    return StatusHealth(
        days=7,
        nodes={_A: _health(_A, Verdict.WARN), _B: _health(_B, Verdict.OK)},
        refresh=RefreshOutcome(
            histories={},
            refreshed=(_A,),
            no_region=(_B,),
            failures=(RefreshFailure(_A, "slow down", "wait"),),
        ),
        network_requests=2,
    )


def test_status_columns_show_the_verdict_and_the_metrics() -> None:
    extra = health_render.status_columns(_status_health())

    assert [header for header, _ in extra.headers] == [
        "Health",
        "Pkt/h",
        "GWs",
        "Direct",
        "Hops\nmax/limit",
        "SNR\nmedian",
        "Top relay",
    ]
    assert [str(cell) for cell in extra.cells[_A]] == ["WARN", "-", "2", "-", "-", "-", "-"]
    assert str(extra.caption).splitlines() == [
        "health over 7 d; history refreshed for 1 node(s), 2 request(s); 1 node(s) without "
        "lorastats data",
        "!ab446357: slow down",
    ]


def test_status_json_appends_health_keys_and_keeps_the_rest() -> None:
    report = _report(MergedNode(node_id=_A), MergedNode(node_id=_B))
    plain = json.loads(render.render_json(report))

    document = json.loads(health_render.status_json(report, _status_health()))

    assert list(document) == [*plain, "health"]
    assert {k: v for k, v in document.items() if k not in {"nodes", "health"}} == {
        k: v for k, v in plain.items() if k != "nodes"
    }
    for plain_node, node in zip(plain["nodes"], document["nodes"], strict=True):
        assert {k: v for k, v in node.items() if k != "health"} == plain_node
    assert [node["health"]["verdict"] for node in document["nodes"]] == ["warn", "ok"]
    assert document["health"] == {
        "days": 7,
        "network_requests": 2,
        "refresh": {"refreshed": [_A.hex], "no_region": [_B.hex], "skipped_rows": 0},
        "failures": [{"node": _A.hex, "message": "slow down", "hint": "wait"}],
    }


def test_assess_status_refreshes_the_reported_nodes_without_gateway_checks(
    tmp_path: Path,
) -> None:
    store = HistoryStore(tmp_path / "cache" / HISTORY_DIRNAME)
    packets = _Packets()
    refresher = HealthRefresher(store, packets)  # type: ignore[arg-type]
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    boot = _NOW - timedelta(hours=5)
    report = _report(
        MergedNode(node_id=_A, lorastats_region="PL", last_boot=boot), MergedNode(node_id=_B)
    )

    health = assess_status(report, refresher, client=client, days=3)

    assert health.days == 3
    assert set(health.nodes) == {_A, _B}
    assert health.nodes[_A].metrics.days == 3
    assert health.refresh.refreshed == (_A,)
    assert health.refresh.no_region == (_B,)
    assert [call[0] for call in packets.calls] == ["reports", "decoded"]
    assert health.network_requests == 0
    assert store.load(_A).boots == (boot.timestamp(),)
