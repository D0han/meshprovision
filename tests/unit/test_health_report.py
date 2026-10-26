"""Assembling node health from status views and histories; the health exit code."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import httpx
import pytest
import respx

from meshprovision.cache.http import CachedHTTPClient
from meshprovision.config.settings import Settings
from meshprovision.db import ods_write
from meshprovision.db.nodes import NodeRecord
from meshprovision.errors import ExitCode
from meshprovision.health.history import HOUR_SECONDS, HourBucket, NodeHistory, NodeInfoSeen
from meshprovision.health.refresh import RefreshFailure, RefreshOutcome
from meshprovision.health.report import (
    HealthOptions,
    HealthReport,
    NodeHealth,
    assess_nodes,
    assess_status,
    refresh_status_histories,
    rejudged_nodes,
    run_health,
)
from meshprovision.health.rules import Verdict
from meshprovision.health.store import HISTORY_DIRNAME, HistoryStore
from meshprovision.nodeid import NodeId
from meshprovision.status.cadence import Cadence, CadenceSource
from meshprovision.status.merge import Availability, MergedNode, Thresholds
from meshprovision.status.report import SourceFailure, StatusReport

pytestmark = pytest.mark.unit

_A = NodeId.from_hex("ab446357")
_B = NodeId.from_hex("979ed146")
_NOW = datetime(2026, 10, 20, 20, 0, tzinfo=UTC)
_H = int(_NOW.timestamp()) - HOUR_SECONDS


def _history(node: NodeId, **fields: object) -> NodeHistory:
    return NodeHistory(node=node, **fields)  # type: ignore[arg-type]


def _assess(nodes, histories, fleet=()) -> tuple[NodeHealth, ...]:
    return assess_nodes(nodes, histories, fleet=fleet, now=_NOW.timestamp(), days=7)


def test_the_role_comes_from_the_sources_then_the_node_info_then_the_database() -> None:
    record = NodeRecord(node_id=_A.hex, short_name="A", long_name="Alpha", role="CLIENT")
    info = NodeInfoSeen(_NOW.timestamp(), "A", "Alpha", "ROUTER_LATE")
    with_info = {_A: _history(_A, nodeinfo=info)}

    sources = _assess([MergedNode(node_id=_A, role="REPEATER", record=record)], with_info)
    nodeinfo = _assess([MergedNode(node_id=_A, record=record)], with_info)
    database = _assess([MergedNode(node_id=_A, record=record)], {})
    nothing = _assess([MergedNode(node_id=_A)], {})

    assert [h[0].role for h in (sources, nodeinfo, database, nothing)] == [
        "REPEATER",
        "ROUTER_LATE",
        "CLIENT",
        None,
    ]


def test_a_node_without_history_and_without_a_sighting_is_unknown() -> None:
    (health,) = _assess([MergedNode(node_id=_A)], {})

    assert health.verdict is Verdict.UNKNOWN
    assert health.metrics.covered_hours == 0
    assert health.history_fetched_at is None


def test_the_status_view_feeds_the_rules() -> None:
    seen = _NOW.replace(hour=19, minute=50)
    node = MergedNode(node_id=_A, last_seen=seen, battery_level=5, last_device_metrics=seen)

    (health,) = _assess([node], {_A: _history(_A, fetched_at=123.0)})

    assert health.verdict is Verdict.CRIT
    assert [f.code for f in health.findings] == ["battery_low"]
    assert health.history_fetched_at == 123.0


def test_importance_counts_fleet_nodes_that_are_not_reported() -> None:
    sole = HourBucket(_H, receptions=30, gateways=MappingProxyType({_A.hex: 30}))
    histories = {_A: _history(_A), _B: _history(_B, hours=(sole,))}

    (health,) = _assess([MergedNode(node_id=_A)], histories, fleet=(_A, _B))

    assert health.importance.sole_gateway_for == (_B,)
    assert health.importance.uplinked == (_B,)


def test_relay_bytes_are_attributed_to_reported_nodes_outside_the_fleet() -> None:
    relayed = HourBucket(_H, receptions=30, relays=MappingProxyType({0x46: 30}))

    (health,) = _assess([MergedNode(node_id=_A)], {_A: _history(_A, hours=(relayed,))}, fleet=(_B,))

    assert health.metrics.relays[0].candidates == (_B,)
    unknown = _assess([MergedNode(node_id=_A)], {_A: _history(_A, hours=(relayed,))})
    assert unknown[0].metrics.relays[0].candidates == ()


def _report(*verdicts: Verdict, status: StatusReport | None = None, refresh=None) -> HealthReport:
    nodes = []
    for verdict in verdicts:
        (health,) = _assess([MergedNode(node_id=_A)], {})
        nodes.append(
            NodeHealth(
                node=health.node,
                metrics=health.metrics,
                verdict=verdict,
                findings=(),
                importance=health.importance,
                advice=(),
                role=None,
                history_fetched_at=None,
            )
        )
    return HealthReport(
        generated_at=_NOW, days=7, fetched=True, nodes=tuple(nodes), status=status, refresh=refresh
    )


def _status(*failures: SourceFailure) -> StatusReport:
    return StatusReport(generated_at=_NOW, nodes=(), thresholds=Thresholds(), failures=failures)


def test_the_exit_code_is_degraded_only_for_a_critical_node_or_a_failure() -> None:
    degraded = int(ExitCode.STATUS_DEGRADED)

    assert _report(Verdict.OK, Verdict.WARN, Verdict.UNKNOWN).exit_code() == 0
    assert _report(Verdict.OK, Verdict.CRIT).exit_code() == degraded
    assert _report(status=_status(SourceFailure("loranet", "down"))).exit_code() == degraded
    assert _report(status=_status()).exit_code() == 0
    failed = RefreshOutcome(histories={}, failures=(RefreshFailure(_A, "429"),))
    assert _report(refresh=failed).exit_code() == degraded
    assert _report(refresh=RefreshOutcome(histories={})).exit_code() == 0


def test_without_fetching_there_are_no_failures() -> None:
    report = _report(Verdict.OK)

    assert report.source_failures == ()
    assert report.refresh_failures == ()


def test_a_recent_sighting_without_history_is_ok_not_unknown() -> None:
    node = MergedNode(node_id=_A, last_seen=_NOW.replace(minute=0) - timedelta(minutes=10))

    (health,) = _assess([node], {})

    assert health.verdict is Verdict.OK


def _settings(tmp_path: Path, db: Path) -> Settings:
    return Settings(db_path=db, cache_dir=tmp_path / "cache", contact="t@example.invalid")


def test_without_fetching_the_whole_fleet_counts_and_nothing_is_asked(
    tmp_path: Path, empty_ods: Path
) -> None:
    ods_write.write_database(
        empty_ods,
        nodes=[
            NodeRecord(node_id=_A.hex, short_name="A", long_name="Alpha").to_row(),
            NodeRecord(node_id=_B.hex, short_name="B", long_name="Bravo").to_row(),
        ],
        keys=[],
        backup=False,
    )
    settings = _settings(tmp_path, empty_ods)
    sole = HourBucket(
        int(time.time()) // HOUR_SECONDS * HOUR_SECONDS,
        receptions=30,
        gateways=MappingProxyType({_A.hex: 30}),
    )
    HistoryStore(settings.cache_dir / HISTORY_DIRNAME).update(
        _B, lambda _old: NodeHistory(node=_B, hours=(sole,))
    )
    client = CachedHTTPClient(cache_dir=settings.cache_dir, user_agent="mp/1 (+t@example.invalid)")
    with respx.mock:
        respx.get("https://example.invalid/").mock(return_value=httpx.Response(200, json=[]))
        client.get("https://example.invalid/")

    report = run_health(settings, HealthOptions(fetch=False, node_ids=(_A,)), client=client)

    (health,) = report.nodes
    assert health.node.short_name == "A"
    assert health.importance.sole_gateway_for == (_B,)
    assert (report.fetched, report.network_requests, report.status, report.refresh) == (
        False,
        0,
        None,
        None,
    )


def _hourly(node: NodeId, hours: int) -> NodeHistory:
    return _history(node, hours=tuple(HourBucket(_H - i * HOUR_SECONDS, 1) for i in range(hours)))


def test_rejudged_nodes_take_the_interval_of_the_refreshed_histories() -> None:
    stale = MergedNode(node_id=_A, age=timedelta(hours=4), role="CLIENT")
    untouched = MergedNode(node_id=_B, age=timedelta(hours=4), role="CLIENT")

    a, b = rejudged_nodes(
        [stale, untouched], {_A: _hourly(_A, 6)}, now=_NOW.timestamp(), floor=Thresholds()
    )

    assert a.cadence == Cadence(timedelta(hours=1), CadenceSource.HISTORY)
    assert a.availability is Availability.STALE
    assert a.thresholds.stale_after == timedelta(hours=2, minutes=15)
    assert b is untouched


def test_rejudged_nodes_keep_an_override_and_a_history_that_teaches_nothing() -> None:
    override = MergedNode(
        node_id=_A,
        age=timedelta(hours=4),
        cadence=Cadence(timedelta(hours=3), CadenceSource.OVERRIDE),
    )
    plain = MergedNode(node_id=_B, age=timedelta(hours=4))

    nodes = rejudged_nodes(
        [override, plain],
        {_A: _hourly(_A, 6), _B: _hourly(_B, 2)},
        now=_NOW.timestamp(),
        floor=Thresholds(),
    )

    assert nodes == (override, plain)


def test_rejudged_nodes_keep_the_floors() -> None:
    node = MergedNode(node_id=_A, age=timedelta(hours=4), role="CLIENT")
    floor = Thresholds(stale_after=timedelta(hours=5), offline_after=timedelta(hours=30))

    (rejudged,) = rejudged_nodes([node], {_A: _hourly(_A, 6)}, now=_NOW.timestamp(), floor=floor)

    assert rejudged.thresholds == floor
    assert rejudged.availability is Availability.ONLINE


class _SpyRefresher:
    """A stand-in for ``HealthRefresher`` that records how it was asked."""

    def __init__(self) -> None:
        self.calls: list[tuple[object, object, bool]] = []

    def refresh(
        self, nodes: object, *, boots: object = None, gateway_check: bool = False
    ) -> RefreshOutcome:
        self.calls.append((nodes, boots, gateway_check))
        return RefreshOutcome(histories={})


def test_the_status_refreshes_never_run_a_gateway_check() -> None:
    report = StatusReport(
        generated_at=_NOW,
        nodes=(MergedNode(node_id=_A, lorastats_region="PL"),),
        thresholds=Thresholds(),
        failures=(),
    )
    refresher = _SpyRefresher()
    client = SimpleNamespace(stats=SimpleNamespace(network_requests=0))

    refresh_status_histories(report, refresher)  # type: ignore[arg-type]
    assess_status(report, refresher, client=client)  # type: ignore[arg-type]

    assert [gateway_check for _, _, gateway_check in refresher.calls] == [False, False]
