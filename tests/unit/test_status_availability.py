"""Availability relative to each node's expected interval (merge, report, table, JSON)."""

from __future__ import annotations

import dataclasses
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from meshprovision.datasources.base import SOURCE_LORANET
from meshprovision.datasources.models import NodeObservation
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import ManagementMode
from meshprovision.health.history import HourBucket, NodeHistory
from meshprovision.health.store import HISTORY_DIRNAME, HistoryStore
from meshprovision.nodeid import NodeId
from meshprovision.status import render
from meshprovision.status.cadence import Cadence, CadenceHint, CadenceSource
from meshprovision.status.merge import (
    Availability,
    MergedNode,
    Thresholds,
    merge_all,
    merge_observations,
    node_thresholds,
)
from meshprovision.status.report import (
    StatusOptions,
    StatusReport,
    build_report,
    learned_intervals,
)

pytestmark = pytest.mark.unit

NID = NodeId.from_hex("deadbe01")
OTHER = NodeId.from_hex("deadbe02")
NOW = datetime(2026, 8, 25, 12, 0, 0, tzinfo=UTC)
_H = timedelta(hours=1)


def _obs(age: timedelta | None, node_id: NodeId = NID, **kwargs: object) -> NodeObservation:
    last_seen = None if age is None else NOW - age
    return NodeObservation(
        node_id=node_id, source=SOURCE_LORANET, observed_at=NOW, last_seen=last_seen, **kwargs
    )


def _merge(
    age: timedelta,
    *,
    role: str | None = None,
    record: NodeRecord | None = None,
    cadence: CadenceHint | None = None,
) -> MergedNode:
    return merge_observations(
        NID, [_obs(age, role=role)], record=record, now=NOW, cadence=cadence or CadenceHint()
    )


# ---------------------------------------------------------------------------
# merge_observations: the node's own thresholds.
# ---------------------------------------------------------------------------


def test_a_hand_built_node_has_the_role_default_cadence() -> None:
    node = MergedNode(node_id=NID)
    assert node.cadence == Cadence(3 * _H, CadenceSource.ROLE)
    assert node.thresholds == Thresholds(stale_after=6.75 * _H, offline_after=24 * _H)


@pytest.mark.parametrize(
    ("age", "expected"),
    [
        (6 * _H, Availability.ONLINE),
        (6.75 * _H, Availability.ONLINE),
        (6.75 * _H + timedelta(seconds=1), Availability.STALE),
        (24 * _H, Availability.STALE),
        (24 * _H + timedelta(seconds=1), Availability.OFFLINE),
    ],
)
def test_a_client_is_judged_against_its_node_info_interval(
    age: timedelta, expected: Availability
) -> None:
    node = _merge(age, role="CLIENT")
    assert node.cadence == Cadence(3 * _H, CadenceSource.ROLE)
    assert node.availability is expected


def test_a_tak_node_may_be_silent_for_two_days() -> None:
    node = _merge(50 * _H, role="TAK")
    assert node.cadence == Cadence(24 * _H, CadenceSource.ROLE)
    assert node.thresholds == Thresholds(stale_after=54 * _H, offline_after=126 * _H)
    assert node.availability is Availability.ONLINE


def test_the_database_role_is_used_when_no_source_reports_one() -> None:
    record = NodeRecord(node_id="deadbe01", role="TAK")
    assert _merge(50 * _H, record=record).cadence.interval == 24 * _H


def test_the_observed_role_beats_the_database_role() -> None:
    record = NodeRecord(node_id="deadbe01", role="TAK")
    assert _merge(50 * _H, role="CLIENT", record=record).cadence.interval == 3 * _H


def test_a_blank_database_role_is_no_role() -> None:
    record = NodeRecord(node_id="deadbe01", management=ManagementMode.OBSERVED, role="")
    assert _merge(_H, record=record).cadence == Cadence(3 * _H, CadenceSource.ROLE)


def test_a_learned_interval_sets_the_thresholds() -> None:
    node = _merge(13 * _H, cadence=CadenceHint(learned=6 * _H))
    assert node.cadence == Cadence(6 * _H, CadenceSource.HISTORY)
    assert node.thresholds == Thresholds(stale_after=13.5 * _H, offline_after=31.5 * _H)
    assert node.availability is Availability.ONLINE


def test_an_override_sets_the_thresholds() -> None:
    node = _merge(3 * _H, role="TAK", cadence=CadenceHint(override=timedelta(minutes=30)))
    assert node.cadence == Cadence(timedelta(minutes=30), CadenceSource.OVERRIDE)
    assert node.thresholds == Thresholds(stale_after=2 * _H, offline_after=24 * _H)
    assert node.availability is Availability.STALE


def test_a_node_nobody_saw_still_gets_its_cadence() -> None:
    record = NodeRecord(node_id="deadbe01", role="TAK")
    node = merge_observations(
        NID, [], record=record, now=NOW, cadence=CadenceHint(configured=6 * _H)
    )
    assert node.availability is Availability.UNKNOWN
    assert node.cadence == Cadence(6 * _H, CadenceSource.TEMPLATE)
    assert node.thresholds == Thresholds(stale_after=13.5 * _H, offline_after=31.5 * _H)
    unseen = merge_observations(NID, [], record=record, now=NOW)
    assert unseen.cadence == Cadence(24 * _H, CadenceSource.ROLE)


def test_a_node_nobody_saw_without_a_record_has_the_default_cadence() -> None:
    node = merge_observations(NID, [], now=NOW)
    assert (node.cadence, node.thresholds) == (MergedNode(NID).cadence, MergedNode(NID).thresholds)


def test_the_floors_still_apply() -> None:
    floors = Thresholds(stale_after=10 * _H, offline_after=40 * _H)
    node = merge_observations(NID, [_obs(9 * _H)], now=NOW, thresholds=floors)
    assert node.thresholds == floors
    assert node.availability is Availability.ONLINE


def test_node_thresholds_stretches_the_floors() -> None:
    floors = Thresholds()
    assert node_thresholds(floors, Cadence(12 * _H, CadenceSource.HISTORY)) == Thresholds(
        stale_after=27 * _H, offline_after=63 * _H
    )
    assert node_thresholds(floors, Cadence(_H / 2, CadenceSource.OVERRIDE)) == floors


def test_the_json_names_the_interval_and_the_thresholds() -> None:
    data = _merge(_H, cadence=CadenceHint(learned=6 * _H)).to_json_dict()
    keys = list(data)
    at = keys.index("availability")
    assert keys[at + 1 : at + 5] == [
        "expected_interval_seconds",
        "expected_interval_source",
        "stale_after_seconds",
        "offline_after_seconds",
    ]
    assert data["expected_interval_seconds"] == 6 * 3600
    assert data["expected_interval_source"] == "history"
    assert data["stale_after_seconds"] == int(13.5 * 3600)
    assert data["offline_after_seconds"] == int(31.5 * 3600)


def test_merge_all_passes_each_node_its_own_hint() -> None:
    observations = {SOURCE_LORANET: {NID: _obs(_H), OTHER: _obs(_H, node_id=OTHER)}}
    merged = merge_all(
        observations, node_ids=[NID, OTHER], now=NOW, cadences={NID: CadenceHint(learned=5 * _H)}
    )
    assert [node.cadence.source for node in merged] == [CadenceSource.HISTORY, CadenceSource.ROLE]


# ---------------------------------------------------------------------------
# build_report: which hint each node gets.
# ---------------------------------------------------------------------------

_TEMPLATE = NodeRecord(node_id="deadbe01", management=ManagementMode.TEMPLATE)
_OBSERVED = NodeRecord(node_id="deadbe02", management=ManagementMode.OBSERVED)


def _report(options: StatusOptions, learned: dict[NodeId, timedelta] | None = None) -> StatusReport:
    return build_report(
        records={NID: _TEMPLATE, OTHER: _OBSERVED},
        observations_by_source={},
        node_ids=[NID, OTHER],
        now=NOW,
        options=options,
        learned=learned,
    )


def test_the_template_interval_applies_to_template_managed_nodes_only() -> None:
    report = _report(StatusOptions(template_interval=6 * _H))
    assert [node.cadence for node in report.nodes] == [
        Cadence(6 * _H, CadenceSource.TEMPLATE),
        Cadence(3 * _H, CadenceSource.ROLE),
    ]


def test_the_override_applies_to_every_node() -> None:
    report = _report(StatusOptions(expected_interval=8 * _H, template_interval=6 * _H))
    assert {node.cadence for node in report.nodes} == {Cadence(8 * _H, CadenceSource.OVERRIDE)}


def test_learned_intervals_reach_their_nodes() -> None:
    report = _report(StatusOptions(template_interval=6 * _H), learned={NID: 2 * _H, OTHER: 4 * _H})
    assert [node.cadence for node in report.nodes] == [
        Cadence(2 * _H, CadenceSource.HISTORY),
        Cadence(4 * _H, CadenceSource.HISTORY),
    ]


def test_without_learned_intervals_nothing_is_learned() -> None:
    report = _report(StatusOptions())
    assert {node.cadence.source for node in report.nodes} == {CadenceSource.ROLE}


# ---------------------------------------------------------------------------
# learned_intervals: reads the histories, writes nothing.
# ---------------------------------------------------------------------------


def _store_history(cache_dir: Path, node: NodeId, heard_every: int, hours: int) -> None:
    newest = int(time.time()) // 3600 * 3600
    buckets = tuple(
        HourBucket(hour=newest - offset * 3600, receptions=0 if offset % heard_every else 4)
        for offset in reversed(range(hours))
    )
    store = HistoryStore(cache_dir / HISTORY_DIRNAME)
    store.update(node, lambda history: dataclasses.replace(history, hours=buckets))


def test_learned_intervals_reads_each_history(tmp_path: Path) -> None:
    _store_history(tmp_path, NID, heard_every=3, hours=24)
    _store_history(tmp_path, OTHER, heard_every=1, hours=2)
    before = sorted(path.stat().st_mtime_ns for path in (tmp_path / HISTORY_DIRNAME).iterdir())

    learned = learned_intervals(
        tmp_path, [NID, OTHER, NodeId.from_hex("deadbe03")], now=time.time()
    )

    assert learned == {NID: 3 * _H}
    after = sorted(path.stat().st_mtime_ns for path in (tmp_path / HISTORY_DIRNAME).iterdir())
    assert after == before


def test_learned_intervals_without_a_history_directory_is_empty(tmp_path: Path) -> None:
    assert learned_intervals(tmp_path, [NID], now=time.time()) == {}
    assert not (tmp_path / HISTORY_DIRNAME).exists()


def test_an_empty_history_learns_nothing(tmp_path: Path) -> None:
    HistoryStore(tmp_path / HISTORY_DIRNAME).update(NID, lambda _: NodeHistory(node=NID))
    assert learned_intervals(tmp_path, [NID], now=time.time()) == {}


# ---------------------------------------------------------------------------
# The table's Every column.
# ---------------------------------------------------------------------------


def _every(cadence: Cadence) -> tuple[str, str]:
    report = StatusReport(
        generated_at=NOW,
        nodes=(MergedNode(node_id=NID, cadence=cadence),),
        thresholds=Thresholds(),
    )
    table = render.build_table(report)
    column = next(column for column in table.columns if column.header == "Every")
    cell = next(iter(column.cells))
    return str(cell), str(getattr(cell, "style", ""))


@pytest.mark.parametrize(
    ("interval", "text"),
    [
        (3 * _H, "3h"),
        (3.5 * _H, "3h 30m"),
        (timedelta(minutes=45), "45m"),
        (timedelta(seconds=59), "0m"),
        (48 * _H, "48h"),
        (_H + timedelta(minutes=1, seconds=59), "1h 1m"),
    ],
)
def test_every_shows_the_interval(interval: timedelta, text: str) -> None:
    assert _every(Cadence(interval, CadenceSource.HISTORY)) == (text, "")


def test_every_is_gray_for_a_role_default_only() -> None:
    assert _every(Cadence(3 * _H, CadenceSource.ROLE)) == ("3h", "grey50")
    assert _every(Cadence(3 * _H, CadenceSource.TEMPLATE))[1] == ""
    assert _every(Cadence(3 * _H, CadenceSource.OVERRIDE))[1] == ""


def test_brief_leaves_every_out() -> None:
    report = StatusReport(generated_at=NOW, nodes=(MergedNode(NID),), thresholds=Thresholds())
    headers = [str(column.header) for column in render.build_table(report, brief=True).columns]
    assert "Every" not in headers


# ---------------------------------------------------------------------------
# Freshness colors stretched to the node's thresholds.
# ---------------------------------------------------------------------------

_TWELVE_HOURLY = Thresholds(stale_after=27 * _H, offline_after=63 * _H)
_CAPPED = Thresholds(stale_after=108 * _H, offline_after=252 * _H)
_SECOND = timedelta(seconds=1)


@pytest.mark.parametrize(
    ("age", "thresholds", "expected"),
    [
        (27 * _H, _TWELVE_HOURLY, "green"),
        (27 * _H + _SECOND, _TWELVE_HOURLY, "yellow"),
        (63 * _H, _TWELVE_HOURLY, "yellow"),
        (63 * _H + _SECOND, _TWELVE_HOURLY, "dark_orange"),
        (7 * 24 * _H, _TWELVE_HOURLY, "dark_orange"),
        (7 * 24 * _H + _SECOND, _TWELVE_HOURLY, "red"),
        (108 * _H, _CAPPED, "green"),
        (252 * _H, _CAPPED, "yellow"),
        (252 * _H + _SECOND, _CAPPED, "red"),
        (24 * _H, Thresholds(), "green"),
        (24 * _H + _SECOND, Thresholds(), "yellow"),
        (48 * _H + _SECOND, Thresholds(), "dark_orange"),
        (None, _CAPPED, "grey50"),
    ],
)
def test_freshness_tiers_reach_at_least_the_node_thresholds(
    age: timedelta | None, thresholds: Thresholds, expected: str
) -> None:
    assert render.age_style(age, thresholds) == expected


def test_the_table_colors_by_the_node_thresholds() -> None:
    seen = NOW - 26 * _H
    node = MergedNode(
        node_id=NID,
        last_seen=seen,
        age=26 * _H,
        last_device_metrics=seen,
        battery_level=80,
        cadence=Cadence(12 * _H, CadenceSource.HISTORY),
        thresholds=_TWELVE_HOURLY,
    )
    report = StatusReport(generated_at=NOW, nodes=(node,), thresholds=Thresholds())
    table = render.build_table(report)
    styles = {
        str(column.header): str(getattr(next(iter(column.cells)), "style", ""))
        for column in table.columns
    }
    assert styles["Last seen"] == "green"
    assert styles["Metrics"] == "green"
    assert styles["Batt"] == "green"
