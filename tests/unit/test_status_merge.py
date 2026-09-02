"""Tests for meshprovision.status.merge and meshprovision.status.render."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from meshprovision.datasources.base import SOURCE_LORANET, SOURCE_LORASTATS
from meshprovision.datasources.models import NodeObservation
from meshprovision.db.nodes import NodeRecord
from meshprovision.errors import DataSourceError, HttpError, MissingContactError
from meshprovision.nodeid import NodeId
from meshprovision.status import render
from meshprovision.status.merge import (
    SOURCE_PRIORITY,
    Availability,
    Thresholds,
    classify_age,
    humanize_age,
    merge_all,
    merge_observations,
)
from meshprovision.status.report import (
    SourceFailure,
    StatusReport,
    build_report,
    collect_observations,
)

pytestmark = pytest.mark.unit

NID = NodeId.from_hex("deadbe01")
NOW = datetime(2026, 8, 25, 12, 0, 0, tzinfo=UTC)


def _obs(source: str, **kwargs) -> NodeObservation:  # noqa: ANN003
    return NodeObservation(node_id=NID, source=source, observed_at=NOW, **kwargs)


# ---------------------------------------------------------------------------
# merge_observations.
# ---------------------------------------------------------------------------


def test_loranet_only() -> None:
    obs = _obs(SOURCE_LORANET, battery_level=90, last_seen=NOW - timedelta(minutes=5))
    merged = merge_observations(NID, [obs], now=NOW)
    assert merged.battery_level == 90
    assert merged.sources == (SOURCE_LORANET,)


def test_lorastats_only() -> None:
    obs = _obs(SOURCE_LORASTATS, short_name="abcd", last_seen=NOW - timedelta(minutes=5))
    merged = merge_observations(NID, [obs], now=NOW)
    assert merged.short_name == "abcd"
    assert merged.sources == (SOURCE_LORASTATS,)


def test_loranet_wins_for_telemetry() -> None:
    loranet_obs = _obs(SOURCE_LORANET, battery_level=50, last_seen=NOW - timedelta(minutes=10))
    lorastats_obs = _obs(SOURCE_LORASTATS, battery_level=99, last_seen=NOW - timedelta(minutes=1))
    merged = merge_observations(NID, [lorastats_obs, loranet_obs], now=NOW)
    assert merged.battery_level == 50


def test_most_recent_last_seen_wins_and_names_source() -> None:
    loranet_obs = _obs(SOURCE_LORANET, last_seen=NOW - timedelta(hours=2))
    lorastats_obs = _obs(SOURCE_LORASTATS, last_seen=NOW - timedelta(minutes=1))
    merged = merge_observations(NID, [loranet_obs, lorastats_obs], now=NOW)
    assert merged.last_seen == NOW - timedelta(minutes=1)
    assert merged.last_seen_source == SOURCE_LORASTATS


def test_sources_reported_in_priority_order() -> None:
    loranet_obs = _obs(SOURCE_LORANET, last_seen=NOW)
    lorastats_obs = _obs(SOURCE_LORASTATS, last_seen=NOW)
    merged = merge_observations(NID, [lorastats_obs, loranet_obs], now=NOW)
    assert merged.sources == (SOURCE_LORANET, SOURCE_LORASTATS)
    assert SOURCE_PRIORITY == (SOURCE_LORANET, SOURCE_LORASTATS)


def test_unobserved_node_in_database() -> None:
    record = NodeRecord(node_id="deadbe01")
    merged = merge_observations(NID, [], record=record, now=NOW)
    assert merged.availability is Availability.UNKNOWN
    assert merged.in_database is True
    assert merged.observed is False


def test_classify_age_boundaries() -> None:
    thresholds = Thresholds()
    assert classify_age(thresholds.stale_after, thresholds) is Availability.ONLINE
    just_past_stale = thresholds.stale_after + timedelta(seconds=1)
    assert classify_age(just_past_stale, thresholds) is Availability.STALE
    assert classify_age(thresholds.offline_after, thresholds) is Availability.STALE
    just_past_offline = thresholds.offline_after + timedelta(seconds=1)
    assert classify_age(just_past_offline, thresholds) is Availability.OFFLINE
    assert classify_age(timedelta(seconds=-5), thresholds) is Availability.ONLINE
    assert classify_age(None, thresholds) is Availability.UNKNOWN


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (None, "never"),
        (-5, "in the future"),
        (59, "just now"),
        (60, "1 minute ago"),
        (3599, "59 minutes ago"),
        (3600, "1 hour ago"),
        (86399, "23 hours ago"),
        (86400, "1 day ago"),
    ],
)
def test_humanize_age_boundaries(seconds: int | None, expected: str) -> None:
    age = None if seconds is None else timedelta(seconds=seconds)
    assert humanize_age(age) == expected


def test_humanize_age_plural_singular() -> None:
    assert humanize_age(timedelta(minutes=1)) == "1 minute ago"
    assert humanize_age(timedelta(minutes=2)) == "2 minutes ago"
    assert humanize_age(timedelta(hours=1)) == "1 hour ago"
    assert humanize_age(timedelta(hours=2)) == "2 hours ago"
    assert humanize_age(timedelta(days=1)) == "1 day ago"
    assert humanize_age(timedelta(days=2)) == "2 days ago"


def test_thresholds_validation_errors() -> None:
    with pytest.raises(ValueError, match="positive"):
        Thresholds(stale_after=timedelta(0))
    with pytest.raises(ValueError, match="positive"):
        Thresholds(offline_after=timedelta(0))
    with pytest.raises(ValueError, match="strictly less"):
        Thresholds(stale_after=timedelta(hours=5), offline_after=timedelta(hours=1))


def test_thresholds_from_hours() -> None:
    thresholds = Thresholds.from_hours(1, 5)
    assert thresholds.stale_after == timedelta(hours=1)
    assert thresholds.offline_after == timedelta(hours=5)


def test_merged_node_to_json_dict_never_contains_secrets() -> None:
    record = NodeRecord(node_id="deadbe01", ble_pin="012345", authorized_admin_keys=("A_pub",))
    obs = _obs(SOURCE_LORANET, last_seen=NOW)
    merged = merge_observations(NID, [obs], record=record, now=NOW)
    payload = merged.to_json_dict()
    text = str(payload)
    assert "012345" not in text
    assert "key_ref" not in text
    assert "A_pub" not in text
    assert payload["database"] == {
        "short_name": "",
        "long_name": "",
        "role": "CLIENT",
        "region": "EU_868",
        "management": "template",
    }


def test_merged_node_management_is_none_when_not_in_database() -> None:
    obs = _obs(SOURCE_LORANET, last_seen=NOW)
    merged = merge_observations(NID, [obs], record=None, now=NOW)
    assert merged.management is None
    assert merged.to_json_dict()["database"] is None


def test_merge_all_preserves_caller_order_never_re_sorts() -> None:
    nid_a = NodeId.from_hex("aaaaaaaa")
    nid_b = NodeId.from_hex("bbbbbbbb")
    merged = merge_all({}, node_ids=[nid_b, nid_a], now=NOW)
    assert [m.node_id for m in merged] == [nid_b, nid_a]


def test_merge_observations_requires_timezone_aware_now() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        merge_observations(NID, [], now=datetime(2026, 1, 1))  # noqa: DTZ001


# ---------------------------------------------------------------------------
# StatusReport.
# ---------------------------------------------------------------------------


def test_status_report_counts_zero_fill_every_availability() -> None:
    report = build_report(records={}, observations_by_source={}, node_ids=[], now=NOW)
    counts = report.counts
    for avail in Availability:
        assert avail in counts
    assert counts[Availability.ONLINE] == 0


def test_status_report_unobserved_has_offline_degraded() -> None:
    record = NodeRecord(node_id="deadbe01")
    obs = _obs(SOURCE_LORANET, last_seen=NOW - timedelta(days=3))
    report = build_report(
        records={NID: record},
        observations_by_source={SOURCE_LORANET: {NID: obs}},
        node_ids=[NID],
        now=NOW,
    )
    assert report.unobserved == ()
    assert report.has_offline is True
    assert report.degraded is True


def test_status_report_exit_code_with_and_without_fail_on_offline() -> None:
    obs = _obs(SOURCE_LORANET, last_seen=NOW - timedelta(days=3))
    report = build_report(
        records={},
        observations_by_source={SOURCE_LORANET: {NID: obs}},
        node_ids=[NID],
        now=NOW,
    )
    assert report.exit_code(fail_on_offline=True) != 0
    assert report.exit_code(fail_on_offline=False) == 0


def test_status_report_exit_code_with_source_failure() -> None:
    report = StatusReport(
        generated_at=NOW,
        nodes=(),
        thresholds=Thresholds(),
        failures=(SourceFailure(source="lorastats", message="boom"),),
    )
    assert report.exit_code() != 0


def test_status_report_summary_text() -> None:
    report = build_report(records={}, observations_by_source={}, node_ids=[], now=NOW)
    assert "0 node(s)" in report.summary()


# ---------------------------------------------------------------------------
# collect_observations.
# ---------------------------------------------------------------------------


class _FailingSource:
    name = "loranet"

    def fetch_nodes(
        self,
        ids,  # noqa: ARG002
        *,
        force_refresh=False,  # noqa: ARG002
    ) -> dict[NodeId, NodeObservation]:
        raise HttpError("boom", url="https://x.invalid")


class _OkSource:
    name = "lorastats"

    def fetch_nodes(
        self,
        ids,  # noqa: ARG002
        *,
        force_refresh=False,  # noqa: ARG002
    ) -> dict[NodeId, NodeObservation]:
        return {NID: _obs("lorastats")}


class _MissingContactSource:
    name = "lorastats"

    def fetch_nodes(
        self,
        ids,  # noqa: ARG002
        *,
        force_refresh=False,  # noqa: ARG002
    ) -> dict[NodeId, NodeObservation]:
        raise MissingContactError()


def test_collect_observations_tolerates_one_failure() -> None:
    observations, failures = collect_observations([_FailingSource(), _OkSource()], [NID])
    assert "loranet" not in observations
    assert "lorastats" in observations
    assert len(failures) == 1
    assert failures[0].source == "loranet"


def test_collect_observations_does_not_catch_missing_contact_error() -> None:
    with pytest.raises(MissingContactError):
        collect_observations([_MissingContactSource()], [NID])


def test_collect_observations_error_is_data_source_error_subclass() -> None:
    assert issubclass(HttpError, DataSourceError)


# ---------------------------------------------------------------------------
# build_report purity/determinism.
# ---------------------------------------------------------------------------


def test_build_report_is_pure_and_deterministic() -> None:
    obs = _obs(SOURCE_LORANET, last_seen=NOW)
    report1 = build_report(
        records={}, observations_by_source={SOURCE_LORANET: {NID: obs}}, node_ids=[NID], now=NOW
    )
    report2 = build_report(
        records={}, observations_by_source={SOURCE_LORANET: {NID: obs}}, node_ids=[NID], now=NOW
    )
    assert render.render_json(report1) == render.render_json(report2)


# ---------------------------------------------------------------------------
# render.
# ---------------------------------------------------------------------------


def test_report_to_json_dict_shape() -> None:
    report = build_report(records={}, observations_by_source={}, node_ids=[], now=NOW)
    payload = render.report_to_json_dict(report)
    assert set(payload) == {
        "generated_at",
        "thresholds",
        "counts",
        "cache",
        "failures",
        "nodes",
    }
    assert payload["generated_at"] == "2026-08-25T12:00:00Z"


def test_build_table_returns_expected_columns() -> None:
    obs = _obs(SOURCE_LORANET, last_seen=NOW)
    report = build_report(
        records={}, observations_by_source={SOURCE_LORANET: {NID: obs}}, node_ids=[NID], now=NOW
    )
    table = render.build_table(report)
    headers = [str(col.header) for col in table.columns]
    assert headers == [
        "Node",
        "Short",
        "Long",
        "Mgmt",
        "Status",
        "Last seen",
        "Timestamp",
        "Batt",
        "Volt",
        "ChUtil",
        "AirTx",
        "Nbrs",
        "Sources",
    ]
