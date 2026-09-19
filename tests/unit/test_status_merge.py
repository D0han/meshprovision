"""Tests for meshprovision.status.merge and meshprovision.status.render."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

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
    _isoformat_z,
    _order_by_recency,
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

# A timestamp whose offset is neither UTC nor this machine's local zone, so
# that a dropped ``.astimezone(UTC)`` is observable in the rendered string
# instead of being masked by the test host's own timezone.
OFFSET_TIMESTAMP = datetime(2026, 8, 25, 8, 14, 10, tzinfo=timezone(timedelta(hours=5)))
OFFSET_TIMESTAMP_Z = "2026-08-25T03:14:10Z"


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


def test_unobserved_node_falls_back_to_database_names() -> None:
    """No source has ever seen this node, but its DB row has names.

    Regression test for `mesh status` showing "-" for Short/Long on a
    node whose names are known -- just not from loranet/lorastats.
    """
    record = NodeRecord(node_id="deadbe01", short_name="MT01", long_name="Meshtastic MT01")
    merged = merge_observations(NID, [], record=record, now=NOW)
    assert merged.short_name == "MT01"
    assert merged.long_name == "Meshtastic MT01"
    assert merged.sources == ()
    assert merged.availability is Availability.UNKNOWN


def test_observed_name_beats_database_name() -> None:
    """A live-reported name still wins over the database's own row."""
    record = NodeRecord(node_id="deadbe01", short_name="MT01", long_name="Meshtastic MT01")
    obs = _obs(SOURCE_LORANET, short_name="LNET", long_name="Loranet Long Name", last_seen=NOW)
    merged = merge_observations(NID, [obs], record=record, now=NOW)
    assert merged.short_name == "LNET"
    assert merged.long_name == "Loranet Long Name"


def test_observation_with_no_name_still_falls_back_to_database() -> None:
    """A node observed for telemetry but with no reported name gets the DB name."""
    record = NodeRecord(node_id="deadbe01", short_name="MT01", long_name="Meshtastic MT01")
    obs = _obs(SOURCE_LORANET, battery_level=90, last_seen=NOW)
    merged = merge_observations(NID, [obs], record=record, now=NOW)
    assert merged.short_name == "MT01"
    assert merged.long_name == "Meshtastic MT01"
    assert merged.sources == (SOURCE_LORANET,)


def test_blank_database_name_still_renders_as_unknown() -> None:
    """A DB row with names left at their default ("") is absent, not a real name."""
    record = NodeRecord(node_id="deadbe01")
    merged = merge_observations(NID, [], record=record, now=NOW)
    assert merged.short_name is None
    assert merged.long_name is None


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
        (0, "just now"),
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
        "management": "observed",
    }


def test_to_json_dict_top_level_name_falls_back_while_database_stays_the_raw_row() -> None:
    """The top-level name may fall back to the DB row; `"database"` never does.

    An unobserved node's top-level ``short_name``/``long_name`` come from
    the fallback (rule 4a), while the nested ``"database"`` object always
    reflects the row exactly as stored -- here the two happen to agree.
    """
    record = NodeRecord(node_id="deadbe01", short_name="MT01", long_name="Meshtastic MT01")
    merged = merge_observations(NID, [], record=record, now=NOW)
    payload = merged.to_json_dict()
    assert payload["short_name"] == "MT01"
    assert payload["long_name"] == "Meshtastic MT01"
    assert payload["database"]["short_name"] == "MT01"
    assert payload["database"]["long_name"] == "Meshtastic MT01"


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


def test_merge_all_tolerates_an_entirely_absent_source_key() -> None:
    """A source key missing from the mapping must not drop the later sources.

    Covers both ways a source can contribute nothing: the higher-priority
    ``loranet`` key is absent altogether, and ``emptysource`` is present
    but has no entry for this node. Neither may stop the scan, so every
    remaining source -- including an unrecognized extra one -- is still
    gathered.
    """
    lorastats_obs = _obs(SOURCE_LORASTATS, last_seen=NOW - timedelta(minutes=3))
    extra_obs = _obs("othersource", battery_level=64)

    merged = merge_all(
        {
            SOURCE_LORASTATS: {NID: lorastats_obs},
            "emptysource": {},
            "othersource": {NID: extra_obs},
        },
        node_ids=[NID],
        now=NOW,
    )

    assert merged[0].sources == (SOURCE_LORASTATS, "othersource")
    assert merged[0].last_seen == NOW - timedelta(minutes=3)
    assert merged[0].battery_level == 64


def test_merge_all_passes_custom_thresholds_through() -> None:
    """The ``thresholds`` argument must reach ``merge_observations``.

    The node below is ``ONLINE`` under the default thresholds and
    ``STALE`` under the custom ones, so a dropped passthrough that falls
    back to the default is visible in the classification.
    """
    obs = _obs(SOURCE_LORANET, last_seen=NOW - timedelta(minutes=30))
    thresholds = Thresholds(stale_after=timedelta(minutes=1), offline_after=timedelta(hours=1))

    default_merged = merge_all({SOURCE_LORANET: {NID: obs}}, node_ids=[NID], now=NOW)
    custom_merged = merge_all(
        {SOURCE_LORANET: {NID: obs}}, node_ids=[NID], now=NOW, thresholds=thresholds
    )

    assert default_merged[0].availability is Availability.ONLINE
    assert custom_merged[0].availability is Availability.STALE


def test_merge_observations_requires_timezone_aware_now() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        merge_observations(NID, [], now=datetime(2026, 1, 1))  # noqa: DTZ001


def test_merge_observations_carries_every_field_through() -> None:
    """Every ``MergedNode`` field must be wired from the winning observation.

    Guards the final ``MergedNode(...)`` construction as a whole: a
    regression that drops any single field back to its ``None`` default
    is silent everywhere else, because a merged node with one missing
    field still renders and still serializes.
    """
    last_seen = NOW - timedelta(minutes=30)
    loranet_obs = _obs(
        SOURCE_LORANET,
        last_seen=last_seen,
        short_name="LNET",
        long_name="Loranet Long Name",
        hw_model="HELTEC_V3",
        role="ROUTER",
        region="EU_868",
        firmware_version="2.7.11",
        latitude=52.2297,
        longitude=21.0122,
        altitude=113,
        battery_level=77,
        voltage=4.05,
        channel_utilization=12.5,
        air_util_tx=3.25,
        neighbor_count=6,
        uptime_seconds=98765,
    )
    lorastats_obs = _obs(
        SOURCE_LORASTATS,
        last_seen=NOW - timedelta(hours=6),
        short_name="LSTA",
        long_name="Lorastats Long Name",
        hw_model="TBEAM",
        role="CLIENT",
        region="US",
        firmware_version="2.6.0",
        latitude=50.0619,
        longitude=19.9369,
        altitude=219,
        battery_level=41,
        voltage=3.71,
        channel_utilization=44.5,
        air_util_tx=9.75,
        neighbor_count=2,
        uptime_seconds=12345,
    )
    record = NodeRecord(node_id="deadbe01")

    merged = merge_observations(NID, [lorastats_obs, loranet_obs], record=record, now=NOW)

    assert merged.node_id == NID
    assert merged.record is record
    assert merged.sources == (SOURCE_LORANET, SOURCE_LORASTATS)
    assert merged.short_name == "LNET"
    assert merged.long_name == "Loranet Long Name"
    assert merged.hw_model == "HELTEC_V3"
    assert merged.role == "ROUTER"
    assert merged.region == "EU_868"
    assert merged.firmware_version == "2.7.11"
    assert merged.latitude == 52.2297
    assert merged.longitude == 21.0122
    assert merged.altitude == 113
    assert merged.battery_level == 77
    assert merged.voltage == 4.05
    assert merged.channel_utilization == 12.5
    assert merged.air_util_tx == 3.25
    assert merged.neighbor_count == 6
    assert merged.uptime_seconds == 98765
    assert merged.last_seen == last_seen
    assert merged.last_seen_source == SOURCE_LORANET
    assert merged.age == timedelta(minutes=30)
    assert merged.age_text == "30 minutes ago"
    assert merged.availability is Availability.ONLINE


def test_more_recent_observation_wins_for_identity_fields() -> None:
    """A renamed node shows its newest name, even from a lower-priority source.

    This is the module docstring's headline example: identity fields
    resolve in *recency* order, not :data:`SOURCE_PRIORITY` order, while
    telemetry fields still resolve by priority.
    """
    stale_loranet = _obs(
        SOURCE_LORANET,
        last_seen=NOW - timedelta(hours=8),
        short_name="OLD_",
        long_name="Old Name",
        battery_level=11,
    )
    fresh_lorastats = _obs(
        SOURCE_LORASTATS,
        last_seen=NOW - timedelta(minutes=1),
        short_name="NEW_",
        long_name="New Name",
        battery_level=22,
    )

    merged = merge_observations(NID, [stale_loranet, fresh_lorastats], now=NOW)

    assert merged.short_name == "NEW_"
    assert merged.long_name == "New Name"
    assert merged.battery_level == 11


def test_order_by_recency_is_most_recent_first_with_none_last() -> None:
    oldest = _obs(SOURCE_LORANET, last_seen=NOW - timedelta(hours=5), short_name="old_")
    never = _obs(SOURCE_LORANET, last_seen=None, short_name="none")
    newest = _obs(SOURCE_LORASTATS, last_seen=NOW - timedelta(minutes=1), short_name="new_")

    ordered = _order_by_recency([oldest, never, newest])

    assert [obs.short_name for obs in ordered] == ["new_", "old_", "none"]


def test_identity_fields_skip_an_observation_without_last_seen() -> None:
    """An observation with no ``last_seen`` must not outrank a dated one."""
    undated_loranet = _obs(SOURCE_LORANET, last_seen=None, short_name="NULL")
    dated = _obs(SOURCE_LORASTATS, last_seen=NOW - timedelta(hours=3), short_name="SEEN")

    merged = merge_observations(NID, [undated_loranet, dated], now=NOW)

    assert merged.short_name == "SEEN"


def test_last_seen_falls_through_a_higher_priority_source_that_has_none() -> None:
    """A missing ``last_seen`` on loranet must not abandon the whole scan."""
    loranet_obs = _obs(SOURCE_LORANET, last_seen=None, battery_level=50)
    lorastats_obs = _obs(SOURCE_LORASTATS, last_seen=NOW - timedelta(minutes=10))

    merged = merge_observations(NID, [loranet_obs, lorastats_obs], now=NOW)

    assert merged.last_seen == NOW - timedelta(minutes=10)
    assert merged.last_seen_source == SOURCE_LORASTATS
    assert merged.availability is Availability.ONLINE
    assert merged.age_text == "10 minutes ago"


def test_last_seen_exact_tie_goes_to_the_higher_priority_source() -> None:
    tied = NOW - timedelta(minutes=7)
    loranet_obs = _obs(SOURCE_LORANET, last_seen=tied)
    lorastats_obs = _obs(SOURCE_LORASTATS, last_seen=tied)

    merged = merge_observations(NID, [lorastats_obs, loranet_obs], now=NOW)

    assert merged.last_seen == tied
    assert merged.last_seen_source == SOURCE_LORANET


def test_observed_node_that_no_source_has_ever_dated() -> None:
    """Observed but with no ``last_seen`` anywhere is ``UNKNOWN``, not ``ONLINE``."""
    loranet_obs = _obs(SOURCE_LORANET, last_seen=None, battery_level=50)
    lorastats_obs = _obs(SOURCE_LORASTATS, last_seen=None, short_name="abcd")

    merged = merge_observations(NID, [loranet_obs, lorastats_obs], now=NOW)

    assert merged.last_seen is None
    assert merged.last_seen_source is None
    assert merged.age is None
    assert merged.age_text == "never"
    assert merged.availability is Availability.UNKNOWN
    assert merged.observed is True
    assert merged.battery_level == 50
    assert merged.short_name == "abcd"


def test_isoformat_z_normalizes_a_non_utc_offset() -> None:
    assert _isoformat_z(OFFSET_TIMESTAMP) == OFFSET_TIMESTAMP_Z
    assert _isoformat_z(None) is None


def test_to_json_dict_last_seen_is_utc_normalized() -> None:
    obs = _obs(SOURCE_LORANET, last_seen=OFFSET_TIMESTAMP)
    merged = merge_observations(NID, [obs], now=NOW)
    assert merged.to_json_dict()["last_seen"] == OFFSET_TIMESTAMP_Z


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


def test_status_report_degraded_and_exit_code_with_skipped_entries() -> None:
    """Regression test: a mass parse-failure must not look identical to "all clean".

    Without this, a source that runs successfully but silently drops a
    large fraction of its entries is indistinguishable from a report
    where every node genuinely responded -- the operator has no signal
    at all unless they tail WARNING logs.
    """
    report = StatusReport(
        generated_at=NOW,
        nodes=(),
        thresholds=Thresholds(),
        skipped_entries={"loranet": 12},
    )
    assert report.degraded is True
    assert report.exit_code(fail_on_offline=False) != 0


def test_status_report_summary_text() -> None:
    report = build_report(records={}, observations_by_source={}, node_ids=[], now=NOW)
    assert "0 node(s)" in report.summary()


def test_status_report_summary_mentions_skipped_entries() -> None:
    report = StatusReport(
        generated_at=NOW,
        nodes=(),
        thresholds=Thresholds(),
        skipped_entries={"loranet": 12, "lorastats": 1},
    )
    summary = report.summary()
    assert "13 unparsable entrie(s)" in summary
    assert "12 from loranet" in summary
    assert "1 from lorastats" in summary


def test_status_report_degraded_and_exit_code_with_field_coercions() -> None:
    """Regression test: a source silently zeroing out one field must be visible too.

    Distinct from skipped_entries: the entry itself parsed fine, only
    one field within it didn't coerce -- without this, a mass field-level
    drop (an upstream schema rename, for example) is invisible.
    """
    report = StatusReport(
        generated_at=NOW,
        nodes=(),
        thresholds=Thresholds(),
        field_coercions={"loranet": 5},
    )
    assert report.degraded is True
    assert report.exit_code(fail_on_offline=False) != 0


def test_status_report_summary_mentions_field_coercions() -> None:
    report = StatusReport(
        generated_at=NOW,
        nodes=(),
        thresholds=Thresholds(),
        field_coercions={"loranet": 5, "lorastats": 2},
    )
    summary = report.summary()
    assert "7 uncoercible field(s)" in summary
    assert "5 from loranet" in summary
    assert "2 from lorastats" in summary


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
    last_fetch_skipped = 0
    last_fetch_field_coercions = 0

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


class _PartiallySkippingSource:
    name = "loranet"
    last_fetch_skipped = 7
    last_fetch_field_coercions = 0

    def fetch_nodes(
        self,
        ids,  # noqa: ARG002
        *,
        force_refresh=False,  # noqa: ARG002
    ) -> dict[NodeId, NodeObservation]:
        return {NID: _obs("loranet")}


def test_collect_observations_tolerates_one_failure() -> None:
    observations, failures, skipped, field_coercions = collect_observations(
        [_FailingSource(), _OkSource()], [NID]
    )
    assert "loranet" not in observations
    assert "lorastats" in observations
    assert len(failures) == 1
    assert failures[0].source == "loranet"
    assert skipped == {}
    assert field_coercions == {}


def test_collect_observations_reports_skipped_entries_for_a_successful_source() -> None:
    """A source that succeeds but skipped entries must be visible, not silently absent."""
    observations, failures, skipped, field_coercions = collect_observations(
        [_PartiallySkippingSource(), _OkSource()], [NID]
    )
    assert failures == ()
    assert "loranet" in observations
    assert skipped == {"loranet": 7}
    assert "lorastats" not in skipped
    assert field_coercions == {}


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
        "skipped_entries",
        "field_coercions",
        "nodes",
    }
    assert payload["generated_at"] == "2026-08-25T12:00:00Z"


def test_report_to_json_dict_includes_skipped_entries() -> None:
    report = StatusReport(
        generated_at=NOW,
        nodes=(),
        thresholds=Thresholds(),
        skipped_entries={"loranet": 12},
    )
    payload = render.report_to_json_dict(report)
    assert payload["skipped_entries"] == {"loranet": 12}


def test_report_to_json_dict_includes_field_coercions() -> None:
    report = StatusReport(
        generated_at=NOW,
        nodes=(),
        thresholds=Thresholds(),
        field_coercions={"loranet": 5},
    )
    payload = render.report_to_json_dict(report)
    assert payload["field_coercions"] == {"loranet": 5}


def test_build_table_caption_mentions_skipped_entries() -> None:
    obs = _obs(SOURCE_LORANET, last_seen=NOW)
    base_report = build_report(
        records={}, observations_by_source={SOURCE_LORANET: {NID: obs}}, node_ids=[NID], now=NOW
    )
    report = StatusReport(
        generated_at=base_report.generated_at,
        nodes=base_report.nodes,
        thresholds=base_report.thresholds,
        skipped_entries={"loranet": 12},
    )
    table = render.build_table(report)
    assert table.caption is not None
    assert "12 entrie(s) could not be parsed" in str(table.caption)


def test_build_table_caption_mentions_field_coercions() -> None:
    obs = _obs(SOURCE_LORANET, last_seen=NOW)
    base_report = build_report(
        records={}, observations_by_source={SOURCE_LORANET: {NID: obs}}, node_ids=[NID], now=NOW
    )
    report = StatusReport(
        generated_at=base_report.generated_at,
        nodes=base_report.nodes,
        thresholds=base_report.thresholds,
        field_coercions={"loranet": 5},
    )
    table = render.build_table(report)
    assert table.caption is not None
    assert "5 field(s) could not be coerced" in str(table.caption)


def test_timestamp_cell_normalizes_a_non_utc_offset() -> None:
    assert render._timestamp_cell(OFFSET_TIMESTAMP) == OFFSET_TIMESTAMP_Z
    assert render._timestamp_cell(None) == "-"


def test_build_table_timestamp_column_renders_utc() -> None:
    obs = _obs(SOURCE_LORANET, last_seen=OFFSET_TIMESTAMP)
    report = build_report(
        records={}, observations_by_source={SOURCE_LORANET: {NID: obs}}, node_ids=[NID], now=NOW
    )
    table = render.build_table(report)
    timestamp_column = table.columns[6]
    assert [str(cell) for cell in timestamp_column.cells] == [OFFSET_TIMESTAMP_Z]


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
