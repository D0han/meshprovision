"""Tests for meshprovision.datasources.models, loranet, and lorastats."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import respx

from meshprovision.cache.http import CachedHTTPClient
from meshprovision.datasources import loranet as loranet_module
from meshprovision.datasources import lorastats as lorastats_module
from meshprovision.datasources.base import SOURCE_LORANET, BaseHTTPDataSource
from meshprovision.datasources.loranet import LORANET_NODES_URL, LoranetSource, parse_node
from meshprovision.datasources.lorastats import (
    LORASTATS_BASE_URL,
    LORASTATS_NODES_PATH,
    LorastatsSource,
    validate_regions,
)
from meshprovision.datasources.models import (
    CoercionTracker,
    NodeObservation,
    coerce_bool,
    coerce_float,
    coerce_int,
    coerce_str,
    e7_to_degrees,
    parse_epoch,
    parse_iso8601,
)
from meshprovision.enums import role_table
from meshprovision.errors import InvalidResponseError, MissingContactError, SettingsError
from meshprovision.nodeid import NodeId

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# models.py coercion helpers.
# ---------------------------------------------------------------------------


def test_coerce_float() -> None:
    assert coerce_float(1) == 1.0
    assert coerce_float(1.5) == 1.5
    assert coerce_float("2.5") == 2.5
    assert coerce_float(True) is None
    assert coerce_float(float("nan")) is None
    assert coerce_float(float("inf")) is None
    assert coerce_float("garbage") is None
    assert coerce_float(None) is None


def test_coerce_int() -> None:
    assert coerce_int(5) == 5
    assert coerce_int(True) is None
    assert coerce_int("42") == 42
    assert coerce_int("not-a-digit") is None


def test_coerce_bool() -> None:
    assert coerce_bool(0) is False
    assert coerce_bool(1) is True
    assert coerce_bool(True) is True
    assert coerce_bool("true") is True
    assert coerce_bool("false") is False
    assert coerce_bool(2) is None
    assert coerce_bool("maybe") is None


def test_coerce_str() -> None:
    assert coerce_str("  hi  ") == "hi"
    assert coerce_str("   ") is None
    assert coerce_str(5) is None


def test_e7_to_degrees() -> None:
    assert e7_to_degrees(500000000, limit=90.0) == 50.0
    assert e7_to_degrees(True, limit=90.0) is None
    assert e7_to_degrees(999999999999, limit=90.0) is None


def test_e7_to_degrees_accepts_the_exact_inclusive_limit() -> None:
    """The limit check is inclusive: exactly +/-90 / +/-180 is a real coordinate.

    The North/South poles and the antimeridian are valid positions, so
    ``-limit <= degrees <= limit`` must not tighten to a strict ``<``.
    """
    assert e7_to_degrees(900_000_000, limit=90.0) == 90.0
    assert e7_to_degrees(-900_000_000, limit=90.0) == -90.0
    assert e7_to_degrees(1_800_000_000, limit=180.0) == 180.0
    assert e7_to_degrees(-1_800_000_000, limit=180.0) == -180.0

    # One E7 tick past the limit is out of range in both directions.
    assert e7_to_degrees(900_000_001, limit=90.0) is None
    assert e7_to_degrees(-900_000_001, limit=90.0) is None
    assert e7_to_degrees(1_800_000_001, limit=180.0) is None
    assert e7_to_degrees(-1_800_000_001, limit=180.0) is None


def test_parse_epoch() -> None:
    result = parse_epoch(1_700_000_000)
    assert result is not None
    assert result.tzinfo is not None
    assert parse_epoch(0) is None
    assert parse_epoch(-1) is None
    assert parse_epoch(True) is None


def test_parse_iso8601_z_suffix() -> None:
    result = parse_iso8601("2026-08-25T03:14:10Z")
    assert result == datetime(2026, 8, 25, 3, 14, 10, tzinfo=UTC)


def test_parse_iso8601_explicit_offset() -> None:
    result = parse_iso8601("2026-08-25T03:14:10+02:00")
    assert result == datetime(2026, 8, 25, 1, 14, 10, tzinfo=UTC)


def test_parse_iso8601_naive_summer_warsaw_is_utc_plus_2() -> None:
    # Warsaw is UTC+2 in summer (CEST).
    result = parse_iso8601("2026-07-15T12:00:00")
    assert result == datetime(2026, 7, 15, 10, 0, 0, tzinfo=UTC)


def test_parse_iso8601_naive_winter_warsaw_is_utc_plus_1() -> None:
    # Warsaw is UTC+1 in winter (CET).
    result = parse_iso8601("2026-01-15T12:00:00")
    assert result == datetime(2026, 1, 15, 11, 0, 0, tzinfo=UTC)


def test_parse_iso8601_rejects_a_lowercase_z_suffix() -> None:
    """Only an uppercase ``Z`` is the ISO 8601 UTC designator.

    The ``endswith("Z")`` rewrite is deliberately case-sensitive, and
    ``datetime.fromisoformat`` rejects a lowercase ``z`` outright -- so a
    lowercase-suffixed timestamp must come back ``None`` rather than
    being silently parsed as a naive local time and shifted by the
    assumed offset.
    """
    assert parse_iso8601("2026-01-01T10:00:00z") is None
    assert parse_iso8601("2026-01-01T10:00:00Z") == datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)


def test_parse_iso8601_naive_uses_the_given_assume_tz_not_utc_or_system_local() -> None:
    """Regression test: a naive parse must attach ``assume_tz``, not fall back to local time.

    ``parsed.replace(tzinfo=assume_tz)`` regressing to ``tzinfo=None``
    would be invisible whenever the machine running the tests happens to
    share LORASTATS_NAIVE_TZ (Europe/Warsaw), because ``astimezone()`` on
    a naive datetime assumes system local time and lands on the same
    answer. Passing an explicit, deliberately different offset makes the
    assumption load-bearing regardless of the host's timezone.
    """
    tokyo = timezone(timedelta(hours=9))

    # 2026-01-15 12:00 at UTC+9 is 03:00 UTC. Neither UTC (12:00) nor
    # Europe/Warsaw in winter (11:00) produces this answer.
    assert parse_iso8601("2026-01-15T12:00:00", assume_tz=tokyo) == datetime(
        2026, 1, 15, 3, 0, 0, tzinfo=UTC
    )

    # A value that already carries an offset ignores assume_tz entirely.
    assert parse_iso8601("2026-01-15T12:00:00+00:00", assume_tz=tokyo) == datetime(
        2026, 1, 15, 12, 0, 0, tzinfo=UTC
    )


def test_node_observation_rejects_naive_datetime() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        NodeObservation(
            node_id="deadbe01",
            source="loranet",
            observed_at=datetime(2026, 1, 1),  # noqa: DTZ001 -- deliberately naive
        )


def test_node_observation_coerces_node_id() -> None:
    obs = NodeObservation(node_id="deadbe01", source="loranet", observed_at=datetime.now(tz=UTC))
    assert obs.node_id == NodeId.from_hex("deadbe01")


def test_coercion_tracker_counts_only_present_but_uncoercible_values() -> None:
    tracker = CoercionTracker()

    # Absent (None) is never a failure -- the field simply wasn't reported.
    assert tracker.coerce(None, coerce_int) is None
    assert tracker.failures == 0

    # Present but uncoercible IS a failure, and the coerced result is
    # still returned (None), consistent with coerce_*'s own contract.
    assert tracker.coerce("not-a-number", coerce_int) is None
    assert tracker.failures == 1

    # Present and coercible is never a failure.
    assert tracker.coerce("5", coerce_int) == 5
    assert tracker.failures == 1


# ---------------------------------------------------------------------------
# base.py: BaseHTTPDataSource.get_json.
# ---------------------------------------------------------------------------


class _RecordingClient:
    """A CachedHTTPClient stand-in that records the kwargs of every get()."""

    def __init__(self, payload: object) -> None:
        self.payload = payload
        self.calls: list[dict[str, object]] = []

    def get(self, url: str, **kwargs: object) -> object:
        self.calls.append({"url": url, **kwargs})
        payload = self.payload
        return type("_Response", (), {"json": staticmethod(lambda: payload)})()


def test_get_json_threads_ttl_params_and_source_through_to_the_client() -> None:
    """Regression test: every get_json kwarg must reach CachedHTTPClient.get().

    ``ttl=`` in particular is the caller's freshness-window override; a
    dropped (or hard-coded ``None``) passthrough would silently fall back
    to the client's default TTL, so a caller asking for a tighter window
    would keep being served a stale cache entry with no visible symptom.
    """
    client = _RecordingClient({"ok": True})
    source = BaseHTTPDataSource(client, source_name=SOURCE_LORANET)  # type: ignore[arg-type]

    assert source.get_json(
        "https://example.invalid/x",
        params={"node": "deadbe01"},
        ttl=12.5,
        force_refresh=True,
    ) == {"ok": True}

    assert client.calls == [
        {
            "url": "https://example.invalid/x",
            "params": {"node": "deadbe01"},
            "ttl": 12.5,
            "force_refresh": True,
            "source": SOURCE_LORANET,
        }
    ]


def test_get_json_defaults_leave_ttl_and_force_refresh_to_the_client() -> None:
    """With no overrides, get_json must pass None -- not invent a default."""
    client = _RecordingClient([])
    source = BaseHTTPDataSource(client, source_name=SOURCE_LORANET)  # type: ignore[arg-type]

    source.get_json("https://example.invalid/y")

    assert client.calls == [
        {
            "url": "https://example.invalid/y",
            "params": None,
            "ttl": None,
            "force_refresh": None,
            "source": SOURCE_LORANET,
        }
    ]


# ---------------------------------------------------------------------------
# lorastats: parse_node.
# ---------------------------------------------------------------------------


def test_lorastats_parse_node_maps_enums() -> None:
    obs = lorastats_module.parse_node(
        {"NodeId": "deadbe01", "ShortName": "abcd", "LongName": "A Node", "Role": 0, "HwModel": 9},
        region="PL",
        observed_at=datetime.now(tz=UTC),
    )
    assert obs is not None
    assert obs.role == "CLIENT"
    assert obs.hw_model == "RAK4631"
    assert obs.short_name == "abcd"


def test_lorastats_parse_node_uncoercible_timestamps_counted_as_field_coercions() -> None:
    """LastSeen/LastBoot must route through the tracker like every other field."""
    tracker = CoercionTracker()
    obs = lorastats_module.parse_node(
        {"NodeId": "deadbe01", "LastSeen": "not-a-timestamp", "LastBoot": "also-not-one"},
        region="PL",
        observed_at=datetime.now(tz=UTC),
        coercion_tracker=tracker,
    )
    assert obs is not None
    assert obs.last_seen is None
    assert obs.last_boot is None
    assert tracker.failures == 2


def test_lorastats_parse_node_missing_node_id_returns_none() -> None:
    assert lorastats_module.parse_node({}, region="PL", observed_at=datetime.now(tz=UTC)) is None


def test_lorastats_parse_node_unparsable_node_id_returns_none() -> None:
    assert (
        lorastats_module.parse_node(
            {"NodeId": "zzzz"}, region="PL", observed_at=datetime.now(tz=UTC)
        )
        is None
    )


def test_validate_regions_strips_dedups_rejects() -> None:
    assert validate_regions([" PL ", "PL", "US"]) == ("PL", "US")
    with pytest.raises(SettingsError):
        validate_regions([])
    with pytest.raises(SettingsError):
        validate_regions(["   "])
    with pytest.raises(SettingsError):
        validate_regions(["bad region!"])


def test_lorastats_blank_contact_raises(tmp_path: Path) -> None:
    from meshprovision.cache.http import CachedHTTPClient as _Client

    client = _Client(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    try:
        with pytest.raises(MissingContactError):
            LorastatsSource(client, contact="   ")
    finally:
        client.close()


@respx.mock
def test_lorastats_fetch_node_empty_array_returns_none(tmp_path: Path) -> None:
    respx.get(
        url__startswith=f"{LORASTATS_BASE_URL}{LORASTATS_NODES_PATH.format(region='PL')}"
    ).mock(return_value=httpx.Response(200, json=[]))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LorastatsSource(client, contact="t@example.invalid")
    assert source.fetch_node("deadbe01") is None


@respx.mock
def test_lorastats_fetch_node_matches_by_node_id(tmp_path: Path) -> None:
    records = [{"NodeId": "aaaaaaaa"}, {"NodeId": "deadbe01", "ShortName": "found"}]
    respx.get(
        url__startswith=f"{LORASTATS_BASE_URL}{LORASTATS_NODES_PATH.format(region='PL')}"
    ).mock(return_value=httpx.Response(200, json=records))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LorastatsSource(client, contact="t@example.invalid")
    obs = source.fetch_node("deadbe01")
    assert obs is not None
    assert obs.short_name == "found"


@respx.mock
def test_lorastats_present_but_uncoercible_field_counted_as_a_field_coercion_not_a_skip(
    tmp_path: Path,
) -> None:
    """A malformed-but-present field must not be conflated with a whole-record skip."""
    records = [{"NodeId": "deadbe01", "ShortName": "found", "Role": "not-a-number"}]
    respx.get(
        url__startswith=f"{LORASTATS_BASE_URL}{LORASTATS_NODES_PATH.format(region='PL')}"
    ).mock(return_value=httpx.Response(200, json=records))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LorastatsSource(client, contact="t@example.invalid")

    obs = source.fetch_node("deadbe01")

    assert obs is not None
    assert obs.short_name == "found"
    assert obs.role_value is None
    assert source.last_fetch_skipped == 0
    assert source.last_fetch_field_coercions == 1


@respx.mock
def test_lorastats_fetch_node_ignores_a_record_for_a_different_node(tmp_path: Path) -> None:
    records = [{"NodeId": "aaaaaaaa", "ShortName": "fallback"}]
    route = respx.get(
        url__startswith=f"{LORASTATS_BASE_URL}{LORASTATS_NODES_PATH.format(region='PL')}"
    ).mock(return_value=httpx.Response(200, json=records))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LorastatsSource(client, contact="t@example.invalid")
    assert source.fetch_node("deadbe01") is None
    assert route.called  # the request was made; None is a match failure, not a short-circuit


@respx.mock
def test_lorastats_fetch_node_tolerant_id_forms_still_match(tmp_path: Path) -> None:
    records = [{"NodeId": "!DEADBE01", "ShortName": "found"}]
    respx.get(
        url__startswith=f"{LORASTATS_BASE_URL}{LORASTATS_NODES_PATH.format(region='PL')}"
    ).mock(return_value=httpx.Response(200, json=records))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LorastatsSource(client, contact="t@example.invalid")
    obs = source.fetch_node("deadbe01")
    assert obs is not None
    assert obs.short_name == "found"


@respx.mock
def test_lorastats_fetch_node_tries_next_region_after_a_malformed_record(tmp_path: Path) -> None:
    respx.get(
        url__startswith=f"{LORASTATS_BASE_URL}{LORASTATS_NODES_PATH.format(region='PL')}"
    ).mock(return_value=httpx.Response(200, json=[{"ShortName": "no id"}]))
    respx.get(
        url__startswith=f"{LORASTATS_BASE_URL}{LORASTATS_NODES_PATH.format(region='XX')}"
    ).mock(return_value=httpx.Response(200, json=[{"NodeId": "deadbe01", "ShortName": "found"}]))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LorastatsSource(client, contact="t@example.invalid", regions=("PL", "XX"))
    obs = source.fetch_node("deadbe01")
    assert obs is not None
    assert obs.short_name == "found"
    assert source.last_fetch_skipped == 1


@respx.mock
def test_lorastats_fetch_nodes_last_fetch_skipped_sums_across_ids_and_resets(
    tmp_path: Path,
) -> None:
    """Regression test: last_fetch_skipped sums per-id skips and resets between calls."""
    respx.get(
        url__startswith=f"{LORASTATS_BASE_URL}{LORASTATS_NODES_PATH.format(region='PL')}"
    ).mock(return_value=httpx.Response(200, json=[{"ShortName": "no id"}]))
    respx.get(
        url__startswith=f"{LORASTATS_BASE_URL}{LORASTATS_NODES_PATH.format(region='XX')}"
    ).mock(return_value=httpx.Response(200, json=[{"NodeId": "deadbe01", "ShortName": "found"}]))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LorastatsSource(client, contact="t@example.invalid", regions=("PL",))

    # Neither id is found (the only PL record is malformed), but each of
    # the two lookups still skips exactly one malformed record while
    # scanning for its match -- 1 + 1 = 2.
    result = source.fetch_nodes([NodeId.from_hex("deadbe01"), NodeId.from_hex("deadbe02")])
    assert result == {}
    assert source.last_fetch_skipped == 2

    # A subsequent clean lookup (region XX, one well-formed matching
    # record, matched on the first record scanned) must reset the
    # counter to 0, not accumulate on top of the dirty call above.
    clean = source.fetch_node("deadbe01", region="XX")
    assert clean is not None
    assert source.last_fetch_skipped == 0


@respx.mock
def test_lorastats_fetch_nodes_never_files_an_observation_under_a_foreign_id(
    tmp_path: Path,
) -> None:
    records = [{"NodeId": "deadbeef", "ShortName": "wrong node"}]
    respx.get(
        url__startswith=f"{LORASTATS_BASE_URL}{LORASTATS_NODES_PATH.format(region='PL')}"
    ).mock(return_value=httpx.Response(200, json=records))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LorastatsSource(client, contact="t@example.invalid")
    assert source.fetch_nodes([NodeId.from_hex("cafefeed")]) == {}


@respx.mock
def test_lorastats_fetch_node_passes_lowercase_hex_query(tmp_path: Path) -> None:
    route = respx.get(
        url__startswith=f"{LORASTATS_BASE_URL}{LORASTATS_NODES_PATH.format(region='PL')}"
    ).mock(return_value=httpx.Response(200, json=[]))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LorastatsSource(client, contact="t@example.invalid")
    source.fetch_node("DEADBE01")
    assert route.calls[0].request.url.params.get("node") == "deadbe01"


@respx.mock
def test_lorastats_html_body_raises_invalid_response(tmp_path: Path) -> None:
    respx.get(
        url__startswith=f"{LORASTATS_BASE_URL}{LORASTATS_NODES_PATH.format(region='PL')}"
    ).mock(return_value=httpx.Response(200, html="<html>nope</html>"))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LorastatsSource(client, contact="t@example.invalid")
    with pytest.raises(InvalidResponseError):
        source.fetch_node("deadbe01")


@respx.mock
def test_lorastats_json_object_instead_of_array_raises(tmp_path: Path) -> None:
    respx.get(
        url__startswith=f"{LORASTATS_BASE_URL}{LORASTATS_NODES_PATH.format(region='PL')}"
    ).mock(return_value=httpx.Response(200, json={"not": "a list"}))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LorastatsSource(client, contact="t@example.invalid")
    with pytest.raises(InvalidResponseError):
        source.fetch_node("deadbe01")


@respx.mock
def test_lorastats_node_status_maps_statuses(tmp_path: Path) -> None:
    from meshprovision.datasources.lorastats import LORASTATS_STATUS_PATH

    url = f"{LORASTATS_BASE_URL}{LORASTATS_STATUS_PATH.format(node='deadbe01')}"
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LorastatsSource(client, contact="t@example.invalid")

    respx.get(url).mock(return_value=httpx.Response(200, text="ok"))
    assert source.node_status("deadbe01") is True

    respx.get(url).mock(return_value=httpx.Response(500))
    assert source.node_status("deadbe01", force_refresh=True) is False

    respx.get(url).mock(return_value=httpx.Response(404))
    assert source.node_status("deadbe01", force_refresh=True) is None


# ---------------------------------------------------------------------------
# loranet.
# ---------------------------------------------------------------------------


@respx.mock
def test_loranet_raw_index_memoizes(tmp_path: Path) -> None:
    route = respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json={}))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LoranetSource(client)

    source.raw_index()
    source.fetch_nodes([NodeId.from_hex("deadbe01")])
    assert route.call_count == 1


@respx.mock
def test_loranet_raw_index_memo_short_circuits_before_get_json(tmp_path: Path, monkeypatch) -> None:
    """Regression test: the in-memory memo must be observed in isolation.

    Counting the respx route's calls cannot see this guard at all: the
    injected CachedHTTPClient's own disk-backed TTL cache sits between
    raw_index() and the network, so a fully broken memo still produces
    exactly one network request. Spying on get_json -- the boundary the
    memo actually short-circuits -- is what makes the guard observable.
    """
    respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json={}))
    client = CachedHTTPClient(
        cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)", ttl=10000
    )
    source = LoranetSource(client)
    real_get_json = source.get_json
    calls = 0

    def counting_get_json(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return real_get_json(*args, **kwargs)

    monkeypatch.setattr(source, "get_json", counting_get_json)

    source.raw_index()
    assert calls == 1

    # Second call, force_refresh left unset: the memo must serve it
    # without touching get_json at all.
    source.raw_index()
    assert calls == 1

    # ...and so must every downstream consumer of the memo.
    source.fetch_all()
    source.fetch_nodes([NodeId.from_hex("deadbe01")])
    assert calls == 1


@respx.mock
def test_loranet_raw_index_force_refresh_returns_the_fresh_value_over_a_live_memo(
    tmp_path: Path,
) -> None:
    """Regression test: force_refresh must beat an already-populated memo.

    Unlike the invalidate() test, this deliberately leaves ``_index``
    populated -- inverting the guard to ``... and force_refresh`` would
    otherwise hand back the stale memo here, while a test that clears the
    memo first cannot tell the two apart.
    """
    key = NodeId.from_hex("deadbe01").decimal
    route = respx.get(LORANET_NODES_URL).mock(
        return_value=httpx.Response(200, json={key: {"shortName": "stale"}})
    )
    client = CachedHTTPClient(
        cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)", ttl=10000
    )
    source = LoranetSource(client)

    assert source.raw_index()[key]["shortName"] == "stale"

    route.mock(return_value=httpx.Response(200, json={key: {"shortName": "fresh"}}))
    assert source.raw_index(force_refresh=True)[key]["shortName"] == "fresh"

    # The refreshed value replaces the memo, so a following default call
    # serves "fresh" too -- never the resurrected original.
    assert source.raw_index()[key]["shortName"] == "fresh"


@respx.mock
def test_loranet_invalidate_drops_memo(tmp_path: Path) -> None:
    route = respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json={}))
    client = CachedHTTPClient(
        cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)", ttl=10000
    )
    source = LoranetSource(client)
    source.raw_index()
    source.invalidate()
    source.raw_index(force_refresh=True)
    assert route.call_count == 2


@respx.mock
def test_loranet_decimal_key_parsed_with_from_decimal(tmp_path: Path) -> None:
    nid = NodeId.from_hex("deadbe01")
    payload = {nid.decimal: {"shortName": "abcd"}}
    respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json=payload))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LoranetSource(client)

    result = source.fetch_all()
    assert nid in result
    assert result[nid].short_name == "abcd"


@respx.mock
def test_loranet_zero_zero_position_becomes_none(tmp_path: Path) -> None:
    nid = NodeId.from_hex("deadbe01")
    payload = {nid.decimal: {"latitude": 0, "longitude": 0}}
    respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json=payload))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LoranetSource(client)

    result = source.fetch_all()
    assert result[nid].latitude is None
    assert result[nid].longitude is None


@respx.mock
def test_loranet_seen_by_derives_neighbor_count_and_last_seen(tmp_path: Path) -> None:
    nid = NodeId.from_hex("deadbe01")
    payload = {nid.decimal: {"seenBy": {"gw1": 1_700_000_000, "gw2": 1_700_000_100}}}
    respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json=payload))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LoranetSource(client)

    result = source.fetch_all()
    obs = result[nid]
    assert obs.neighbor_count == 2
    assert obs.seen_by == ("gw1", "gw2")
    assert obs.last_seen == datetime.fromtimestamp(1_700_000_100, tz=UTC)


@respx.mock
def test_loranet_last_seen_prefers_the_most_recent_of_all_three_activity_signals(
    tmp_path: Path,
) -> None:
    """Regression test: last_seen must reflect ALL of a node's activity signals.

    last_seen is documented as "the node's most recent activity," not
    "the most recent seenBy relay" -- a device-metrics or map report is
    just as much activity, and ignoring them could report a node
    STALE/OFFLINE minutes after it was genuinely active.
    """
    nid = NodeId.from_hex("deadbe01")
    payload = {
        nid.decimal: {
            "seenBy": {"gw1": 1_700_000_000},  # oldest
            "lastMapReport": 1_700_000_500,  # middle
            "lastDeviceMetrics": 1_700_000_900,  # most recent -- must win
        }
    }
    respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json=payload))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LoranetSource(client)

    result = source.fetch_all()
    obs = result[nid]
    assert obs.last_seen == datetime.fromtimestamp(1_700_000_900, tz=UTC)
    assert obs.last_device_metrics == datetime.fromtimestamp(1_700_000_900, tz=UTC)
    assert obs.last_map_report == datetime.fromtimestamp(1_700_000_500, tz=UTC)


@respx.mock
def test_loranet_last_seen_falls_back_to_device_metrics_with_no_seen_by(tmp_path: Path) -> None:
    nid = NodeId.from_hex("deadbe01")
    payload = {nid.decimal: {"lastDeviceMetrics": 1_700_000_900}}
    respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json=payload))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LoranetSource(client)

    result = source.fetch_all()
    obs = result[nid]
    assert obs.neighbor_count is None
    assert obs.last_seen == datetime.fromtimestamp(1_700_000_900, tz=UTC)


@respx.mock
def test_loranet_malformed_entry_skipped_not_fatal(tmp_path: Path) -> None:
    good_nid = NodeId.from_hex("deadbe01")
    payload = {
        good_nid.decimal: {"shortName": "good"},
        "not-a-decimal-key": {"shortName": "bad"},
        "9999999999": "not-a-dict",
    }
    respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json=payload))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LoranetSource(client)

    result = source.fetch_all()
    assert good_nid in result
    assert len(result) == 1
    assert source.last_fetch_skipped == 2


@respx.mock
def test_loranet_present_but_uncoercible_field_counted_as_a_field_coercion_not_a_skip(
    tmp_path: Path,
) -> None:
    """A malformed-but-present field must not be conflated with a whole-entry skip.

    The entry itself still parses into a real NodeObservation (voltage
    just ends up None); last_fetch_skipped must stay 0 for it, while
    last_fetch_field_coercions must count the one bad field.
    """
    nid = NodeId.from_hex("deadbe01")
    payload = {nid.decimal: {"shortName": "good", "voltage": "not-a-number"}}
    respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json=payload))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LoranetSource(client)

    result = source.fetch_all()

    assert nid in result
    assert result[nid].voltage is None
    assert result[nid].short_name == "good"
    assert source.last_fetch_skipped == 0
    assert source.last_fetch_field_coercions == 1


@respx.mock
def test_loranet_uncoercible_position_counted_as_field_coercions(tmp_path: Path) -> None:
    """latitude/longitude must route through the tracker like every other field."""
    nid = NodeId.from_hex("deadbe01")
    payload = {
        nid.decimal: {"shortName": "good", "latitude": "not-a-number", "longitude": 12345678}
    }
    respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json=payload))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LoranetSource(client)

    result = source.fetch_all()

    assert result[nid].latitude is None
    assert result[nid].longitude == pytest.approx(1.2345678)
    assert source.last_fetch_skipped == 0
    assert source.last_fetch_field_coercions == 1


@respx.mock
def test_loranet_uncoercible_hw_model_counted_as_one_field_coercion_not_two(
    tmp_path: Path,
) -> None:
    """A malformed hwModel must count once, not once per derived output (name + value)."""
    nid = NodeId.from_hex("deadbe01")
    payload = {nid.decimal: {"shortName": "good", "hwModel": [1, 2, 3]}}
    respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json=payload))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LoranetSource(client)

    result = source.fetch_all()

    assert result[nid].hw_model is None
    assert result[nid].hw_model_value is None
    assert source.last_fetch_skipped == 0
    assert source.last_fetch_field_coercions == 1


@respx.mock
def test_loranet_unresolvable_but_well_typed_enum_value_not_counted_as_a_coercion_failure(
    tmp_path: Path,
) -> None:
    """A forward-incompatible-but-well-typed enum value is not a coercion failure."""
    nid = NodeId.from_hex("deadbe01")
    payload = {nid.decimal: {"shortName": "good", "hwModel": 99999}}
    respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json=payload))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LoranetSource(client)

    result = source.fetch_all()

    assert result[nid].hw_model == "99999"
    assert result[nid].hw_model_value is None
    assert source.last_fetch_field_coercions == 0


@respx.mock
def test_loranet_fetch_nodes_last_fetch_field_coercions_resets_between_calls(
    tmp_path: Path,
) -> None:
    """Regression test: the counter reflects only the *last* fetch_nodes call."""
    bad_nid = NodeId.from_hex("deadbe01")
    good_nid = NodeId.from_hex("deadbe02")
    payload = {
        bad_nid.decimal: {"shortName": "bad", "voltage": "not-a-number"},
        good_nid.decimal: {"shortName": "good", "voltage": 3.7},
    }
    respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json=payload))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LoranetSource(client)

    source.fetch_nodes([bad_nid])
    assert source.last_fetch_field_coercions == 1

    source.fetch_nodes([good_nid])
    assert source.last_fetch_field_coercions == 0


@respx.mock
def test_loranet_fetch_nodes_last_fetch_skipped_resets_and_excludes_absent_ids(
    tmp_path: Path,
) -> None:
    """Regression test: last_fetch_skipped counts parse failures, not absent ids.

    An id simply missing from the dump is never a parse failure -- it
    must not be counted -- and the counter must reset between calls
    rather than accumulate forever.
    """
    good_nid = NodeId.from_hex("deadbe01")
    absent_nid = NodeId.from_hex("deadbe02")
    malformed_nid = NodeId.from_hex("deadbe03")
    payload = {
        good_nid.decimal: {"shortName": "good"},
        malformed_nid.decimal: "not-a-dict",
    }
    respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json=payload))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LoranetSource(client)

    result = source.fetch_nodes([good_nid, absent_nid, malformed_nid])
    assert set(result) == {good_nid}
    assert source.last_fetch_skipped == 1

    # A second, all-clean fetch must reset the counter, not accumulate.
    clean_result = source.fetch_nodes([good_nid])
    assert set(clean_result) == {good_nid}
    assert source.last_fetch_skipped == 0


@respx.mock
def test_loranet_fetch_nodes_counts_a_present_null_entry_as_skipped(tmp_path: Path) -> None:
    """Regression test: a present-but-null dump entry is not the same as an absent key.

    dict.get() returns None both when a key is absent AND when it is
    present with a JSON null value -- fetch_nodes must not conflate
    "never in the dump" (never a parse failure) with "in the dump but
    failed to parse" (must be counted), or a source that starts emitting
    null for some entries would silently vanish from last_fetch_skipped.
    """
    good_nid = NodeId.from_hex("deadbe01")
    null_nid = NodeId.from_hex("deadbe02")
    payload = {
        good_nid.decimal: {"shortName": "good"},
        null_nid.decimal: None,
    }
    respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json=payload))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LoranetSource(client)

    result = source.fetch_nodes([good_nid, null_nid])
    assert set(result) == {good_nid}
    assert source.last_fetch_skipped == 1


def test_loranet_parse_node_maps_every_field_from_its_own_json_key() -> None:
    """Regression test: pin parse_node's whole JSON-key -> field wiring.

    parse_node is the entire loranet -> NodeObservation contract, and
    every field is independently droppable: reading the wrong key (or no
    key) silently yields None rather than an error, so only a
    field-by-field assertion over a fully-populated payload can catch it.
    The trailing "which fields are still None" check keeps this test
    honest as NodeObservation grows.
    """
    node_id = NodeId.from_hex("deadbe01")
    observed_at = datetime(2026, 8, 25, 3, 14, 10, tzinfo=UTC)
    tracker = CoercionTracker()
    payload = {
        "shortName": "  abcd  ",  # stripped by coerce_str
        "longName": "Alpha Node",
        "hwModel": "RAK4631",
        "role": "ROUTER",
        "region": "EU_868",
        "modemPreset": "LONG_FAST",
        "fwVersion": "2.7.11",
        "latitude": 521_234_567,
        "longitude": 210_123_456,
        "altitude": 123,
        "precision": 16,
        "batteryLevel": 87,
        "voltage": 4.05,
        "chUtil": 7.5,
        "airUtilTx": 1.25,
        "temperature": 21.5,
        "uptime": 98_765,
        "onlineLocalNodes": 12,
        "hasDefaultCh": False,
        "seenBy": {"gw2": 1_700_000_100, "gw1": 1_700_000_000},
        "lastDeviceMetrics": 1_700_000_500,
        "lastMapReport": 1_700_000_300,
    }

    obs = parse_node(node_id, payload, observed_at=observed_at, coercion_tracker=tracker)

    assert obs.node_id == node_id
    assert obs.source == SOURCE_LORANET
    assert obs.observed_at == observed_at

    assert obs.short_name == "abcd"
    assert obs.long_name == "Alpha Node"
    assert obs.hw_model == "RAK4631"
    assert obs.hw_model_value == 9
    assert obs.role == "ROUTER"
    assert obs.role_value == 2
    assert obs.region == "EU_868"
    assert obs.modem_preset == "LONG_FAST"
    assert obs.firmware_version == "2.7.11"

    assert obs.latitude == pytest.approx(52.1234567)
    assert obs.longitude == pytest.approx(21.0123456)
    assert obs.altitude == 123
    assert obs.position_precision == 16

    assert obs.battery_level == 87
    assert obs.voltage == pytest.approx(4.05)
    assert obs.channel_utilization == pytest.approx(7.5)
    assert obs.air_util_tx == pytest.approx(1.25)
    assert obs.temperature == pytest.approx(21.5)
    assert obs.uptime_seconds == 98_765
    assert obs.online_local_nodes == 12
    assert obs.has_default_channel is False

    assert obs.neighbor_count == 2
    assert obs.seen_by == ("gw1", "gw2")  # sorted, not payload order
    assert obs.last_device_metrics == datetime.fromtimestamp(1_700_000_500, tz=UTC)
    assert obs.last_map_report == datetime.fromtimestamp(1_700_000_300, tz=UTC)
    # The newest of seenBy's max (…100), lastDeviceMetrics (…500) and
    # lastMapReport (…300).
    assert obs.last_seen == datetime.fromtimestamp(1_700_000_500, tz=UTC)

    # Nothing in this payload was uncoercible.
    assert tracker.failures == 0

    # Completeness guard: with every loranet-reported key populated, the
    # only fields left unset are the two loranet genuinely never reports.
    # A newly added field wired from the wrong key would show up here.
    assert {name for name, value in obs if value is None} == {"region_queried", "last_boot"}


@respx.mock
def test_loranet_fetch_all_skipped_counts_every_skip_not_just_the_first(tmp_path: Path) -> None:
    """Regression test: last_fetch_skipped is a running count, not a "saw one" flag.

    Both skip paths in fetch_all (an unparsable key and an unparsable
    entry) increment the same counter, so the scenario needs at least two
    skips *of each kind* -- with one of each, a counter that latches at 1
    on either path still lands on the correct total by accident.
    """
    good_nid = NodeId.from_hex("deadbe01")
    payload = {
        good_nid.decimal: {"shortName": "good"},
        # Two unparsable keys: "not a decimal at all", and a decimal too
        # large to be a node id. Both fail at _parse_key.
        "not-a-decimal-key": {"shortName": "bad key"},
        "9999999999": {"shortName": "out-of-range key"},
        # Two well-formed keys whose *payload* is not a JSON object.
        # Both fail one step later, at _parse_entry.
        NodeId.from_hex("deadbe02").decimal: "not-a-dict",
        NodeId.from_hex("deadbe03").decimal: 12345,
    }
    respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json=payload))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LoranetSource(client)

    result = source.fetch_all()

    assert set(result) == {good_nid}
    assert source.last_fetch_skipped == 4


@respx.mock
def test_loranet_fetch_nodes_skipped_counts_every_skip_not_just_the_first(tmp_path: Path) -> None:
    """Regression test: fetch_nodes' skip counter must accumulate across ids."""
    good_nid = NodeId.from_hex("deadbe01")
    bad_nids = [
        NodeId.from_hex("deadbe02"),
        NodeId.from_hex("deadbe03"),
        NodeId.from_hex("dead0004"),
    ]
    payload: dict[str, object] = {good_nid.decimal: {"shortName": "good"}}
    payload.update({nid.decimal: "not-a-dict" for nid in bad_nids})
    respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json=payload))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LoranetSource(client)

    result = source.fetch_nodes([good_nid, *bad_nids])

    assert set(result) == {good_nid}
    assert source.last_fetch_skipped == 3


def test_loranet_enum_resolution_rejects_a_boolean() -> None:
    """A JSON ``true``/``false`` is not an enum lookup key, despite bool being an int.

    Python's ``True == 1`` would otherwise resolve ``role: true`` to
    whichever role happens to be numbered 1, inventing a confident wrong
    answer from a clearly malformed payload -- the same reason
    coerce_int/coerce_float/e7_to_degrees/parse_epoch all reject bool.
    """
    role = role_table()
    for raw in (True, False):
        assert loranet_module._typed_enum_raw(raw) is None
        assert loranet_module._resolve_enum_name(role, raw) is None
        assert loranet_module._resolve_enum_value(role, raw) is None

    # A well-typed int of the same numeric value still resolves, so the
    # guard is rejecting the *type*, not the value.
    assert loranet_module._resolve_enum_name(role, 1) is not None
    assert loranet_module._resolve_enum_value(role, 1) == 1


def test_loranet_parse_node_treats_a_boolean_enum_field_as_uncoercible() -> None:
    """End-to-end: a boolean role/hwModel/region is dropped and counted, not resolved."""
    tracker = CoercionTracker()

    obs = parse_node(
        NodeId.from_hex("deadbe01"),
        {"shortName": "good", "role": True, "hwModel": False, "region": True},
        observed_at=datetime.now(tz=UTC),
        coercion_tracker=tracker,
    )

    assert obs.short_name == "good"
    assert obs.role is None
    assert obs.role_value is None
    assert obs.hw_model is None
    assert obs.hw_model_value is None
    assert obs.region is None
    # Three present-but-uncoercible fields, counted once each (not once
    # per derived name/value output).
    assert tracker.failures == 3


@respx.mock
def test_loranet_json_array_payload_raises_invalid_response(tmp_path: Path) -> None:
    respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json=[1, 2, 3]))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LoranetSource(client)
    with pytest.raises(InvalidResponseError):
        source.raw_index()
