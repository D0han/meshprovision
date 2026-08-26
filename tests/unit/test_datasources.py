"""Tests for meshprovision.datasources.models, loranet, and lorastats."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import respx

from meshprovision.cache.http import CachedHTTPClient
from meshprovision.datasources import lorastats as lorastats_module
from meshprovision.datasources.loranet import LORANET_NODES_URL, LoranetSource
from meshprovision.datasources.lorastats import (
    LORASTATS_BASE_URL,
    LORASTATS_NODES_PATH,
    LorastatsSource,
    validate_regions,
)
from meshprovision.datasources.models import (
    NodeObservation,
    coerce_bool,
    coerce_float,
    coerce_int,
    coerce_str,
    e7_to_degrees,
    parse_epoch,
    parse_iso8601,
)
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


@respx.mock
def test_loranet_json_array_payload_raises_invalid_response(tmp_path: Path) -> None:
    respx.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json=[1, 2, 3]))
    client = CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)")
    source = LoranetSource(client)
    with pytest.raises(InvalidResponseError):
        source.raw_index()
