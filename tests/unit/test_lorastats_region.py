"""``LorastatsRegionFeed``: a region's raw packets (fresh, never kept) and node list (cached)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import respx

from meshprovision.cache.http import CachedHTTPClient
from meshprovision.datasources import lorastats_region
from meshprovision.datasources.lorastats import LORASTATS_BASE_URL, LORASTATS_NODES_PATH
from meshprovision.datasources.lorastats_region import (
    LORASTATS_PACKETS_RAW_PATH,
    LorastatsRegionFeed,
)
from meshprovision.errors import HttpError, InvalidResponseError, RateLimitError, SettingsError
from meshprovision.nodeid import NodeId

pytestmark = pytest.mark.unit

_SINCE = datetime(2026, 10, 20, 6, 48, 30, tzinfo=UTC).timestamp()
_ROWS = [{"Time": "2026-10-20T08:50:00", "Gateway": "bbad0594", "Data": "AAAA"}]
_NODES = [
    {"NodeId": "c464e761", "ShortName": "FCM6", "Role": 2, "LastSeen": "2026-10-20T08:50:00"},
    {"NodeId": "250643bc", "ShortName": "D0h3", "Role": 1},
    {"ShortName": "no id"},
    "not an object",
]


def _url(path: str, region: str = "Zach%C3%B3d") -> str:
    return LORASTATS_BASE_URL + path.format(region=region)


def _client(tmp_path: Path, *, ttl: float = 60.0) -> CachedHTTPClient:
    return CachedHTTPClient(
        cache_dir=tmp_path / "cache",
        user_agent="mp/1 (+t@example.invalid)",
        ttl=ttl,
        sleep=lambda _s: None,
    )


def _cached_entries(tmp_path: Path) -> list[Path]:
    return sorted((tmp_path / "cache").glob("*/*.json"))


@respx.mock
def test_raw_asks_for_the_region_since_a_time_and_keeps_nothing_cached(tmp_path: Path) -> None:
    route = respx.get(_url(LORASTATS_PACKETS_RAW_PATH)).mock(
        return_value=httpx.Response(200, json=_ROWS)
    )
    client = _client(tmp_path)
    feed = LorastatsRegionFeed(client)

    first = feed.raw("Zachód", since=_SINCE)
    second = feed.raw("Zachód", since=_SINCE)

    assert first == second == _ROWS
    assert route.call_count == 2
    request = route.calls[0].request
    assert dict(request.url.params) == {"since": "2026-10-20T08:48:30"}
    assert "t@example.invalid" in request.headers["User-Agent"]
    assert client.stats.writes == 0
    assert _cached_entries(tmp_path) == []


@respx.mock
def test_raw_without_since_asks_for_everything(tmp_path: Path) -> None:
    route = respx.get(_url(LORASTATS_PACKETS_RAW_PATH)).mock(
        return_value=httpx.Response(200, json=[])
    )

    assert LorastatsRegionFeed(_client(tmp_path)).raw("Zachód", since=None) == []
    assert dict(route.calls[0].request.url.params) == {}


@respx.mock
@pytest.mark.parametrize(
    "response",
    [
        pytest.param(httpx.Response(200, html="<html>maintenance</html>"), id="soft-404"),
        pytest.param(httpx.Response(200, json={"rows": []}), id="not-a-list"),
    ],
)
def test_raw_that_is_not_a_json_array_is_refused(tmp_path: Path, response: httpx.Response) -> None:
    respx.get(_url(LORASTATS_PACKETS_RAW_PATH)).mock(return_value=response)

    with pytest.raises(InvalidResponseError):
        LorastatsRegionFeed(_client(tmp_path)).raw("Zachód", since=None)
    assert _cached_entries(tmp_path) == []


@respx.mock
def test_raw_over_the_size_cap_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lorastats_region, "REGION_RAW_MAX_BYTES", 10)
    respx.get(_url(LORASTATS_PACKETS_RAW_PATH)).mock(return_value=httpx.Response(200, json=_ROWS))

    with pytest.raises(HttpError, match="10"):
        LorastatsRegionFeed(_client(tmp_path)).raw("Zachód", since=None)


@respx.mock
def test_a_rate_limit_propagates(tmp_path: Path) -> None:
    respx.get(_url(LORASTATS_PACKETS_RAW_PATH)).mock(return_value=httpx.Response(429))

    with pytest.raises(RateLimitError) as limited:
        LorastatsRegionFeed(_client(tmp_path)).raw("Zachód", since=None)
    assert limited.value.source == "lorastats"


@respx.mock
@pytest.mark.parametrize("method", ["raw", "nodes"])
def test_a_malformed_region_is_refused_before_any_request(tmp_path: Path, method: str) -> None:
    route = respx.get(url__startswith=LORASTATS_BASE_URL).mock(
        return_value=httpx.Response(200, json=[])
    )
    feed = LorastatsRegionFeed(_client(tmp_path))

    with pytest.raises(SettingsError):
        if method == "raw":
            feed.raw("../Nodes", since=None)
        else:
            feed.nodes("../Nodes")
    assert route.call_count == 0


@respx.mock
def test_the_region_is_nfc_normalized_and_percent_encoded(tmp_path: Path) -> None:
    route = respx.get(_url(LORASTATS_PACKETS_RAW_PATH)).mock(
        return_value=httpx.Response(200, json=[])
    )

    LorastatsRegionFeed(_client(tmp_path), base_url=LORASTATS_BASE_URL + "/").raw(
        "Zachód", since=None
    )

    assert route.calls[0].request.url.raw_path == b"/API/Zach%C3%B3d/PacketsRaw/JSON"


@respx.mock
def test_nodes_are_parsed_and_records_without_an_id_left_out(tmp_path: Path) -> None:
    respx.get(_url(LORASTATS_NODES_PATH)).mock(return_value=httpx.Response(200, json=_NODES))

    nodes = LorastatsRegionFeed(_client(tmp_path)).nodes("Zachód")

    assert [(n.node_id, n.short_name, n.role, n.region_queried) for n in nodes] == [
        (NodeId.from_hex("c464e761"), "FCM6", "ROUTER", "Zachód"),
        (NodeId.from_hex("250643bc"), "D0h3", "CLIENT_MUTE", "Zachód"),
    ]
    assert nodes[0].last_seen == datetime(2026, 10, 20, 6, 50, tzinfo=UTC)


@respx.mock
@pytest.mark.parametrize(
    ("ttl", "later", "requests"),
    [(60.0, 3599.0, 1), (60.0, 3601.0, 2), (7200.0, 3601.0, 1), (7200.0, 7201.0, 2)],
)
def test_nodes_ask_for_the_whole_region_at_most_hourly(
    tmp_path: Path, ttl: float, later: float, requests: int
) -> None:
    route = respx.get(_url(LORASTATS_NODES_PATH)).mock(
        return_value=httpx.Response(200, json=_NODES)
    )
    now = [_SINCE]
    client = CachedHTTPClient(
        cache_dir=tmp_path / "cache",
        user_agent="mp/1 (+t@example.invalid)",
        ttl=ttl,
        sleep=lambda _s: None,
        clock=lambda: now[0],
    )
    feed = LorastatsRegionFeed(client)

    feed.nodes("Zachód")
    now[0] += later
    feed.nodes("Zachód")

    assert route.call_count == requests
    assert dict(route.calls[0].request.url.params) == {}


@respx.mock
def test_nodes_that_are_not_a_json_array_are_refused_and_dropped(tmp_path: Path) -> None:
    route = respx.get(_url(LORASTATS_NODES_PATH)).mock(
        side_effect=[httpx.Response(200, json={"rows": []}), httpx.Response(200, json=[])]
    )
    feed = LorastatsRegionFeed(_client(tmp_path))

    with pytest.raises(InvalidResponseError):
        feed.nodes("Zachód")

    assert feed.nodes("Zachód") == ()
    assert route.call_count == 2


@respx.mock
def test_nodes_over_the_size_cap_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lorastats_region, "REGION_NODES_MAX_BYTES", 10)
    respx.get(_url(LORASTATS_NODES_PATH)).mock(return_value=httpx.Response(200, json=_NODES))

    with pytest.raises(HttpError, match="10"):
        LorastatsRegionFeed(_client(tmp_path)).nodes("Zachód")
