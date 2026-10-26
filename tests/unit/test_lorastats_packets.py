"""``LorastatsPackets``: the PacketReports/PacketsParsed requests, fresh and never kept."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import respx

from meshprovision.cache.http import CachedHTTPClient
from meshprovision.datasources import lorastats_packets
from meshprovision.datasources.lorastats import LORASTATS_BASE_URL
from meshprovision.datasources.lorastats_packets import (
    LORASTATS_PACKET_REPORTS_PATH,
    LORASTATS_PACKETS_PARSED_PATH,
    LorastatsPackets,
    since_param,
)
from meshprovision.errors import HttpError, InvalidResponseError, RateLimitError, SettingsError
from meshprovision.nodeid import NodeId

pytestmark = pytest.mark.unit

_NODE = NodeId.from_hex("ab446357")
_SINCE = datetime(2026, 10, 20, 6, 48, 30, tzinfo=UTC).timestamp()
_ROWS = [{"Time": "2026-10-20T08:50:00", "FromNode": "ab446357", "PacketId": "1"}]


def _url(path: str, region: str = "Zach%C3%B3d") -> str:
    return LORASTATS_BASE_URL + path.format(region=region)


def _client(tmp_path: Path) -> CachedHTTPClient:
    return CachedHTTPClient(
        cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)", sleep=lambda _s: None
    )


def _cached_entries(tmp_path: Path) -> list[Path]:
    return sorted((tmp_path / "cache").glob("*/*.json"))


@pytest.mark.parametrize(
    ("instant", "expected"),
    [
        (datetime(2026, 10, 20, 6, 48, 30, tzinfo=UTC), "2026-10-20T08:48:30"),
        (datetime(2026, 1, 5, 23, 0, 0, 900000, tzinfo=UTC), "2026-01-06T00:00:00"),
        (datetime(2026, 10, 25, 0, 30, tzinfo=UTC), "2026-10-25T02:30:00"),
        (datetime(2026, 10, 25, 1, 30, tzinfo=UTC), "2026-10-25T02:30:00"),
    ],
)
def test_since_is_naive_warsaw_time_to_the_second(instant: datetime, expected: str) -> None:
    assert since_param(instant.timestamp()) == expected


@respx.mock
def test_reports_ask_for_the_node_since_a_time_and_keep_nothing_cached(tmp_path: Path) -> None:
    route = respx.get(_url(LORASTATS_PACKET_REPORTS_PATH)).mock(
        return_value=httpx.Response(200, json=_ROWS)
    )
    packets = LorastatsPackets(_client(tmp_path))

    first = packets.reports(_NODE, "Zachód", since=_SINCE)
    second = packets.reports(_NODE, "Zachód", since=_SINCE)

    assert first == second == _ROWS
    assert route.call_count == 2
    request = route.calls[0].request
    assert dict(request.url.params) == {"fromNode": "ab446357", "since": "2026-10-20T08:48:30"}
    assert "t@example.invalid" in request.headers["User-Agent"]
    assert _cached_entries(tmp_path) == []


@respx.mock
def test_without_since_everything_is_asked_for(tmp_path: Path) -> None:
    route = respx.get(_url(LORASTATS_PACKETS_PARSED_PATH)).mock(
        return_value=httpx.Response(200, json=[])
    )

    assert LorastatsPackets(_client(tmp_path)).decoded(_NODE, "Zachód", since=None) == []
    assert dict(route.calls[0].request.url.params) == {"fromNode": "ab446357"}


@respx.mock
def test_a_gateway_check_asks_by_gateway(tmp_path: Path) -> None:
    route = respx.get(_url(LORASTATS_PACKET_REPORTS_PATH, "PL")).mock(
        return_value=httpx.Response(200, json=[])
    )

    LorastatsPackets(_client(tmp_path)).uplinked(_NODE, "PL", since=_SINCE)

    assert dict(route.calls[0].request.url.params) == {
        "gateway": "ab446357",
        "since": "2026-10-20T08:48:30",
    }


@respx.mock
@pytest.mark.parametrize(
    "response",
    [
        pytest.param(httpx.Response(200, html="<html>maintenance</html>"), id="soft-404"),
        pytest.param(httpx.Response(200, json={"rows": []}), id="not-a-list"),
    ],
)
def test_an_answer_that_is_not_a_json_array_is_refused_and_dropped(
    tmp_path: Path, response: httpx.Response
) -> None:
    respx.get(_url(LORASTATS_PACKET_REPORTS_PATH)).mock(return_value=response)

    with pytest.raises(InvalidResponseError):
        LorastatsPackets(_client(tmp_path)).reports(_NODE, "Zachód", since=None)
    assert _cached_entries(tmp_path) == []


@respx.mock
def test_a_failed_request_and_a_rate_limit_propagate(tmp_path: Path) -> None:
    respx.get(_url(LORASTATS_PACKET_REPORTS_PATH)).mock(return_value=httpx.Response(404))
    respx.get(_url(LORASTATS_PACKETS_PARSED_PATH)).mock(return_value=httpx.Response(429))
    packets = LorastatsPackets(_client(tmp_path))

    with pytest.raises(HttpError) as failed:
        packets.reports(_NODE, "Zachód", since=None)
    with pytest.raises(RateLimitError) as limited:
        packets.decoded(_NODE, "Zachód", since=None)
    assert (failed.value.source, limited.value.source) == ("lorastats", "lorastats")


@respx.mock
def test_an_answer_over_the_size_cap_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lorastats_packets, "PACKETS_MAX_BYTES", 10)
    respx.get(_url(LORASTATS_PACKET_REPORTS_PATH)).mock(
        return_value=httpx.Response(200, json=_ROWS)
    )

    with pytest.raises(HttpError, match="10"):
        LorastatsPackets(_client(tmp_path)).reports(_NODE, "Zachód", since=None)


@respx.mock
@pytest.mark.parametrize(("padding", "refused"), [(0, False), (1, True)])
def test_an_answer_over_eight_mebibytes_is_refused(
    tmp_path: Path, padding: int, refused: bool
) -> None:
    body = json.dumps(_ROWS)
    respx.get(_url(LORASTATS_PACKET_REPORTS_PATH)).mock(
        return_value=httpx.Response(
            200,
            content=body + " " * (8 * 1024 * 1024 - len(body) + padding),
            headers={"content-type": "application/json"},
        )
    )
    packets = LorastatsPackets(_client(tmp_path))

    if refused:
        with pytest.raises(HttpError):
            packets.reports(_NODE, "Zachód", since=None)
    else:
        assert packets.reports(_NODE, "Zachód", since=None) == _ROWS


@respx.mock
def test_a_malformed_region_is_refused_before_any_request(tmp_path: Path) -> None:
    route = respx.get(url__startswith=LORASTATS_BASE_URL).mock(
        return_value=httpx.Response(200, json=[])
    )

    with pytest.raises(SettingsError):
        LorastatsPackets(_client(tmp_path)).reports(_NODE, "../Nodes", since=None)
    assert route.call_count == 0


@respx.mock
def test_a_base_url_override_is_used_without_a_trailing_slash(tmp_path: Path) -> None:
    route = respx.get("https://example.invalid/API/PL/PacketReports/JSON").mock(
        return_value=httpx.Response(200, json=[])
    )

    LorastatsPackets(_client(tmp_path), base_url="https://example.invalid/").reports(
        _NODE, "PL", since=None
    )

    assert route.call_count == 1


@respx.mock
def test_a_cached_answer_for_the_same_request_is_not_used(tmp_path: Path) -> None:
    route = respx.get(_url(LORASTATS_PACKET_REPORTS_PATH)).mock(
        side_effect=[httpx.Response(200, json=[]), httpx.Response(200, json=_ROWS)]
    )
    client = _client(tmp_path)
    client.get(
        _url(LORASTATS_PACKET_REPORTS_PATH),
        params={"fromNode": "ab446357", "since": "2026-10-20T08:48:30"},
    )

    assert LorastatsPackets(client).reports(_NODE, "Zachód", since=_SINCE) == _ROWS
    assert route.call_count == 2


@respx.mock
def test_the_region_is_percent_encoded_like_lorastats_source_does(tmp_path: Path) -> None:
    route = respx.get(_url(LORASTATS_PACKET_REPORTS_PATH, "A%26B")).mock(
        return_value=httpx.Response(200, json=[])
    )

    LorastatsPackets(_client(tmp_path)).reports(_NODE, "A&B", since=None)

    assert route.calls[0].request.url.raw_path.startswith(b"/API/A%26B/PacketReports/JSON")


@respx.mock
def test_no_answer_is_ever_written_to_the_http_cache(tmp_path: Path) -> None:
    """Up to 8 MiB per answer (about 11 MiB of JSON) was written, then deleted right away."""
    for path in (LORASTATS_PACKET_REPORTS_PATH, LORASTATS_PACKETS_PARSED_PATH):
        respx.get(url__startswith=_url(path)).mock(return_value=httpx.Response(200, json=_ROWS))
    client = _client(tmp_path)
    packets = LorastatsPackets(client)

    packets.reports(_NODE, "Zachód", since=_SINCE)
    packets.decoded(_NODE, "Zachód", since=None)
    packets.uplinked(_NODE, "Zachód", since=_SINCE)

    assert client.stats.writes == 0
    assert _cached_entries(tmp_path) == []
