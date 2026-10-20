"""Tests for meshprovision.datasources.lorastats_regions (no real request is ever sent)."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import httpx
import pytest
import respx

from meshprovision.cache.http import DEFAULT_MAX_RETRIES, CachedHTTPClient
from meshprovision.datasources import lorastats_regions as list_module
from meshprovision.datasources.lorastats import LORASTATS_MAX_REGIONS, LorastatsSource
from meshprovision.datasources.lorastats_regions import (
    REGION_LIST_FILENAME,
    REGION_LIST_MAX_PAGE_BYTES,
    REGION_LIST_TTL_SECONDS,
    REGION_LIST_VERSION,
    RegionList,
    parse_region_list,
)
from meshprovision.errors import DataSourceError, RateLimitError, SettingsError
from tests.conftest import LORASTATS_NODES_PAGE, LORASTATS_NODES_PAGE_REGIONS, TEST_CONTACT

pytestmark = pytest.mark.unit

_PAGE_URL = "https://lorastats.pl/Nodes"
_NOW = 1_760_000_000.0


def _client(tmp_path: Path, now: list[float]) -> CachedHTTPClient:
    return CachedHTTPClient(
        cache_dir=tmp_path / "cache",
        user_agent=f"mp/1 (+{TEST_CONTACT})",
        clock=lambda: now[0],
        sleep=lambda _s: None,
    )


def _page_route(response: httpx.Response | Exception | None = None) -> respx.Route:
    route = respx.get(_PAGE_URL)
    if isinstance(response, Exception):
        return route.mock(side_effect=response)
    return route.mock(
        return_value=response or httpx.Response(200, html=LORASTATS_NODES_PAGE),
    )


def _write_cache(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "cache" / REGION_LIST_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _cached(regions: list[str], fetched_at: float) -> dict[str, object]:
    return {"version": REGION_LIST_VERSION, "regions": regions, "fetched_at": fetched_at}


# ---------------------------------------------------------------------------
# Parsing the navigation.
# ---------------------------------------------------------------------------


def test_the_navigation_names_the_regions_in_first_seen_order() -> None:
    assert parse_region_list(LORASTATS_NODES_PAGE) == LORASTATS_NODES_PAGE_REGIONS


@pytest.mark.parametrize(
    ("href", "region"),
    [
        ("/Nodes/Szczecin", "Szczecin"),
        ("/Nodes/Zach%C3%B3d", "Zachód"),
        ("/Nodes/Zacho%CC%81d", "Zachód"),
        ("/Nodes/Gda%C5%84sk/Router", "Gdańsk"),
        ("/Nodes/Warszawa/ClientBase", "Warszawa"),
        ("https://lorastats.pl/Nodes/Rzesz%C3%B3w", "Rzeszów"),
        (" /Nodes/Lublin ", "Lublin"),
    ],
)
def test_a_region_or_role_link_names_its_region(href: str, region: str) -> None:
    assert parse_region_list(f'<a href="{href}">x</a>') == (region,)


@pytest.mark.parametrize(
    "href",
    [
        "/Nodes",
        "/Nodes/",
        "/Nodes?poi=Krak%C3%B3w",
        "/Nodes/Lublin?poi=x",
        "/Nodes/Lublin#top",
        "/Nodes/Client",
        "/Nodes/Tracker/Client",
        "/Nodes/Lublin/Unknown",
        "/Nodes/Lublin/Client/Extra",
        "/Nodes/../../etc/passwd",
        "/Nodes/..",
        "/Nodes/.",
        "/Nodes/a%2Fb",
        "/Nodes/a%5Cb",
        "/Nodes/a%3Fb",
        "/Nodes/%00",
        "/Nodes/%FF%FE",
        "/Nodes/" + "x" * 65,
        "/nodes/Lublin",
        "Nodes/Lublin",
        "/Regions",
        "http://lorastats.pl/Nodes/Lublin",
        "https://example.com/Nodes/Lublin",
        "//example.com/Nodes/Lublin",
        "javascript:alert(1)",
        "http://[::1/Nodes/Lublin",
    ],
)
def test_any_other_link_names_no_region(href: str) -> None:
    assert parse_region_list(f'<a href="{href}">x</a>') == ()


def test_only_anchor_hrefs_are_read() -> None:
    page = (
        '<link href="/Nodes/Linked"><img src="/Nodes/Image"><a name="/Nodes/Named">x</a>'
        "<script>document.write('<a href=\"/Nodes/Scripted\">')</script>"
        '<a title="/Nodes/Titled" href="/Nodes/Kielce">x</a>'
    )
    assert parse_region_list(page) == ("Kielce",)


def test_only_the_first_href_of_an_anchor_is_read() -> None:
    assert parse_region_list('<a href="/Nodes/Kielce" href="/Nodes/Lublin">x</a>') == ("Kielce",)


def test_an_anchor_without_an_href_value_is_skipped() -> None:
    assert parse_region_list('<a href>x</a><a href="/Nodes/Kielce">y</a>') == ("Kielce",)


def test_at_most_the_region_limit_is_kept(caplog: pytest.LogCaptureFixture) -> None:
    names = [f"R{i}" for i in range(LORASTATS_MAX_REGIONS + 1)]
    page = "".join(f'<a href="/Nodes/{name}">x</a>' for name in names)

    with caplog.at_level(logging.WARNING):
        assert parse_region_list(page) == tuple(names[:LORASTATS_MAX_REGIONS])
    assert f"names {LORASTATS_MAX_REGIONS + 1} regions" in caplog.text


def test_exactly_the_region_limit_is_kept_without_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    names = [f"R{i}" for i in range(LORASTATS_MAX_REGIONS)]
    page = "".join(f'<a href="/Nodes/{name}">x</a>' for name in names)

    with caplog.at_level(logging.WARNING):
        assert parse_region_list(page) == tuple(names)
    assert caplog.text == ""


def test_the_region_limit_counts_each_region_once() -> None:
    names = [f"R{i}" for i in range(LORASTATS_MAX_REGIONS)]
    page = "".join(
        f'<a href="/Nodes/{name}">x</a><a href="/Nodes/{name}/Client">x</a>' for name in names
    )
    assert parse_region_list(page) == tuple(names)


# ---------------------------------------------------------------------------
# Fetching and caching.
# ---------------------------------------------------------------------------


@respx.mock
def test_a_first_run_requests_the_page_once_and_caches_the_list(tmp_path: Path) -> None:
    route = _page_route()
    client = _client(tmp_path, [_NOW])

    assert RegionList(clock=lambda: _NOW).regions(client) == LORASTATS_NODES_PAGE_REGIONS

    assert route.call_count == 1
    request = route.calls[0].request
    assert request.headers["User-Agent"] == f"mp/1 (+{TEST_CONTACT})"
    assert request.headers["Accept"] == "text/html"
    cached = json.loads((tmp_path / "cache" / REGION_LIST_FILENAME).read_text(encoding="utf-8"))
    assert cached == _cached(list(LORASTATS_NODES_PAGE_REGIONS), _NOW)


@respx.mock
def test_the_page_itself_is_not_kept_in_the_http_cache(tmp_path: Path) -> None:
    _page_route()
    client = _client(tmp_path, [_NOW])

    RegionList(clock=lambda: _NOW).regions(client)

    assert [p.name for p in (tmp_path / "cache").rglob("*") if p.is_file()] == [
        REGION_LIST_FILENAME
    ]


@respx.mock
def test_a_fresh_cached_list_is_used_without_a_request(tmp_path: Path) -> None:
    route = _page_route()
    _write_cache(tmp_path, _cached(["Zachód", "Gdańsk"], _NOW - REGION_LIST_TTL_SECONDS))

    regions = RegionList(clock=lambda: _NOW).regions(_client(tmp_path, [_NOW]))

    assert regions == ("Zachód", "Gdańsk")
    assert route.call_count == 0


@respx.mock
def test_a_cached_list_older_than_a_week_is_fetched_again(tmp_path: Path) -> None:
    route = _page_route()
    _write_cache(tmp_path, _cached(["Zachód"], _NOW - REGION_LIST_TTL_SECONDS - 1))

    regions = RegionList(clock=lambda: _NOW).regions(_client(tmp_path, [_NOW]))

    assert regions == LORASTATS_NODES_PAGE_REGIONS
    assert route.call_count == 1


@respx.mock
def test_a_cached_list_from_the_future_is_fetched_again(tmp_path: Path) -> None:
    route = _page_route()
    _write_cache(tmp_path, _cached(["Zachód"], _NOW + 301))
    RegionList(clock=lambda: _NOW).regions(_client(tmp_path, [_NOW]))
    assert route.call_count == 1


@respx.mock
def test_a_cached_list_within_a_small_clock_skew_is_fresh(tmp_path: Path) -> None:
    route = _page_route()
    _write_cache(tmp_path, _cached(["Zachód"], _NOW + 300))
    assert RegionList(clock=lambda: _NOW).regions(_client(tmp_path, [_NOW])) == ("Zachód",)
    assert route.call_count == 0


@respx.mock
def test_refresh_requests_the_page_even_with_a_fresh_list(tmp_path: Path) -> None:
    route = _page_route()
    _write_cache(tmp_path, _cached(["Zachód"], _NOW))

    regions = RegionList(refresh=True, clock=lambda: _NOW).regions(_client(tmp_path, [_NOW]))

    assert regions == LORASTATS_NODES_PAGE_REGIONS
    assert route.call_count == 1


@respx.mock
def test_a_refresh_never_reads_the_page_from_the_http_cache(tmp_path: Path) -> None:
    route = _page_route()
    client = _client(tmp_path, [_NOW])
    client.get(_PAGE_URL)  # an HTTP cache entry for the page, still fresh

    RegionList(refresh=True, clock=lambda: _NOW).regions(client)

    assert route.call_count == 2


@respx.mock
def test_one_region_list_loads_once(tmp_path: Path) -> None:
    route = _page_route()
    client = _client(tmp_path, [_NOW])
    region_list = RegionList(refresh=True, clock=lambda: _NOW)

    region_list.regions(client)
    (tmp_path / "cache" / REGION_LIST_FILENAME).unlink()
    assert region_list.regions(client) == LORASTATS_NODES_PAGE_REGIONS
    assert route.call_count == 1


@respx.mock
def test_a_failed_load_is_not_retried_by_the_same_region_list(tmp_path: Path) -> None:
    route = _page_route(httpx.Response(404))
    client = _client(tmp_path, [_NOW])
    region_list = RegionList(clock=lambda: _NOW)

    with pytest.raises(DataSourceError) as first:
        region_list.regions(client)
    with pytest.raises(DataSourceError) as second:
        region_list.regions(client)
    assert second.value is first.value
    assert route.call_count == 1


@pytest.mark.parametrize(
    "response",
    [
        pytest.param(httpx.Response(404), id="404"),
        pytest.param(httpx.Response(200, html="<p>maintenance</p>"), id="no-region"),
        pytest.param(
            httpx.Response(
                200,
                content=b'<a href="/Nodes/Kielce">x</a>'.ljust(REGION_LIST_MAX_PAGE_BYTES + 1),
            ),
            id="too-large",
        ),
    ],
)
@respx.mock
def test_without_a_cached_list_a_failed_fetch_names_the_setting(
    tmp_path: Path, response: httpx.Response
) -> None:
    route = _page_route(response)

    with pytest.raises(DataSourceError) as exc_info:
        RegionList(clock=lambda: _NOW).regions(_client(tmp_path, [_NOW]))

    assert exc_info.value.message.startswith("No lorastats region list: ")
    assert "MESHPROVISION_LORASTATS_REGIONS" in (exc_info.value.hint or "")
    assert route.call_count == 1
    assert not (tmp_path / "cache" / REGION_LIST_FILENAME).exists()


@respx.mock
def test_an_unreachable_page_is_retried_like_any_request_then_fails(tmp_path: Path) -> None:
    route = _page_route(httpx.ConnectError("refused"))

    with pytest.raises(DataSourceError):
        RegionList(clock=lambda: _NOW).regions(_client(tmp_path, [_NOW]))
    assert route.call_count == DEFAULT_MAX_RETRIES + 1


@respx.mock
def test_a_rate_limited_page_fails_and_starts_the_host_cool_down(tmp_path: Path) -> None:
    _page_route(httpx.Response(429, headers={"Retry-After": "600"}))
    nodes = respx.get(url__startswith="https://lorastats.pl/API/").mock(
        return_value=httpx.Response(200, json=[])
    )
    client = _client(tmp_path, [_NOW])

    with pytest.raises(DataSourceError):
        RegionList(clock=lambda: _NOW).regions(client)
    with pytest.raises(RateLimitError):
        LorastatsSource(client, contact=TEST_CONTACT, regions=("Zachód",)).fetch_node("deadbe01")
    assert nodes.call_count == 0


@pytest.mark.parametrize(
    "response",
    [
        pytest.param(httpx.Response(503), id="503"),
        pytest.param(httpx.Response(429), id="429"),
        pytest.param(httpx.Response(200, html="<p>nothing</p>"), id="no-region"),
    ],
)
@respx.mock
def test_a_failed_refresh_falls_back_to_the_stale_list(
    tmp_path: Path, response: httpx.Response, caplog: pytest.LogCaptureFixture
) -> None:
    _page_route(response)
    path = _write_cache(tmp_path, _cached(["Zachód", "Gdańsk"], _NOW - 30 * 24 * 3600))
    before = path.read_bytes()

    with caplog.at_level(logging.WARNING):
        regions = RegionList(clock=lambda: _NOW).regions(_client(tmp_path, [_NOW]))

    assert regions == ("Zachód", "Gdańsk")
    assert "using the cached one" in caplog.text
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "document",
    [
        pytest.param("not an object", id="not-object"),
        pytest.param({**_cached(["Zachód"], _NOW), "version": 2}, id="other-version"),
        pytest.param({**_cached(["Zachód"], _NOW), "regions": "Zachód"}, id="regions-not-list"),
        pytest.param({**_cached(["Zachód"], _NOW), "regions": 5}, id="regions-a-number"),
        pytest.param(_cached([], _NOW), id="no-region"),
        pytest.param(_cached(["Zachód", 7], _NOW), id="non-str-region"),
        pytest.param(_cached(["a/b"], _NOW), id="invalid-region"),
        pytest.param(_cached(["Zachód"], _NOW), id="non-canonical-region"),
        pytest.param(_cached(["PL", "PL"], _NOW), id="duplicate-region"),
        pytest.param(
            _cached([f"R{i}" for i in range(LORASTATS_MAX_REGIONS + 1)], _NOW), id="too-many"
        ),
        pytest.param({**_cached(["Zachód"], _NOW), "fetched_at": True}, id="bool-time"),
        pytest.param({**_cached(["Zachód"], _NOW), "fetched_at": "now"}, id="str-time"),
        pytest.param({"version": REGION_LIST_VERSION, "regions": ["Zachód"]}, id="no-time"),
    ],
)
@respx.mock
def test_a_malformed_cached_list_is_ignored(tmp_path: Path, document: object) -> None:
    route = _page_route()
    _write_cache(tmp_path, document)

    regions = RegionList(clock=lambda: _NOW).regions(_client(tmp_path, [_NOW]))

    assert regions == LORASTATS_NODES_PAGE_REGIONS
    assert route.call_count == 1


@respx.mock
def test_a_non_finite_cached_time_is_never_fresh_but_still_a_fallback(tmp_path: Path) -> None:
    _page_route(httpx.Response(404))
    path = tmp_path / "cache" / REGION_LIST_FILENAME
    path.parent.mkdir(parents=True)
    path.write_text('{"version": 1, "regions": ["Zachód"], "fetched_at": NaN}', encoding="utf-8")

    assert RegionList(clock=lambda: _NOW).regions(_client(tmp_path, [_NOW])) == ("Zachód",)


@respx.mock
def test_a_cached_list_with_a_boolean_time_is_no_fallback(tmp_path: Path) -> None:
    _page_route(httpx.Response(404))
    _write_cache(tmp_path, {**_cached(["Zachód"], _NOW), "fetched_at": True})

    with pytest.raises(DataSourceError):
        RegionList(clock=lambda: _NOW).regions(_client(tmp_path, [_NOW]))


@respx.mock
def test_an_integer_cached_time_is_accepted(tmp_path: Path) -> None:
    route = _page_route()
    _write_cache(tmp_path, _cached(["Zachód"], int(_NOW)))
    assert RegionList(clock=lambda: _NOW).regions(_client(tmp_path, [_NOW])) == ("Zachód",)
    assert route.call_count == 0


@respx.mock
def test_a_page_that_is_not_utf8_still_yields_its_region_links(tmp_path: Path) -> None:
    _page_route(httpx.Response(200, content=b'\xff<a href="/Nodes/Kielce">\xfe</a>'))
    regions = RegionList(clock=lambda: _NOW).regions(_client(tmp_path, [_NOW]))
    assert regions == ("Kielce",)


@respx.mock
def test_nothing_of_the_page_is_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    _page_route()
    with caplog.at_level(logging.DEBUG):
        RegionList(clock=lambda: _NOW).regions(_client(tmp_path, [_NOW]))
    assert "PAGE-TEXT-NEVER-LOGGED" not in caplog.text
    assert "Scripted" not in caplog.text


@respx.mock
def test_a_list_that_cannot_be_cached_is_still_used(tmp_path: Path) -> None:
    _page_route()
    client = _client(tmp_path, [_NOW])
    (tmp_path / "cache").write_text("a file where the cache directory should be")

    assert RegionList(clock=lambda: _NOW).regions(client) == LORASTATS_NODES_PAGE_REGIONS


# ---------------------------------------------------------------------------
# LorastatsSource with a region list.
# ---------------------------------------------------------------------------


@respx.mock
def test_a_source_without_configured_regions_asks_the_listed_ones(tmp_path: Path) -> None:
    _write_cache(tmp_path, _cached(["Zachód", "Gdańsk"], _NOW))
    respx.get("https://lorastats.pl/Node/deadbe01/Status").mock(return_value=httpx.Response(200))
    zachod = respx.get(url__startswith="https://lorastats.pl/API/Zach%C3%B3d/Nodes/JSON").mock(
        return_value=httpx.Response(200, json=[])
    )
    gdansk = respx.get(url__startswith="https://lorastats.pl/API/Gda%C5%84sk/Nodes/JSON").mock(
        return_value=httpx.Response(200, json=[{"NodeId": "deadbe01"}])
    )
    client = _client(tmp_path, [_NOW])
    source = LorastatsSource(
        client, contact=TEST_CONTACT, region_list=RegionList(clock=lambda: _NOW)
    )

    observation = source.fetch_node("deadbe01")

    assert observation is not None
    assert observation.region_queried == "Gdańsk"
    assert (zachod.call_count, gdansk.call_count) == (1, 1)


def test_a_source_needs_regions_or_a_region_list(tmp_path: Path) -> None:
    with pytest.raises(SettingsError, match="No lorastats regions"):
        LorastatsSource(_client(tmp_path, [_NOW]), contact=TEST_CONTACT)


@respx.mock
def test_configured_regions_never_load_the_region_list(tmp_path: Path) -> None:
    page = _page_route()
    respx.get(url__startswith="https://lorastats.pl/API/").mock(
        return_value=httpx.Response(200, json=[])
    )
    source = LorastatsSource(
        _client(tmp_path, [_NOW]),
        contact=TEST_CONTACT,
        regions=("Kielce",),
        region_list=RegionList(refresh=True),
    )

    source.fetch_node("deadbe01")

    assert page.call_count == 0


def test_the_page_cap_is_two_mebibytes() -> None:
    assert list_module.REGION_LIST_MAX_PAGE_BYTES == 2 * 1024 * 1024
