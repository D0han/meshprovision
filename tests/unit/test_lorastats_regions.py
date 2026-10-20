"""``LorastatsSource`` across several regions: the region memo, the status probe, the budget."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

import httpx
import pytest
import respx

from meshprovision.cache.http import DEFAULT_MAX_RETRIES, CachedHTTPClient
from meshprovision.datasources.lorastats import (
    LORASTATS_BASE_URL,
    LORASTATS_MAX_REGIONS,
    LORASTATS_NODES_PATH,
    LORASTATS_STATUS_PATH,
    LORASTATS_STATUS_TTL_SECONDS,
    LorastatsSource,
    validate_regions,
)
from meshprovision.datasources.region_memo import RegionMemo
from meshprovision.errors import HttpError, RateLimitError, SettingsError
from meshprovision.nodeid import NodeId
from tests.conftest import LORASTATS_NODES_PAGE_REGIONS

pytestmark = pytest.mark.unit

_NOW = 1_760_000_000.0
_NODE = NodeId.from_hex("deadbe01")
_OTHER = NodeId.from_hex("deadbe02")
_REGIONS = ("Zachód", "Gdańsk")


@dataclass
class _Lorastats:
    """respx routes for one node: the status endpoint and one route per region."""

    status: respx.Route
    regions: dict[str, respx.Route]

    def calls(self) -> dict[str, int]:
        return {
            "status": self.status.call_count,
            **{name: route.call_count for name, route in self.regions.items()},
        }


def _region_url(region: str) -> str:
    return LORASTATS_BASE_URL + LORASTATS_NODES_PATH.format(region=quote(region, safe=""))


def _mock(
    *, status: int | httpx.Response | Exception = 200, found_in: str | None = None
) -> _Lorastats:
    """Mock lorastats for ``_NODE`` (any node id) living in region ``found_in``."""
    status_route = respx.get(url__regex=r"^https://lorastats\.pl/Node/[0-9a-f]{8}/Status$")
    if isinstance(status, int):
        status_route.mock(return_value=httpx.Response(status, text="Wszystko OK."))
    elif isinstance(status, httpx.Response):
        status_route.mock(return_value=status)
    else:
        status_route.mock(side_effect=status)
    regions = {}
    for region in (*_REGIONS, "Rzeszów"):

        def answer(request: httpx.Request, region: str = region) -> httpx.Response:
            node = request.url.params["node"]
            records = [{"NodeId": node, "ShortName": "MTa1"}] if region == found_in else []
            return httpx.Response(200, json=records)

        regions[region] = respx.get(url__startswith=_region_url(region)).mock(side_effect=answer)
    return _Lorastats(status=status_route, regions=regions)


def _client(tmp_path: Path, now: list[float], *, ttl: float = 300.0) -> CachedHTTPClient:
    return CachedHTTPClient(
        cache_dir=tmp_path / "cache",
        user_agent="mp/1 (+t@example.invalid)",
        ttl=ttl,
        clock=lambda: now[0],
        sleep=lambda _s: None,
    )


def _memo(tmp_path: Path, now: list[float]) -> RegionMemo:
    return RegionMemo(tmp_path / "cache" / "lorastats_regions.json", clock=lambda: now[0])


def _source(
    tmp_path: Path,
    now: list[float],
    *,
    regions: tuple[str, ...] = _REGIONS,
    memo: RegionMemo | None = None,
    ttl: float = 300.0,
) -> tuple[LorastatsSource, CachedHTTPClient]:
    client = _client(tmp_path, now, ttl=ttl)
    source = LorastatsSource(client, contact="t@example.invalid", regions=regions, region_memo=memo)
    return source, client


@respx.mock
def test_a_node_in_the_second_region_costs_the_probe_and_two_region_requests(
    tmp_path: Path,
) -> None:
    now = [_NOW]
    mocked = _mock(found_in="Gdańsk")
    memo = _memo(tmp_path, now)
    source, client = _source(tmp_path, now, memo=memo)

    observation = source.fetch_node(_NODE)

    assert observation is not None
    assert observation.region_queried == "Gdańsk"
    assert mocked.calls() == {"status": 1, "Zachód": 1, "Gdańsk": 1, "Rzeszów": 0}
    assert client.stats.network_requests == 1 + len(_REGIONS)
    assert _memo(tmp_path, now).region_for(_NODE) == "Gdańsk"


@respx.mock
def test_the_status_probe_asks_by_bare_lowercase_hex(tmp_path: Path) -> None:
    now = [_NOW]
    mocked = _mock(found_in="Gdańsk")
    source, _ = _source(tmp_path, now)

    source.fetch_node("!DEADBE01")

    assert str(mocked.status.calls[0].request.url) == (
        LORASTATS_BASE_URL + LORASTATS_STATUS_PATH.format(node="deadbe01")
    )


@respx.mock
def test_the_remembered_region_is_asked_first_and_alone(tmp_path: Path) -> None:
    now = [_NOW]
    mocked = _mock(found_in="Gdańsk")
    memo = _memo(tmp_path, now)
    memo.remember(_NODE, "Gdańsk")
    source, client = _source(tmp_path, now, memo=memo)

    observation = source.fetch_node(_NODE)

    assert observation is not None
    assert observation.region_queried == "Gdańsk"
    assert mocked.calls() == {"status": 0, "Zachód": 0, "Gdańsk": 1, "Rzeszów": 0}
    assert client.stats.network_requests == 1


@respx.mock
def test_a_remembered_region_that_answers_is_not_written_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [_NOW]
    _mock(found_in="Gdańsk")
    memo = _memo(tmp_path, now)
    memo.remember(_NODE, "Gdańsk")
    changes: list[str] = []
    monkeypatch.setattr(memo, "remember", lambda node, region: changes.append(f"{node} {region}"))
    monkeypatch.setattr(memo, "forget", lambda node: changes.append(f"forget {node}"))
    source, _ = _source(tmp_path, now, memo=memo)

    assert source.fetch_node(_NODE) is not None
    assert changes == []


@respx.mock
def test_an_unknown_node_costs_one_status_request_and_no_region_request(tmp_path: Path) -> None:
    now = [_NOW]
    mocked = _mock(status=404, found_in="Gdańsk")
    memo = _memo(tmp_path, now)
    source, client = _source(tmp_path, now, memo=memo)

    assert source.fetch_node(_NODE) is None
    assert mocked.calls() == {"status": 1, "Zachód": 0, "Gdańsk": 0, "Rzeszów": 0}
    assert client.stats.network_requests == 1
    assert not memo.path.exists()


@respx.mock
def test_an_unknown_node_is_not_asked_about_again_for_an_hour(tmp_path: Path) -> None:
    now = [_NOW]
    mocked = _mock(status=404)
    source, _ = _source(tmp_path, now, ttl=0.0)

    source.fetch_node(_NODE)
    now[0] += LORASTATS_STATUS_TTL_SECONDS
    source.fetch_node(_NODE)
    assert mocked.status.call_count == 1

    now[0] += 1
    source.fetch_node(_NODE)
    assert mocked.status.call_count == 2


@respx.mock
def test_a_client_ttl_longer_than_an_hour_also_holds_for_the_status_probe(
    tmp_path: Path,
) -> None:
    now = [_NOW]
    mocked = _mock(status=404)
    source, _ = _source(tmp_path, now, ttl=2 * LORASTATS_STATUS_TTL_SECONDS)

    source.fetch_node(_NODE)
    now[0] += 2 * LORASTATS_STATUS_TTL_SECONDS
    source.fetch_node(_NODE)
    assert mocked.status.call_count == 1


@respx.mock
def test_force_refresh_asks_the_status_endpoint_again(tmp_path: Path) -> None:
    now = [_NOW]
    mocked = _mock(status=404)
    source, _ = _source(tmp_path, now)

    source.fetch_node(_NODE)
    source.fetch_node(_NODE, force_refresh=True)

    assert mocked.status.call_count == 2


@respx.mock
def test_a_known_node_without_packets_is_asked_in_every_region_without_retrying_the_500(
    tmp_path: Path,
) -> None:
    now = [_NOW]
    mocked = _mock(status=500)
    source, client = _source(tmp_path, now)

    assert source.fetch_node(_NODE) is None
    assert mocked.calls() == {"status": 1, "Zachód": 1, "Gdańsk": 1, "Rzeszów": 0}
    assert client.stats.retries == 0


@respx.mock
def test_the_status_body_is_never_read(tmp_path: Path) -> None:
    """A 2xx page of any kind (a soft 404 included) means "ask the regions"."""
    now = [_NOW]
    mocked = _mock(
        status=httpx.Response(200, html="<html>Status Code: 404</html>"), found_in="Gdańsk"
    )
    source, _ = _source(tmp_path, now)

    assert source.fetch_node(_NODE) is not None
    assert mocked.calls()["Gdańsk"] == 1


@respx.mock
def test_a_stale_memo_falls_back_to_the_other_regions_and_is_updated(tmp_path: Path) -> None:
    now = [_NOW]
    mocked = _mock(found_in="Gdańsk")
    memo = _memo(tmp_path, now)
    memo.remember(_NODE, "Zachód")
    source, client = _source(tmp_path, now, memo=memo)

    observation = source.fetch_node(_NODE)

    assert observation is not None
    assert observation.region_queried == "Gdańsk"
    assert mocked.calls() == {"status": 1, "Zachód": 1, "Gdańsk": 1, "Rzeszów": 0}
    assert client.stats.network_requests == 1 + len(_REGIONS)
    assert _memo(tmp_path, now).region_for(_NODE) == "Gdańsk"


@respx.mock
def test_a_stale_remembered_region_is_asked_once_even_with_force_refresh(tmp_path: Path) -> None:
    now = [_NOW]
    mocked = _mock(found_in="Gdańsk")
    memo = _memo(tmp_path, now)
    memo.remember(_NODE, "Zachód")
    source, client = _source(tmp_path, now, memo=memo)

    assert source.fetch_node(_NODE, force_refresh=True) is not None
    assert mocked.calls() == {"status": 1, "Zachód": 1, "Gdańsk": 1, "Rzeszów": 0}
    assert client.stats.network_requests == 1 + len(_REGIONS)


@respx.mock
def test_a_stale_memo_of_a_node_found_nowhere_is_forgotten(tmp_path: Path) -> None:
    now = [_NOW]
    mocked = _mock(found_in=None)
    memo = _memo(tmp_path, now)
    memo.remember(_NODE, "Gdańsk")
    source, _ = _source(tmp_path, now, memo=memo)

    assert source.fetch_node(_NODE) is None
    assert mocked.calls() == {"status": 1, "Zachód": 1, "Gdańsk": 1, "Rzeszów": 0}
    assert _memo(tmp_path, now).region_for(_NODE) is None


@respx.mock
def test_the_memo_of_a_node_lorastats_no_longer_knows_is_forgotten(tmp_path: Path) -> None:
    now = [_NOW]
    mocked = _mock(status=404)
    memo = _memo(tmp_path, now)
    memo.remember(_NODE, "Gdańsk")
    source, _ = _source(tmp_path, now, memo=memo)

    assert source.fetch_node(_NODE) is None
    assert mocked.calls() == {"status": 1, "Zachód": 0, "Gdańsk": 1, "Rzeszów": 0}
    assert _memo(tmp_path, now).region_for(_NODE) is None


@respx.mock
def test_a_remembered_region_that_is_not_configured_is_never_asked(tmp_path: Path) -> None:
    now = [_NOW]
    mocked = _mock(found_in="Zachód")
    memo = _memo(tmp_path, now)
    memo.remember(_NODE, "Rzeszów")
    source, _ = _source(tmp_path, now, memo=memo)

    observation = source.fetch_node(_NODE)

    assert observation is not None
    assert mocked.calls() == {"status": 1, "Zachód": 1, "Gdańsk": 0, "Rzeszów": 0}
    assert _memo(tmp_path, now).region_for(_NODE) == "Zachód"


@respx.mock
def test_a_remembered_region_that_is_not_configured_is_kept_when_nothing_answers(
    tmp_path: Path,
) -> None:
    now = [_NOW]
    _mock(found_in=None)
    memo = _memo(tmp_path, now)
    memo.remember(_NODE, "Rzeszów")
    source, _ = _source(tmp_path, now, memo=memo)

    assert source.fetch_node(_NODE) is None
    assert _memo(tmp_path, now).region_for(_NODE) == "Rzeszów"


@respx.mock
def test_without_a_memo_the_probe_and_every_region_are_still_asked(tmp_path: Path) -> None:
    now = [_NOW]
    mocked = _mock(found_in="Gdańsk")
    source, _ = _source(tmp_path, now, memo=None)

    assert source.fetch_node(_NODE) is not None
    assert source.fetch_node(_NODE, force_refresh=True) is not None
    assert mocked.calls() == {"status": 2, "Zachód": 2, "Gdańsk": 2, "Rzeszów": 0}


@respx.mock
def test_a_single_region_is_asked_directly_without_probe_or_memo(tmp_path: Path) -> None:
    now = [_NOW]
    mocked = _mock(found_in=None)
    memo = _memo(tmp_path, now)
    memo.remember(_NODE, "Zachód")
    source, client = _source(tmp_path, now, regions=("Gdańsk",), memo=memo)

    assert source.fetch_node(_NODE) is None
    assert mocked.calls() == {"status": 0, "Zachód": 0, "Gdańsk": 1, "Rzeszów": 0}
    assert client.stats.network_requests == 1
    assert _memo(tmp_path, now).region_for(_NODE) == "Zachód"


@respx.mock
def test_an_explicit_region_skips_the_probe_and_the_memo(tmp_path: Path) -> None:
    now = [_NOW]
    mocked = _mock(found_in="Rzeszów")
    memo = _memo(tmp_path, now)
    memo.remember(_NODE, "Gdańsk")
    source, _ = _source(tmp_path, now, memo=memo)

    observation = source.fetch_node(_NODE, region="Rzeszów")

    assert observation is not None
    assert mocked.calls() == {"status": 0, "Zachód": 0, "Gdańsk": 0, "Rzeszów": 1}
    assert _memo(tmp_path, now).region_for(_NODE) == "Gdańsk"


@pytest.mark.parametrize("status", [403, 410, 502])
@respx.mock
def test_any_other_status_answer_fails_the_source_without_asking_a_region(
    tmp_path: Path, status: int
) -> None:
    now = [_NOW]
    mocked = _mock(status=status, found_in="Gdańsk")
    source, _ = _source(tmp_path, now)

    with pytest.raises(HttpError) as exc_info:
        source.fetch_node(_NODE)
    assert exc_info.value.status_code == status
    assert {k: v for k, v in mocked.calls().items() if k != "status"} == {
        "Zachód": 0,
        "Gdańsk": 0,
        "Rzeszów": 0,
    }


@respx.mock
def test_an_unreachable_status_endpoint_fails_the_source_after_its_retries(
    tmp_path: Path,
) -> None:
    now = [_NOW]
    mocked = _mock(status=httpx.ConnectError("refused"), found_in="Gdańsk")
    source, _ = _source(tmp_path, now)

    with pytest.raises(HttpError):
        source.fetch_node(_NODE)
    assert mocked.calls() == {
        "status": DEFAULT_MAX_RETRIES + 1,
        "Zachód": 0,
        "Gdańsk": 0,
        "Rzeszów": 0,
    }


@respx.mock
def test_a_rate_limited_status_probe_stops_every_lorastats_request(tmp_path: Path) -> None:
    now = [_NOW]
    mocked = _mock(status=httpx.Response(429, headers={"Retry-After": "600"}), found_in="Gdańsk")
    source, client = _source(tmp_path, now)

    with pytest.raises(RateLimitError):
        source.fetch_nodes([_NODE, _OTHER])
    with pytest.raises(RateLimitError):
        source.fetch_node(_OTHER)
    assert mocked.calls() == {"status": 1, "Zachód": 0, "Gdańsk": 0, "Rzeszów": 0}
    assert client.stats.network_requests == 1


@respx.mock
def test_the_status_probe_does_not_count_toward_data_as_of(tmp_path: Path) -> None:
    now = [_NOW]
    _mock(found_in="Gdańsk")
    source, _ = _source(tmp_path, now, ttl=0.0)
    source.fetch_node(_NODE)  # caches the probe answer at _NOW

    now[0] += 120  # past the 60 s floor of the region responses, not the probe's
    source.fetch_node(_NODE)

    assert source.last_fetch_data_as_of == datetime.fromtimestamp(_NOW + 120, tz=UTC)


@respx.mock
def test_an_unknown_node_has_no_data_as_of(tmp_path: Path) -> None:
    now = [_NOW]
    _mock(status=404)
    source, _ = _source(tmp_path, now)

    assert source.fetch_node(_NODE) is None
    assert source.last_fetch_data_as_of is None


@respx.mock
def test_fetch_nodes_costs_each_node_at_most_one_more_request_than_regions(
    tmp_path: Path,
) -> None:
    """The worst case: a stale memo, then every region. The memo hit costs one."""
    now = [_NOW]
    mocked = _mock(found_in="Gdańsk")
    memo = _memo(tmp_path, now)
    memo.remember(_NODE, "Zachód")  # stale
    memo.remember(_OTHER, "Gdańsk")  # current
    source, client = _source(tmp_path, now, memo=memo)

    result = source.fetch_nodes([_NODE, _OTHER])

    assert set(result) == {_NODE, _OTHER}
    assert client.stats.network_requests == (1 + len(_REGIONS)) + 1
    assert mocked.calls() == {"status": 1, "Zachód": 1, "Gdańsk": 2, "Rzeszów": 0}


@respx.mock
def test_skipped_records_are_summed_across_the_memo_and_the_other_regions(
    tmp_path: Path,
) -> None:
    now = [_NOW]
    respx.get(LORASTATS_BASE_URL + LORASTATS_STATUS_PATH.format(node=_NODE.hex)).mock(
        return_value=httpx.Response(200)
    )
    for region in _REGIONS:
        respx.get(url__startswith=_region_url(region)).mock(
            return_value=httpx.Response(200, json=[{"ShortName": "no id"}])
        )
    memo = _memo(tmp_path, now)
    memo.remember(_NODE, "Gdańsk")
    source, _ = _source(tmp_path, now, memo=memo)

    assert source.fetch_node(_NODE) is None
    assert source.last_fetch_skipped == len(_REGIONS)


def test_at_most_sixteen_regions_can_be_configured() -> None:
    limit = tuple(f"R{i}" for i in range(LORASTATS_MAX_REGIONS))
    assert validate_regions(limit) == limit
    with pytest.raises(SettingsError, match="At most 16 lorastats regions"):
        validate_regions((*limit, "R16"))


def test_duplicates_do_not_count_toward_the_region_limit() -> None:
    limit = tuple(f"R{i}" for i in range(LORASTATS_MAX_REGIONS))
    assert validate_regions((*limit, "R0")) == limit


@pytest.mark.parametrize(
    "regions",
    [
        pytest.param(LORASTATS_NODES_PAGE_REGIONS, id="lorastats-pl-list"),
        pytest.param(tuple(f"R{i}" for i in range(LORASTATS_MAX_REGIONS)), id="the-limit"),
    ],
)
@respx.mock
def test_a_known_node_found_nowhere_costs_one_status_and_one_request_per_region(
    tmp_path: Path, regions: tuple[str, ...]
) -> None:
    now = [_NOW]
    respx.get(url__regex=r"^https://lorastats\.pl/Node/[0-9a-f]{8}/Status$").mock(
        return_value=httpx.Response(500)
    )
    nodes = respx.get(url__regex=r"^https://lorastats\.pl/API/[^/]+/Nodes/JSON").mock(
        return_value=httpx.Response(200, json=[])
    )
    source, client = _source(tmp_path, now, regions=regions, memo=_memo(tmp_path, now))

    assert source.fetch_node(_NODE) is None
    assert nodes.call_count == len(regions)
    assert client.stats.network_requests == 1 + len(regions) <= 1 + LORASTATS_MAX_REGIONS
    asked = [call.request.url.raw_path.decode().split("/")[2] for call in nodes.calls]
    assert asked == [quote(region, safe="") for region in regions]  # in order, percent-encoded
