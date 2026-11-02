"""``RegionRefresher`` and region selection: the request budget, incremental fetches, outages."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
import respx

from meshprovision.cache.http import DEFAULT_MAX_RETRIES, CachedHTTPClient
from meshprovision.datasources.lorastats import LORASTATS_BASE_URL
from meshprovision.datasources.lorastats_region import LorastatsRegionFeed
from meshprovision.datasources.models import NodeObservation
from meshprovision.errors import (
    DataSourceError,
    HttpError,
    InvalidResponseError,
    RateLimitError,
    SettingsError,
)
from meshprovision.health.history import HOUR_SECONDS, floor_hour
from meshprovision.network.keystore import KeyStore
from meshprovision.network.refresh import (
    NETWORK_DEFAULT_MAX_REGIONS,
    NETWORK_FORCED_REFRESH_INTERVAL_SECONDS,
    NETWORK_REFRESH_INTERVAL_SECONDS,
    NetworkRefresh,
    RegionFailure,
    RegionRefresher,
    select_regions,
)
from meshprovision.network.store import RegionState, RegionStore
from meshprovision.nodeid import NodeId
from tests.unit.network_fixtures import NOW, T0, packet, row

pytestmark = pytest.mark.unit

_O = "ab446357"
_NODE = NodeObservation(
    node_id=NodeId.from_hex("c464e761"),
    source="lorastats",
    observed_at=datetime.fromtimestamp(NOW, tz=UTC),
)


@dataclass
class _Feed:
    """A stand-in for ``LorastatsRegionFeed`` that records every request."""

    rows: list[Any] = field(default_factory=lambda: [row(packet(0xAB446357, 1))])
    fail_for: dict[tuple[str, str], Exception] = field(default_factory=dict)
    calls: list[tuple[str, str, float | None]] = field(default_factory=list)

    def _check(self, kind: str, region: str, since: float | None) -> None:
        self.calls.append((kind, region, since))
        error = self.fail_for.get((kind, region))
        if error is not None:
            raise error

    def raw(self, region: str, *, since: float | None) -> list[Any]:
        self._check("raw", region, since)
        return self.rows

    def nodes(self, region: str) -> tuple[NodeObservation, ...]:
        self._check("nodes", region, None)
        return (_NODE,)


def _setup(
    tmp_path: Path, *, force: bool = False
) -> tuple[RegionRefresher, _Feed, RegionStore, list[float]]:
    now = [NOW]
    store = RegionStore(tmp_path / "network", clock=lambda: now[0])
    feed = _Feed()
    refresher = RegionRefresher(
        store,
        cast("LorastatsRegionFeed", feed),
        keys=KeyStore(tmp_path / "network", clock=lambda: now[0]),
        known_bad=frozenset(),
        force=force,
        clock=lambda: now[0],
    )
    return refresher, feed, store, now


def test_a_first_refresh_asks_for_everything_and_stores_it(tmp_path: Path) -> None:
    refresher, feed, store, _ = _setup(tmp_path)
    feed.rows = [*feed.rows, "not a row"]

    outcome = refresher.refresh(["Zachód"])

    assert feed.calls == [("raw", "Zachód", None), ("nodes", "Zachód", None)]
    assert outcome == NetworkRefresh(
        refreshed=("Zachód",), nodes={"Zachód": (_NODE,)}, skipped_rows=1
    )
    assert store.state("Zachód") == RegionState(fetched_at=NOW, skipped_rows=1)
    hours = store.load("Zachód", start=0)
    assert [bucket.hour for bucket in hours] == [floor_hour(T0), floor_hour(NOW)]
    assert hours[0].traffic.packets == {_O: 1}


def test_within_the_interval_only_the_node_list_is_asked(tmp_path: Path) -> None:
    refresher, feed, _, now = _setup(tmp_path)
    refresher.refresh(["Zachód"])
    feed.calls.clear()
    now[0] = NOW + NETWORK_REFRESH_INTERVAL_SECONDS - 1

    outcome = refresher.refresh(["Zachód"])

    assert feed.calls == [("nodes", "Zachód", None)]
    assert outcome.refreshed == ()


def test_after_the_interval_it_asks_from_an_hour_before_the_previous_fetchs_hour(
    tmp_path: Path,
) -> None:
    refresher, feed, store, now = _setup(tmp_path)
    refresher.refresh(["Zachód"])
    feed.calls.clear()
    now[0] = NOW + NETWORK_REFRESH_INTERVAL_SECONDS
    margin = [row(packet(0xAB446357, n), time=floor_hour(NOW) - 30) for n in (3, 4)]
    feed.rows = [*margin, row(packet(0xAB446357, 2), time=NOW + 60)]

    refresher.refresh(["Zachód"])

    assert feed.calls[0] == ("raw", "Zachód", floor_hour(NOW) - HOUR_SECONDS)
    hours = {bucket.hour: bucket.traffic for bucket in store.load("Zachód", start=0)}
    assert hours[floor_hour(T0)].packets == {_O: 1}
    assert hours[floor_hour(NOW)].packets == {_O: 1}


def test_a_refresh_replaces_the_hours_it_asked_for(tmp_path: Path) -> None:
    refresher, feed, store, now = _setup(tmp_path)
    feed.rows = [row(packet(0xAB446357, n), time=NOW + 10) for n in (1, 2)]
    refresher.refresh(["Zachód"])
    now[0] = NOW + NETWORK_REFRESH_INTERVAL_SECONDS

    refresher.refresh(["Zachód"])

    (hour,) = store.load("Zachód", start=NOW)
    assert hour.hour == floor_hour(NOW)
    assert hour.traffic.packets == {_O: 2}
    assert hour.traffic.direct[_O]["bbad0594"].receptions == 2


@pytest.mark.parametrize(
    ("force", "elapsed", "asked"),
    [
        (False, NETWORK_REFRESH_INTERVAL_SECONDS - 1, False),
        (False, NETWORK_REFRESH_INTERVAL_SECONDS, True),
        (True, NETWORK_FORCED_REFRESH_INTERVAL_SECONDS - 1, False),
        (True, NETWORK_FORCED_REFRESH_INTERVAL_SECONDS, True),
    ],
)
def test_the_interval_and_the_forced_interval(
    tmp_path: Path, force: bool, elapsed: float, asked: bool
) -> None:
    refresher, feed, _, now = _setup(tmp_path, force=force)
    refresher.refresh(["Zachód"])
    feed.calls.clear()
    now[0] = NOW + elapsed

    refresher.refresh(["Zachód"])

    assert ("raw" in {call[0] for call in feed.calls}) is asked


def test_a_fetch_stored_in_the_future_does_not_block_and_is_not_asked_from(
    tmp_path: Path,
) -> None:
    refresher, feed, store, _ = _setup(tmp_path)
    store.update("Zachód", [], fetched_at=NOW + 2 * HOUR_SECONDS, skipped_rows=0)

    refresher.refresh(["Zachód"])

    assert feed.calls[0] == ("raw", "Zachód", floor_hour(NOW) - HOUR_SECONDS)


def test_a_fetch_stored_a_year_ahead_is_replaced_so_the_interval_holds_again(
    tmp_path: Path,
) -> None:
    refresher, feed, store, now = _setup(tmp_path)
    store.update("Zachód", [], fetched_at=NOW + 365 * 24 * HOUR_SECONDS, skipped_rows=0)
    refresher.refresh(["Zachód"])
    feed.calls.clear()
    now[0] = NOW + NETWORK_FORCED_REFRESH_INTERVAL_SECONDS

    refresher.refresh(["Zachód"])

    assert store.state("Zachód").fetched_at == NOW
    assert feed.calls == [("nodes", "Zachód", None)]


def test_a_fetch_just_inside_the_future_skew_counts(tmp_path: Path) -> None:
    refresher, feed, store, _ = _setup(tmp_path)
    store.update("Zachód", [], fetched_at=NOW + 300, skipped_rows=0)

    refresher.refresh(["Zachód"])

    assert feed.calls == [("nodes", "Zachód", None)]


def _transport_error() -> HttpError:
    try:
        raise HttpError("unreachable", url="u") from httpx.ConnectError("refused")
    except HttpError as exc:
        return exc


_DOWN = [
    pytest.param(HttpError("503", url="u", status_code=503, hint="later"), id="503"),
    pytest.param(_transport_error(), id="transport"),
    pytest.param(RateLimitError("slow", url="u", status_code=429), id="429"),
]
_ONE_ANSWER = [
    pytest.param(HttpError("gone", url="u", status_code=404, hint="h"), id="404"),
    pytest.param(InvalidResponseError("html", url="u", status_code=200), id="invalid"),
    pytest.param(HttpError("too large", url="u"), id="too-large"),
    pytest.param(DataSourceError("odd"), id="other"),
]


@pytest.mark.parametrize("error", _DOWN)
def test_lorastats_failing_for_one_region_stops_the_refresh(
    tmp_path: Path, error: DataSourceError
) -> None:
    refresher, feed, store, _ = _setup(tmp_path)
    feed.fail_for[("raw", "A")] = error

    outcome = refresher.refresh(["A", "B"])

    assert feed.calls == [("raw", "A", None)]
    not_asked = f"not asked: lorastats failed for A ({error.message})"
    assert outcome == NetworkRefresh(
        failures=(
            RegionFailure("A", error.message, error.hint),
            RegionFailure("A", not_asked),
            RegionFailure("B", not_asked),
            RegionFailure("B", not_asked),
        )
    )
    assert store.state("B") == RegionState()


@pytest.mark.parametrize("error", _ONE_ANSWER)
def test_a_failed_answer_is_reported_and_the_others_still_asked(
    tmp_path: Path, error: DataSourceError
) -> None:
    refresher, feed, store, _ = _setup(tmp_path)
    feed.fail_for[("raw", "A")] = error

    outcome = refresher.refresh(["A", "B"])

    assert [call[:2] for call in feed.calls] == [
        ("raw", "A"),
        ("nodes", "A"),
        ("raw", "B"),
        ("nodes", "B"),
    ]
    assert outcome.failures == (RegionFailure("A", error.message, error.hint),)
    assert outcome.refreshed == ("B",)
    assert store.state("A") == RegionState()


@respx.mock
def test_a_503_storm_costs_one_request_and_its_retries(tmp_path: Path) -> None:
    route = respx.get(url__startswith=f"{LORASTATS_BASE_URL}/API/").mock(
        return_value=httpx.Response(503)
    )
    slept: list[float] = []
    client = CachedHTTPClient(
        cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)", sleep=slept.append
    )
    refresher = RegionRefresher(
        RegionStore(tmp_path / "network"),
        LorastatsRegionFeed(client),
        keys=KeyStore(tmp_path / "network"),
        known_bad=frozenset(),
    )

    outcome = refresher.refresh(["A", "B", "C"])

    assert route.call_count == DEFAULT_MAX_RETRIES + 1
    assert len(slept) == DEFAULT_MAX_RETRIES
    assert len(outcome.failures) == 6


def test_a_failed_node_list_is_reported_and_its_region_left_without_one(
    tmp_path: Path,
) -> None:
    refresher, feed, _, _ = _setup(tmp_path)
    feed.fail_for[("nodes", "A")] = HttpError("gone", url="u", status_code=404)

    outcome = refresher.refresh(["A", "B"])

    assert outcome.refreshed == ("A", "B")
    assert dict(outcome.nodes) == {"B": (_NODE,)}
    assert outcome.failures == (RegionFailure("A", "gone"),)


def test_an_outage_on_the_node_list_stops_the_next_region(tmp_path: Path) -> None:
    refresher, feed, _, _ = _setup(tmp_path)
    feed.fail_for[("nodes", "A")] = RateLimitError("slow", url="u", status_code=429)

    outcome = refresher.refresh(["A", "B"])

    assert [call[:2] for call in feed.calls] == [("raw", "A"), ("nodes", "A")]
    assert outcome.refreshed == ("A",)
    assert len(outcome.failures) == 3


def test_selected_regions_are_validated_and_deduplicated() -> None:
    assert select_regions(["PL", " Zachód", "PL"], [None]) == ("PL", "Zachód")


@pytest.mark.parametrize("asked", [["../Nodes"], [str(n) for n in range(17)]])
def test_a_bad_region_list_is_refused(asked: list[str]) -> None:
    with pytest.raises(SettingsError):
        select_regions(asked, ["PL"])


def test_without_regions_asked_our_nodes_regions_are_used_busiest_first() -> None:
    fleet = ["B", None, "A", "A", "C", "B", "A", "D", "E", "../x", "Zachód"]

    assert select_regions([], fleet) == ("A", "B", "C", "D")
    assert NETWORK_DEFAULT_MAX_REGIONS == 4


def test_without_any_region_known_the_hint_says_how_to_get_one() -> None:
    with pytest.raises(SettingsError) as error:
        select_regions([], [None, "../x"])

    assert error.value.hint is not None
    assert "--region" in error.value.hint
