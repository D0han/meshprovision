"""``HealthRefresher``: incremental refreshes within the per-node request budget."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from meshprovision.cache.http import DEFAULT_MAX_RETRIES, CachedHTTPClient
from meshprovision.datasources.lorastats import LORASTATS_BASE_URL
from meshprovision.datasources.lorastats_packets import LorastatsPackets
from meshprovision.errors import DataSourceError, HttpError, InvalidResponseError, RateLimitError
from meshprovision.health.history import (
    HOUR_SECONDS,
    GatewayCheck,
    HourBucket,
    NodeHistory,
    floor_hour,
)
from meshprovision.health.refresh import (
    FORCED_REFRESH_INTERVAL_SECONDS,
    GATEWAY_CHECK_INTERVAL_SECONDS,
    GATEWAY_CHECK_WINDOW_SECONDS,
    REFRESH_INTERVAL_SECONDS,
    SINCE_MARGIN_SECONDS,
    STATUS_REFRESH_INTERVAL_SECONDS,
    HealthRefresher,
    RefreshFailure,
)
from meshprovision.health.store import HISTORY_DIRNAME, HistoryStore
from meshprovision.nodeid import NodeId

pytestmark = pytest.mark.unit

_NODE = NodeId.from_hex("ab446357")
_OTHER = NodeId.from_hex("979ed146")
_NOW = datetime(2026, 10, 20, 20, 30, tzinfo=UTC).timestamp()


def _row(node: NodeId, minutes_ago: float, *, packet: str = "1", **extra: object) -> dict[str, Any]:
    stamp = datetime.fromtimestamp(_NOW - minutes_ago * 60, tz=UTC).isoformat()
    return {"Time": stamp, "FromNode": node.hex, "PacketId": packet, **extra}


@dataclass
class _Packets:
    """A stand-in for ``LorastatsPackets`` that records every request."""

    reports_rows: list[Any] = field(default_factory=list)
    decoded_rows: list[Any] = field(default_factory=list)
    uplinked_rows: list[Any] = field(default_factory=list)
    fail: Exception | None = None
    fail_for: dict[tuple[str, str], Exception] = field(default_factory=dict)
    calls: list[tuple[str, str, str, float | None]] = field(default_factory=list)

    def _answer(self, kind: str, node: NodeId, region: str, since: float | None) -> list[Any]:
        self.calls.append((kind, node.hex, region, since))
        error = self.fail_for.get((kind, node.hex), self.fail)
        if error is not None:
            raise error
        return {"reports": self.reports_rows, "decoded": self.decoded_rows}.get(
            kind, self.uplinked_rows
        )

    def reports(self, node: NodeId, region: str, *, since: float | None) -> list[Any]:
        return self._answer("reports", node, region, since)

    def decoded(self, node: NodeId, region: str, *, since: float | None) -> list[Any]:
        return self._answer("decoded", node, region, since)

    def uplinked(self, gateway: NodeId, region: str, *, since: float) -> list[Any]:
        return self._answer("uplinked", gateway, region, since)


def _setup(
    tmp_path: Path,
    *,
    force: bool = False,
    interval: float | None = None,
    packets: _Packets | None = None,
) -> tuple[HealthRefresher, _Packets, HistoryStore, list[float]]:
    now = [_NOW]
    store = HistoryStore(tmp_path / "cache" / HISTORY_DIRNAME, clock=lambda: now[0])
    fake = packets or _Packets(
        reports_rows=[
            _row(_NODE, 180, packet="0", Gateway="bbad0594"),
            _row(_NODE, 5, Gateway="bbad0594", RelayNode=0x61, HopLimit=5),
            _row(_NODE, 5, Gateway="0000000a", RelayNode=0x57, HopLimit=7),
            "junk",
        ],
        decoded_rows=[_row(_NODE, 5, HopStart=7, PortNum=67, Payload="50% Bat"), 7],
    )
    refresher = HealthRefresher(
        store,
        fake,  # type: ignore[arg-type]
        force=force,
        interval=interval,
        clock=lambda: now[0],
    )
    return refresher, fake, store, now


def test_the_constants_are_the_documented_ones() -> None:
    assert (
        REFRESH_INTERVAL_SECONDS,
        FORCED_REFRESH_INTERVAL_SECONDS,
        STATUS_REFRESH_INTERVAL_SECONDS,
        GATEWAY_CHECK_INTERVAL_SECONDS,
        GATEWAY_CHECK_WINDOW_SECONDS,
        SINCE_MARGIN_SECONDS,
    ) == (600.0, 60.0, 3600.0, 3600.0, 3600.0, 3600)


def test_a_first_refresh_asks_for_everything_and_stores_the_history(tmp_path: Path) -> None:
    refresher, packets, store, _ = _setup(tmp_path)

    outcome = refresher.refresh([(_NODE, "Zachód")])

    assert packets.calls == [
        ("reports", _NODE.hex, "Zachód", None),
        ("decoded", _NODE.hex, "Zachód", None),
    ]
    assert outcome.refreshed == (_NODE,)
    assert outcome.skipped_rows == 2
    history = outcome.histories[_NODE]
    assert history == store.load(_NODE)
    assert history.fetched_at == _NOW
    bucket = {b.hour: b for b in history.hours}[floor_hour(_NOW - 300)]
    assert (bucket.receptions, bucket.packets, bucket.direct) == (2, 1, 1)
    assert dict(bucket.hops) == {0: 1, 2: 1}
    assert history.telemetry[0].battery == 50


def test_a_node_is_not_asked_again_within_the_refresh_interval(tmp_path: Path) -> None:
    refresher, packets, _, now = _setup(tmp_path)
    refresher.refresh([(_NODE, "Zachód")])
    packets.calls.clear()
    now[0] = _NOW + REFRESH_INTERVAL_SECONDS - 1

    outcome = refresher.refresh([(_NODE, "Zachód")])

    assert packets.calls == []
    assert outcome.refreshed == ()
    assert outcome.histories[_NODE].fetched_at == _NOW


def test_a_due_refresh_asks_from_an_hour_before_the_previous_refreshs_hour(tmp_path: Path) -> None:
    refresher, packets, _, now = _setup(tmp_path)
    refresher.refresh([(_NODE, "Zachód")])
    packets.calls.clear()
    now[0] = _NOW + REFRESH_INTERVAL_SECONDS

    outcome = refresher.refresh([(_NODE, "Zachód")])

    since = floor_hour(_NOW) - SINCE_MARGIN_SECONDS
    assert packets.calls == [
        ("reports", _NODE.hex, "Zachód", since),
        ("decoded", _NODE.hex, "Zachód", since),
    ]
    history = outcome.histories[_NODE]
    assert history.fetched_at == _NOW + REFRESH_INTERVAL_SECONDS
    assert sum(b.receptions for b in history.hours) == 3
    assert history.hours[0].hour == floor_hour(_NOW - 180 * 60)


def test_a_forced_refresh_still_waits_for_the_lorastats_ttl_floor(tmp_path: Path) -> None:
    refresher, packets, _, now = _setup(tmp_path, force=True)
    refresher.refresh([(_NODE, "PL")])
    now[0] = _NOW + FORCED_REFRESH_INTERVAL_SECONDS - 1
    refresher.refresh([(_NODE, "PL")])
    assert len(packets.calls) == 2

    now[0] = _NOW + FORCED_REFRESH_INTERVAL_SECONDS
    refresher.refresh([(_NODE, "PL")])

    assert len(packets.calls) == 4


@pytest.mark.parametrize("force", [False, True])
def test_an_explicit_interval_wins_over_the_default_and_forced_ones(
    tmp_path: Path, force: bool
) -> None:
    refresher, packets, _, now = _setup(
        tmp_path, force=force, interval=STATUS_REFRESH_INTERVAL_SECONDS
    )
    refresher.refresh([(_NODE, "PL")])
    now[0] = _NOW + STATUS_REFRESH_INTERVAL_SECONDS - 1
    refresher.refresh([(_NODE, "PL")])
    assert len(packets.calls) == 2

    now[0] = _NOW + STATUS_REFRESH_INTERVAL_SECONDS
    refresher.refresh([(_NODE, "PL")])

    assert len(packets.calls) == 4


def test_the_interval_holds_within_a_process_even_when_nothing_could_be_stored(
    tmp_path: Path,
) -> None:
    now = [_NOW]
    (tmp_path / "blocker").write_text("a file, not a directory")
    store = HistoryStore(tmp_path / "blocker" / HISTORY_DIRNAME, clock=lambda: now[0])
    packets = _Packets()
    refresher = HealthRefresher(store, packets, clock=lambda: now[0])  # type: ignore[arg-type]
    refresher.refresh([(_NODE, "PL")])
    now[0] = _NOW + REFRESH_INTERVAL_SECONDS - 1

    refresher.refresh([(_NODE, "PL")])

    assert len(packets.calls) == 2


def test_a_refresh_time_in_the_future_does_not_block_refreshing(tmp_path: Path) -> None:
    refresher, packets, store, _ = _setup(tmp_path)
    store.update(_NODE, lambda _old: NodeHistory(node=_NODE, fetched_at=_NOW + 86400))

    refresher.refresh([(_NODE, "PL")])

    assert [call[0] for call in packets.calls] == ["reports", "decoded"]
    assert packets.calls[0][3] == floor_hour(_NOW) - SINCE_MARGIN_SECONDS


@pytest.mark.parametrize(("back", "asked"), [(86400.0, True), (301.0, True), (300.0, False)])
def test_a_gateway_check_from_the_future_does_not_block_checking(
    tmp_path: Path, back: float, asked: bool
) -> None:
    # The clock stepped back after a check: that check now lies in the future.
    refresher, packets, _, now = _setup(tmp_path)
    now[0] = _NOW + back
    refresher.refresh([(_NODE, "PL")], gateway_check=True)
    now[0] = _NOW

    refresher.refresh([(_NODE, "PL")], gateway_check=True)

    uplinked = [call for call in packets.calls if call[0] == "uplinked"]
    assert len(uplinked) == (2 if asked else 1)


def test_a_node_without_a_region_is_never_asked_about(tmp_path: Path) -> None:
    refresher, packets, _, _ = _setup(tmp_path)

    outcome = refresher.refresh([(_NODE, None), (_OTHER, "PL")], gateway_check=True)

    assert outcome.no_region == (_NODE,)
    assert {call[1] for call in packets.calls} == {_OTHER.hex}
    assert outcome.histories[_NODE] == NodeHistory(node=_NODE)


def _transport_error() -> HttpError:
    try:
        raise HttpError("unreachable", url="u") from httpx.ConnectError("refused")
    except HttpError as exc:
        return exc


_DOWN = [
    pytest.param(HttpError("503", url="u", status_code=503, hint="try later"), id="503"),
    pytest.param(HttpError("500", url="u", status_code=500), id="500"),
    pytest.param(_transport_error(), id="transport"),
    pytest.param(RateLimitError("slow", url="u", status_code=429), id="429"),
]
_NODE_ONLY = [
    pytest.param(HttpError("gone", url="u", status_code=404, hint="h"), id="404"),
    pytest.param(HttpError("499", url="u", status_code=499), id="499"),
    pytest.param(InvalidResponseError("html", url="u", status_code=200), id="invalid"),
    pytest.param(
        InvalidResponseError("bad gateway page", url="u", status_code=502), id="invalid-5xx"
    ),
    pytest.param(HttpError("too large", url="u"), id="too-large"),
    pytest.param(DataSourceError("odd"), id="other"),
]


@pytest.mark.parametrize("error", _NODE_ONLY)
def test_a_failed_request_is_reported_and_leaves_the_history_alone(
    tmp_path: Path, error: DataSourceError
) -> None:
    refresher, packets, store, now = _setup(tmp_path)
    packets.fail = error

    outcome = refresher.refresh([(_NODE, "PL"), (_OTHER, "PL")])

    assert outcome.failures == (
        RefreshFailure(_NODE, error.message, error.hint),
        RefreshFailure(_OTHER, error.message, error.hint),
    )
    assert outcome.refreshed == ()
    assert [call[0] for call in packets.calls] == ["reports", "reports"]
    assert store.load(_NODE) == NodeHistory(node=_NODE)
    packets.calls.clear()
    now[0] = _NOW + REFRESH_INTERVAL_SECONDS - 1
    refresher.refresh([(_NODE, "PL")])
    assert packets.calls == []


@pytest.mark.parametrize("error", _DOWN)
def test_lorastats_failing_for_one_node_stops_the_refresh_of_the_others(
    tmp_path: Path, error: DataSourceError
) -> None:
    """20 due nodes against a 503 cost 80 requests and 70 s of back-off before the table."""
    refresher, packets, store, _ = _setup(tmp_path)
    packets.fail = error
    nodes = [(NodeId.from_int(index + 1), "PL") for index in range(20)]

    outcome = refresher.refresh(nodes)

    assert [call[1] for call in packets.calls] == [NodeId.from_int(1).hex]
    assert outcome.refreshed == ()
    assert outcome.failures[0] == RefreshFailure(nodes[0][0], error.message, error.hint)
    not_asked = f"not asked: lorastats failed for {nodes[0][0].hex} ({error.message})"
    assert outcome.failures[1:] == tuple(RefreshFailure(node, not_asked) for node, _ in nodes[1:])
    assert store.load(nodes[1][0]) == NodeHistory(node=nodes[1][0])


@respx.mock
def test_a_503_storm_costs_one_node_its_retries_and_nothing_more(tmp_path: Path) -> None:
    route = respx.get(url__startswith=f"{LORASTATS_BASE_URL}/API/").mock(
        return_value=httpx.Response(503)
    )
    slept: list[float] = []
    client = CachedHTTPClient(
        cache_dir=tmp_path / "cache", user_agent="mp/1 (+t@example.invalid)", sleep=slept.append
    )
    store = HistoryStore(tmp_path / "cache" / HISTORY_DIRNAME)
    refresher = HealthRefresher(store, LorastatsPackets(client))
    nodes = [(NodeId.from_int(index + 1), "Zachód") for index in range(20)]

    outcome = refresher.refresh(nodes, gateway_check=True)

    assert route.call_count == DEFAULT_MAX_RETRIES + 1
    assert len(slept) == DEFAULT_MAX_RETRIES
    assert len(outcome.failures) == 2 * len(nodes)


def test_a_failure_of_one_node_still_asks_the_next_nodes(tmp_path: Path) -> None:
    refresher, packets, _, _ = _setup(tmp_path)
    packets.fail_for[("reports", _NODE.hex)] = HttpError("gone", url="u", status_code=404)

    outcome = refresher.refresh([(_NODE, "PL"), (_OTHER, "PL")])

    assert outcome.refreshed == (_OTHER,)
    assert outcome.failures == (RefreshFailure(_NODE, "gone"),)


def test_the_next_refresh_asks_the_nodes_it_did_not_ask_again(tmp_path: Path) -> None:
    refresher, packets, _, now = _setup(tmp_path)
    packets.fail_for[("reports", _NODE.hex)] = HttpError("503", url="u", status_code=503)
    refresher.refresh([(_NODE, "PL"), (_OTHER, "PL")])
    packets.calls.clear()
    packets.fail_for.clear()
    now[0] = _NOW + 1

    outcome = refresher.refresh([(_NODE, "PL"), (_OTHER, "PL")])

    assert [call[:2] for call in packets.calls] == [
        ("reports", _OTHER.hex),
        ("decoded", _OTHER.hex),
    ]
    assert outcome.refreshed == (_OTHER,)
    assert outcome.failures == ()


def test_a_tripped_refresh_still_records_boot_times(tmp_path: Path) -> None:
    refresher, packets, store, _ = _setup(tmp_path)
    packets.fail = HttpError("503", url="u", status_code=503)

    refresher.refresh([(_NODE, "PL"), (_OTHER, "PL")], boots={_OTHER: _NOW - 5000})

    assert store.load(_OTHER).boots == (_NOW - 5000,)


def test_a_tripped_refresh_skips_the_gateway_checks_too(tmp_path: Path) -> None:
    refresher, packets, _, _ = _setup(tmp_path)
    packets.fail_for[("reports", _NODE.hex)] = HttpError("503", url="u", status_code=503)

    outcome = refresher.refresh([(_NODE, "PL"), (_OTHER, "PL")], gateway_check=True)

    assert [call[:2] for call in packets.calls] == [("reports", _NODE.hex)]
    not_asked = f"not asked: lorastats failed for {_NODE.hex} (503)"
    assert outcome.failures == (
        RefreshFailure(_NODE, "503"),
        RefreshFailure(_NODE, not_asked),
        RefreshFailure(_OTHER, not_asked),
        RefreshFailure(_OTHER, not_asked),
    )


def test_a_failing_gateway_check_stops_the_refresh_of_the_next_nodes(tmp_path: Path) -> None:
    refresher, packets, _, _ = _setup(tmp_path)
    packets.fail_for[("uplinked", _NODE.hex)] = HttpError("502", url="u", status_code=502)

    outcome = refresher.refresh([(_NODE, "PL"), (_OTHER, "PL")], gateway_check=True)

    assert [call[:2] for call in packets.calls] == [
        ("reports", _NODE.hex),
        ("decoded", _NODE.hex),
        ("uplinked", _NODE.hex),
    ]
    assert outcome.refreshed == (_NODE,)
    assert [failure.node for failure in outcome.failures] == [_NODE, _OTHER, _OTHER]


def test_a_node_only_gateway_check_failure_does_not_stop_the_refresh(tmp_path: Path) -> None:
    refresher, packets, _, _ = _setup(tmp_path)
    packets.fail_for[("uplinked", _NODE.hex)] = InvalidResponseError("html", url="u")

    outcome = refresher.refresh([(_NODE, "PL"), (_OTHER, "PL")], gateway_check=True)

    assert outcome.refreshed == (_NODE, _OTHER)
    assert [call[0] for call in packets.calls].count("uplinked") == 2


def test_one_warning_says_the_refresh_stopped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    refresher, packets, _, _ = _setup(tmp_path)
    packets.fail = HttpError("503", url="u", status_code=503)
    nodes = [(NodeId.from_int(index + 1), "PL") for index in range(5)]

    with caplog.at_level(logging.WARNING, logger="meshprovision.health.refresh"):
        refresher.refresh(nodes)

    assert [record.getMessage() for record in caplog.records] == [
        f"lorastats packets for {nodes[0][0].hex} failed: 503",
        "lorastats is failing; not asking it about any other node in this refresh",
    ]


def test_a_boot_time_is_recorded_once_without_a_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    refresher, packets, store, now = _setup(tmp_path)
    refresher.refresh([(_NODE, "PL")])
    packets.calls.clear()
    now[0] = _NOW + 1
    boot = _NOW - 5000
    writes: list[NodeId] = []
    update = store.update

    def counting_update(node: NodeId, change: Any, **kwargs: Any) -> NodeHistory:
        writes.append(node)
        return update(node, change, **kwargs)

    monkeypatch.setattr(store, "update", counting_update)

    refresher.refresh([(_NODE, "PL")], boots={_NODE: boot})
    outcome = refresher.refresh([(_NODE, "PL")], boots={_NODE: boot})

    assert packets.calls == []
    assert outcome.histories[_NODE].boots == (boot,)
    assert writes == [_NODE]


def test_a_boot_time_is_recorded_for_a_node_without_a_region(tmp_path: Path) -> None:
    refresher, packets, store, _ = _setup(tmp_path)

    refresher.refresh([(_NODE, None)], boots={_NODE: _NOW - 5})

    assert store.load(_NODE).boots == (_NOW - 5,)
    assert packets.calls == []


def test_a_gateway_check_counts_rows_and_senders_at_most_once_an_hour(tmp_path: Path) -> None:
    packets = _Packets(
        uplinked_rows=[
            _row(_NODE, 1),
            _row(_OTHER, 2),
            _row(_OTHER, 3, packet="2"),
            {"FromNode": "zz"},
            {"FromNode": 5},
            "junk",
        ]
    )
    refresher, _, store, now = _setup(tmp_path, packets=packets)

    refresher.refresh([(_NODE, "PL")], gateway_check=True)
    now[0] = _NOW + GATEWAY_CHECK_INTERVAL_SECONDS - 1
    refresher.refresh([(_NODE, "PL")], gateway_check=True)

    uplinked = [call for call in packets.calls if call[0] == "uplinked"]
    assert uplinked == [("uplinked", _NODE.hex, "PL", _NOW - 3600)]
    assert store.load(_NODE).gateway_checks == (GatewayCheck(_NOW, 3600.0, 6, 2),)
    now[0] = _NOW + GATEWAY_CHECK_INTERVAL_SECONDS
    refresher.refresh([(_NODE, "PL")], gateway_check=True)
    assert len([call for call in packets.calls if call[0] == "uplinked"]) == 2


def test_a_failed_gateway_check_is_reported_with_its_hint(tmp_path: Path) -> None:
    refresher, packets, _, _ = _setup(tmp_path)
    packets.fail_for[("uplinked", _NODE.hex)] = HttpError(
        "gone", url="u", status_code=404, hint="check the region"
    )

    outcome = refresher.refresh([(_NODE, "PL")], gateway_check=True)

    assert outcome.refreshed == (_NODE,)
    assert outcome.failures == (RefreshFailure(_NODE, "gone", "check the region"),)


def test_a_stored_gateway_check_counts_for_a_new_process(tmp_path: Path) -> None:
    refresher, packets, _, _ = _setup(tmp_path)
    refresher.refresh([(_NODE, "PL")], gateway_check=True)
    now = [_NOW + REFRESH_INTERVAL_SECONDS]
    store = HistoryStore(tmp_path / "cache" / HISTORY_DIRNAME, clock=lambda: now[0])
    fresh = HealthRefresher(store, packets, clock=lambda: now[0])  # type: ignore[arg-type]
    packets.calls.clear()

    fresh.refresh([(_NODE, "PL")], gateway_check=True)

    assert [call[0] for call in packets.calls] == ["reports", "decoded"]


def test_no_gateway_check_unless_asked(tmp_path: Path) -> None:
    refresher, packets, _, _ = _setup(tmp_path)

    refresher.refresh([(_NODE, "PL")])

    assert "uplinked" not in {call[0] for call in packets.calls}


def test_a_failed_gateway_check_is_reported_and_the_refresh_still_stored(tmp_path: Path) -> None:
    refresher, packets, store, _ = _setup(tmp_path)

    def uplinked(gateway: NodeId, region: str, *, since: float) -> list[Any]:
        raise HttpError("gateway check failed", url="u")

    packets.uplinked = uplinked  # type: ignore[method-assign]

    outcome = refresher.refresh([(_NODE, "PL")], gateway_check=True)

    assert outcome.failures == (RefreshFailure(_NODE, "gateway check failed"),)
    assert outcome.refreshed == (_NODE,)
    assert store.load(_NODE).fetched_at == _NOW


def test_every_due_node_costs_two_requests(tmp_path: Path) -> None:
    refresher, packets, _, _ = _setup(tmp_path)
    nodes = [(NodeId.from_int(index + 1), "PL") for index in range(5)]

    refresher.refresh(nodes)
    refresher.refresh(nodes)

    assert len(packets.calls) == 2 * len(nodes)


def test_the_hour_margin_is_one_hour() -> None:
    assert SINCE_MARGIN_SECONDS == HOUR_SECONDS


def test_the_margin_hour_is_asked_for_but_never_replaced(tmp_path: Path) -> None:
    refresher, packets, store, now = _setup(tmp_path)
    margin_hour = floor_hour(_NOW) - HOUR_SECONDS
    store.update(
        _NODE,
        lambda _old: NodeHistory(
            node=_NODE, fetched_at=_NOW - 60, hours=(HourBucket(margin_hour, receptions=5),)
        ),
    )
    now[0] = _NOW + REFRESH_INTERVAL_SECONDS

    outcome = refresher.refresh([(_NODE, "PL")])

    assert packets.calls[0][3] == margin_hour
    hours = {b.hour: b.receptions for b in outcome.histories[_NODE].hours}
    assert hours[margin_hour] == 5


def test_a_boot_time_and_a_due_refresh_are_both_recorded(tmp_path: Path) -> None:
    refresher, _, store, _ = _setup(tmp_path)

    refresher.refresh([(_NODE, "PL")], boots={_NODE: _NOW - 5000})

    history = store.load(_NODE)
    assert history.boots == (_NOW - 5000,)
    assert history.fetched_at == _NOW


def test_the_gateway_check_interval_holds_within_a_process_when_nothing_is_stored(
    tmp_path: Path,
) -> None:
    now = [_NOW]
    (tmp_path / "blocker").write_text("a file, not a directory")
    store = HistoryStore(tmp_path / "blocker" / HISTORY_DIRNAME, clock=lambda: now[0])
    packets = _Packets()
    refresher = HealthRefresher(store, packets, clock=lambda: now[0])  # type: ignore[arg-type]
    refresher.refresh([(_NODE, "PL")], gateway_check=True)
    now[0] = _NOW + REFRESH_INTERVAL_SECONDS

    refresher.refresh([(_NODE, "PL")], gateway_check=True)

    assert [call[0] for call in packets.calls].count("uplinked") == 1


def test_a_fleet_larger_than_the_file_cap_keeps_every_history(tmp_path: Path) -> None:
    """With 140 nodes each write evicted the oldest file: every run refetched everything."""
    refresher, packets, store, now = _setup(tmp_path, interval=STATUS_REFRESH_INTERVAL_SECONDS)
    nodes = [(NodeId.from_int(0x20000000 + index), "PL") for index in range(140)]
    refresher.refresh(nodes)
    packets.calls.clear()
    now[0] = _NOW + STATUS_REFRESH_INTERVAL_SECONDS

    refresher.refresh(nodes)

    assert len(list(store.directory.iterdir())) == 140
    assert len(packets.calls) == 2 * 140
    assert all(since is not None for _, _, _, since in packets.calls)
