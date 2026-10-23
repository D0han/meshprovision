"""``HealthRefresher``: incremental refreshes within the per-node request budget."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from meshprovision.errors import HttpError, RateLimitError
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
    calls: list[tuple[str, str, str, float | None]] = field(default_factory=list)

    def _answer(self, kind: str, node: NodeId, region: str, since: float | None) -> list[Any]:
        self.calls.append((kind, node.hex, region, since))
        if self.fail is not None:
            raise self.fail
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


def test_a_node_without_a_region_is_never_asked_about(tmp_path: Path) -> None:
    refresher, packets, _, _ = _setup(tmp_path)

    outcome = refresher.refresh([(_NODE, None), (_OTHER, "PL")], gateway_check=True)

    assert outcome.no_region == (_NODE,)
    assert {call[1] for call in packets.calls} == {_OTHER.hex}
    assert outcome.histories[_NODE] == NodeHistory(node=_NODE)


@pytest.mark.parametrize(
    "error", [HttpError("boom", url="u", hint="try later"), RateLimitError("slow", url="u")]
)
def test_a_failed_request_is_reported_and_leaves_the_history_alone(
    tmp_path: Path, error: Exception
) -> None:
    refresher, packets, store, now = _setup(tmp_path)
    packets.fail = error

    outcome = refresher.refresh([(_NODE, "PL"), (_OTHER, "PL")])

    assert outcome.failures == (
        RefreshFailure(_NODE, error.message, error.hint),  # type: ignore[attr-defined]
        RefreshFailure(_OTHER, error.message, error.hint),  # type: ignore[attr-defined]
    )
    assert outcome.refreshed == ()
    assert [call[0] for call in packets.calls] == ["reports", "reports"]
    assert store.load(_NODE) == NodeHistory(node=_NODE)
    packets.calls.clear()
    now[0] = _NOW + REFRESH_INTERVAL_SECONDS - 1
    refresher.refresh([(_NODE, "PL")])
    assert packets.calls == []


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

    def counting_update(node: NodeId, change: Any) -> NodeHistory:
        writes.append(node)
        return update(node, change)

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
    assert uplinked == [("uplinked", _NODE.hex, "PL", _NOW - GATEWAY_CHECK_WINDOW_SECONDS)]
    assert store.load(_NODE).gateway_checks == (
        GatewayCheck(_NOW, GATEWAY_CHECK_WINDOW_SECONDS, 6, 2),
    )
    now[0] = _NOW + GATEWAY_CHECK_INTERVAL_SECONDS
    refresher.refresh([(_NODE, "PL")], gateway_check=True)
    assert len([call for call in packets.calls if call[0] == "uplinked"]) == 2


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
