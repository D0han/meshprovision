"""Hourly region buckets: what one refresh contributes, merging, pruning and adding up."""

from __future__ import annotations

from types import MappingProxyType

import pytest

from meshprovision.health.history import HOUR_SECONDS, floor_hour
from meshprovision.network.buckets import (
    NETWORK_RETENTION_SECONDS,
    LastHop,
    Radio,
    RegionHour,
    Traffic,
    combine,
    merge,
    prune,
    summarize,
)
from meshprovision.network.rawpackets import parse_raw
from tests.unit.network_fixtures import NOW, T0, neighbor_info, packet, row, traceroute

pytestmark = pytest.mark.unit

_ORIGIN = 0xAB446357
_O = "ab446357"
_GW_A, _GW_B = "bbad0594", "0192b5f8"
_HOUR = floor_hour(T0)
_SINCE = floor_hour(NOW) - 3 * HOUR_SECONDS


def _hours(rows: list[dict[str, object]], *, since: int | None = _SINCE) -> tuple[RegionHour, ...]:
    return summarize(parse_raw(rows, now=NOW), since=since, fetched_at=NOW)


def _traffic(rows: list[dict[str, object]]) -> Traffic:
    return {bucket.hour: bucket.traffic for bucket in _hours(rows)}[_HOUR]


def test_a_packet_heard_relayed_and_direct_is_counted_in_its_hour() -> None:
    relayed = packet(_ORIGIN, 1, relay=0x61, hop_start=3, hop_limit=2, snr=-7.25, rssi=-118)
    direct = packet(_ORIGIN, 1, snr=6.5, rssi=-90)

    traffic = _traffic([row(relayed, gateway=_GW_A), row(direct, gateway=_GW_B)])

    assert traffic == Traffic(
        packets={_O: 1},
        relayed={0x61: {_GW_A: Radio(1, 1, -7.25, -118)}},
        direct={_O: {_GW_B: Radio(1, 1, 6.5, -90)}},
        last_hops={_O: {0x61: LastHop(1, 1)}},
    )
    assert isinstance(traffic.relayed, MappingProxyType)
    assert isinstance(traffic.relayed[0x61], MappingProxyType)


def test_a_packet_relayed_by_one_byte_only_and_one_gateway_only() -> None:
    relayed = packet(_ORIGIN, 1, relay=0x61, hop_start=4, hop_limit=1)
    again = packet(_ORIGIN, 2, relay=0x61, hop_start=4, hop_limit=1)

    traffic = _traffic([row(relayed), row(again), row(again, gateway=_GW_B)])

    assert traffic.sole_relay == {_O: {0x61: 2}}
    assert traffic.only_gateway == {_O: {_GW_A: 1}}
    assert traffic.last_hops == {_O: {0x61: LastHop(3, 0)}}


def test_two_relays_or_a_direct_reception_is_no_sole_relay() -> None:
    one = packet(_ORIGIN, 1, relay=0x61, hop_limit=2)
    other = packet(_ORIGIN, 1, relay=0x62, hop_limit=2)
    direct = packet(_ORIGIN, 2)
    direct_relayed = packet(_ORIGIN, 2, relay=0x61, hop_limit=2)

    traffic = _traffic(
        [row(one), row(other, gateway=_GW_B), row(direct), row(direct_relayed, gateway=_GW_B)]
    )

    assert traffic.sole_relay == {}


def test_a_collision_and_a_reception_without_relay_byte_are_neither_relayed_nor_direct() -> None:
    collision = packet(_ORIGIN, 1, hop_start=3, hop_limit=2)
    no_relay = packet(_ORIGIN, 2, relay=0)

    traffic = _traffic([row(collision), row(no_relay)])

    assert (traffic.relayed, traffic.direct, traffic.last_hops) == ({}, {}, {})
    assert (traffic.packets, traffic.unrelayed) == ({_O: 2}, 1)
    assert traffic.sole_relay == {}


@pytest.mark.parametrize(("snr", "rssi"), [(0.0, 0), (60.0, -90)])
def test_a_reception_without_snr_or_rssi_is_counted_but_not_measured(snr: float, rssi: int) -> None:
    traffic = _traffic([row(packet(_ORIGIN, 1, rssi=rssi, snr=snr))])

    assert traffic.direct == {_O: {_GW_A: Radio(1)}}
    assert traffic.direct[_O][_GW_A].mean_snr is None
    assert traffic.direct[_O][_GW_A].mean_rssi is None


def test_a_packet_belongs_to_the_hour_of_its_first_reception() -> None:
    late = row(packet(_ORIGIN, 1), gateway=_GW_B, time=_HOUR + HOUR_SECONDS + 10)
    early = row(packet(_ORIGIN, 1), time=_HOUR + HOUR_SECONDS - 10)

    hours = {bucket.hour: bucket.traffic for bucket in _hours([late, early])}

    assert hours[_HOUR].direct == {_O: {_GW_A: Radio(1, 1, 6.5, -90), _GW_B: Radio(1, 1, 6.5, -90)}}
    assert hours[_HOUR + HOUR_SECONDS] == Traffic()


def test_rows_before_since_are_left_out_with_all_receptions_of_their_packet() -> None:
    since = _HOUR
    before = row(packet(_ORIGIN, 1), time=since - 5)
    after_same_packet = row(packet(_ORIGIN, 1), gateway=_GW_B, time=since + 5)
    port, payload = traceroute([0x22222222])
    route = row(packet(_ORIGIN, 2, port=port, payload=payload), time=since - 5)
    n_port, n_payload = neighbor_info(_ORIGIN, [0x22222222])
    report = row(packet(_ORIGIN, 3, port=n_port, payload=n_payload), time=since - 5)

    hours = _hours([before, after_same_packet, route, report], since=since)

    assert [bucket.hour for bucket in hours] == [_HOUR, _HOUR + HOUR_SECONDS]
    assert all(bucket.traffic == Traffic() for bucket in hours)


def test_every_answered_hour_gets_a_bucket_silent_ones_empty() -> None:
    hours = _hours([row(packet(_ORIGIN, 1))])

    assert [bucket.hour for bucket in hours] == [_SINCE + i * HOUR_SECONDS for i in range(4)]
    assert [bucket.traffic == Traffic() for bucket in hours] == [True, True, False, True]


@pytest.mark.parametrize(("rows", "count"), [(False, 0), (True, 2)])
def test_a_first_refresh_starts_at_the_oldest_row(rows: bool, count: int) -> None:
    hours = _hours([row(packet(_ORIGIN, 1))] if rows else [], since=None)

    assert len(hours) == count


def test_a_relayed_reception_that_took_no_hop_is_no_first_hop() -> None:
    traffic = _traffic([row(packet(_ORIGIN, 1, relay=0x61, hop_start=3, hop_limit=3))])

    assert traffic.last_hops == {_O: {0x61: LastHop(1, 0)}}


def test_a_route_that_repeats_a_node_gives_no_edge_to_itself() -> None:
    port, payload = traceroute([_ORIGIN])

    assert _traffic([row(packet(_ORIGIN, 1, port=port, payload=payload))]).edges == {}


def test_routes_and_neighbor_reports_are_counted_as_edges() -> None:
    port, payload = traceroute([0x22222222, 0x11111111])
    route = row(packet(_ORIGIN, 1, port=port, payload=payload))
    n_port, n_payload = neighbor_info(_ORIGIN, [0x22222222])
    report = packet(_ORIGIN, 2, port=n_port, payload=n_payload)

    traffic = _traffic(
        [route, row(report), row(packet(_ORIGIN, 3, port=n_port, payload=n_payload))]
    )

    assert traffic.edges == {
        ("11111111", "22222222", "t"): 1,
        ("22222222", _O, "t"): 1,
        ("22222222", _O, "n"): 2,
    }


def _bucket(hour: int, packets: int) -> RegionHour:
    return RegionHour(hour, Traffic(packets={_O: packets}))


def test_merge_replaces_the_refreshed_hours_and_keeps_the_others() -> None:
    old = (_bucket(_HOUR - HOUR_SECONDS, 1), _bucket(_HOUR, 2))
    new = (_bucket(_HOUR, 5), _bucket(_HOUR + HOUR_SECONDS, 7))

    merged = merge(old, new)

    assert merged == (_bucket(_HOUR - HOUR_SECONDS, 1), _bucket(_HOUR, 5), new[1])
    assert merge(merged, new) == merged


def test_prune_keeps_the_retention_and_drops_the_future() -> None:
    oldest = floor_hour(NOW - NETWORK_RETENTION_SECONDS)
    newest = floor_hour(NOW + 300)
    hours = [_bucket(h, 1) for h in (oldest - HOUR_SECONDS, oldest, newest, newest + HOUR_SECONDS)]

    assert [bucket.hour for bucket in prune(hours, now=NOW)] == [oldest, newest]


def test_combine_adds_up_hours_and_gives_means() -> None:
    first = Traffic(
        packets={_O: 1},
        relayed={0x61: {_GW_A: Radio(2, 2, -10.0, -200)}},
        last_hops={_O: {0x61: LastHop(2, 1)}},
        edges={("11111111", "22222222", "t"): 1},
        unrelayed=1,
    )
    second = Traffic(
        packets={_O: 2, "11111111": 1},
        relayed={0x61: {_GW_A: Radio(1, 1, -2.0, -10), _GW_B: Radio(1, 1, 3.0, -50)}},
        sole_relay={_O: {0x61: 1}},
        only_gateway={_O: {_GW_A: 1}},
        direct={_O: {_GW_A: Radio(1, 1, 1.0, -40)}},
        last_hops={_O: {0x61: LastHop(1, 1), 0x62: LastHop(1, 1)}},
        edges={("11111111", "22222222", "t"): 2},
        unrelayed=2,
    )

    total = combine([RegionHour(_HOUR, first), RegionHour(_HOUR + HOUR_SECONDS, second)])

    assert total == Traffic(
        packets={"11111111": 1, _O: 3},
        relayed={0x61: {_GW_B: Radio(1, 1, 3.0, -50), _GW_A: Radio(3, 3, -12.0, -210)}},
        direct={_O: {_GW_A: Radio(1, 1, 1.0, -40)}},
        last_hops={_O: {0x61: LastHop(3, 2), 0x62: LastHop(1, 1)}},
        sole_relay={_O: {0x61: 1}},
        only_gateway={_O: {_GW_A: 1}},
        edges={("11111111", "22222222", "t"): 3},
        unrelayed=3,
    )
    cell = total.relayed[0x61][_GW_A]
    assert (cell.mean_snr, cell.mean_rssi) == (-4.0, -70.0)


def test_combine_of_nothing_is_empty() -> None:
    assert combine([]) == Traffic()
