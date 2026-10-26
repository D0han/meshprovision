"""The health history model: hourly buckets, series, idempotent merging, pruning (pure)."""

from __future__ import annotations

import dataclasses
from datetime import timedelta

import pytest

from meshprovision.health.history import (
    ASSUMED_LORASTATS_RETENTION_SECONDS,
    HISTORY_RETENTION_SECONDS,
    HOUR_SECONDS,
    MAX_BOOTS,
    MAX_GATEWAY_CHECKS,
    MAX_GATEWAYS_PER_HOUR,
    MAX_NEIGHBORS,
    MAX_POSITIONS,
    MAX_RELAYS_PER_HOUR,
    MAX_SERIES_POINTS,
    SNR_BIN_MAX,
    SNR_BIN_MIN,
    GatewayCheck,
    HourBucket,
    LocalStatsPoint,
    NodeHistory,
    NodeInfoSeen,
    PositionPoint,
    TelemetryPoint,
    floor_hour,
    merge,
    prune,
    replace_from,
    summarize,
    with_boot,
    with_gateway_check,
)
from meshprovision.health.packets import DecodedPacket, Reception
from meshprovision.nodeid import NodeId
from meshprovision.status.cadence import learned_interval

pytestmark = pytest.mark.unit

_NODE = NodeId.from_hex("ab446357")
_OWN_BYTE = 0x57
_H = 1_760_994_000
"""An hour start (2026-10-20 21:00 UTC)."""
_NOW = _H + 2 * HOUR_SECONDS + 600


def _rx(
    time: float,
    *,
    gateway: str = "bbad0594",
    packet: str = "1",
    snr: float | None = 5.0,
    rssi: int | None = 150,
    hop_limit: int | None = 5,
    relay: int | None = 97,
) -> Reception:
    return Reception(time, gateway, packet, snr, rssi, hop_limit, relay)


def _pkt(
    time: float,
    *,
    packet: str = "1",
    hop_start: int | None = 7,
    port: int | None = 1,
    payload: str = "",
) -> DecodedPacket:
    return DecodedPacket(time, packet, hop_start, port, payload)


def _summary(
    receptions=(), decoded=(), *, since: int | None = _H, fetched_at: float = _NOW
) -> NodeHistory:
    return summarize(_NODE, receptions, decoded, since=since, fetched_at=fetched_at)


def _hours(history: NodeHistory) -> dict[int, HourBucket]:
    return {bucket.hour: bucket for bucket in history.hours}


def test_floor_hour_is_the_start_of_the_utc_hour() -> None:
    assert floor_hour(_H) == _H
    assert floor_hour(_H + 3599.9) == _H
    assert floor_hour(_H - 0.1) == _H - HOUR_SECONDS


def test_a_bucket_counts_receptions_packets_gateways_and_direct_ones() -> None:
    receptions = [
        _rx(_H + 10, gateway="0000000a", packet="1"),
        _rx(_H + 11, gateway="0000000b", packet="1", relay=_OWN_BYTE),
        _rx(_H + 12, gateway="0000000a", packet="2", relay=25),
        _rx(_H + 13, gateway="0000000c", packet="2", relay=None),
    ]

    bucket = _hours(_summary(receptions))[_H]

    assert (bucket.receptions, bucket.packets, bucket.direct) == (4, 2, 1)
    assert dict(bucket.gateways) == {"0000000a": 2, "0000000b": 1, "0000000c": 1}
    assert dict(bucket.relays) == {97: 1, 25: 1}


def test_a_packet_counts_in_the_hour_it_was_first_heard() -> None:
    receptions = [_rx(_H + HOUR_SECONDS + 1, packet="1"), _rx(_H + 3599, packet="1")]

    hours = _hours(_summary(receptions))

    assert (hours[_H].packets, hours[_H].receptions) == (1, 1)
    assert (hours[_H + HOUR_SECONDS].packets, hours[_H + HOUR_SECONDS].receptions) == (0, 1)


def test_hops_are_counted_only_for_decoded_packets_with_both_hop_values() -> None:
    receptions = [
        _rx(_H + 1, packet="1", hop_limit=7),
        _rx(_H + 2, packet="1", hop_limit=5, gateway="0000000b"),
        _rx(_H + 3, packet="2", hop_limit=5),
        _rx(_H + 4, packet="3", hop_limit=None),
        _rx(_H + 5, packet="4", hop_limit=6),
        _rx(_H + 6, packet="5", hop_limit=2),
    ]
    decoded = [
        _pkt(_H + 1, packet="1", hop_start=7),
        _pkt(_H + 4, packet="3", hop_start=7),
        _pkt(_H + 5, packet="4", hop_start=None),
        _pkt(_H + 6, packet="5", hop_start=1),
    ]

    bucket = _hours(_summary(receptions, decoded))[_H]

    assert dict(bucket.hops) == {0: 1, 2: 1}


def test_snr_steps_are_floored_and_clamped_and_rssi_summed() -> None:
    receptions = [
        _rx(_H + 1, packet="1", snr=-3.25, rssi=120),
        _rx(_H + 2, packet="2", snr=-3.0, rssi=None),
        _rx(_H + 3, packet="3", snr=12.75, rssi=200),
        _rx(_H + 4, packet="4", snr=-45.0, rssi=130),
        _rx(_H + 5, packet="5", snr=48.0),
        _rx(_H + 6, packet="6", snr=None),
    ]

    bucket = _hours(_summary(receptions))[_H]

    assert dict(bucket.snr) == {SNR_BIN_MIN: 1, -4: 1, -3: 1, 12: 1, SNR_BIN_MAX: 1}
    assert bucket.rssi == (120 + 200 + 130 + 150 + 150, 5, 120, 200)


def test_an_hour_without_rssi_has_none() -> None:
    bucket = _hours(_summary([_rx(_H + 1, rssi=None)]))[_H]

    assert bucket.rssi is None


def test_ports_and_hop_starts_count_decoded_packets_by_their_own_hour() -> None:
    decoded = [
        _pkt(_H + 1, packet="1", port=67, hop_start=7),
        _pkt(_H + 2, packet="2", port=67, hop_start=3),
        _pkt(_H + 3, packet="3", port=None, hop_start=None),
        _pkt(_H + HOUR_SECONDS, packet="4", port=3, hop_start=7),
    ]

    hours = _hours(_summary((), decoded))

    assert dict(hours[_H].ports) == {67: 2}
    assert dict(hours[_H].hop_starts) == {3: 1, 7: 1}
    assert dict(hours[_H + HOUR_SECONDS].ports) == {3: 1}


def test_the_busiest_gateways_and_relays_are_kept_per_hour() -> None:
    receptions = [
        _rx(_H + 1, gateway=f"{index:08x}", packet=f"{index:x}", relay=index % 256)
        for index in range(MAX_GATEWAYS_PER_HOUR + 6)
    ]
    receptions.append(_rx(_H + 2, gateway=f"{69:08x}", packet="ffff", relay=69))

    bucket = _hours(_summary(receptions))[_H]

    assert len(bucket.gateways) == MAX_GATEWAYS_PER_HOUR
    assert bucket.gateways[f"{69:08x}"] == 2
    assert f"{68:08x}" not in bucket.gateways
    assert f"{0:08x}" in bucket.gateways
    assert len(bucket.relays) == MAX_RELAYS_PER_HOUR
    assert bucket.relays[69] == 2
    assert 68 not in bucket.relays


def test_rows_before_since_are_left_out_and_every_hour_since_gets_a_bucket() -> None:
    receptions = [
        _rx(_H - 1, packet="old"),
        _rx(_H, packet="edge"),
        _rx(_H + HOUR_SECONDS + 5, packet="new"),
    ]
    decoded = [_pkt(_H - 1, packet="old", port=67, payload="50% Bat")]

    history = _summary(receptions, decoded, since=_H, fetched_at=_NOW)

    assert [bucket.hour for bucket in history.hours] == [
        _H,
        _H + HOUR_SECONDS,
        _H + 2 * HOUR_SECONDS,
    ]
    assert [bucket.receptions for bucket in history.hours] == [1, 1, 0]
    assert history.telemetry == ()
    assert history.last_heard == _H + HOUR_SECONDS + 5
    assert history.fetched_at == _NOW


def test_with_since_silent_hours_start_at_since_even_before_the_first_row() -> None:
    history = _summary([_rx(_H + HOUR_SECONDS + 5)], since=_H, fetched_at=_NOW)

    assert [(b.hour, b.receptions) for b in history.hours] == [
        (_H, 0),
        (_H + HOUR_SECONDS, 1),
        (_H + 2 * HOUR_SECONDS, 0),
    ]


def test_without_since_silent_hours_start_at_the_oldest_reception_even_days_back() -> None:
    """A row this old proves every later hour: lorastats deletes its oldest reports first."""
    fetched_at = _NOW
    assumed = floor_hour(fetched_at - ASSUMED_LORASTATS_RETENTION_SECONDS) + HOUR_SECONDS
    old_row = _rx(assumed - 5 * HOUR_SECONDS, packet="old")

    history = _summary([old_row], since=None, fetched_at=fetched_at)

    hours = [bucket.hour for bucket in history.hours]
    assert hours == list(range(floor_hour(old_row.time), floor_hour(fetched_at) + 1, HOUR_SECONDS))
    assert [bucket.receptions for bucket in history.hours][:2] == [1, 0]


def test_a_node_heard_every_6_hours_with_48_hours_held_learns_6_hours() -> None:
    """Silent hours only inside the last day made a 6 h node learn 3h51 on its first refresh."""
    now = _NOW
    receptions = [_rx(now - age * HOUR_SECONDS - 600, packet=f"{age:x}") for age in range(0, 48, 6)]

    history = merge(NodeHistory(node=_NODE), _summary(receptions, since=None, fetched_at=now))

    hours = [(bucket.hour, bucket.receptions) for bucket in history.hours]
    assert sum(1 for _, received in hours if received) == 8
    assert learned_interval(hours, now=now) == timedelta(hours=6)


def test_with_an_old_since_silent_hours_start_at_the_oldest_reception_returned() -> None:
    """A refresh more than a day after the previous one: rows back to since prove those hours."""
    since = floor_hour(_NOW - 2 * ASSUMED_LORASTATS_RETENTION_SECONDS)
    oldest = since + 3 * HOUR_SECONDS

    history = _summary([_rx(oldest + 5, packet="old")], since=since, fetched_at=_NOW)

    assert history.hours[0].hour == oldest
    assert len(history.hours) == (floor_hour(_NOW) - oldest) // HOUR_SECONDS + 1


def test_silent_hours_never_start_before_since_whatever_lorastats_returned() -> None:
    since = floor_hour(_NOW - 2 * ASSUMED_LORASTATS_RETENTION_SECONDS)

    history = _summary(
        [_rx(since - 3 * HOUR_SECONDS, packet="older")], since=since, fetched_at=_NOW
    )

    assert history.hours[0].hour == since
    assert history.hours[0].receptions == 0


def test_a_reception_inside_the_assumed_retention_does_not_shorten_it() -> None:
    since = floor_hour(_NOW - 2 * ASSUMED_LORASTATS_RETENTION_SECONDS)
    assumed = floor_hour(_NOW - ASSUMED_LORASTATS_RETENTION_SECONDS) + HOUR_SECONDS

    history = _summary([_rx(_NOW - 60, packet="recent")], since=since, fetched_at=_NOW)

    assert history.hours[0].hour == assumed


def test_a_first_refresh_has_silent_hours_only_from_its_oldest_reception() -> None:
    recent = _rx(_NOW - 3 * HOUR_SECONDS, packet="recent")

    history = _summary([recent], since=None, fetched_at=_NOW)
    empty = _summary([], [_pkt(_NOW - 60, packet="d")], since=None, fetched_at=_NOW)

    assert history.hours[0].hour == floor_hour(recent.time)
    assert history.hours[-1].hour == floor_hour(_NOW)
    assert [bucket.hour for bucket in empty.hours] == [floor_hour(_NOW - 60)]


def test_a_since_older_than_the_assumed_retention_does_not_invent_silent_hours() -> None:
    since = floor_hour(_NOW - 3 * ASSUMED_LORASTATS_RETENTION_SECONDS)

    history = _summary([], since=since, fetched_at=_NOW)

    oldest_silent = floor_hour(_NOW - ASSUMED_LORASTATS_RETENTION_SECONDS) + HOUR_SECONDS
    assert history.hours[0].hour == oldest_silent


def test_series_come_from_decoded_payloads() -> None:
    decoded = [
        _pkt(_H + 1, packet="1", port=67, payload="5.93% ChUtil, 0.03% AirUtilTx, 90% Bat"),
        _pkt(_H + 2, packet="2", port=67, payload="167305 rx, 1129 tx, 252 relay, 84 kB"),
        _pkt(_H + 3, packet="3", port=67, payload=""),
        _pkt(_H + 4, packet="4", port=3, payload="52.379648° N, 16.950886° E"),
        _pkt(_H + 5, packet="5", port=3, payload="nowhere"),
        _pkt(_H + 6, packet="6", port=4, payload="Old, Old name, Client"),
        _pkt(_H + 7, packet="7", port=4, payload="D0h5, D0h5 long, ClientMute"),
        _pkt(_H + 8, packet="8", port=4, payload="broken"),
        _pkt(_H + 9, packet="9", port=71, payload="979ed146"),
        _pkt(_H + 10, packet="a", port=71, payload="979ed146"),
        _pkt(_H + 11, packet="b", port=71, payload="zz"),
        _pkt(_H + 12, packet="c", port=1, payload="90% Bat"),
    ]

    history = _summary((), decoded)

    assert history.telemetry == (TelemetryPoint(_H + 1, 90, None, 5.93, 0.03),)
    assert history.local_stats == (LocalStatsPoint(_H + 2, 167305, 1129, 252),)
    assert history.positions == (PositionPoint(_H + 4, 52.379648, 16.950886),)
    assert history.nodeinfo == NodeInfoSeen(_H + 7, "D0h5", "D0h5 long", "CLIENT_MUTE")
    assert dict(history.neighbors) == {"979ed146": _H + 10}


def test_replace_from_is_the_hour_of_the_previous_refresh() -> None:
    assert replace_from(NodeHistory(node=_NODE), now=_NOW) is None
    assert replace_from(NodeHistory(node=_NODE, fetched_at=_H + 1800), now=_NOW) == _H
    assert replace_from(NodeHistory(node=_NODE, fetched_at=_NOW + 86400), now=_NOW) == floor_hour(
        _NOW
    )


def _stored() -> NodeHistory:
    return NodeHistory(
        node=_NODE,
        fetched_at=_H + 600,
        last_heard=_H + 500,
        hours=(
            HourBucket(_H - HOUR_SECONDS, receptions=3, packets=1),
            HourBucket(_H, receptions=2, packets=1),
        ),
        telemetry=(TelemetryPoint(_H - 100, battery=80), TelemetryPoint(_H + 100, battery=79)),
        local_stats=(LocalStatsPoint(_H + 100, rx=1),),
        positions=(PositionPoint(_H + 100, 1.0, 2.0),),
        nodeinfo=NodeInfoSeen(_H + 100, "A", "Old", None),
        neighbors={"0000000a": _H + 100, "0000000b": _H + 9000},
        boots=(_H - 5000.0,),
        gateway_checks=(GatewayCheck(_H + 100, 3600, 5, 2),),
    )


def _refresh() -> NodeHistory:
    receptions = [_rx(_H + 1000, packet="2"), _rx(_H + 1001, packet="2", gateway="0000000b")]
    decoded = [
        _pkt(_H + 1000, packet="2", port=67, payload="78% Bat"),
        _pkt(_H + 1100, packet="3", port=71, payload="0000000a"),
    ]
    return _summary(receptions, decoded, since=_H, fetched_at=_H + 1200)


def test_a_refresh_replaces_the_hours_it_speaks_for_and_keeps_the_others() -> None:
    merged = merge(_stored(), _refresh())

    hours = _hours(merged)
    assert hours[_H - HOUR_SECONDS].receptions == 3
    assert (hours[_H].receptions, hours[_H].packets) == (2, 1)
    assert dict(hours[_H].gateways) == {"bbad0594": 1, "0000000b": 1}
    assert merged.telemetry == (
        TelemetryPoint(_H - 100, battery=80),
        TelemetryPoint(_H + 1000, battery=78),
    )
    assert merged.local_stats == ()
    assert merged.positions == ()
    assert (merged.fetched_at, merged.last_heard) == (_H + 1200, _H + 1001)


def test_merging_the_same_refresh_twice_counts_nothing_twice() -> None:
    once = merge(_stored(), _refresh())

    assert merge(once, _refresh()) == once


def test_merge_keeps_the_newest_nodeinfo_and_neighbour_times_and_every_boot() -> None:
    newer_info = dataclasses.replace(_stored(), nodeinfo=NodeInfoSeen(_H + 9999, "N", "New", None))
    new = dataclasses.replace(
        _refresh(),
        nodeinfo=NodeInfoSeen(_H + 1000, "M", "Mid", "CLIENT"),
        neighbors={"0000000a": _H + 1100, "0000000b": _H + 1100},
        boots=(_H + 50.0,),
        gateway_checks=(GatewayCheck(_H + 100, 3600, 9, 3), GatewayCheck(_H + 200, 3600, 1, 1)),
    )

    merged = merge(newer_info, new)

    assert merged.nodeinfo == NodeInfoSeen(_H + 9999, "N", "New", None)
    assert merge(_stored(), new).nodeinfo == NodeInfoSeen(_H + 1000, "M", "Mid", "CLIENT")
    assert dict(merged.neighbors) == {"0000000a": _H + 1100, "0000000b": _H + 9000}
    assert merged.boots == (_H - 5000.0, _H + 50.0)
    assert merged.gateway_checks == (
        GatewayCheck(_H + 100, 3600, 9, 3),
        GatewayCheck(_H + 200, 3600, 1, 1),
    )


def test_merge_into_an_empty_history_takes_the_refresh() -> None:
    refresh = _refresh()

    assert merge(NodeHistory(node=_NODE), refresh) == dataclasses.replace(
        refresh, neighbors=dict(refresh.neighbors)
    )


def test_a_known_boot_and_a_repeated_gateway_check_are_recorded_once() -> None:
    history = with_boot(with_boot(NodeHistory(node=_NODE), 5.0), 5.0)
    history = with_boot(history, 1.0)
    history = with_gateway_check(history, GatewayCheck(10.0, 600, 1, 1))
    history = with_gateway_check(history, GatewayCheck(10.0, 600, 4, 2))

    assert history.boots == (1.0, 5.0)
    assert history.gateway_checks == (GatewayCheck(10.0, 600, 4, 2),)


def test_prune_keeps_exactly_the_retention_window() -> None:
    oldest = _NOW - HISTORY_RETENTION_SECONDS
    newest = _NOW + 300
    history = NodeHistory(
        node=_NODE,
        hours=(
            HourBucket(floor_hour(oldest) - HOUR_SECONDS),
            HourBucket(floor_hour(oldest)),
            HourBucket(floor_hour(newest)),
            HourBucket(floor_hour(newest) + HOUR_SECONDS),
        ),
        telemetry=(
            TelemetryPoint(oldest - 1),
            TelemetryPoint(oldest),
            TelemetryPoint(newest),
            TelemetryPoint(newest + 1),
        ),
        local_stats=(LocalStatsPoint(oldest - 1), LocalStatsPoint(oldest)),
        positions=(PositionPoint(oldest - 1, 1, 1), PositionPoint(newest + 1, 2, 2)),
        nodeinfo=NodeInfoSeen(oldest - 1, "A", "B", None),
        neighbors={"0000000a": oldest - 1, "0000000b": newest},
        boots=(oldest - 1, oldest),
        gateway_checks=(GatewayCheck(newest + 1, 1, 1, 1), GatewayCheck(oldest, 1, 1, 1)),
    )

    pruned = prune(history, now=_NOW)

    assert [b.hour for b in pruned.hours] == [floor_hour(oldest), floor_hour(newest)]
    assert [p.time for p in pruned.telemetry] == [oldest, newest]
    assert [p.time for p in pruned.local_stats] == [oldest]
    assert pruned.positions == ()
    assert pruned.nodeinfo is None
    assert dict(pruned.neighbors) == {"0000000b": newest}
    assert pruned.boots == (oldest,)
    assert pruned.gateway_checks == (GatewayCheck(oldest, 1, 1, 1),)


def test_prune_keeps_a_current_nodeinfo() -> None:
    info = NodeInfoSeen(_NOW, "A", "B", None)

    assert prune(NodeHistory(node=_NODE, nodeinfo=info), now=_NOW).nodeinfo == info


def test_prune_applies_every_cap_keeping_the_newest() -> None:
    start = _NOW - 20 * 24 * 3600
    times = [start + index for index in range(MAX_SERIES_POINTS + 2)]
    history = NodeHistory(
        node=_NODE,
        telemetry=tuple(TelemetryPoint(t) for t in times),
        local_stats=tuple(LocalStatsPoint(t) for t in times),
        positions=tuple(PositionPoint(t, 0.0, float(i)) for i, t in enumerate(times)),
        neighbors={f"{i:08x}": start + i for i in range(MAX_NEIGHBORS + 2)},
        boots=tuple(float(t) for t in times[: MAX_BOOTS + 2]),
        gateway_checks=tuple(GatewayCheck(t, 1, 1, 1) for t in times[: MAX_GATEWAY_CHECKS + 2]),
    )

    pruned = prune(history, now=_NOW)

    assert [p.time for p in pruned.telemetry] == times[-MAX_SERIES_POINTS:]
    assert [p.time for p in pruned.local_stats] == times[-MAX_SERIES_POINTS:]
    assert [p.time for p in pruned.positions] == times[-MAX_POSITIONS:]
    assert sorted(pruned.neighbors) == [f"{i:08x}" for i in range(2, MAX_NEIGHBORS + 2)]
    assert pruned.boots == tuple(float(t) for t in times[2 : MAX_BOOTS + 2])
    assert [c.time for c in pruned.gateway_checks] == times[2 : MAX_GATEWAY_CHECKS + 2]


def test_prune_drops_a_position_equal_to_the_one_before() -> None:
    positions = (
        PositionPoint(_NOW - 3, 1.0, 2.0),
        PositionPoint(_NOW - 2, 1.0, 2.0),
        PositionPoint(_NOW - 1, 1.0, 3.0),
        PositionPoint(_NOW, 1.0, 2.0),
    )

    pruned = prune(NodeHistory(node=_NODE, positions=positions), now=_NOW)

    assert [p.time for p in pruned.positions] == [_NOW - 3, _NOW - 1, _NOW]


def test_merging_an_older_refresh_keeps_the_newer_fetch_and_reception_times() -> None:
    newer = dataclasses.replace(_stored(), fetched_at=_H + 9000, last_heard=_H + 8000)

    merged = merge(newer, _refresh())

    assert (merged.fetched_at, merged.last_heard) == (_H + 9000, _H + 8000)
