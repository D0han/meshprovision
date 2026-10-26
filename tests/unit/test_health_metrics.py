"""Health metrics of a node over a window of its history (pure)."""

from __future__ import annotations

from types import MappingProxyType

import pytest

from meshprovision.health.history import (
    HOUR_SECONDS,
    GatewayCheck,
    HourBucket,
    LocalStatsPoint,
    NodeHistory,
    NodeInfoSeen,
    PositionPoint,
    TelemetryPoint,
)
from meshprovision.health.metrics import (
    BATTERY_TREND_MIN_POINTS,
    BATTERY_TREND_MIN_SPAN_HOURS,
    MAX_RELAYS_LISTED,
    NodeMetrics,
    RelayShare,
    compute_metrics,
    quantile,
)
from meshprovision.nodeid import NodeId

pytestmark = pytest.mark.unit

_NODE = NodeId.from_hex("ab446357")
_RELAY = NodeId.from_hex("12345661")
_H = 1_760_994_000
_NOW = float(_H + 1800)
_DAY = 86400


def _metrics(history: NodeHistory, *, days: int = 1, fleet=(), now: float = _NOW) -> NodeMetrics:
    return compute_metrics(history, now=now, days=days, fleet=fleet)


def _history(*hours: HourBucket, **fields: object) -> NodeHistory:
    return NodeHistory(node=_NODE, hours=hours, **fields)  # type: ignore[arg-type]


def test_quantile_reads_a_histogram() -> None:
    counts = {1: 2, 2: 1, 5: 1}

    assert quantile(counts, 0.5) == 1
    assert quantile(counts, 0.51) == 2
    assert quantile(counts, 0.75) == 2
    assert quantile(counts, 0.76) == 5
    assert quantile(counts, 1.0) == 5
    assert quantile(counts, 0.0) == 1
    assert quantile({}, 0.5) is None


def test_an_empty_history_has_no_metrics() -> None:
    metrics = _metrics(NodeHistory(node=_NODE))

    assert (metrics.covered_hours, metrics.receptions, metrics.packets) == (0, 0, 0)
    assert metrics.packets_per_hour is None
    assert metrics.direct_share is None
    assert metrics.decoded_share is None
    assert metrics.hops_max is None
    assert metrics.hops_median is None
    assert metrics.top_relay is None
    assert metrics.battery is None
    assert metrics.snr_median is None
    assert metrics.rssi_mean is None
    assert metrics.telemetry_per_hour is None


def test_counts_add_up_over_the_hours_of_the_window_only() -> None:
    history = _history(
        HourBucket(_H - _DAY - HOUR_SECONDS, receptions=100, packets=50),
        HourBucket(_H - _DAY, receptions=3, packets=1, direct=1),
        HourBucket(_H, receptions=7, packets=2, direct=2),
        HourBucket(_H + HOUR_SECONDS, receptions=1000),
    )

    metrics = _metrics(history)

    assert metrics.covered_hours == 2
    assert (metrics.receptions, metrics.packets, metrics.direct) == (10, 3, 3)
    assert metrics.packets_per_hour == 1.5
    assert metrics.direct_share == 0.3
    assert metrics.window_start == _NOW - _DAY


def test_silent_hours_and_the_longest_silence_need_consecutive_covered_hours() -> None:
    history = _history(
        HourBucket(_H - 6 * HOUR_SECONDS),
        HourBucket(_H - 5 * HOUR_SECONDS),
        HourBucket(_H - 4 * HOUR_SECONDS, receptions=1),
        HourBucket(_H - 3 * HOUR_SECONDS),
        HourBucket(_H - 1 * HOUR_SECONDS),
        HourBucket(_H),
    )

    metrics = _metrics(history)

    assert metrics.silent_hours == 5
    assert metrics.longest_silence_hours == 2


def test_gateways_are_ranked_and_counted_and_a_self_uplink_noticed() -> None:
    history = _history(
        HourBucket(_H - HOUR_SECONDS, gateways=MappingProxyType({"0000000b": 2, _NODE.hex: 1})),
        HourBucket(_H, gateways=MappingProxyType({"0000000a": 2, "0000000b": 1})),
    )

    metrics = _metrics(history)

    assert metrics.gateways == (("0000000b", 3), ("0000000a", 2), (_NODE.hex, 1))
    assert metrics.gateway_count == 3
    assert metrics.uplinks_itself is True
    others = _history(HourBucket(_H, gateways=MappingProxyType({"0000000a": 2})))
    assert _metrics(others).uplinks_itself is False


def test_hops_and_hop_start_come_from_the_decoded_sample() -> None:
    history = _history(
        HourBucket(
            _H,
            receptions=10,
            hops=MappingProxyType({1: 3, 3: 1}),
            hop_starts=MappingProxyType({7: 2, 3: 3}),
        ),
        HourBucket(_H - HOUR_SECONDS, hops=MappingProxyType({0: 1}), hop_starts={5: 1}),
    )

    metrics = _metrics(history)

    assert dict(metrics.hops) == {0: 1, 1: 3, 3: 1}
    assert (metrics.hop_samples, metrics.hops_max, metrics.hops_median) == (5, 3, 1)
    assert metrics.decoded_share == 0.5
    assert (metrics.hop_start, metrics.hop_start_samples) == (3, 6)
    tie = _history(HourBucket(_H, hop_starts=MappingProxyType({3: 2, 7: 2})))
    assert _metrics(tie).hop_start == 7


def test_snr_and_rssi_statistics() -> None:
    history = _history(
        HourBucket(_H, snr=MappingProxyType({-10: 1, 2: 4, 9: 5}), rssi=(300, 2, 140, 160)),
        HourBucket(_H - HOUR_SECONDS, rssi=(0, 0, 0, 0)),
        HourBucket(_H - 2 * HOUR_SECONDS, rssi=(100, 1, 100, 100)),
    )

    metrics = _metrics(history)

    assert (metrics.snr_median, metrics.snr_low, metrics.snr_samples) == (2, -10, 10)
    assert metrics.rssi_mean == pytest.approx(400 / 3)
    assert _metrics(_history(HourBucket(_H, rssi=(0, 0, 0, 0)))).rssi_mean is None


def test_relays_are_ranked_with_shares_and_fleet_candidates() -> None:
    relays = {0x61: 6, 0x19: 2, **dict.fromkeys(range(1, MAX_RELAYS_LISTED + 2), 1)}
    history = _history(HourBucket(_H, relays=MappingProxyType(relays)))
    other_61 = NodeId.from_hex("aaaaaa61")
    fleet = (_NODE, _RELAY, other_61, NodeId.from_hex("00000019"))

    metrics = _metrics(history, fleet=fleet)

    total = sum(relays.values())
    assert metrics.relayed == total
    assert len(metrics.relays) == MAX_RELAYS_LISTED
    assert metrics.top_relay == RelayShare(0x61, 6, 6 / total, (_RELAY, other_61))
    assert metrics.relays[1] == RelayShare(0x19, 2, 2 / total, (NodeId.from_hex("00000019"),))
    assert [share.byte for share in metrics.relays[2:]] == [1, 2, 3]


def test_a_relay_byte_equal_to_the_nodes_own_is_not_its_own_candidate() -> None:
    history = _history(HourBucket(_H, relays=MappingProxyType({0x57: 1})))

    metrics = _metrics(history, fleet=(_NODE,))

    assert metrics.relays[0].candidates == ()


def test_ports_give_decoded_counts_and_per_hour_rates() -> None:
    history = _history(
        HourBucket(_H, ports=MappingProxyType({67: 3, 3: 1, 4: 1})),
        HourBucket(_H - HOUR_SECONDS, ports=MappingProxyType({67: 1, 3: 1})),
    )

    metrics = _metrics(history)

    assert metrics.decoded_packets == 7
    assert metrics.telemetry_per_hour == 2.0
    assert metrics.positions_per_hour == 1.0


def _battery_points(levels: list[int], *, step: float) -> tuple[TelemetryPoint, ...]:
    return tuple(
        TelemetryPoint(_NOW - (len(levels) - 1 - index) * step, battery=level)
        for index, level in enumerate(levels)
    )


def test_the_battery_trend_is_a_slope_per_day() -> None:
    step = BATTERY_TREND_MIN_SPAN_HOURS * HOUR_SECONDS / (BATTERY_TREND_MIN_POINTS - 1)
    levels = [90 - index for index in range(BATTERY_TREND_MIN_POINTS)]
    history = _history(telemetry=_battery_points(levels, step=step))

    trend = _metrics(history).battery

    assert trend is not None
    assert (trend.latest, trend.latest_time) == (levels[-1], _NOW)
    assert trend.points == BATTERY_TREND_MIN_POINTS
    assert trend.span_hours == pytest.approx(BATTERY_TREND_MIN_SPAN_HOURS)
    assert trend.slope_per_day == pytest.approx(-_DAY / step)


def test_too_few_or_too_close_battery_readings_have_no_slope() -> None:
    step = BATTERY_TREND_MIN_SPAN_HOURS * HOUR_SECONDS / (BATTERY_TREND_MIN_POINTS - 1)
    few = [90] * (BATTERY_TREND_MIN_POINTS - 1)
    close = [90] * BATTERY_TREND_MIN_POINTS

    few_trend = _metrics(_history(telemetry=_battery_points(few, step=step * 2))).battery
    close_trend = _metrics(_history(telemetry=_battery_points(close, step=step * 0.99))).battery

    assert few_trend is not None
    assert few_trend.slope_per_day is None
    assert close_trend is not None
    assert close_trend.slope_per_day is None


def test_external_power_and_empty_readings_are_not_battery_levels() -> None:
    telemetry = (
        TelemetryPoint(_NOW - 300, battery=101),
        TelemetryPoint(_NOW - 200, battery=0),
        TelemetryPoint(_NOW - 100, battery=100),
        TelemetryPoint(_NOW - 50, battery=None, channel_utilization=10.0),
    )

    trend = _metrics(_history(telemetry=telemetry)).battery

    assert trend is not None
    assert (trend.latest, trend.points) == (100, 1)
    assert _metrics(_history(telemetry=telemetry[:2])).battery is None


def test_utilization_means_and_latest_readings_cover_the_window_only() -> None:
    telemetry = (
        TelemetryPoint(_NOW - _DAY - 1, channel_utilization=90.0, air_util_tx=90.0),
        TelemetryPoint(_NOW - _DAY, channel_utilization=10.0, air_util_tx=1.0),
        TelemetryPoint(_NOW - 10, channel_utilization=20.0),
        TelemetryPoint(_NOW + 1, channel_utilization=99.0),
    )

    metrics = _metrics(_history(telemetry=telemetry))

    assert metrics.channel_utilization == 15.0
    assert metrics.air_util_tx == 1.0
    assert metrics.latest_telemetry == telemetry[2]


def test_series_and_lists_are_cut_to_the_window() -> None:
    history = _history(
        local_stats=(LocalStatsPoint(_NOW - _DAY - 1, rx=1), LocalStatsPoint(_NOW - 5, rx=2)),
        positions=(PositionPoint(_NOW - 5, 1.0, 2.0), PositionPoint(_NOW + 5, 3.0, 4.0)),
        nodeinfo=NodeInfoSeen(_NOW - 3 * _DAY, "A", "B", "CLIENT"),
        boots=(_NOW - _DAY - 1, _NOW - _DAY, _NOW - 100),
        neighbors={"0000000a": _NOW - 50, "0000000b": _NOW - 10, "0000000c": _NOW - 2 * _DAY},
        gateway_checks=(GatewayCheck(_NOW - 60, 600, 3, 2), GatewayCheck(_NOW - 2 * _DAY, 1, 1, 1)),
    )

    metrics = _metrics(history)

    assert metrics.latest_local_stats == LocalStatsPoint(_NOW - 5, rx=2)
    assert metrics.position == PositionPoint(_NOW - 5, 1.0, 2.0)
    assert metrics.nodeinfo == NodeInfoSeen(_NOW - 3 * _DAY, "A", "B", "CLIENT")
    assert metrics.boots == (_NOW - _DAY, _NOW - 100)
    assert metrics.neighbors == (("0000000b", _NOW - 10), ("0000000a", _NOW - 50))
    assert metrics.gateway_check == GatewayCheck(_NOW - 60, 600, 3, 2)


def test_the_newest_position_local_stats_and_gateway_check_in_the_window_are_kept() -> None:
    history = _history(
        positions=(PositionPoint(_NOW - 7200, 52.0, 21.0), PositionPoint(_NOW - 3600, 52.5, 21.5)),
        local_stats=(LocalStatsPoint(_NOW - 7200, rx=1), LocalStatsPoint(_NOW - 3600, rx=2)),
        gateway_checks=(
            GatewayCheck(_NOW - 7200, 3600, 9, 4),
            GatewayCheck(_NOW - 3600, 3600, 0, 0),
        ),
    )

    metrics = _metrics(history)

    assert metrics.position == PositionPoint(_NOW - 3600, 52.5, 21.5)
    assert metrics.latest_local_stats == LocalStatsPoint(_NOW - 3600, rx=2)
    assert metrics.gateway_check == GatewayCheck(_NOW - 3600, 3600, 0, 0)


def test_tied_gateways_and_relays_are_ordered_by_id_and_byte() -> None:
    history = _history(
        HourBucket(
            _H,
            gateways=MappingProxyType({"000000bb": 2, "000000aa": 2}),
            relays=MappingProxyType({0x20: 3, 0x10: 3}),
        )
    )

    metrics = _metrics(history)

    assert metrics.gateways == (("000000aa", 2), ("000000bb", 2))
    assert [relay.byte for relay in metrics.relays] == [0x10, 0x20]


def test_a_longer_window_covers_older_hours() -> None:
    history = _history(HourBucket(_H - 6 * _DAY, receptions=4), HourBucket(_H, receptions=1))

    assert _metrics(history, days=7).receptions == 5
    assert _metrics(history, days=7).days == 7
    assert _metrics(history, days=1).receptions == 1
