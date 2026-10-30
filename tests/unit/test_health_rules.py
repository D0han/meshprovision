"""Health verdicts, importance and suggestions, each rule at its boundaries (pure)."""

from __future__ import annotations

import dataclasses

import pytest

from meshprovision.health import rules
from meshprovision.health.history import GatewayCheck, NodeHistory
from meshprovision.health.metrics import BatteryTrend, NodeMetrics, RelayShare, compute_metrics
from meshprovision.health.rules import (
    AIR_UTIL_TX_CRIT_PERCENT,
    AIR_UTIL_TX_WARN_PERCENT,
    BATTERY_CRIT_PERCENT,
    BATTERY_DRAIN_WARN_PER_DAY,
    BATTERY_FRESH_SECONDS,
    BATTERY_FROM_HISTORY,
    BATTERY_FROM_STATUS,
    BATTERY_WARN_PERCENT,
    CHANNEL_UTILIZATION_CRIT_PERCENT,
    CHANNEL_UTILIZATION_WARN_PERCENT,
    CHATTY_PER_HOUR,
    DEFAULT_HOP_LIMIT,
    HOP_ADVICE_MIN_SAMPLES,
    MIN_RECEPTIONS,
    REBOOTS_WARN,
    REBOOTS_WINDOW_DAYS,
    RELAY_CONCENTRATION_SHARE,
    RELAY_DEPENDENCY_SHARE,
    ROUTER_MIN_GATEWAYS,
    SILENCE_RUN_MISSED,
    SILENCE_WARN_HOURS,
    SILENT_CRIT_SECONDS,
    SILENT_WARN_SECONDS,
    Advice,
    BatteryReading,
    Finding,
    Importance,
    NodeContext,
    Verdict,
    advise,
    assess,
    battery_reading,
    rank_importance,
)
from meshprovision.nodeid import NodeId
from meshprovision.status import render

pytestmark = pytest.mark.unit

_NODE = NodeId.from_hex("ab446357")
_OTHER = NodeId.from_hex("979ed146")
_THIRD = NodeId.from_hex("00000561")
_NOW = 1_760_994_000.0
_LOW = Importance("low", 0)


def _m(**fields: object) -> NodeMetrics:
    base: dict[str, object] = {
        "node": _NODE,
        "days": 7,
        "window_start": _NOW - 7 * 86400,
        "now": _NOW,
        "covered_hours": 24,
        "last_heard": _NOW - 60,
    }
    base.update(fields)
    return NodeMetrics(**base)  # type: ignore[arg-type]


def _codes(metrics: NodeMetrics, context: NodeContext | None = None) -> dict[str, Verdict]:
    _, findings = assess(metrics, context or NodeContext())
    return {finding.code: finding.severity for finding in findings}


def test_the_thresholds_match_the_status_table_colours() -> None:
    assert BATTERY_WARN_PERCENT == render.BATTERY_WARN_PERCENT
    assert BATTERY_CRIT_PERCENT == render.BATTERY_ALARM_PERCENT
    assert CHANNEL_UTILIZATION_WARN_PERCENT == render.CHANNEL_UTILIZATION_WARN_PERCENT
    assert CHANNEL_UTILIZATION_CRIT_PERCENT == render.CHANNEL_UTILIZATION_ALARM_PERCENT
    assert AIR_UTIL_TX_WARN_PERCENT == render.AIR_UTIL_TX_WARN_PERCENT
    assert AIR_UTIL_TX_CRIT_PERCENT == render.AIR_UTIL_TX_ALARM_PERCENT


def test_the_constants_are_the_documented_ones() -> None:
    assert (
        SILENT_WARN_SECONDS,
        SILENT_CRIT_SECONDS,
        BATTERY_WARN_PERCENT,
        BATTERY_CRIT_PERCENT,
        BATTERY_FRESH_SECONDS,
        BATTERY_DRAIN_WARN_PER_DAY,
        MIN_RECEPTIONS,
        REBOOTS_WARN,
        REBOOTS_WINDOW_DAYS,
        SILENCE_WARN_HOURS,
        SILENCE_RUN_MISSED,
        DEFAULT_HOP_LIMIT,
        HOP_ADVICE_MIN_SAMPLES,
    ) == (7200.0, 86400.0, 20, 10, 86400.0, -10.0, 20, 3, 7, 6, 5, 3, 20)
    assert (
        CHANNEL_UTILIZATION_WARN_PERCENT,
        CHANNEL_UTILIZATION_CRIT_PERCENT,
        AIR_UTIL_TX_WARN_PERCENT,
        AIR_UTIL_TX_CRIT_PERCENT,
    ) == (25.0, 40.0, 5.0, 10.0)


def test_a_healthy_node_is_ok_without_findings() -> None:
    assert assess(_m(), NodeContext()) == (Verdict.OK, ())


def test_a_node_without_any_data_is_unknown() -> None:
    verdict, findings = assess(_m(covered_hours=0, last_heard=None), NodeContext())

    assert verdict is Verdict.UNKNOWN
    assert findings == (
        Finding(Verdict.UNKNOWN, "no_data", "no lorastats data and no last-seen time"),
    )


def test_a_node_lorastats_was_asked_about_but_never_heard_is_critical() -> None:
    verdict, findings = assess(_m(last_heard=None, covered_hours=25), NodeContext())

    assert verdict is Verdict.CRIT
    assert findings[0].code == "never_heard"


@pytest.mark.parametrize(
    ("age", "expected"),
    [
        (SILENT_WARN_SECONDS, None),
        (SILENT_WARN_SECONDS + 1, Verdict.WARN),
        (SILENT_CRIT_SECONDS, Verdict.WARN),
        (SILENT_CRIT_SECONDS + 1, Verdict.CRIT),
    ],
)
def test_silence_thresholds(age: float, expected: Verdict | None) -> None:
    assert _codes(_m(last_heard=_NOW - age)).get("silent") == expected


def test_the_newest_of_history_and_status_last_seen_counts() -> None:
    old = _m(last_heard=_NOW - SILENT_CRIT_SECONDS - 1)

    assert "silent" not in _codes(old, NodeContext(last_seen=_NOW - 10))
    assert _codes(_m(last_heard=None), NodeContext(last_seen=_NOW - 3 * 86400))["silent"] == (
        Verdict.CRIT
    )
    _, findings = assess(_m(last_heard=_NOW - 3 * 86400), NodeContext())
    assert findings[0].text == "not heard for 3 d"
    _, findings = assess(_m(last_heard=_NOW - 5 * 3600), NodeContext())
    assert findings[0].text == "not heard for 5 h"
    _, findings = assess(_m(last_heard=_NOW - 47 * 3600), NodeContext())
    assert findings[0].text == "not heard for 47 h"
    _, findings = assess(_m(last_heard=_NOW - 48 * 3600), NodeContext())
    assert findings[0].text == "not heard for 2 d"


def _trend(latest: int, *, age: float = 60.0, slope: float | None = None) -> BatteryTrend:
    return BatteryTrend(latest, _NOW - age, 8, 20.0, slope)


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        (BATTERY_WARN_PERCENT + 1, None),
        (BATTERY_WARN_PERCENT, Verdict.WARN),
        (BATTERY_CRIT_PERCENT + 1, Verdict.WARN),
        (BATTERY_CRIT_PERCENT, Verdict.CRIT),
        (1, Verdict.CRIT),
    ],
)
def test_battery_thresholds(level: int, expected: Verdict | None) -> None:
    assert _codes(_m(battery=_trend(level))).get("battery_low") == expected
    status_only = NodeContext(battery=level, battery_time=_NOW - 60)
    assert _codes(_m(), status_only).get("battery_low") == expected


@pytest.mark.parametrize("level", [0, 101, -5])
def test_a_battery_level_that_is_no_reading_is_not_judged(level: int) -> None:
    assert "battery_low" not in _codes(_m(), NodeContext(battery=level, battery_time=_NOW))


def test_a_newer_external_power_reading_ends_an_older_low_level() -> None:
    """A node plugged in 2 minutes ago was judged by its 8% of 10 hours ago."""
    powered_now = NodeContext(battery=101, battery_time=_NOW - 120)

    assert "battery_low" not in _codes(_m(battery=_trend(8, age=10 * 3600)), powered_now)
    assert battery_reading(_m(battery=_trend(8, age=10 * 3600)), powered_now) == (
        BatteryReading(101, _NOW - 120, BATTERY_FROM_STATUS, fresh=True)
    )


def test_the_battery_reading_is_the_newest_fresh_level_of_history_and_status() -> None:
    newer_status = NodeContext(battery=9, battery_time=_NOW - 3600)

    assert battery_reading(_m(battery=_trend(60, age=5 * 86400)), newer_status) == (
        BatteryReading(9, _NOW - 3600, BATTERY_FROM_STATUS, fresh=True)
    )
    assert battery_reading(_m(battery=_trend(60, age=60)), newer_status) == (
        BatteryReading(60, _NOW - 60, BATTERY_FROM_HISTORY, fresh=True)
    )
    assert battery_reading(_m(), newer_status) == (
        BatteryReading(9, _NOW - 3600, BATTERY_FROM_STATUS, fresh=True)
    )


def test_a_newer_battery_level_wins_over_an_older_external_power_reading() -> None:
    powered_before = NodeContext(battery=101, battery_time=_NOW - 10 * 3600)

    assert battery_reading(_m(battery=_trend(8, age=3600)), powered_before) == (
        BatteryReading(8, _NOW - 3600, BATTERY_FROM_HISTORY, fresh=True)
    )
    assert _codes(_m(battery=_trend(8, age=3600)), powered_before)["battery_low"] is Verdict.CRIT
    assert battery_reading(_m(), powered_before) == (
        BatteryReading(101, _NOW - 10 * 3600, BATTERY_FROM_STATUS, fresh=True)
    )


def test_the_history_external_power_reading_competes_with_its_level_on_time() -> None:
    plugged_in = _m(battery=_trend(8, age=10 * 3600), battery_powered_time=_NOW - 3600)
    unplugged = _m(battery=_trend(8, age=3600), battery_powered_time=_NOW - 10 * 3600)

    assert battery_reading(plugged_in, NodeContext()) == (
        BatteryReading(101, _NOW - 3600, BATTERY_FROM_HISTORY, fresh=True)
    )
    assert "battery_low" not in _codes(plugged_in)
    assert battery_reading(unplugged, NodeContext()) == (
        BatteryReading(8, _NOW - 3600, BATTERY_FROM_HISTORY, fresh=True)
    )
    assert battery_reading(_m(battery_powered_time=_NOW - 60), NodeContext()) == (
        BatteryReading(101, _NOW - 60, BATTERY_FROM_HISTORY, fresh=True)
    )


def test_an_external_power_reading_too_old_to_judge_does_not_hide_a_fresh_level() -> None:
    old_power = _NOW - BATTERY_FRESH_SECONDS - 1
    metrics = _m(battery=_trend(8, age=BATTERY_FRESH_SECONDS), battery_powered_time=old_power)

    assert _codes(metrics)["battery_low"] is Verdict.CRIT
    assert battery_reading(_m(battery_powered_time=old_power), NodeContext()) == (
        BatteryReading(101, old_power, BATTERY_FROM_HISTORY, fresh=False)
    )


def test_at_the_same_time_external_power_wins_over_a_level() -> None:
    same_time = NodeContext(battery=101, battery_time=_NOW - 100)

    assert battery_reading(_m(battery=_trend(5, age=100)), same_time) == (
        BatteryReading(101, _NOW - 100, BATTERY_FROM_STATUS, fresh=True)
    )


def test_a_full_battery_is_a_level_not_external_power() -> None:
    powered_before = NodeContext(battery=101, battery_time=_NOW - 200)

    assert battery_reading(_m(battery=_trend(100, age=100)), powered_before) == (
        BatteryReading(100, _NOW - 100, BATTERY_FROM_HISTORY, fresh=True)
    )
    assert battery_reading(_m(), NodeContext(battery=100, battery_time=_NOW - 10)) == (
        BatteryReading(100, _NOW - 10, BATTERY_FROM_STATUS, fresh=True)
    )


def test_a_fresh_external_power_reading_wins_over_a_stale_level() -> None:
    powered_now = NodeContext(battery=101, battery_time=_NOW - 10)
    stale = _trend(5, age=BATTERY_FRESH_SECONDS + 1)

    assert battery_reading(_m(battery=stale), powered_now) == (
        BatteryReading(101, _NOW - 10, BATTERY_FROM_STATUS, fresh=True)
    )
    assert "battery_low" not in _codes(_m(battery=stale), powered_now)


def test_only_stale_readings_give_the_newest_one_not_fresh() -> None:
    old_status = NodeContext(battery=40, battery_time=_NOW - BATTERY_FRESH_SECONDS - 5)
    stale = _trend(5, age=BATTERY_FRESH_SECONDS + 1)

    assert battery_reading(_m(battery=stale), old_status) == (
        BatteryReading(5, _NOW - BATTERY_FRESH_SECONDS - 1, BATTERY_FROM_HISTORY, fresh=False)
    )


def test_a_status_level_without_a_time_counts_only_without_a_dated_reading() -> None:
    undated = NodeContext(battery=55)

    assert battery_reading(_m(), undated) == BatteryReading(55, None, BATTERY_FROM_STATUS, False)
    assert battery_reading(_m(battery=_trend(80, age=BATTERY_FRESH_SECONDS + 1)), undated) == (
        BatteryReading(80, _NOW - BATTERY_FRESH_SECONDS - 1, BATTERY_FROM_HISTORY, fresh=False)
    )
    assert "battery_low" not in _codes(_m(), NodeContext(battery=5))


@pytest.mark.parametrize("level", [0, -5])
def test_a_zero_or_negative_level_is_no_battery_reading(level: int) -> None:
    assert battery_reading(_m(), NodeContext(battery=level, battery_time=_NOW)) is None
    assert battery_reading(_m(), NodeContext(battery=level)) is None
    assert battery_reading(_m(battery=_trend(level)), NodeContext()) is None


def test_a_battery_reading_stays_fresh_for_the_stale_threshold_when_longer() -> None:
    stale_after = BATTERY_FRESH_SECONDS * 2
    context = NodeContext(battery=50, battery_time=_NOW - stale_after, stale_after=stale_after)

    reading = battery_reading(_m(), context)

    assert reading is not None
    assert reading.fresh
    assert _codes(_m(), dataclasses.replace(context, battery=5))["battery_low"] is Verdict.CRIT


def test_a_stale_battery_reading_is_not_judged_and_the_newest_one_wins() -> None:
    stale = _trend(5, age=BATTERY_FRESH_SECONDS + 1)
    edge = _trend(5, age=BATTERY_FRESH_SECONDS)

    assert "battery_low" not in _codes(_m(battery=stale))
    assert _codes(_m(battery=edge))["battery_low"] is Verdict.CRIT
    assert "battery_low" not in _codes(_m(battery=stale), NodeContext(battery=5))
    newer_status = NodeContext(battery=90, battery_time=_NOW - 10)
    assert "battery_low" not in _codes(_m(battery=_trend(5, age=100)), newer_status)
    older_status = NodeContext(battery=90, battery_time=_NOW - 200)
    assert _codes(_m(battery=_trend(5, age=100)), older_status)["battery_low"] is Verdict.CRIT


@pytest.mark.parametrize(
    ("slope", "expected"),
    [
        (BATTERY_DRAIN_WARN_PER_DAY + 0.1, None),
        (BATTERY_DRAIN_WARN_PER_DAY, Verdict.WARN),
        (None, None),
    ],
)
def test_battery_drain_threshold(slope: float | None, expected: Verdict | None) -> None:
    metrics = _m(battery=_trend(80, slope=slope))

    assert _codes(metrics).get("battery_draining") == expected
    if expected is not None:
        _, findings = assess(metrics, NodeContext())
        assert findings[0].text == "battery falling 10 points a day (8 readings over 20 h)"


def test_a_draining_battery_now_on_external_power_is_not_draining() -> None:
    """Batt 'powered' stood next to 'battery falling 12 points a day'."""
    draining = _trend(40, age=3600, slope=-12.0)

    plugged_in = _m(battery=draining, battery_powered_time=_NOW - 60)
    unplugged = _m(battery=draining, battery_powered_time=_NOW - 7200)

    assert "battery_draining" not in _codes(plugged_in)
    assert "battery_draining" not in _codes(
        _m(battery=draining), NodeContext(battery=101, battery_time=_NOW - 60)
    )
    assert _codes(unplugged)["battery_draining"] is Verdict.WARN
    stale_power = _m(battery=draining, battery_powered_time=_NOW - BATTERY_FRESH_SECONDS - 1)
    assert _codes(stale_power)["battery_draining"] is Verdict.WARN
    full = _m(battery=_trend(100, age=60, slope=-12.0))
    assert _codes(full)["battery_draining"] is Verdict.WARN


@pytest.mark.parametrize(
    ("gateways", "receptions", "expected"),
    [
        (1, MIN_RECEPTIONS, Verdict.WARN),
        (1, MIN_RECEPTIONS - 1, None),
        (2, MIN_RECEPTIONS, None),
        (0, MIN_RECEPTIONS, None),
    ],
)
def test_single_gateway_rule(gateways: int, receptions: int, expected: Verdict | None) -> None:
    metrics = _m(gateway_count=gateways, receptions=receptions)

    assert _codes(metrics).get("single_gateway") == expected


@pytest.mark.parametrize(
    ("boots", "expected"), [(REBOOTS_WARN, Verdict.WARN), (REBOOTS_WARN - 1, None)]
)
def test_reboots_rule(boots: int, expected: Verdict | None) -> None:
    metrics = _m(boots=tuple(float(index) for index in range(boots)))

    assert _codes(metrics).get("reboots") == expected


@pytest.mark.parametrize(
    ("field", "code", "warn", "crit"),
    [
        (
            "channel_utilization",
            "channel_busy",
            CHANNEL_UTILIZATION_WARN_PERCENT,
            CHANNEL_UTILIZATION_CRIT_PERCENT,
        ),
        ("air_util_tx", "airtime_high", AIR_UTIL_TX_WARN_PERCENT, AIR_UTIL_TX_CRIT_PERCENT),
    ],
)
def test_utilization_thresholds(field: str, code: str, warn: float, crit: float) -> None:
    assert code not in _codes(_m(**{field: warn}))
    assert _codes(_m(**{field: warn + 0.1}))[code] is Verdict.WARN
    assert _codes(_m(**{field: crit}))[code] is Verdict.WARN
    assert _codes(_m(**{field: crit + 0.1}))[code] is Verdict.CRIT


@pytest.mark.parametrize(("hours", "expected"), [(6, Verdict.WARN), (5, None)])
def test_long_silence_rule(hours: int, expected: Verdict | None) -> None:
    assert _codes(_m(longest_silence_hours=hours)).get("silent_hours") == expected


def test_the_verdict_is_the_worst_finding_and_findings_are_sorted_by_severity() -> None:
    metrics = _m(
        channel_utilization=30.0, air_util_tx=AIR_UTIL_TX_CRIT_PERCENT + 1, boots=(1.0, 2.0, 3.0)
    )

    verdict, findings = assess(metrics, NodeContext())

    assert verdict is Verdict.CRIT
    assert [finding.code for finding in findings] == ["airtime_high", "reboots", "channel_busy"]
    warn_only, _ = assess(_m(boots=(1.0, 2.0, 3.0)), NodeContext())
    assert warn_only is Verdict.WARN


def _relayed(top: RelayShare, relayed: int = MIN_RECEPTIONS) -> NodeMetrics:
    return _m(node=_OTHER, relayed=relayed, relays=(top,))


def test_importance_scores_a_gateway_its_sole_gateway_nodes_dependents_and_role() -> None:
    fleet = {
        _NODE: _m(uplinks_itself=True),
        _OTHER: _m(
            node=_OTHER,
            receptions=MIN_RECEPTIONS,
            gateways=((_NODE.hex, MIN_RECEPTIONS),),
            relayed=MIN_RECEPTIONS,
            relays=(RelayShare(0x57, 10, RELAY_DEPENDENCY_SHARE, (_NODE,)),),
        ),
        _THIRD: _m(node=_THIRD),
    }

    ranked = rank_importance(fleet, {_NODE: "ROUTER", _THIRD: "CLIENT"})

    assert ranked[_NODE] == Importance(
        "high",
        3 + 3 + 2 + 1,
        (
            "MQTT gateway",
            "uplinks 1 of our nodes",
            "only gateway for 1 of our nodes",
            "busiest relay of 1 of our nodes",
            "role ROUTER",
        ),
        (_OTHER,),
        (_OTHER,),
        (_OTHER,),
    )
    assert ranked[_THIRD] == Importance("low", 0)
    assert ranked[_OTHER] == Importance("low", 0)


def test_a_newer_idle_gateway_check_ends_the_gateway_points() -> None:
    checks = (GatewayCheck(_NOW - 7200, 3600, 9, 4), GatewayCheck(_NOW - 3600, 3600, 0, 0))
    history = NodeHistory(node=_NODE, gateway_checks=checks)

    metrics = compute_metrics(history, now=_NOW, days=7)

    assert "MQTT gateway" not in rank_importance({_NODE: metrics}, {})[_NODE].reasons


@pytest.mark.parametrize(
    ("metrics", "expected"),
    [
        pytest.param(_m(uplinks_itself=True, gateways=((_NODE.hex, 5),)), 3, id="uplinks-itself"),
        pytest.param(_m(gateway_check=GatewayCheck(_NOW, 600, 5, 1)), 3, id="gateway-check"),
        pytest.param(_m(gateway_check=GatewayCheck(_NOW, 600, 0, 0)), 0, id="idle-check"),
    ],
)
def test_importance_of_a_gateway(metrics: NodeMetrics, expected: int) -> None:
    importance = rank_importance({_NODE: metrics}, {})[_NODE]

    assert importance.score == expected
    assert importance.uplinked == ()


@pytest.mark.parametrize(
    ("score", "level"),
    [
        (rules.IMPORTANCE_HIGH_SCORE, "high"),
        (rules.IMPORTANCE_HIGH_SCORE - 1, "medium"),
        (rules.IMPORTANCE_MEDIUM_SCORE, "medium"),
        (rules.IMPORTANCE_MEDIUM_SCORE - 1, "low"),
    ],
)
def test_importance_levels(score: int, level: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rules, "_ROUTER_POINTS", score)

    assert rank_importance({_NODE: _m()}, {_NODE: "ROUTER_LATE"})[_NODE].level == level


def test_a_node_with_too_few_receptions_does_not_make_its_gateway_its_sole_one() -> None:
    other = _m(node=_OTHER, receptions=MIN_RECEPTIONS - 1, gateways=((_NODE.hex, 5),))

    ranked = rank_importance({_NODE: _m(), _OTHER: other}, {})

    assert ranked[_NODE].sole_gateway_for == ()
    assert ranked[_NODE].uplinked == (_OTHER,)


def test_two_gateways_mean_neither_is_the_sole_one() -> None:
    other = _m(node=_OTHER, receptions=50, gateways=((_NODE.hex, 25), ("0000000a", 25)))

    assert rank_importance({_NODE: _m(), _OTHER: other}, {})[_NODE].sole_gateway_for == ()


@pytest.mark.parametrize(
    "dependent",
    [
        pytest.param(
            _relayed(RelayShare(0x57, 9, RELAY_DEPENDENCY_SHARE - 0.01, (_NODE,))), id="low-share"
        ),
        pytest.param(
            _relayed(RelayShare(0x57, 9, 0.9, (_NODE,)), relayed=MIN_RECEPTIONS - 1),
            id="few-relayed",
        ),
        pytest.param(
            _relayed(RelayShare(0x57, 9, 0.9, (_NODE, NodeId.from_hex("11111157")))),
            id="ambiguous-byte",
        ),
        pytest.param(_m(node=_OTHER, relayed=50), id="no-relay"),
    ],
)
def test_a_relay_dependency_needs_share_samples_and_an_unambiguous_byte(
    dependent: NodeMetrics,
) -> None:
    assert rank_importance({_NODE: _m(), _OTHER: dependent}, {})[_NODE].dependents == ()


def _advice(metrics: NodeMetrics, context: NodeContext | None = None, importance=_LOW) -> list[str]:
    return [item.code for item in advise(metrics, context or NodeContext(), importance)]


def _hops(hop_start: int, hops_max: int, samples: int = HOP_ADVICE_MIN_SAMPLES) -> NodeMetrics:
    return _m(hop_start=hop_start, hops={0: samples - 1, hops_max: 1}, hop_samples=samples)


def test_a_hop_limit_above_what_was_needed_is_suggested_lower() -> None:
    (advice,) = advise(_hops(7, 2), NodeContext(), _LOW)

    assert advice == Advice(
        "hop_limit",
        "hop limit 7, but gateways heard it within 2 hops (20 decoded receptions): "
        "consider a hop limit of 3",
    )
    assert advise(_hops(7, 4), NodeContext(), _LOW)[0].text.endswith("hop limit of 5")


@pytest.mark.parametrize(
    "metrics",
    [
        pytest.param(_hops(DEFAULT_HOP_LIMIT, 0), id="already-default"),
        pytest.param(_hops(5, 4), id="needed"),
        pytest.param(_hops(7, 1, samples=HOP_ADVICE_MIN_SAMPLES - 1), id="few-samples"),
        pytest.param(_m(hops={1: 30}, hop_samples=30), id="no-hop-start"),
        pytest.param(_m(hop_start=7, hop_samples=30), id="no-hops"),
    ],
)
def test_no_hop_limit_suggestion(metrics: NodeMetrics) -> None:
    assert "hop_limit" not in _advice(metrics)


def test_chatty_telemetry_is_flagged_only_on_a_busy_channel() -> None:
    busy = CHANNEL_UTILIZATION_WARN_PERCENT + 1

    assert _advice(_m(telemetry_per_hour=CHATTY_PER_HOUR + 0.1, channel_utilization=busy)) == [
        "telemetry_interval"
    ]
    assert _advice(_m(telemetry_per_hour=CHATTY_PER_HOUR, channel_utilization=busy)) == []
    assert (
        _advice(
            _m(
                telemetry_per_hour=CHATTY_PER_HOUR + 1,
                channel_utilization=CHANNEL_UTILIZATION_WARN_PERCENT,
            )
        )
        == []
    )
    assert _advice(_m(telemetry_per_hour=9.0)) == []


def test_chatty_positions_are_flagged() -> None:
    assert _advice(_m(positions_per_hour=CHATTY_PER_HOUR + 0.1)) == ["position_interval"]
    assert _advice(_m(positions_per_hour=CHATTY_PER_HOUR)) == []


def test_a_mute_client_that_is_a_busiest_relay_is_flagged() -> None:
    relied_on = Importance("medium", 2, dependents=(_OTHER,))

    assert _advice(_m(), NodeContext(role="CLIENT_MUTE"), relied_on) == ["mute_relay"]
    assert _advice(_m(), NodeContext(role="CLIENT"), relied_on) == []
    assert _advice(_m(), NodeContext(role="CLIENT_MUTE"), _LOW) == []


@pytest.mark.parametrize(
    ("gateways", "receptions", "role", "flagged"),
    [
        (ROUTER_MIN_GATEWAYS - 1, MIN_RECEPTIONS, "ROUTER", True),
        (ROUTER_MIN_GATEWAYS - 1, MIN_RECEPTIONS, "REPEATER", True),
        (ROUTER_MIN_GATEWAYS, MIN_RECEPTIONS, "ROUTER", False),
        (ROUTER_MIN_GATEWAYS - 1, MIN_RECEPTIONS - 1, "ROUTER", False),
        (ROUTER_MIN_GATEWAYS - 1, MIN_RECEPTIONS, "CLIENT", False),
    ],
)
def test_a_router_heard_by_few_gateways_is_flagged(
    gateways: int, receptions: int, role: str, flagged: bool
) -> None:
    metrics = _m(gateway_count=gateways, receptions=receptions)

    assert ("router_placement" in _advice(metrics, NodeContext(role=role))) is flagged


def test_relay_concentration_names_a_likely_relay() -> None:
    top = RelayShare(0x61, 80, RELAY_CONCENTRATION_SHARE, (_THIRD,))

    (advice,) = advise(_m(relayed=100, relays=(top,)), NodeContext(), _LOW)

    assert advice.code == "relay_concentration"
    assert advice.text.startswith("80% of its relayed receptions came through relay byte 0x61")
    assert "(likely !00000561)" in advice.text
    ambiguous = dataclasses.replace(top, candidates=(_THIRD, NodeId.from_hex("22222261")))
    (unnamed,) = advise(_m(relayed=100, relays=(ambiguous,)), NodeContext(), _LOW)
    assert "likely" not in unnamed.text


@pytest.mark.parametrize(
    "metrics",
    [
        pytest.param(
            _m(relayed=100, relays=(RelayShare(0x61, 79, RELAY_CONCENTRATION_SHARE - 0.01, ()),)),
            id="low-share",
        ),
        pytest.param(
            _m(relayed=MIN_RECEPTIONS - 1, relays=(RelayShare(0x61, 19, 1.0, ()),)),
            id="few-relayed",
        ),
    ],
)
def test_no_relay_concentration_suggestion(metrics: NodeMetrics) -> None:
    assert _advice(metrics) == []
