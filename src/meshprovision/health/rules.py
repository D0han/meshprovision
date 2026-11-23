"""Verdicts, importance and configuration suggestions from health metrics. Pure.

Every rule is a named threshold below, documented with its reason in
``docs/commands.md`` (``mesh health``), and tested at its boundaries.
They are heuristics for a mesh operator, not firmware limits. The rules
about silence are relative to how often the node is expected to be heard
(:class:`NodeContext`, from :mod:`meshprovision.status.cadence`), so a
node configured to report every few hours is not judged like an hourly one:

- a **verdict** (``ok``/``warn``/``crit``, ``unknown`` without any data)
  with the reasons that set it;
- an **importance** (``high``/``medium``/``low``): a score that counts what
  the rest of our fleet would lose without the node, raised to how much
  its region relied on it when ``mesh network`` data says so (see
  :func:`rank_importance`, in :mod:`meshprovision.health.importance` and
  re-exported here);
- **suggestions**: configuration changes worth considering, worded as
  such; nothing here ever changes a node.

This module imports nothing that reads files or the network (no
``httpx``, ``pathlib``, :mod:`meshprovision.cache` or
:mod:`meshprovision.db`); ``tests/unit/test_import_contracts.py`` holds it
to that.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from meshprovision.battery import EXTERNAL_POWER_BATTERY_LEVEL, is_external_power
from meshprovision.health.importance import (
    IMPORTANCE_HIGH_SCORE,
    IMPORTANCE_MEDIUM_SCORE,
    MIN_RECEPTIONS,
    RELAY_DEPENDENCY_SHARE,
    ROUTER_ROLES,
    Importance,
    RegionImportance,
    rank_importance,
)
from meshprovision.health.metrics import NodeMetrics
from meshprovision.health.packets import FUTURE_SKEW_SECONDS
from meshprovision.status.cadence import OFFLINE_MISSED, CadenceSource, interval_text

__all__ = [
    "AIR_UTIL_TX_CRIT_PERCENT",
    "AIR_UTIL_TX_WARN_PERCENT",
    "BATTERY_CRIT_PERCENT",
    "BATTERY_DRAIN_WARN_PER_DAY",
    "BATTERY_FRESH_SECONDS",
    "BATTERY_FROM_HISTORY",
    "BATTERY_FROM_STATUS",
    "BATTERY_WARN_PERCENT",
    "CHANNEL_UTILIZATION_CRIT_PERCENT",
    "CHANNEL_UTILIZATION_WARN_PERCENT",
    "CHATTY_MAX_PER_HOUR",
    "CHATTY_MIN_PER_HOUR",
    "CHATTY_PER_HOUR",
    "CHATTY_REFERENCE_PRESET",
    "DEFAULT_HOP_LIMIT",
    "HOP_ADVICE_MIN_SAMPLES",
    "IMPORTANCE_HIGH_SCORE",
    "IMPORTANCE_MEDIUM_SCORE",
    "LONG_PRESETS",
    "LONG_PRESET_MAX_NODES",
    "MIN_RECEPTIONS",
    "PRESET_AIRTIME_MS",
    "REBOOTS_WARN",
    "REBOOTS_WINDOW_DAYS",
    "RELAY_CONCENTRATION_SHARE",
    "RELAY_DEPENDENCY_SHARE",
    "ROUTER_MIN_GATEWAYS",
    "ROUTER_ROLES",
    "SILENCE_RUN_MISSED",
    "SILENCE_WARN_HOURS",
    "SILENT_CRIT_SECONDS",
    "SILENT_WARN_SECONDS",
    "Advice",
    "BatteryReading",
    "Finding",
    "Importance",
    "NodeContext",
    "RegionImportance",
    "Verdict",
    "advise",
    "assess",
    "battery_reading",
    "chatty_limit",
    "rank_importance",
]

SILENT_WARN_SECONDS: Final[float] = 2 * 3600.0
"""Not heard for longer than this: warn, unless :class:`NodeContext` gives the node's own
stale threshold (``mesh status``'s, at least this)."""

SILENT_CRIT_SECONDS: Final[float] = 24 * 3600.0
"""Not heard for longer than this: critical, unless :class:`NodeContext` gives the node's own
offline threshold (``mesh status``'s, at least this)."""

BATTERY_WARN_PERCENT: Final[int] = 20
"""A current battery reading at or below this: warn (as ``mesh status`` colours it)."""

BATTERY_CRIT_PERCENT: Final[int] = 10
"""A current battery reading at or below this: critical."""

BATTERY_FRESH_SECONDS: Final[float] = 24 * 3600.0
"""A battery reading older than this, and than the node's stale threshold, is not judged."""

BATTERY_DRAIN_WARN_PER_DAY: Final[float] = -10.0
"""A battery trend at or below this many percentage points a day: warn."""

REBOOTS_WARN: Final[int] = 3
"""This many boots per :data:`REBOOTS_WINDOW_DAYS` of the window or more (at least this
many in any window): warn."""

REBOOTS_WINDOW_DAYS: Final[int] = 7
"""The days :data:`REBOOTS_WARN` is counted over."""

CHANNEL_UTILIZATION_WARN_PERCENT: Final[float] = 25.0
"""Mean channel utilization above this: warn (firmware starts delaying sends)."""

CHANNEL_UTILIZATION_CRIT_PERCENT: Final[float] = 40.0
"""Mean channel utilization above this: critical."""

AIR_UTIL_TX_WARN_PERCENT: Final[float] = 5.0
"""Mean transmit air utilization above this: warn."""

AIR_UTIL_TX_CRIT_PERCENT: Final[float] = 10.0
"""Mean transmit air utilization above this (the common duty-cycle limit): critical."""

SILENCE_WARN_HOURS: Final[int] = 6
"""This many consecutive covered hours without a reception, or more: warn (at least; see
:data:`SILENCE_RUN_MISSED`)."""

SILENCE_RUN_MISSED: Final[int] = OFFLINE_MISSED
"""A silent run warns only once it is this many expected intervals long (as long as the
offline rule's): a past outage, not a few lost packets."""

DEFAULT_HOP_LIMIT: Final[int] = 3
"""Meshtastic's default hop limit; never suggest less."""

HOP_ADVICE_MIN_SAMPLES: Final[int] = 20
"""Fewest receptions with a hop count before a hop limit is suggested."""

CHATTY_PER_HOUR: Final[float] = 2.0
"""More telemetry or position packets an hour than this, on :data:`CHATTY_REFERENCE_PRESET`,
is suggested to be reduced; other presets get the same airtime (see :func:`chatty_limit`)."""

CHATTY_REFERENCE_PRESET: Final[str] = "LONG_FAST"
"""The preset :data:`CHATTY_PER_HOUR` is stated for (the default, and assumed when unknown)."""

CHATTY_MIN_PER_HOUR: Final[float] = 1.0
"""The lowest chatty limit: hourly packets are never suggested to be reduced."""

CHATTY_MAX_PER_HOUR: Final[float] = 6.0
"""The highest chatty limit, however cheap a packet: more is a lot on any shared mesh."""

PRESET_AIRTIME_MS: Final[Mapping[str, int]] = MappingProxyType(
    {
        "SHORT_TURBO": 23,
        "SHORT_FAST": 45,
        "SHORT_SLOW": 85,
        "MEDIUM_TURBO": 80,
        "MEDIUM_FAST": 160,
        "MEDIUM_SLOW": 300,
        "LONG_TURBO": 378,
        "LONG_FAST": 559,
        "LONG_MODERATE": 1642,
        "LONG_SLOW": 3023,
    }
)
"""Airtime of a typical 40-byte packet per modem preset, milliseconds (LoRa time-on-air
formula: 16-symbol preamble, explicit header, CRC)."""

LONG_PRESETS: Final[frozenset[str]] = frozenset(
    {"LONG_FAST", "LONG_MODERATE", "LONG_SLOW", "LONG_TURBO", "VERY_LONG_SLOW"}
)
"""The long-range presets, whose packets are the most expensive."""

LONG_PRESET_MAX_NODES: Final[int] = 60
"""More nodes online around a node on a long preset than this: suggest a faster preset
(the Meshtastic project's own advice for ``LONG_FAST``)."""

RELAY_CONCENTRATION_SHARE: Final[float] = 0.8
"""One relay carrying at least this share of a node's relayed receptions is a single point of
failure for it."""

ROUTER_MIN_GATEWAYS: Final[int] = 3
"""A router heard by fewer gateways than this (besides itself) may be poorly placed."""

_HOURS_PER_DAY: Final[int] = 24
_SECONDS_PER_HOUR: Final[float] = 3600.0
_SOURCE_TEXTS: Final[Mapping[str, str]] = {
    CadenceSource.OVERRIDE: "as given",
    CadenceSource.HISTORY: "learned from its history",
    CadenceSource.TEMPLATE: "from the template",
    CadenceSource.ROLE: "its role's default",
}
"""How each source of an expected interval is named in a finding."""


class Verdict(StrEnum):
    """A node's overall health.

    Attributes:
        OK: No rule fired.
        WARN: At least one warning, no critical finding.
        CRIT: At least one critical finding.
        UNKNOWN: Nothing is known about the node.
    """

    OK = "ok"
    WARN = "warn"
    CRIT = "crit"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Finding:
    """One reason for a verdict.

    Attributes:
        severity: :attr:`Verdict.WARN`, :attr:`Verdict.CRIT` or
            :attr:`Verdict.UNKNOWN`.
        code: A stable identifier (for ``--json``).
        text: What was found, for a person.
    """

    severity: Verdict
    code: str
    text: str


@dataclass(frozen=True, slots=True)
class Advice:
    """One configuration change worth considering.

    Attributes:
        code: A stable identifier (for ``--json``).
        text: The suggestion, for a person.
    """

    code: str
    text: str


@dataclass(frozen=True, slots=True)
class NodeContext:
    """What the rules know about a node beyond its history.

    Attributes:
        role: The node's role (canonical name), when known.
        last_seen: When any source last saw it, epoch seconds.
        battery: Its battery level from ``mesh status``'s sources.
        battery_time: When that battery level was reported, epoch seconds.
        stale_after: Its stale threshold, seconds (``mesh status``'s).
        offline_after: Its offline threshold, seconds.
        expected_interval: How often it is expected to be heard, seconds,
            when known.
        cadence_source: Where that came from
            (:class:`~meshprovision.status.cadence.CadenceSource` value).
        preset: Its modem preset, when known.
        online_local_nodes: How many nodes it counted online around it,
            when known.
    """

    role: str | None = None
    last_seen: float | None = None
    battery: int | None = None
    battery_time: float | None = None
    stale_after: float = SILENT_WARN_SECONDS
    offline_after: float = SILENT_CRIT_SECONDS
    expected_interval: float | None = None
    cadence_source: str | None = None
    preset: str | None = None
    online_local_nodes: int | None = None


def _duration(seconds: float) -> str:
    """Render a duration as hours below two days, else days."""
    hours = seconds / _SECONDS_PER_HOUR
    if hours < 2 * _HOURS_PER_DAY:
        return f"{hours:.0f} h"
    return f"{hours / _HOURS_PER_DAY:.0f} d"


def _expectation(context: NodeContext) -> str:
    """Name the node's expected interval for a finding, or nothing when unknown."""
    if context.expected_interval is None:
        return ""
    every = interval_text(timedelta(seconds=context.expected_interval))
    source = _SOURCE_TEXTS.get(context.cadence_source or "", "")
    return f" (expected every {every}" + (f", {source})" if source else ")")


@dataclass(frozen=True, slots=True)
class BatteryReading:
    """A node's newest battery reading.

    Attributes:
        level: The percentage; above 100 means external power.
        time: When it was reported, epoch seconds; ``None`` when the
            source gave no time.
        source: :data:`BATTERY_FROM_HISTORY` or :data:`BATTERY_FROM_STATUS`.
        fresh: Whether it is recent enough to judge.
    """

    level: int
    time: float | None
    source: str
    fresh: bool


BATTERY_FROM_HISTORY: Final[str] = "history"
"""A :class:`BatteryReading` from the node's history (its telemetry)."""

BATTERY_FROM_STATUS: Final[str] = "mesh status"
"""A :class:`BatteryReading` from ``mesh status``'s sources."""


def battery_reading(metrics: NodeMetrics, context: NodeContext) -> BatteryReading | None:
    """Return the battery reading to show and judge, from the node's history or ``mesh status``.

    A level of 0 or less is no reading (a node without a battery sensor
    reports 0). The history gives its newest battery level and its newest
    external-power reading (above 100). The newest fresh reading wins,
    level or external power, so a node plugged in after a low reading is
    not judged by that reading (and one unplugged since is judged by its
    level); at the same time a higher level wins. Without a fresh
    reading the newest one wins, not fresh. A reading dated more than
    :data:`FUTURE_SKEW_SECONDS` ahead is dropped. A ``mesh status`` level
    without a usable time counts only when there is no dated reading, and
    never as fresh. Fresh means not older than :data:`BATTERY_FRESH_SECONDS`
    or, when longer, the node's stale threshold.

    Args:
        metrics: The node's metrics.
        context: What else is known about it.

    Returns:
        The reading, or ``None`` when there is none.
    """
    readings: list[tuple[float, int, str]] = []
    if metrics.battery is not None and metrics.battery.latest > 0:
        readings.append((metrics.battery.latest_time, metrics.battery.latest, BATTERY_FROM_HISTORY))
    if metrics.battery_powered_time is not None:
        readings.append(
            (metrics.battery_powered_time, EXTERNAL_POWER_BATTERY_LEVEL, BATTERY_FROM_HISTORY)
        )
    status_level = context.battery if context.battery is not None and context.battery > 0 else None
    if status_level is not None and context.battery_time is not None:
        readings.append((context.battery_time, status_level, BATTERY_FROM_STATUS))
    readings = [reading for reading in readings if reading[0] <= metrics.now + FUTURE_SKEW_SECONDS]
    fresh_for = max(BATTERY_FRESH_SECONDS, context.stale_after)
    fresh = [reading for reading in readings if metrics.now - reading[0] <= fresh_for]
    for candidates, is_fresh in ((fresh, True), (readings, False)):
        if candidates:
            time, level, source = max(candidates)
            return BatteryReading(level, time, source, is_fresh)
    if status_level is not None:
        return BatteryReading(status_level, None, BATTERY_FROM_STATUS, fresh=False)
    return None


def _current_battery(metrics: NodeMetrics, context: NodeContext) -> int | None:
    """Return the battery level to judge: the reading's when fresh (external power is never low)."""
    reading = battery_reading(metrics, context)
    return reading.level if reading is not None and reading.fresh else None


def _by_silence(seconds: float, context: NodeContext) -> Verdict | None:
    """Judge a silence against the node's thresholds: critical, warning or nothing."""
    if seconds > context.offline_after:
        return Verdict.CRIT
    if seconds > context.stale_after:
        return Verdict.WARN
    return None


def _silence(metrics: NodeMetrics, context: NodeContext) -> Finding | None:
    """Judge how long ago the node was last heard, against its own thresholds."""
    heard = [t for t in (metrics.last_heard, context.last_seen) if t is not None]
    expected = _expectation(context)
    if not heard:
        if metrics.covered_hours:
            covered = metrics.covered_hours * _SECONDS_PER_HOUR
            text = f"lorastats never heard it in {metrics.covered_hours} covered hours{expected}"
            return Finding(_by_silence(covered, context) or Verdict.UNKNOWN, "never_heard", text)
        return Finding(Verdict.UNKNOWN, "no_data", "no lorastats data and no last-seen time")
    age = metrics.now - max(heard)
    severity = _by_silence(age, context)
    if severity is None:
        return None
    return Finding(severity, "silent", f"not heard for {_duration(age)}{expected}")


def _silence_run_hours(context: NodeContext) -> int:
    """Return the run of silent hours that warns: :data:`SILENCE_RUN_MISSED` intervals."""
    if context.expected_interval is None:
        return SILENCE_WARN_HOURS
    run = math.ceil(SILENCE_RUN_MISSED * context.expected_interval / _SECONDS_PER_HOUR)
    return max(SILENCE_WARN_HOURS, run)


def _reboots_warn(days: int) -> int:
    """Return the boots in a window of ``days`` that warn."""
    return max(REBOOTS_WARN, math.ceil(REBOOTS_WARN * days / REBOOTS_WINDOW_DAYS))


def _battery_findings(metrics: NodeMetrics, context: NodeContext) -> list[Finding]:
    """Judge the current battery level and its trend (no trend on external power)."""
    findings = []
    level = _current_battery(metrics, context)
    powered = is_external_power(level)
    if level is not None and level <= BATTERY_CRIT_PERCENT:
        findings.append(Finding(Verdict.CRIT, "battery_low", f"battery at {level}%"))
    elif level is not None and level <= BATTERY_WARN_PERCENT:
        findings.append(Finding(Verdict.WARN, "battery_low", f"battery at {level}%"))
    trend = metrics.battery
    if (
        not powered
        and trend is not None
        and trend.slope_per_day is not None
        and trend.slope_per_day <= BATTERY_DRAIN_WARN_PER_DAY
    ):
        findings.append(
            Finding(
                Verdict.WARN,
                "battery_draining",
                f"battery falling {-trend.slope_per_day:.0f} points a day "
                f"({trend.points} readings over {trend.span_hours:.0f} h)",
            )
        )
    return findings


def _utilization(
    value: float | None, warn: float, crit: float, code: str, label: str
) -> list[Finding]:
    """Judge a mean utilization percentage."""
    if value is None or value <= warn:
        return []
    severity = Verdict.CRIT if value > crit else Verdict.WARN
    return [Finding(severity, code, f"{label} averaging {value:.1f}%")]


def _single_gateway(metrics: NodeMetrics) -> Finding | None:
    """Judge a node one gateway uplinks, or none but itself (its own uplinks do not count)."""
    if metrics.receptions < MIN_RECEPTIONS:
        return None
    others = metrics.other_gateway_count
    if others == 1:
        text = f"uplinked by one gateway only ({metrics.receptions} receptions)"
    elif others == 0 and metrics.uplinks_itself:
        text = f"heard by no other gateway, only uplinks itself ({metrics.receptions} receptions)"
    else:
        return None
    return Finding(Verdict.WARN, "single_gateway", text)


def assess(metrics: NodeMetrics, context: NodeContext) -> tuple[Verdict, tuple[Finding, ...]]:
    """Judge a node's health.

    Args:
        metrics: Its metrics.
        context: What else is known about it.

    Returns:
        The verdict and the findings behind it, most severe first.
    """
    findings: list[Finding] = []
    silence = _silence(metrics, context)
    if silence is not None:
        findings.append(silence)
    findings.extend(_battery_findings(metrics, context))
    single = _single_gateway(metrics)
    if single is not None:
        findings.append(single)
    if len(metrics.boots) >= _reboots_warn(metrics.days):
        findings.append(
            Finding(Verdict.WARN, "reboots", f"{len(metrics.boots)} boots in {metrics.days} d")
        )
    findings.extend(
        _utilization(
            metrics.channel_utilization,
            CHANNEL_UTILIZATION_WARN_PERCENT,
            CHANNEL_UTILIZATION_CRIT_PERCENT,
            "channel_busy",
            "channel utilization",
        )
    )
    findings.extend(
        _utilization(
            metrics.air_util_tx,
            AIR_UTIL_TX_WARN_PERCENT,
            AIR_UTIL_TX_CRIT_PERCENT,
            "airtime_high",
            "transmit air utilization",
        )
    )
    if metrics.longest_silence_hours >= _silence_run_hours(context):
        findings.append(
            Finding(
                Verdict.WARN,
                "silent_hours",
                f"{metrics.longest_silence_hours} hours in a row without a reception"
                f"{_expectation(context)}",
            )
        )
    order = {Verdict.CRIT: 0, Verdict.WARN: 1, Verdict.UNKNOWN: 2}
    findings.sort(key=lambda finding: order[finding.severity])
    severities = {finding.severity for finding in findings}
    for verdict in (Verdict.CRIT, Verdict.WARN, Verdict.UNKNOWN):
        if verdict in severities:
            return verdict, tuple(findings)
    return Verdict.OK, ()


def chatty_limit(preset: str | None) -> float:
    """Return how many telemetry or position packets an hour a preset affords.

    The airtime of :data:`CHATTY_PER_HOUR` packets on
    :data:`CHATTY_REFERENCE_PRESET`, in packets of ``preset``, between
    :data:`CHATTY_MIN_PER_HOUR` and :data:`CHATTY_MAX_PER_HOUR`.

    Args:
        preset: The modem preset; unknown or ``None`` counts as the
            reference preset.

    Returns:
        The limit, packets an hour.
    """
    airtime = PRESET_AIRTIME_MS.get(preset or "")
    if airtime is None:
        return CHATTY_PER_HOUR
    budget = CHATTY_PER_HOUR * PRESET_AIRTIME_MS[CHATTY_REFERENCE_PRESET]
    return min(CHATTY_MAX_PER_HOUR, max(CHATTY_MIN_PER_HOUR, budget / airtime))


def _preset_name(preset: str | None) -> str:
    """Name the preset a chatty limit was computed for."""
    if preset in PRESET_AIRTIME_MS:
        return f"on {preset}"
    return f"on {CHATTY_REFERENCE_PRESET}, assumed"


def advise(
    metrics: NodeMetrics, context: NodeContext, importance: Importance
) -> tuple[Advice, ...]:
    """Suggest configuration changes worth considering.

    Args:
        metrics: The node's metrics.
        context: What else is known about it.
        importance: Its importance (for the relay-role check).

    Returns:
        The suggestions, in a fixed order.
    """
    advice: list[Advice] = []
    hops_max = metrics.hops_max
    if (
        metrics.hop_start is not None
        and hops_max is not None
        and metrics.hop_samples >= HOP_ADVICE_MIN_SAMPLES
    ):
        enough = max(DEFAULT_HOP_LIMIT, hops_max + 1)
        if metrics.hop_start > enough:
            advice.append(
                Advice(
                    "hop_limit",
                    f"hop limit {metrics.hop_start}, but gateways heard it within {hops_max} "
                    f"hops ({metrics.hop_samples} decoded receptions): consider a hop limit "
                    f"of {enough}",
                )
            )
    limit = chatty_limit(context.preset)
    afforded = f"(more than {limit:.1f} an hour {_preset_name(context.preset)})"
    busy = (metrics.channel_utilization or 0.0) > CHANNEL_UTILIZATION_WARN_PERCENT
    if busy and (metrics.telemetry_per_hour or 0.0) > limit:
        advice.append(
            Advice(
                "telemetry_interval",
                f"at least {metrics.telemetry_per_hour:.1f} telemetry packets an hour on a busy "
                f"channel {afforded}: consider a longer telemetry interval",
            )
        )
    if (metrics.positions_per_hour or 0.0) > limit:
        advice.append(
            Advice(
                "position_interval",
                f"at least {metrics.positions_per_hour:.1f} position packets an hour {afforded}: "
                "consider a longer position interval or smart position",
            )
        )
    online = context.online_local_nodes
    if context.preset in LONG_PRESETS and online is not None and online > LONG_PRESET_MAX_NODES:
        advice.append(
            Advice(
                "preset_congested",
                f"{online} nodes online around it on {context.preset}: a mesh of more than "
                f"{LONG_PRESET_MAX_NODES} nodes is better served by a faster preset such as "
                "MEDIUM_FAST (a change for the whole mesh, not for this node alone)",
            )
        )
    if context.role == "CLIENT_MUTE" and importance.dependents:
        advice.append(
            Advice(
                "mute_relay",
                f"role CLIENT_MUTE, yet its id byte is the busiest relay of "
                f"{len(importance.dependents)} of our nodes: another node with the same last "
                "byte, or the role is not what it reports",
            )
        )
    if (
        context.role in ROUTER_ROLES
        and metrics.receptions >= MIN_RECEPTIONS
        and metrics.other_gateway_count < ROUTER_MIN_GATEWAYS
    ):
        besides = " besides itself" if metrics.uplinks_itself else ""
        advice.append(
            Advice(
                "router_placement",
                f"role {context.role}, but only {metrics.other_gateway_count} gateway(s){besides} "
                "uplinked it: consider whether it is placed well enough to be a router",
            )
        )
    top = metrics.top_relay
    if (
        top is not None
        and metrics.relayed >= MIN_RECEPTIONS
        and top.share >= RELAY_CONCENTRATION_SHARE
    ):
        likely = f" (likely {top.candidates[0].display})" if len(top.candidates) == 1 else ""
        advice.append(
            Advice(
                "relay_concentration",
                f"{top.share:.0%} of its relayed receptions came through relay byte "
                f"0x{top.byte:02x}{likely}: a single point of failure for it; consider "
                "another router or base station within its reach",
            )
        )
    return tuple(advice)
