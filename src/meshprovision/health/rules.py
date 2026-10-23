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
  the rest of our fleet would lose without the node (see
  :func:`rank_importance`);
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

from meshprovision.health.metrics import NodeMetrics
from meshprovision.nodeid import NodeId
from meshprovision.status.cadence import OFFLINE_MISSED, CadenceSource, interval_text

__all__ = [
    "AIR_UTIL_TX_CRIT_PERCENT",
    "AIR_UTIL_TX_WARN_PERCENT",
    "BATTERY_CRIT_PERCENT",
    "BATTERY_DRAIN_WARN_PER_DAY",
    "BATTERY_FRESH_SECONDS",
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
    "Finding",
    "Importance",
    "NodeContext",
    "Verdict",
    "advise",
    "assess",
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

MIN_RECEPTIONS: Final[int] = 20
"""Fewest receptions (or relayed receptions) a gateway or relay rule judges."""

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

RELAY_DEPENDENCY_SHARE: Final[float] = 0.5
"""A node of ours depends on a relay that carried at least this share of its relayed receptions."""

RELAY_CONCENTRATION_SHARE: Final[float] = 0.8
"""One relay carrying at least this share of a node's relayed receptions is a single point of
failure for it."""

ROUTER_MIN_GATEWAYS: Final[int] = 3
"""A router heard by fewer gateways than this may be poorly placed."""

ROUTER_ROLES: Final[frozenset[str]] = frozenset(
    {"ROUTER", "ROUTER_LATE", "ROUTER_CLIENT", "REPEATER"}
)
"""Roles that rebroadcast for everyone."""

IMPORTANCE_HIGH_SCORE: Final[int] = 5
"""An importance score of this or more is ``high``."""

IMPORTANCE_MEDIUM_SCORE: Final[int] = 2
"""An importance score of this or more is ``medium``; below it ``low``."""

_FULL_BATTERY: Final[int] = 100
"""A battery level above this means external power, 0 no reading."""
_GATEWAY_POINTS: Final[int] = 3
_SOLE_GATEWAY_POINTS: Final[int] = 3
_DEPENDENT_POINTS: Final[int] = 2
_ROUTER_POINTS: Final[int] = 1
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
class Importance:
    """How much the rest of our fleet relies on a node.

    Attributes:
        level: ``"high"``, ``"medium"`` or ``"low"``.
        score: The points behind it.
        reasons: Why, for a person.
        uplinked: Our nodes it uplinked as an MQTT gateway.
        sole_gateway_for: Our nodes no other gateway uplinked.
        dependents: Our nodes whose busiest relay is (likely) it.
    """

    level: str
    score: int
    reasons: tuple[str, ...] = ()
    uplinked: tuple[NodeId, ...] = ()
    sole_gateway_for: tuple[NodeId, ...] = ()
    dependents: tuple[NodeId, ...] = ()


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


def _current_battery(metrics: NodeMetrics, context: NodeContext) -> int | None:
    """Return the newest battery percentage that is fresh enough to judge.

    Fresh means not older than :data:`BATTERY_FRESH_SECONDS` or, when
    longer, the node's stale threshold.
    """
    fresh_for = max(BATTERY_FRESH_SECONDS, context.stale_after)
    candidates: list[tuple[float, int]] = []
    if metrics.battery is not None:
        candidates.append((metrics.battery.latest_time, metrics.battery.latest))
    if context.battery is not None and context.battery_time is not None:
        candidates.append((context.battery_time, context.battery))
    fresh = [
        (time, level)
        for time, level in candidates
        if metrics.now - time <= fresh_for and 0 < level <= _FULL_BATTERY
    ]
    return max(fresh)[1] if fresh else None


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
    """Judge the current battery level and its trend."""
    findings = []
    level = _current_battery(metrics, context)
    if level is not None and level <= BATTERY_CRIT_PERCENT:
        findings.append(Finding(Verdict.CRIT, "battery_low", f"battery at {level}%"))
    elif level is not None and level <= BATTERY_WARN_PERCENT:
        findings.append(Finding(Verdict.WARN, "battery_low", f"battery at {level}%"))
    trend = metrics.battery
    if (
        trend is not None
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
    if metrics.gateway_count == 1 and metrics.receptions >= MIN_RECEPTIONS:
        findings.append(
            Finding(
                Verdict.WARN,
                "single_gateway",
                f"uplinked by one gateway only ({metrics.receptions} receptions)",
            )
        )
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


def _gateway_ids(metrics: NodeMetrics) -> frozenset[str]:
    """Return every gateway that uplinked the node."""
    return frozenset(gateway for gateway, _ in metrics.gateways)


def _depends_on(metrics: NodeMetrics, relay: NodeId) -> bool:
    """Tell whether ``relay`` (likely) carried most of a node's relayed receptions."""
    top = metrics.top_relay
    return (
        top is not None
        and metrics.relayed >= MIN_RECEPTIONS
        and top.share >= RELAY_DEPENDENCY_SHARE
        and top.candidates == (relay,)
    )


def rank_importance(
    metrics_by_node: Mapping[NodeId, NodeMetrics], roles: Mapping[NodeId, str | None]
) -> dict[NodeId, Importance]:
    """Score how much the rest of our fleet relies on each node.

    Points: an MQTT gateway (it uplinks itself or one of our nodes, or a
    gateway check saw it uplink anything) 3; per node of ours it is the
    only gateway for (with at least :data:`MIN_RECEPTIONS` receptions) 3;
    per node of ours whose busiest relay byte is unambiguously its own
    and carried at least :data:`RELAY_DEPENDENCY_SHARE` of its relayed
    receptions 2; a router role 1. ``high`` from
    :data:`IMPORTANCE_HIGH_SCORE`, ``medium`` from
    :data:`IMPORTANCE_MEDIUM_SCORE`.

    Args:
        metrics_by_node: Our nodes' metrics (the fleet).
        roles: Our nodes' roles, when known.

    Returns:
        Each node's importance.
    """
    result: dict[NodeId, Importance] = {}
    for node, metrics in metrics_by_node.items():
        others = [(other, m) for other, m in metrics_by_node.items() if other != node]
        uplinked = tuple(other for other, m in others if node.hex in _gateway_ids(m))
        sole = tuple(
            other
            for other, m in others
            if m.receptions >= MIN_RECEPTIONS and _gateway_ids(m) == {node.hex}
        )
        dependents = tuple(other for other, m in others if _depends_on(m, node))
        check = metrics.gateway_check
        gateway = (
            metrics.uplinks_itself or bool(uplinked) or (check is not None and check.nodes > 0)
        )
        router = roles.get(node) in ROUTER_ROLES
        score = (
            _GATEWAY_POINTS * gateway
            + _SOLE_GATEWAY_POINTS * len(sole)
            + _DEPENDENT_POINTS * len(dependents)
            + _ROUTER_POINTS * router
        )
        reasons = [
            text
            for text, applies in (
                ("MQTT gateway", gateway),
                (f"uplinks {len(uplinked)} of our nodes", bool(uplinked)),
                (f"only gateway for {len(sole)} of our nodes", bool(sole)),
                (f"busiest relay of {len(dependents)} of our nodes", bool(dependents)),
                (f"role {roles.get(node)}", router),
            )
            if applies
        ]
        level = (
            "high"
            if score >= IMPORTANCE_HIGH_SCORE
            else "medium"
            if score >= IMPORTANCE_MEDIUM_SCORE
            else "low"
        )
        result[node] = Importance(level, score, tuple(reasons), uplinked, sole, dependents)
    return result


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
        and metrics.gateway_count < ROUTER_MIN_GATEWAYS
    ):
        advice.append(
            Advice(
                "router_placement",
                f"role {context.role}, but only {metrics.gateway_count} gateway(s) uplinked it: "
                "consider whether it is placed well enough to be a router",
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
