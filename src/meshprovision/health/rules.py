"""Verdicts, importance and configuration suggestions from health metrics. Pure.

Every rule is a named threshold below, documented with its reason in
``docs/commands.md`` (``mesh health``), and tested at its boundaries.
They are heuristics for a mesh operator, not firmware limits:

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

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from meshprovision.health.metrics import NodeMetrics
from meshprovision.nodeid import NodeId

__all__ = [
    "AIR_UTIL_TX_CRIT_PERCENT",
    "AIR_UTIL_TX_WARN_PERCENT",
    "BATTERY_CRIT_PERCENT",
    "BATTERY_DRAIN_WARN_PER_DAY",
    "BATTERY_FRESH_SECONDS",
    "BATTERY_WARN_PERCENT",
    "CHANNEL_UTILIZATION_CRIT_PERCENT",
    "CHANNEL_UTILIZATION_WARN_PERCENT",
    "CHATTY_PER_HOUR",
    "DEFAULT_HOP_LIMIT",
    "HOP_ADVICE_MIN_SAMPLES",
    "IMPORTANCE_HIGH_SCORE",
    "IMPORTANCE_MEDIUM_SCORE",
    "MIN_RECEPTIONS",
    "REBOOTS_WARN",
    "RELAY_CONCENTRATION_SHARE",
    "RELAY_DEPENDENCY_SHARE",
    "ROUTER_MIN_GATEWAYS",
    "ROUTER_ROLES",
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
    "rank_importance",
]

SILENT_WARN_SECONDS: Final[float] = 2 * 3600.0
"""Not heard for longer than this (``mesh status``'s stale threshold): warn."""

SILENT_CRIT_SECONDS: Final[float] = 24 * 3600.0
"""Not heard for longer than this (``mesh status``'s offline threshold): critical."""

BATTERY_WARN_PERCENT: Final[int] = 20
"""A current battery reading at or below this: warn (as ``mesh status`` colours it)."""

BATTERY_CRIT_PERCENT: Final[int] = 10
"""A current battery reading at or below this: critical."""

BATTERY_FRESH_SECONDS: Final[float] = 24 * 3600.0
"""A battery reading older than this is not judged."""

BATTERY_DRAIN_WARN_PER_DAY: Final[float] = -10.0
"""A battery trend at or below this many percentage points a day: warn."""

MIN_RECEPTIONS: Final[int] = 20
"""Fewest receptions (or relayed receptions) a gateway or relay rule judges."""

REBOOTS_WARN: Final[int] = 3
"""This many boots in the window or more: warn."""

CHANNEL_UTILIZATION_WARN_PERCENT: Final[float] = 25.0
"""Mean channel utilization above this: warn (firmware starts delaying sends)."""

CHANNEL_UTILIZATION_CRIT_PERCENT: Final[float] = 40.0
"""Mean channel utilization above this: critical."""

AIR_UTIL_TX_WARN_PERCENT: Final[float] = 5.0
"""Mean transmit air utilization above this: warn."""

AIR_UTIL_TX_CRIT_PERCENT: Final[float] = 10.0
"""Mean transmit air utilization above this (the common duty-cycle limit): critical."""

SILENCE_WARN_HOURS: Final[int] = 6
"""This many consecutive covered hours without a reception, or more: warn."""

DEFAULT_HOP_LIMIT: Final[int] = 3
"""Meshtastic's default hop limit; never suggest less."""

HOP_ADVICE_MIN_SAMPLES: Final[int] = 20
"""Fewest receptions with a hop count before a hop limit is suggested."""

CHATTY_PER_HOUR: Final[float] = 2.0
"""More telemetry or position packets an hour than this is suggested to be reduced."""

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
    """

    role: str | None = None
    last_seen: float | None = None
    battery: int | None = None
    battery_time: float | None = None


def _duration(seconds: float) -> str:
    """Render a duration as hours below two days, else days."""
    hours = seconds / _SECONDS_PER_HOUR
    if hours < 2 * _HOURS_PER_DAY:
        return f"{hours:.0f} h"
    return f"{hours / _HOURS_PER_DAY:.0f} d"


def _current_battery(metrics: NodeMetrics, context: NodeContext) -> int | None:
    """Return the newest battery percentage not older than :data:`BATTERY_FRESH_SECONDS`."""
    candidates: list[tuple[float, int]] = []
    if metrics.battery is not None:
        candidates.append((metrics.battery.latest_time, metrics.battery.latest))
    if context.battery is not None and context.battery_time is not None:
        candidates.append((context.battery_time, context.battery))
    fresh = [
        (time, level)
        for time, level in candidates
        if metrics.now - time <= BATTERY_FRESH_SECONDS and 0 < level <= _FULL_BATTERY
    ]
    return max(fresh)[1] if fresh else None


def _silence(metrics: NodeMetrics, context: NodeContext) -> Finding | None:
    """Judge how long ago the node was last heard."""
    heard = [t for t in (metrics.last_heard, context.last_seen) if t is not None]
    if not heard:
        if metrics.covered_hours:
            return Finding(Verdict.CRIT, "never_heard", "lorastats never heard it")
        return Finding(Verdict.UNKNOWN, "no_data", "no lorastats data and no last-seen time")
    age = metrics.now - max(heard)
    if age > SILENT_CRIT_SECONDS:
        return Finding(Verdict.CRIT, "silent", f"not heard for {_duration(age)}")
    if age > SILENT_WARN_SECONDS:
        return Finding(Verdict.WARN, "silent", f"not heard for {_duration(age)}")
    return None


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
    if len(metrics.boots) >= REBOOTS_WARN:
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
    if metrics.longest_silence_hours >= SILENCE_WARN_HOURS:
        findings.append(
            Finding(
                Verdict.WARN,
                "silent_hours",
                f"{metrics.longest_silence_hours} hours in a row without a reception",
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
    busy = (metrics.channel_utilization or 0.0) > CHANNEL_UTILIZATION_WARN_PERCENT
    if busy and (metrics.telemetry_per_hour or 0.0) > CHATTY_PER_HOUR:
        advice.append(
            Advice(
                "telemetry_interval",
                f"at least {metrics.telemetry_per_hour:.1f} telemetry packets an hour on a busy "
                "channel: consider a longer telemetry interval",
            )
        )
    if (metrics.positions_per_hour or 0.0) > CHATTY_PER_HOUR:
        advice.append(
            Advice(
                "position_interval",
                f"at least {metrics.positions_per_hour:.1f} position packets an hour: consider a "
                "longer position interval or smart position",
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
