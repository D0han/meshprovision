"""Presentation of a :class:`~meshprovision.health.report.HealthReport`.

Three forms: the compact table (every node one row), the detailed report
(``mesh health NODE``) and a stable JSON document. Like
:mod:`meshprovision.status.render` this only reads a report; only
:func:`render_console` touches a ``Console``. Every text that came from a
data source or the history is passed through
:func:`~meshprovision.termsafe.terminal_safe` (or
:func:`~meshprovision.termsafe.json_dumps_safe`).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, cast

from rich import box
from rich.console import Console, Group, JustifyMethod, RenderableType
from rich.table import Table
from rich.text import Text

from meshprovision.health.metrics import NodeMetrics, RelayShare
from meshprovision.health.packets import (
    PORT_NEIGHBORINFO,
    PORT_NODEINFO,
    PORT_POSITION,
    PORT_TELEMETRY,
)
from meshprovision.health.refresh import RefreshOutcome
from meshprovision.health.report import HealthReport, NodeHealth, StatusHealth
from meshprovision.health.rules import Verdict
from meshprovision.status import timefmt
from meshprovision.status.merge import humanize_age
from meshprovision.status.render import ExtraColumns, report_to_json_dict
from meshprovision.termsafe import json_dumps_safe, terminal_safe

if TYPE_CHECKING:
    from meshprovision.nodeid import NodeId
    from meshprovision.status.report import StatusReport

__all__ = [
    "VERDICT_STYLES",
    "build_detail",
    "build_table",
    "health_to_json_dict",
    "node_health_to_json_dict",
    "render_console",
    "render_json",
    "status_columns",
    "status_json",
]

VERDICT_STYLES: Final[dict[Verdict, str]] = {
    Verdict.OK: "green",
    Verdict.WARN: "bold dark_orange",
    Verdict.CRIT: "bold red",
    Verdict.UNKNOWN: "grey50",
}
"""``rich`` style of each verdict."""

_IMPORTANCE_STYLES: Final[dict[str, str]] = {"high": "bold", "medium": "", "low": "grey50"}
_DASH: Final[str] = "-"
_POWERED: Final[int] = 100
"""A battery level above this means external power."""
_MAX_REASONS: Final[int] = 2
"""Findings shown per table row; the detailed report and ``--json`` show all."""
_MAX_GATEWAYS: Final[int] = 10
"""Gateways listed in the detailed report; ``--json`` lists all."""
_PORT_NAMES: Final[dict[int, str]] = {
    PORT_TELEMETRY: "telemetry",
    PORT_POSITION: "position",
    PORT_NODEINFO: "nodeinfo",
    PORT_NEIGHBORINFO: "neighbours",
}
_LIMITS: Final[str] = (
    "Limits: receptions are lorastats PacketReports rows (one per packet per MQTT gateway; "
    "MQTT and radio receptions cannot be told apart); hops come only from the packets lorastats "
    "decoded (see 'decoded'); relays are known by their last id byte only; RSSI is lorastats' "
    "raw positive value; rates from decoded packets are lower bounds; lorastats keeps about "
    "a day or two, older hours come from the local history."
)


def _time(value: float | None) -> datetime | None:
    """Return an epoch time as an aware UTC datetime."""
    return None if value is None else datetime.fromtimestamp(value, tz=UTC)


def _ago(value: float | None, now: datetime) -> str:
    """Render how long ago an epoch time was."""
    moment = _time(value)
    return _DASH if moment is None else humanize_age(now - moment)


def _last_heard(health: NodeHealth) -> float | None:
    """Return the newest of the history's last reception and the sources' last seen."""
    seen = health.node.last_seen.timestamp() if health.node.last_seen is not None else None
    times = [t for t in (health.metrics.last_heard, seen) if t is not None]
    return max(times) if times else None


def _percent(value: float | None) -> str:
    """Render a share as a whole percentage."""
    return _DASH if value is None else f"{value:.0%}"


def _number(value: float | None, digits: int = 1) -> str:
    """Render an optional number."""
    return _DASH if value is None else f"{value:.{digits}f}"


def _hops_cell(metrics: NodeMetrics) -> str:
    """Render ``max hops/hop limit`` (``?`` for an unknown part)."""
    if metrics.hops_max is None and metrics.hop_start is None:
        return _DASH
    hops = "?" if metrics.hops_max is None else str(metrics.hops_max)
    limit = "?" if metrics.hop_start is None else str(metrics.hop_start)
    return f"{hops}/{limit}"


def _relay_cell(relay: RelayShare | None) -> str:
    """Render the busiest relay byte and its share."""
    return _DASH if relay is None else f"0x{relay.byte:02x} {relay.share:.0%}"


def _battery(health: NodeHealth) -> str:
    """Render the newest battery reading of the history, else of the sources."""
    trend = health.metrics.battery
    level = trend.latest if trend is not None else health.node.battery_level
    if level is None or level <= 0:
        return _DASH
    return "powered" if level > _POWERED else f"{level}%"


def _name(health: NodeHealth) -> str:
    """Render a node's short name."""
    return terminal_safe(health.node.short_name) if health.node.short_name else _DASH


def build_table(report: HealthReport) -> Table:
    """Build the compact table: one row per node.

    Args:
        report: The report.

    Returns:
        The ``rich`` table, with a caption summing up the run.
    """
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold")
    columns: tuple[tuple[str, JustifyMethod], ...] = (
        ("Node", "left"),
        ("Short", "left"),
        ("Verdict", "left"),
        ("Importance", "left"),
        ("Last heard", "left"),
        *_METRIC_COLUMNS,
        ("Batt", "right"),
        ("Reasons", "left"),
    )
    for column, justify in columns:
        table.add_column(column, justify=justify)
    now = report.generated_at
    for health in report.nodes:
        reasons = "; ".join(f.text for f in health.findings[:_MAX_REASONS])
        if len(health.findings) > _MAX_REASONS:
            reasons += f" (+{len(health.findings) - _MAX_REASONS})"
        table.add_row(
            health.node.node_id.display,
            _name(health),
            Text(health.verdict.value.upper(), style=VERDICT_STYLES[health.verdict]),
            Text(health.importance.level, style=_IMPORTANCE_STYLES[health.importance.level]),
            _ago(_last_heard(health), now),
            *_metric_cells(health.metrics),
            _battery(health),
            terminal_safe(reasons) if reasons else _DASH,
        )
    table.caption = _caption(report)
    return table


def _caption(report: HealthReport) -> Text:
    """Sum up the run below the table."""
    counts = dict.fromkeys(Verdict, 0)
    for health in report.nodes:
        counts[health.verdict] += 1
    text = Text(
        f"{len(report.nodes)} node(s): "
        + ", ".join(f"{counts[verdict]} {verdict.value}" for verdict in Verdict)
        + f"; window {report.days} d"
    )
    if not report.fetched:
        text.append("; history only, nothing fetched")
    elif report.refresh is not None:
        text.append_text(_refresh_summary(report.refresh, report.network_requests))
    for failure in report.source_failures:
        text.append(f"\n{failure.source}: {failure.message}", style="dim red")
    if report.refresh is not None:
        text.append_text(_refresh_problems(report.refresh))
    return text


def _refresh_summary(refresh: RefreshOutcome, requests: int) -> Text:
    """Say how many histories a refresh updated, at what cost, and what it could not ask."""
    text = Text(f"; history refreshed for {len(refresh.refreshed)} node(s), {requests} request(s)")
    if refresh.no_region:
        text.append(f"; {len(refresh.no_region)} node(s) without lorastats data")
    return text


def _refresh_problems(refresh: RefreshOutcome) -> Text:
    """List a refresh's failed nodes and unusable rows, one line each."""
    text = Text()
    for failure in refresh.failures:
        text.append(f"\n{failure.node.display}: {failure.message}", style="dim red")
    if refresh.skipped_rows:
        text.append(
            f"\nlorastats: {refresh.skipped_rows} row(s) could not be used", style="dim yellow"
        )
    return text


_METRIC_COLUMNS: Final[tuple[tuple[str, JustifyMethod], ...]] = (
    ("Pkt/h", "right"),
    ("GWs", "right"),
    ("Direct", "right"),
    ("Hops\nmax/limit", "right"),
    ("SNR\nmedian", "right"),
    ("Top relay", "right"),
)
"""The metric columns shared by the health table and ``mesh status --detail full``."""


def _metric_cells(metrics: NodeMetrics) -> list[str]:
    """Render the cells of :data:`_METRIC_COLUMNS`."""
    return [
        _number(metrics.packets_per_hour),
        str(metrics.gateway_count) if metrics.covered_hours else _DASH,
        _percent(metrics.direct_share),
        _hops_cell(metrics),
        _DASH if metrics.snr_median is None else f"{metrics.snr_median} dB",
        _relay_cell(metrics.top_relay),
    ]


def status_columns(status_health: StatusHealth) -> ExtraColumns:
    """Build the columns ``mesh status --detail full`` appends to its table.

    Args:
        status_health: The reported nodes' health.

    Returns:
        ``Health`` (the verdict) and the metric columns of the health
        table, plus a caption line on the window and the refresh.
    """
    cells: dict[NodeId, Sequence[RenderableType]] = {
        node: (
            Text(health.verdict.value.upper(), style=VERDICT_STYLES[health.verdict]),
            *_metric_cells(health.metrics),
        )
        for node, health in status_health.nodes.items()
    }
    caption = Text(f"health over {status_health.days} d")
    caption.append_text(_refresh_summary(status_health.refresh, status_health.network_requests))
    caption.append_text(_refresh_problems(status_health.refresh))
    return ExtraColumns(
        headers=(("Health", "left"), *_METRIC_COLUMNS), cells=cells, caption=caption
    )


def status_json(report: StatusReport, status_health: StatusHealth) -> str:
    """Render ``mesh status --json --detail full``: the status JSON plus health keys.

    Every key of the plain document is kept, in place and unchanged; each
    node gains ``health`` (see :func:`node_health_to_json_dict`) and the
    document a top-level ``health`` (window, requests, refresh, failures).

    Args:
        report: The status report.
        status_health: The reported nodes' health.

    Returns:
        The JSON text.
    """
    document = report_to_json_dict(report)
    nodes = cast("list[dict[str, object]]", document["nodes"])
    refresh = status_health.refresh
    return json_dumps_safe(
        {
            **document,
            "nodes": [
                {
                    **node_document,
                    "health": node_health_to_json_dict(status_health.nodes[node.node_id]),
                }
                for node_document, node in zip(nodes, report.nodes, strict=True)
            ],
            "health": {
                "days": status_health.days,
                "network_requests": status_health.network_requests,
                "refresh": _refresh_json(refresh),
                "failures": [
                    {"node": f.node.hex, "message": f.message, "hint": f.hint}
                    for f in refresh.failures
                ],
            },
        },
        indent=2,
    )


def _refresh_json(refresh: RefreshOutcome) -> dict[str, object]:
    """Render what a refresh did."""
    return {
        "refreshed": [node.hex for node in refresh.refreshed],
        "no_region": [node.hex for node in refresh.no_region],
        "skipped_rows": refresh.skipped_rows,
    }


def _lines(health: NodeHealth, now: datetime) -> Iterable[str]:
    """Write the detailed report of one node, line by line."""
    node, metrics = health.node, health.metrics
    yield (
        f"{node.node_id.display}  {_name(health)}  {terminal_safe(node.long_name or '')}  "
        f"role {health.role or '?'}  lorastats region {terminal_safe(node.lorastats_region or '?')}"
    )
    yield f"Verdict: {health.verdict.value.upper()}" + "".join(
        f"\n  - {finding.severity.value}: {finding.text}" for finding in health.findings
    )
    yield (
        f"Importance: {health.importance.level} (score {health.importance.score})"
        + "".join(f"\n  - {reason}" for reason in health.importance.reasons)
    )
    yield (
        f"Window: last {metrics.days} d; {metrics.covered_hours} of {metrics.days * 24} hours "
        f"covered, {metrics.silent_hours} silent (longest {metrics.longest_silence_hours} in a "
        f"row); history refreshed {_ago(health.history_fetched_at, now)}"
    )
    yield f"Last heard: {_ago(_last_heard(health), now)}"
    yield (
        f"Traffic: {metrics.packets} packets ({_number(metrics.packets_per_hour)}/h), "
        f"{metrics.receptions} receptions, {_percent(metrics.direct_share)} direct"
    )
    listed = ", ".join(f"{gw} {count}" for gw, count in metrics.gateways[:_MAX_GATEWAYS])
    yield f"Gateways ({metrics.gateway_count}): {listed or _DASH}" + (
        "; it uplinks its own packets (an MQTT gateway)" if metrics.uplinks_itself else ""
    )
    hops = " ".join(f"{hops}:{count}" for hops, count in metrics.hops.items())
    yield (
        f"Hops: {hops or _DASH} ({metrics.hop_samples} receptions of decoded packets, "
        f"{_percent(metrics.decoded_share)} of all); hop limit "
        f"{metrics.hop_start if metrics.hop_start is not None else '?'} "
        f"(HopStart of {metrics.hop_start_samples} decoded packets)"
    )
    yield (
        f"SNR: median {_number(metrics.snr_median, 0)} dB, 10th percentile "
        f"{_number(metrics.snr_low, 0)} dB ({metrics.snr_samples} receptions); "
        f"RSSI (raw lorastats value) mean {_number(metrics.rssi_mean, 0)}"
    )
    relays = ", ".join(_relay_text(relay) for relay in metrics.relays)
    yield f"Relays ({metrics.relayed} relayed receptions): {relays or _DASH}"
    ports = ", ".join(
        f"{_PORT_NAMES.get(port, f'port {port}')} {count}" for port, count in metrics.ports.items()
    )
    yield (
        f"Decoded packets ({metrics.decoded_packets}): {ports or _DASH}; at least "
        f"{_number(metrics.telemetry_per_hour)} telemetry and "
        f"{_number(metrics.positions_per_hour)} position packets an hour"
    )
    yield _battery_line(health, now)
    stats = metrics.latest_local_stats
    if stats is not None:
        yield (
            f"Local stats ({_ago(stats.time, now)}): {stats.rx} rx, {stats.tx} tx, "
            f"{stats.relayed} relayed since boot"
        )
    if metrics.boots:
        boots = ", ".join(
            timefmt.format_local(datetime.fromtimestamp(boot, tz=UTC)) for boot in metrics.boots
        )
        yield f"Boots in the window: {boots}"
    if metrics.neighbors:
        yield "Neighbours: " + ", ".join(
            f"!{neighbor} ({_ago(seen, now)})" for neighbor, seen in metrics.neighbors
        )
    check = metrics.gateway_check
    if check is not None:
        yield (
            f"As a gateway ({_ago(check.time, now)}): uplinked {check.receptions} reports from "
            f"{check.nodes} node(s) in the {check.window_seconds / 60:.0f} minutes before"
        )
    if health.advice:
        yield "Suggestions:" + "".join(f"\n  - {advice.text}" for advice in health.advice)


def _relay_text(relay: RelayShare) -> str:
    """Render one relay byte, its share and its likely node."""
    likely = f" (likely {relay.candidates[0].display})" if len(relay.candidates) == 1 else ""
    return f"0x{relay.byte:02x} {relay.share:.0%}{likely}"


def _battery_line(health: NodeHealth, now: datetime) -> str:
    """Render the battery and utilization readings."""
    metrics = health.metrics
    trend = metrics.battery
    if trend is None:
        battery = f"{_battery(health)} (from mesh status)"
    else:
        slope = (
            "no trend yet"
            if trend.slope_per_day is None
            else f"{trend.slope_per_day:+.1f} points a day"
        )
        battery = (
            f"{trend.latest}% ({_ago(trend.latest_time, now)}), {slope} over "
            f"{trend.points} readings"
        )
    return (
        f"Battery: {battery}; channel utilization {_number(metrics.channel_utilization)}%, "
        f"transmit air utilization {_number(metrics.air_util_tx, 2)}%"
    )


def build_detail(report: HealthReport) -> Group:
    """Build the detailed report: every node in full.

    Args:
        report: The report.

    Returns:
        The ``rich`` renderable.
    """
    parts: list[Text] = []
    for health in report.nodes:
        text = Text(
            terminal_safe("\n".join(_lines(health, report.generated_at)), allow_newlines=True)
        )
        parts.extend((text, Text("")))
    parts.append(_caption(report))
    parts.append(Text(_LIMITS, style="dim"))
    return Group(*parts)


def render_console(report: HealthReport, *, console: Console, detail: bool) -> None:
    """Print the table, or the detailed report.

    Args:
        report: The report.
        console: Where to print it.
        detail: The detailed report instead of the table.
    """
    renderable = build_detail(report) if detail else build_table(report)
    console.print(renderable, markup=False, highlight=False)


def _iso(value: float | None) -> str | None:
    """Render an epoch time as UTC ISO 8601 with a ``Z``."""
    return timefmt.isoformat_z(_time(value))


def node_health_to_json_dict(health: NodeHealth) -> dict[str, object]:
    """Render one node's health as a stable JSON-able mapping.

    Args:
        health: The node's health.

    Returns:
        ``verdict``, ``findings``, ``importance``, ``suggestions`` and
        ``metrics``, with insertion-ordered keys.
    """
    metrics = health.metrics
    trend = metrics.battery
    check = metrics.gateway_check
    return {
        "verdict": health.verdict.value,
        "findings": [
            {"severity": f.severity.value, "code": f.code, "text": f.text} for f in health.findings
        ],
        "importance": {
            "level": health.importance.level,
            "score": health.importance.score,
            "reasons": list(health.importance.reasons),
            "uplinked": [node.hex for node in health.importance.uplinked],
            "sole_gateway_for": [node.hex for node in health.importance.sole_gateway_for],
            "dependents": [node.hex for node in health.importance.dependents],
        },
        "suggestions": [{"code": a.code, "text": a.text} for a in health.advice],
        "role": health.role,
        "history_fetched_at": _iso(health.history_fetched_at),
        "metrics": {
            "days": metrics.days,
            "window_start": _iso(metrics.window_start),
            "covered_hours": metrics.covered_hours,
            "silent_hours": metrics.silent_hours,
            "longest_silence_hours": metrics.longest_silence_hours,
            "last_heard": _iso(metrics.last_heard),
            "receptions": metrics.receptions,
            "packets": metrics.packets,
            "packets_per_hour": metrics.packets_per_hour,
            "direct": metrics.direct,
            "direct_share": metrics.direct_share,
            "gateway_count": metrics.gateway_count,
            "gateways": [{"gateway": gw, "receptions": count} for gw, count in metrics.gateways],
            "uplinks_itself": metrics.uplinks_itself,
            "hops": {str(hops): count for hops, count in metrics.hops.items()},
            "hop_samples": metrics.hop_samples,
            "decoded_share": metrics.decoded_share,
            "hops_max": metrics.hops_max,
            "hop_start": metrics.hop_start,
            "hop_start_samples": metrics.hop_start_samples,
            "snr_median": metrics.snr_median,
            "snr_low": metrics.snr_low,
            "snr_samples": metrics.snr_samples,
            "rssi_mean_raw": metrics.rssi_mean,
            "relayed": metrics.relayed,
            "relays": [
                {
                    "byte": relay.byte,
                    "receptions": relay.receptions,
                    "share": relay.share,
                    "candidates": [node.hex for node in relay.candidates],
                }
                for relay in metrics.relays
            ],
            "ports": {str(port): count for port, count in metrics.ports.items()},
            "decoded_packets": metrics.decoded_packets,
            "telemetry_per_hour": metrics.telemetry_per_hour,
            "positions_per_hour": metrics.positions_per_hour,
            "battery": None
            if trend is None
            else {
                "latest": trend.latest,
                "time": _iso(trend.latest_time),
                "points": trend.points,
                "span_hours": trend.span_hours,
                "slope_per_day": trend.slope_per_day,
            },
            "channel_utilization": metrics.channel_utilization,
            "air_util_tx": metrics.air_util_tx,
            "boots": [_iso(boot) for boot in metrics.boots],
            "neighbors": [
                {"node": neighbor, "last_reported": _iso(seen)}
                for neighbor, seen in metrics.neighbors
            ],
            "gateway_check": None
            if check is None
            else {
                "time": _iso(check.time),
                "window_seconds": check.window_seconds,
                "receptions": check.receptions,
                "nodes": check.nodes,
            },
        },
    }


def health_to_json_dict(report: HealthReport) -> dict[str, object]:
    """Render a health report as its stable JSON-able shape.

    Args:
        report: The report.

    Returns:
        ``generated_at``, ``days``, ``fetched``, ``network_requests``,
        ``failures``, ``refresh`` and ``nodes`` (each node's identity plus
        :func:`node_health_to_json_dict`), with insertion-ordered keys.
    """
    refresh = report.refresh
    return {
        "generated_at": timefmt.isoformat_z(report.generated_at),
        "days": report.days,
        "fetched": report.fetched,
        "network_requests": report.network_requests,
        "failures": [
            {"source": f.source, "node": None, "message": f.message, "hint": f.hint}
            for f in report.source_failures
        ]
        + [
            {"source": "lorastats", "node": f.node.hex, "message": f.message, "hint": f.hint}
            for f in report.refresh_failures
        ],
        "refresh": None if refresh is None else _refresh_json(refresh),
        "nodes": [
            {
                "node_id": health.node.node_id.hex,
                "display": health.node.node_id.display,
                "short_name": health.node.short_name,
                "long_name": health.node.long_name,
                "lorastats_region": health.node.lorastats_region,
                **node_health_to_json_dict(health),
            }
            for health in report.nodes
        ],
    }


def render_json(report: HealthReport) -> str:
    """Render a health report as indented, terminal-safe JSON.

    Args:
        report: The report.

    Returns:
        The JSON text.
    """
    return json_dumps_safe(health_to_json_dict(report), indent=2)
