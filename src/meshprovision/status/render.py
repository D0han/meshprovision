"""Presentation for a :class:`~meshprovision.status.report.StatusReport`.

Two output forms, and nothing else: a ``rich`` terminal table
(:func:`build_table`, :func:`render_console`) and a stable JSON
serialization (:func:`report_to_json_dict`, :func:`render_json`). This
module imports nothing that can write anything -- it only ever reads a
:class:`~meshprovision.status.report.StatusReport` and either builds a
``rich`` renderable or returns a string.

:func:`render_console` is the only function in this module permitted to
touch a ``Console`` -- so that ``mesh status --json`` can call
:func:`render_json` and ``click.echo`` the result with nothing else ever
written to stdout.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Final

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from meshprovision.status.merge import Availability
from meshprovision.status.report import StatusReport

__all__ = [
    "AVAILABILITY_LABELS",
    "AVAILABILITY_STYLES",
    "build_table",
    "render_console",
    "render_json",
    "report_to_json_dict",
]

AVAILABILITY_STYLES: Final[MappingProxyType[Availability, str]] = MappingProxyType(
    {
        Availability.ONLINE: "green",
        Availability.STALE: "yellow",
        Availability.OFFLINE: "red",
        Availability.UNKNOWN: "dim",
    }
)
"""``rich`` style name applied to a node's table row, by availability."""

AVAILABILITY_LABELS: Final[MappingProxyType[Availability, str]] = MappingProxyType(
    {
        Availability.ONLINE: "online",
        Availability.STALE: "stale",
        Availability.OFFLINE: "offline",
        Availability.UNKNOWN: "unknown",
    }
)
"""Display label for the ``Status`` column, by availability."""

_DASH: Final[str] = "-"


def _text_cell(value: str | None) -> str:
    """Render an optional string cell, never as the literal ``"None"``.

    Args:
        value: The cell's value, or ``None``/blank.

    Returns:
        ``value`` when truthy; otherwise :data:`_DASH`.
    """
    return value if value else _DASH


def _int_cell(value: int | None) -> str:
    """Render an optional integer cell.

    Args:
        value: The cell's value, or ``None``.

    Returns:
        ``str(value)``, or :data:`_DASH` when ``value`` is ``None``.
    """
    return _DASH if value is None else str(value)


def _battery_cell(value: int | None) -> str:
    """Render an optional battery-percentage cell.

    Args:
        value: The battery level percentage, or ``None``.

    Returns:
        ``f"{value}%"``, or :data:`_DASH` when ``value`` is ``None``.
    """
    return _DASH if value is None else f"{value}%"


def _voltage_cell(value: float | None) -> str:
    """Render an optional voltage cell.

    Args:
        value: The voltage, or ``None``.

    Returns:
        ``f"{value:.2f}V"``, or :data:`_DASH` when ``value`` is ``None``.
    """
    return _DASH if value is None else f"{value:.2f}V"


def _percent_cell(value: float | None) -> str:
    """Render an optional one-decimal percentage cell.

    Args:
        value: The percentage, or ``None``.

    Returns:
        ``f"{value:.1f}%"``, or :data:`_DASH` when ``value`` is ``None``.
    """
    return _DASH if value is None else f"{value:.1f}%"


def _timestamp_cell(value: datetime | None) -> str:
    """Render an optional timestamp cell as ISO-8601 with a ``Z`` suffix.

    Args:
        value: The timestamp, or ``None``.

    Returns:
        For example ``"2026-08-25T03:14:10Z"``, or :data:`_DASH` when
        ``value`` is ``None``.
    """
    if value is None:
        return _DASH
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _sources_cell(sources: tuple[str, ...]) -> str:
    """Render a node's contributing sources cell.

    Args:
        sources: The node's :attr:`~meshprovision.status.merge.MergedNode.sources`.

    Returns:
        ``"+".join(sources)``, or :data:`_DASH` when ``sources`` is empty.
    """
    return "+".join(sources) if sources else _DASH


def build_table(report: StatusReport) -> Table:
    """Build the ``rich`` table rendering of a status report.

    Every ``None`` field renders as a single dim hyphen, never the
    literal ``"None"``. Numeric columns are right-justified. Each row's
    style comes from :data:`AVAILABILITY_STYLES`, keyed by the node's
    availability. A caption is attached below the table:
    :meth:`~meshprovision.status.report.StatusReport.summary`, plus --
    when the report has any source failures -- one dim red line per
    failure. A database with zero nodes renders a header-only table with
    a single ``"No nodes in the database"`` caption instead.

    Args:
        report: The report to render.

    Returns:
        The built, not-yet-printed ``rich`` table.
    """
    table = Table(title=None, box=box.SIMPLE_HEAVY, header_style="bold")
    table.add_column("Node")
    table.add_column("Short")
    table.add_column("Long")
    table.add_column("Mgmt")
    table.add_column("Status")
    table.add_column("Last seen")
    table.add_column("Timestamp")
    table.add_column("Batt", justify="right")
    table.add_column("Volt", justify="right")
    table.add_column("ChUtil", justify="right")
    table.add_column("AirTx", justify="right")
    table.add_column("Nbrs", justify="right")
    table.add_column("Sources")

    if not report.nodes:
        table.caption = "No nodes in the database"
        return table

    for node in report.nodes:
        table.add_row(
            node.node_id.display,
            _text_cell(node.short_name),
            _text_cell(node.long_name),
            _text_cell(node.management),
            AVAILABILITY_LABELS[node.availability],
            node.age_text,
            _timestamp_cell(node.last_seen),
            _battery_cell(node.battery_level),
            _voltage_cell(node.voltage),
            _percent_cell(node.channel_utilization),
            _percent_cell(node.air_util_tx),
            _int_cell(node.neighbor_count),
            _sources_cell(node.sources),
            style=AVAILABILITY_STYLES[node.availability],
        )

    caption = Text(report.summary())
    for failure in report.failures:
        caption.append("\n")
        caption.append(f"{failure.source}: {failure.message}", style="dim red")
    table.caption = caption
    return table


def render_console(
    report: StatusReport, *, console: Console | None = None, show_summary: bool = True
) -> None:
    """Print a status report's table (and optional summary caption) to a console.

    The only function in this module permitted to touch a ``Console``.

    Args:
        report: The report to render.
        console: The ``rich`` console to print to. Defaults to a new
            :class:`~rich.console.Console`.
        show_summary: Whether to include the summary/failures caption
            below the table.
    """
    active_console = console if console is not None else Console()
    table = build_table(report)
    if not show_summary:
        table.caption = None
    active_console.print(table)


def report_to_json_dict(report: StatusReport) -> dict[str, object]:
    """Render a status report to its stable, diffable JSON-able shape.

    Key order is fixed and insertion-ordered (never ``sort_keys``), so
    successive runs against unchanged data produce byte-identical output.
    Never emits ``ble_pin``, key material, or a ``key_ref`` -- each
    node's ``record`` is never serialized wholesale (see
    :meth:`~meshprovision.status.merge.MergedNode.to_json_dict`).

    Args:
        report: The report to render.

    Returns:
        A mapping shaped as::

            {
                "generated_at": "2026-08-25T03:14:10Z",
                "thresholds": {"stale_after_seconds": 7200, "offline_after_seconds": 86400},
                "counts": {"online": 3, "stale": 1, "offline": 0, "unknown": 2},
                "cache": {"hits": 2, "misses": 1, "network_requests": 1},
                "failures": [{"source": "lorastats", "message": "...", "hint": None}],
                "nodes": [...],
            }
    """
    counts = report.counts
    generated_at = report.generated_at.astimezone(UTC).isoformat(timespec="seconds")
    return {
        "generated_at": generated_at.replace("+00:00", "Z"),
        "thresholds": {
            "stale_after_seconds": int(report.thresholds.stale_after.total_seconds()),
            "offline_after_seconds": int(report.thresholds.offline_after.total_seconds()),
        },
        "counts": {availability.value: counts[availability] for availability in Availability},
        "cache": {
            "hits": report.cache_hits,
            "misses": report.cache_misses,
            "network_requests": report.network_requests,
        },
        "failures": [
            {"source": failure.source, "message": failure.message, "hint": failure.hint}
            for failure in report.failures
        ],
        "nodes": [node.to_json_dict() for node in report.nodes],
    }


def render_json(report: StatusReport, *, indent: int = 2) -> str:
    """Render a status report as a stable, indented JSON string.

    Args:
        report: The report to render.
        indent: ``json.dumps`` indent level.

    Returns:
        ``json.dumps(report_to_json_dict(report), indent=indent, ensure_ascii=False)``,
        with insertion-ordered (never sorted) keys.
    """
    return json.dumps(report_to_json_dict(report), indent=indent, ensure_ascii=False)
