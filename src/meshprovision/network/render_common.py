"""Shared pieces of the ``mesh network`` views' text and JSON.

Node labels, times, the first line of a region's view, the refresh's
problems and the proxy caveat. Every text that came from a data source,
the database or a store is passed through
:func:`~meshprovision.termsafe.terminal_safe`; the views print
:class:`rich.text.Text` objects, never markup.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

from rich.text import Text

from meshprovision.status import timefmt
from meshprovision.termsafe import terminal_safe

if TYPE_CHECKING:
    from meshprovision.network.refresh import NetworkRefresh
    from meshprovision.network.report import NetworkReport, RegionReport
    from meshprovision.network.resolve import Resolution

__all__ = [
    "MAX_NAMED",
    "PROXY_CAVEAT",
    "confidence_text",
    "data_line",
    "iso",
    "label",
    "names",
    "percent",
    "refresh_json",
    "refresh_lines",
    "text_cell",
    "time_text",
]

MAX_NAMED: Final[int] = 8
"""Nodes named in one finding's text; ``--json`` lists all."""


def time_text(epoch: float | None) -> str:
    """Render an epoch time in local time, ``-`` when unknown.

    Args:
        epoch: Unix epoch seconds, or ``None``.

    Returns:
        For example ``"2026-10-31 23:26:00"``.
    """
    if epoch is None:
        return "-"
    return timefmt.format_local(datetime.fromtimestamp(epoch, tz=UTC), include_zone=False)


def iso(epoch: float | None) -> str | None:
    """Render an epoch time as ISO-8601 UTC.

    Args:
        epoch: Unix epoch seconds, or ``None``.

    Returns:
        For example ``"2026-10-31T22:26:00Z"``, or ``None``.
    """
    return None if epoch is None else timefmt.isoformat_z(datetime.fromtimestamp(epoch, tz=UTC))


def names(report: NetworkReport, region: RegionReport) -> dict[str, str]:
    """Build the short name of every node a region's view knows one for.

    Our database's names win over a node's own node info, which wins over
    lorastats' node list.

    Args:
        report: The report.
        region: The region.

    Returns:
        Hex id -> terminal-safe short name.
    """
    found = {
        node.node_id.hex: terminal_safe(node.short_name) for node in region.nodes if node.short_name
    }
    found.update({entry.node: entry.short_name for entry in region.keys.seen if entry.short_name})
    found.update({member.node: member.short_name for member in report.fleet if member.short_name})
    return found


def label(node: str, known: Mapping[str, str]) -> str:
    """Render a node as ``<hex id> <short name>`` (just the id without a name).

    Args:
        node: The hex id.
        known: Hex id -> short name.

    Returns:
        The label.
    """
    name = known.get(node)
    return f"{node} {name}" if name else node


def data_line(report: NetworkReport, region: RegionReport, what: str) -> Text:
    """Render a view's first line: what, where, the window and how fresh the data is.

    Args:
        report: The report.
        region: The region.
        what: The view's name, for example ``"Key scan"``.

    Returns:
        The line.
    """
    window = "last 24 h" if report.days == 1 else f"last {report.days} days"
    fresh = (
        "no data yet" if region.fetched_at is None else f"data as of {time_text(region.fetched_at)}"
    )
    return Text(f"{what}: {terminal_safe(region.region)}, {window} ({fresh})", style="bold")


def refresh_lines(refresh: NetworkRefresh | None) -> Iterable[Text]:
    """Render what a refresh could not do, one line each.

    Args:
        refresh: The refresh, or ``None`` without fetching.

    Yields:
        One line per failure, and one for unusable rows.
    """
    if refresh is None:
        yield Text("Nothing fetched (--no-fetch): stored data only.", style="dim")
        return
    for failure in refresh.failures:
        text = f"{terminal_safe(failure.region)}: {terminal_safe(failure.message)}"
        yield Text(text, style="dim red")
    if refresh.skipped_rows:
        yield Text(
            f"lorastats: {refresh.skipped_rows} row(s) could not be used", style="dim yellow"
        )


def refresh_json(refresh: NetworkRefresh | None) -> dict[str, object] | None:
    """Render what a refresh did as JSON.

    Args:
        refresh: The refresh, or ``None`` without fetching.

    Returns:
        ``{"refreshed", "failures", "skipped_rows"}``, or ``None``.
    """
    if refresh is None:
        return None
    return {
        "refreshed": list(refresh.refreshed),
        "failures": [
            {"region": f.region, "message": f.message, "hint": f.hint} for f in refresh.failures
        ],
        "skipped_rows": refresh.skipped_rows,
    }


PROXY_CAVEAT: Final[str] = (
    "Shares are of receptions at gateways, by last hop. Meshtastic floods: when a relay is "
    "gone, another node usually rebroadcasts instead. These numbers show who carries "
    "traffic now, not what breaks without it."
)


def percent(share: float | None) -> str:
    """Render a share as a percentage, ``-`` when unknown.

    Args:
        share: A share, ``0..1``, or ``None``.

    Returns:
        For example ``"16.0%"``.
    """
    return "-" if share is None else f"{100 * share:.1f}%"


def confidence_text(resolution: Resolution) -> str:
    """Render a resolution's label, with the date of a learned one.

    Args:
        resolution: A relay byte's resolution.

    Returns:
        For example ``"high"`` or ``"medium (learned 2026-10-30 12:00:00)"``.
    """
    if resolution.learned_at is not None:
        return f"{resolution.confidence.value} (learned {time_text(resolution.learned_at)})"
    return resolution.confidence.value


def text_cell(value: str) -> Text:
    """Make a table cell plain, terminal-safe text: never rich markup (a name may be ``[/]``).

    Args:
        value: The cell's text.

    Returns:
        The cell.
    """
    return Text(terminal_safe(value))
