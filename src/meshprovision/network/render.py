"""Presentation of a :class:`~meshprovision.network.report.NetworkReport`: text and JSON.

Like :mod:`meshprovision.health.render` this only reads a report; only the
``render_*_console`` functions touch a ``Console``, and they print
:class:`rich.text.Text` objects with markup and highlighting off (a node's
name such as ``[/]`` or ``[link=...]`` stays text). Every text that came from
a data source, the database or a store is passed through
:func:`~meshprovision.termsafe.terminal_safe` (or
:func:`~meshprovision.termsafe.json_dumps_safe`).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

from rich.text import Text

from meshprovision.network.keys import FindingKind, KeyFinding, Severity, short_digest
from meshprovision.status import timefmt
from meshprovision.termsafe import json_dumps_safe, terminal_safe

if TYPE_CHECKING:
    from rich.console import Console

    from meshprovision.network.refresh import NetworkRefresh
    from meshprovision.network.report import NetworkReport, RegionReport

__all__ = [
    "keys_to_json_dict",
    "render_keys_console",
    "render_keys_json",
]

_SEVERITY_STYLES: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "bold red",
    Severity.WARNING: "bold dark_orange",
    Severity.INFO: "",
}
_KIND_LABELS: Final[dict[FindingKind, str]] = {
    FindingKind.OUR_KEY_ELSEWHERE: "our key on another id",
    FindingKind.OUR_ID_OTHER_KEY: "our id, other key",
    FindingKind.WEAK_KEY: "weak key",
    FindingKind.CLONE: "clone",
    FindingKind.HANDOVER: "hand-over",
    FindingKind.MIGRATION: "migration",
    FindingKind.KEY_CHANGED: "key changed",
}
_MAX_NAMED: Final[int] = 8
"""Nodes named in one finding's text; ``--json`` lists all."""

_COVERAGE_NOTE: Final[str] = (
    "Only nodes whose node info travels unencrypted (the default channel) can be seen."
)


def _time(epoch: float | None) -> str:
    """Render an epoch time in local time, ``-`` when unknown."""
    if epoch is None:
        return "-"
    return timefmt.format_local(datetime.fromtimestamp(epoch, tz=UTC), include_zone=False)


def _iso(epoch: float | None) -> str | None:
    """Render an epoch time as ISO-8601 UTC."""
    return None if epoch is None else timefmt.isoformat_z(datetime.fromtimestamp(epoch, tz=UTC))


def _names(report: NetworkReport, region: RegionReport) -> dict[str, str]:
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


def _label(node: str, known: Mapping[str, str]) -> str:
    """Render a node as ``<hex id> <short name>`` (just the id without a name).

    Args:
        node: The hex id.
        known: Hex id -> short name.

    Returns:
        The label.
    """
    name = known.get(node)
    return f"{node} {name}" if name else node


def _data_line(report: NetworkReport, region: RegionReport, what: str) -> Text:
    """Render a view's first line: what, where, the window and how fresh the data is.

    Args:
        report: The report.
        region: The region.
        what: The view's name, for example ``"Key scan"``.

    Returns:
        The line.
    """
    window = "last 24 h" if report.days == 1 else f"last {report.days} days"
    fresh = "no data yet" if region.fetched_at is None else f"data as of {_time(region.fetched_at)}"
    return Text(f"{what}: {terminal_safe(region.region)}, {window} ({fresh})", style="bold")


def _refresh_lines(refresh: NetworkRefresh | None) -> Iterable[Text]:
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


def _refresh_json(refresh: NetworkRefresh | None) -> dict[str, object] | None:
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


def _finding_text(finding: KeyFinding, known: Mapping[str, str]) -> str:
    """Describe one key finding in a sentence."""
    named = [_label(node, known) for node in finding.nodes[:_MAX_NAMED]]
    if len(finding.nodes) > _MAX_NAMED:
        named.append(f"and {len(finding.nodes) - _MAX_NAMED} more")
    listed = ", ".join(named)
    kind = finding.kind
    if kind is FindingKind.OUR_KEY_ELSEWHERE:
        return f"{named[0]}'s database key is advertised by {named[1]}"
    if kind is FindingKind.OUR_ID_OTHER_KEY:
        if finding.severity is Severity.CRITICAL:
            return (
                f"{listed} advertises a key that is not its database key; its id derives "
                "from the database key, so this is another device using its id"
            )
        return (
            f"{listed} advertises a key that is not its database key "
            "(the database is out of date, the node was re-flashed, or it is a spoof)"
        )
    if kind is FindingKind.WEAK_KEY:
        return f"{listed}: {', '.join(finding.checks)}"
    if kind is FindingKind.CLONE:
        return (
            f"{len(finding.nodes)} nodes heard at the same time: {listed}; their direct "
            "messages can be read by each other (CVE-2025-52464)"
        )
    if kind is FindingKind.HANDOVER:
        return (
            f"used by {', then '.join(named)}; the older id was last heard "
            f"{_time(finding.last_heard)} (a restored backup or a re-flashed node)"
        )
    if kind is FindingKind.MIGRATION:
        return f"{' became '.join(named)} (firmware >= 2.8 derives the node id from the key)"
    if finding.severity is Severity.CRITICAL:
        return f"{listed} changed its key; its old key was derived from its id, the new one is not"
    return f"{listed} changed its key"


def _finding_line(finding: KeyFinding, known: Mapping[str, str]) -> Text:
    """Render one key finding as a line."""
    whose = "ours" if finding.fleet else "outsiders"
    line = Text(f"{finding.severity.value.upper():<9}", style=_SEVERITY_STYLES[finding.severity])
    line.append(f" {_KIND_LABELS[finding.kind]} ({whose})  {short_digest(finding.digest)}  ")
    line.append(terminal_safe(_finding_text(finding, known)))
    return line


def _keys_lines(report: NetworkReport, region: RegionReport) -> Iterable[Text]:
    """Render one region's key scan."""
    scan = region.keys
    known = _names(report, region)
    of = f" (of {len(region.nodes)} in lorastats' node list)" if region.nodes else ""
    yield _data_line(report, region, "Key scan")
    yield Text(f"{scan.nodes} node(s) advertised a key{of}. {_COVERAGE_NOTE}")
    ours = sum(1 for finding in scan.findings if finding.fleet)
    yield Text(
        f"Our nodes: {len(scan.fleet_seen)} of {len(report.fleet)} advertised a key; "
        + (f"{ours} finding(s) involve them." if ours else "no finding involves them.")
    )
    for finding in scan.findings:
        yield _finding_line(finding, known)
    if not scan.findings:
        yield Text("No key finding.")
    if scan.derived:
        yield Text(f"Info: {len(scan.derived)} node(s) use a key-derived id (firmware >= 2.8).")


def render_keys_console(report: NetworkReport, *, console: Console) -> None:
    """Print the key scan of every region.

    Args:
        report: The report.
        console: Where to print.
    """
    for index, region in enumerate(report.regions):
        if index:
            console.print()
        for line in _keys_lines(report, region):
            console.print(line, markup=False, highlight=False)
    for line in _refresh_lines(report.refresh):
        console.print(line, markup=False, highlight=False)


def keys_to_json_dict(report: NetworkReport) -> dict[str, object]:
    """Render the key scan as a JSON-serializable mapping.

    Args:
        report: The report.

    Returns:
        ``{"generated_at", "days", "fleet_nodes", "regions": [...], "refresh",
        "exit_code"}``; each finding names its key by its 64-bit digest.
    """
    regions = []
    for region in report.regions:
        scan = region.keys
        regions.append(
            {
                "region": region.region,
                "data_as_of": _iso(region.fetched_at),
                "nodes_with_key": scan.nodes,
                "nodes_listed": len(region.nodes) if region.nodes else None,
                "fleet_seen": list(scan.fleet_seen),
                "derived_ids": list(scan.derived),
                "findings": [
                    {
                        "kind": f.kind.value,
                        "severity": f.severity.value,
                        "key": f.digest,
                        "nodes": list(f.nodes),
                        "fleet": f.fleet,
                        "checks": list(f.checks),
                        "last_heard": _iso(f.last_heard),
                    }
                    for f in scan.findings
                ],
            }
        )
    return {
        "generated_at": _iso(report.generated_at),
        "days": report.days,
        "fleet_nodes": len(report.fleet),
        "regions": regions,
        "refresh": _refresh_json(report.refresh),
        "exit_code": report.exit_code(crypto=report.keys_critical),
    }


def render_keys_json(report: NetworkReport) -> str:
    """Render the key scan as indented, terminal-safe JSON.

    Args:
        report: The report.

    Returns:
        The JSON text.
    """
    return json_dumps_safe(keys_to_json_dict(report), indent=2)
