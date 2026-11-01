"""Presentation of the ``mesh network keys`` and ``relays`` views: text and JSON.

Like :mod:`meshprovision.health.render` this only reads a report; only the
``render_*_console`` functions touch a ``Console``, and they print
:class:`rich.text.Text` objects with markup and highlighting off (a node's
name such as ``[/]`` or ``[link=...]`` stays text). Every text that came from
a data source, the database or a store is passed through
:func:`~meshprovision.termsafe.terminal_safe` (or
:func:`~meshprovision.termsafe.json_dumps_safe`). The shared pieces are in
:mod:`meshprovision.network.render_common`, ``impact`` is in
:mod:`meshprovision.network.render_impact`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING, Final

from rich import box
from rich.console import JustifyMethod, RenderableType
from rich.table import Table
from rich.text import Text

from meshprovision.network.keys import FindingKind, KeyFinding, Severity, short_digest
from meshprovision.network.relays import RelayRow, RelayTable, byte_label, relay_table
from meshprovision.network.render_common import (
    MAX_NAMED,
    PROXY_CAVEAT,
    confidence_text,
    data_line,
    iso,
    label,
    names,
    percent,
    refresh_json,
    refresh_lines,
    text_cell,
    time_text,
)
from meshprovision.termsafe import json_dumps_safe, terminal_safe

if TYPE_CHECKING:
    from rich.console import Console

    from meshprovision.network.report import NetworkReport, RegionReport

__all__ = [
    "keys_to_json_dict",
    "relays_of",
    "relays_to_json_dict",
    "render_keys_console",
    "render_keys_json",
    "render_relays_console",
    "render_relays_json",
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
_COVERAGE_NOTE: Final[str] = (
    "Only nodes whose node info travels unencrypted (the default channel) can be seen."
)


def _finding_text(finding: KeyFinding, known: Mapping[str, str]) -> str:
    """Describe one key finding in a sentence."""
    named = [label(node, known) for node in finding.nodes[:MAX_NAMED]]
    if len(finding.nodes) > MAX_NAMED:
        named.append(f"and {len(finding.nodes) - MAX_NAMED} more")
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
            f"{time_text(finding.last_heard)} (a restored backup or a re-flashed node)"
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
    known = names(report, region)
    of = f" (of {len(region.nodes)} in lorastats' node list)" if region.nodes else ""
    yield data_line(report, region, "Key scan")
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
    for line in refresh_lines(report.refresh):
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
                "data_as_of": iso(region.fetched_at),
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
                        "last_heard": iso(f.last_heard),
                    }
                    for f in scan.findings
                ],
            }
        )
    return {
        "generated_at": iso(report.generated_at),
        "days": report.days,
        "fleet_nodes": len(report.fleet),
        "regions": regions,
        "refresh": refresh_json(report.refresh),
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


def _relay_name(row: RelayRow, known: Mapping[str, str]) -> tuple[str, str]:
    """Render a row's relay and name cells (an unattributed byte names its candidates)."""
    resolution = row.resolution
    node = resolution.node
    if node is not None:
        return node, known.get(node, "")
    candidates = ", ".join(score.node for score in resolution.candidates)
    return byte_label(resolution.byte), f"{resolution.confidence.value} ({candidates})"


def _relay_table(table: RelayTable, known: Mapping[str, str], limit: int) -> Table:
    """Build the relays table."""
    grid = Table(box=box.SIMPLE_HEAVY, header_style="bold")
    columns: tuple[tuple[str, JustifyMethod], ...] = (
        ("Relay", "left"),
        ("Name", "left"),
        ("Role", "left"),
        ("Conf", "left"),
        ("Ours via", "right"),
        ("Our nodes", "right"),
        ("Sole 1st hop", "left"),
        ("Region", "right"),
        ("Gateways>=50%", "right"),
        ("Last seen", "left"),
        ("Notes", "left"),
    )
    for column, justify in columns:
        grid.add_column(column, justify=justify)
    for row in table.rows[:limit]:
        relay, name = _relay_name(row, known)
        cells = (
            relay,
            name or "-",
            row.role or "-",
            confidence_text(row.resolution),
            percent(row.our_share) if row.our_receptions else "-",
            str(len(row.our_origins)),
            ", ".join(label(node, known) for node in row.our_sole_first_hop) or "-",
            percent(row.region_share),
            f"{row.gateways_relying} (max {percent(row.max_gateway_share)})",
            time_text(row.last_seen),
            "; ".join(row.gaps) or "-",
        )
        grid.add_row(*(text_cell(cell) for cell in cells))
    return grid


def _relays_lines(
    report: NetworkReport, region: RegionReport, *, everything: bool, limit: int
) -> Iterable[RenderableType]:
    """Render one region's relay table."""
    table = relays_of(report, region, everything=everything)
    known = names(report, region)
    what = (
        "Relays by share of relayed traffic" if everything else "Relays we depend on but don't own"
    )
    yield data_line(report, region, what)
    yield Text(
        f"{table.our_packets} of our packets, {table.our_relayed} of their receptions relayed; "
        f"{table.relayed} relayed receptions in the region"
    )
    if not table.rows:
        yield Text("No relay carried any of our packets." if not everything else "No relay.")
        return
    yield _relay_table(table, known, limit)
    if len(table.rows) > limit:
        yield Text(f"{len(table.rows) - limit} more (--limit).", style="dim")


def relays_of(report: NetworkReport, region: RegionReport, *, everything: bool) -> RelayTable:
    """Build a region's relay table from a report.

    Args:
        report: The report.
        region: The region.
        everything: Every relay not ours (``--all``), else those carrying ours.

    Returns:
        The table.
    """
    return relay_table(
        region.traffic,
        region.resolutions,
        [member.node for member in report.fleet],
        nodes=region.nodes,
        keys=region.keys.seen,
        everything=everything,
    )


def render_relays_console(
    report: NetworkReport, *, console: Console, everything: bool, limit: int
) -> None:
    """Print the relay table of every region.

    Args:
        report: The report.
        console: Where to print.
        everything: Every relay not ours (``--all``).
        limit: The most rows per region.
    """
    for index, region in enumerate(report.regions):
        if index:
            console.print()
        for item in _relays_lines(report, region, everything=everything, limit=limit):
            console.print(item, markup=False, highlight=False)
    console.print(Text(PROXY_CAVEAT, style="dim"), markup=False, highlight=False)
    for line in refresh_lines(report.refresh):
        console.print(line, markup=False, highlight=False)


def _row_json(row: RelayRow) -> dict[str, object]:
    """Render one relay row as JSON."""
    resolution = row.resolution
    return {
        "byte": resolution.byte,
        "node": resolution.node,
        "confidence": resolution.confidence.value,
        "learned_at": iso(resolution.learned_at),
        "candidates": [
            {"node": c.node, "coverage": round(c.coverage, 4), "distance_db": c.distance}
            for c in resolution.candidates
        ],
        "relayed_receptions": row.relayed,
        "region_share": round(row.region_share, 4),
        "origins": row.origins,
        "our_receptions": row.our_receptions,
        "our_share": None if row.our_share is None else round(row.our_share, 4),
        "our_origins": list(row.our_origins),
        "our_sole_first_hop": list(row.our_sole_first_hop),
        "our_sole_path_packets": row.our_sole_path_packets,
        "gateways_relying": row.gateways_relying,
        "max_gateway_share": round(row.max_gateway_share, 4),
        "gateways_hearing_directly": row.heard_directly_by,
        "role": row.role,
        "last_seen": iso(row.last_seen),
        "last_boot": iso(row.last_boot),
        "gaps": list(row.gaps),
    }


def relays_to_json_dict(report: NetworkReport, *, everything: bool) -> dict[str, object]:
    """Render the relay tables as a JSON-serializable mapping (every row, no limit).

    Args:
        report: The report.
        everything: Every relay not ours (``--all``).

    Returns:
        ``{"generated_at", "days", "regions": [...], "refresh", "exit_code"}``.
    """
    regions = []
    for region in report.regions:
        table = relays_of(report, region, everything=everything)
        regions.append(
            {
                "region": region.region,
                "data_as_of": iso(region.fetched_at),
                "relayed_receptions": table.relayed,
                "our_packets": table.our_packets,
                "our_relayed_receptions": table.our_relayed,
                "relays": [_row_json(row) for row in table.rows],
            }
        )
    return {
        "generated_at": iso(report.generated_at),
        "days": report.days,
        "regions": regions,
        "refresh": refresh_json(report.refresh),
        "exit_code": report.exit_code(),
    }


def render_relays_json(report: NetworkReport, *, everything: bool) -> str:
    """Render the relay tables as indented, terminal-safe JSON.

    Args:
        report: The report.
        everything: Every relay not ours (``--all``).

    Returns:
        The JSON text.
    """
    return json_dumps_safe(relays_to_json_dict(report, everything=everything), indent=2)
