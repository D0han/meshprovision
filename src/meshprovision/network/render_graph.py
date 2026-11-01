"""Presentation of the relay graph (``mesh network graph``): text and JSON.

Text and JSON of :mod:`meshprovision.network.graph` for each region of a
:class:`~meshprovision.network.report.NetworkReport`, with the observed
measure (sole first hops) and the inferred one (cut vertices) kept apart
and labelled, and what the graph does not claim printed every time.
Every name is printed as plain text, never as rich markup. The shared
pieces are in :mod:`meshprovision.network.render_common`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING, Final

from rich import box
from rich.console import RenderableType
from rich.table import Table
from rich.text import Text

from meshprovision.network.graph import (
    MIN_ORIGIN_RECEPTIONS,
    OurRedundancy,
    RelayGraph,
    build_graph,
)
from meshprovision.network.render_common import (
    MAX_NAMED,
    data_line,
    iso,
    label,
    names,
    refresh_json,
    refresh_lines,
    text_cell,
)
from meshprovision.termsafe import json_dumps_safe, terminal_safe

if TYPE_CHECKING:
    from rich.console import Console

    from meshprovision.network.report import NetworkReport, RegionReport

__all__ = [
    "NON_CLAIMS",
    "graph_of",
    "graph_to_json_dict",
    "render_graph_console",
    "render_graph_json",
]

NON_CLAIMS: Final[tuple[str, ...]] = (
    "An absent edge is not an absent link: only the last and first hops of packets that "
    "reached a gateway are seen (the middle of a longer path only in traceroutes).",
    "Flooding redundancy is suppressed on the air, hence invisible here.",
    "Gateways are MQTT visibility, not mesh connectivity: a node cut off from MQTT may "
    "still talk on the mesh.",
    "One window of data: moved nodes and changing conditions are not modelled.",
)
"""What the graph does not claim, printed above it."""


def graph_of(report: NetworkReport, region: RegionReport) -> RelayGraph:
    """Build a region's relay graph from a report.

    Args:
        report: The report.
        region: The region.

    Returns:
        The graph, with our nodes' redundancy in database order.
    """
    return build_graph(region.traffic, region.resolutions, [m.node for m in report.fleet])


def _listed(nodes: Iterable[str], known: Mapping[str, str]) -> str:
    """Name nodes, at most :data:`MAX_NAMED`."""
    found = list(nodes)
    text = ", ".join(label(node, known) for node in found[:MAX_NAMED])
    if len(found) > MAX_NAMED:
        text += f" and {len(found) - MAX_NAMED} more"
    return text


def _note(entry: OurRedundancy) -> str:
    """Say what our node's paths and first hops mean together."""
    if entry.paths == 0:
        return "no path to MQTT seen"
    if entry.paths == 1:
        single = "single point (1 path)"
        return single if entry.sole_first_hop is None else f"{single}; single observed first hop"
    if entry.sole_first_hop is not None:
        return "single observed first hop; other neighbours known"
    return "-"


def _ours_table(graph: RelayGraph, known: Mapping[str, str]) -> Table:
    """Build the table of our nodes' redundancy."""
    grid = Table(box=box.SIMPLE_HEAVY, header_style="bold")
    for column in (
        "Node",
        "Name",
        "Paths to MQTT",
        "First hops",
        "Sole first hop",
        "Gateways",
        "Note",
    ):
        grid.add_column(column)
    for entry in graph.ours:
        cells = (
            entry.node,
            known.get(entry.node, "-"),
            str(entry.paths),
            str(entry.first_hops),
            "-" if entry.sole_first_hop is None else label(entry.sole_first_hop, known),
            str(entry.gateways),
            _note(entry),
        )
        grid.add_row(*(text_cell(cell) for cell in cells))
    return grid


def _graph_lines(report: NetworkReport, region: RegionReport) -> Iterable[RenderableType]:
    """Render one region's graph."""
    graph = graph_of(report, region)
    known = names(report, region)
    yield data_line(report, region, "Relay graph")
    yield Text(
        f"{graph.nodes} nodes, {len(graph.edges)} edges (MQTT joins every gateway); "
        f"{graph.left_out} relayed receptions left out (ambiguous or unknown relay byte)."
    )
    for claim in NON_CLAIMS:
        yield Text(f"Not claimed: {claim}", style="dim")
    yield Text(
        "Observed: sole first hops (the only first hop seen; the strong claim)", style="bold"
    )
    by_hop: dict[str, list[str]] = {}
    for entry in graph.sole_first_hops:
        by_hop.setdefault(entry.first_hop, []).append(entry.origin)
    for hop, origins in sorted(by_hop.items(), key=lambda item: (-len(item[1]), item[0])):
        yield Text(
            terminal_safe(
                f"  {label(hop, known)} was the only first hop of {_listed(origins, known)}"
            )
        )
    if not by_hop:
        yield Text("  none")
    yield Text(
        "Inferred: cut vertices toward MQTT (the weak claim; only nodes with at least "
        f"{MIN_ORIGIN_RECEPTIONS} receptions as an origin are counted as cut off)",
        style="bold",
    )
    for cut in graph.cut_vertices:
        yield Text(
            terminal_safe(f"  {label(cut.node, known)} cuts off {_listed(cut.cuts_off, known)}")
        )
    if not graph.cut_vertices:
        yield Text("  none")
    yield Text("Our nodes", style="bold")
    yield _ours_table(graph, known)


def render_graph_console(report: NetworkReport, *, console: Console) -> None:
    """Print the relay graph of every region.

    Args:
        report: The report.
        console: Where to print.
    """
    for index, region in enumerate(report.regions):
        if index:
            console.print()
        for item in _graph_lines(report, region):
            console.print(item, markup=False, highlight=False)
    for line in refresh_lines(report.refresh):
        console.print(line, markup=False, highlight=False)


def graph_to_json_dict(report: NetworkReport) -> dict[str, object]:
    """Render the relay graphs as a JSON-serializable mapping (every edge, for other tools).

    Args:
        report: The report.

    Returns:
        ``{"generated_at", "days", "not_claimed", "regions": [...], "refresh", "exit_code"}``.
    """
    regions = []
    for region in report.regions:
        graph = graph_of(report, region)
        regions.append(
            {
                "region": region.region,
                "data_as_of": iso(region.fetched_at),
                "nodes": graph.nodes,
                "left_out_receptions": graph.left_out,
                "edges": [{"a": e.a, "b": e.b, "evidence": dict(e.evidence)} for e in graph.edges],
                "observed_sole_first_hops": [
                    {
                        "origin": s.origin,
                        "first_hop": s.first_hop,
                        "events": s.events,
                        "share": round(s.share, 4),
                    }
                    for s in graph.sole_first_hops
                ],
                "inferred_cut_vertices": [
                    {"node": c.node, "cuts_off": list(c.cuts_off)} for c in graph.cut_vertices
                ],
                "ours": [
                    {
                        "node": o.node,
                        "paths_to_mqtt": o.paths,
                        "first_hops": o.first_hops,
                        "sole_first_hop": o.sole_first_hop,
                        "gateways": o.gateways,
                        "note": _note(o),
                    }
                    for o in graph.ours
                ],
            }
        )
    return {
        "generated_at": iso(report.generated_at),
        "days": report.days,
        "not_claimed": list(NON_CLAIMS),
        "regions": regions,
        "refresh": refresh_json(report.refresh),
        "exit_code": report.exit_code(),
    }


def render_graph_json(report: NetworkReport) -> str:
    """Render the relay graphs as indented, terminal-safe JSON.

    Args:
        report: The report.

    Returns:
        The JSON text.
    """
    return json_dumps_safe(graph_to_json_dict(report), indent=2)
