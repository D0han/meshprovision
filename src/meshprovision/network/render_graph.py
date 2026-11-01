"""Presentation of the relay graph (``mesh network graph``): text and JSON.

Text and JSON of :mod:`meshprovision.network.graph` for each region of a
:class:`~meshprovision.network.report.NetworkReport`, with the observed
measure (sole first hops) and the inferred one (cut vertices) kept apart
and labelled, and what the graph does not claim printed every time.
loranet's neighbour lists only ever add a separate, labelled difference.
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
    CutVertex,
    LoranetPaths,
    OurRedundancy,
    RelayGraph,
    build_graph,
)
from meshprovision.network.render import loranet_json, loranet_line
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
    "LORANET_NON_CLAIM",
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

LORANET_NON_CLAIM: Final[str] = (
    "loranet neighbour lists are what a node reported hearing (one direction, from the window "
    "only); they are shown apart and never create a single point or a sole first hop."
)
"""What loranet's neighbour edges do not claim, printed when they were read."""


def graph_of(report: NetworkReport, region: RegionReport) -> RelayGraph:
    """Build a region's relay graph from a report.

    Args:
        report: The report.
        region: The region.

    Returns:
        The graph, with our nodes' redundancy in database order.
    """
    loranet = None if report.loranet is None else report.loranet.reported
    return build_graph(
        region.traffic,
        region.resolutions,
        [m.node for m in report.fleet],
        loranet=loranet,
        start=report.start,
        end=report.generated_at,
    )


def _non_claims(graph: RelayGraph) -> tuple[str, ...]:
    """What this graph does not claim (the loranet line only when its lists were read)."""
    return NON_CLAIMS if graph.with_loranet is None else (*NON_CLAIMS, LORANET_NON_CLAIM)


def _bypassed(cut: CutVertex, loranet: LoranetPaths | None) -> int:
    """How many of a cut vertex's cut-off nodes loranet's lists give another path to MQTT."""
    if loranet is None:
        return 0
    still = next((c.cuts_off for c in loranet.cut_vertices if c.node == cut.node), ())
    return len(set(cut.cuts_off) - set(still))


def _paths_cell(entry: OurRedundancy, loranet: LoranetPaths | None) -> str:
    """Render our node's paths, with loranet's count apart when it differs."""
    with_lists = None if loranet is None else dict(loranet.ours).get(entry.node)
    if with_lists is None or with_lists == entry.paths:
        return str(entry.paths)
    return f"{entry.paths} ({with_lists} with loranet neighbour lists)"


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
            _paths_cell(entry, graph.with_loranet),
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
    if graph.with_loranet is not None:
        yield Text(
            f"loranet neighbour lists: {graph.with_loranet.reports} report(s) in the window "
            f"between nodes of the graph, {graph.with_loranet.only_loranet} edge(s) no "
            "observation shows (shown apart below)."
        )
    for claim in _non_claims(graph):
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
        bypassed = _bypassed(cut, graph.with_loranet)
        apart = (
            f"; loranet neighbour lists show another path for {bypassed} of {len(cut.cuts_off)}"
            if bypassed
            else ""
        )
        yield Text(
            terminal_safe(
                f"  {label(cut.node, known)} cuts off {_listed(cut.cuts_off, known)}{apart}"
            )
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
    missing = loranet_line(report.loranet, missing="neighbour lists")
    if missing is not None:
        console.print(missing, markup=False, highlight=False)


def _loranet_paths_json(loranet: LoranetPaths | None) -> dict[str, object] | None:
    """Render the inferred measures with loranet's lists added, or ``None``."""
    if loranet is None:
        return None
    return {
        "reports": loranet.reports,
        "edges_only_from_loranet": loranet.only_loranet,
        "cut_vertices": [
            {"node": c.node, "cuts_off": list(c.cuts_off)} for c in loranet.cut_vertices
        ],
        "ours": [{"node": node, "paths": paths} for node, paths in loranet.ours],
    }


def graph_to_json_dict(report: NetworkReport) -> dict[str, object]:
    """Render the relay graphs as a JSON-serializable mapping (every edge, for other tools).

    Args:
        report: The report.

    Returns:
        ``{"generated_at", "days", "not_claimed", "regions": [...], "refresh",
        "loranet", "exit_code"}``; each region's ``with_loranet`` is ``null``
        unless loranet's neighbour lists were read.
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
                "with_loranet": _loranet_paths_json(graph.with_loranet),
            }
        )
    return {
        "generated_at": iso(report.generated_at),
        "days": report.days,
        "not_claimed": list(
            NON_CLAIMS
            if report.loranet is None or report.loranet.reported is None
            else (*NON_CLAIMS, LORANET_NON_CLAIM)
        ),
        "regions": regions,
        "refresh": refresh_json(report.refresh),
        "loranet": loranet_json(report.loranet),
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
