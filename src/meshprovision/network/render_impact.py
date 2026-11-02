"""Presentation of what depends on a node, or on our nodes (``mesh network impact``).

Text and JSON of :mod:`meshprovision.network.impact` for each region of a
:class:`~meshprovision.network.report.NetworkReport`; the shared pieces are
in :mod:`meshprovision.network.render_common`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import TYPE_CHECKING, Final

from rich import box
from rich.console import RenderableType
from rich.table import Table
from rich.text import Text

from meshprovision.network.impact import (
    Dependant,
    FleetImpact,
    Level,
    NodeImpact,
    fleet_impact,
    node_impact,
)
from meshprovision.network.relays import byte_label
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
)
from meshprovision.nodeid import relay_byte
from meshprovision.termsafe import json_dumps_safe, terminal_safe

if TYPE_CHECKING:
    from rich.console import Console

    from meshprovision.network.report import NetworkReport, RegionReport

__all__ = ["impact_to_json_dict", "render_impact_console", "render_impact_json"]


def _byte_cell(impact: NodeImpact, known: Mapping[str, str]) -> str:
    """Say what a node's relay byte resolves to."""
    byte = byte_label(relay_byte(impact.node))
    resolution = impact.resolution
    if resolution is None:
        return f"{byte}: not seen as a relay"
    if impact.credited:
        return f"{byte}: {confidence_text(resolution)}"
    if resolution.node is not None:
        return f"{byte}: attributed to {label(resolution.node, known)}"
    return f"{byte}: {resolution.confidence.value}"


def _dependants(dependants: Iterable[Dependant], known: Mapping[str, str]) -> str:
    """Render dependants with their shares, at most :data:`MAX_NAMED`."""
    listed = list(dependants)
    text = ", ".join(f"{label(d.node, known)} ({percent(d.share)})" for d in listed[:MAX_NAMED])
    if len(listed) > MAX_NAMED:
        text += f" and {len(listed) - MAX_NAMED} more"
    return text or "-"


def _impact_table(fleet: FleetImpact, known: Mapping[str, str]) -> Table:
    """Build the per-node impact table."""
    grid = Table(box=box.SIMPLE_HEAVY, header_style="bold")
    for column in (
        "Node",
        "Name",
        "Relay byte",
        "Carried",
        "Origins>=50%",
        "Gateways>=50%",
        "Sole 1st hop for",
        "Only gateway for",
        "Level",
    ):
        grid.add_column(column)
    for impact in fleet.nodes:
        cells = (
            impact.node,
            known.get(impact.node, "-"),
            _byte_cell(impact, known),
            percent(impact.carried_share),
            str(len(impact.origins)),
            str(len(impact.gateways)),
            str(len(impact.sole_first_hop_for)),
            str(len(impact.only_gateway_for)),
        )
        grid.add_row(
            *(text_cell(cell) for cell in cells),
            Text(impact.level.value, style=_LEVEL_STYLES[impact.level]),
        )
    return grid


_LEVEL_STYLES: Final[dict[Level, str]] = {Level.HIGH: "bold", Level.MEDIUM: "", Level.LOW: "grey50"}


def _fleet_lines(report: NetworkReport, region: RegionReport) -> Iterable[RenderableType]:
    """Render what depends on our nodes in one region."""
    fleet = fleet_impact(region.traffic, region.resolutions, [m.node for m in report.fleet])
    yield data_line(report, region, "Impact of our nodes")
    yield Text(
        f"Our nodes carried {fleet.carried} of {fleet.relayed} relayed receptions "
        f"({percent(fleet.carried / fleet.relayed if fleet.relayed else 0.0)}); possibly "
        f"{fleet.possibly_carried} more (ambiguous relay bytes with one of ours "
        "among the candidates)."
    )
    yield Text(
        f"Outsiders relying on us: {fleet.origins_half} of {fleet.origins_judged} origins "
        f"(with >= 20 relayed receptions) got >= 50% via us, {fleet.origins_most} >= 80%; "
        f"{fleet.gateways_half} of {fleet.gateways_judged} gateways >= 50%, "
        f"{fleet.gateways_most} >= 80%; {fleet.sole_path_packets} of {fleet.outsider_packets} "
        f"outsider packets reached gateways only via us; {fleet.only_gateway_origins} "
        "origin(s) seen by MQTT mostly only through our gateways."
    )
    yield _impact_table(fleet, names(report, region))


def _node_lines(report: NetworkReport, region: RegionReport, node: str) -> Iterable[Text]:
    """Render what depends on one node in one region."""
    known = names(report, region)
    ours = [m.node for m in report.fleet]
    impact = node_impact(region.traffic, region.resolutions, node, ours=ours)
    yield data_line(report, region, f"Impact of {terminal_safe(label(node, known))}")
    yield Text(f"Level: {impact.level.value}", style=_LEVEL_STYLES[impact.level])
    yield Text(f"Relay byte {_byte_cell(impact, known)}")
    total = sum(r.receptions for cells in region.traffic.relayed.values() for r in cells.values())
    yield Text(
        f"Carried {impact.carried} of {total} relayed receptions ({percent(impact.carried_share)})."
    )
    for title, text in (
        (
            "Origins getting >= 50% of their relayed receptions via it",
            _dependants(impact.origins, known),
        ),
        (
            "Gateways getting >= 50% of their relayed receptions via it",
            _dependants(impact.gateways, known),
        ),
        (
            "Was the only first hop seen of",
            ", ".join(label(n, known) for n in impact.sole_first_hop_for) or "-",
        ),
        ("Packets whose every reception it relayed last", str(impact.sole_path_packets)),
        (
            "Would no longer be seen by MQTT/lorastats without it",
            _dependants(impact.only_gateway_for, known),
        ),
    ):
        yield Text(f"{title}: {terminal_safe(text)}")


def _region_lines(
    report: NetworkReport, region: RegionReport, nodes: Sequence[str]
) -> Iterable[RenderableType]:
    """Render one region: each node in ``nodes``, else our nodes' summary."""
    if not nodes:
        yield from _fleet_lines(report, region)
        return
    for position, node in enumerate(nodes):
        if position:
            yield Text()
        yield from _node_lines(report, region, node)


def render_impact_console(report: NetworkReport, *, console: Console, nodes: Sequence[str]) -> None:
    """Print what depends on our nodes (or on ``nodes``) in every region.

    Args:
        report: The report.
        console: Where to print.
        nodes: The nodes to detail; empty for our nodes' summary.
    """
    for index, region in enumerate(report.regions):
        if index:
            console.print()
        for item in _region_lines(report, region, nodes):
            console.print(item, markup=False, highlight=False)
    console.print(Text(PROXY_CAVEAT, style="dim"), markup=False, highlight=False)
    for line in refresh_lines(report.refresh):
        console.print(line, markup=False, highlight=False)


def _impact_json(impact: NodeImpact) -> dict[str, object]:
    """Render one node's impact as JSON."""
    resolution = impact.resolution

    def dependants(found: Iterable[Dependant]) -> list[dict[str, object]]:
        return [{"node": d.node, "share": round(d.share, 4)} for d in found]

    return {
        "node": impact.node,
        "relay_byte": relay_byte(impact.node),
        "relay_confidence": None if resolution is None else resolution.confidence.value,
        "relay_attributed_to": None if resolution is None else resolution.node,
        "carried": impact.carried,
        "carried_share": round(impact.carried_share, 4),
        "origins_relying": dependants(impact.origins),
        "gateways_relying": dependants(impact.gateways),
        "sole_first_hop_for": list(impact.sole_first_hop_for),
        "sole_path_packets": impact.sole_path_packets,
        "only_gateway_for": dependants(impact.only_gateway_for),
        "level": impact.level.value,
    }


def impact_to_json_dict(report: NetworkReport, *, nodes: Sequence[str]) -> dict[str, object]:
    """Render what depends on our nodes (or on ``nodes``) as a JSON-serializable mapping.

    Args:
        report: The report.
        nodes: The nodes to detail; empty for our nodes' summary.

    Returns:
        ``{"generated_at", "days", "regions": [...], "refresh", "exit_code"}``.
    """
    regions: list[dict[str, object]] = []
    ours = [m.node for m in report.fleet]
    for region in report.regions:
        entry: dict[str, object] = {"region": region.region, "data_as_of": iso(region.fetched_at)}
        if nodes:
            entry["nodes"] = [
                _impact_json(node_impact(region.traffic, region.resolutions, n, ours=ours))
                for n in nodes
            ]
        else:
            fleet = fleet_impact(region.traffic, region.resolutions, ours)
            entry["fleet"] = {
                "relayed_receptions": fleet.relayed,
                "carried": fleet.carried,
                "possibly_carried": fleet.possibly_carried,
                "origins_judged": fleet.origins_judged,
                "origins_relying_half": fleet.origins_half,
                "origins_relying_most": fleet.origins_most,
                "gateways_judged": fleet.gateways_judged,
                "gateways_relying_half": fleet.gateways_half,
                "gateways_relying_most": fleet.gateways_most,
                "outsider_packets": fleet.outsider_packets,
                "sole_path_packets": fleet.sole_path_packets,
                "only_gateway_origins": fleet.only_gateway_origins,
            }
            entry["nodes"] = [_impact_json(impact) for impact in fleet.nodes]
        regions.append(entry)
    return {
        "generated_at": iso(report.generated_at),
        "days": report.days,
        "regions": regions,
        "refresh": refresh_json(report.refresh),
        "exit_code": report.exit_code(),
    }


def render_impact_json(report: NetworkReport, *, nodes: Sequence[str]) -> str:
    """Render the impact view as indented, terminal-safe JSON.

    Args:
        report: The report.
        nodes: The nodes to detail; empty for our nodes' summary.

    Returns:
        The JSON text.
    """
    return json_dumps_safe(impact_to_json_dict(report, nodes=nodes), indent=2)
