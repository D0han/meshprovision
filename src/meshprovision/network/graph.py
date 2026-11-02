"""A relay graph of a region's window, and what it can and cannot say about single points. Pure.

**Edges** (undirected, node ids; a virtual ``MQTT`` node joins every
gateway), each with its evidence counted per source:

- ``direct`` -- an origin and a gateway that heard it directly (kept from
  :data:`MIN_OBSERVED` observations);
- ``relayed`` -- a relay and a gateway that heard it as the last hop
  (from :data:`MIN_OBSERVED`);
- ``first_hop`` -- an origin and the relay that took its packet's first hop
  (receptions after exactly one hop; from :data:`MIN_OBSERVED`);
- ``traceroute`` and ``neighbor`` -- consecutive nodes of a traceroute, a
  node and a neighbour it reported (from one observation).

Relayed receptions whose relay byte is ambiguous or unknown cannot be
placed and are counted as left out.

``loranet_neighbor`` edges are kept apart: loranet's neighbour lists are
what a node reported hearing, over a longer horizon. Only reports made in
the window between two nodes the observed graph already has count (the
node set never grows), as evidence on the edge, and never in the observed
measures below: :class:`LoranetPaths` repeats the inferred ones with those
edges added, to report only the differences.

**Measures**, never merged into one score:

1. *Sole first hop* (observed, the strong claim): see
   :class:`~meshprovision.network.relays.FirstHops`.
2. *Cut vertices toward MQTT* (inferred, the weak claim): the nodes that
   lose every path to MQTT when one node is removed. Only nodes with at
   least :data:`MIN_ORIGIN_RECEPTIONS` receptions as an origin are
   reported as cut off: a node observed once or twice has one edge because
   it was barely observed, not because it has one neighbour.
3. *Redundancy of our nodes*: vertex-disjoint paths to MQTT (at most
   :data:`MAX_PATHS`), next to their observed first hops and the gateways
   that heard them directly.

What this does NOT claim: an absent edge is not an absent link (only last
and first hops of packets that reached a gateway are seen, the middle of a
longer path only in traceroutes); flooding redundancy is suppressed, hence
invisible; gateways are MQTT visibility, not mesh connectivity; one window,
no movement or weather.

This module imports nothing that reads files or the network (no
``httpx``, ``pathlib``, :mod:`meshprovision.cache` or
:mod:`meshprovision.db`); ``tests/unit/test_import_contracts.py`` holds it
to that.
"""

from __future__ import annotations

from bisect import bisect_left
from collections import Counter, defaultdict, deque
from collections.abc import Collection, Iterable, Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from meshprovision.network.buckets import EDGE_NEIGHBOR, EDGE_TRACEROUTE
from meshprovision.network.relays import (
    SOLE_FIRST_HOP_MIN_EVENTS,
    SOLE_FIRST_HOP_MIN_EVENTS_OURS,
    first_hops,
    gateway_relayed,
)

if TYPE_CHECKING:
    from meshprovision.network.buckets import Traffic
    from meshprovision.network.resolve import Resolution

__all__ = [
    "LORANET_NEIGHBOR",
    "MAX_PATHS",
    "MIN_OBSERVED",
    "MIN_ORIGIN_RECEPTIONS",
    "MQTT",
    "CutVertex",
    "Edge",
    "LoranetPaths",
    "OurRedundancy",
    "RelayGraph",
    "SoleFirstHop",
    "build_graph",
]

MQTT: Final[str] = "MQTT"
"""The virtual node every gateway is joined to."""

MIN_OBSERVED: Final[int] = 2
"""The fewest observations of a reception edge (direct, relayed, first hop) to keep it."""

MIN_ORIGIN_RECEPTIONS: Final[int] = 20
"""The fewest receptions as an origin for a node to be reported as cut off."""

MAX_PATHS: Final[int] = 4
"""Vertex-disjoint paths are counted up to this."""

LORANET_NEIGHBOR: Final[str] = "loranet_neighbor"
"""The evidence key of a neighbour loranet's node dump says a node reported."""

_SOURCES: Final[dict[str, str]] = {EDGE_TRACEROUTE: "traceroute", EDGE_NEIGHBOR: "neighbor"}


@dataclass(frozen=True, slots=True)
class Edge:
    """One link, with its evidence.

    Attributes:
        a: One end (the smaller id, or ``MQTT`` last).
        b: The other end.
        evidence: Source -> observations (``direct``, ``relayed``,
            ``first_hop``, ``traceroute``, ``neighbor``, ``gateway``).
    """

    a: str
    b: str
    evidence: Mapping[str, int]


@dataclass(frozen=True, slots=True)
class SoleFirstHop:
    """An origin whose every observed first hop was one relay.

    Attributes:
        origin: The origin.
        first_hop: The relay (a node, or a byte label).
        events: Its first-hop events.
        share: The relay's share of them.
    """

    origin: str
    first_hop: str
    events: int
    share: float


@dataclass(frozen=True, slots=True)
class CutVertex:
    """A node whose removal cuts well-observed nodes off from MQTT.

    Attributes:
        node: The node.
        cuts_off: The well-observed nodes left without a path, sorted.
    """

    node: str
    cuts_off: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OurRedundancy:
    """How many ways one of our nodes has to MQTT.

    Attributes:
        node: Our node.
        paths: Vertex-disjoint paths to MQTT in the graph (at most :data:`MAX_PATHS`).
        first_hops: Its distinct observed first hops (relays and gateways).
        gateways: The gateways that heard it directly.
        sole_first_hop: Its sole first hop, if it has one.
    """

    node: str
    paths: int
    first_hops: int
    gateways: int
    sole_first_hop: str | None


@dataclass(frozen=True, slots=True)
class LoranetPaths:
    """The inferred measures again, with loranet's neighbour lists added.

    Attributes:
        reports: Neighbour reports kept (in the window, both ends in the graph).
        only_loranet: Edges no observation shows, only those reports.
        cut_vertices: The cut vertices of the graph with those edges.
        ours: Each of our nodes and its vertex-disjoint paths to MQTT then.
    """

    reports: int
    only_loranet: int
    cut_vertices: tuple[CutVertex, ...]
    ours: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class RelayGraph:
    """A region's relay graph and its measures.

    Attributes:
        nodes: The nodes in the graph (``MQTT`` not counted).
        edges: Every edge, sorted.
        left_out: Relayed receptions whose relay byte could not be placed.
        sole_first_hops: Every origin with a sole first hop.
        cut_vertices: Every node that cuts a well-observed node off, the most first.
        ours: Our nodes' redundancy, in the order given.
        with_loranet: The inferred measures with loranet's neighbour lists
            added, when they were given.
    """

    nodes: int
    edges: tuple[Edge, ...]
    left_out: int
    sole_first_hops: tuple[SoleFirstHop, ...] = ()
    cut_vertices: tuple[CutVertex, ...] = ()
    ours: tuple[OurRedundancy, ...] = ()
    with_loranet: LoranetPaths | None = None


def _edges(
    traffic: Traffic, resolutions: Mapping[int, Resolution]
) -> tuple[dict[tuple[str, str], Counter[str]], int]:
    """Collect every edge's evidence and the receptions left out."""
    found: defaultdict[tuple[str, str], Counter[str]] = defaultdict(Counter)

    def add(x: str, y: str, source: str, count: int) -> None:
        if x != y:
            found[_key(x, y)][source] += count

    for origin, cells in traffic.direct.items():
        for gateway, radio in cells.items():
            add(origin, gateway, "direct", radio.receptions)
    left_out = 0
    for byte, cells in traffic.relayed.items():
        relay = resolutions[byte].node if byte in resolutions else None
        for gateway, radio in cells.items():
            if relay is None:
                left_out += radio.receptions
            else:
                add(relay, gateway, "relayed", radio.receptions)
    for origin, hops in traffic.last_hops.items():
        for byte, hop in hops.items():
            relay = resolutions[byte].node if byte in resolutions else None
            if relay is not None and hop.first_hop:
                add(origin, relay, "first_hop", hop.first_hop)
    for (a, b, source), count in traffic.edges.items():
        add(a, b, _SOURCES[source], count)
    for gateway in gateway_relayed(traffic).keys() | {
        g for c in traffic.direct.values() for g in c
    }:
        add(gateway, MQTT, "gateway", 1)
    return dict(found), left_out


def _key(x: str, y: str) -> tuple[str, str]:
    """Order an edge's ends: the smaller id first, ``MQTT`` always last."""
    if MQTT in (x, y):
        return (y if x == MQTT else x), MQTT
    return min(x, y), max(x, y)


def _kept(evidence: Mapping[str, int]) -> bool:
    """Tell whether an edge has enough evidence: one observed link, or a few receptions."""
    if any(evidence.get(source, 0) for source in ("traceroute", "neighbor", "gateway")):
        return True
    return any(evidence.get(s, 0) >= MIN_OBSERVED for s in ("direct", "relayed", "first_hop"))


def _adjacency(edges: Iterable[Edge]) -> dict[str, set[str]]:
    """Build the adjacency sets of the graph."""
    adjacency: defaultdict[str, set[str]] = defaultdict(set)
    for edge in edges:
        adjacency[edge.a].add(edge.b)
        adjacency[edge.b].add(edge.a)
    return dict(adjacency)


def _origin_receptions(traffic: Traffic) -> Counter[str]:
    """Count each origin's receptions (direct and relayed)."""
    counts: Counter[str] = Counter()
    for origin, cells in traffic.direct.items():
        counts[origin] += sum(radio.receptions for radio in cells.values())
    for origin, hops in traffic.last_hops.items():
        counts[origin] += sum(hop.receptions for hop in hops.values())
    return counts


def _cut_vertices(
    adjacency: Mapping[str, set[str]], observed: Counter[str]
) -> tuple[CutVertex, ...]:
    """Find every node whose removal cuts a well-observed node off from MQTT.

    One depth-first search from MQTT (Tarjan's articulation points, linear
    in nodes and edges): removing a node cuts off exactly the subtrees of
    its children that reach no node discovered before it, and each subtree
    is a run of the discovery order.
    """
    if MQTT not in adjacency:
        return ()
    order, cut_off = _cut_subtrees(adjacency)
    well = [i for i, node in enumerate(order) if observed[node] >= MIN_ORIGIN_RECEPTIONS]
    found = []
    for node, runs in cut_off.items():
        kept = tuple(
            sorted(
                order[i]
                for first, end in runs
                for i in well[bisect_left(well, first) : bisect_left(well, end)]
            )
        )
        if kept:
            found.append(CutVertex(node, kept))
    return tuple(sorted(found, key=lambda cut: (-len(cut.cuts_off), cut.node)))


def _cut_subtrees(
    adjacency: Mapping[str, set[str]],
) -> tuple[list[str], dict[str, list[tuple[int, int]]]]:
    """Search depth-first from MQTT, iteratively, for what each node's removal cuts off.

    Returns:
        The nodes reachable from MQTT in discovery order, and each node but
        MQTT whose removal cuts some off -> the ``[first, end)`` runs of that
        order it cuts off.
    """
    order = [MQTT]
    index = {MQTT: 0}
    low = {MQTT: 0}
    cut_off: defaultdict[str, list[tuple[int, int]]] = defaultdict(list)
    stack: list[tuple[str, str | None, Iterator[str]]] = [(MQTT, None, iter(adjacency[MQTT]))]
    while stack:
        node, parent, neighbors = stack[-1]
        for neighbor in neighbors:
            if neighbor not in index:
                index[neighbor] = low[neighbor] = len(order)
                order.append(neighbor)
                stack.append((neighbor, node, iter(adjacency[neighbor])))
                break
            # The parent counts too: harmless, as a cut is low >= the parent's index.
            low[node] = min(low[node], index[neighbor])
        else:
            stack.pop()
            if parent is not None:
                low[parent] = min(low[parent], low[node])
                if parent != MQTT and low[node] >= index[parent]:
                    cut_off[parent].append((index[node], len(order)))
    return order, dict(cut_off)


def _disjoint_paths(adjacency: Mapping[str, set[str]], source: str) -> int:
    """Count vertex-disjoint paths from ``source`` to MQTT, up to :data:`MAX_PATHS`.

    Each node but the two ends is split into an inner and an outer half
    joined by a unit capacity; a path is found by breadth-first search in
    the residual graph, as often as one exists.
    """
    if source not in adjacency or MQTT not in adjacency:
        return 0
    capacity: defaultdict[tuple[str, str], int] = defaultdict(int)
    for node, neighbors in adjacency.items():
        if node not in (source, MQTT):
            capacity[(f"{node}>", f"{node}<")] = 1
        for neighbor in neighbors:
            capacity[(_out(node, source), _in(neighbor, source))] = 1
    paths = 0
    while paths < MAX_PATHS and _augment(capacity, _out(source, source), _in(MQTT, source)):
        paths += 1
    return paths


def _in(node: str, source: str) -> str:
    """The half of a split node edges arrive at (the ends are not split)."""
    return node if node in (source, MQTT) else f"{node}>"


def _out(node: str, source: str) -> str:
    """The half of a split node edges leave from (the ends are not split)."""
    return node if node in (source, MQTT) else f"{node}<"


def _augment(capacity: defaultdict[tuple[str, str], int], start: str, end: str) -> bool:
    """Find one augmenting path by breadth-first search and push a unit along it."""
    links: defaultdict[str, list[str]] = defaultdict(list)
    for (x, y), left in capacity.items():
        if left > 0:
            links[x].append(y)
    parent: dict[str, str] = {start: start}
    queue = deque([start])
    while queue and end not in parent:
        current = queue.popleft()
        for nxt in links[current]:
            if nxt not in parent:
                parent[nxt] = current
                queue.append(nxt)
    if end not in parent:
        return False
    node = end
    while node != start:
        previous = parent[node]
        capacity[(previous, node)] -= 1
        capacity[(node, previous)] += 1
        node = previous
    return True


def _loranet_pairs(
    reported: Mapping[str, Iterable[tuple[str, float]]],
    nodes: Collection[str],
    *,
    start: float,
    end: float,
) -> Counter[tuple[str, str]]:
    """Count the neighbour reports in the window between two nodes of the graph, per edge."""
    pairs: Counter[tuple[str, str]] = Counter()
    for reporter, neighbors in reported.items():
        if reporter not in nodes:
            continue
        for neighbor, updated in neighbors:
            if neighbor != reporter and neighbor in nodes and start <= updated <= end:
                pairs[_key(reporter, neighbor)] += 1
    return pairs


def _merged(edges: tuple[Edge, ...], pairs: Mapping[tuple[str, str], int]) -> tuple[Edge, ...]:
    """Add the loranet evidence to the observed edges, and the edges only it shows."""
    by_key = {(edge.a, edge.b): dict(edge.evidence) for edge in edges}
    for key, count in pairs.items():
        by_key.setdefault(key, {})[LORANET_NEIGHBOR] = count
    return tuple(
        Edge(a, b, MappingProxyType(dict(sorted(evidence.items()))))
        for (a, b), evidence in sorted(by_key.items())
    )


def _sole_first_hops(
    traffic: Traffic, resolutions: Mapping[int, Resolution], ours: Collection[str]
) -> tuple[SoleFirstHop, ...]:
    """Find every origin whose observed first hops were all one relay."""
    sole = []
    for origin in sorted(traffic.last_hops.keys() | traffic.direct.keys()):
        hops = first_hops(traffic, resolutions, origin)
        minimum = SOLE_FIRST_HOP_MIN_EVENTS_OURS if origin in ours else SOLE_FIRST_HOP_MIN_EVENTS
        top = hops.sole(minimum)
        if top is not None:
            sole.append(SoleFirstHop(origin, top, hops.events, hops.relays[top] / hops.events))
    return tuple(sole)


def build_graph(
    traffic: Traffic,
    resolutions: Mapping[int, Resolution],
    ours: Collection[str],
    *,
    loranet: Mapping[str, Iterable[tuple[str, float]]] | None = None,
    start: float = float("-inf"),
    end: float = float("inf"),
) -> RelayGraph:
    """Build a region's relay graph and work out its measures.

    Args:
        traffic: The window's traffic.
        resolutions: Each relay byte's resolution.
        ours: Our nodes' hex ids, in output order.
        loranet: Each node's reported neighbours as ``(neighbour hex id,
            report time)``, from loranet; ``None`` when not had.
        start: The window's start, epoch seconds (for ``loranet``).
        end: The window's end, epoch seconds (for ``loranet``).

    Returns:
        The graph. Its observed measures never count ``loranet``; its edges
        carry it as ``loranet_neighbor`` evidence.
    """
    found, left_out = _edges(traffic, resolutions)
    edges = tuple(
        Edge(a, b, MappingProxyType(dict(sorted(evidence.items()))))
        for (a, b), evidence in sorted(found.items())
        if _kept(evidence)
    )
    adjacency = _adjacency(edges)
    observed = _origin_receptions(traffic)
    sole = _sole_first_hops(traffic, resolutions, ours)
    by_origin = {entry.origin: entry.first_hop for entry in sole}
    with_loranet = None
    if loranet is not None:
        pairs = _loranet_pairs(loranet, adjacency.keys() - {MQTT}, start=start, end=end)
        merged = _merged(edges, pairs)
        combined = _adjacency(merged)
        with_loranet = LoranetPaths(
            reports=sum(pairs.values()),
            only_loranet=len(merged) - len(edges),
            cut_vertices=_cut_vertices(combined, observed),
            ours=tuple((node, _disjoint_paths(combined, node)) for node in ours),
        )
        edges = merged
    return RelayGraph(
        nodes=len(adjacency.keys() - {MQTT}),
        edges=edges,
        left_out=left_out,
        sole_first_hops=sole,
        cut_vertices=_cut_vertices(adjacency, observed),
        ours=tuple(
            OurRedundancy(
                node=node,
                paths=_disjoint_paths(adjacency, node),
                first_hops=len(first_hops(traffic, resolutions, node).relays)
                + len(traffic.direct.get(node, {})),
                gateways=len(traffic.direct.get(node, {})),
                sole_first_hop=by_origin.get(node),
            )
            for node in ours
        ),
        with_loranet=with_loranet,
    )
