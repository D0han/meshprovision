"""The relay graph: edges and their evidence, sole first hops, cut vertices, disjoint paths."""

from __future__ import annotations

import io
import itertools
import random
from collections import Counter, deque

import pytest
from rich.console import Console

from meshprovision.datasources.loranet import ReportedNeighbor
from meshprovision.network import graph as graph_module
from meshprovision.network.buckets import LastHop, Radio, Traffic
from meshprovision.network.graph import (
    LORANET_NEIGHBOR,
    MIN_ORIGIN_RECEPTIONS,
    MQTT,
    CutVertex,
    LoranetPaths,
    OurRedundancy,
    RelayGraph,
    SoleFirstHop,
    build_graph,
)
from meshprovision.network.keys import FleetKey, KeyScan
from meshprovision.network.render_graph import graph_to_json_dict, render_graph_console
from meshprovision.network.report import (
    FleetNode,
    LoranetView,
    NetworkReport,
    RegionReport,
    heard_ids,
)
from meshprovision.network.resolve import Confidence, Resolution
from meshprovision.nodeid import NodeId
from tests.unit.network_fixtures import NOW

pytestmark = pytest.mark.unit

_G1, _G2, _G3 = "6a000071", "6a000072", "6a000073"
_R, _OURS, _O = "c0ffee61", "d0000a01", "a1000011"
_RES = {0x61: Resolution(0x61, Confidence.HIGH, _R)}


def _edges(
    traffic: Traffic, resolutions: dict[int, Resolution] = _RES
) -> dict[tuple[str, str], dict[str, int]]:
    graph = build_graph(traffic, resolutions, ())
    return {(e.a, e.b): dict(e.evidence) for e in graph.edges}


def test_reception_edges_need_two_observations_and_gateways_join_mqtt() -> None:
    traffic = Traffic(
        direct={_O: {_G1: Radio(2), _G2: Radio(1)}},
        relayed={0x61: {_G1: Radio(3), _G3: Radio(1)}, 0xE4: {_G1: Radio(4)}},
        last_hops={_O: {0x61: LastHop(3, 2), 0xE4: LastHop(4, 4)}, "b0000009": {0x61: LastHop(9)}},
        edges={("b0000009", _R, "n"): 1},
    )

    edges = _edges(traffic)

    assert edges == {
        (_G1, _O): {"direct": 2},
        (_G1, _R): {"relayed": 3},
        (_O, _R): {"first_hop": 2},
        ("b0000009", _R): {"neighbor": 1},
        (_G1, MQTT): {"gateway": 1},
        (_G2, MQTT): {"gateway": 1},
        (_G3, MQTT): {"gateway": 1},
    }
    assert build_graph(traffic, _RES, ()).left_out == 4


def test_explicit_links_count_from_one_observation() -> None:
    traffic = Traffic(edges={(_O, _R, "t"): 1, (_O, _R, "n"): 1, ("11111111", _R, "n"): 1})

    assert _edges(traffic) == {
        (_O, _R): {"neighbor": 1, "traceroute": 1},
        ("11111111", _R): {"neighbor": 1},
    }


_GZ = "ff000071"


def _chain(receptions: int = 25) -> Traffic:
    """Origin -> relay -> gateway, plus our node next to the gateway."""
    return Traffic(
        direct={_R: {_GZ: Radio(5)}, _OURS: {_GZ: Radio(30)}},
        relayed={0x61: {_GZ: Radio(receptions)}},
        last_hops={_O: {0x61: LastHop(receptions, receptions)}},
    )


def test_a_cut_vertex_is_reported_only_for_well_observed_nodes() -> None:
    graph = build_graph(_chain(), _RES, ())

    assert graph.cut_vertices == (
        CutVertex(_GZ, (_O, _OURS)),
        CutVertex(_R, (_O,)),
    )
    assert build_graph(_chain(20), _RES, ()).cut_vertices[1] == CutVertex(_R, (_O,))
    assert build_graph(_chain(19), _RES, ()).cut_vertices == (CutVertex(_GZ, (_OURS,)),)


def _reachable(adjacency: dict[str, set[str]], *, without: str | None = None) -> set[str]:
    """The nodes reachable from MQTT without one node: the reference's search."""
    if MQTT not in adjacency:
        return set()
    seen = {MQTT}
    queue = deque([MQTT])
    while queue:
        for neighbor in adjacency[queue.popleft()]:
            if neighbor != without and neighbor not in seen:
                seen.add(neighbor)
                queue.append(neighbor)
    return seen


def _cut_vertices_by_removal(
    adjacency: dict[str, set[str]], observed: Counter[str]
) -> tuple[CutVertex, ...]:
    """The reference: remove each node in turn and see who loses MQTT (quadratic)."""
    reachable = _reachable(adjacency)
    found = []
    for node in sorted(reachable - {MQTT}):
        lost = reachable - _reachable(adjacency, without=node) - {node}
        kept = tuple(sorted(n for n in lost if observed[n] >= MIN_ORIGIN_RECEPTIONS))
        if kept:
            found.append(CutVertex(node, kept))
    return tuple(sorted(found, key=lambda cut: (-len(cut.cuts_off), cut.node)))


def _random_graph(rng: random.Random) -> tuple[dict[str, set[str]], Counter[str]]:
    """A sparse random graph, MQTT joined to a few nodes (or absent), random observations."""
    nodes = [f"{i:08x}" for i in range(rng.randint(0, 40))]
    adjacency: dict[str, set[str]] = {}
    pairs = [(rng.choice(nodes), rng.choice(nodes)) for _ in range(len(nodes) * rng.randint(0, 2))]
    gateways = [(node, MQTT) for node in rng.sample(nodes, min(len(nodes), rng.randint(0, 3)))]
    for a, b in [*pairs, *gateways]:
        if a != b:
            adjacency.setdefault(a, set()).add(b)
            adjacency.setdefault(b, set()).add(a)
    observed = Counter({node: rng.choice([0, 5, 19, 20, 50]) for node in nodes})
    return adjacency, observed


@pytest.mark.parametrize("seed", range(10))
def test_cut_vertices_match_removing_each_node_in_turn(seed: int) -> None:
    rng = random.Random(20261102 + seed)  # noqa: S311 -- deterministic property sweep, not crypto
    for _ in range(60):
        adjacency, observed = _random_graph(rng)

        found = graph_module._cut_vertices(adjacency, observed)

        assert found == _cut_vertices_by_removal(adjacency, observed)


def test_cut_vertices_of_a_long_chain_need_no_recursion() -> None:
    nodes = [f"{i:08x}" for i in range(5000)]
    path = [MQTT, *nodes]
    adjacency = {node: set() for node in path}
    for a, b in itertools.pairwise(path):
        adjacency[a].add(b)
        adjacency[b].add(a)

    found = graph_module._cut_vertices(adjacency, Counter({nodes[-1]: MIN_ORIGIN_RECEPTIONS}))

    assert found == tuple(CutVertex(node, (nodes[-1],)) for node in nodes[:-1])


def test_a_sole_first_hop_needs_twenty_events_for_others_and_five_for_ours() -> None:
    traffic = Traffic(
        relayed={0x61: {_G1: Radio(25)}},
        last_hops={_O: {0x61: LastHop(19, 19)}, _OURS: {0x61: LastHop(6, 5)}},
    )

    graph = build_graph(traffic, _RES, (_OURS,))

    assert graph.sole_first_hops == (SoleFirstHop(_OURS, _R, 5, 1.0),)


def _two_ways() -> Traffic:
    """Our node heard via the router and via a neighbour it reported, both to a gateway."""
    return Traffic(
        direct={_R: {_G1: Radio(5)}, "b0000002": {_G2: Radio(5)}},
        relayed={0x61: {_G1: Radio(6)}},
        last_hops={_OURS: {0x61: LastHop(6, 6)}},
        edges={(_OURS, "b0000002", "n"): 1},
    )


def test_our_node_with_one_observed_first_hop_but_two_ways_out() -> None:
    graph = build_graph(_two_ways(), _RES, (_OURS,))

    assert graph.ours == (OurRedundancy(_OURS, 2, 1, 0, _R),)


def test_disjoint_paths_share_no_node() -> None:
    traffic = Traffic(
        direct={"b0000001": {_G1: Radio(5)}, "b0000002": {_G1: Radio(5)}},
        edges={(_OURS, "b0000001", "n"): 1, (_OURS, "b0000002", "n"): 1},
    )

    (ours,) = build_graph(traffic, {}, (_OURS,)).ours

    assert ours.paths == 1


def test_a_shared_middle_node_allows_one_path() -> None:
    traffic = Traffic(
        direct={"b0000009": {_G1: Radio(5), _G2: Radio(5)}},
        edges={
            (_OURS, "b0000001", "n"): 1,
            (_OURS, "b0000002", "n"): 1,
            ("b0000001", "b0000009", "n"): 1,
            ("b0000002", "b0000009", "n"): 1,
        },
    )

    (ours,) = build_graph(traffic, {}, (_OURS,)).ours

    assert ours.paths == 1


def test_paths_are_counted_up_to_four() -> None:
    relays = [f"b000000{i}" for i in range(6)]
    traffic = Traffic(
        direct={relay: {f"6a00000{i}": Radio(5)} for i, relay in enumerate(relays)},
        edges={(_OURS, relay, "n"): 1 for relay in relays},
    )

    (ours,) = build_graph(traffic, {}, (_OURS,)).ours

    assert ours.paths == 4


def test_a_node_not_in_the_graph_has_no_path() -> None:
    graph = build_graph(Traffic(), {}, (_OURS,))

    assert graph.ours == (OurRedundancy(_OURS, 0, 0, 0, None),)
    assert (graph.nodes, graph.edges, graph.cut_vertices) == (0, (), ())


def test_first_hops_and_gateways_of_our_node() -> None:
    traffic = Traffic(
        direct={_OURS: {_G1: Radio(3), _G2: Radio(2)}},
        relayed={0x61: {_G1: Radio(3)}},
        last_hops={_OURS: {0x61: LastHop(3, 3)}},
    )

    (ours,) = build_graph(traffic, _RES, (_OURS,)).ours

    assert (ours.first_hops, ours.gateways, ours.sole_first_hop) == (3, 2, None)
    assert ours.paths == 2


def test_a_node_of_ours_without_a_path_is_said_so() -> None:
    region = RegionReport("PL", NOW, KeyScan((), (), (), ()))
    report = NetworkReport(NOW, 1, (FleetNode(_OURS, "Our1", FleetKey(_OURS)),), (region,))

    (ours,) = graph_to_json_dict(report)["regions"][0]["ours"]  # type: ignore[index]

    assert ours["note"] == "no path to MQTT seen"


def _observed(graph: RelayGraph) -> tuple[object, ...]:
    """Every observed measure, to compare with and without loranet's lists."""
    return (graph.nodes, graph.left_out, graph.sole_first_hops, graph.cut_vertices, graph.ours)


def test_loranet_lists_never_change_the_observed_measures() -> None:
    plain = build_graph(_chain(), _RES, (_OURS,))
    reported = {_O: ((_GZ, NOW), (_OURS, NOW)), _OURS: ((_O, NOW),)}

    with_lists = build_graph(_chain(), _RES, (_OURS,), loranet=reported, start=0, end=NOW)

    assert _observed(with_lists) == _observed(plain)
    assert plain.with_loranet is None
    assert {e.a + e.b for e in plain.edges} <= {e.a + e.b for e in with_lists.edges}


def test_an_empty_list_reports_nothing_and_adds_no_edge() -> None:
    plain = build_graph(_chain(), _RES, (_OURS,))

    graph = build_graph(_chain(), _RES, (_OURS,), loranet={}, start=0, end=NOW)

    assert graph.edges == plain.edges
    assert graph.with_loranet == LoranetPaths(0, 0, plain.cut_vertices, ((_OURS, 1),))


def test_only_reports_in_the_window_between_nodes_of_the_graph_count() -> None:
    reported = {
        _O: (
            (_GZ, NOW - 10),  # kept: both ends in the graph, in the window
            (_OURS, NOW - 100_000),  # too old
            ("b0000009", NOW - 10),  # never heard in the window
            (_O, NOW - 10),  # itself
        ),
        _OURS: ((_O, NOW + 5),),  # after the window
        "b0000009": ((_GZ, NOW - 10),),  # reporter not in the graph
    }

    graph = build_graph(_chain(), _RES, (), loranet=reported, start=NOW - 86400, end=NOW)

    loranet = {(e.a, e.b): dict(e.evidence) for e in graph.edges if LORANET_NEIGHBOR in e.evidence}
    assert loranet == {(min(_O, _GZ), max(_O, _GZ)): {LORANET_NEIGHBOR: 1}}
    assert graph.with_loranet is not None
    assert (graph.with_loranet.reports, graph.with_loranet.only_loranet) == (1, 1)
    assert graph.nodes == build_graph(_chain(), _RES, ()).nodes


def test_both_directions_are_summed_on_an_observed_edge() -> None:
    reported = {_R: ((_GZ, NOW),), _GZ: ((_R, NOW),)}

    graph = build_graph(_chain(), _RES, (), loranet=reported, start=0, end=NOW)

    (edge,) = [e for e in graph.edges if {e.a, e.b} == {_R, _GZ}]
    assert edge.evidence == {"direct": 5, "relayed": 25, LORANET_NEIGHBOR: 2}
    assert graph.with_loranet is not None
    assert graph.with_loranet.only_loranet == 0


def test_a_loranet_edge_bypassing_a_cut_vertex_is_reported_apart() -> None:
    """The router cuts the origin off; the origin reported hearing the gateway."""
    reported = {_O: ((_GZ, NOW),)}

    graph = build_graph(_chain(), _RES, (), loranet=reported, start=0, end=NOW)

    assert CutVertex(_R, (_O,)) in graph.cut_vertices
    assert graph.with_loranet is not None
    assert all(cut.node != _R for cut in graph.with_loranet.cut_vertices)


def test_our_paths_with_loranet_lists_are_counted_apart() -> None:
    reported = {_OURS: (("b0000002", NOW),)}
    traffic = Traffic(
        direct={_R: {_G1: Radio(5)}, "b0000002": {_G2: Radio(5)}},
        relayed={0x61: {_G1: Radio(6)}},
        last_hops={_OURS: {0x61: LastHop(6, 6)}},
    )

    graph = build_graph(traffic, _RES, (_OURS,), loranet=reported, start=0, end=NOW)

    assert graph.ours[0].paths == 1
    assert graph.with_loranet is not None
    assert graph.with_loranet.ours == ((_OURS, 2),)


def _report_with_lists(neighbors: dict[str, tuple[ReportedNeighbor, ...]]) -> NetworkReport:
    traffic = Traffic(
        direct={_R: {_G1: Radio(5)}, "b0000002": {_G2: Radio(5)}},
        relayed={0x61: {_G1: Radio(6)}},
        last_hops={_OURS: {0x61: LastHop(6, 6)}},
    )
    region = RegionReport("PL", NOW, KeyScan((), (), (), ()), traffic, resolutions=_RES)
    return NetworkReport(
        NOW,
        1,
        (FleetNode(_OURS, "Our1", FleetKey(_OURS)),),
        (region,),
        loranet=LoranetView(asked=True, neighbors=neighbors),
    )


def test_our_paths_cell_shows_the_loranet_count_apart_only_when_it_differs() -> None:
    reported = {_OURS: (ReportedNeighbor(NodeId.from_hex("b0000002"), None, NOW - 60),)}
    buffer = io.StringIO()

    render_graph_console(
        _report_with_lists(reported), console=Console(file=buffer, width=250, color_system=None)
    )
    render_graph_console(
        _report_with_lists({}), console=Console(file=buffer, width=250, color_system=None)
    )

    out = buffer.getvalue()
    assert "1 (2 with loranet neighbour lists)" in out
    assert out.count("with loranet neighbour lists)") == 1
    assert out.count("Not claimed: loranet neighbour lists") == 2


def test_heard_ids_are_every_origin_gateway_and_resolved_relay() -> None:
    traffic = Traffic(
        direct={_O: {_G1: Radio(2)}},
        relayed={0x61: {_G2: Radio(3)}},
        last_hops={"b0000009": {0x61: LastHop(3)}},
    )
    region = RegionReport("PL", NOW, KeyScan((), (), (), ()), traffic, resolutions=_RES)

    assert heard_ids((region,)) == {NodeId.from_hex(n) for n in (_O, _G1, _G2, "b0000009", _R)}


def test_reported_lists_only_when_loranet_answered() -> None:
    entry = ReportedNeighbor(NodeId.from_hex(_O), 1.0, NOW)

    assert LoranetView(asked=True, neighbors={_R: (entry,)}).reported == {_R: ((_O, NOW),)}
    assert LoranetView(asked=False).reported is None
    assert LoranetView(asked=True, error="down", neighbors={_R: (entry,)}).reported is None
