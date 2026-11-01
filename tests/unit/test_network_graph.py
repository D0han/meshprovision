"""The relay graph: edges and their evidence, sole first hops, cut vertices, disjoint paths."""

from __future__ import annotations

import pytest

from meshprovision.network.buckets import LastHop, Radio, Traffic
from meshprovision.network.graph import (
    MQTT,
    CutVertex,
    OurRedundancy,
    SoleFirstHop,
    build_graph,
)
from meshprovision.network.keys import FleetKey, KeyScan
from meshprovision.network.render_graph import graph_to_json_dict
from meshprovision.network.report import FleetNode, NetworkReport, RegionReport
from meshprovision.network.resolve import Confidence, Resolution
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
    region = RegionReport("PL", NOW, None, KeyScan((), (), (), ()))
    report = NetworkReport(NOW, 1, (FleetNode(_OURS, "Our1", FleetKey(_OURS)),), (region,))

    (ours,) = graph_to_json_dict(report)["regions"][0]["ours"]  # type: ignore[index]

    assert ours["note"] == "no path to MQTT seen"
