"""What depends on a node, or on our nodes: shares, sole first hops, only gateways, levels."""

from __future__ import annotations

import pytest

from meshprovision.network.buckets import LastHop, Radio, Traffic
from meshprovision.network.impact import (
    Dependant,
    FleetImpact,
    Level,
    fleet_impact,
    node_impact,
)
from meshprovision.network.resolve import CandidateScore, Confidence, Resolution

pytestmark = pytest.mark.unit

_N = "d0000c03"
_OTHER = "bb0000bc"
_G1, _G2 = "6a000071", "6a000072"


def _resolved(byte: int, node: str | None, confidence: Confidence = Confidence.HIGH) -> Resolution:
    return Resolution(byte, confidence, node)


def _traffic(through: int, elsewhere: int, *, first_hop: int = 0) -> Traffic:
    """One outsider origin with ``through`` receptions via 0x03 and ``elsewhere`` via 0x61."""
    return Traffic(
        packets={"a3000013": through + elsewhere},
        relayed={
            0x03: {_G1: Radio(through)},
            0x61: {_G1: Radio(elsewhere), _G2: Radio(1000)},
        },
        last_hops={"a3000013": {0x03: LastHop(through, first_hop), 0x61: LastHop(elsewhere)}},
    )


_RES = {0x03: _resolved(0x03, _N), 0x61: _resolved(0x61, "c0ffee61")}


@pytest.mark.parametrize(
    ("through", "elsewhere", "level"),
    [
        pytest.param(16, 4, Level.HIGH, id="eighty-percent"),
        pytest.param(15, 5, Level.MEDIUM, id="seventy-five-percent"),
        pytest.param(10, 10, Level.MEDIUM, id="half"),
        pytest.param(1, 19, Level.LOW, id="little"),
    ],
)
def test_the_level_follows_how_much_an_origin_relies_on_it(
    through: int, elsewhere: int, level: Level
) -> None:
    impact = node_impact(_traffic(through, elsewhere), _RES, _N)

    assert impact.level is level
    assert impact.carried == through
    assert impact.credited


def test_an_origin_with_few_relayed_receptions_is_not_judged() -> None:
    impact = node_impact(_traffic(19, 0), _RES, _N)

    assert impact.origins == ()


def test_a_gateway_relying_on_it_counts() -> None:
    traffic = Traffic(
        packets={"a1": 1},
        relayed={0x03: {_G1: Radio(16)}, 0x61: {_G1: Radio(4)}},
        last_hops={"a1": {0x03: LastHop(1)}},
    )

    impact = node_impact(traffic, _RES, _N)

    assert impact.gateways == (Dependant(_G1, 0.8),)
    assert impact.level is Level.HIGH


def test_a_gateway_with_few_relayed_receptions_is_not_judged() -> None:
    traffic = Traffic(packets={"a1": 1}, relayed={0x03: {_G1: Radio(19)}})

    assert node_impact(traffic, _RES, _N).gateways == ()


@pytest.mark.parametrize(
    ("share", "level"),
    [(0.10, Level.HIGH), (0.09, Level.MEDIUM), (0.03, Level.MEDIUM), (0.02, Level.LOW)],
)
def test_the_level_follows_the_share_carried(share: float, level: Level) -> None:
    carried = round(share * 1000)
    traffic = Traffic(relayed={0x03: {_G1: Radio(carried)}, 0x61: {_G1: Radio(1000 - carried)}})

    impact = node_impact(traffic, _RES, _N)

    assert impact.carried_share == pytest.approx(share)
    assert impact.level is level


def test_a_sole_first_hop_makes_it_high() -> None:
    impact = node_impact(_traffic(20, 0, first_hop=20), _RES, _N)

    assert impact.sole_first_hop_for == ("a3000013",)
    assert impact.level is Level.HIGH
    assert node_impact(_traffic(19, 0, first_hop=19), _RES, _N).sole_first_hop_for == ()


@pytest.mark.parametrize(
    ("alone", "packets", "found"), [(3, 6, True), (2, 6, False), (4, 4, False)]
)
def test_an_only_gateway_for_at_least_half_of_five_packets_makes_it_high(
    alone: int, packets: int, found: bool
) -> None:
    traffic = Traffic(packets={"a1": packets}, only_gateway={"a1": {_N: alone, _G1: 1}})

    impact = node_impact(traffic, {}, _N)

    assert impact.only_gateway_for == ((Dependant("a1", alone / packets),) if found else ())
    assert impact.level is (Level.HIGH if found else Level.LOW)
    assert impact.resolution is None
    assert not impact.credited


@pytest.mark.parametrize(
    "resolution",
    [
        pytest.param(_resolved(0x03, _OTHER), id="attributed-elsewhere"),
        pytest.param(_resolved(0x03, None, Confidence.AMBIGUOUS), id="ambiguous"),
    ],
)
def test_a_byte_not_resolved_to_the_node_credits_it_with_nothing(resolution: Resolution) -> None:
    impact = node_impact(_traffic(20, 0, first_hop=20), {**_RES, 0x03: resolution}, _N)

    assert (impact.carried, impact.origins, impact.sole_first_hop_for) == (0, (), ())
    assert impact.resolution is resolution
    assert not impact.credited
    assert impact.level is Level.LOW


def test_for_one_of_ours_our_other_nodes_are_not_dependants() -> None:
    traffic = _traffic(20, 0, first_hop=20)

    assert node_impact(traffic, _RES, _N, ours={_N, "a3000013"}).origins == ()
    assert node_impact(traffic, _RES, _N, ours={"a3000013"}).origins == (
        Dependant("a3000013", 1.0),
    )


def test_sole_path_packets_count_the_dependants_packets_it_alone_relayed() -> None:
    traffic = Traffic(
        packets={"a1": 7, _N: 9},
        relayed={0x03: {_G1: Radio(3)}},
        sole_relay={"a1": {0x03: 2, 0x61: 5}, _N: {0x03: 9}},
    )

    assert node_impact(traffic, _RES, _N).sole_path_packets == 2


def test_dependants_are_sorted_by_share_then_id() -> None:
    traffic = Traffic(
        relayed={0x03: {_G1: Radio(60)}, 0x61: {_G1: Radio(10)}},
        last_hops={
            "b": {0x03: LastHop(20)},
            "a": {0x03: LastHop(20)},
            "c": {0x03: LastHop(20), 0x61: LastHop(10)},
        },
    )

    impact = node_impact(traffic, _RES, _N)

    assert [d.node for d in impact.origins] == ["a", "b", "c"]


def test_the_fleet_summary() -> None:
    traffic = Traffic(
        packets={"o1": 30, "o2": 30, _N: 5},
        relayed={
            0x03: {_G1: Radio(25), _G2: Radio(15)},
            0x61: {_G2: Radio(10)},
            0xBC: {_G1: Radio(1)},
            0xE4: {_G1: Radio(4)},
        },
        last_hops={
            "o1": {0x03: LastHop(25)},
            "o2": {0x03: LastHop(15), 0x61: LastHop(10)},
            _N: {0xE4: LastHop(4)},
        },
        sole_relay={"o1": {0x03: 20}, "o2": {0x61: 9}},
        only_gateway={"o2": {_N: 20}},
    )
    candidates = (CandidateScore("x00000e4", 1.0, None), CandidateScore("d00000e4", 1.0, None))
    resolutions = {
        **_RES,
        0xE4: Resolution(0xE4, Confidence.AMBIGUOUS, None, candidates),
        0xBC: Resolution(0xBC, Confidence.HIGH, _OTHER, (CandidateScore("d00000e4", 0.0, None),)),
    }

    fleet = fleet_impact(traffic, resolutions, [_N, "d00000e4"])

    assert fleet == FleetImpact(
        relayed=55,
        carried=40,
        possibly_carried=4,
        origins_judged=2,
        origins_half=2,
        origins_most=1,
        gateways_judged=2,
        gateways_half=2,
        gateways_most=1,
        outsider_packets=60,
        sole_path_packets=20,
        only_gateway_origins=1,
        nodes=fleet.nodes,
    )
    assert [n.node for n in fleet.nodes] == [_N, "d00000e4"]
    assert fleet.nodes[0].level is Level.HIGH
