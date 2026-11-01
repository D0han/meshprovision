"""The relay table: first hops, shares, gateways relying, ordering and identity."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from meshprovision.datasources.models import NodeObservation
from meshprovision.network.buckets import LastHop, Radio, Traffic
from meshprovision.network.keys import KeySeen
from meshprovision.network.relays import (
    FirstHops,
    RelayRow,
    byte_label,
    first_hops,
    gateway_relayed,
    relay_table,
)
from meshprovision.network.resolve import Confidence, Resolution
from meshprovision.nodeid import NodeId
from tests.unit.network_fixtures import NOW

pytestmark = pytest.mark.unit

_OURS, _OUT = "d0000a01", "a1000011"
_R, _S = "c0ffee61", "bb0000bc"
_G1, _G2, _G3 = "6a000071", "6a000072", "6a000073"
_HIGH = {0x61: Resolution(0x61, Confidence.HIGH, _R), 0xBC: Resolution(0xBC, Confidence.MEDIUM, _S)}


@pytest.mark.parametrize(
    ("hops", "minimum", "sole"),
    [
        pytest.param(FirstHops(0, {"r": 9, "s": 1}), 5, "r", id="ninety-percent"),
        pytest.param(FirstHops(0, {"r": 8, "s": 1}), 5, None, id="below-ninety"),
        pytest.param(FirstHops(1, {"r": 20}), 5, None, id="heard-directly"),
        pytest.param(FirstHops(0, {"r": 4}), 5, None, id="too-few-events"),
        pytest.param(FirstHops(0, {"r": 5}), 5, "r", id="just-enough-events"),
        pytest.param(FirstHops(0, {}), 0, None, id="no-relay"),
        pytest.param(FirstHops(0, {"a": 5, "b": 5}), 5, None, id="a-tie"),
    ],
)
def test_a_sole_first_hop(hops: FirstHops, minimum: int, sole: str | None) -> None:
    assert hops.sole(minimum) == sole


def test_first_hops_count_direct_receptions_and_one_hop_relays_by_attributed_node() -> None:
    traffic = Traffic(
        direct={_OURS: {_G1: Radio(2), _G2: Radio(1)}},
        last_hops={_OURS: {0x61: LastHop(5, 4), 0xE4: LastHop(3, 2), 0xBC: LastHop(2, 0)}},
    )
    resolutions = {**_HIGH, 0xE4: Resolution(0xE4, Confidence.AMBIGUOUS, None)}

    hops = first_hops(traffic, resolutions, _OURS)

    assert hops == FirstHops(3, {_R: 4, "0xe4": 2})
    assert hops.events == 9
    assert first_hops(traffic, {}, "nobody") == FirstHops()


def test_a_byte_label_is_hex() -> None:
    assert byte_label(0x0C) == "0x0c"


def _traffic() -> Traffic:
    return Traffic(
        packets={_OURS: 10, _OUT: 30, "d0000002": 4},
        relayed={
            0x61: {_G1: Radio(30), _G2: Radio(15)},
            0xBC: {_G1: Radio(10), _G3: Radio(5)},
            0x03: {_G2: Radio(15)},
        },
        last_hops={
            _OURS: {0x61: LastHop(8, 8), 0xBC: LastHop(2, 0)},
            _OUT: {0x61: LastHop(37, 0), 0xBC: LastHop(13, 0), 0x03: LastHop(15, 15)},
        },
        sole_relay={_OURS: {0x61: 6}},
        direct={_R: {_G1: Radio(3), _G2: Radio(3)}},
    )


def test_the_default_table_shows_the_relays_carrying_ours_by_dependence() -> None:
    resolutions = {**_HIGH, 0x03: Resolution(0x03, Confidence.HIGH, "d0000c03")}

    table = relay_table(_traffic(), resolutions, [_OURS, "d0000c03", "d0000002"])

    assert (table.relayed, table.our_packets, table.our_relayed) == (75, 14, 10)
    router, collider = table.rows
    assert router == RelayRow(
        resolution=_HIGH[0x61],
        relayed=45,
        region_share=0.6,
        origins=2,
        our_receptions=8,
        our_share=0.8,
        our_origins=(_OURS,),
        our_sole_first_hop=(_OURS,),
        our_sole_path_packets=6,
        gateways_relying=2,
        max_gateway_share=0.75,
        heard_directly_by=2,
        gaps=("not in lorastats' node list", "no node info"),
    )
    assert (collider.our_receptions, collider.our_sole_first_hop) == (2, ())
    assert collider.gateways_relying == 0
    assert collider.max_gateway_share == pytest.approx(0.25)


def test_a_gateway_with_few_relayed_receptions_is_not_judged() -> None:
    table = relay_table(_traffic(), _HIGH, [_OURS], everything=True)

    collider = next(row for row in table.rows if row.resolution.byte == 0xBC)
    assert collider.max_gateway_share == pytest.approx(0.25)
    assert gateway_relayed(_traffic()) == {_G1: 40, _G2: 30, _G3: 5}


def test_everything_is_by_region_share_and_keeps_unattributed_bytes() -> None:
    resolutions = {**_HIGH, 0x03: Resolution(0x03, Confidence.AMBIGUOUS, None)}

    table = relay_table(_traffic(), resolutions, [_OURS], everything=True)

    assert [row.resolution.byte for row in table.rows] == [0x61, 0x03, 0xBC]
    ambiguous = table.rows[1]
    assert (ambiguous.role, ambiguous.gaps, ambiguous.heard_directly_by) == (None, (), 0)
    assert [row.origins for row in table.rows] == [2, 1, 2]


def test_ties_in_dependence_are_broken_by_our_receptions_then_region_share() -> None:
    traffic = Traffic(
        packets={_OURS: 1},
        relayed={1: {_G1: Radio(5)}, 2: {_G1: Radio(9)}, 3: {_G1: Radio(1)}},
        last_hops={_OURS: {1: LastHop(2), 2: LastHop(1), 3: LastHop(2)}},
    )
    resolutions = {b: Resolution(b, Confidence.HIGH, f"0000000{b}") for b in (1, 2, 3)}

    table = relay_table(traffic, resolutions, [_OURS])

    assert [row.resolution.byte for row in table.rows] == [1, 3, 2]


def test_a_sole_first_hop_on_an_unattributed_byte_belongs_to_that_byte() -> None:
    traffic = Traffic(
        packets={_OURS: 6},
        relayed={0xE4: {_G1: Radio(6)}},
        last_hops={_OURS: {0xE4: LastHop(6, 6)}},
    )
    resolutions = {0xE4: Resolution(0xE4, Confidence.AMBIGUOUS, None)}

    (row,) = relay_table(traffic, resolutions, [_OURS]).rows

    assert row.our_sole_first_hop == (_OURS,)


def test_without_our_relayed_receptions_there_is_no_share() -> None:
    table = relay_table(_traffic(), _HIGH, ["d0000002"], everything=True)

    assert all(row.our_share is None for row in table.rows)
    assert relay_table(Traffic(), {}, [_OURS]).rows == ()


def test_the_relays_health_and_identity_come_from_the_node_list_and_node_info() -> None:
    listed = NodeObservation(
        node_id=NodeId.from_hex(_R),
        source="lorastats",
        observed_at=datetime.fromtimestamp(NOW, tz=UTC),
        role="ROUTER",
        last_seen=datetime.fromtimestamp(NOW - 60, tz=UTC),
        last_boot=datetime.fromtimestamp(NOW - 86400, tz=UTC),
    )
    keys = [
        KeySeen(_R, "sha256:" + "1" * 16, NOW - 99, NOW - 90, (), derived=False),
        KeySeen(_R, "sha256:" + "2" * 16, NOW - 50, NOW - 40, (), role="CLIENT", derived=True),
        KeySeen(_S, "sha256:" + "3" * 16, NOW, NOW, (), role="ROUTER_LATE", derived=True),
    ]

    table = relay_table(_traffic(), _HIGH, [_OURS], nodes=[listed], keys=keys)

    router, collider = table.rows
    assert (router.role, router.last_seen, router.last_boot, router.gaps) == (
        "ROUTER",
        NOW - 60,
        NOW - 86400,
        (),
    )
    assert (collider.role, collider.gaps) == ("ROUTER_LATE", ("not in lorastats' node list",))


def test_a_byte_attributed_to_one_of_ours_is_never_a_row() -> None:
    table = relay_table(_traffic(), _HIGH, [_OURS, _R], everything=True)

    assert [row.resolution.byte for row in table.rows] == [0xBC]


def test_a_relay_carrying_none_of_ours_is_not_in_the_default_table() -> None:
    traffic = Traffic(
        packets={_OURS: 1},
        relayed={1: {_G1: Radio(5)}, 2: {_G1: Radio(9)}},
        last_hops={_OURS: {1: LastHop(2)}, _OUT: {2: LastHop(9)}},
    )
    resolutions = {b: Resolution(b, Confidence.HIGH, f"0000000{b}") for b in (1, 2)}

    assert [row.resolution.byte for row in relay_table(traffic, resolutions, [_OURS]).rows] == [1]


def test_a_sole_first_hop_ranks_before_more_of_our_receptions() -> None:
    traffic = Traffic(
        packets={_OURS: 6, "d0000002": 9},
        relayed={1: {_G1: Radio(6)}, 2: {_G1: Radio(9)}},
        last_hops={_OURS: {1: LastHop(6, 6)}, "d0000002": {2: LastHop(9, 0)}},
        direct={"d0000002": {_G2: Radio(1)}},
    )
    resolutions = {b: Resolution(b, Confidence.HIGH, f"0000000{b}") for b in (1, 2)}

    table = relay_table(traffic, resolutions, [_OURS, "d0000002"])

    assert [row.resolution.byte for row in table.rows] == [1, 2]


@pytest.mark.parametrize(("receptions", "judged"), [(20, True), (19, False)])
def test_a_gateway_needs_twenty_relayed_receptions_to_be_judged(
    receptions: int, judged: bool
) -> None:
    traffic = Traffic(
        packets={_OURS: 1},
        relayed={1: {_G1: Radio(receptions)}},
        last_hops={_OURS: {1: LastHop(1)}},
    )
    resolutions = {1: Resolution(1, Confidence.HIGH, "00000001")}

    (row,) = relay_table(traffic, resolutions, [_OURS]).rows

    assert (row.gateways_relying, row.max_gateway_share) == ((1, 1.0) if judged else (0, 0.0))
