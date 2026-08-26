"""Tests for meshprovision.nodeid."""

from __future__ import annotations

import random

import pytest

from meshprovision.errors import NodeIdError
from meshprovision.nodeid import BROADCAST, NODE_ID_MAX, NodeId

pytestmark = pytest.mark.unit

_CORPUS = (0, 1, 0xFFFF, 0xDEADBE01, 0xA0CB5CC4, 0x12345E78, NODE_ID_MAX)


def _assert_all_forms_agree(num: int) -> None:
    nid = NodeId(num)
    assert NodeId.from_hex(nid.hex) == nid
    assert NodeId.from_hex(nid.display) == nid
    assert NodeId.from_display(nid.display) == nid
    assert NodeId.from_decimal(nid.decimal) == nid
    assert NodeId.from_decimal(num) == nid
    assert NodeId.from_int(num) == nid
    assert len(nid.hex) == 8
    assert nid.hex == nid.hex.lower()
    assert nid.db_value == nid.hex
    assert str(nid) == nid.display
    assert repr(nid) == f"NodeId({nid.display!r})"
    assert int(nid) == num


@pytest.mark.parametrize("num", _CORPUS)
def test_round_trip_corpus(num: int) -> None:
    _assert_all_forms_agree(num)


def test_round_trip_property_sweep() -> None:
    rng = random.Random(20260825)  # noqa: S311 -- deterministic property sweep, not crypto
    for _ in range(500):
        num = rng.randint(0, NODE_ID_MAX)
        _assert_all_forms_agree(num)
        nid = NodeId(num)
        assert NodeId.parse(nid.display) == nid
        assert NodeId.parse(num) == nid


def test_parse_ambiguity_eight_hex_wins_over_decimal() -> None:
    assert NodeId.parse("12345678") == NodeId(0x12345678)
    assert NodeId.parse("3735928321") == NodeId.from_hex("deadbe01")


def test_parse_case_and_prefix_tolerance() -> None:
    expected = NodeId(0xA0CB5CC4)
    assert NodeId.parse("!A0CB5CC4") == expected
    assert NodeId.parse("0xA0CB5CC4") == expected
    assert NodeId.parse(" a0cb5cc4 ") == expected
    assert NodeId.parse("5cc4") == NodeId(0x5CC4)


@pytest.mark.parametrize(
    "raw",
    [
        True,
        False,
        3.5,
        "",
        "deadbeef1",
        "zzzz",
        "١٢٣",
        2**32,
    ],
)
def test_parse_errors(raw: object) -> None:
    with pytest.raises(NodeIdError):
        NodeId.parse(raw)


def test_from_int_negative_out_of_range_errors() -> None:
    with pytest.raises(NodeIdError):
        NodeId.from_int(-(2**31) - 1)


def test_from_int_negative_one_is_broadcast_two_complement() -> None:
    assert NodeId.from_int(-1) == NodeId(NODE_ID_MAX)


def test_from_display_requires_bang_prefix() -> None:
    with pytest.raises(NodeIdError):
        NodeId.from_display("a0cb5cc4")


def test_try_parse_returns_none_on_failure() -> None:
    assert NodeId.try_parse(object()) is None
    assert NodeId.try_parse("garbage!!") is None
    assert NodeId.try_parse("!a0cb5cc4") == NodeId(0xA0CB5CC4)


def test_broadcast_and_unset() -> None:
    assert BROADCAST.is_broadcast
    assert BROADCAST.num == NODE_ID_MAX
    assert NodeId(0).is_unset
    assert not NodeId(1).is_unset


def test_ordering_hashing_and_container_usage() -> None:
    values = [NodeId(5), NodeId(1), NodeId(3)]
    assert sorted(values) == [NodeId(1), NodeId(3), NodeId(5)]
    s = {NodeId(1), NodeId(1), NodeId(2)}
    assert len(s) == 2
    d = {NodeId(1): "a"}
    assert d[NodeId(1)] == "a"


def test_equality_against_int_is_false() -> None:
    assert (NodeId(1) == 1) is False


def test_constructor_rejects_bool_and_out_of_range() -> None:
    with pytest.raises(NodeIdError):
        NodeId(True)  # type: ignore[arg-type]
    with pytest.raises(NodeIdError):
        NodeId(-1)
    with pytest.raises(NodeIdError):
        NodeId(NODE_ID_MAX + 1)
