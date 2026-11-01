"""loranet's ``neighbors`` lists: parsed apart, bounded, inventing nothing."""

from __future__ import annotations

import pytest

from meshprovision.datasources import loranet
from meshprovision.datasources.loranet import (
    MAX_REPORTED_NEIGHBORS,
    LoranetSource,
    ReportedNeighbor,
    parse_neighbors,
)
from meshprovision.nodeid import NodeId

pytestmark = pytest.mark.unit

_T = 1_761_000_000
_A = NodeId.from_hex("c0ffee61")
_B = NodeId.from_hex("a1000011")


def test_a_list_is_parsed_with_and_without_snr() -> None:
    parsed = parse_neighbors(
        {_A.decimal: {"snr": 6.25, "updated": _T}, _B.decimal: {"updated": _T - 60}}
    )

    assert parsed == (
        ReportedNeighbor(_A, 6.25, float(_T)),
        ReportedNeighbor(_B, None, float(_T - 60)),
    )


def test_milliseconds_are_read_as_seconds() -> None:
    (entry,) = parse_neighbors({_A.decimal: {"updated": _T * 1000}})

    assert entry.updated == float(_T)


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(None, id="null"),
        pytest.param([], id="list"),
        pytest.param("x", id="text"),
        pytest.param({"not-a-number": {"updated": _T}}, id="bad-id"),
        pytest.param({"99999999999": {"updated": _T}}, id="id-out-of-range"),
        pytest.param({_A.hex: {"updated": _T}}, id="hex-id"),
        pytest.param({_A.decimal: {"snr": 1.0}}, id="no-updated"),
        pytest.param({_A.decimal: {"updated": 0}}, id="zero-time"),
        pytest.param({_A.decimal: {"updated": True}}, id="bool-time"),
        pytest.param({_A.decimal: "x"}, id="entry-not-an-object"),
    ],
)
def test_unusable_entries_are_dropped(payload: object) -> None:
    assert parse_neighbors(payload) == ()


def test_a_non_numeric_snr_is_left_out() -> None:
    (entry,) = parse_neighbors({_A.decimal: {"snr": "loud", "updated": _T}})

    assert entry.snr is None


def test_at_most_the_first_sixty_four_are_kept() -> None:
    payload = {str(1000 + n): {"updated": _T} for n in range(MAX_REPORTED_NEIGHBORS + 10)}
    payload = {"bad": {"updated": _T}, **payload}

    parsed = parse_neighbors(payload)

    assert MAX_REPORTED_NEIGHBORS == 64
    assert len(parsed) == MAX_REPORTED_NEIGHBORS
    assert parsed[0].node == NodeId(1000)
    assert parsed[-1].node == NodeId(1000 + MAX_REPORTED_NEIGHBORS - 1)


def test_reported_neighbors_reads_the_memoized_dump_for_the_ids_asked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    index = {
        _A.decimal: {"neighbors": {_B.decimal: {"updated": _T}}},
        _B.decimal: {"neighbors": {}},
        "123": {"neighbors": {_A.decimal: {"updated": _T}}},
        "456": None,
    }
    source = object.__new__(LoranetSource)
    monkeypatch.setattr(source, "raw_index", lambda **_kwargs: index, raising=False)

    found = source.reported_neighbors([_A, _B, NodeId(123), NodeId(456), NodeId(789)])

    assert found == {
        _A: (ReportedNeighbor(_B, None, float(_T)),),
        NodeId(123): (ReportedNeighbor(_A, None, float(_T)),),
    }
    assert loranet.MAX_REPORTED_NEIGHBORS == MAX_REPORTED_NEIGHBORS


def test_an_updated_time_too_large_for_a_float_is_dropped_and_the_rest_kept() -> None:
    parsed = parse_neighbors({_A.decimal: {"updated": 10**400}, _B.decimal: {"updated": _T}})

    assert parsed == (ReportedNeighbor(_B, None, float(_T)),)


def test_an_entry_that_fails_to_parse_in_any_way_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = loranet._neighbor

    def flaky(key: object, value: object) -> ReportedNeighbor | None:
        if key == _A.decimal:
            raise ZeroDivisionError("boom")
        return real(key, value)

    monkeypatch.setattr(loranet, "_neighbor", flaky)

    parsed = parse_neighbors({_A.decimal: {"updated": _T}, _B.decimal: {"updated": _T}})

    assert parsed == (ReportedNeighbor(_B, None, float(_T)),)
