"""Relay-byte resolution: candidates, coverage, radio distance and each confidence rule."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from meshprovision.datasources.models import NodeObservation
from meshprovision.network.buckets import Radio, Traffic
from meshprovision.network.resolve import (
    CandidateScore,
    Confidence,
    LearnedRelay,
    Resolution,
    relay_candidates,
    resolve_relays,
)
from meshprovision.nodeid import NodeId
from tests.unit.network_fixtures import NOW

pytestmark = pytest.mark.unit

_B = 0x61
_RELAY, _OTHER, _THIRD = "c464e761", "11111161", "22222261"
_G1, _G2, _G3 = "aaaaaa01", "aaaaaa02", "aaaaaa03"


def _radio(n: int, snr: float, rssi: float) -> Radio:
    """``n`` measured receptions with these means."""
    return Radio(n, n, snr * n, round(rssi * n))


def _resolve(
    relayed: dict[str, Radio],
    direct: dict[str, dict[str, Radio]],
    candidates: tuple[str, ...] | None = None,
    learned: dict[int, LearnedRelay] | None = None,
) -> Resolution:
    traffic = Traffic(relayed={_B: relayed}, direct=direct)
    names = tuple(direct) if candidates is None else candidates
    return resolve_relays(traffic, {_B: names}, learned=learned)[_B]


def test_a_matching_fingerprint_is_high() -> None:
    resolution = _resolve(
        {_G1: _radio(10, -5.0, -100), _G2: _radio(10, 2.0, -80)},
        {_RELAY: {_G1: _radio(3, -5.5, -101), _G2: _radio(3, 2.0, -80)}},
    )

    assert resolution == Resolution(
        _B, Confidence.HIGH, _RELAY, (CandidateScore(_RELAY, 1.0, pytest.approx(0.5)),)
    )


def test_a_collision_is_resolved_by_coverage_and_radio() -> None:
    resolution = _resolve(
        {_G1: _radio(98, -10.0, -110), _G2: _radio(2, 5.0, -70)},
        {
            _RELAY: {_G1: _radio(5, -10.0, -110)},
            _OTHER: {_G2: _radio(5, 5.0, -70)},
        },
    )

    assert (resolution.confidence, resolution.node) == (Confidence.HIGH, _RELAY)
    assert [(c.node, c.coverage) for c in resolution.candidates] == [
        (_RELAY, 0.98),
        (_OTHER, 0.02),
    ]


def test_a_close_rival_makes_it_ambiguous() -> None:
    resolution = _resolve(
        {_G1: _radio(10, -5.0, -100), _G2: _radio(10, 0.0, -90)},
        {
            _RELAY: {_G1: _radio(3, -5.0, -100), _G2: _radio(3, 0.0, -90)},
            _OTHER: {_G1: _radio(3, -6.0, -100)},
        },
    )

    assert resolution == Resolution(
        _B,
        Confidence.AMBIGUOUS,
        None,
        (CandidateScore(_RELAY, 1.0, 0.0), CandidateScore(_OTHER, 0.5, 1.0)),
    )


@pytest.mark.parametrize(("rival_snr", "label"), [(-9.0, Confidence.HIGH), (-8.9, None)])
def test_a_rival_at_least_four_db_farther_does_not_compete(
    rival_snr: float, label: Confidence | None
) -> None:
    resolution = _resolve(
        {_G1: _radio(10, -5.0, -100)},
        {_RELAY: {_G1: _radio(3, -5.0, -100)}, _OTHER: {_G1: _radio(3, rival_snr, -100)}},
    )

    assert resolution.confidence is (label or Confidence.AMBIGUOUS)


@pytest.mark.parametrize(
    ("rival_receptions", "label"), [(33, Confidence.HIGH), (34, Confidence.AMBIGUOUS)]
)
def test_a_rival_covering_a_third_of_the_best_competes(
    rival_receptions: int, label: Confidence
) -> None:
    resolution = _resolve(
        {_G1: _radio(100 - rival_receptions, -5.0, -100), _G2: _radio(rival_receptions, 0, -90)},
        {
            _RELAY: {_G1: _radio(3, -5.0, -100), _G2: _radio(3, 0, -90)},
            _OTHER: {_G2: _radio(3, 0, -90)},
        },
    )

    assert resolution.confidence is label


@pytest.mark.parametrize(("rssi", "label"), [(-108, Confidence.HIGH), (-109, Confidence.AMBIGUOUS)])
def test_the_distance_counts_rssi_at_half_and_allows_four_db(rssi: int, label: Confidence) -> None:
    resolution = _resolve({_G1: _radio(10, -5.0, -100)}, {_RELAY: {_G1: _radio(3, -5.0, rssi)}})

    assert resolution.confidence is label


@pytest.mark.parametrize(("covered", "label"), [(50, Confidence.HIGH), (49, Confidence.MEDIUM)])
def test_half_the_relayed_receptions_is_enough_coverage(covered: int, label: Confidence) -> None:
    resolution = _resolve(
        {_G1: _radio(covered, -5.0, -100), _G2: _radio(100 - covered, 0, -90)},
        {_RELAY: {_G1: _radio(3, -5.0, -100)}},
    )

    assert (resolution.confidence, resolution.node) == (label, _RELAY)


def test_the_only_candidate_without_radio_evidence_is_medium() -> None:
    resolution = _resolve({_G1: Radio(10)}, {_RELAY: {}})

    assert resolution == Resolution(
        _B, Confidence.MEDIUM, _RELAY, (CandidateScore(_RELAY, 0.0, None),)
    )


def test_the_only_candidate_whose_radio_contradicts_it_is_ambiguous() -> None:
    resolution = _resolve({_G1: _radio(10, -5.0, -100)}, {_RELAY: {_G1: _radio(3, 7.0, -100)}})

    assert (resolution.confidence, resolution.node) == (Confidence.AMBIGUOUS, None)
    assert resolution.candidates == (CandidateScore(_RELAY, 1.0, 12.0),)


def test_full_coverage_without_radio_overlap_and_no_rival_is_medium() -> None:
    resolution = _resolve(
        {_G1: Radio(10)},
        {_RELAY: {_G1: _radio(3, -5.0, -100)}, _OTHER: {}},
    )

    assert (resolution.confidence, resolution.node) == (Confidence.MEDIUM, _RELAY)


def test_full_coverage_with_a_contradicting_radio_and_a_rival_is_ambiguous() -> None:
    resolution = _resolve(
        {_G1: _radio(10, -5.0, -100)},
        {_RELAY: {_G1: _radio(3, 7.0, -100)}, _OTHER: {}},
    )

    assert resolution.confidence is Confidence.AMBIGUOUS


def test_a_byte_without_candidates_is_unknown() -> None:
    assert _resolve({_G1: Radio(3)}, {}, candidates=()) == Resolution(_B, Confidence.UNKNOWN, None)


def test_a_gateway_with_one_measured_relayed_reception_is_not_compared() -> None:
    resolution = _resolve(
        {_G1: _radio(10, -5.0, -100), _G2: _radio(1, 9.0, -60)},
        {_RELAY: {_G1: _radio(3, -5.0, -100), _G2: _radio(3, -9.0, -100)}},
    )

    assert resolution.candidates == (CandidateScore(_RELAY, 1.0, 0.0),)


def test_a_gateway_weighs_at_most_fifty_receptions() -> None:
    resolution = _resolve(
        {_G1: _radio(1000, -5.0, -100), _G2: _radio(50, 0.0, -90)},
        {_RELAY: {_G1: _radio(3, -5.0, -100), _G2: _radio(3, 10.0, -90)}},
    )

    assert resolution.candidates == (CandidateScore(_RELAY, 1.0, 5.0),)
    assert resolution.confidence is Confidence.AMBIGUOUS


def test_the_candidate_as_a_gateway_covers_but_is_not_compared() -> None:
    resolution = _resolve(
        {_RELAY: _radio(5, 9.0, -60), _G1: _radio(5, -5.0, -100)},
        {_RELAY: {_RELAY: _radio(5, -20.0, -130), _G1: _radio(3, -5.0, -100)}},
    )

    assert resolution.candidates == (CandidateScore(_RELAY, 1.0, 0.0),)


def test_an_unmeasured_direct_reception_is_not_compared() -> None:
    resolution = _resolve({_G1: _radio(10, -5.0, -100)}, {_RELAY: {_G1: Radio(3)}})

    assert resolution.candidates == (CandidateScore(_RELAY, 1.0, None),)


def test_equal_candidates_are_ranked_by_id() -> None:
    resolution = _resolve({_G1: Radio(10)}, {_THIRD: {}, _OTHER: {}})

    assert [c.node for c in resolution.candidates] == [_OTHER, _THIRD]


def test_coverage_ranks_before_distance() -> None:
    resolution = _resolve(
        {_G1: _radio(10, -5.0, -100), _G2: _radio(90, 0.0, -90)},
        {_OTHER: {_G1: _radio(3, -5.0, -100)}, _RELAY: {_G2: _radio(3, 3.0, -90)}},
    )

    assert [c.node for c in resolution.candidates] == [_RELAY, _OTHER]
    assert (resolution.confidence, resolution.node) == (Confidence.HIGH, _RELAY)


_AMBIGUOUS = (
    {_G1: _radio(10, -5.0, -100)},
    {_RELAY: {_G1: _radio(3, -5.0, -100)}, _OTHER: {_G1: _radio(3, -5.5, -100)}},
)


def test_a_learned_node_still_a_candidate_makes_an_ambiguous_byte_medium() -> None:
    learned = {_B: LearnedRelay(_OTHER, NOW - 3600)}

    resolution = _resolve(*_AMBIGUOUS, learned=learned)

    assert (resolution.confidence, resolution.node, resolution.learned_at) == (
        Confidence.MEDIUM,
        _OTHER,
        NOW - 3600,
    )


def test_a_learned_node_no_longer_a_candidate_is_ignored() -> None:
    learned = {_B: LearnedRelay(_THIRD, NOW)}

    assert _resolve(*_AMBIGUOUS, learned=learned).confidence is Confidence.AMBIGUOUS


def test_a_learned_node_never_overrides_todays_evidence() -> None:
    learned = {_B: LearnedRelay(_OTHER, NOW)}

    resolution = _resolve(
        {_G1: _radio(10, -5.0, -100)},
        {_RELAY: {_G1: _radio(3, -5.0, -100)}, _OTHER: {}},
        learned=learned,
    )

    assert (resolution.confidence, resolution.node, resolution.learned_at) == (
        Confidence.HIGH,
        _RELAY,
        None,
    )


def test_only_bytes_with_relayed_receptions_are_resolved() -> None:
    traffic = Traffic(relayed={1: {_G1: Radio(1)}, 2: {_G1: Radio(1)}})

    resolved = resolve_relays(traffic, {2: ("aaaaaa02",), 3: ("aaaaaa03",)})

    assert {byte: r.confidence for byte, r in resolved.items()} == {
        1: Confidence.UNKNOWN,
        2: Confidence.MEDIUM,
    }


def _observation(
    hex_id: str, *, role: str | None = None, seen: float | None = None
) -> NodeObservation:
    return NodeObservation(
        node_id=NodeId.from_hex(hex_id),
        source="lorastats",
        observed_at=datetime.fromtimestamp(NOW, tz=UTC),
        role=role,
        last_seen=None if seen is None else datetime.fromtimestamp(seen, tz=UTC),
    )


def test_candidates_are_the_nodes_heard_in_the_window_by_byte() -> None:
    traffic = Traffic(
        packets={"000000a1": 1},
        relayed={0xB2: {"000000c3": Radio(1)}},
        direct={"000000a1": {"000001c3": Radio(1)}},
        only_gateway={"000000a1": {"000002c3": 1}},
    )
    nodes = [
        _observation("000003c3", seen=NOW - 10),
        _observation("000004c3", seen=NOW - 3600 - 1),
        _observation("000005c3"),
        _observation("000006a1", role="CLIENT_MUTE", seen=NOW),
        _observation("000000c3", role="CLIENT_MUTE"),
    ]

    candidates = relay_candidates(traffic, nodes, start=NOW - 3600)

    assert candidates == {
        0xA1: ("000000a1",),
        0xC3: ("000001c3", "000002c3", "000003c3"),
    }


def test_a_last_seen_exactly_at_the_start_is_heard() -> None:
    nodes = [_observation("000003c3", seen=NOW - 3600)]

    assert relay_candidates(Traffic(), nodes, start=NOW - 3600) == {0xC3: ("000003c3",)}


def test_at_equal_distance_the_larger_coverage_ranks_first() -> None:
    resolution = _resolve(
        {_G1: Radio(40), _G2: Radio(60)},
        {_OTHER: {_G2: Radio(1)}, _RELAY: {_G1: Radio(1), _G2: Radio(1)}},
    )

    assert [(c.node, c.coverage) for c in resolution.candidates] == [(_RELAY, 1.0), (_OTHER, 0.6)]


def test_without_radio_overlap_a_rival_covering_a_third_makes_it_ambiguous() -> None:
    resolution = _resolve(
        {_G1: Radio(10), _G2: Radio(10)},
        {_RELAY: {_G1: Radio(1), _G2: Radio(1)}, _OTHER: {_G2: Radio(1)}},
    )

    assert resolution.confidence is Confidence.AMBIGUOUS


def test_a_rival_covering_exactly_a_third_competes() -> None:
    resolution = _resolve(
        {_G1: _radio(25, -5.0, -100), _G2: _radio(50, -5.0, -100), _G3: _radio(25, 0.0, -90)},
        {
            _RELAY: {_G1: _radio(3, -5.0, -100), _G2: _radio(3, -5.0, -100)},
            _OTHER: {_G3: _radio(3, 0.0, -90)},
        },
    )

    assert [c.coverage for c in resolution.candidates] == [0.75, 0.25]
    assert resolution.confidence is Confidence.AMBIGUOUS


def test_a_rival_without_a_distance_to_compare_competes() -> None:
    resolution = _resolve(
        {_G1: _radio(10, -5.0, -100), _G2: Radio(10)},
        {_RELAY: {_G1: _radio(3, -5.0, -100)}, _OTHER: {_G2: Radio(1)}},
    )

    assert resolution.candidates == (
        CandidateScore(_RELAY, 0.5, 0.0),
        CandidateScore(_OTHER, 0.5, None),
    )
    assert resolution.confidence is Confidence.AMBIGUOUS


def test_the_candidate_as_a_gateway_covers_without_hearing_itself() -> None:
    resolution = _resolve(
        {_RELAY: Radio(5), _G1: _radio(5, -5.0, -100)},
        {_RELAY: {_G1: _radio(3, -5.0, -100)}},
    )

    assert resolution.candidates == (CandidateScore(_RELAY, 1.0, 0.0),)


def test_a_node_whose_own_node_info_says_client_mute_is_no_candidate() -> None:
    traffic = Traffic(packets={"000000a1": 1, "000001a1": 1})

    assert relay_candidates(traffic, start=NOW, mute={"000000a1"}) == {0xA1: ("000001a1",)}
