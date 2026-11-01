"""The day files' JSON for one hour of region traffic: round trip and strict reading."""

from __future__ import annotations

from typing import Any

import pytest

from meshprovision.network.buckets import LastHop, Radio, RegionHour, Traffic
from meshprovision.network.hourjson import hour_from_json, hour_to_json, read_number

pytestmark = pytest.mark.unit

_HOUR = 1_792_533_600
_O, _GW = "ab446357", "bbad0594"
_FULL = RegionHour(
    _HOUR,
    Traffic(
        packets={_O: 3},
        relayed={97: {_GW: Radio(2, 1, -7.25, -118)}},
        direct={_O: {_GW: Radio(1, 1, 6.5, -90)}},
        last_hops={_O: {97: LastHop(2, 1)}},
        sole_relay={_O: {97: 1}},
        only_gateway={_O: {_GW: 1}},
        edges={("11111111", _O, "t"): 2, ("11111111", _O, "n"): 1},
        unrelayed=4,
    ),
)
_FULL_JSON: dict[str, Any] = {
    "h": _HOUR,
    "pk": {_O: 3},
    "rl": {"97": {_GW: [2, 1, -7.25, -118]}},
    "dr": {_O: {_GW: [1, 1, 6.5, -90]}},
    "ob": {_O: {"97": [2, 1]}},
    "so": {_O: {"97": 1}},
    "og": {_O: {_GW: 1}},
    "ed": [["11111111", _O, "t", 2], ["11111111", _O, "n", 1]],
    "nr": 4,
}


def test_an_hour_is_written_with_short_keys_and_read_back() -> None:
    assert hour_to_json(_FULL) == _FULL_JSON
    assert hour_from_json(_FULL_JSON) == _FULL


def test_a_silent_hour_is_only_its_start() -> None:
    assert hour_to_json(RegionHour(_HOUR)) == {"h": _HOUR}
    assert hour_from_json({"h": _HOUR}) == RegionHour(_HOUR)


def test_snr_sums_are_rounded_to_a_hundredth() -> None:
    bucket = RegionHour(_HOUR, Traffic(direct={_O: {_GW: Radio(3, 3, 1.0 / 3, -100)}}))

    assert hour_to_json(bucket)["dr"] == {_O: {_GW: [3, 3, 0.33, -100]}}


def test_read_maps_are_immutable() -> None:
    read = hour_from_json(_FULL_JSON)

    assert read is not None
    with pytest.raises(TypeError):
        read.traffic.relayed[97] = {}  # type: ignore[index]
    with pytest.raises(TypeError):
        read.traffic.edges[("a", "b", "t")] = 1  # type: ignore[index]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        pytest.param("h", _HOUR + 1, id="hour-not-on-the-hour"),
        pytest.param("h", -3600, id="negative-hour"),
        pytest.param("h", True, id="hour-bool"),
        pytest.param("h", None, id="no-hour"),
        pytest.param("pk", {"AB446357": 1}, id="uppercase-id"),
        pytest.param("pk", {_O: True}, id="count-bool"),
        pytest.param("pk", {_O: -1}, id="negative-count"),
        pytest.param("pk", [], id="packets-not-an-object"),
        pytest.param("rl", {"0": {_GW: [1, 0, 0, 0]}}, id="relay-byte-0"),
        pytest.param("rl", {"256": {_GW: [1, 0, 0, 0]}}, id="relay-byte-256"),
        pytest.param("rl", {"097": {_GW: [1, 0, 0, 0]}}, id="relay-byte-not-canonical"),
        pytest.param("rl", {"97": {_GW: [1, 2, 0, 0]}}, id="more-measured-than-receptions"),
        pytest.param("rl", {"97": {_GW: [1, 1, 50.5, -1]}}, id="snr-sum-out-of-range"),
        pytest.param("rl", {"97": {_GW: [1, 1, float("nan"), -1]}}, id="snr-sum-nan"),
        pytest.param("rl", {"97": {_GW: [1, 1, 0, 1]}}, id="rssi-sum-positive"),
        pytest.param("rl", {"97": {_GW: [1, 1, 0, -201]}}, id="rssi-sum-too-low"),
        pytest.param("rl", {"97": {_GW: [1, 1, 0, -1.5]}}, id="rssi-sum-not-an-int"),
        pytest.param("rl", {"97": {_GW: [1, 1, 0, False]}}, id="rssi-sum-bool"),
        pytest.param("rl", {"97": {_GW: [1, 1, 0]}}, id="radio-too-short"),
        pytest.param("dr", {_O: [1, 1, 0, -1]}, id="direct-not-nested"),
        pytest.param("ob", {_O: {"97": [1, 2]}}, id="more-first-hops-than-receptions"),
        pytest.param("ob", {_O: {"97": [1]}}, id="last-hop-too-short"),
        pytest.param("so", {_O: {"x": 1}}, id="sole-relay-bad-byte"),
        pytest.param("og", {_O: {"gw": 1}}, id="only-gateway-bad-id"),
        pytest.param("ed", [[_O, "11111111", "t", 1]], id="edge-not-ordered"),
        pytest.param("ed", [[_O, _O, "t", 1]], id="edge-to-itself"),
        pytest.param("ed", [["11111111", _O, "x", 1]], id="edge-unknown-source"),
        pytest.param("ed", [["11111111", _O, "t", 0]], id="edge-never-seen"),
        pytest.param("ed", [["11111111", _O, "t"]], id="edge-too-short"),
        pytest.param("ed", {"a": 1}, id="edges-not-a-list"),
        pytest.param("nr", -1, id="negative-unrelayed"),
    ],
)
def test_a_malformed_field_makes_the_whole_hour_unusable(key: str, value: object) -> None:
    assert hour_from_json({**_FULL_JSON, key: value}) is None


def test_an_hour_that_is_not_an_object_is_unusable() -> None:
    assert hour_from_json([_HOUR]) is None


def test_a_number_too_large_for_a_float_is_not_a_number() -> None:
    assert read_number(10**400, 0, float("inf")) is None
