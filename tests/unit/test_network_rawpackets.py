"""Parsing lorastats ``PacketsRaw`` rows (synthetic rows shaped like real answers)."""

from __future__ import annotations

import base64
from typing import Any

import pytest
from meshtastic.protobuf import portnums_pb2

from meshprovision.network.rawpackets import (
    AdvertisedKey,
    NeighborObservation,
    ParsedRaw,
    RawReception,
    RouteObservation,
    parse_raw,
)
from meshprovision.nodeid import NodeId
from tests.unit.network_fixtures import (
    BROADCAST,
    NOW,
    T0,
    neighbor_info,
    node_info,
    packet,
    row,
    traceroute,
)

pytestmark = pytest.mark.unit

_ORIGIN = 0xAB446357
_GATEWAY = NodeId.from_hex("bbad0594")
_KEY = bytes(range(1, 33))


def _one(**fields: Any) -> RawReception:
    parsed = parse_raw([row(packet(_ORIGIN, 77, **fields))], now=NOW)
    assert parsed.skipped == 0
    (reception,) = parsed.receptions
    return reception


def test_a_relayed_encrypted_reception_is_read_field_by_field() -> None:
    parsed = parse_raw(
        [row(packet(_ORIGIN, 77, relay=0x61, hop_start=5, hop_limit=3, snr=-7.25, rssi=-118))],
        now=NOW,
    )

    assert parsed == ParsedRaw(
        receptions=(
            RawReception(
                time=T0,
                gateway=_GATEWAY,
                origin=NodeId(_ORIGIN),
                packet_id=77,
                relay=0x61,
                hop_start=5,
                hop_limit=3,
                snr=-7.25,
                rssi=-118,
                port=None,
            ),
        )
    )
    assert parsed.receptions[0].hops_taken == 2


def test_a_time_with_an_offset_is_honoured() -> None:
    data = row(packet(_ORIGIN, 77))["Data"]

    parsed = parse_raw(
        [{"Time": "2026-10-20T20:15:00+00:00", "Gateway": "bbad0594", "Data": data}], now=NOW
    )

    assert parsed.receptions[0].time == T0


@pytest.mark.parametrize(
    ("fields", "hops", "relayed", "direct"),
    [
        pytest.param({}, 0, False, True, id="own-byte-no-hop"),
        pytest.param({"relay": 0x61, "hop_limit": 2}, 1, True, False, id="relayed"),
        pytest.param({"hop_limit": 2}, 1, False, False, id="own-byte-after-a-hop-is-a-collision"),
        pytest.param({"relay": 0}, 0, False, False, id="no-relay-byte"),
        pytest.param({"hop_start": 0}, None, False, True, id="no-hop-start-own-byte"),
        pytest.param({"hop_start": 2, "hop_limit": 3}, None, False, True, id="limit-above-start"),
        pytest.param({"hop_start": 0, "relay": 0x61}, None, True, False, id="no-hop-start-relayed"),
    ],
)
def test_hops_relayed_and_strict_direct(
    fields: dict[str, int], hops: int | None, relayed: bool, direct: bool
) -> None:
    reception = _one(**fields)

    assert (reception.hops_taken, reception.is_relayed, reception.is_direct) == (
        hops,
        relayed,
        direct,
    )


@pytest.mark.parametrize(
    ("fields", "attribute", "expected"),
    [
        pytest.param({"hop_limit": 8}, "hop_limit", None, id="hop-limit-8"),
        pytest.param({"hop_limit": 0}, "hop_limit", 0, id="hop-limit-0-kept"),
        pytest.param({"hop_start": 8}, "hop_start", None, id="hop-start-8"),
        pytest.param({"hop_start": 7, "hop_limit": 7}, "hop_start", 7, id="hop-start-7-kept"),
        pytest.param({"hop_start": 0}, "hop_start", None, id="hop-start-0-is-unknown"),
        pytest.param({"relay": 0}, "relay", None, id="relay-0-is-unknown"),
        pytest.param({"relay": 255}, "relay", 255, id="relay-255-kept"),
        pytest.param({"relay": 256}, "relay", None, id="relay-256"),
        pytest.param({"snr": 50.0}, "snr", 50.0, id="snr-50-kept"),
        pytest.param({"snr": -50.0}, "snr", -50.0, id="snr-minus-50-kept"),
        pytest.param({"snr": 50.5}, "snr", None, id="snr-above-50"),
        pytest.param({"snr": -50.5}, "snr", None, id="snr-below-minus-50"),
        pytest.param({"snr": float("nan")}, "snr", None, id="snr-nan"),
        pytest.param({"snr": 0.0}, "snr", 0.0, id="snr-0-with-rssi-kept"),
        pytest.param({"snr": 0.0, "rssi": 0}, "snr", None, id="snr-0-without-rssi-unknown"),
        pytest.param({"snr": 4.0, "rssi": 0}, "snr", 4.0, id="snr-without-rssi-kept"),
        pytest.param({"rssi": 0}, "rssi", None, id="rssi-0-is-unknown"),
        pytest.param({"rssi": -200}, "rssi", -200, id="rssi-minus-200-kept"),
        pytest.param({"rssi": -1}, "rssi", -1, id="rssi-minus-1-kept"),
        pytest.param({"rssi": -201}, "rssi", None, id="rssi-below-minus-200"),
        pytest.param({"rssi": 28}, "rssi", None, id="rssi-positive"),
    ],
)
def test_out_of_range_values_are_kept_as_none(
    fields: dict[str, Any], attribute: str, expected: object
) -> None:
    assert getattr(_one(**fields), attribute) == expected


def _bad_rows() -> list[pytest.ParameterSet]:
    good = row(packet(_ORIGIN, 77))
    return [
        pytest.param("not an object", id="not-an-object"),
        pytest.param({**good, "Time": None}, id="no-time"),
        pytest.param({**good, "Time": "yesterday"}, id="bad-time"),
        pytest.param(row(packet(_ORIGIN, 77), time=NOW + 301), id="future-time"),
        pytest.param({**good, "Gateway": "nothex!!"}, id="bad-gateway"),
        pytest.param({**good, "Gateway": 12345}, id="gateway-not-a-string"),
        pytest.param({**good, "Gateway": "ffffffff"}, id="gateway-broadcast"),
        pytest.param({**good, "Gateway": "0"}, id="gateway-zero"),
        pytest.param({**good, "Data": None}, id="no-data"),
        pytest.param({**good, "Data": "@@@@"}, id="bad-base64"),
        pytest.param({**good, "Data": "!" + str(good["Data"])}, id="base64-with-a-stray-character"),
        pytest.param({**good, "Data": base64.b64encode(b"\xff\xff").decode()}, id="not-protobuf"),
        pytest.param(row(packet(0, 77)), id="from-zero"),
        pytest.param(row(packet(BROADCAST, 77)), id="from-broadcast"),
        pytest.param(row(packet(_ORIGIN, 0)), id="id-zero"),
    ]


@pytest.mark.parametrize("bad", _bad_rows())
def test_an_unusable_row_is_skipped_and_counted(bad: object) -> None:
    parsed = parse_raw([bad, row(packet(_ORIGIN, 78))], now=NOW)

    assert parsed.skipped == 1
    assert [r.packet_id for r in parsed.receptions] == [78]


def test_a_time_just_inside_the_future_skew_is_kept() -> None:
    parsed = parse_raw([row(packet(_ORIGIN, 77), time=NOW + 300)], now=NOW)

    assert len(parsed.receptions) == 1


@pytest.mark.parametrize(("padding", "kept"), [(727, True), (728, False)])
def test_data_longer_than_1024_characters_is_skipped(padding: int, kept: bool) -> None:
    built = packet(_ORIGIN, 77, encrypted=b"x" * padding)
    data = row(built)["Data"]

    parsed = parse_raw([row(built)], now=NOW)

    assert (len(str(data)) <= 1024) is kept
    assert (len(parsed.receptions), parsed.skipped) == ((1, 0) if kept else (0, 1))


def test_a_repeated_uplink_is_kept_once_and_not_counted() -> None:
    first = row(packet(_ORIGIN, 77))
    other_gateway = row(packet(_ORIGIN, 77), gateway="0192b5f8")

    parsed = parse_raw([first, first, other_gateway, row(packet(_ORIGIN, 78))], now=NOW)

    assert [(r.gateway.hex, r.packet_id) for r in parsed.receptions] == [
        ("bbad0594", 77),
        ("0192b5f8", 77),
        ("bbad0594", 78),
    ]
    assert parsed.skipped == 0


def test_a_decoded_packet_has_its_port() -> None:
    reception = _one(port=portnums_pb2.TEXT_MESSAGE_APP, payload=b"hi")

    assert reception.port == portnums_pb2.TEXT_MESSAGE_APP


def _key_packet(packet_id: int = 77, **info: Any) -> dict[str, object]:
    port, payload = node_info(_ORIGIN, info.pop("key", _KEY), **info)
    return row(packet(_ORIGIN, packet_id, port=port, payload=payload))


def test_a_node_info_key_is_read_with_names_and_enums() -> None:
    parsed = parse_raw([_key_packet()], now=NOW)

    assert parsed.keys == (
        AdvertisedKey(
            time=T0,
            node=NodeId(_ORIGIN),
            public_key=_KEY,
            short_name="AB12",
            hw_model="HELTEC_V3",
            role="ROUTER",
        ),
    )
    assert parsed.bad_keys == 0


def test_a_node_info_heard_by_two_gateways_gives_one_key() -> None:
    port, payload = node_info(_ORIGIN, _KEY)
    built = packet(_ORIGIN, 77, port=port, payload=payload)

    parsed = parse_raw([row(built), row(built, gateway="0192b5f8")], now=NOW)

    assert len(parsed.receptions) == 2
    assert len(parsed.keys) == 1


def test_a_node_info_first_uplinked_encrypted_is_read_from_its_decoded_row() -> None:
    port, payload = node_info(_ORIGIN, _KEY)
    encrypted = packet(_ORIGIN, 77)
    decoded = packet(_ORIGIN, 77, port=port, payload=payload)

    parsed = parse_raw(
        [row(encrypted), row(decoded, gateway="0192b5f8"), row(decoded, gateway="435784c4")],
        now=NOW,
    )

    assert [r.port for r in parsed.receptions] == [None, port, port]
    assert len(parsed.keys) == 1


@pytest.mark.parametrize(("length", "bad"), [(31, 1), (33, 1), (0, 0)])
def test_a_key_that_is_not_32_bytes_is_skipped(length: int, bad: int) -> None:
    parsed = parse_raw([_key_packet(key=b"k" * length)], now=NOW)

    assert (parsed.keys, parsed.bad_keys) == ((), bad)
    assert len(parsed.receptions) == 1


@pytest.mark.parametrize(
    ("user_id", "kept"),
    [("!ab446357", True), ("!AB446357", True), ("", True), ("!12345678", False)],
)
def test_a_node_info_must_name_its_sender(user_id: str, kept: bool) -> None:
    parsed = parse_raw([_key_packet(user_id=user_id)], now=NOW)

    assert len(parsed.keys) == int(kept)


@pytest.mark.parametrize(
    ("short_name", "expected"),
    [
        ("   ", None),
        ("x" * 80, "x" * 64),
        ("a\x1bb", "a\\x1bb"),
        ("\x1b" * 17, ("\\x1b" * 17)[:64]),
    ],
)
def test_a_short_name_is_trimmed_capped_and_terminal_safe(
    short_name: str, expected: str | None
) -> None:
    (key,) = parse_raw([_key_packet(short_name=short_name)], now=NOW).keys

    assert key.short_name == expected


def test_unknown_enum_numbers_are_none() -> None:
    (key,) = parse_raw([_key_packet(hw_model=9999, role=999)], now=NOW).keys

    assert (key.hw_model, key.role) == (None, None)


def test_an_undecodable_payload_is_ignored_but_the_reception_kept() -> None:
    built = packet(_ORIGIN, 77, port=portnums_pb2.NODEINFO_APP, payload=b"\xff\xff")

    parsed = parse_raw([row(built)], now=NOW)

    assert (len(parsed.receptions), parsed.keys, parsed.skipped) == (1, (), 0)


def _route_packet(route: list[int], *, request_id: int = 0, to: int = 0x11111111) -> object:
    port, payload = traceroute(route)
    return row(packet(_ORIGIN, 77, to=to, port=port, payload=payload, request_id=request_id))


def test_a_traceroute_request_is_its_sender_then_the_relays() -> None:
    parsed = parse_raw([_route_packet([0x22222222, 0x33333333])], now=NOW)

    assert parsed.routes == (
        RouteObservation(T0, (NodeId(_ORIGIN), NodeId(0x22222222), NodeId(0x33333333))),
    )


def test_a_traceroute_reply_runs_from_the_requester_to_the_sender() -> None:
    parsed = parse_raw([_route_packet([0x22222222], request_id=5, to=0x11111111)], now=NOW)

    assert parsed.routes[0].path == (NodeId(0x11111111), NodeId(0x22222222), NodeId(_ORIGIN))


def test_an_unrecorded_hop_splits_the_route_and_a_lone_node_is_dropped() -> None:
    parsed = parse_raw(
        [_route_packet([0x22222222, BROADCAST, 0x33333333, 0x44444444, 0, 0x55555555])], now=NOW
    )

    assert [route.path for route in parsed.routes] == [
        (NodeId(_ORIGIN), NodeId(0x22222222)),
        (NodeId(0x33333333), NodeId(0x44444444)),
    ]


def test_a_traceroute_without_relays_gives_no_route() -> None:
    assert parse_raw([_route_packet([])], now=NOW).routes == ()


def _neighbor_packet(node: int, neighbors: list[int]) -> object:
    port, payload = neighbor_info(node, neighbors)
    return row(packet(_ORIGIN, 77, port=port, payload=payload))


@pytest.mark.parametrize("reported", [_ORIGIN, 0])
def test_a_neighbor_report_names_valid_neighbors_other_than_the_sender(reported: int) -> None:
    parsed = parse_raw(
        [_neighbor_packet(reported, [0x22222222, 0, BROADCAST, _ORIGIN, 0x33333333])], now=NOW
    )

    assert parsed.neighbors == (
        NeighborObservation(T0, NodeId(_ORIGIN), (NodeId(0x22222222), NodeId(0x33333333))),
    )


@pytest.mark.parametrize(
    ("reported", "neighbors"),
    [
        pytest.param(0x12345678, [0x22222222], id="someone-elses-report"),
        pytest.param(_ORIGIN, [0, BROADCAST], id="no-valid-neighbor"),
    ],
)
def test_a_neighbor_report_is_dropped(reported: int, neighbors: list[int]) -> None:
    assert parse_raw([_neighbor_packet(reported, neighbors)], now=NOW).neighbors == ()


def test_no_rows_parse_to_nothing() -> None:
    assert parse_raw([], now=NOW) == ParsedRaw()
