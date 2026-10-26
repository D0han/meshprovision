"""Parsing lorastats packet rows and payloads (synthetic rows shaped like real answers)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from meshprovision.health.packets import (
    DecodedPacket,
    NodeInfo,
    Reception,
    Telemetry,
    parse_decoded,
    parse_neighbor,
    parse_nodeinfo,
    parse_position,
    parse_receptions,
    parse_telemetry,
)
from meshprovision.nodeid import NodeId

pytestmark = pytest.mark.unit

_NODE = NodeId.from_hex("ab446357")
_NOW = datetime(2026, 10, 20, 21, 0, tzinfo=UTC).timestamp()
_T0 = datetime(2026, 10, 20, 20, 52, 10, tzinfo=UTC).timestamp()
"""``2026-10-20T22:52:10`` in Warsaw (CEST, UTC+2)."""


def _report(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "Time": "2026-10-20T22:52:10",
        "Gateway": "bbad0594",
        "FromNode": "ab446357",
        "ToNode": None,
        "PacketId": "d883d91d",
        "SNR": 11.5,
        "RSSI": 155,
        "HopLimit": 2,
        "RelayNode": 25,
        "NextHop": 0,
    }
    row.update(overrides)
    return row


def _parsed(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "Time": "2026-10-20T22:52:10+02:00",
        "FromNode": "ab446357",
        "ToNode": None,
        "PacketId": "d883d91d",
        "HopStart": 7,
        "WantAck": False,
        "WantResponse": False,
        "PortNum": 67,
        "BitField": 1,
        "Channel": 1003,
        "Payload": "0.79% ChUtil, 0.02% AirUtilTx, 48% Bat",
    }
    row.update(overrides)
    return row


def _one_reception(**overrides: object) -> Reception | None:
    receptions, _ = parse_receptions([_report(**overrides)], _NODE, now=_NOW)
    return receptions[0] if receptions else None


def test_a_report_row_becomes_a_reception() -> None:
    receptions, skipped = parse_receptions([_report()], _NODE, now=_NOW)

    assert receptions == (
        Reception(
            time=_T0,
            gateway="bbad0594",
            packet_id="d883d91d",
            snr=11.5,
            rssi=155,
            hop_limit=2,
            relay=25,
        ),
    )
    assert skipped == 0


def test_a_naive_time_is_warsaw_time_and_an_offset_is_honoured() -> None:
    naive = _one_reception(Time="2026-10-20T22:52:10")
    offset = _one_reception(Time="2026-10-20T20:52:10+00:00")

    assert naive is not None
    assert offset is not None
    assert naive.time == offset.time == _T0


@pytest.mark.parametrize(
    "row",
    [
        pytest.param("not a row", id="not-an-object"),
        pytest.param(_report(FromNode="979ed146"), id="another-node"),
        pytest.param(_report(FromNode=None), id="no-from-node"),
        pytest.param(_report(FromNode="zz"), id="bad-from-node"),
        pytest.param(_report(Time=None), id="no-time"),
        pytest.param(_report(Time="yesterday"), id="bad-time"),
        pytest.param(_report(PacketId=None), id="no-packet-id"),
        pytest.param(_report(PacketId="123456789"), id="long-packet-id"),
        pytest.param(_report(PacketId="d883d91g"), id="non-hex-packet-id"),
        pytest.param(_report(Gateway=None), id="no-gateway"),
        pytest.param(_report(Gateway="not-hex"), id="bad-gateway"),
    ],
)
def test_an_unusable_report_row_is_skipped_and_counted(row: object) -> None:
    receptions, skipped = parse_receptions([row, _report(PacketId="1")], _NODE, now=_NOW)

    assert [reception.packet_id for reception in receptions] == ["1"]
    assert skipped == 1


def test_a_row_too_far_in_the_future_is_skipped_but_one_within_the_skew_is_kept() -> None:
    at_limit = _NOW + 300
    beyond = datetime.fromtimestamp(at_limit + 1, tz=UTC).isoformat()
    edge = datetime.fromtimestamp(at_limit, tz=UTC).isoformat()

    receptions, skipped = parse_receptions(
        [_report(Time=beyond, PacketId="1"), _report(Time=edge, PacketId="2")], _NODE, now=_NOW
    )

    assert [reception.packet_id for reception in receptions] == ["2"]
    assert skipped == 1


def test_ids_are_normalized_and_a_repeated_reception_is_kept_once() -> None:
    rows = [
        _report(PacketId="D883D91D", Gateway="!BBAD0594"),
        _report(PacketId="d883d91d", Gateway="bbad0594", SNR=1.0),
        _report(PacketId="d883d91d", Gateway="ae6170a8"),
        _report(PacketId="5", Gateway="5"),
        _report(PacketId=" 77C1EDC1 ", Gateway="bbad0594"),
    ]

    receptions, skipped = parse_receptions(rows, _NODE, now=_NOW)

    assert [(r.packet_id, r.gateway, r.snr) for r in receptions] == [
        ("d883d91d", "bbad0594", 11.5),
        ("d883d91d", "ae6170a8", 11.5),
        ("5", "00000005", 11.5),
        ("77c1edc1", "bbad0594", 11.5),
    ]
    assert skipped == 0


@pytest.mark.parametrize(
    ("field", "value", "attribute", "expected"),
    [
        ("SNR", -50, "snr", -50.0),
        ("SNR", 50.0, "snr", 50.0),
        ("SNR", 50.25, "snr", None),
        ("SNR", -50.25, "snr", None),
        ("SNR", "x", "snr", None),
        ("RSSI", 0, "rssi", 0),
        ("RSSI", 255, "rssi", 255),
        ("RSSI", 256, "rssi", None),
        ("RSSI", -1, "rssi", None),
        ("HopLimit", 0, "hop_limit", 0),
        ("HopLimit", 7, "hop_limit", 7),
        ("HopLimit", 8, "hop_limit", None),
        ("HopLimit", True, "hop_limit", None),
        ("RelayNode", 0, "relay", 0),
        ("RelayNode", 255, "relay", 255),
        ("RelayNode", 256, "relay", None),
        ("RelayNode", None, "relay", None),
    ],
)
def test_report_values_are_range_checked(
    field: str, value: object, attribute: str, expected: object
) -> None:
    reception = _one_reception(**{field: value})

    assert reception is not None
    assert getattr(reception, attribute) == expected


def test_a_parsed_row_becomes_a_decoded_packet() -> None:
    packets, skipped = parse_decoded([_parsed()], _NODE, now=_NOW)

    assert packets == (
        DecodedPacket(
            time=_T0,
            packet_id="d883d91d",
            hop_start=7,
            port=67,
            payload="0.79% ChUtil, 0.02% AirUtilTx, 48% Bat",
        ),
    )
    assert skipped == 0


@pytest.mark.parametrize(
    "row",
    [
        pytest.param(["not", "a", "row"], id="not-an-object"),
        pytest.param(_parsed(FromNode="979ed146"), id="another-node"),
        pytest.param(_parsed(Time=""), id="no-time"),
        pytest.param(_parsed(PacketId=7), id="bad-packet-id"),
        pytest.param(_parsed(Time="2099-01-01T00:00:00"), id="future"),
    ],
)
def test_an_unusable_parsed_row_is_skipped_and_counted(row: object) -> None:
    packets, skipped = parse_decoded([row, _parsed(PacketId="1")], _NODE, now=_NOW)

    assert [packet.packet_id for packet in packets] == ["1"]
    assert skipped == 1


def test_a_repeated_decoded_packet_is_kept_once_and_odd_values_degrade() -> None:
    rows = [
        _parsed(PacketId="a", HopStart=8, PortNum=1024, Payload=None),
        _parsed(PacketId="a", Payload="later copy"),
        _parsed(PacketId="b", HopStart=0, PortNum=0, Payload="x" * 512),
        _parsed(PacketId="c", HopStart="7", PortNum=1023, Payload="x" * 513),
    ]

    packets, skipped = parse_decoded(rows, _NODE, now=_NOW)

    assert [(p.packet_id, p.hop_start, p.port, len(p.payload)) for p in packets] == [
        ("a", None, None, 0),
        ("b", 0, 0, 512),
        ("c", 7, 1023, 0),
    ]
    assert skipped == 0


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(
            "5.93% ChUtil, 0.03% AirUtilTx, 90% Bat",
            Telemetry(battery=90, channel_utilization=5.93, air_util_tx=0.03),
            id="device-metrics",
        ),
        pytest.param(
            "167305 rx, 1129 tx, 252 relay, 84 kB",
            Telemetry(rx=167305, tx=1129, relayed=252),
            id="local-stats",
        ),
        pytest.param("101% Bat, 4.2 V", Telemetry(battery=101, voltage=4.2), id="powered"),
        pytest.param("3.71V", Telemetry(voltage=3.71), id="voltage-without-space"),
        pytest.param(
            "100% ChUtil, 100% AirUtilTx",
            Telemetry(channel_utilization=100.0, air_util_tx=100.0),
            id="percent-at-limit",
        ),
        pytest.param("102% Bat, 100.5% ChUtil, 10.5 V", None, id="out-of-range"),
        pytest.param("0% Bat, 0 V", Telemetry(battery=0, voltage=0.0), id="zero"),
        pytest.param("9% Bat, 20% Bat", Telemetry(battery=9), id="first-reading-wins"),
        pytest.param("", None, id="empty"),
        pytest.param("22.5°C, 1013 hPa", None, id="unknown-readings"),
        pytest.param("-3% Bat", None, id="negative"),
        pytest.param("4294967295 rx, 5 tx", Telemetry(rx=4294967295, tx=5), id="counter-at-limit"),
        pytest.param("4294967296 rx, 5 tx", Telemetry(tx=5), id="counter-over-limit"),
    ],
)
def test_telemetry_payloads_are_parsed_defensively(text: str, expected: Telemetry | None) -> None:
    assert parse_telemetry(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("52.379648° N, 16.950886° E", (52.379648, 16.950886)),
        ("33.5° S, 70.25° W", (-33.5, -70.25)),
        ("90° N, 180° E", (90.0, 180.0)),
        ("0° N, 0.000001° E", (0.0, 0.000001)),
    ],
)
def test_a_position_payload_gives_signed_degrees(text: str, expected: tuple[float, float]) -> None:
    assert parse_position(text) == expected


@pytest.mark.parametrize(
    "text",
    ["90.000001° N, 1° E", "1° N, 180.000001° E", "0° N, 0° E", "52.1 N, 16.9 E", "", "x"],
)
def test_an_unusable_position_payload_is_none(text: str) -> None:
    assert parse_position(text) is None


def test_a_nodeinfo_payload_keeps_commas_in_the_long_name_and_maps_the_role() -> None:
    info = parse_nodeinfo("D0h5, D0h5 | FW+, https://loranet.pl/firmware, ClientMute")

    assert info == NodeInfo(
        short_name="D0h5", long_name="D0h5 | FW+, https://loranet.pl/firmware", role="CLIENT_MUTE"
    )


@pytest.mark.parametrize(
    ("role_text", "role"),
    [("RouterLate", "ROUTER_LATE"), ("Client", "CLIENT"), ("ClientBase", "CLIENT_BASE")],
)
def test_nodeinfo_roles_are_canonical_names(role_text: str, role: str) -> None:
    info = parse_nodeinfo(f"S, Long, {role_text}")

    assert info is not None
    assert info.role == role


def test_an_unknown_nodeinfo_role_is_none_but_the_names_are_kept() -> None:
    assert parse_nodeinfo("S, Long, Wizard") == NodeInfo("S", "Long", None)
    assert parse_nodeinfo("S, Long, ") == NodeInfo("S", "Long", None)


def test_nodeinfo_parts_are_stripped() -> None:
    info = parse_nodeinfo("Ab , Alpha ,  Beta , Router ")

    assert info == NodeInfo("Ab", "Alpha, Beta", "ROUTER")


@pytest.mark.parametrize("text", ["S, Client", " , Long, Client", "S, , Client", ""])
def test_an_incomplete_nodeinfo_payload_is_none(text: str) -> None:
    assert parse_nodeinfo(text) is None


def test_nodeinfo_names_are_made_terminal_safe() -> None:
    info = parse_nodeinfo("A\x1b[2J, B\x07, Client")

    assert info is not None
    assert "\x1b" not in info.short_name
    assert "\x07" not in info.long_name


def test_a_neighbour_payload_is_one_node_id() -> None:
    assert parse_neighbor(" 979ed146 ") == NodeId.from_hex("979ed146")
    assert parse_neighbor("not a node") is None
    assert parse_neighbor("") is None
