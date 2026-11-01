"""The maintenance note: from the store only, recent data only, only when it matters."""

from __future__ import annotations

from pathlib import Path

import pytest

from meshprovision.network import maintenance
from meshprovision.network.buckets import summarize
from meshprovision.network.keys import KeySeen
from meshprovision.network.keystore import KeyStore
from meshprovision.network.maintenance import (
    MAINTENANCE_MAX_AGE_SECONDS,
    maintenance_note,
)
from meshprovision.network.rawpackets import parse_raw
from meshprovision.network.store import RegionStore
from meshprovision.nodeid import NodeId
from tests.unit.network_fixtures import NOW, packet, row

pytestmark = pytest.mark.unit

_NODE = NodeId.from_hex("deadbe01")
_G = "6a000073"


def _seed(
    directory: Path,
    region: str,
    *,
    dependants: int = 1,
    first_hop: bool = True,
    fetched_at: float = NOW,
    noise: int = 0,
    elsewhere: int = 0,
    hours_before: int = 1,
    twin: bool = False,
) -> None:
    """Store ``dependants`` outsiders relayed by the node (byte 0x01), each 25 times."""
    at = fetched_at - hours_before * 3600
    rows = []
    for d in range(dependants):
        origin = 0xA3000010 + d
        for n in range(25):
            hops = 1 if first_hop else 2
            built = packet(origin, 1000 * d + n + 1, relay=0x01, hop_limit=3 - hops, rssi=-85)
            rows.append(row(built, gateway=_G, time=at + n))
        for n in range(elsewhere):
            other = packet(origin, 1000 * d + 500 + n, relay=0x61, hop_limit=1, rssi=-85)
            rows.append(row(other, gateway=_G, time=at + n))
    rows += [row(packet(_NODE.num, 9000 + n, rssi=-85), gateway=_G, time=at) for n in range(5)]
    if twin:
        rows += [row(packet(0xC1000001, 8000 + n, rssi=-85), gateway=_G, time=at) for n in range(5)]
    rows += [
        row(packet(0xB0000002, 7000 + n, relay=0x61, hop_limit=2), gateway=_G, time=at)
        for n in range(noise)
    ]
    hours = summarize(parse_raw(rows, now=fetched_at), since=None, fetched_at=fetched_at)
    RegionStore(directory, clock=lambda: fetched_at).update(
        region, hours, fetched_at=fetched_at, skipped_rows=0
    )


def _note(directory: Path, now: float = NOW) -> str | None:
    return maintenance_note(_NODE, directory, clock=lambda: now)


def test_a_sole_first_hop_gives_a_note(tmp_path: Path) -> None:
    _seed(tmp_path, "PL")

    note = _note(tmp_path)

    assert note is not None
    assert note.startswith("!deadbe01 carried 100.0% of PL's relayed traffic in the 24 h before ")
    assert "; 1 node(s) used it as their only first hop; 1 node(s) and 1 gateway(s) got" in note
    assert note.endswith("Applying this plan reboots it. See: mesh network impact deadbe01")


def test_a_low_node_gets_none(tmp_path: Path) -> None:
    _seed(tmp_path, "PL", dependants=0, noise=50)

    assert _note(tmp_path) is None


def test_nothing_stored_gets_none(tmp_path: Path) -> None:
    assert _note(tmp_path / "missing") is None


@pytest.mark.parametrize(
    ("age", "noted"),
    [
        (MAINTENANCE_MAX_AGE_SECONDS, True),
        (MAINTENANCE_MAX_AGE_SECONDS + 1, False),
        (0, True),
        (-1, False),
    ],
)
def test_only_data_at_most_48_hours_old_counts(tmp_path: Path, age: float, noted: bool) -> None:
    _seed(tmp_path, "PL", fetched_at=NOW - age)

    assert (_note(tmp_path) is not None) is noted


def test_the_region_where_it_matters_most_is_named(tmp_path: Path) -> None:
    _seed(tmp_path, "A", first_hop=False, noise=600, elsewhere=10)
    _seed(tmp_path, "B", dependants=2)
    _seed(tmp_path, "C", first_hop=False, noise=100, elsewhere=10)

    note = _note(tmp_path)

    assert note is not None
    assert "of B's relayed traffic" in note
    assert "2 node(s) used it as their only first hop" in note


def test_between_two_high_regions_the_larger_share_wins(tmp_path: Path) -> None:
    _seed(tmp_path, "A", noise=100)
    _seed(tmp_path, "B", noise=10)

    note = _note(tmp_path)

    assert note is not None and "of B's relayed traffic" in note


def test_a_medium_node_is_noted_without_a_sole_first_hop(tmp_path: Path) -> None:
    _seed(tmp_path, "PL", first_hop=False, noise=600, elsewhere=10)

    note = _note(tmp_path)

    assert note is not None
    assert "only first hop" not in note
    assert "carried 3.9% of PL's" in note
    assert "1 node(s) and 0 gateway(s) got at least half" in note


def test_any_failure_gives_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed(tmp_path, "PL")

    def broken(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("boom")

    monkeypatch.setattr(maintenance, "combine", broken)

    assert _note(tmp_path) is None


def test_the_regions_are_named_from_their_state_files(tmp_path: Path) -> None:
    _seed(tmp_path, "Zachód")
    _seed(tmp_path, "PL")
    (tmp_path / "r-0000000000000000").mkdir()
    (tmp_path / "r-0000000000000000" / "state.json").write_text(
        '{"version": 1, "region": "PL", "fetched_at": 1, "skipped_rows": 0}', encoding="utf-8"
    )

    assert RegionStore(tmp_path).regions() == ("PL", "Zachód")


def test_only_the_24_hours_before_the_fetch_count(tmp_path: Path) -> None:
    _seed(tmp_path, "PL", hours_before=26)

    assert _note(tmp_path) is None


def test_a_high_region_wins_over_a_medium_one_with_more_traffic(tmp_path: Path) -> None:
    _seed(tmp_path, "A", first_hop=False, noise=250, elsewhere=10)
    _seed(tmp_path, "B", noise=2000)

    note = _note(tmp_path)

    assert note is not None and "of B's relayed traffic" in note


def test_a_node_whose_own_node_info_says_client_mute_does_not_make_the_byte_ambiguous(
    tmp_path: Path,
) -> None:
    _seed(tmp_path, "PL", twin=True)
    assert _note(tmp_path) is None

    KeyStore(tmp_path, clock=lambda: NOW).update(
        "PL",
        [KeySeen("c1000001", "sha256:" + "1" * 16, NOW - 60, NOW - 60, (), role="CLIENT_MUTE")],
    )

    assert _note(tmp_path) is not None
