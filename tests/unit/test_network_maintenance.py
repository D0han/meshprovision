"""The maintenance note: from the store only, recent data only, only when it matters."""

from __future__ import annotations

from pathlib import Path

import pytest

from meshprovision.network import maintenance
from meshprovision.network.buckets import summarize
from meshprovision.network.impact import Level
from meshprovision.network.keys import KeySeen
from meshprovision.network.keystore import KeyStore
from meshprovision.network.maintenance import (
    MAINTENANCE_MAX_AGE_SECONDS,
    StoredImpact,
    maintenance_note,
    stored_impacts,
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
    RegionStore(directory, clock=lambda: fetched_at).update(region, hours, fetched_at=fetched_at)


def _note(directory: Path, now: float = NOW) -> str | None:
    return maintenance_note(_NODE, directory, clock=lambda: now)


def test_a_sole_first_hop_gives_a_note(tmp_path: Path) -> None:
    _seed(tmp_path, "PL")

    note = _note(tmp_path)

    assert note is not None
    assert note.startswith(
        "!deadbe01 carried 100.0% of PL's stored relayed traffic in the 24 h before "
    )
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
    assert "of B's stored relayed traffic" in note
    assert "2 node(s) used it as their only first hop" in note


def test_between_two_high_regions_the_larger_share_wins(tmp_path: Path) -> None:
    _seed(tmp_path, "A", noise=100)
    _seed(tmp_path, "B", noise=10)

    note = _note(tmp_path)

    assert note is not None and "of B's stored relayed traffic" in note


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

    assert note is not None and "of B's stored relayed traffic" in note


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


def test_a_plan_that_renumbers_the_node_says_so(tmp_path: Path) -> None:
    _seed(tmp_path, "PL")

    note = maintenance_note(_NODE, tmp_path, renumbers=True, clock=lambda: NOW)

    assert note is not None
    assert note.endswith(
        "Applying this plan reboots it and changes its node id (firmware >= 2.8 derives it "
        "from the new key). See: mesh network impact deadbe01"
    )


def _impacts(directory: Path, *nodes: NodeId, now: float = NOW) -> dict[NodeId, StoredImpact]:
    return stored_impacts(nodes, directory, now=now)


def test_stored_impacts_loads_each_region_once_for_every_node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed(tmp_path, "A")
    _seed(tmp_path, "B", noise=10)
    loads: list[str] = []
    real_load = RegionStore.load

    def counting(self: RegionStore, region: str, **kwargs: float) -> object:
        loads.append(region)
        return real_load(self, region, **kwargs)

    monkeypatch.setattr(RegionStore, "load", counting)
    others = [NodeId(0xA3000010), NodeId(0xB0000002), NodeId(0x12345678)]

    impacts = _impacts(tmp_path, _NODE, *others)

    assert sorted(loads) == ["A", "B"]
    assert set(impacts) == {_NODE, *others}


def test_stored_impacts_keeps_each_nodes_best_region(tmp_path: Path) -> None:
    _seed(tmp_path, "A", first_hop=False, noise=250, elsewhere=10)
    _seed(tmp_path, "B", noise=2000)

    stored = _impacts(tmp_path, _NODE)[_NODE]

    assert (stored.region, stored.impact.level) == ("B", Level.HIGH)
    assert stored.fetched_at == NOW


def test_stored_impacts_keep_a_low_node_that_the_note_leaves_out(tmp_path: Path) -> None:
    _seed(tmp_path, "PL", dependants=0, noise=50)

    stored = _impacts(tmp_path, _NODE)

    assert stored[_NODE].impact.level is Level.LOW
    assert _note(tmp_path) is None


def test_a_low_region_never_beats_a_medium_one_with_less_traffic(tmp_path: Path) -> None:
    _seed(tmp_path, "A", first_hop=False, noise=600, elsewhere=10)
    _seed(tmp_path, "B", dependants=0, noise=5)

    stored = _impacts(tmp_path, _NODE)[_NODE]

    assert (stored.region, stored.impact.level) == ("A", Level.MEDIUM)


@pytest.mark.parametrize(
    ("age", "kept"),
    [
        (MAINTENANCE_MAX_AGE_SECONDS, True),
        (MAINTENANCE_MAX_AGE_SECONDS + 1, False),
        (-1, False),
    ],
)
def test_stored_impacts_use_only_fresh_regions(tmp_path: Path, age: float, kept: bool) -> None:
    _seed(tmp_path, "PL", fetched_at=NOW - age)

    assert (_NODE in _impacts(tmp_path, _NODE)) is kept


def test_stored_impacts_count_every_other_node_as_a_dependant(tmp_path: Path) -> None:
    """Judging the dependant too must not hide it from the node's impact."""
    _seed(tmp_path, "PL")

    alone = _impacts(tmp_path, _NODE)[_NODE].impact
    together = _impacts(tmp_path, _NODE, NodeId(0xA3000010))[_NODE].impact

    assert alone == together
    assert alone.sole_first_hop_for == ("a3000010",)


def test_stored_impacts_on_any_failure_are_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed(tmp_path, "PL")

    def broken(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("boom")

    monkeypatch.setattr(maintenance, "resolve_window", broken)

    assert _impacts(tmp_path, _NODE) == {}


def test_stored_impacts_without_a_store_are_empty(tmp_path: Path) -> None:
    assert _impacts(tmp_path / "missing", _NODE) == {}


def test_a_medium_region_beats_a_low_one_that_carried_more(tmp_path: Path) -> None:
    """Medium from one relying origin (1.2% carried) over low with 2.2% carried."""
    _seed(tmp_path, "A", first_hop=False, elsewhere=10, noise=2000)
    _seed(tmp_path, "B", first_hop=False, elsewhere=100, noise=1000)

    stored = _impacts(tmp_path, _NODE)[_NODE]

    assert (stored.region, stored.impact.level) == ("A", Level.MEDIUM)
    assert stored.impact.carried_share < 0.03


def test_between_equal_regions_the_first_is_kept(tmp_path: Path) -> None:
    _seed(tmp_path, "A")
    _seed(tmp_path, "B")

    assert _impacts(tmp_path, _NODE)[_NODE].region == "A"
