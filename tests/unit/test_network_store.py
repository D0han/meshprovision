"""``RegionStore``: day files per region, tolerant reads, merging writes and every bound."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from meshprovision.health.history import HOUR_SECONDS, floor_hour
from meshprovision.network import store as store_module
from meshprovision.network.buckets import NETWORK_RETENTION_SECONDS, RegionHour, Traffic
from meshprovision.network.resolve import Confidence, LearnedRelay, Resolution
from meshprovision.network.store import (
    LEARNED_RELAY_MAX_AGE_SECONDS,
    STORE_VERSION,
    RegionState,
    RegionStore,
    region_dirname,
)
from tests.unit.network_fixtures import NOW

pytestmark = pytest.mark.unit

_REGION = "Zachód"
_O = "ab446357"
_HOUR = floor_hour(NOW)
_DAY = 24 * HOUR_SECONDS


def _store(tmp_path: Path, now: float = NOW) -> RegionStore:
    return RegionStore(tmp_path / "network", clock=lambda: now)


def _bucket(hour: int, packets: int = 1) -> RegionHour:
    return RegionHour(hour, Traffic(packets={_O: packets}))


def _update(store: RegionStore, *hours: RegionHour, region: str = _REGION) -> None:
    store.update(region, hours, fetched_at=NOW, skipped_rows=2)


def _day_file(store: RegionStore, day: str, region: str = _REGION) -> Path:
    return store.path_for(region) / f"{day}.json"


def test_hours_written_are_read_back_with_the_state(tmp_path: Path) -> None:
    store = _store(tmp_path)
    hours = (_bucket(_HOUR - HOUR_SECONDS, 3), RegionHour(_HOUR))

    _update(store, *hours)

    assert store.load(_REGION, start=_HOUR - _DAY) == hours
    assert store.state(_REGION) == RegionState(fetched_at=NOW, skipped_rows=2)


def test_one_file_per_utc_day_owner_only(tmp_path: Path) -> None:
    store = _store(tmp_path)
    midnight = _HOUR - 21 * HOUR_SECONDS

    _update(store, _bucket(midnight - HOUR_SECONDS), _bucket(midnight))

    directory = store.path_for(_REGION)
    assert sorted(p.name for p in directory.iterdir()) == [
        "2026-10-19.json",
        "2026-10-20.json",
        "state.json",
    ]
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert {stat.S_IMODE(p.stat().st_mode) for p in directory.iterdir()} == {0o600}
    document = json.loads(_day_file(store, "2026-10-20").read_text(encoding="utf-8"))
    assert document == {
        "version": STORE_VERSION,
        "region": _REGION,
        "day": "2026-10-20",
        "hours": [{"h": midnight, "pk": {_O: 1}}],
    }


def test_each_region_has_its_own_digest_directory(tmp_path: Path) -> None:
    store = _store(tmp_path)

    _update(store, _bucket(_HOUR, 1))
    _update(store, _bucket(_HOUR, 2), region="zachód")

    assert region_dirname(_REGION) != region_dirname("zachód")
    assert region_dirname("Zachód") == region_dirname(_REGION)
    assert region_dirname(_REGION).startswith("r-") and len(region_dirname(_REGION)) == 18
    assert store.load(_REGION, start=_HOUR) == (_bucket(_HOUR, 1),)
    assert store.load("zachód", start=_HOUR) == (_bucket(_HOUR, 2),)


def test_load_starts_at_the_hour_of_start(tmp_path: Path) -> None:
    store = _store(tmp_path)
    hours = tuple(_bucket(_HOUR - i * HOUR_SECONDS) for i in (30, 2, 1, 0))
    _update(store, *hours)

    assert store.load(_REGION, start=_HOUR - HOUR_SECONDS) == hours[2:]
    assert store.load(_REGION, start=_HOUR - HOUR_SECONDS - 1) == hours[1:]
    assert store.load(_REGION, start=_HOUR - 2 * _DAY) == hours


def test_an_update_replaces_its_hours_and_keeps_the_others(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _update(store, _bucket(_HOUR - HOUR_SECONDS, 1), _bucket(_HOUR, 1))

    _update(store, _bucket(_HOUR, 5))
    _update(store, _bucket(_HOUR, 5))

    assert store.load(_REGION, start=_HOUR - _DAY) == (
        _bucket(_HOUR - HOUR_SECONDS, 1),
        _bucket(_HOUR, 5),
    )


def test_two_processes_updating_one_region_both_leave_their_hours(tmp_path: Path) -> None:
    first, second = _store(tmp_path), _store(tmp_path)

    first.update(_REGION, [_bucket(_HOUR - HOUR_SECONDS)], fetched_at=NOW - 60, skipped_rows=0)
    second.update(_REGION, [_bucket(_HOUR)], fetched_at=NOW - 120, skipped_rows=1)

    assert first.load(_REGION, start=_HOUR - _DAY) == (
        _bucket(_HOUR - HOUR_SECONDS),
        _bucket(_HOUR),
    )
    assert first.state(_REGION) == RegionState(fetched_at=NOW - 60, skipped_rows=1)


def test_nothing_stored_reads_as_empty(tmp_path: Path) -> None:
    store = _store(tmp_path)

    assert store.load(_REGION, start=0) == ()
    assert store.state(_REGION) == RegionState()


def _write(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document if isinstance(document, str) else json.dumps(document))


@pytest.mark.parametrize(
    "change",
    [
        pytest.param({"version": 2}, id="other-version"),
        pytest.param({"region": "zachód"}, id="other-region"),
        pytest.param({"day": "2026-10-19"}, id="other-day"),
        pytest.param({"hours": {"h": 0}}, id="hours-not-a-list"),
    ],
)
def test_a_day_file_of_an_unexpected_shape_reads_as_empty(
    tmp_path: Path, change: dict[str, object]
) -> None:
    store = _store(tmp_path)
    _update(store, _bucket(_HOUR))
    path = _day_file(store, "2026-10-20")
    _write(path, {**json.loads(path.read_text(encoding="utf-8")), **change})

    assert store.load(_REGION, start=_HOUR) == ()


def test_a_corrupt_day_file_reads_as_empty_and_is_rewritten(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _update(store, _bucket(_HOUR - HOUR_SECONDS))
    _write(_day_file(store, "2026-10-20"), "{not json")

    assert store.load(_REGION, start=_HOUR - _DAY) == ()
    _update(store, _bucket(_HOUR))
    assert store.load(_REGION, start=_HOUR - _DAY) == (_bucket(_HOUR),)


def test_a_malformed_hour_or_one_outside_its_day_is_dropped(tmp_path: Path) -> None:
    store = _store(tmp_path)
    yesterday = _HOUR - _DAY
    _update(store, _bucket(yesterday))
    path = _day_file(store, "2026-10-19")
    document = json.loads(path.read_text(encoding="utf-8"))
    outside = [{"h": h, "pk": {_O: 9}} for h in (yesterday - _DAY, _HOUR)]
    document["hours"] += [{"h": yesterday + 1}, *outside, "x"]
    _write(path, document)

    assert store.load(_REGION, start=0) == (_bucket(yesterday),)


def test_a_day_file_over_the_cap_is_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    _update(store, _bucket(_HOUR))
    size = _day_file(store, "2026-10-20").stat().st_size

    monkeypatch.setattr(store_module, "DAY_MAX_BYTES", size - 1)

    assert store.load(_REGION, start=_HOUR) == ()


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        pytest.param("{", RegionState(), id="corrupt"),
        pytest.param(
            {"version": STORE_VERSION, "region": "x", "fetched_at": NOW},
            RegionState(),
            id="other-region",
        ),
        pytest.param(
            {"version": STORE_VERSION, "region": _REGION, "fetched_at": -1, "skipped_rows": -3},
            RegionState(),
            id="bad-values",
        ),
        pytest.param(
            {"version": STORE_VERSION, "region": _REGION, "fetched_at": NOW, "skipped_rows": 4},
            RegionState(NOW, 4),
            id="good",
        ),
    ],
)
def test_the_state_is_read_tolerantly(
    tmp_path: Path, document: object, expected: RegionState
) -> None:
    store = _store(tmp_path)
    _write(store.path_for(_REGION) / "state.json", document)

    assert store.state(_REGION) == expected


def test_hours_older_than_the_retention_are_neither_kept_nor_read(tmp_path: Path) -> None:
    store = _store(tmp_path)
    oldest = floor_hour(NOW - NETWORK_RETENTION_SECONDS)
    _update(store, _bucket(oldest - HOUR_SECONDS), _bucket(oldest), _bucket(_HOUR))

    assert store.load(_REGION, start=0) == (_bucket(oldest), _bucket(_HOUR))

    later = _store(tmp_path, NOW + HOUR_SECONDS)
    assert later.load(_REGION, start=0) == (_bucket(_HOUR),)


@pytest.mark.parametrize(("after_end", "deleted"), [(0, True), (-1, False)])
def test_a_day_file_past_the_retention_is_deleted_on_the_next_update(
    tmp_path: Path, after_end: int, deleted: bool
) -> None:
    store = _store(tmp_path)
    old_hour = floor_hour(NOW - NETWORK_RETENTION_SECONDS) + HOUR_SECONDS
    _update(store, _bucket(old_hour), _bucket(_HOUR))
    old_day = store_module._day_of(old_hour)
    day_end = old_hour - old_hour % _DAY + _DAY
    assert store_module._day_of(day_end - 1) == old_day != store_module._day_of(day_end)
    later = day_end + NETWORK_RETENTION_SECONDS + after_end

    _update(_store(tmp_path, later), _bucket(floor_hour(later)))

    assert _day_file(store, old_day).exists() is not deleted
    assert _day_file(store, "2026-10-20").exists()


def test_a_day_file_over_the_cap_keeps_its_newest_hours(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    hours = [_bucket(_HOUR - i * HOUR_SECONDS, 10**6 + i) for i in range(4)]
    _update(store, *hours[:1])
    one_hour = _day_file(store, "2026-10-20").stat().st_size
    monkeypatch.setattr(store_module, "DAY_MAX_BYTES", one_hour + 60)

    _update(store, *hours)

    assert store.load(_REGION, start=0) == (hours[1], hours[0])


def _days(store: RegionStore, region: str = _REGION) -> list[str]:
    return sorted(p.stem for p in store.path_for(region).glob("????-??-??.json"))


def test_a_region_over_its_cap_loses_its_oldest_days(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    _update(store, *(_bucket(_HOUR - i * _DAY) for i in range(3)))
    size = _day_file(store, "2026-10-20").stat().st_size
    monkeypatch.setattr(store_module, "REGION_MAX_BYTES", 2 * size + 10)

    _update(store, _bucket(_HOUR, 2))

    assert _days(store) == ["2026-10-19", "2026-10-20"]


def test_over_the_total_cap_the_least_recently_refreshed_region_goes_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    _update(store, *(_bucket(_HOUR - i * _DAY) for i in range(2)), region="old")
    state = store.path_for("old") / "state.json"
    os.utime(state, (NOW - _DAY, NOW - _DAY))
    size = _day_file(store, "2026-10-20", "old").stat().st_size
    monkeypatch.setattr(store_module, "STORE_MAX_TOTAL_BYTES", 3 * size + 10)

    _update(store, *(_bucket(_HOUR - i * _DAY) for i in range(2)), region="new")

    assert _days(store, "old") == ["2026-10-20"]
    assert _days(store, "new") == ["2026-10-19", "2026-10-20"]


def test_a_region_not_refreshed_for_the_retention_and_without_days_is_removed(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _update(store, _bucket(_HOUR), region="gone")
    directory = store.path_for("gone")
    for path in directory.glob("????-??-??.json"):
        path.unlink()
    expired = NOW - NETWORK_RETENTION_SECONDS - 1
    os.utime(directory / "state.json", (expired, expired))
    _update(store, _bucket(_HOUR), region="kept")
    _update(store, _bucket(_HOUR), region="recent")
    os.utime(store.path_for("kept") / "state.json", (expired, expired))
    for path in store.path_for("recent").glob("????-??-??.json"):
        path.unlink()

    _update(store, _bucket(_HOUR, 2))

    assert not directory.exists()
    assert store.path_for("kept").exists()
    assert store.path_for("recent").exists()


def test_a_store_that_cannot_be_written_never_raises(tmp_path: Path) -> None:
    (tmp_path / "network").write_text("a file, not a directory")
    store = _store(tmp_path)

    _update(store, _bucket(_HOUR))

    assert store.load(_REGION, start=0) == ()
    assert store.state(_REGION) == RegionState()


def _resolution(byte: int, node: str | None, confidence: Confidence) -> Resolution:
    return Resolution(byte, confidence, node)


def test_bytes_resolved_high_are_learned_and_read_back(tmp_path: Path) -> None:
    store = _store(tmp_path)

    store.remember_relays(
        _REGION,
        seen_at=NOW,
        resolutions={
            0x61: _resolution(0x61, "c464e761", Confidence.HIGH),
            0xBC: _resolution(0xBC, "f24810bc", Confidence.MEDIUM),
            0xE4: _resolution(0xE4, None, Confidence.AMBIGUOUS),
        },
    )

    assert store.learned_relays(_REGION) == {0x61: LearnedRelay("c464e761", NOW)}
    path = store.path_for(_REGION) / "relays.json"
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "version": STORE_VERSION,
        "region": _REGION,
        "relays": {"97": ["c464e761", NOW]},
    }
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_learning_keeps_the_other_bytes_and_renews_a_byte(tmp_path: Path) -> None:
    _store(tmp_path, NOW - 3600).remember_relays(
        _REGION,
        seen_at=NOW - 3600,
        resolutions={
            0x61: _resolution(0x61, "c464e761", Confidence.HIGH),
            0xBC: _resolution(0xBC, "f24810bc", Confidence.HIGH),
        },
    )
    store = _store(tmp_path)

    store.remember_relays(
        _REGION, {0xBC: _resolution(0xBC, "7c5b07bc", Confidence.HIGH)}, seen_at=NOW
    )

    assert store.learned_relays(_REGION) == {
        0x61: LearnedRelay("c464e761", NOW - 3600),
        0xBC: LearnedRelay("7c5b07bc", NOW),
    }


@pytest.mark.parametrize(
    ("age", "kept"),
    [
        (LEARNED_RELAY_MAX_AGE_SECONDS, True),
        (LEARNED_RELAY_MAX_AGE_SECONDS + 1, False),
        (-300, True),
        (-301, False),
    ],
)
def test_a_learned_byte_is_used_for_a_week(tmp_path: Path, age: float, kept: bool) -> None:
    _store(tmp_path, NOW - age).remember_relays(
        _REGION, {0x61: _resolution(0x61, "c464e761", Confidence.HIGH)}, seen_at=NOW - age
    )

    assert (0x61 in _store(tmp_path).learned_relays(_REGION)) is kept


def test_nothing_new_to_learn_writes_nothing(tmp_path: Path) -> None:
    store = _store(tmp_path)

    store.remember_relays(
        _REGION, {0xE4: _resolution(0xE4, None, Confidence.AMBIGUOUS)}, seen_at=NOW
    )

    assert not (store.path_for(_REGION) / "relays.json").exists()


@pytest.mark.parametrize(
    "relays",
    [
        pytest.param({"97": ["c464e762", NOW]}, id="node-of-another-byte"),
        pytest.param({"0": ["c464e700", NOW]}, id="byte-0"),
        pytest.param({"97": ["C464E761", NOW]}, id="uppercase-id"),
        pytest.param({"97": ["c464e761", "now"]}, id="time-not-a-number"),
        pytest.param({"97": ["c464e761"]}, id="too-short"),
        pytest.param({"97": "c464e761"}, id="not-a-list"),
    ],
)
def test_a_malformed_learned_entry_is_dropped(tmp_path: Path, relays: dict[str, object]) -> None:
    store = _store(tmp_path)
    document = {
        "version": STORE_VERSION,
        "region": _REGION,
        "relays": {**relays, "188": ["f24810bc", NOW]},
    }
    _write(store.path_for(_REGION) / "relays.json", document)

    assert store.learned_relays(_REGION) == {0xBC: LearnedRelay("f24810bc", NOW)}


@pytest.mark.parametrize(
    "document",
    [
        pytest.param("{", id="corrupt"),
        pytest.param({"version": STORE_VERSION, "region": "x", "relays": {}}, id="other-region"),
        pytest.param({"version": STORE_VERSION, "region": _REGION, "relays": []}, id="not-a-map"),
    ],
)
def test_an_unusable_learned_file_reads_as_empty(tmp_path: Path, document: object) -> None:
    store = _store(tmp_path)
    _write(store.path_for(_REGION) / "relays.json", document)

    assert store.learned_relays(_REGION) == {}


def test_old_evidence_never_renews_a_learned_byte(tmp_path: Path) -> None:
    store = _store(tmp_path)
    high = {0x61: _resolution(0x61, "c464e761", Confidence.HIGH)}
    store.remember_relays(_REGION, high, seen_at=NOW - 3600)

    store.remember_relays(_REGION, high, seen_at=NOW - 7200)
    assert store.learned_relays(_REGION) == {0x61: LearnedRelay("c464e761", NOW - 3600)}

    store.remember_relays(_REGION, high, seen_at=NOW - 60)
    assert store.learned_relays(_REGION) == {0x61: LearnedRelay("c464e761", NOW - 60)}
