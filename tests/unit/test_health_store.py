"""The per-node health history files: format, tolerant reads, bounded atomic writes."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from types import MappingProxyType

import pytest

from meshprovision.health import store as store_module
from meshprovision.health.history import (
    HISTORY_RETENTION_SECONDS,
    HOUR_SECONDS,
    GatewayCheck,
    HourBucket,
    LocalStatsPoint,
    NodeHistory,
    NodeInfoSeen,
    PositionPoint,
    TelemetryPoint,
)
from meshprovision.health.store import (
    HISTORY_DIRNAME,
    HISTORY_VERSION,
    HistoryStore,
    history_from_json,
    history_to_json,
)
from meshprovision.nodeid import NodeId

pytestmark = pytest.mark.unit

_NODE = NodeId.from_hex("ab446357")
_H = 1_760_994_000
_NOW = float(_H + 600)


def _rich() -> NodeHistory:
    return NodeHistory(
        node=_NODE,
        fetched_at=_NOW,
        last_heard=_NOW - 5,
        hours=(
            HourBucket(_H - HOUR_SECONDS),
            HourBucket(
                _H,
                receptions=5,
                packets=2,
                direct=1,
                gateways=MappingProxyType({"0000000a": 3, "bbad0594": 2}),
                relays=MappingProxyType({25: 1, 97: 3}),
                hops=MappingProxyType({0: 1, 2: 4}),
                snr=MappingProxyType({-30: 1, -3: 2, 20: 2}),
                rssi=(700, 5, 120, 160),
                ports=MappingProxyType({3: 1, 67: 1}),
                hop_starts=MappingProxyType({7: 2}),
            ),
        ),
        telemetry=(TelemetryPoint(_NOW - 60, 90, 4.1, 5.93, 0.03), TelemetryPoint(_NOW - 30)),
        local_stats=(LocalStatsPoint(_NOW - 60, 167305, 1129, 252),),
        positions=(PositionPoint(_NOW - 60, 52.379648, -16.950886),),
        nodeinfo=NodeInfoSeen(_NOW - 60, "D0h5", "D0h5 | FW+", "CLIENT_MUTE"),
        neighbors=MappingProxyType({"979ed146": _NOW - 60}),
        boots=(_NOW - 9000,),
        gateway_checks=(GatewayCheck(_NOW - 60, 3600.0, 34, 24),),
    )


def _document(**overrides: object) -> dict[str, object]:
    document = history_to_json(_rich())
    document.update(overrides)
    return document


def _read(document: object) -> NodeHistory | None:
    return history_from_json(json.loads(json.dumps(document)), _NODE)


def test_a_history_survives_the_round_trip_through_json() -> None:
    assert _read(history_to_json(_rich())) == _rich()


def test_empty_bucket_fields_are_left_out_of_the_file() -> None:
    hours = history_to_json(_rich())["hours"]

    assert isinstance(hours, list)
    assert hours[0] == {"h": _H - HOUR_SECONDS}
    assert hours[1]["rl"] == {"25": 1, "97": 3}


@pytest.mark.parametrize(
    "document",
    [
        pytest.param(None, id="missing"),
        pytest.param([], id="not-an-object"),
        pytest.param(_document(version=HISTORY_VERSION + 1), id="other-version"),
        pytest.param(_document(version=None), id="no-version"),
        pytest.param(_document(node="979ed146"), id="other-node"),
    ],
)
def test_a_document_that_is_not_this_nodes_history_reads_as_none(document: object) -> None:
    assert history_from_json(document, _NODE) is None


def _bucket(**fields: object) -> dict[str, object]:
    return {"h": _H, "rx": 1, **fields}


@pytest.mark.parametrize(
    "bucket",
    [
        pytest.param("x", id="not-an-object"),
        pytest.param({"h": _H + 1}, id="hour-not-aligned"),
        pytest.param({"h": -HOUR_SECONDS}, id="hour-negative"),
        pytest.param({"h": True}, id="hour-bool"),
        pytest.param({"h": str(_H)}, id="hour-string"),
        pytest.param({"rx": 1}, id="no-hour"),
        pytest.param(_bucket(rx=-1), id="negative-count"),
        pytest.param(_bucket(pk=1.5), id="float-count"),
        pytest.param(_bucket(dr=True), id="bool-count"),
        pytest.param(_bucket(rx=10**9 + 1), id="huge-count"),
        pytest.param(_bucket(gw={"BBAD0594": 1}), id="gateway-uppercase"),
        pytest.param(_bucket(gw={"bad0594": 1}), id="gateway-short"),
        pytest.param(_bucket(gw=[1]), id="gateways-not-an-object"),
        pytest.param(_bucket(gw={f"{i:08x}": 1 for i in range(65)}), id="too-many-gateways"),
        pytest.param(_bucket(rl={"256": 1}), id="relay-out-of-range"),
        pytest.param(_bucket(rl={"07": 1}), id="relay-not-canonical"),
        pytest.param(_bucket(rl={"x": 1}), id="relay-not-a-number"),
        pytest.param(_bucket(rl={"1": -1}), id="relay-negative-count"),
        pytest.param(_bucket(hp={"8": 1}), id="hops-out-of-range"),
        pytest.param(_bucket(sn={"-31": 1}), id="snr-below-range"),
        pytest.param(_bucket(sn={"21": 1}), id="snr-above-range"),
        pytest.param(_bucket(pt={"1024": 1}), id="port-out-of-range"),
        pytest.param(_bucket(hs={"-1": 1}), id="hop-start-negative"),
        pytest.param(_bucket(rs=[1, 2, 3]), id="rssi-short"),
        pytest.param(_bucket(rs=[1, 2, 3, -4]), id="rssi-negative"),
        pytest.param(_bucket(rs="x"), id="rssi-not-a-list"),
    ],
)
def test_a_malformed_bucket_is_dropped_alone(bucket: object) -> None:
    history = _read(_document(hours=[bucket, {"h": _H + HOUR_SECONDS, "rx": 2}]))

    assert history is not None
    assert [(b.hour, b.receptions) for b in history.hours] == [(_H + HOUR_SECONDS, 2)]


def test_bucket_keys_at_their_limits_are_read() -> None:
    bucket = _bucket(
        gw={f"{i:08x}": 1 for i in range(64)},
        rl={"0": 1, "255": 1},
        hp={"0": 1, "7": 1},
        sn={"-30": 1, "20": 1},
        pt={"0": 1, "1023": 1},
        hs={"0": 1, "7": 1},
        rs=[0, 1, 0, 0],
        rx=10**9,
    )

    history = _read(_document(hours=[bucket]))

    assert history is not None
    (read,) = history.hours
    assert len(read.gateways) == 64
    assert dict(read.snr) == {-30: 1, 20: 1}
    assert dict(read.ports) == {0: 1, 1023: 1}
    assert read.rssi == (0, 1, 0, 0)
    assert read.receptions == 10**9


def test_a_repeated_hour_keeps_the_last_bucket() -> None:
    history = _read(_document(hours=[_bucket(rx=1), _bucket(rx=2)]))

    assert history is not None
    assert [b.receptions for b in history.hours] == [2]


@pytest.mark.parametrize(
    ("field", "item"),
    [
        ("telemetry", [_NOW, 90, 4.1, 5.9]),
        ("telemetry", [-1, 90, None, None, None]),
        ("telemetry", [_NOW, 102, None, None, None]),
        ("telemetry", [_NOW, 50.5, None, None, None]),
        ("telemetry", [_NOW, None, 10.5, None, None]),
        ("telemetry", [_NOW, None, None, 100.5, None]),
        ("telemetry", [_NOW, None, None, None, -0.5]),
        ("telemetry", [_NOW, None, None, None, "1"]),
        ("telemetry", "x"),
        ("local_stats", [_NOW, -1, None, None]),
        ("local_stats", [None, 1, 2, 3]),
        ("positions", [_NOW, 90.5, 1.0]),
        ("positions", [_NOW, 1.0, -180.5]),
        ("positions", [_NOW, 1.0, None]),
        ("gateway_checks", [_NOW, 3600, -1, 1]),
        ("gateway_checks", [_NOW, None, 1, 1]),
        ("telemetry", [_NOW, 90, 4.1, 5.9, 0.1, 1]),
    ],
)
def test_a_malformed_point_is_dropped_alone(field: str, item: object) -> None:
    good = {
        "telemetry": [_NOW - 1, 101, 0, 100, 0],
        "local_stats": [_NOW - 1, 0, None, 10**9],
        "positions": [_NOW - 1, -90, 180],
        "gateway_checks": [_NOW - 1, 0, 0, 0],
    }[field]

    history = _read(_document(**{field: [item, good]}))

    assert history is not None
    points = getattr(history, field)
    assert [p.time for p in points] == [_NOW - 1]


def test_a_repeated_point_time_keeps_the_last_point() -> None:
    history = _read(
        _document(telemetry=[[_NOW, 50, None, None, None], [_NOW, 49, None, None, None]])
    )

    assert history is not None
    assert history.telemetry == (TelemetryPoint(_NOW, 49),)


@pytest.mark.parametrize("value", [None, 5, "text", {"h": 1}])
def test_a_section_that_is_not_a_list_reads_as_empty(value: object) -> None:
    history = _read(
        _document(hours=value, telemetry=value, boots=value, gateway_checks=value, neighbors=value)
    )

    assert history is not None
    assert (history.hours, history.telemetry, history.boots, history.gateway_checks) == (
        (),
        (),
        (),
        (),
    )
    assert dict(history.neighbors) == {}


def test_an_overflowing_or_infinite_time_reads_as_none() -> None:
    document = _document(fetched_at=10**400, last_heard=float("inf"))

    history = history_from_json(json.loads(json.dumps(document)), _NODE)

    assert history is not None
    assert (history.fetched_at, history.last_heard) == (None, None)


@pytest.mark.parametrize(
    "nodeinfo",
    [
        pytest.param([_NOW, " ", "Long", None], id="blank-short-name"),
        pytest.param([_NOW, "S", "x" * 257, None], id="long-name-too-long"),
        pytest.param([_NOW, "S", "Long", 3], id="role-not-a-string"),
        pytest.param([_NOW, "S", "Long"], id="short-row"),
        pytest.param([None, "S", "Long", None], id="no-time"),
        pytest.param("S", id="not-a-list"),
    ],
)
def test_a_malformed_nodeinfo_reads_as_none(nodeinfo: object) -> None:
    history = _read(_document(nodeinfo=nodeinfo))

    assert history is not None
    assert history.nodeinfo is None


def test_nodeinfo_names_are_read_terminal_safe_and_a_null_role_is_kept() -> None:
    history = _read(_document(nodeinfo=[_NOW, "S\x1b[2J", "x" * 256, None]))

    assert history is not None
    assert history.nodeinfo is not None
    assert "\x1b" not in history.nodeinfo.short_name
    assert history.nodeinfo.role is None


def test_malformed_neighbours_and_boots_are_dropped() -> None:
    history = _read(
        _document(
            neighbors={"979ed146": _NOW, "979ED146": _NOW, "0000000a": "x", "0000000b": 5},
            boots=[5, "x", -1, 5.0, True],
        )
    )

    assert history is not None
    assert dict(history.neighbors) == {"0000000b": 5.0, "979ed146": _NOW}
    assert history.boots == (5.0,)


def _store(tmp_path: Path, now: list[float]) -> HistoryStore:
    return HistoryStore(tmp_path / "cache" / HISTORY_DIRNAME, clock=lambda: now[0])


def test_a_missing_history_loads_empty(tmp_path: Path) -> None:
    assert _store(tmp_path, [_NOW]).load(_NODE) == NodeHistory(node=_NODE)


@pytest.mark.parametrize(
    "content",
    [b"{not json", b'{"version": 1, "node": "979ed146"}', b"[]"],
    ids=["corrupt", "other-node", "wrong-shape"],
)
def test_an_unusable_file_loads_empty(tmp_path: Path, content: bytes) -> None:
    store = _store(tmp_path, [_NOW])
    store.directory.mkdir(parents=True)
    store.path_for(_NODE).write_bytes(content)

    assert store.load(_NODE) == NodeHistory(node=_NODE)


def test_a_file_over_two_mebibytes_is_not_read(tmp_path: Path) -> None:
    store = _store(tmp_path, [_NOW])
    store.directory.mkdir(parents=True)
    text = json.dumps(history_to_json(_rich()))
    store.path_for(_NODE).write_text(text + " " * (2 * 1024 * 1024 - len(text) + 1))

    assert store.load(_NODE) == NodeHistory(node=_NODE)


def test_a_file_at_the_size_limit_is_read(tmp_path: Path) -> None:
    store = _store(tmp_path, [_NOW])
    store.directory.mkdir(parents=True)
    text = json.dumps(history_to_json(_rich()))
    store.path_for(_NODE).write_text(text + " " * (2 * 1024 * 1024 - len(text)))

    assert store.load(_NODE) == _rich()


def test_load_prunes_what_has_aged_out(tmp_path: Path) -> None:
    now = [_NOW]
    store = _store(tmp_path, now)
    store.update(_NODE, lambda _old: _rich())
    now[0] = _NOW + HISTORY_RETENTION_SECONDS + 2 * HOUR_SECONDS

    loaded = store.load(_NODE)

    assert loaded.hours == ()
    assert loaded.fetched_at == _NOW


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_update_writes_an_owner_only_file_in_an_owner_only_directory(tmp_path: Path) -> None:
    store = _store(tmp_path, [_NOW])

    written = store.update(_NODE, lambda old: _rich() if old == NodeHistory(node=_NODE) else old)

    assert written == _rich()
    assert stat.S_IMODE(store.path_for(_NODE).stat().st_mode) == 0o600
    assert stat.S_IMODE(store.directory.stat().st_mode) == 0o700
    assert sorted(p.name for p in store.directory.iterdir()) == [f"{_NODE.hex}.json"]
    assert store.load(_NODE) == _rich()


def test_update_merges_into_what_is_on_disk_now(tmp_path: Path) -> None:
    now = [_NOW]
    first = _store(tmp_path, now)
    second = _store(tmp_path, now)
    first.update(_NODE, lambda old: NodeHistory(node=_NODE, boots=(*old.boots, 1.0 + _H)))

    second.update(_NODE, lambda old: NodeHistory(node=_NODE, boots=(*old.boots, 2.0 + _H)))

    assert first.load(_NODE).boots == (1.0 + _H, 2.0 + _H)


def test_a_failed_write_is_skipped_and_the_history_still_returned(tmp_path: Path) -> None:
    store = HistoryStore(tmp_path / "blocker" / HISTORY_DIRNAME, clock=lambda: _NOW)
    (tmp_path / "blocker").write_text("a file, not a directory")

    assert store.update(_NODE, lambda _old: _rich()) == _rich()


def test_an_oversized_history_loses_its_oldest_days_until_it_fits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hours = tuple(
        HourBucket(_H - index * HOUR_SECONDS, receptions=1, gateways={"bbad0594": 1})
        for index in reversed(range(72))
    )
    history = NodeHistory(
        node=_NODE,
        hours=hours,
        telemetry=(TelemetryPoint(hours[0].hour), TelemetryPoint(hours[24].hour)),
        boots=(float(hours[0].hour), float(hours[-1].hour)),
    )
    size_of_two_days = (
        len(json.dumps(history_to_json(NodeHistory(node=_NODE, hours=hours[24:])))) + 400
    )
    monkeypatch.setattr(store_module, "HISTORY_MAX_FILE_BYTES", size_of_two_days)
    store = _store(tmp_path, [_NOW])

    written = store.update(_NODE, lambda _old: history)

    assert written.hours == hours[24:]
    assert written.telemetry == (TelemetryPoint(hours[24].hour),)
    assert written.boots == (float(hours[-1].hour),)
    assert len(store.path_for(_NODE).read_bytes()) <= size_of_two_days


def test_a_history_one_byte_over_the_cap_loses_its_oldest_day(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hours = tuple(HourBucket(_H - index * HOUR_SECONDS) for index in reversed(range(30)))
    history = NodeHistory(node=_NODE, hours=hours)
    full = len(json.dumps(history_to_json(history)))
    monkeypatch.setattr(store_module, "HISTORY_MAX_FILE_BYTES", full - 1)

    written = _store(tmp_path, [_NOW]).update(_NODE, lambda _old: history)

    assert written.hours == hours[24:]


def test_a_history_exactly_at_the_cap_is_written_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hours = tuple(HourBucket(_H - index * HOUR_SECONDS) for index in reversed(range(30)))
    history = NodeHistory(node=_NODE, hours=hours)
    monkeypatch.setattr(
        store_module, "HISTORY_MAX_FILE_BYTES", len(json.dumps(history_to_json(history)))
    )

    assert _store(tmp_path, [_NOW]).update(_NODE, lambda _old: history) == history


def test_update_prunes_before_writing(tmp_path: Path) -> None:
    old_hour = HourBucket(_H - 40 * 24 * HOUR_SECONDS, receptions=1)
    store = _store(tmp_path, [_NOW])

    written = store.update(_NODE, lambda _old: NodeHistory(node=_NODE, hours=(old_hour,)))

    assert written.hours == ()
    hours = json.loads(store.path_for(_NODE).read_text())["hours"]
    assert hours == []


def test_a_history_that_never_fits_is_written_without_hours(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module, "HISTORY_MAX_FILE_BYTES", 10)
    store = _store(tmp_path, [_NOW])

    written = store.update(_NODE, lambda _old: _rich())

    assert written.hours == ()
    assert written.telemetry == ()


def _touch(store: HistoryStore, name: str, mtime: float) -> Path:
    path = store.directory / name
    path.write_text("{}")
    os.utime(path, (mtime, mtime))
    return path


def test_files_not_written_for_the_retention_are_swept(tmp_path: Path) -> None:
    store = _store(tmp_path, [_NOW])
    store.directory.mkdir(parents=True)
    expired = _touch(store, "0000000a.json", _NOW - HISTORY_RETENTION_SECONDS - 1)
    kept = _touch(store, "0000000b.json", _NOW - HISTORY_RETENTION_SECONDS + 1)
    other = _touch(store, "notes.json", _NOW - HISTORY_RETENTION_SECONDS - 1)

    store.update(_NODE, lambda _old: _rich())

    assert not expired.exists()
    assert kept.exists()
    assert other.exists()


def test_only_the_most_recently_written_files_are_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module, "HISTORY_MAX_NODES", 3)
    monkeypatch.setattr(store_module, "HISTORY_SPARE_NODES", 0)
    store = _store(tmp_path, [_NOW])
    store.directory.mkdir(parents=True)
    files = [_touch(store, f"0000000{i}.json", _NOW - 100 + i) for i in range(4)]
    store.path_for(_NODE).write_text("{}")
    os.utime(store.path_for(_NODE), (_NOW - 1000, _NOW - 1000))

    store.update(_NODE, lambda _old: _rich())

    assert [path.exists() for path in files] == [False, False, True, True]
    assert store.path_for(_NODE).exists()


def test_a_failed_sweep_is_ignored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path, [_NOW])

    def refuse(_self: Path) -> object:
        raise PermissionError("no listing")

    monkeypatch.setattr(Path, "iterdir", refuse)

    assert store.update(_NODE, lambda _old: _rich()) == _rich()


def _keep_ids(count: int) -> list[NodeId]:
    return [NodeId.from_int(0x100 + index) for index in range(count)]


def test_the_files_of_the_nodes_refreshed_together_are_never_swept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refreshing more nodes than the cap evicted each node's file before it came round again."""
    monkeypatch.setattr(store_module, "HISTORY_MAX_NODES", 3)
    monkeypatch.setattr(store_module, "HISTORY_SPARE_NODES", 0)
    store = _store(tmp_path, [_NOW])
    store.directory.mkdir(parents=True)
    fleet = _keep_ids(4)
    kept = [_touch(store, f"{node.hex}.json", _NOW - 1000 + i) for i, node in enumerate(fleet)]
    others = [_touch(store, f"0000000{i}.json", _NOW - 100 + i) for i in range(2)]

    store.update(_NODE, lambda _old: _rich(), keep=fleet)

    assert all(path.exists() for path in kept)
    assert not any(path.exists() for path in others)
    assert store.path_for(_NODE).exists()


def test_the_cap_grows_with_the_nodes_refreshed_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module, "HISTORY_MAX_NODES", 3)
    monkeypatch.setattr(store_module, "HISTORY_SPARE_NODES", 2)
    store = _store(tmp_path, [_NOW])
    store.directory.mkdir(parents=True)
    fleet = _keep_ids(4)
    for node in fleet:
        _touch(store, f"{node.hex}.json", _NOW - 1000)
    others = [_touch(store, f"0000000{i}.json", _NOW - 100 + i) for i in range(4)]

    store.update(_NODE, lambda _old: _rich(), keep=fleet)

    # 9 files, cap = 4 refreshed together (+ the one written) + 2 spare = 7
    assert [path.exists() for path in others] == [False, False, True, True]


def test_the_oldest_other_files_go_until_all_fit_the_byte_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path, [_NOW])
    store.update(_NODE, lambda _old: _rich())
    written = store.path_for(_NODE).stat().st_size
    monkeypatch.setattr(store_module, "HISTORY_MAX_TOTAL_BYTES", written + 250)
    others = []
    for i in range(4):
        path = store.directory / f"0000000{i}.json"
        path.write_text("x" * 100)
        os.utime(path, (_NOW - 100 + i, _NOW - 100 + i))
        others.append(path)

    store.update(_NODE, lambda _old: _rich())

    assert [path.exists() for path in others] == [False, False, True, True]


def test_a_file_exactly_at_the_byte_bound_is_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path, [_NOW])
    store.update(_NODE, lambda _old: _rich())
    written = store.path_for(_NODE).stat().st_size
    monkeypatch.setattr(store_module, "HISTORY_MAX_TOTAL_BYTES", written + 100)
    other = store.directory / "0000000a.json"
    other.write_text("x" * 100)

    store.update(_NODE, lambda _old: _rich())

    assert other.exists()


def test_the_files_refreshed_together_are_kept_even_beyond_the_byte_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module, "HISTORY_MAX_TOTAL_BYTES", 1)
    store = _store(tmp_path, [_NOW])
    store.directory.mkdir(parents=True)
    fleet = _keep_ids(2)
    kept = [_touch(store, f"{node.hex}.json", _NOW - 1000) for node in fleet]

    store.update(_NODE, lambda _old: _rich(), keep=fleet)

    assert all(path.exists() for path in kept)
    assert store.path_for(_NODE).exists()


def test_the_bounds_are_128_files_32_spare_and_256_mib() -> None:
    assert store_module.HISTORY_MAX_NODES == 128
    assert store_module.HISTORY_SPARE_NODES == 32
    assert store_module.HISTORY_MAX_TOTAL_BYTES == 256 * 1024 * 1024
