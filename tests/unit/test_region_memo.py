"""Tests for meshprovision.datasources.region_memo."""

from __future__ import annotations

import json
import logging
import stat
from pathlib import Path

import pytest

from meshprovision.datasources import region_memo as memo_module
from meshprovision.datasources.region_memo import (
    REGION_MEMO_VERSION,
    RegionMemo,
)
from meshprovision.nodeid import NodeId

pytestmark = pytest.mark.unit

_NOW = 1_760_000_000.0
_A = NodeId.from_hex("deadbe01")
_B = NodeId.from_hex("deadbe02")
_C = NodeId.from_hex("deadbe03")


def _memo(tmp_path: Path, now: list[float] | None = None) -> RegionMemo:
    clock = now if now is not None else [_NOW]
    return RegionMemo(tmp_path / "cache" / "lorastats_regions.json", clock=lambda: clock[0])


def _write_raw(memo: RegionMemo, document: object) -> None:
    memo.path.parent.mkdir(parents=True, exist_ok=True)
    memo.path.write_text(json.dumps(document), encoding="utf-8")


def _nodes(**entries: object) -> dict[str, object]:
    return {"version": REGION_MEMO_VERSION, "nodes": entries}


def test_a_remembered_region_is_read_back_by_a_later_process(tmp_path: Path) -> None:
    _memo(tmp_path).remember(_A, "Zachód")

    later = _memo(tmp_path)
    assert later.region_for(_A) == "Zachód"
    assert later.region_for(_B) is None


def test_the_file_is_owner_only_json_and_leaves_no_temp_file(tmp_path: Path) -> None:
    memo = _memo(tmp_path)
    memo.remember(_A, "Zachód")

    assert json.loads(memo.path.read_text(encoding="utf-8")) == _nodes(
        deadbe01={"region": "Zachód", "stored_at": _NOW}
    )
    assert stat.S_IMODE(memo.path.stat().st_mode) == 0o600
    assert [p.name for p in memo.path.parent.iterdir()] == [memo.path.name]


def test_a_missing_cache_directory_is_created_owner_only(tmp_path: Path) -> None:
    memo = _memo(tmp_path)
    memo.remember(_A, "PL")
    assert stat.S_IMODE(memo.path.parent.stat().st_mode) == 0o700


def test_remember_replaces_the_previous_region(tmp_path: Path) -> None:
    now = [_NOW]
    memo = _memo(tmp_path, now)
    memo.remember(_A, "PL")
    now[0] += 10
    memo.remember(_A, "Zachód")

    assert memo.region_for(_A) == "Zachód"
    assert _memo(tmp_path, now).region_for(_A) == "Zachód"


def test_forget_drops_the_entry_on_disk(tmp_path: Path) -> None:
    memo = _memo(tmp_path)
    memo.remember(_A, "PL")
    memo.remember(_B, "Zachód")

    memo.forget(_A)

    assert memo.region_for(_A) is None
    later = _memo(tmp_path)
    assert (later.region_for(_A), later.region_for(_B)) == (None, "Zachód")


def test_forgetting_keeps_another_processes_entries(tmp_path: Path) -> None:
    first, second = _memo(tmp_path), _memo(tmp_path)
    assert first.region_for(_A) is None
    second.remember(_B, "Zachód")
    first.remember(_A, "PL")
    second.remember(_C, "Warszawa")

    first.forget(_A)

    later = _memo(tmp_path)
    assert [later.region_for(node) for node in (_A, _B, _C)] == [None, "Zachód", "Warszawa"]


def test_forgetting_before_any_lookup_still_drops_the_entry(tmp_path: Path) -> None:
    _memo(tmp_path).remember(_A, "PL")

    _memo(tmp_path).forget(_A)

    assert _memo(tmp_path).region_for(_A) is None


def test_forgetting_an_unknown_node_writes_nothing(tmp_path: Path) -> None:
    memo = _memo(tmp_path)
    memo.forget(_A)
    assert not memo.path.exists()


def test_a_read_never_creates_the_file(tmp_path: Path) -> None:
    memo = _memo(tmp_path)
    assert memo.region_for(_A) is None
    assert not memo.path.parent.exists()


def test_a_write_keeps_another_processes_entries(tmp_path: Path) -> None:
    first = _memo(tmp_path)
    second = _memo(tmp_path)
    assert second.region_for(_B) is None  # loaded before the first process wrote

    first.remember(_A, "Zachód")
    second.remember(_B, "PL")

    later = _memo(tmp_path)
    assert (later.region_for(_A), later.region_for(_B)) == ("Zachód", "PL")


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(b"{not json", id="not-json"),
        pytest.param(b"\xff\xfe", id="not-utf8"),
        pytest.param(b"[1, 2]", id="a-list"),
        pytest.param(b'"text"', id="a-string"),
        pytest.param(json.dumps({"version": 2, "nodes": {}}).encode(), id="other-version"),
        pytest.param(json.dumps({"version": 1, "nodes": []}).encode(), id="nodes-not-object"),
        pytest.param(json.dumps({"version": 1}).encode(), id="no-nodes"),
        pytest.param(b"[" * 100_000 + b"]" * 100_000, id="too-deep"),
    ],
)
def test_an_unreadable_file_reads_as_no_memo(
    tmp_path: Path, content: bytes, caplog: pytest.LogCaptureFixture
) -> None:
    memo = _memo(tmp_path)
    memo.path.parent.mkdir(parents=True)
    memo.path.write_bytes(content)

    with caplog.at_level(logging.DEBUG):
        assert memo.region_for(_A) is None
    assert "ignoring the lorastats region memo" in caplog.text


def test_an_oversized_file_is_not_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    memo = _memo(tmp_path)
    _write_raw(memo, _nodes(deadbe01={"region": "PL", "stored_at": _NOW}))
    monkeypatch.setattr(memo_module, "_MAX_FILE_BYTES", memo.path.stat().st_size - 1)

    assert memo.region_for(_A) is None


def test_a_file_at_the_size_limit_is_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    memo = _memo(tmp_path)
    _write_raw(memo, _nodes(deadbe01={"region": "PL", "stored_at": _NOW}))
    monkeypatch.setattr(memo_module, "_MAX_FILE_BYTES", memo.path.stat().st_size)

    assert memo.region_for(_A) == "PL"


def test_a_path_that_cannot_be_read_reads_as_no_memo(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    memo = _memo(tmp_path)
    memo.path.mkdir(parents=True)  # a directory where the file should be

    with caplog.at_level(logging.DEBUG):
        assert memo.region_for(_A) is None
    assert "could not read the lorastats region memo" in caplog.text


@pytest.mark.parametrize(
    ("key", "value"),
    [
        pytest.param("DEADBE01", {"region": "PL", "stored_at": _NOW}, id="uppercase-key"),
        pytest.param("!deadbe01", {"region": "PL", "stored_at": _NOW}, id="bang-key"),
        pytest.param("1", {"region": "PL", "stored_at": _NOW}, id="short-key"),
        pytest.param("not-hex", {"region": "PL", "stored_at": _NOW}, id="non-hex-key"),
        pytest.param("deadbe01", "PL", id="value-not-object"),
        pytest.param("deadbe01", {"stored_at": _NOW}, id="no-region"),
        pytest.param("deadbe01", {"region": 7, "stored_at": _NOW}, id="region-not-str"),
        pytest.param("deadbe01", {"region": "", "stored_at": _NOW}, id="empty-region"),
        pytest.param("deadbe01", {"region": "PL"}, id="no-stored-at"),
        pytest.param("deadbe01", {"region": "PL", "stored_at": True}, id="bool-stored-at"),
        pytest.param("deadbe01", {"region": "PL", "stored_at": "1"}, id="str-stored-at"),
        pytest.param("deadbe01", {"region": "PL", "stored_at": "NaN"}, id="nan-stored-at"),
        pytest.param("deadbe01", {"region": "PL", "stored_at": 1e400}, id="inf-stored-at"),
    ],
)
def test_a_malformed_entry_is_skipped_but_its_siblings_are_kept(
    tmp_path: Path, key: str, value: object
) -> None:
    memo = _memo(tmp_path)
    good = {"region": "Zachód", "stored_at": _NOW}
    _write_raw(memo, _nodes(**{key: value, "deadbe02": good}))

    assert memo.region_for(_A) is None
    assert memo.region_for(_B) == "Zachód"
    memo.remember(NodeId.from_hex("deadbe03"), "PL")
    assert set(json.loads(memo.path.read_text(encoding="utf-8"))["nodes"]) == {
        "deadbe02",
        "deadbe03",
    }


def test_a_boolean_stored_at_is_not_a_time(tmp_path: Path) -> None:
    memo = _memo(tmp_path, [1.0])
    _write_raw(memo, _nodes(deadbe01={"region": "PL", "stored_at": True}))
    assert memo.region_for(_A) is None


def test_a_nan_stored_at_written_as_a_json_literal_is_skipped(tmp_path: Path) -> None:
    memo = _memo(tmp_path)
    memo.path.parent.mkdir(parents=True)
    memo.path.write_text(
        '{"version": 1, "nodes": {"deadbe01": {"region": "PL", "stored_at": NaN}}}',
        encoding="utf-8",
    )
    assert memo.region_for(_A) is None


def test_an_integer_stored_at_is_accepted(tmp_path: Path) -> None:
    memo = _memo(tmp_path)
    _write_raw(memo, _nodes(deadbe01={"region": "PL", "stored_at": int(_NOW)}))
    assert memo.region_for(_A) == "PL"


def test_an_entry_expires_after_its_maximum_age(tmp_path: Path) -> None:
    now = [_NOW]
    _memo(tmp_path, now).remember(_A, "PL")

    now[0] = _NOW + 30 * 24 * 3600
    assert _memo(tmp_path, now).region_for(_A) == "PL"
    now[0] += 1
    assert _memo(tmp_path, now).region_for(_A) is None


def test_an_entry_expires_in_a_long_running_process_too(tmp_path: Path) -> None:
    now = [_NOW]
    memo = _memo(tmp_path, now)
    memo.remember(_A, "PL")

    now[0] = _NOW + 30 * 24 * 3600 + 1
    assert memo.region_for(_A) is None


def test_an_entry_stored_in_the_future_is_used_only_within_a_small_skew(tmp_path: Path) -> None:
    memo = _memo(tmp_path)
    _write_raw(
        memo,
        _nodes(
            deadbe01={"region": "PL", "stored_at": _NOW + 300},
            deadbe02={"region": "PL", "stored_at": _NOW + 301},
        ),
    )
    assert (memo.region_for(_A), memo.region_for(_B)) == ("PL", None)


def test_an_expired_entry_is_dropped_on_the_next_write(tmp_path: Path) -> None:
    now = [_NOW]
    _memo(tmp_path, now).remember(_A, "PL")
    now[0] = _NOW + 30 * 24 * 3600 + 1
    memo = _memo(tmp_path, now)
    memo.remember(_B, "Zachód")

    assert set(json.loads(memo.path.read_text(encoding="utf-8"))["nodes"]) == {"deadbe02"}


@pytest.mark.parametrize(("padding", "region"), [(0, "PL"), (1, None)])
def test_a_file_over_one_mebibyte_is_not_read(
    tmp_path: Path, padding: int, region: str | None
) -> None:
    memo = _memo(tmp_path)
    text = json.dumps(_nodes(deadbe01={"region": "PL", "stored_at": _NOW}))
    memo.path.parent.mkdir(parents=True)
    memo.path.write_text(text + " " * (1024 * 1024 - len(text) + padding), encoding="utf-8")

    assert memo.region_for(_A) == region


def test_a_write_keeps_at_most_2048_entries(tmp_path: Path) -> None:
    entries = {
        f"{index:08x}": {"region": "PL", "stored_at": _NOW - index} for index in range(1, 2049)
    }
    memo = _memo(tmp_path)
    _write_raw(memo, _nodes(**entries))

    memo.remember(_A, "Zachód")

    kept = json.loads(memo.path.read_text(encoding="utf-8"))["nodes"]
    assert len(kept) == 2048
    assert "deadbe01" in kept
    assert f"{2048:08x}" not in kept


def test_a_write_keeps_only_the_newest_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(memo_module, "REGION_MEMO_MAX_ENTRIES", 2)
    now = [_NOW]
    memo = _memo(tmp_path, now)
    for value in (1, 2, 3):
        now[0] += 1
        memo.remember(NodeId.from_int(value), "PL")

    later = _memo(tmp_path, now)
    assert [later.region_for(NodeId.from_int(value)) for value in (1, 2, 3)] == [None, "PL", "PL"]


def test_a_failed_write_is_logged_and_keeps_the_region_for_this_process(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    (tmp_path / "cache").write_text("a file where the cache directory should be")
    memo = _memo(tmp_path)

    with caplog.at_level(logging.DEBUG):
        memo.remember(_A, "PL")

    assert memo.region_for(_A) == "PL"
    assert "could not write the lorastats region memo" in caplog.text


def test_a_failed_replace_leaves_no_temp_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    memo = _memo(tmp_path)
    memo.remember(_A, "PL")

    def refuse(self: Path, target: Path) -> Path:
        raise PermissionError("read-only")

    monkeypatch.setattr(Path, "replace", refuse)
    memo.remember(_B, "Zachód")

    assert [p.name for p in memo.path.parent.iterdir()] == [memo.path.name]
    assert _memo(tmp_path).region_for(_B) is None
