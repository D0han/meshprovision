"""Tests for meshprovision.db.atomic_writer."""

from __future__ import annotations

import errno
import logging
import os
import shutil
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from meshprovision.db import atomic_writer, backups, fs_primitives
from meshprovision.db.atomic_writer import atomic_write, restore_backup, write_bytes_atomic
from meshprovision.db.backups import (
    BackupInfo,
    _backup_name_re,
    _backup_sort_key,
    _claim_backup_path,
    _parse_backup_timestamp,
    backup_dir_for,
    backup_name,
    create_backup,
    legacy_backup_notice,
    list_backups,
    prune_backups,
)
from meshprovision.db.fs_primitives import link_no_clobber
from meshprovision.errors import AtomicWriteError
from tests.unit.conftest import FsyncEvent

pytestmark = pytest.mark.unit


def test_write_bytes_atomic_creates_file_no_stray_temp(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    write_bytes_atomic(target, b"hello", backup=False, backup_dir=backup_dir)
    assert target.read_bytes() == b"hello"
    assert sorted(tmp_path.iterdir()) == [target]
    assert not backup_dir.exists()


def test_exception_inside_block_leaves_target_untouched(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    target.write_bytes(b"original")
    backup_dir = tmp_path / "backups"

    with (
        pytest.raises(RuntimeError),
        atomic_write(target, backup=False, backup_dir=backup_dir) as tmp,
    ):
        tmp.write_bytes(b"new content")
        raise RuntimeError("boom")

    assert target.read_bytes() == b"original"
    leftovers = [p for p in tmp_path.iterdir() if p.name.startswith(f".{target.name}.tmp")]
    assert leftovers == []


def test_backup_taken_before_replace(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    write_bytes_atomic(target, b"v1", backup=False, backup_dir=backup_dir)
    write_bytes_atomic(target, b"v2", backup=True, backup_dir=backup_dir)

    backups = list_backups(target, backup_dir=backup_dir)
    assert len(backups) == 1
    assert backups[0].path.read_bytes() == b"v1"
    assert target.read_bytes() == b"v2"


def test_backup_name_and_parse_round_trip(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    when = datetime(2026, 8, 25, 3, 14, 10, 123456, tzinfo=UTC)
    name = backup_name(target, when)
    assert name == "nodes_db-20260825T031410.123456Z.ods"
    assert _parse_backup_timestamp(name, target) == when


def test_legacy_second_resolution_backup_names_still_parse(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    assert _parse_backup_timestamp("nodes_db-20260825T031410Z.ods", target) == datetime(
        2026, 8, 25, 3, 14, 10, tzinfo=UTC
    )


def test_parse_backup_timestamp_returns_none_for_wrong_prefix(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    assert _parse_backup_timestamp("totally_unrelated_file.ods", target) is None


def test_parse_backup_timestamp_returns_none_for_unparseable_token(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    assert _parse_backup_timestamp("nodes_db-not-a-real-timestamp.ods", target) is None


def test_backup_sort_key_falls_back_to_mtime_when_name_is_unparseable(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    unparseable = tmp_path / "totally_unrelated_file.ods"
    unparseable.write_bytes(b"x")

    key = _backup_sort_key(unparseable, target)

    expected_mtime = unparseable.stat().st_mtime
    assert key == (datetime.fromtimestamp(expected_mtime, tz=UTC), expected_mtime)


def test_two_backups_same_second_get_distinct_paths(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v1")
    when = datetime(2026, 8, 25, 3, 14, 10, tzinfo=UTC)

    info1 = create_backup(target, backup_dir=backup_dir, now=when)
    target.write_bytes(b"v2")
    info2 = create_backup(target, backup_dir=backup_dir, now=when)

    assert info1 is not None
    assert info2 is not None
    assert info1.path != info2.path
    assert info1.path.exists()
    assert info2.path.exists()


def test_backup_racing_an_identical_name_does_not_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v1")
    when = datetime(2026, 8, 25, 3, 14, 10, 123456, tzinfo=UTC)

    real_copy2 = shutil.copy2
    inner: list[BackupInfo] = []

    def copy2_then_race(src: Path, dst: Path, *args: object, **kwargs: object) -> object:
        result = real_copy2(src, dst, *args, **kwargs)
        if not inner:  # only the outer call races; the inner one must not recurse
            monkeypatch.setattr(shutil, "copy2", real_copy2)
            target.write_bytes(b"v2")
            info = create_backup(target, backup_dir=backup_dir, now=when)
            assert info is not None
            inner.append(info)
            monkeypatch.setattr(shutil, "copy2", copy2_then_race)
        return result

    monkeypatch.setattr(shutil, "copy2", copy2_then_race)
    outer = create_backup(target, backup_dir=backup_dir, now=when)

    assert outer is not None
    assert outer.path != inner[0].path
    assert outer.path.read_bytes() == b"v1"
    assert inner[0].path.read_bytes() == b"v2"
    assert len(list_backups(target, backup_dir=backup_dir)) == 2


def test_claim_backup_path_never_overwrites_an_existing_name(tmp_path: Path) -> None:
    directory = tmp_path / "backups"
    directory.mkdir()
    (directory / "data-20260825T031410.123456Z.txt").write_bytes(b"existing")
    source = directory / ".tmp-copy"
    source.write_bytes(b"new")

    claimed = _claim_backup_path(directory, "data-20260825T031410.123456Z.txt", source)

    assert claimed.name == "data-20260825T031410.123456Z-1.txt"
    assert (directory / "data-20260825T031410.123456Z.txt").read_bytes() == b"existing"
    assert claimed.read_bytes() == b"new"
    assert not source.exists()


def test_prune_backups_keeps_exactly_retention_newest(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v0")

    for i in range(5):
        target.write_bytes(f"v{i + 1}".encode())
        create_backup(
            target,
            backup_dir=backup_dir,
            retention=1000,
            now=datetime(2026, 8, 25, 0, 0, i, tzinfo=UTC),
        )

    backups_before = list_backups(target, backup_dir=backup_dir)
    assert len(backups_before) == 5

    removed = prune_backups(target, backup_dir=backup_dir, retention=2)
    assert len(removed) == 3

    backups_after = list_backups(target, backup_dir=backup_dir)
    assert len(backups_after) == 2


def test_prune_backups_retention_non_positive_prunes_nothing(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v0")
    create_backup(target, backup_dir=backup_dir)
    target.write_bytes(b"v1")
    create_backup(target, backup_dir=backup_dir)

    removed = prune_backups(target, backup_dir=backup_dir, retention=0)
    assert removed == ()
    assert len(list_backups(target, backup_dir=backup_dir)) == 2


def test_list_backups_newest_first_and_empty_when_absent(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    assert list_backups(target, backup_dir=backup_dir) == ()

    target.write_bytes(b"v0")
    create_backup(target, backup_dir=backup_dir, now=datetime(2026, 1, 1, tzinfo=UTC))
    target.write_bytes(b"v1")
    create_backup(target, backup_dir=backup_dir, now=datetime(2026, 6, 1, tzinfo=UTC))

    backups = list_backups(target, backup_dir=backup_dir)
    assert len(backups) == 2
    assert backups[0].created_at >= backups[1].created_at


def test_create_backup_returns_none_when_target_absent(tmp_path: Path) -> None:
    target = tmp_path / "does_not_exist.txt"
    assert create_backup(target, backup_dir=tmp_path / "backups") is None


def test_restore_backup_restores_and_backs_up_current(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    write_bytes_atomic(target, b"v1", backup=False, backup_dir=backup_dir)
    info = create_backup(target, backup_dir=backup_dir)
    assert info is not None
    write_bytes_atomic(target, b"v2", backup=False, backup_dir=backup_dir)

    restore_backup(info.path, target, backup_dir=backup_dir)
    assert target.read_bytes() == b"v1"

    backups = list_backups(target, backup_dir=backup_dir)
    assert any(b.path.read_bytes() == b"v2" for b in backups)


def test_restore_backup_missing_file_raises(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    target.write_bytes(b"v1")
    with pytest.raises(AtomicWriteError):
        restore_backup(tmp_path / "nope.bak", target, backup_dir=tmp_path / "backups")


def test_restore_backup_validate_failure_writes_nothing(tmp_path: Path) -> None:
    """A validate callback that raises must stop the restore before any write."""
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    write_bytes_atomic(target, b"v1", backup=False, backup_dir=backup_dir)
    bad_backup = tmp_path / "bad.bak"
    bad_backup.write_bytes(b"garbage")

    def raising_validate(data: bytes) -> None:
        assert data == b"garbage"
        raise ValueError("not a valid database")

    with pytest.raises(ValueError, match="not a valid database"):
        restore_backup(bad_backup, target, backup_dir=backup_dir, validate=raising_validate)

    assert target.read_bytes() == b"v1"
    assert list_backups(target, backup_dir=backup_dir) == ()


def test_restore_backup_validate_success_still_restores(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    write_bytes_atomic(target, b"v1", backup=False, backup_dir=backup_dir)
    info = create_backup(target, backup_dir=backup_dir)
    assert info is not None
    write_bytes_atomic(target, b"v2", backup=False, backup_dir=backup_dir)

    seen: list[bytes] = []
    restore_backup(info.path, target, backup_dir=backup_dir, validate=seen.append)

    assert seen == [b"v1"]
    assert target.read_bytes() == b"v1"


def test_backup_directory_cannot_be_created_raises(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    target.write_bytes(b"v1")
    blocking_file = tmp_path / "blocked"
    blocking_file.write_text("i am a file, not a dir")
    bad_backup_dir = blocking_file / "backups"

    with pytest.raises(AtomicWriteError):
        create_backup(target, backup_dir=bad_backup_dir)


@pytest.mark.skipif(os.name != "posix", reason="permission bits are not meaningful on this OS")
def test_atomic_write_creates_a_new_file_with_owner_only_permissions(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    old_umask = os.umask(0o000)
    try:
        write_bytes_atomic(target, b"x", backup=False, backup_dir=tmp_path / "backups")
    finally:
        os.umask(old_umask)

    assert target.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name != "posix", reason="permission bits are not meaningful on this OS")
def test_atomic_write_rewrites_an_existing_file_with_owner_only_permissions(
    tmp_path: Path,
) -> None:
    target = tmp_path / "data.txt"
    target.write_bytes(b"old")
    target.chmod(0o644)

    write_bytes_atomic(target, b"new", backup=False, backup_dir=tmp_path / "backups")

    assert target.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name != "posix", reason="permission bits are not meaningful on this OS")
def test_temp_file_is_not_world_readable_while_the_caller_holds_it(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    with atomic_write(target, backup=False, backup_dir=tmp_path / "backups") as tmp:
        assert tmp.stat().st_mode & 0o777 == 0o600
        tmp.write_bytes(b"hello")


def test_atomic_write_mkdir_failure_raises_atomic_write_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "sub" / "data.txt"
    real_mkdir = Path.mkdir

    def failing_mkdir(self: Path, *args: object, **kwargs: object) -> None:
        if self == target.parent:
            raise OSError("no space left on device")
        real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", failing_mkdir)

    with pytest.raises(AtomicWriteError), atomic_write(target, backup=False) as tmp:
        tmp.write_bytes(b"x")


def test_atomic_write_temp_file_creation_failure_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "data.txt"
    real_open = os.open

    def failing_open(path: object, flags: int, mode: int = 0o777) -> int:
        if isinstance(path, Path) and ".tmp-" in path.name:
            raise OSError("permission denied")
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", failing_open)

    with pytest.raises(AtomicWriteError), atomic_write(target, backup=False) as tmp:
        tmp.write_bytes(b"x")


def test_atomic_write_replace_failure_leaves_target_untouched_and_cleans_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "data.txt"
    target.write_bytes(b"original")
    real_replace = Path.replace

    def failing_replace(self: Path, target_arg: object) -> Path:
        if self.name.startswith(f".{target.name}.tmp-"):
            raise OSError("disk gone mid-replace")
        return real_replace(self, target_arg)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "replace", failing_replace)

    with pytest.raises(AtomicWriteError), atomic_write(target, backup=False) as tmp:
        tmp.write_bytes(b"new content")

    assert target.read_bytes() == b"original"
    leftovers = [p for p in tmp_path.iterdir() if p.name.startswith(f".{target.name}.tmp")]
    assert leftovers == []


@pytest.mark.skipif(os.name != "posix", reason="permission bits are not meaningful on this OS")
def test_backup_files_are_owner_only(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v1")
    target.chmod(0o644)

    write_bytes_atomic(target, b"v2", backup=True, backup_dir=backup_dir)

    backups = list_backups(target, backup_dir=backup_dir)
    assert backups
    for info in backups:
        assert info.path.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name != "posix", reason="permission bits are not meaningful on this OS")
def test_backup_dir_is_tightened_to_0700(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    backup_dir.chmod(0o755)

    write_bytes_atomic(target, b"v1", backup=False, backup_dir=backup_dir)
    write_bytes_atomic(target, b"v2", backup=True, backup_dir=backup_dir)

    assert backup_dir.stat().st_mode & 0o777 == 0o700
    assert len(list_backups(target, backup_dir=backup_dir)) == 1


@pytest.mark.skipif(os.name != "posix", reason="permission bits are not meaningful on this OS")
def test_backup_is_written_via_a_temp_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v1")
    target.chmod(0o644)

    real_copy2 = shutil.copy2
    seen_dst: list[Path] = []

    def fake_copy2(src: Path, dst: Path, *args: object, **kwargs: object) -> object:
        seen_dst.append(Path(dst))
        return real_copy2(src, dst, *args, **kwargs)

    monkeypatch.setattr(shutil, "copy2", fake_copy2)

    real_link = os.link
    modes_at_link: list[int] = []

    def fake_link(src: object, dst: object, *args: object, **kwargs: object) -> object:
        modes_at_link.append(Path(src).stat().st_mode & 0o777)
        return real_link(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "link", fake_link)

    info = create_backup(target, backup_dir=backup_dir)

    assert info is not None
    assert len(seen_dst) == 1
    # The copy lands on a temp path, not the final backup name.
    assert seen_dst[0] != info.path
    assert seen_dst[0].parent == backup_dir
    # The temp file is already 0o600 by the time it is linked into place --
    # this is what distinguishes chmod-on-temp-before-link (correct) from
    # chmod-on-destination-after-link (incorrect): both produce the same
    # *final* mode, but only the correct order satisfies this assertion.
    assert modes_at_link == [0o600]


def test_failed_backup_copy_leaves_no_stray_temp_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v1")

    def failing_copy2(src: Path, dst: Path, *args: object, **kwargs: object) -> object:
        raise OSError("disk gone")

    monkeypatch.setattr(shutil, "copy2", failing_copy2)

    with pytest.raises(AtomicWriteError):
        create_backup(target, backup_dir=backup_dir)

    stray = [p for p in backup_dir.iterdir() if ".tmp-" in p.name]
    assert stray == []


def test_prune_tolerates_a_backup_that_vanished(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v0")

    for i in range(3):
        target.write_bytes(f"v{i + 1}".encode())
        create_backup(
            target,
            backup_dir=backup_dir,
            retention=1000,
            now=datetime(2026, 8, 25, 0, 0, i, tzinfo=UTC),
        )

    backups = list_backups(target, backup_dir=backup_dir)
    assert len(backups) == 3
    victim = backups[-1].path  # oldest -- first candidate for pruning

    real_unlink = Path.unlink

    def flaky_unlink(self: Path, *args: object, **kwargs: object) -> None:
        if self == victim:
            raise FileNotFoundError(f"already gone: {self}")
        real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", flaky_unlink)

    removed = prune_backups(target, backup_dir=backup_dir, retention=1)

    assert victim not in removed
    assert len(removed) == 1


def test_prune_still_raises_on_a_permission_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v0")

    for i in range(2):
        target.write_bytes(f"v{i + 1}".encode())
        create_backup(
            target,
            backup_dir=backup_dir,
            retention=1000,
            now=datetime(2026, 8, 25, 0, 0, i, tzinfo=UTC),
        )

    def failing_unlink(self: Path, *args: object, **kwargs: object) -> None:
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "unlink", failing_unlink)

    with pytest.raises(AtomicWriteError):
        prune_backups(target, backup_dir=backup_dir, retention=1)


def test_atomic_write_completes_when_pruning_loses_a_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v0")

    for i in range(2):
        target.write_bytes(f"v{i + 1}".encode())
        create_backup(
            target,
            backup_dir=backup_dir,
            retention=1000,
            now=datetime(2026, 8, 25, 0, 0, i, tzinfo=UTC),
        )

    real_unlink = Path.unlink

    def flaky_unlink(self: Path, *args: object, **kwargs: object) -> None:
        # Only real backup files are "lost the race" -- the temp source
        # _claim_backup_path unlinks after a successful link is process-local
        # and no concurrent writer could ever have removed it first.
        if ".tmp-" in self.name:
            real_unlink(self, *args, **kwargs)
            return
        raise FileNotFoundError("lost the race")

    monkeypatch.setattr(Path, "unlink", flaky_unlink)

    write_bytes_atomic(target, b"v3", backup=True, backup_dir=backup_dir, retention=1)

    assert target.read_bytes() == b"v3"
    stray = [p for p in tmp_path.iterdir() if p.name.startswith(f".{target.name}.tmp")]
    assert stray == []


def test_list_backups_skips_a_file_removed_mid_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v0")

    for i in range(2):
        target.write_bytes(f"v{i + 1}".encode())
        create_backup(
            target,
            backup_dir=backup_dir,
            retention=1000,
            now=datetime(2026, 8, 25, 0, 0, i, tzinfo=UTC),
        )

    backups = list_backups(target, backup_dir=backup_dir)
    assert len(backups) == 2
    victim = backups[0].path

    real_stat = Path.stat

    def flaky_stat(self: Path, *args: object, **kwargs: object) -> os.stat_result:
        if self == victim:
            raise FileNotFoundError(f"vanished: {self}")
        return real_stat(self, *args, **kwargs)

    # Bypass is_file()'s own OSError-swallowing so the scan reaches the
    # guarded stat() calls this test is pinning, rather than short-circuiting
    # on the is_file() check first.
    monkeypatch.setattr(Path, "is_file", lambda _self: True)
    monkeypatch.setattr(Path, "stat", flaky_stat)

    remaining = list_backups(target, backup_dir=backup_dir)

    assert victim not in [info.path for info in remaining]
    assert len(remaining) == 1


def test_backup_preserves_source_mtime(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v1")

    info = create_backup(target, backup_dir=backup_dir)

    assert info is not None
    assert info.path.stat().st_mtime == pytest.approx(target.stat().st_mtime)


def test_backup_sweeps_a_stale_orphan_temp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v1")
    backup_dir.mkdir()
    orphan = (
        backup_dir / f".{backup_name(target, datetime(2026, 1, 1, tzinfo=UTC))}.tmp-999-deadbeef"
    )
    orphan.write_bytes(b"half-copied")

    monkeypatch.setattr(fs_primitives, "_STALE_TEMP_MIN_AGE_SECONDS", 0.0)
    info = create_backup(target, backup_dir=backup_dir)

    assert not orphan.exists()
    assert info is not None
    assert info.path.read_bytes() == b"v1"


def test_backup_preserves_a_live_concurrent_backup_temp(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v1")
    thirty_days_ago = datetime.now(tz=UTC).timestamp() - 30 * 24 * 60 * 60
    os.utime(target, (thirty_days_ago, thirty_days_ago))
    backup_dir.mkdir()

    # Reproduce the real in-flight code path: copy2 restores the source's
    # 30-day-old mtime onto the temp while leaving its ctime fresh, so an
    # mtime-only staleness check would sweep this live file immediately.
    live_temp = (
        backup_dir / f".{backup_name(target, datetime(2026, 1, 1, tzinfo=UTC))}.tmp-999-deadbeef"
    )
    shutil.copy2(target, live_temp)
    assert live_temp.stat().st_mtime == pytest.approx(thirty_days_ago)

    create_backup(target, backup_dir=backup_dir)

    assert live_temp.exists()


def test_atomic_write_sweeps_a_stale_orphan_in_the_target_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "data.txt"
    orphan = tmp_path / f".{target.name}.tmp-999-deadbeef"
    orphan.write_bytes(b"half-written")

    monkeypatch.setattr(fs_primitives, "_STALE_TEMP_MIN_AGE_SECONDS", 0.0)
    with atomic_write(target, backup=False) as tmp:
        assert not orphan.exists()
        assert tmp.exists()
        tmp.write_bytes(b"v1")

    assert target.read_bytes() == b"v1"


def test_atomic_write_preserves_a_live_concurrent_temp_in_the_target_dir(tmp_path: Path) -> None:
    """Another writer's in-flight temp (fresh ctime) must survive this write's sweep."""
    target = tmp_path / "data.txt"
    live_temp = tmp_path / f".{target.name}.tmp-999-deadbeef"
    live_temp.write_bytes(b"another writer, mid-write")

    with atomic_write(target, backup=False) as tmp:
        tmp.write_bytes(b"v1")

    assert live_temp.read_bytes() == b"another writer, mid-write"
    assert target.read_bytes() == b"v1"


def test_sweep_leaves_real_backups_and_other_targets_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "data.txt"
    other = tmp_path / "other.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v1")
    backup_dir.mkdir()

    real_backup = backup_dir / backup_name(target, datetime(2026, 1, 1, tzinfo=UTC))
    real_backup.write_bytes(b"v0")
    other_temp = (
        backup_dir / f".{backup_name(other, datetime(2026, 1, 1, tzinfo=UTC))}.tmp-999-deadbeef"
    )
    other_temp.write_bytes(b"not mine")

    monkeypatch.setattr(fs_primitives, "_STALE_TEMP_MIN_AGE_SECONDS", 0.0)
    create_backup(target, backup_dir=backup_dir, retention=0)

    assert real_backup.exists()
    assert other_temp.exists()


def test_sweep_never_raises_on_an_undeletable_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v1")
    backup_dir.mkdir()
    orphan = (
        backup_dir / f".{backup_name(target, datetime(2026, 1, 1, tzinfo=UTC))}.tmp-999-deadbeef"
    )
    orphan.write_bytes(b"undeletable")

    real_unlink = Path.unlink

    def refusing_unlink(self: Path, *args: object, **kwargs: object) -> None:
        if self == orphan:
            raise PermissionError(f"refusing to unlink {self}")
        real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(fs_primitives, "_STALE_TEMP_MIN_AGE_SECONDS", 0.0)
    monkeypatch.setattr(Path, "unlink", refusing_unlink)

    info = create_backup(target, backup_dir=backup_dir)

    assert info is not None
    assert info.path.read_bytes() == b"v1"
    assert orphan.exists()


def test_prune_failure_during_create_backup_only_warns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    target = tmp_path / "nodes_db.ods"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v0")

    def failing_prune(*args: object, **kwargs: object) -> tuple[Path, ...]:
        raise AtomicWriteError("simulated prune failure", path=str(target))

    monkeypatch.setattr(backups, "prune_backups", failing_prune)

    with caplog.at_level("WARNING", logger="meshprovision.db.backups"):
        write_bytes_atomic(target, b"v1", backup=True, backup_dir=backup_dir, retention=1)

    assert target.read_bytes() == b"v1"
    backup_files = [p for p in backup_dir.iterdir() if p.name.startswith(f"{target.stem}-")]
    assert len(backup_files) == 1
    assert backup_files[0].read_bytes() == b"v0"
    messages = [record.getMessage() for record in caplog.records]
    assert any("pruning old backups failed" in message for message in messages)
    stray = [p for p in tmp_path.iterdir() if p.name.startswith(f".{target.name}.tmp")]
    assert stray == []


def test_atomic_write_cleans_up_temp_when_backup_step_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "nodes_db.ods"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v0")

    def failing_create_backup(*args: object, **kwargs: object) -> None:
        raise AtomicWriteError("simulated backup failure", path=str(target))

    monkeypatch.setattr(atomic_writer, "create_backup", failing_create_backup)

    with (
        pytest.raises(AtomicWriteError),
        atomic_write(target, backup=True, backup_dir=backup_dir) as tmp,
    ):
        tmp.write_bytes(b"v1")

    assert target.read_bytes() == b"v0"
    stray = [p for p in tmp_path.iterdir() if p.name.startswith(f".{target.name}.tmp")]
    assert stray == []


def test_link_no_clobber_falls_back_when_hardlinks_are_unsupported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"payload")

    def unsupported_link(*args: object, **kwargs: object) -> None:
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(atomic_writer.os, "link", unsupported_link)

    link_no_clobber(source, destination)

    assert destination.read_bytes() == b"payload"
    assert not source.exists()


@pytest.mark.parametrize(
    "unsupported_errno", [errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS, errno.EMLINK]
)
def test_link_no_clobber_falls_back_for_every_unsupported_errno(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsupported_errno: int
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"payload")

    def unsupported_link(*args: object, **kwargs: object) -> None:
        raise OSError(unsupported_errno, "unsupported")

    monkeypatch.setattr(atomic_writer.os, "link", unsupported_link)

    link_no_clobber(source, destination)

    assert destination.read_bytes() == b"payload"
    assert not source.exists()


def test_link_no_clobber_reraises_unrelated_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"payload")

    def failing_link(*args: object, **kwargs: object) -> None:
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(atomic_writer.os, "link", failing_link)

    with pytest.raises(OSError, match="I/O error"):
        link_no_clobber(source, destination)

    assert source.exists()
    assert not destination.exists()


def test_link_no_clobber_does_not_clobber_existing_destination_under_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"new")
    destination.write_bytes(b"existing")

    def unsupported_link(*args: object, **kwargs: object) -> None:
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(atomic_writer.os, "link", unsupported_link)

    with pytest.raises(FileExistsError):
        link_no_clobber(source, destination)

    assert destination.read_bytes() == b"existing"
    assert source.read_bytes() == b"new"


def test_link_no_clobber_cleans_up_placeholder_when_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"payload")

    def unsupported_link(*args: object, **kwargs: object) -> None:
        raise OSError(errno.EPERM, "Operation not permitted")

    def failing_replace(self: Path, *args: object, **kwargs: object) -> None:
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(atomic_writer.os, "link", unsupported_link)
    monkeypatch.setattr(Path, "replace", failing_replace)

    with pytest.raises(OSError, match="I/O error"):
        link_no_clobber(source, destination)

    assert not destination.exists()
    assert source.exists()


def test_claim_backup_path_falls_back_and_still_claims_first_free_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "backups"
    directory.mkdir()
    (directory / "data-20260825T031410.123456Z.txt").write_bytes(b"existing")
    source = directory / ".tmp-copy"
    source.write_bytes(b"new")

    def unsupported_link(*args: object, **kwargs: object) -> None:
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(atomic_writer.os, "link", unsupported_link)

    claimed = _claim_backup_path(directory, "data-20260825T031410.123456Z.txt", source)

    assert claimed.name == "data-20260825T031410.123456Z-1.txt"
    assert (directory / "data-20260825T031410.123456Z.txt").read_bytes() == b"existing"
    assert claimed.read_bytes() == b"new"
    assert not source.exists()


def test_write_bytes_atomic_succeeds_when_filesystem_has_no_hard_link_support(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "nodes_db.ods"
    backup_dir = tmp_path / "backups"
    write_bytes_atomic(target, b"v1", backup=False, backup_dir=backup_dir)

    def unsupported_link(*args: object, **kwargs: object) -> None:
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(atomic_writer.os, "link", unsupported_link)

    write_bytes_atomic(target, b"v2", backup=True, backup_dir=backup_dir)

    assert target.read_bytes() == b"v2"
    backups = list_backups(target, backup_dir=backup_dir)
    assert len(backups) == 1
    assert backups[0].path.read_bytes() == b"v1"
    assert backups[0].path.stat().st_mode & 0o777 == 0o600

    for directory in (tmp_path, backup_dir):
        stray = [p for p in directory.iterdir() if p.name.startswith(".") and "tmp" in p.name]
        assert stray == []


def test_backup_racing_an_identical_name_does_not_overwrite_without_hard_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two concurrent claims of the same candidate name still can't both win.

    Same race as ``test_backup_racing_an_identical_name_does_not_overwrite``,
    reproduced under the O_CREAT|O_EXCL fallback used when hard links are
    unsupported, to confirm that fallback is just as collision-safe.
    """
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v1")
    when = datetime(2026, 8, 25, 3, 14, 10, 123456, tzinfo=UTC)

    def unsupported_link(*args: object, **kwargs: object) -> None:
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(atomic_writer.os, "link", unsupported_link)

    real_copy2 = shutil.copy2
    inner: list[BackupInfo] = []

    def copy2_then_race(src: Path, dst: Path, *args: object, **kwargs: object) -> object:
        result = real_copy2(src, dst, *args, **kwargs)
        if not inner:  # only the outer call races; the inner one must not recurse
            monkeypatch.setattr(shutil, "copy2", real_copy2)
            target.write_bytes(b"v2")
            info = create_backup(target, backup_dir=backup_dir, now=when)
            assert info is not None
            inner.append(info)
            monkeypatch.setattr(shutil, "copy2", copy2_then_race)
        return result

    monkeypatch.setattr(shutil, "copy2", copy2_then_race)
    outer = create_backup(target, backup_dir=backup_dir, now=when)

    assert outer is not None
    assert outer.path != inner[0].path
    assert outer.path.read_bytes() == b"v1"
    assert inner[0].path.read_bytes() == b"v2"
    assert len(list_backups(target, backup_dir=backup_dir)) == 2


def test_atomic_write_cleans_up_temp_when_backup_step_raises_keyboard_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "nodes_db.ods"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v0")

    def interrupting_create_backup(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(atomic_writer, "create_backup", interrupting_create_backup)

    with (
        pytest.raises(KeyboardInterrupt),
        atomic_write(target, backup=True, backup_dir=backup_dir) as tmp,
    ):
        tmp.write_bytes(b"v1")

    assert target.read_bytes() == b"v0"
    stray = [p for p in tmp_path.iterdir() if p.name.startswith(f".{target.name}.tmp")]
    assert stray == []


# --- backup_dir_for: per-target resolution (1a) ------------------------------------


def test_backup_dir_for_resolves_next_to_an_absolute_target(tmp_path: Path) -> None:
    target = tmp_path / "fleet" / "nodes_db.ods"
    target.parent.mkdir()
    assert backup_dir_for(target) == target.parent / "backups"


def test_backup_dir_for_is_cwd_independent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "fleet" / "nodes_db.ods"
    target.parent.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    monkeypatch.chdir(elsewhere)
    assert backup_dir_for(target) == target.parent / "backups"


def test_backup_dir_for_resolves_a_relative_target_from_the_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    target = Path("data/nodes_db.ods")
    assert backup_dir_for(target) == tmp_path / "data" / "backups"


def test_backup_dir_for_explicit_override_ignores_target_location(tmp_path: Path) -> None:
    target = tmp_path / "fleetA" / "nodes_db.ods"
    override = tmp_path / "elsewhere" / "custom-backups"
    assert backup_dir_for(target, override) is override


def test_backup_dir_for_two_same_named_databases_never_share_a_directory(tmp_path: Path) -> None:
    fleet_a = tmp_path / "fleetA" / "nodes_db.ods"
    fleet_b = tmp_path / "fleetB" / "nodes_db.ods"
    fleet_a.parent.mkdir()
    fleet_b.parent.mkdir()

    assert backup_dir_for(fleet_a) != backup_dir_for(fleet_b)


# --- strict backup-name matching (1b) ------------------------------------------


def test_backup_name_re_rejects_a_sibling_stem_prefixed_database(tmp_path: Path) -> None:
    target = tmp_path / "fleet.ods"
    pattern = _backup_name_re(target)

    assert pattern.fullmatch("fleet-20260825T031410.123456Z.ods") is not None
    assert pattern.fullmatch("fleet-west-20260825T031410.123456Z.ods") is None
    assert pattern.fullmatch("fleet-west.known-good.ods") is None


def test_list_backups_excludes_a_sibling_database_sharing_a_stem_prefix(tmp_path: Path) -> None:
    """Reproduces aspect 3's HIGH, widened.

    `fleet-west.ods`'s files must never be counted among `fleet.ods`'s
    own backups, despite sharing a stem prefix and living in the same
    directory.
    """
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    target = tmp_path / "fleet.ods"

    own = backup_dir / "fleet-20260101T000000.000000Z.ods"
    own.write_bytes(b"fleet's own backup")
    (backup_dir / "fleet-west-20260102T000000.000000Z.ods").write_bytes(b"west's backup")
    (backup_dir / "fleet-west.known-good.ods").write_bytes(b"west's known-good")

    backups = list_backups(target, backup_dir=backup_dir)

    assert [info.path for info in backups] == [own]


def test_prune_backups_never_deletes_a_sibling_stem_prefixed_databases_files(
    tmp_path: Path,
) -> None:
    backup_dir = tmp_path / "backups"
    fleet = tmp_path / "fleet.ods"
    fleet_west = tmp_path / "fleet-west.ods"
    fleet.write_bytes(b"fleet v0")
    fleet_west.write_bytes(b"fleet-west v0")

    for i in range(3):
        fleet.write_bytes(f"fleet v{i + 1}".encode())
        create_backup(
            fleet,
            backup_dir=backup_dir,
            retention=1000,
            now=datetime(2026, 1, 1, 0, 0, i, tzinfo=UTC),
        )
    for i in range(3):
        fleet_west.write_bytes(f"fleet-west v{i + 1}".encode())
        create_backup(
            fleet_west,
            backup_dir=backup_dir,
            retention=1000,
            now=datetime(2026, 1, 1, 0, 0, i, tzinfo=UTC),
        )
    (backup_dir / "fleet-west.known-good.ods").write_bytes(b"west's known-good")

    removed = prune_backups(fleet, backup_dir=backup_dir, retention=1)

    assert all("fleet-west" not in path.name for path in removed)
    assert len(list_backups(fleet_west, backup_dir=backup_dir)) == 3
    assert (backup_dir / "fleet-west.known-good.ods").exists()


def test_hand_named_backup_is_no_longer_listed_or_pruned(tmp_path: Path) -> None:
    """Documented behavior change (1b).

    A hand-named file that merely starts with the target's stem is no
    longer treated as one of its backups.
    """
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    target = tmp_path / "nodes_db.ods"
    hand_named = backup_dir / "nodes_db-old.ods"
    hand_named.write_bytes(b"kept by hand")

    assert list_backups(target, backup_dir=backup_dir) == ()
    assert prune_backups(target, backup_dir=backup_dir, retention=0) == ()
    assert hand_named.exists()


# --- legacy CWD-relative backup directory notice (1d, D1=A) --------------------


def test_legacy_backup_notice_none_when_backup_dir_is_overridden(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    assert legacy_backup_notice(target, backup_dir=tmp_path / "custom") is None


def test_legacy_backup_notice_none_when_no_legacy_directory_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "elsewhere" / "nodes_db.ods"
    assert legacy_backup_notice(target) is None


def test_legacy_backup_notice_none_for_the_default_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data" / "backups").mkdir(parents=True)
    target = tmp_path / "data" / "nodes_db.ods"
    assert legacy_backup_notice(target) is None


def test_legacy_backup_notice_none_when_no_matching_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    legacy_dir = tmp_path / "data" / "backups"
    legacy_dir.mkdir(parents=True)
    (legacy_dir / "unrelated-thing.ods").write_bytes(b"x")
    target = tmp_path / "elsewhere" / "nodes_db.ods"

    assert legacy_backup_notice(target) is None


def test_legacy_backup_notice_reports_matching_legacy_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    legacy_dir = tmp_path / "data" / "backups"
    legacy_dir.mkdir(parents=True)
    target = tmp_path / "elsewhere" / "nodes_db.ods"
    target.parent.mkdir()
    (legacy_dir / "nodes_db-20260101T000000.000000Z.ods").write_bytes(b"x")
    (legacy_dir / "nodes_db-20260102T000000.000000Z.ods").write_bytes(b"y")
    (legacy_dir / "nodes_db_other-20260101T000000.000000Z.ods").write_bytes(b"not a match")

    notice = legacy_backup_notice(target)

    assert notice is not None
    assert "2 older backups" in notice
    assert "data/backups" in notice
    assert "--known-good" in notice


# --- atomic_write resolves a symlinked target (B3) ------------------------------


def test_atomic_write_through_a_symlink_updates_the_real_file(tmp_path: Path) -> None:
    real_dir = tmp_path / "shared"
    real_dir.mkdir()
    real_target = real_dir / "nodes_db.ods"
    link_dir = tmp_path / "ws1" / "data"
    link_dir.mkdir(parents=True)
    link = link_dir / "nodes_db.ods"
    link.symlink_to(real_target)

    write_bytes_atomic(link, b"hello", backup=False)

    assert link.is_symlink()
    assert link.resolve() == real_target
    assert real_target.read_bytes() == b"hello"


def test_atomic_write_through_a_symlink_does_not_replace_the_link_with_a_regular_file(
    tmp_path: Path,
) -> None:
    real_dir = tmp_path / "shared"
    real_dir.mkdir()
    real_target = real_dir / "nodes_db.ods"
    real_target.write_bytes(b"original")
    link_dir = tmp_path / "ws1" / "data"
    link_dir.mkdir(parents=True)
    link = link_dir / "nodes_db.ods"
    link.symlink_to(real_target)

    write_bytes_atomic(link, b"updated", backup=False)

    assert link.is_symlink()
    assert real_target.read_bytes() == b"updated"


def test_atomic_write_backups_follow_a_symlinked_target(tmp_path: Path) -> None:
    real_dir = tmp_path / "shared"
    real_dir.mkdir()
    real_target = real_dir / "nodes_db.ods"
    real_target.write_bytes(b"original")
    link_dir = tmp_path / "ws1" / "data"
    link_dir.mkdir(parents=True)
    link = link_dir / "nodes_db.ods"
    link.symlink_to(real_target)

    write_bytes_atomic(link, b"updated", backup=True)

    assert backup_dir_for(real_target).is_dir()
    assert not (link_dir / "backups").exists()


def test_atomic_write_creates_the_real_file_through_a_dangling_symlink(tmp_path: Path) -> None:
    real_dir = tmp_path / "shared"
    link_dir = tmp_path / "ws1" / "data"
    link_dir.mkdir(parents=True)
    real_target = real_dir / "nodes_db.ods"
    link = link_dir / "nodes_db.ods"
    link.symlink_to(real_target)

    write_bytes_atomic(link, b"hello", backup=False)

    assert link.is_symlink()
    assert real_target.read_bytes() == b"hello"


def test_atomic_write_symlink_loop_raises_atomic_write_error(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.symlink_to(b)
    b.symlink_to(a)

    with pytest.raises(AtomicWriteError):
        write_bytes_atomic(a, b"hello", backup=False)


_LOOP_MESSAGE = "symlink loop (too many levels of symbolic links)"


def _loop_target(tmp_path: Path, form: str, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Build one symlink-loop form :func:`fs_primitives.resolve_path` must refuse.

    ``file_loop``/``dir_loop`` are real loops, resolved natively by whichever
    Python runs the test. The other three force one Python version's
    ``Path.resolve()`` behaviour for the returned path, so every branch
    runs on every interpreter: ``runtime_error`` is 3.11/3.12 (non-strict
    resolve raises :class:`RuntimeError`), ``eloop_oserror`` a strict-style
    :class:`OSError` ``ELOOP``, and ``unresolved`` is 3.13+ handing back a
    parent-directory loop unresolved -- whose last component is no
    symlink at all, so only the whole-path check catches it.
    """
    a = tmp_path / "a.ods"
    a.symlink_to(tmp_path / "b.ods")
    (tmp_path / "b.ods").symlink_to(a)
    (tmp_path / "d1").symlink_to(tmp_path / "d2")
    (tmp_path / "d2").symlink_to(tmp_path / "d1")
    in_dir_loop = tmp_path / "d1" / "x.ods"
    if form == "file_loop":
        return a
    if form == "dir_loop":
        return in_dir_loop
    target = in_dir_loop if form == "unresolved" else a
    real_resolve = Path.resolve

    def fake_resolve(self: Path, strict: bool = False) -> Path:
        if self != target:
            return real_resolve(self, strict=strict)
        if form == "runtime_error":
            raise RuntimeError(f"Symlink loop from {str(self)!r}")
        if form == "eloop_oserror":
            raise OSError(errno.ELOOP, "Too many levels of symbolic links", str(self))
        return self.absolute()

    monkeypatch.setattr(Path, "resolve", fake_resolve)
    return target


@pytest.mark.parametrize(
    "form", ["file_loop", "dir_loop", "runtime_error", "eloop_oserror", "unresolved"]
)
def test_resolve_path_refuses_every_symlink_loop_form_alike(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, form: str
) -> None:
    """Every Python version's symlink-loop behaviour becomes the same AtomicWriteError.

    3.11/3.12 used to escape as a raw RuntimeError traceback from the
    unguarded resolve() sites (backup_dir_for, lock_path_for), and 3.13
    returned the loop unresolved -- including a loop in a parent
    directory, whose last component is no symlink at all.
    """
    path = _loop_target(tmp_path, form, monkeypatch)

    with pytest.raises(AtomicWriteError) as excinfo:
        fs_primitives.resolve_path(path)

    assert str(excinfo.value) == f"Failed to resolve {path}: {_LOOP_MESSAGE}"
    assert excinfo.value.path == str(path)
    assert excinfo.value.hint is not None
    assert "symlink" in excinfo.value.hint


def test_resolve_path_reports_any_other_resolve_failure_verbatim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-loop OSError, from resolve() itself or from the symlink check, keeps its text."""
    path = tmp_path / "nodes_db.ods"
    resolve_error = FileNotFoundError(errno.ENOENT, "No such file or directory")
    check_error = PermissionError(errno.EACCES, "Permission denied")

    def fake_resolve(self: Path, strict: bool = False) -> Path:
        raise resolve_error

    def fake_is_symlink(self: Path) -> bool:
        raise check_error

    for error, attr, fake in (
        (resolve_error, "resolve", fake_resolve),
        (check_error, "is_symlink", fake_is_symlink),
    ):
        with monkeypatch.context() as patch:
            patch.setattr(Path, attr, fake)
            with pytest.raises(AtomicWriteError) as excinfo:
                fs_primitives.resolve_path(path)

        assert str(excinfo.value) == f"Failed to resolve {path}: {error}"
        assert excinfo.value.hint is None
        assert excinfo.value.__cause__ is error


@pytest.mark.parametrize("link", ["file_link", "dir_link"])
def test_resolve_path_follows_a_good_symlink_without_reporting_a_loop(
    tmp_path: Path, link: str
) -> None:
    """The whole-path symlink check never flags an ordinary, fully resolvable symlink."""
    base = tmp_path.resolve()
    real_dir = base / "real"
    real_dir.mkdir()
    if link == "file_link":
        (real_dir / "nodes_db.ods").write_bytes(b"db")
        (base / "nodes_db.ods").symlink_to(real_dir / "nodes_db.ods")
        path = base / "nodes_db.ods"
    else:
        (base / "linked").symlink_to(real_dir)
        path = base / "linked" / "nodes_db.ods"

    assert fs_primitives.resolve_path(path) == real_dir / "nodes_db.ods"


def _seed_future_backups(target: Path, backup_dir: Path, count: int) -> list[Path]:
    """Create ``count`` backups of ``target`` named an hour or more ahead of the clock.

    Returns:
        Their paths, newest first.
    """
    future = datetime.now(tz=UTC) + timedelta(hours=1)
    for i in range(count):
        create_backup(target, backup_dir=backup_dir, retention=0, now=future + timedelta(seconds=i))
    return [info.path for info in list_backups(target, backup_dir=backup_dir)]


def _clock_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage() for r in caplog.records if "is behind the newest backup" in r.getMessage()
    ]


def test_create_backup_behind_the_clock_keeps_the_new_backup_and_lists_it_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(backups, "_warned_clock_behind", False)
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"old")
    seeded = _seed_future_backups(target, backup_dir, 3)
    target.write_bytes(b"new")

    info = create_backup(target, backup_dir=backup_dir, retention=3)

    assert info is not None
    assert info.path.read_bytes() == b"new"
    listed = list_backups(target, backup_dir=backup_dir)
    assert [entry.path for entry in listed] == [info.path, *seeded[:2]]
    assert listed[0].created_at == info.created_at
    assert info.created_at == listed[1].created_at + timedelta(microseconds=1)
    assert not seeded[-1].exists()


def test_create_backup_behind_the_clock_warns_once_per_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(backups, "_warned_clock_behind", False)
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v")
    _seed_future_backups(target, backup_dir, 2)

    with caplog.at_level(logging.WARNING, logger="meshprovision.db.backups"):
        create_backup(target, backup_dir=backup_dir)
        create_backup(target, backup_dir=backup_dir)

    warnings = _clock_warnings(caplog)
    assert len(warnings) == 1
    assert str(target) in warnings[0]


def test_create_backup_with_an_explicit_earlier_now_sorts_newest_without_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(backups, "_warned_clock_behind", False)
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    target.write_bytes(b"v")
    legacy = backup_dir / "data-20991231T000000Z.txt"
    legacy.write_bytes(b"legacy")

    with caplog.at_level(logging.WARNING, logger="meshprovision.db.backups"):
        info = create_backup(target, backup_dir=backup_dir, now=datetime(2026, 1, 1, tzinfo=UTC))

    assert info is not None
    assert info.path.name == "data-20991231T000000.000001Z.txt"
    assert [entry.path for entry in list_backups(target, backup_dir=backup_dir)] == [
        info.path,
        legacy,
    ]
    assert _clock_warnings(caplog) == []


def test_prune_backups_never_deletes_the_kept_backup(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v")
    for i in range(4):
        create_backup(
            target,
            backup_dir=backup_dir,
            retention=0,
            now=datetime(2026, 1, 1, 0, 0, i, tzinfo=UTC),
        )
    paths = [info.path for info in list_backups(target, backup_dir=backup_dir)]

    removed = prune_backups(target, backup_dir=backup_dir, retention=2, keep=paths[-1])

    assert sorted(removed) == sorted(paths[1:3])
    assert [info.path for info in list_backups(target, backup_dir=backup_dir)] == [
        paths[0],
        paths[-1],
    ]


def _fail_fsync(
    monkeypatch: pytest.MonkeyPatch, *, file_errno: int | None, dir_errno: int | None
) -> None:
    """Make ``os.fsync`` raise ``file_errno`` for files and ``dir_errno`` for directories."""

    def fsync(fd: int) -> None:
        code = dir_errno if stat.S_ISDIR(os.fstat(fd).st_mode) else file_errno
        if code is not None:
            raise OSError(code, os.strerror(code))

    monkeypatch.setattr(os, "fsync", fsync)


@pytest.mark.skipif(sys.platform == "win32", reason="no directory fsync on Windows")
def test_write_bytes_atomic_flushes_the_temp_before_replacing_and_the_directory_after(
    tmp_path: Path, fsync_recorder: list[FsyncEvent]
) -> None:
    target = tmp_path / "data.txt"

    write_bytes_atomic(target, b"v1", backup=False)

    ino = target.stat().st_ino
    assert fsync_recorder == [
        ("fsync", ino, False),
        ("replace", ino, False),
        ("fsync", tmp_path.stat().st_ino, True),
    ]


def test_write_bytes_atomic_refuses_to_replace_when_the_file_flush_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "data.txt"
    target.write_bytes(b"v0")
    _fail_fsync(monkeypatch, file_errno=errno.EIO, dir_errno=None)

    with pytest.raises(AtomicWriteError, match=r"Failed to flush .* to disk"):
        write_bytes_atomic(target, b"v1", backup=False)

    assert target.read_bytes() == b"v0"
    assert sorted(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize(
    ("file_errno", "dir_errno"),
    [(errno.EINVAL, None), (None, errno.EIO)],
    ids=["file-flush-unsupported", "directory-flush-fails"],
)
def test_write_bytes_atomic_tolerates_an_unsupported_file_flush_or_a_failed_directory_flush(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, file_errno: int | None, dir_errno: int | None
) -> None:
    target = tmp_path / "data.txt"
    _fail_fsync(monkeypatch, file_errno=file_errno, dir_errno=dir_errno)

    write_bytes_atomic(target, b"v1", backup=False)

    assert target.read_bytes() == b"v1"


@pytest.mark.skipif(sys.platform == "win32", reason="no directory fsync on Windows")
def test_create_backup_flushes_the_copy_before_linking_it_and_the_directory_after(
    tmp_path: Path, fsync_recorder: list[FsyncEvent]
) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v0")
    backup_dir.mkdir()

    info = create_backup(target, backup_dir=backup_dir)

    assert info is not None
    ino = info.path.stat().st_ino
    assert fsync_recorder == [
        ("fsync", ino, False),
        ("link", ino, False),
        ("fsync", backup_dir.stat().st_ino, True),
    ]


def test_fsync_dir_is_a_no_op_on_windows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[object] = []
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(os, "open", lambda *args, **_kwargs: opened.append(args))

    fs_primitives._fsync_dir(tmp_path)

    assert opened == []


def _linked_target(tmp_path: Path) -> tuple[Path, Path]:
    """Build ``ws/fleet.ods`` -> ``shared/nodes_db.ods``: one file, two spellings."""
    real = tmp_path / "shared" / "nodes_db.ods"
    real.parent.mkdir()
    real.write_bytes(b"v0")
    link = tmp_path / "ws" / "fleet.ods"
    link.parent.mkdir()
    link.symlink_to(real)
    return real, link


def test_backups_through_either_spelling_share_names_and_one_listing(tmp_path: Path) -> None:
    """Saves (which resolve) and `mesh db backup` (which did not) used to split the history."""
    real, link = _linked_target(tmp_path)

    write_bytes_atomic(link, b"v1", backup=True)
    first = create_backup(link, now=datetime(2026, 1, 1, tzinfo=UTC))
    second = create_backup(real, now=datetime(2026, 1, 2, tzinfo=UTC))

    assert first is not None
    assert second is not None
    names = [info.path.name for info in list_backups(link)]
    assert len(names) == 3
    assert all(name.startswith("nodes_db-") for name in names)
    assert [info.path for info in list_backups(real)] == [info.path for info in list_backups(link)]


def test_older_spelling_backups_are_listed_and_pruned_with_the_rest(tmp_path: Path) -> None:
    real, link = _linked_target(tmp_path)
    directory = backup_dir_for(real)
    directory.mkdir()
    older = directory / backup_name(Path("fleet.ods"), datetime(2026, 1, 1, tzinfo=UTC))
    older.write_bytes(b"old")
    create_backup(link, now=datetime(2026, 1, 2, tzinfo=UTC))

    assert [info.path for info in list_backups(link)][1:] == [older]

    create_backup(link, retention=2, now=datetime(2026, 1, 3, tzinfo=UTC))

    assert not older.exists()
    assert len(list_backups(link)) == 2


def test_older_spelling_backups_are_left_to_the_database_that_owns_that_name(
    tmp_path: Path,
) -> None:
    real, link = _linked_target(tmp_path)
    (real.parent / "fleet.ods").write_bytes(b"another database")
    directory = backup_dir_for(real)
    directory.mkdir()
    theirs = directory / backup_name(Path("fleet.ods"), datetime(2026, 1, 1, tzinfo=UTC))
    theirs.write_bytes(b"theirs")

    create_backup(link, retention=1, now=datetime(2026, 1, 2, tzinfo=UTC))

    assert theirs.exists()
    assert theirs not in [info.path for info in list_backups(link)]
    assert backups.backup_name_targets(link) == (real,)
