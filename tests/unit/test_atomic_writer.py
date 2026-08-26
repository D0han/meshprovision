"""Tests for meshprovision.db.atomic_writer."""

from __future__ import annotations

import os
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from meshprovision.db.atomic_writer import (
    atomic_write,
    backup_name,
    create_backup,
    list_backups,
    prune_backups,
    restore_backup,
    write_bytes_atomic,
)
from meshprovision.errors import AtomicWriteError

pytestmark = pytest.mark.unit


def test_write_bytes_atomic_creates_file_no_stray_temp(tmp_path: Path) -> None:
    target = tmp_path / "data.txt"
    backup_dir = tmp_path / "backups"
    write_bytes_atomic(target, b"hello", backup=False, backup_dir=backup_dir)
    assert target.read_bytes() == b"hello"
    assert list(tmp_path.iterdir()) == [target] or all(
        p in (target, backup_dir) for p in tmp_path.iterdir()
    )
    stray = [p for p in tmp_path.iterdir() if p.name.startswith(".") and "tmp" in p.name]
    assert stray == []


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
    when = datetime(2026, 8, 25, 3, 14, 10, tzinfo=UTC)
    name = backup_name(target, when)
    assert name == "nodes_db-20260825T031410Z.ods"


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

    real_replace = Path.replace
    modes_at_replace: list[int] = []

    def fake_replace(self: Path, target_path: str | Path) -> Path:
        modes_at_replace.append(self.stat().st_mode & 0o777)
        return real_replace(self, target_path)

    monkeypatch.setattr(Path, "replace", fake_replace)

    info = create_backup(target, backup_dir=backup_dir)

    assert info is not None
    assert len(seen_dst) == 1
    # The copy lands on a temp path, not the final backup name.
    assert seen_dst[0] != info.path
    assert seen_dst[0].parent == backup_dir
    # The temp file is already 0o600 by the time it is renamed into place --
    # this is what distinguishes chmod-on-temp-before-replace (correct) from
    # chmod-on-destination-after-replace (incorrect): both produce the same
    # *final* mode, but only the correct order satisfies this assertion.
    assert modes_at_replace == [0o600]


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

    def flaky_unlink(self: Path, *args: object, **kwargs: object) -> None:
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
