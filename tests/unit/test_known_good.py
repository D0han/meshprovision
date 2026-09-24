"""Tests for meshprovision.db.known_good."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from meshprovision.db import known_good
from meshprovision.db.atomic_writer import create_backup, list_backups

pytestmark = pytest.mark.unit


def test_known_good_name_and_path() -> None:
    target = Path("/some/dir/nodes_db.ods")
    assert known_good.known_good_name(target) == "nodes_db.known-good.ods"
    assert known_good.known_good_path(target, Path("/backups")) == Path(
        "/backups/nodes_db.known-good.ods"
    )


def test_known_good_info_none_when_absent(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    assert known_good.known_good_info(target, backup_dir=tmp_path / "backups") is None


def test_refresh_known_good_none_when_target_absent(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    assert known_good.refresh_known_good(target, backup_dir=tmp_path / "backups") is None


def test_refresh_known_good_creates_a_stable_named_copy(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"

    info = known_good.refresh_known_good(target, backup_dir=backup_dir)

    assert info is not None
    assert info.path == backup_dir / "nodes_db.known-good.ods"
    assert info.path.read_bytes() == b"v1"
    assert info.path.stat().st_mode & 0o777 == 0o600


def test_refresh_known_good_never_matches_the_timestamped_backup_glob(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"

    create_backup(target, backup_dir=backup_dir)
    known_good.refresh_known_good(target, backup_dir=backup_dir)

    timestamped = list_backups(target, backup_dir=backup_dir)
    assert len(timestamped) == 1
    refreshed = known_good.known_good_info(target, backup_dir=backup_dir)
    assert refreshed is not None
    assert refreshed.path not in {info.path for info in timestamped}


def test_refresh_known_good_updates_when_target_changed(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    backup_dir = tmp_path / "backups"

    target.write_bytes(b"v1")
    known_good.refresh_known_good(target, backup_dir=backup_dir)
    first_mtime = target.stat().st_mtime

    target.write_bytes(b"v2-longer-content")
    # Force a mtime distinctly later than the first write's, rather than
    # relying on real wall-clock granularity between the two writes,
    # which can otherwise land in the same tick on a coarse filesystem
    # clock and make this test flaky.
    os.utime(target, (first_mtime + 5, first_mtime + 5))
    info = known_good.refresh_known_good(target, backup_dir=backup_dir)

    assert info is not None
    assert info.path.read_bytes() == b"v2-longer-content"


def test_refresh_known_good_detects_a_same_tick_content_change(tmp_path: Path) -> None:
    """Regression test for Round 35's backup-adoption review, Finding 8.

    The fast-path used to compare whole-second mtime alone, treating
    mtime equality as content equality -- which silently retains a stale
    copy on a coarse-mtime filesystem (exFAT ~10ms, FAT32 2s) or after an
    external tool rewrites target while preserving its mtime (cp -p,
    rsync -t). Forcing an identical mtime across two different-content
    writes simulates exactly that; the known-good copy must still be
    refreshed because the size differs.
    """
    target = tmp_path / "nodes_db.ods"
    backup_dir = tmp_path / "backups"

    target.write_bytes(b"GOOD CONTENT")
    known_good.refresh_known_good(target, backup_dir=backup_dir)
    same_mtime = target.stat().st_mtime

    target.write_bytes(b"CORRUPT/CHANGED CONTENT, DIFFERENT SIZE")
    os.utime(target, (same_mtime, same_mtime))
    assert target.stat().st_mtime == same_mtime  # sanity: mtime genuinely unchanged

    info = known_good.refresh_known_good(target, backup_dir=backup_dir)

    assert info is not None
    assert info.path.read_bytes() == b"CORRUPT/CHANGED CONTENT, DIFFERENT SIZE"


def test_refresh_known_good_skips_the_copy_when_target_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"
    known_good.refresh_known_good(target, backup_dir=backup_dir)

    def fail_copy(*args: object, **kwargs: object) -> None:
        raise AssertionError("shutil.copy2 must not be called when target is unchanged")

    monkeypatch.setattr(shutil, "copy2", fail_copy)

    info = known_good.refresh_known_good(target, backup_dir=backup_dir)

    assert info is not None
    assert info.path.read_bytes() == b"v1"


def test_refresh_known_good_never_raises_when_backup_dir_is_unwritable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"

    def refuse_mkdir(self: Path, *args: object, **kwargs: object) -> None:
        raise PermissionError(f"refusing to create {self}")

    monkeypatch.setattr(Path, "mkdir", refuse_mkdir)

    info = known_good.refresh_known_good(target, backup_dir=backup_dir)

    assert info is None
    assert target.read_bytes() == b"v1"  # the target itself is never touched


def test_refresh_known_good_cleans_up_its_temp_file_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"

    real_replace = Path.replace

    def refuse_replace(self: Path, other: Path) -> Path:
        if self.name.startswith(".") and "known-good" in self.name:
            raise OSError("simulated replace failure")
        return real_replace(self, other)

    monkeypatch.setattr(Path, "replace", refuse_replace)

    info = known_good.refresh_known_good(target, backup_dir=backup_dir)

    assert info is None
    leftover_temps = list(backup_dir.glob(".*.tmp-*"))
    assert leftover_temps == []
