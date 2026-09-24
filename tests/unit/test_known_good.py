"""Tests for meshprovision.db.known_good."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from meshprovision.db import known_good
from meshprovision.db.atomic_writer import BackupInfo, create_backup, list_backups

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


# --- provenance sidecar (1c, D2=A) ----------------------------------------------


def test_refresh_known_good_writes_a_provenance_sidecar(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"

    known_good.refresh_known_good(target, backup_dir=backup_dir)

    sidecar = backup_dir / "nodes_db.known-good.json"
    assert sidecar.is_file()
    assert sidecar.stat().st_mode & 0o777 == 0o600
    payload = json.loads(sidecar.read_bytes())
    assert payload["format"] == 1
    assert payload["source"] == str(target.resolve())
    assert payload["sha256"] == hashlib.sha256(b"v1").hexdigest()


def test_refresh_known_good_rewrites_the_sidecar_when_content_changes(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    backup_dir = tmp_path / "backups"

    target.write_bytes(b"v1")
    known_good.refresh_known_good(target, backup_dir=backup_dir)
    first_mtime = target.stat().st_mtime

    target.write_bytes(b"v2-longer-content")
    os.utime(target, (first_mtime + 5, first_mtime + 5))
    known_good.refresh_known_good(target, backup_dir=backup_dir)

    sidecar = backup_dir / "nodes_db.known-good.json"
    payload = json.loads(sidecar.read_bytes())
    assert payload["sha256"] == hashlib.sha256(b"v2-longer-content").hexdigest()


def test_known_good_status_verified_immediately_after_refresh(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"
    known_good.refresh_known_good(target, backup_dir=backup_dir)

    status = known_good.known_good_status(target, backup_dir=backup_dir)

    assert status is not None
    assert status.provenance is known_good.KnownGoodProvenance.VERIFIED
    assert status.recorded_source == str(target.resolve())


def test_known_good_status_none_when_no_copy_exists(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    assert known_good.known_good_status(target, backup_dir=tmp_path / "backups") is None


def test_known_good_status_unrecorded_when_sidecar_is_missing(tmp_path: Path) -> None:
    """A known-good copy left by an older meshprovision, before the sidecar existed."""
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"
    known_good.refresh_known_good(target, backup_dir=backup_dir)
    (backup_dir / "nodes_db.known-good.json").unlink()

    status = known_good.known_good_status(target, backup_dir=backup_dir)

    assert status is not None
    assert status.provenance is known_good.KnownGoodProvenance.UNRECORDED
    assert status.recorded_source is None


def test_known_good_status_unrecorded_when_sidecar_is_malformed_json(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"
    known_good.refresh_known_good(target, backup_dir=backup_dir)
    (backup_dir / "nodes_db.known-good.json").write_bytes(b"not json{{")

    status = known_good.known_good_status(target, backup_dir=backup_dir)

    assert status is not None
    assert status.provenance is known_good.KnownGoodProvenance.UNRECORDED


def test_known_good_status_other_source_after_a_directory_copy(tmp_path: Path) -> None:
    """Reproduces the "whole fleet directory copied elsewhere" case (D2's headline)."""
    fleet_a_dir = tmp_path / "fleetA"
    fleet_a_dir.mkdir()
    target_a = fleet_a_dir / "nodes_db.ods"
    target_a.write_bytes(b"a")
    known_good.refresh_known_good(target_a, backup_dir=fleet_a_dir / "backups")

    fleet_c_dir = tmp_path / "fleetC"
    shutil.copytree(fleet_a_dir, fleet_c_dir)
    target_c = fleet_c_dir / "nodes_db.ods"

    status = known_good.known_good_status(target_c, backup_dir=fleet_c_dir / "backups")

    assert status is not None
    assert status.provenance is known_good.KnownGoodProvenance.OTHER_SOURCE
    assert status.recorded_source == str(target_a.resolve())


def test_known_good_status_content_mismatch_when_the_copy_is_tampered_with(
    tmp_path: Path,
) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"
    known_good.refresh_known_good(target, backup_dir=backup_dir)
    (backup_dir / "nodes_db.known-good.ods").write_bytes(b"tampered content, different size")

    status = known_good.known_good_status(target, backup_dir=backup_dir)

    assert status is not None
    assert status.provenance is known_good.KnownGoodProvenance.CONTENT_MISMATCH


def test_known_good_status_never_hashes_when_no_copy_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "nodes_db.ods"

    def fail_read(*args: object, **kwargs: object) -> bytes:
        raise AssertionError("must not read a nonexistent known-good copy")

    monkeypatch.setattr(Path, "read_bytes", fail_read)

    assert known_good.known_good_status(target, backup_dir=tmp_path / "backups") is None


def _dummy_backup_info(tmp_path: Path) -> BackupInfo:
    return BackupInfo(
        path=tmp_path / "nodes_db.known-good.ods",
        source=tmp_path / "nodes_db.ods",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        size_bytes=1,
    )


def test_provenance_reason_describes_each_non_verified_case(tmp_path: Path) -> None:
    info = _dummy_backup_info(tmp_path)

    unrecorded = known_good.KnownGood(
        info=info, provenance=known_good.KnownGoodProvenance.UNRECORDED, recorded_source=None
    )
    assert "no provenance record" in known_good.provenance_reason(unrecorded)

    other_source = known_good.KnownGood(
        info=info,
        provenance=known_good.KnownGoodProvenance.OTHER_SOURCE,
        recorded_source="/fleetB/nodes_db.ods",
    )
    assert "/fleetB/nodes_db.ods" in known_good.provenance_reason(other_source)

    mismatch = known_good.KnownGood(
        info=info,
        provenance=known_good.KnownGoodProvenance.CONTENT_MISMATCH,
        recorded_source=str(tmp_path / "nodes_db.ods"),
    )
    assert "checksum" in known_good.provenance_reason(mismatch)


def test_provenance_reason_raises_for_an_already_verified_status(tmp_path: Path) -> None:
    info = _dummy_backup_info(tmp_path)
    verified = known_good.KnownGood(
        info=info,
        provenance=known_good.KnownGoodProvenance.VERIFIED,
        recorded_source=str(tmp_path / "nodes_db.ods"),
    )

    with pytest.raises(ValueError, match="already verified"):
        known_good.provenance_reason(verified)


def test_refresh_known_good_heals_a_legacy_copy_missing_its_sidecar(tmp_path: Path) -> None:
    """A known-good copy from before the sidecar existed must still heal.

    Given a matching ``(mtime_ns, size)``, it must still gain a sidecar
    on the next load -- otherwise it can never become VERIFIED.
    """
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    legacy_copy = backup_dir / "nodes_db.known-good.ods"
    shutil.copy2(target, legacy_copy)
    assert not (backup_dir / "nodes_db.known-good.json").exists()

    info = known_good.refresh_known_good(target, backup_dir=backup_dir)

    assert info is not None
    status = known_good.known_good_status(target, backup_dir=backup_dir)
    assert status is not None
    assert status.provenance is known_good.KnownGoodProvenance.VERIFIED


def test_refresh_known_good_fast_path_requires_a_matching_sidecar_source(tmp_path: Path) -> None:
    """The (mtime_ns, size) fast path alone is not enough.

    A copy whose sidecar names a different source must still be
    recopied and get its own sidecar.
    """
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"
    known_good.refresh_known_good(target, backup_dir=backup_dir)

    # Simulate a directory copy: the sidecar still names the old source.
    sidecar = backup_dir / "nodes_db.known-good.json"
    stale = json.loads(sidecar.read_bytes())
    stale["source"] = str(tmp_path / "elsewhere" / "nodes_db.ods")
    sidecar.write_bytes(json.dumps(stale).encode())

    known_good.refresh_known_good(target, backup_dir=backup_dir)

    status = known_good.known_good_status(target, backup_dir=backup_dir)
    assert status is not None
    assert status.provenance is known_good.KnownGoodProvenance.VERIFIED
    assert status.recorded_source == str(target.resolve())


def test_known_good_path_differs_for_two_same_named_databases_in_different_directories(
    tmp_path: Path,
) -> None:
    """Aspect 5's headline regression for the original HIGH.

    Two same-named databases in different directories must never share
    a known-good slot.
    """
    fleet_a = tmp_path / "fleetA" / "nodes_db.ods"
    fleet_b = tmp_path / "fleetB" / "nodes_db.ods"
    fleet_a.parent.mkdir()
    fleet_b.parent.mkdir()

    assert known_good.known_good_path(fleet_a) != known_good.known_good_path(fleet_b)
