"""Tests for meshprovision.db.known_good."""

from __future__ import annotations

import errno
import hashlib
import json
import logging
import os
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from meshprovision.db import fs_primitives, known_good
from meshprovision.db.backups import BackupInfo, create_backup, list_backups
from tests.unit.conftest import FsyncEvent

pytestmark = pytest.mark.unit


def _refresh(target: Path, *, backup_dir: Path | None = None) -> BackupInfo | None:
    """Call ``refresh_known_good`` with content/source_stat read fresh from ``target``.

    Matches how the real caller (``ods.load_database``, via
    ``ods_read._read_db_file``) supplies them -- from one read of ``target``,
    not from ``target`` alone -- for tests whose scenario is just
    "``target`` currently holds this content".
    """
    return known_good.refresh_known_good(
        target, content=target.read_bytes(), source_stat=target.stat(), backup_dir=backup_dir
    )


def test_known_good_name_and_path() -> None:
    target = Path("/some/dir/nodes_db.ods")
    assert known_good.known_good_name(target) == "nodes_db.known-good.ods"
    assert known_good.known_good_path(target, Path("/backups")) == Path(
        "/backups/nodes_db.known-good.ods"
    )


def test_known_good_info_none_when_absent(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    assert known_good.known_good_info(target, backup_dir=tmp_path / "backups") is None


def test_refresh_known_good_writes_the_given_content_not_targets_current_bytes(
    tmp_path: Path,
) -> None:
    """Regression for Round 37 aspect 3 Batch 2: the copy comes from ``content``.

    ``ods.load_database`` reads ``target`` once, validates those exact
    bytes, and only then calls this function -- so the copy must be
    built from the ``content``/``source_stat`` it is handed, never by
    re-opening ``target``, which could have changed underneath it
    between validation and this call (a concurrent ``db restore``, an
    external editor's save). Simulated here by passing content that
    differs from what is currently on disk at ``target``.
    """
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"validated content")
    backup_dir = tmp_path / "backups"
    stat_result = target.stat()

    # Something else replaces target's on-disk bytes after the read that
    # produced `content`/`stat_result` above -- the exact race this closes.
    target.write_bytes(b"a different, later write")

    info = known_good.refresh_known_good(
        target, content=b"validated content", source_stat=stat_result, backup_dir=backup_dir
    )

    assert info is not None
    assert info.path.read_bytes() == b"validated content"


def test_refresh_known_good_creates_a_stable_named_copy(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"

    info = _refresh(target, backup_dir=backup_dir)

    assert info is not None
    assert info.path == backup_dir / "nodes_db.known-good.ods"
    assert info.path.read_bytes() == b"v1"
    assert info.path.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name != "posix", reason="permission bits are not meaningful on this OS")
def test_refresh_known_good_tightens_backup_dir_to_0700(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    backup_dir.chmod(0o755)

    info = _refresh(target, backup_dir=backup_dir)

    assert info is not None
    assert backup_dir.stat().st_mode & 0o777 == 0o700


def test_refresh_known_good_never_matches_the_timestamped_backup_glob(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"

    create_backup(target, backup_dir=backup_dir)
    _refresh(target, backup_dir=backup_dir)

    timestamped = list_backups(target, backup_dir=backup_dir)
    assert len(timestamped) == 1
    refreshed = known_good.known_good_info(target, backup_dir=backup_dir)
    assert refreshed is not None
    assert refreshed.path not in {info.path for info in timestamped}


def test_refresh_known_good_updates_when_target_changed(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    backup_dir = tmp_path / "backups"

    target.write_bytes(b"v1")
    _refresh(target, backup_dir=backup_dir)
    first_mtime = target.stat().st_mtime

    target.write_bytes(b"v2-longer-content")
    # Force a mtime distinctly later than the first write's, rather than
    # relying on real wall-clock granularity between the two writes,
    # which can otherwise land in the same tick on a coarse filesystem
    # clock and make this test flaky.
    os.utime(target, (first_mtime + 5, first_mtime + 5))
    info = _refresh(target, backup_dir=backup_dir)

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
    _refresh(target, backup_dir=backup_dir)
    same_mtime = target.stat().st_mtime

    target.write_bytes(b"CORRUPT/CHANGED CONTENT, DIFFERENT SIZE")
    os.utime(target, (same_mtime, same_mtime))
    assert target.stat().st_mtime == same_mtime  # sanity: mtime genuinely unchanged

    info = _refresh(target, backup_dir=backup_dir)

    assert info is not None
    assert info.path.read_bytes() == b"CORRUPT/CHANGED CONTENT, DIFFERENT SIZE"


def test_refresh_known_good_skips_the_copy_when_target_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"
    _refresh(target, backup_dir=backup_dir)

    def fail_open(*args: object, **kwargs: object) -> int:
        raise AssertionError("the known-good copy must not be rewritten when target is unchanged")

    monkeypatch.setattr(known_good.os, "open", fail_open)

    info = _refresh(target, backup_dir=backup_dir)

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

    info = _refresh(target, backup_dir=backup_dir)

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

    info = _refresh(target, backup_dir=backup_dir)

    assert info is None
    leftover_temps = list(backup_dir.glob(".*.tmp-*"))
    assert leftover_temps == []


# --- provenance sidecar (1c, D2=A) ----------------------------------------------


def test_refresh_known_good_writes_a_provenance_sidecar(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"

    _refresh(target, backup_dir=backup_dir)

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
    _refresh(target, backup_dir=backup_dir)
    first_mtime = target.stat().st_mtime

    target.write_bytes(b"v2-longer-content")
    os.utime(target, (first_mtime + 5, first_mtime + 5))
    _refresh(target, backup_dir=backup_dir)

    sidecar = backup_dir / "nodes_db.known-good.json"
    payload = json.loads(sidecar.read_bytes())
    assert payload["sha256"] == hashlib.sha256(b"v2-longer-content").hexdigest()


def test_known_good_status_verified_immediately_after_refresh(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"
    _refresh(target, backup_dir=backup_dir)

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
    _refresh(target, backup_dir=backup_dir)
    (backup_dir / "nodes_db.known-good.json").unlink()

    status = known_good.known_good_status(target, backup_dir=backup_dir)

    assert status is not None
    assert status.provenance is known_good.KnownGoodProvenance.UNRECORDED
    assert status.recorded_source is None


def test_known_good_status_unrecorded_when_sidecar_is_malformed_json(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"
    _refresh(target, backup_dir=backup_dir)
    (backup_dir / "nodes_db.known-good.json").write_bytes(b"not json{{")

    status = known_good.known_good_status(target, backup_dir=backup_dir)

    assert status is not None
    assert status.provenance is known_good.KnownGoodProvenance.UNRECORDED


def test_known_good_status_unrecorded_when_the_sidecar_source_is_not_a_string(
    tmp_path: Path,
) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"
    _refresh(target, backup_dir=backup_dir)
    sidecar = backup_dir / "nodes_db.known-good.json"
    sidecar.write_text(json.dumps({**json.loads(sidecar.read_bytes()), "source": 5}))

    status = known_good.known_good_status(target, backup_dir=backup_dir)

    assert status is not None
    assert status.provenance is known_good.KnownGoodProvenance.UNRECORDED
    assert status.recorded_source is None


def test_known_good_status_is_not_verified_when_the_copy_cannot_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unreadable copy (EACCES, EIO) was never hashed, so it must not count as verified."""
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"
    _refresh(target, backup_dir=backup_dir)
    copy = backup_dir / "nodes_db.known-good.ods"
    real_read_bytes = Path.read_bytes

    def read_bytes(self: Path) -> bytes:
        if self == copy:
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(self))
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)

    status = known_good.known_good_status(target, backup_dir=backup_dir)

    assert status is not None
    assert status.provenance is known_good.KnownGoodProvenance.UNRECORDED
    assert status.recorded_source == str(target.resolve())


def test_known_good_status_other_source_after_a_directory_copy(tmp_path: Path) -> None:
    """Reproduces the "whole fleet directory copied elsewhere" case (D2's headline)."""
    fleet_a_dir = tmp_path / "fleetA"
    fleet_a_dir.mkdir()
    target_a = fleet_a_dir / "nodes_db.ods"
    target_a.write_bytes(b"a")
    _refresh(target_a, backup_dir=fleet_a_dir / "backups")

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
    _refresh(target, backup_dir=backup_dir)
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

    info = _refresh(target, backup_dir=backup_dir)

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
    _refresh(target, backup_dir=backup_dir)

    # Simulate a directory copy: the sidecar still names the old source.
    sidecar = backup_dir / "nodes_db.known-good.json"
    stale = json.loads(sidecar.read_bytes())
    stale["source"] = str(tmp_path / "elsewhere" / "nodes_db.ods")
    sidecar.write_bytes(json.dumps(stale).encode())

    _refresh(target, backup_dir=backup_dir)

    status = known_good.known_good_status(target, backup_dir=backup_dir)
    assert status is not None
    assert status.provenance is known_good.KnownGoodProvenance.VERIFIED
    assert status.recorded_source == str(target.resolve())


def test_refresh_known_good_heals_a_copy_left_mid_refresh_by_a_kill(tmp_path: Path) -> None:
    """Regression for Round 38 aspect 3 Batch 1 (C38-3).

    A process killed between replacing the known-good copy and writing
    its sidecar leaves the copy's content and the sidecar's recorded
    hash disagreeing. The old fast path matched on mtime/size/source
    alone and never re-checked the hash, so this CONTENT_MISMATCH state
    persisted forever. The fast path must now re-verify the hash and
    heal it on the very next refresh.
    """
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"
    _refresh(target, backup_dir=backup_dir)

    # Simulate the kill: a new copy lands (matching target's current
    # mtime/size), but the sidecar still records the old content's hash.
    target.write_bytes(b"v1-newer-same-length")
    copy_path = backup_dir / "nodes_db.known-good.ods"
    shutil.copy2(target, copy_path)
    os.utime(copy_path, ns=(target.stat().st_atime_ns, target.stat().st_mtime_ns))

    status_before = known_good.known_good_status(target, backup_dir=backup_dir)
    assert status_before is not None
    assert status_before.provenance is known_good.KnownGoodProvenance.CONTENT_MISMATCH

    _refresh(target, backup_dir=backup_dir)

    status_after = known_good.known_good_status(target, backup_dir=backup_dir)
    assert status_after is not None
    assert status_after.provenance is known_good.KnownGoodProvenance.VERIFIED
    sidecar_payload = json.loads((backup_dir / "nodes_db.known-good.json").read_bytes())
    assert sidecar_payload["sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()


def test_refresh_known_good_heals_a_copy_torn_by_interleaved_readers(tmp_path: Path) -> None:
    """Regression for Round 38 aspect 3 Batch 1 (C38-3).

    Two unlocked readers refreshing concurrently can interleave their
    copy-replace and sidecar-write steps, leaving the copy holding one
    version's content while the sidecar records a different version's
    hash. This must self-heal on the next refresh instead of staying
    stuck as CONTENT_MISMATCH.
    """
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"version-one")
    backup_dir = tmp_path / "backups"
    _refresh(target, backup_dir=backup_dir)

    # Reader B's copy (version-two) lands, matching target's current
    # mtime/size, but reader A's sidecar (version-one's hash) wins the
    # write race and is what's actually on disk afterward.
    target.write_bytes(b"version-two-content")
    copy_path = backup_dir / "nodes_db.known-good.ods"
    shutil.copy2(target, copy_path)
    os.utime(copy_path, ns=(target.stat().st_atime_ns, target.stat().st_mtime_ns))
    sidecar = backup_dir / "nodes_db.known-good.json"
    stale = json.loads(sidecar.read_bytes())
    stale["sha256"] = hashlib.sha256(b"version-one").hexdigest()
    sidecar.write_bytes(json.dumps(stale).encode())

    status_before = known_good.known_good_status(target, backup_dir=backup_dir)
    assert status_before is not None
    assert status_before.provenance is known_good.KnownGoodProvenance.CONTENT_MISMATCH

    _refresh(target, backup_dir=backup_dir)

    status_after = known_good.known_good_status(target, backup_dir=backup_dir)
    assert status_after is not None
    assert status_after.provenance is known_good.KnownGoodProvenance.VERIFIED
    sidecar_payload = json.loads(sidecar.read_bytes())
    assert sidecar_payload["sha256"] == hashlib.sha256(b"version-two-content").hexdigest()


def _replace_target(target: Path, data: bytes) -> None:
    """Install ``data`` at ``target`` as a new inode, the way every real write does."""
    tmp = target.with_name(f".{target.name}.writer-tmp")
    tmp.write_bytes(data)
    tmp.replace(target)


def test_refresh_known_good_never_reverts_a_copy_already_mirroring_a_newer_target(
    tmp_path: Path,
) -> None:
    """Regression for Round 39 aspect 3 (C39-1): a stale reader must not revert the copy.

    An unlocked read-only load reads v1, a locked save then replaces
    ``target`` with v2 and refreshes the copy from it, and only then
    does the slow reader's own refresh run -- with v1's content and
    stat. It must leave the v2 copy alone.
    """
    target = tmp_path / "nodes_db.ods"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v1")
    stale_stat = target.stat()

    _replace_target(target, b"v2-longer")
    _refresh(target, backup_dir=backup_dir)

    info = known_good.refresh_known_good(
        target, content=b"v1", source_stat=stale_stat, backup_dir=backup_dir
    )

    assert info is not None
    assert info.path.read_bytes() == b"v2-longer"
    status = known_good.known_good_status(target, backup_dir=backup_dir)
    assert status is not None
    assert status.provenance is known_good.KnownGoodProvenance.VERIFIED
    assert list(backup_dir.glob(".*.tmp-*")) == []


def test_refresh_known_good_rechecks_the_target_right_before_replacing_the_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C39-1: the check runs after the temp copy is written, not only on entry.

    A newer save-and-refresh is raced in from inside ``os.utime`` --
    after this call's temp copy is already written, before it replaces
    the known-good copy -- so a check placed only at the top of the
    function would miss it.
    """
    target = tmp_path / "nodes_db.ods"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v1")
    stale_stat = target.stat()
    real_utime = os.utime
    raced = False

    def racing_utime(path: Path, *, ns: tuple[int, int]) -> None:
        nonlocal raced
        real_utime(path, ns=ns)
        if not raced:
            raced = True
            _replace_target(target, b"v2-longer")
            _refresh(target, backup_dir=backup_dir)

    monkeypatch.setattr(known_good.os, "utime", racing_utime)

    known_good.refresh_known_good(
        target, content=b"v1", source_stat=stale_stat, backup_dir=backup_dir
    )

    assert raced
    assert (backup_dir / "nodes_db.known-good.ods").read_bytes() == b"v2-longer"
    status = known_good.known_good_status(target, backup_dir=backup_dir)
    assert status is not None
    assert status.provenance is known_good.KnownGoodProvenance.VERIFIED
    assert list(backup_dir.glob(".*.tmp-*")) == []


def test_refresh_known_good_still_captures_a_validated_read_when_target_then_breaks(
    tmp_path: Path,
) -> None:
    """C39-1: a target that moved on does not by itself block the refresh.

    Only a copy that already mirrors the newer ``target`` is protected.
    Here ``target`` was broken by hand right after a validated read, and
    the copy still holds an older version, so the validated read must
    still become the known-good copy.
    """
    target = tmp_path / "nodes_db.ods"
    backup_dir = tmp_path / "backups"
    target.write_bytes(b"v0")
    _refresh(target, backup_dir=backup_dir)
    _replace_target(target, b"v1-valid")
    validated_stat = target.stat()

    _replace_target(target, b"broken by hand")

    info = known_good.refresh_known_good(
        target, content=b"v1-valid", source_stat=validated_stat, backup_dir=backup_dir
    )

    assert info is not None
    assert info.path.read_bytes() == b"v1-valid"


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


def test_known_good_status_falls_back_when_the_target_cannot_be_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """known_good_status never raises on an unresolvable target: it compares the path as given.

    Forced to 3.11/3.12's behaviour (a non-strict resolve() raising
    RuntimeError on a symlink loop) so it holds on every interpreter.
    """
    base = tmp_path.resolve()
    target = base / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = base / "backups"
    _refresh(target, backup_dir=backup_dir)
    real_resolve = Path.resolve

    def fake_resolve(self: Path, strict: bool = False) -> Path:
        if self == target:
            raise RuntimeError(f"Symlink loop from {str(self)!r}")
        return real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", fake_resolve)

    status = known_good.known_good_status(target, backup_dir=backup_dir)

    assert status is not None
    assert status.provenance is known_good.KnownGoodProvenance.VERIFIED


@pytest.mark.skipif(sys.platform == "win32", reason="no directory fsync on Windows")
def test_refresh_known_good_flushes_the_copy_before_replacing_it_and_the_directory_after(
    tmp_path: Path, fsync_recorder: list[FsyncEvent]
) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"content")
    backup_dir = tmp_path / "backups"

    known_good.refresh_known_good(
        target, content=b"content", source_stat=target.stat(), backup_dir=backup_dir
    )

    copy_ino = known_good.known_good_path(target, backup_dir).stat().st_ino
    sidecar_ino = known_good._sidecar_path(target, backup_dir).stat().st_ino
    dir_event = ("fsync", backup_dir.stat().st_ino, True)
    assert fsync_recorder == [
        ("fsync", copy_ino, False),
        ("replace", copy_ino, False),
        dir_event,
        ("fsync", sidecar_ino, False),
        ("replace", sidecar_ino, False),
        dir_event,
    ]


def test_refresh_known_good_flush_failure_is_logged_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"content")
    backup_dir = tmp_path / "backups"

    def failing_fsync(_fd: int) -> None:
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(os, "fsync", failing_fsync)

    with caplog.at_level(logging.WARNING, logger="meshprovision.db.known_good"):
        result = known_good.refresh_known_good(
            target, content=b"content", source_stat=target.stat(), backup_dir=backup_dir
        )

    assert result is None
    assert "Failed to refresh known-good copy" in caplog.text
    assert list(backup_dir.iterdir()) == []


def _linked_db(tmp_path: Path) -> tuple[Path, Path]:
    """Build ``ws/fleet.ods`` -> ``shared/nodes_db.ods``: one database, two spellings."""
    real = tmp_path / "shared" / "nodes_db.ods"
    real.parent.mkdir()
    real.write_bytes(b"v1")
    link = tmp_path / "ws" / "fleet.ods"
    link.parent.mkdir()
    link.symlink_to(real)
    return real, link


def _rename_slot_to(real: Path, stem: str) -> tuple[Path, Path]:
    """Move the current known-good copy and sidecar to an older spelling of the name."""
    directory = known_good.known_good_path(real).parent
    copy = directory / f"{stem}.known-good.ods"
    sidecar = directory / f"{stem}.known-good.json"
    known_good.known_good_path(real).rename(copy)
    (directory / "nodes_db.known-good.json").rename(sidecar)
    return copy, sidecar


@pytest.mark.parametrize(
    "refresh_via_link", [True, False], ids=["refreshed-via-link", "refreshed-via-real"]
)
def test_known_good_has_one_verified_slot_across_spellings(
    tmp_path: Path, refresh_via_link: bool
) -> None:
    real, link = _linked_db(tmp_path)
    refresher, reader = (link, real) if refresh_via_link else (real, link)

    _refresh(refresher)
    status = known_good.known_good_status(reader)

    assert status is not None
    assert status.provenance is known_good.KnownGoodProvenance.VERIFIED
    assert status.info.path.name == "nodes_db.known-good.ods"
    assert known_good.known_good_path(link) == known_good.known_good_path(real)


def test_known_good_status_finds_a_copy_named_after_the_symlink(tmp_path: Path) -> None:
    """A database that fails to load right after upgrading must still restore --known-good."""
    real, link = _linked_db(tmp_path)
    _refresh(real)
    copy, _sidecar = _rename_slot_to(real, "fleet")

    status = known_good.known_good_status(link)

    assert status is not None
    assert status.info.path == copy
    assert status.provenance is known_good.KnownGoodProvenance.VERIFIED


def test_refresh_removes_an_older_spelling_copy_of_the_same_database(tmp_path: Path) -> None:
    real, link = _linked_db(tmp_path)
    _refresh(real)
    copy, sidecar = _rename_slot_to(real, "fleet")

    info = _refresh(link)

    assert info is not None
    assert info.path == known_good.known_good_path(real)
    assert not copy.exists()
    assert not sidecar.exists()


def test_an_unchanged_refresh_also_removes_an_older_spelling_copy(tmp_path: Path) -> None:
    """The fast path (copy already current) retires a leftover too, not only a rewrite."""
    real, link = _linked_db(tmp_path)
    _refresh(real)
    directory = known_good.known_good_path(real).parent
    copy = directory / "fleet.known-good.ods"
    sidecar = directory / "fleet.known-good.json"
    shutil.copy2(known_good.known_good_path(real), copy)
    shutil.copy2(directory / "nodes_db.known-good.json", sidecar)
    inode_before = known_good.known_good_path(real).stat().st_ino

    _refresh(link)

    assert known_good.known_good_path(real).stat().st_ino == inode_before
    assert not copy.exists()
    assert not sidecar.exists()


def test_refresh_keeps_an_older_spelling_copy_of_another_database(tmp_path: Path) -> None:
    real, link = _linked_db(tmp_path)
    _refresh(real)
    copy, sidecar = _rename_slot_to(real, "fleet")
    sidecar.write_text(json.dumps({"format": 1, "source": "/elsewhere/fleet.ods", "sha256": "0"}))

    _refresh(link)

    assert copy.exists()
    assert sidecar.exists()
    assert known_good.known_good_path(real).exists()


def test_refresh_interrupted_by_ctrl_c_leaves_no_temp_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The temp is a full database copy, keys included; only OSError used to clean it up."""
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"

    def interrupted_utime(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(known_good.os, "utime", interrupted_utime)

    with pytest.raises(KeyboardInterrupt):
        _refresh(target, backup_dir=backup_dir)

    assert list(backup_dir.iterdir()) == []


def test_refresh_sweeps_stale_temp_copies_under_every_spelling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real, link = _linked_db(tmp_path)
    directory = known_good.known_good_path(real).parent
    directory.mkdir()
    orphans = [
        directory / ".nodes_db.known-good.ods.tmp-999-deadbeef",
        directory / ".fleet.known-good.ods.tmp-999-deadbeef",
    ]
    for orphan in orphans:
        orphan.write_bytes(b"killed mid-refresh")
    unrelated = directory / ".other_db.known-good.ods.tmp-999-deadbeef"
    unrelated.write_bytes(b"another database's copy")
    monkeypatch.setattr(fs_primitives, "_STALE_TEMP_MIN_AGE_SECONDS", 0.0)

    _refresh(link)

    assert [orphan for orphan in orphans if orphan.exists()] == []
    assert unrelated.exists()
