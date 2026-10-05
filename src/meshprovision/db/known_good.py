"""The known-good copy: the last database that loaded cleanly.

A single, stable-named copy of a target file -- refreshed on every
successful load and save (see :func:`meshprovision.db.ods.load_database`
and :meth:`meshprovision.db.ods.OdsDatabase.save`) -- kept outside the
timestamped backup rotation in :mod:`meshprovision.db.backups` so
it is never pruned and never listed alongside it.

Alongside the copy itself, a small JSON sidecar (``<stem>.known-good.json``)
records which database it was refreshed from and a content hash. Two
different databases that happen to share a file name (two fleets, both
``nodes_db.ods``, one at each database's own resolved ``backups/``
directory) never collide on this copy, since :func:`~meshprovision.db.
backups.backup_dir_for` resolves per target -- but a directory
*copied or renamed* wholesale still carries an old known-good copy that
is no longer this database's, and the sidecar is what makes that
detectable. See :func:`known_good_status`.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Final

from meshprovision.db.atomic_writer import write_bytes_atomic
from meshprovision.db.backups import BackupInfo, backup_dir_for
from meshprovision.db.fs_primitives import _BACKUP_DIR_MODE, _FILE_MODE, resolve_path
from meshprovision.errors import AtomicWriteError

__all__ = [
    "KNOWN_GOOD_SUFFIX",
    "KnownGood",
    "KnownGoodProvenance",
    "known_good_info",
    "known_good_name",
    "known_good_path",
    "known_good_status",
    "provenance_reason",
    "refresh_known_good",
]

_logger = logging.getLogger(__name__)

_SIDECAR_FORMAT: Final[int] = 1

KNOWN_GOOD_SUFFIX: Final[str] = ".known-good"
"""Marker inserted between a target's stem and suffix for its known-good copy.

Deliberately a ``.`` immediately after the stem, not a ``-``, so
``known_good_name``'s output never matches
:func:`meshprovision.db.backups.list_backups`'/
:func:`meshprovision.db.backups.prune_backups`'
``f"{target.stem}-*{target.suffix}"`` glob -- the known-good copy is a
single stable slot outside the timestamped rotation, never pruned and
never listed alongside it.
"""


def known_good_name(target: Path) -> str:
    """Build the stable known-good file name for one target file.

    Args:
        target: The file the known-good copy is for.

    Returns:
        For example ``"nodes_db.known-good.ods"``.
    """
    return f"{target.stem}{KNOWN_GOOD_SUFFIX}{target.suffix}"


def known_good_path(target: Path, backup_dir: Path | None = None) -> Path:
    """Resolve the known-good copy's path for a target file.

    Args:
        target: The file the known-good copy is for.
        backup_dir: An explicit backup directory to use instead of the
            default.

    Returns:
        ``backup_dir_for(target, backup_dir) / known_good_name(target)``.
    """
    return backup_dir_for(target, backup_dir) / known_good_name(target)


def known_good_info(target: Path, *, backup_dir: Path | None = None) -> BackupInfo | None:
    """Look up the current known-good copy of a target file, if any.

    Pure ``stat()``, no write.

    Args:
        target: The file to look up a known-good copy for.
        backup_dir: Directory the known-good copy is stored under.
            Defaults to :func:`meshprovision.db.backups.backup_dir_for`'s
            resolution.

    Returns:
        Its metadata (``created_at`` taken from its mtime, since it has
        no embedded timestamp the way a rotated backup does), or
        ``None`` if no known-good copy exists yet, or it vanished or
        could not be stat'd between the existence check and the stat
        call (a concurrent refresh mid-replace -- treated the same as
        "none yet" rather than raised).
    """
    path = known_good_path(target, backup_dir)
    try:
        stat_result = path.stat()
    except OSError:
        return None
    return BackupInfo(
        path=path,
        source=target,
        created_at=datetime.fromtimestamp(stat_result.st_mtime, tz=UTC),
        size_bytes=stat_result.st_size,
    )


def _sidecar_name(target: Path) -> str:
    """Build the provenance sidecar's file name for one target file.

    Args:
        target: The file the known-good copy (and its sidecar) is for.

    Returns:
        For example ``"nodes_db.known-good.json"``. The ``.json``
        extension means this can never fullmatch
        :func:`meshprovision.db.backups._backup_name_re`'s pattern
        or the glob that prefilters it, so it is never mistaken for a
        timestamped backup.
    """
    return f"{target.stem}{KNOWN_GOOD_SUFFIX}.json"


def _sidecar_path(target: Path, backup_dir: Path | None = None) -> Path:
    """Resolve the provenance sidecar's path for a target file.

    Args:
        target: The file the known-good copy (and its sidecar) is for.
        backup_dir: An explicit backup directory to use instead of the
            default.

    Returns:
        ``backup_dir_for(target, backup_dir) / _sidecar_name(target)``.
    """
    return backup_dir_for(target, backup_dir) / _sidecar_name(target)


def _read_sidecar(path: Path) -> dict[str, object] | None:
    """Read and parse a provenance sidecar, tolerating any way it can be bad.

    Args:
        path: The sidecar file's path.

    Returns:
        Its parsed JSON object, or ``None`` if the file is missing,
        unreadable, not valid JSON, or not a JSON object -- all treated
        the same as "no provenance recorded", never raised.
    """
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _write_sidecar(path: Path, *, source: str, sha256_hex: str) -> None:
    """Atomically write a provenance sidecar.

    Args:
        path: The sidecar file's path.
        source: ``str(target.resolve())`` at the moment the known-good
            copy was refreshed.
        sha256_hex: Hex SHA-256 digest of the known-good copy's bytes.

    Raises:
        AtomicWriteError: If the write fails. The caller is expected to
            catch this alongside :class:`OSError`, matching
            :func:`refresh_known_good`'s "never raises" contract.
    """
    payload = json.dumps(
        {"format": _SIDECAR_FORMAT, "source": source, "sha256": sha256_hex}
    ).encode("ascii")
    write_bytes_atomic(path, payload, backup=False)


class KnownGoodProvenance(StrEnum):
    """How trustworthy a known-good copy's recorded origin is."""

    VERIFIED = "verified"
    """The sidecar's recorded source and content hash both match."""

    UNRECORDED = "unrecorded"
    """No sidecar, or it could not be parsed -- written by an older
    meshprovision, or the sidecar was lost/removed independently of the
    copy."""

    OTHER_SOURCE = "other_source"
    """The sidecar names a different database as this copy's source --
    typically a whole directory tree copied or renamed."""

    CONTENT_MISMATCH = "content_mismatch"
    """The sidecar's recorded source matches, but its content hash does
    not -- a torn or interleaved concurrent refresh, or the copy was
    modified independently of :func:`refresh_known_good`."""


@dataclass(frozen=True, slots=True)
class KnownGood:
    """A known-good copy together with how much its provenance can be trusted.

    Attributes:
        info: The copy's own metadata (path, timestamp, size).
        provenance: How trustworthy the recorded origin is.
        recorded_source: The sidecar's ``source`` field, or ``None`` when
            ``provenance`` is :attr:`KnownGoodProvenance.UNRECORDED`
            because no sidecar could be read at all.
    """

    info: BackupInfo
    provenance: KnownGoodProvenance
    recorded_source: str | None


def known_good_status(target: Path, *, backup_dir: Path | None = None) -> KnownGood | None:
    """Look up the current known-good copy of a target file, with provenance.

    Unlike :func:`known_good_info`, this reads and hashes the copy's
    bytes and its sidecar, so it is not free -- callers that only need
    to know a copy exists (for example a per-load fast-path check, or a
    display-only listing) should prefer :func:`known_good_info`. This is
    meant for the error and restore paths, which run rarely, where the
    provenance decision actually matters.

    Args:
        target: The file to look up a known-good copy for.
        backup_dir: Directory the known-good copy is stored under.
            Defaults to :func:`meshprovision.db.backups.backup_dir_for`'s
            resolution.

    Returns:
        ``None`` if no known-good copy exists yet (same as
        :func:`known_good_info`). Otherwise a :class:`KnownGood` whose
        ``provenance`` is :attr:`~KnownGoodProvenance.VERIFIED` only when
        a sidecar exists, names this exact resolved ``target`` as its
        source, and its recorded hash matches the copy's actual bytes.
    """
    info = known_good_info(target, backup_dir=backup_dir)
    if info is None:
        return None

    sidecar = _read_sidecar(_sidecar_path(target, backup_dir))
    recorded_source = sidecar.get("source") if sidecar is not None else None
    if sidecar is None or not isinstance(recorded_source, str):
        return KnownGood(info=info, provenance=KnownGoodProvenance.UNRECORDED, recorded_source=None)

    try:
        current_source = str(resolve_path(target))
    except AtomicWriteError:
        current_source = str(target)
    if recorded_source != current_source:
        return KnownGood(
            info=info,
            provenance=KnownGoodProvenance.OTHER_SOURCE,
            recorded_source=recorded_source,
        )

    try:
        actual_sha256 = hashlib.sha256(info.path.read_bytes()).hexdigest()
    except OSError:
        return KnownGood(
            info=info, provenance=KnownGoodProvenance.UNRECORDED, recorded_source=recorded_source
        )
    if sidecar.get("sha256") != actual_sha256:
        return KnownGood(
            info=info,
            provenance=KnownGoodProvenance.CONTENT_MISMATCH,
            recorded_source=recorded_source,
        )

    return KnownGood(
        info=info, provenance=KnownGoodProvenance.VERIFIED, recorded_source=recorded_source
    )


def provenance_reason(status: KnownGood) -> str:
    """Describe why a known-good copy's provenance is not verified.

    Args:
        status: A :class:`KnownGood` whose ``provenance`` is not
            :attr:`~KnownGoodProvenance.VERIFIED`.

    Returns:
        A short, lowercase clause suitable for embedding in a sentence,
        for example "it has no provenance record...".

    Raises:
        ValueError: If ``status.provenance`` is already
            :attr:`~KnownGoodProvenance.VERIFIED` -- there is nothing to
            explain.
    """
    if status.provenance is KnownGoodProvenance.UNRECORDED:
        return "it has no provenance record (written by an older meshprovision)"
    if status.provenance is KnownGoodProvenance.OTHER_SOURCE:
        return f"it was taken from {status.recorded_source}, not this database"
    if status.provenance is KnownGoodProvenance.CONTENT_MISMATCH:
        return "its recorded checksum no longer matches its content"
    raise ValueError(f"{status.provenance} is already verified; there is no mismatch to explain")


def _superseded(target: Path, source_stat: os.stat_result, destination: Path) -> bool:
    """Whether a newer version of ``target`` already reached the known-good copy.

    True only when both hold: ``target`` itself has moved on since the
    read ``source_stat`` describes (a different device/inode/mtime/size
    -- the same identity tuple :meth:`meshprovision.db.ods.OdsDatabase.
    _check_not_concurrently_modified` uses), *and* the known-good copy
    already mirrors that newer ``target`` by ``(mtime_ns, size)`` -- the
    identity :func:`refresh_known_good` itself stamps onto every copy it
    writes. That second condition is what keeps a validated read whose
    ``target`` was then broken (by a hand-edit, say) still able to
    refresh the copy: only a copy someone else already brought up to
    date with the newer ``target`` is protected from being reverted.

    Args:
        target: The file the known-good copy is for.
        source_stat: The ``stat`` result of the read whose content is
            about to be written to the copy.
        destination: The known-good copy's path.

    Returns:
        ``False`` whenever either file cannot be stat'd (including no
        known-good copy yet), so the caller just goes ahead and writes.
    """
    try:
        live = target.stat()
        copy = destination.stat()
    except OSError:
        return False
    source_identity = (
        source_stat.st_dev,
        source_stat.st_ino,
        source_stat.st_mtime_ns,
        source_stat.st_size,
    )
    if (live.st_dev, live.st_ino, live.st_mtime_ns, live.st_size) == source_identity:
        return False
    return (copy.st_mtime_ns, copy.st_size) == (live.st_mtime_ns, live.st_size)


def refresh_known_good(
    target: Path,
    *,
    content: bytes,
    source_stat: os.stat_result,
    backup_dir: Path | None = None,
) -> BackupInfo | None:
    """Refresh the single, stable known-good copy of a target file.

    Unlike every other function in this module, **this never raises**.
    It is called from :func:`meshprovision.db.ods.load_database` on
    *every* successful load -- including read-only commands such as
    ``mesh status``/``mesh db list`` -- so a read must never fail just
    because a safety copy of it could not be written (a full disk, a
    read-only-mounted backup directory, a permissions problem): any such
    failure is logged at ``WARNING`` and swallowed.

    ``content`` and ``source_stat`` must come from the exact same read of
    ``target`` that was validated (see :func:`meshprovision.db.ods_read.
    _read_db_file`), not from a fresh open of ``target`` here. Re-opening
    the path at this point is exactly the TOCTOU this closes: a write
    landing between validation and this call would otherwise publish
    unvalidated bytes as "known-good". The known-good copy is written
    from ``content`` directly, never by copying ``target`` again.

    A no-op, cheap ``stat()``-only call when the known-good copy already
    matches ``source_stat``'s content identity: this function preserves
    the source's mtime onto the copy (``os.utime``, mirroring what
    ``shutil.copy2`` used to provide), so a known-good copy whose
    ``(mtime_ns, size)`` equals ``source_stat``'s ``(mtime_ns, size)`` is
    already current -- this is what keeps a polling loop (for example
    ``mesh status --watch``) from rewriting an unchanged copy on every
    single load. Comparing nanosecond mtime plus size, not just
    whole-second mtime alone, avoids treating two different writes as
    identical on a coarse-mtime filesystem (exFAT ~10ms, FAT32 2s) or
    after an external tool rewrites ``target`` while preserving its mtime
    (``cp -p``, ``rsync -t``) -- either of which could otherwise leave
    the known-good copy silently stale.

    The fast path additionally requires the sidecar (see
    :func:`known_good_status`) to already name this exact resolved
    ``target`` as its source, and its recorded ``sha256`` to already match
    ``content``'s hash. Without the source check, a known-good copy left
    by an older meshprovision (no sidecar yet) whose ``(mtime_ns, size)``
    happens to match would never gain one -- this makes sure a first
    load after upgrading still writes it, healing the legacy copy into
    a verifiable one, at the cost of one extra recopy that one time.
    Without the hash check, a copy left mid-refresh -- killed between
    replacing the copy and writing its sidecar, or torn by two unlocked
    readers refreshing concurrently -- could have its
    :attr:`KnownGoodProvenance.CONTENT_MISMATCH` state persist forever,
    since the fast path would keep matching on mtime/size/source alone
    and never re-verify; requiring the hash to already agree makes the
    fast path self-heal that state on the very next load instead.

    Never reverts a copy that already reflects a *newer* write (see
    :func:`_superseded`). A read-only load holds no lock, so it can
    finish validating after a locked ``save()`` already replaced
    ``target`` and refreshed the copy from it; replacing that copy with
    this older read would leave ``mesh db restore --known-good`` restoring
    a version from before the save. Such a call keeps the copy as it is
    and returns its metadata. The check runs immediately before the
    replace but is not atomic with it: a competing refresh that lands
    entirely between the two can still be reverted -- by one version,
    which the next load's refresh corrects.

    Args:
        target: The file to refresh a known-good copy of.
        content: The exact bytes that were read and validated from
            ``target``. Written to the known-good copy as-is.
        source_stat: The ``stat`` result from the same read that produced
            ``content`` (see :func:`meshprovision.db.ods_read._read_db_file`,
            which uses ``fstat`` on the read fd so this describes exactly
            the inode ``content`` came from).
        backup_dir: Directory to store the known-good copy under.
            Defaults to :func:`meshprovision.db.backups.backup_dir_for`'s
            resolution.

    Returns:
        The refreshed (or already-current, or already-newer) copy's
        metadata, or ``None`` if the refresh itself failed.
    """
    try:
        current_source = str(resolve_path(target))
    except AtomicWriteError:
        current_source = str(target)
    tmp_destination: Path | None = None
    digest = hashlib.sha256(content).hexdigest()
    try:
        resolved_dir = backup_dir_for(target, backup_dir)
        destination = resolved_dir / known_good_name(target)
        sidecar_path = _sidecar_path(target, backup_dir)
        target_identity = (source_stat.st_mtime_ns, source_stat.st_size)
        if destination.is_file():
            dest_stat = destination.stat()
            if (dest_stat.st_mtime_ns, dest_stat.st_size) == target_identity:
                sidecar = _read_sidecar(sidecar_path)
                if (
                    sidecar is not None
                    and sidecar.get("source") == current_source
                    and sidecar.get("sha256") == digest
                ):
                    return known_good_info(target, backup_dir=backup_dir)

        resolved_dir.mkdir(parents=True, exist_ok=True)
        try:
            resolved_dir.chmod(_BACKUP_DIR_MODE)
        except OSError:
            _logger.debug("Failed to chmod backup directory %s", resolved_dir)

        tmp_destination = resolved_dir / f".{destination.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
        fd = os.open(tmp_destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, _FILE_MODE)
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
        os.utime(tmp_destination, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns))
        # Checked as late as possible -- after the temp copy is written,
        # immediately before the replace -- to keep the window in which
        # a newer refresh can still slip in behind this check as small
        # as it can be made without a lock.
        if _superseded(target, source_stat, destination):
            _logger.debug("Known-good copy of %s already reflects a newer write; kept.", target)
            with contextlib.suppress(OSError):
                tmp_destination.unlink()
            return known_good_info(target, backup_dir=backup_dir)
        tmp_destination.replace(destination)
        tmp_destination = None
        _write_sidecar(sidecar_path, source=current_source, sha256_hex=digest)
    except (OSError, AtomicWriteError) as exc:
        _logger.warning("Failed to refresh known-good copy of %s: %s", target, exc)
        if tmp_destination is not None:
            with contextlib.suppress(OSError):
                tmp_destination.unlink()
        return None

    return known_good_info(target, backup_dir=backup_dir)
