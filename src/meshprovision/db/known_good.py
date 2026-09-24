"""The known-good copy: the last database that loaded cleanly.

A single, stable-named copy of a target file -- refreshed on every
successful load (see :func:`meshprovision.db.ods.load_database`) -- kept
outside the timestamped backup rotation in :mod:`meshprovision.db.atomic_writer`
so it is never pruned and never listed alongside it.
"""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from meshprovision.db.atomic_writer import _BACKUP_DIR_MODE, _FILE_MODE, BackupInfo, backup_dir_for

__all__ = [
    "KNOWN_GOOD_SUFFIX",
    "known_good_info",
    "known_good_name",
    "known_good_path",
    "refresh_known_good",
]

_logger = logging.getLogger(__name__)

KNOWN_GOOD_SUFFIX: Final[str] = ".known-good"
"""Marker inserted between a target's stem and suffix for its known-good copy.

Deliberately a ``.`` immediately after the stem, not a ``-``, so
``known_good_name``'s output never matches
:func:`meshprovision.db.atomic_writer.list_backups`'/
:func:`meshprovision.db.atomic_writer.prune_backups`'
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
            Defaults to :func:`meshprovision.db.atomic_writer.backup_dir_for`'s
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


def refresh_known_good(target: Path, *, backup_dir: Path | None = None) -> BackupInfo | None:
    """Refresh the single, stable known-good copy of a target file.

    Unlike every other function in this module, **this never raises**.
    It is called from :func:`meshprovision.db.ods.load_database` on
    *every* successful load -- including read-only commands such as
    ``mesh status``/``mesh db list`` -- so a read must never fail just
    because a safety copy of it could not be written (a full disk, a
    read-only-mounted backup directory, a permissions problem): any such
    failure is logged at ``WARNING`` and swallowed.

    A no-op, cheap ``stat()``-only call when the known-good copy already
    matches ``target``'s current content: ``shutil.copy2`` (used here,
    same as :func:`meshprovision.db.atomic_writer.create_backup`)
    preserves the source's mtime onto the copy, so a known-good copy
    whose ``(mtime_ns, size)`` equals ``target``'s current ``(mtime_ns,
    size)`` is already current -- this is what keeps a polling loop (for
    example ``mesh status --watch``) from rewriting an unchanged copy on
    every single load. Comparing nanosecond mtime plus size, not just
    whole-second mtime alone, avoids treating two different writes as
    identical on a coarse-mtime filesystem (exFAT ~10ms, FAT32 2s) or
    after an external tool rewrites ``target`` while preserving its mtime
    (``cp -p``, ``rsync -t``) -- either of which could otherwise leave
    the known-good copy silently stale.

    Args:
        target: The file to refresh a known-good copy of.
        backup_dir: Directory to store the known-good copy under.
            Defaults to :func:`meshprovision.db.atomic_writer.backup_dir_for`'s
            resolution.

    Returns:
        The refreshed (or already-current) copy's metadata, or ``None``
        if ``target`` does not exist, or the refresh itself failed.
    """
    if not target.exists():
        return None

    resolved_dir = backup_dir_for(target, backup_dir)
    destination = resolved_dir / known_good_name(target)
    tmp_destination: Path | None = None
    try:
        target_stat = target.stat()
        target_identity = (target_stat.st_mtime_ns, target_stat.st_size)
        if destination.is_file():
            dest_stat = destination.stat()
            if (dest_stat.st_mtime_ns, dest_stat.st_size) == target_identity:
                return known_good_info(target, backup_dir=backup_dir)

        resolved_dir.mkdir(parents=True, exist_ok=True)
        try:
            resolved_dir.chmod(_BACKUP_DIR_MODE)
        except OSError:
            _logger.debug("Failed to chmod backup directory %s", resolved_dir)

        tmp_destination = resolved_dir / f".{destination.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
        shutil.copy2(target, tmp_destination)
        try:
            tmp_destination.chmod(_FILE_MODE)
        except OSError:
            _logger.debug("Failed to chmod known-good copy %s", tmp_destination)
        tmp_destination.replace(destination)
    except OSError as exc:
        _logger.warning("Failed to refresh known-good copy of %s: %s", target, exc)
        if tmp_destination is not None:
            with contextlib.suppress(OSError):
                tmp_destination.unlink()
        return None

    return known_good_info(target, backup_dir=backup_dir)
