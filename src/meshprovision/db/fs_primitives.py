"""Filesystem primitives shared by the backup and atomic-write layers.

Two leaf-level building blocks live here, with no dependency on either
:mod:`meshprovision.db.backups` or :mod:`meshprovision.db.atomic_writer`:

- :func:`link_no_clobber`, a collision-safe "give this file a new name"
  primitive, used by both the backup-claiming logic and by
  ``cli/setup.py``'s own no-clobber file creation.
- :func:`_sweep_stale_temps`, a best-effort cleanup of orphaned temp
  files left by a killed writer, called from both the backup-creation
  path and the target-replace path.

Both classes of temp file -- a backup's temp copy and a target's own
write temp -- are swept opportunistically at their creation sites, since
a SIGKILL between creating one and renaming it leaves an orphan nothing
else on disk ever reclaims. The sweep is age-guarded, and the guard
cannot key off mtime alone: ``shutil.copy2`` restores the *source*
file's mtime onto a backup temp, so a temp created seconds ago from a
month-old database looks a month old by mtime. Staleness is therefore
``now - max(st_mtime, st_ctime)``, and ``st_ctime`` (which ``copystat``
bumps and which no userspace call can set backwards) keeps a live
concurrent backup's temp file from being swept out from under it.
"""

from __future__ import annotations

import contextlib
import errno
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

__all__ = [
    "link_no_clobber",
]

_logger = logging.getLogger(__name__)

_BACKUP_DIR_MODE: Final[int] = 0o700

_FILE_MODE: Final[int] = 0o600

_STALE_TEMP_MIN_AGE_SECONDS: Final[float] = 24 * 60 * 60
"""Minimum age an orphaned temp file must reach before a sweep removes it."""

_LINK_UNSUPPORTED_ERRNOS: Final[frozenset[int]] = frozenset(
    {errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS, errno.EMLINK}
)
"""``os.link`` errnos meaning "this filesystem has no hard links", not a real failure.

Seen on FAT/exFAT and some SMB/FUSE mounts. ``EOPNOTSUPP`` and ``ENOTSUP``
are the same value on Linux; both are named because POSIX allows either.
Anything else (for example ``EIO``, ``ENOSPC``) is a genuine failure and
must not fall back.
"""


def _sweep_stale_temps(
    directory: Path, pattern: str, *, min_age_seconds: float = _STALE_TEMP_MIN_AGE_SECONDS
) -> int:
    """Best-effort removal of orphaned temp files left by a killed writer.

    Never raises: a temp file that vanishes mid-sweep (lost to another
    sweeper) or cannot be stat'd or unlinked is logged at debug and
    skipped, since failing to tidy up must never fail the write this
    sweep is running alongside.

    Age is measured as ``now - max(st_mtime, st_ctime)``, not by mtime
    alone. ``shutil.copy2`` restores the source database's mtime onto a
    backup temp, so an in-flight backup of a month-old database carries
    a month-old mtime the moment it is created; ``st_ctime`` is bumped
    by that same ``copystat`` and cannot be moved backwards from
    userspace, so taking the newer of the two errs towards keeping a
    file that might still be live.

    Args:
        directory: The directory to sweep.
        pattern: A glob matching only the temp class being swept. Must
            start with a literal ``"."`` to match these dot-prefixed
            names -- unlike the stdlib ``glob`` module,
            :meth:`pathlib.Path.glob` matches dotfiles when the pattern
            does.
        min_age_seconds: Minimum age, in seconds, before a match is
            removed.

    Returns:
        The number of files actually removed. Both call sites ignore
        this; it exists for tests and ad-hoc logging.
    """
    now = datetime.now(tz=UTC).timestamp()
    removed = 0
    for path in directory.glob(pattern):
        try:
            stat_result = path.stat()
            if now - max(stat_result.st_mtime, stat_result.st_ctime) < min_age_seconds:
                continue
            path.unlink()
        except OSError as exc:
            _logger.debug("could not sweep stale temp file %s: %s", path, exc)
            continue
        removed += 1
    return removed


def link_no_clobber(source: Path, destination: Path) -> None:
    """Give ``source``'s content the name ``destination``, without clobbering.

    Tries ``os.link`` first: it fails with :class:`FileExistsError`
    rather than overwriting, which is what makes the caller's
    claim-a-free-name loop safe against a concurrent writer racing for
    the same name. On a filesystem with no hard-link support (FAT/exFAT,
    some SMB/FUSE mounts), ``os.link`` instead fails with one of
    :data:`_LINK_UNSUPPORTED_ERRNOS`; this function then falls back to
    claiming ``destination`` with an ``O_CREAT | O_EXCL`` placeholder --
    which is exactly as collision-safe as ``os.link``'s own
    :class:`FileExistsError`, since it is the same atomic claim-a-name
    primitive -- and then ``os.replace``-ing ``source`` onto it. Either
    way, ``source`` is consumed: on the link path it is unlinked after
    the link succeeds; on the fallback path it is moved.

    A SIGKILL between the fallback's placeholder claim and its
    ``os.replace`` leaves a 0-byte file under ``destination``'s name.
    That is the same residual :func:`_sweep_stale_temps` already accepts
    for the link path's own unlink step, and it only arises on a
    filesystem with no hard links to begin with.

    Args:
        source: The file to give ``destination``'s name. Consumed on
            success.
        destination: The name to claim. Never overwritten if it already
            exists.

    Raises:
        FileExistsError: If ``destination`` already exists.
        OSError: If linking (and, on a link-less filesystem, the
            fallback claim or replace) fails for any other reason.
    """
    try:
        os.link(source, destination)
    except OSError as exc:
        # FileExistsError (EEXIST) is an OSError subclass and is never in
        # _LINK_UNSUPPORTED_ERRNOS, so it always re-raises here too.
        if exc.errno not in _LINK_UNSUPPORTED_ERRNOS:
            raise
        os.close(os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, _FILE_MODE))
        try:
            source.replace(destination)
        except OSError:
            with contextlib.suppress(OSError):
                destination.unlink()
            raise
        return
    source.unlink()
