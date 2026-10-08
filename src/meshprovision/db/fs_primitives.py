"""Filesystem primitives shared by the backup and atomic-write layers.

Four leaf-level building blocks live here, with no dependency on either
:mod:`meshprovision.db.backups` or :mod:`meshprovision.db.atomic_writer`
(only on :mod:`meshprovision.errors`):

- :func:`resolve_path`, the one place a database-related path is
  resolved, so a symlink loop fails the same way on every supported
  Python: 3.11/3.12 raise :class:`RuntimeError` from a non-strict
  ``Path.resolve()``, while 3.13 hands back the path unresolved. Used by
  :func:`~meshprovision.db.atomic_writer.atomic_write`,
  :func:`~meshprovision.db.backups.backup_dir_for`,
  :func:`~meshprovision.db.locking.lock_path_for`, and the CLI's
  ``open_database``.

- :func:`link_no_clobber`, a collision-safe "give this file a new name"
  primitive, used by both the backup-claiming logic and by
  ``cli/setup.py``'s own no-clobber file creation.
- :func:`sweep_stale_temps`, a best-effort cleanup of orphaned temp
  files left by a killed writer, called from both the backup-creation
  path and the target-replace path.
- :func:`fsync_file`/:func:`fsync_fd` and :func:`fsync_dir`, the
  durability step of every write: a temp file's data is flushed to disk
  before it is renamed or linked into place, and its directory after, so
  a power cut cannot leave a final name pointing at an empty or torn
  file (XFS, f2fs and vfat -- and ext4 for a brand-new file -- can
  otherwise commit the rename before the data). Used by
  :func:`~meshprovision.db.atomic_writer.atomic_write`,
  :func:`~meshprovision.db.backups.create_backup` and
  :func:`~meshprovision.db.known_good.refresh_known_good`.

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
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from meshprovision.errors import AtomicWriteError

__all__ = [
    "BACKUP_DIR_MODE",
    "FILE_MODE",
    "STALE_TEMP_MIN_AGE_SECONDS",
    "fsync_dir",
    "fsync_fd",
    "fsync_file",
    "link_no_clobber",
    "resolve_path",
    "sweep_stale_temps",
    "temp_glob",
    "temp_sibling",
]

_logger = logging.getLogger(__name__)

BACKUP_DIR_MODE: Final[int] = 0o700

FILE_MODE: Final[int] = 0o600

STALE_TEMP_MIN_AGE_SECONDS: Final[float] = 24 * 60 * 60
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

_FSYNC_UNSUPPORTED_ERRNOS: Final[frozenset[int]] = frozenset(
    {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS}
)
"""``fsync`` errnos meaning "this file cannot be synchronized here", not a failure.

``EINVAL`` is POSIX's own "does not support synchronization"; some
FUSE/SMB/old NFS mounts return the others. Anything else (``EIO``,
``ENOSPC``, ...) means the data may not have reached the disk.
"""


def sweep_stale_temps(
    directory: Path, pattern: str, *, min_age_seconds: float = STALE_TEMP_MIN_AGE_SECONDS
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
        The number of files actually removed. Every call site ignores
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


def temp_sibling(directory: Path, name: str) -> Path:
    """Return a fresh, unique temp-file path for ``name`` inside ``directory``.

    The one spelling of a write temp's name, ``.<name>.tmp-<pid>-<uuid>``,
    so :func:`temp_glob` -- and therefore :func:`sweep_stale_temps` --
    always matches what a killed writer left behind.

    Args:
        directory: The directory the temp file lives in.
        name: The final file name the temp stands in for.

    Returns:
        The temp path. Nothing is created on disk.
    """
    return directory / f".{name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"


def temp_glob(name_glob: str) -> str:
    """Return the sweep pattern matching :func:`temp_sibling` temps of ``name_glob``.

    Args:
        name_glob: A final file name, or a glob over final file names.

    Returns:
        A pattern for :func:`sweep_stale_temps`.
    """
    return f".{name_glob}.tmp-*"


_SYMLINK_LOOP_HINT: Final[str] = (
    "Fix or remove the looping symlink, or point --db-path/MESHPROVISION_DB_PATH at the real file."
)


def _symlink_loop_error(path: Path) -> AtomicWriteError:
    """Build the one error every symlink-loop form of :func:`resolve_path` raises.

    Args:
        path: The path that could not be resolved.

    Returns:
        The :class:`AtomicWriteError` to raise.
    """
    return AtomicWriteError(
        f"Failed to resolve {path}: symlink loop (too many levels of symbolic links)",
        path=str(path),
        hint=_SYMLINK_LOOP_HINT,
    )


def resolve_path(path: Path) -> Path:
    """Resolve ``path`` (non-strict: it need not exist), refusing symlink loops.

    A symlink loop surfaces differently per Python version: 3.11/3.12
    raise :class:`RuntimeError` even from a non-strict ``resolve()``, a
    strict resolve raises :class:`OSError` ``ELOOP``, and 3.13+ returns
    the path *unresolved*. A fully resolved path contains no symlink
    anywhere, so any component of the result that is still a symlink
    means a loop -- checking every component, not just the last, also
    catches a loop in a parent directory (``d1 -> d2 -> d1`` with the
    file at ``d1/x.ods``), whose final component 3.13 reports as no
    symlink at all.

    Args:
        path: The path to resolve.

    Returns:
        The resolved absolute path.

    Raises:
        AtomicWriteError: If ``path`` is part of a symlink loop, or
            resolving it fails for another reason (for example the
            working directory was removed).
    """
    try:
        resolved = path.resolve()
    except RuntimeError as exc:
        raise _symlink_loop_error(path) from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise _symlink_loop_error(path) from exc
        raise AtomicWriteError(f"Failed to resolve {path}: {exc}", path=str(path)) from exc
    try:
        is_loop = any(part.is_symlink() for part in (resolved, *resolved.parents))
    except OSError as exc:
        raise AtomicWriteError(f"Failed to resolve {path}: {exc}", path=str(path)) from exc
    if is_loop:
        raise _symlink_loop_error(path)
    return resolved


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
    That is the same residual :func:`sweep_stale_temps` already accepts
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
        os.close(os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, FILE_MODE))
        try:
            source.replace(destination)
        except OSError:
            with contextlib.suppress(OSError):
                destination.unlink()
            raise
        return
    source.unlink()


def fsync_fd(fd: int) -> None:
    """Flush an open file's data to disk.

    Calls ``os.fsync`` through the module attribute (never a ``from os
    import fsync`` binding), so the test suite's autouse no-op stub and
    the durability tests' recorders both reach it.

    Args:
        fd: An open file descriptor. A buffered writer must be flushed
            first.

    Raises:
        OSError: If the flush fails for any reason other than one of
            :data:`_FSYNC_UNSUPPORTED_ERRNOS`, which is logged at debug
            and otherwise ignored.
    """
    try:
        os.fsync(fd)
    except OSError as exc:
        if exc.errno not in _FSYNC_UNSUPPORTED_ERRNOS:
            raise
        _logger.debug("fsync is not supported here: %s", exc)


def fsync_file(path: Path) -> None:
    """Flush a closed file's data to disk, by path.

    Opened read-write rather than read-only, since Windows refuses to
    flush a descriptor without write access.

    Args:
        path: The file to flush.

    Raises:
        OSError: If ``path`` cannot be opened, or :func:`fsync_fd` fails.
    """
    fd = os.open(path, os.O_RDWR | getattr(os, "O_BINARY", 0))
    try:
        fsync_fd(fd)
    finally:
        os.close(fd)


def fsync_dir(directory: Path) -> None:
    """Best-effort flush of a directory, so a rename or link into it is durable.

    Never raises: by the time this runs the rename or link has already
    happened, so a failure here cannot be undone and must not fail the
    write -- it is logged at debug, like SQLite does. A no-op on Windows,
    which cannot open a directory at all (and needs no directory flush).

    Args:
        directory: The directory a file was just renamed or linked into.
    """
    if sys.platform == "win32":
        return
    try:
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        _logger.debug("could not fsync directory %s: %s", directory, exc)
