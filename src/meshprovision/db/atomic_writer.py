"""Byte-level atomic file writes with pre-write timestamped backups.

This module has no knowledge of the ODS format at all -- it operates on
raw ``bytes``. The write pattern is: write to a temp file in the *same*
directory as the target (so the final rename is on one filesystem and
therefore atomic), copy the previous version of the target into a
timestamped backup directory (see :mod:`meshprovision.db.backups`,
itself via its own temp-then-rename, so a partially-copied backup can
never appear under a final name), then ``os.replace()`` the temp file
into place. Order matters: the backup is taken **before** the replace,
so an interrupted or failed replace never loses the pre-write state.

Both the target file and each backup are created with mode ``0o600``:
the target's temp file is pre-created at that mode before it is handed
to the caller, and ``os.replace`` carries it onto the target unchanged.
There is no window in which a fully-written database sits at the
process umask, and a brand-new database gets the same treatment as a
rewrite.

The target's own write temp is swept opportunistically at its creation
site (see :mod:`meshprovision.db.fs_primitives`), since a SIGKILL
between creating one and renaming it leaves an orphan nothing else on
disk ever reclaims.
"""

from __future__ import annotations

import contextlib
import os
import uuid
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path

from meshprovision.db import fs_primitives
from meshprovision.db.backups import DEFAULT_RETENTION, create_backup
from meshprovision.db.fs_primitives import _FILE_MODE
from meshprovision.errors import AtomicWriteError

__all__ = [
    "atomic_write",
    "restore_backup",
    "write_bytes_atomic",
]


@contextlib.contextmanager
def atomic_write(
    target: Path,
    *,
    backup: bool = True,
    backup_dir: Path | None = None,
    retention: int = DEFAULT_RETENTION,
    now: datetime | None = None,
) -> Iterator[Path]:
    """Yield a temp path in ``target.parent``; replace ``target`` atomically on success.

    ``target`` is resolved (non-strict) before anything else, so a
    symlinked database path is written through to the real file rather
    than having the symlink itself replaced by a regular file -- a
    concurrent write through a different symlink to the same real file
    is then a genuine collision, not a silent split-brain. See
    :func:`~meshprovision.db.locking.lock_path_for`, which resolves for
    the same reason.

    On clean exit from the ``with`` block, a backup of the current
    ``target`` is taken (when ``backup`` is true and ``target`` exists),
    and then the temp file is moved into place via ``os.replace()`` --
    atomic because both paths are on the same filesystem. On any
    exception raised inside the ``with`` block (including one raised by
    this function's own replace step), the temp file is removed and the
    exception propagates; ``target`` is left untouched.

    Args:
        target: The file to atomically write.
        backup: Whether to back up the current ``target`` before
            replacing it.
        backup_dir: Directory to store the backup under, when ``backup``
            is true. Defaults to
            :func:`~meshprovision.db.backups.backup_dir_for`'s
            resolution.
        retention: Number of backups to retain, when ``backup`` is true.
        now: Timestamp to embed in the backup's name, when ``backup`` is
            true. Defaults to the current time.

    Yields:
        A temporary file path in ``target``'s directory, already created
        with mode ``0o600``. The caller must write the full desired
        contents of ``target`` to this path; both ``open("wb")`` and
        ``write_bytes`` truncate without changing the mode.

    Raises:
        AtomicWriteError: If ``target`` cannot be resolved (for example a
            symlink loop), or if creating the temporary file, creating
            the backup, or replacing ``target`` fails.
    """
    try:
        target = target.resolve()
    except (OSError, RuntimeError) as exc:
        raise AtomicWriteError(f"Failed to resolve {target}: {exc}", path=str(target)) from exc
    # Python 3.13+ no longer raises on a symlink loop in a non-strict
    # resolve(); it hands back the unresolved path. A fully resolved path
    # is never itself a symlink, so one that still is means a loop --
    # refuse it rather than let os.replace swap the symlink for a file.
    if target.is_symlink():
        raise AtomicWriteError(
            f"Failed to resolve {target}: symlink loop (too many levels of symbolic links)",
            path=str(target),
        )

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise AtomicWriteError(
            f"Failed to create directory {target.parent}: {exc}", path=str(target)
        ) from exc

    # Before this call's own temp exists, so it can never sweep it.
    fs_primitives._sweep_stale_temps(
        target.parent,
        f".{target.name}.tmp-*",
        min_age_seconds=fs_primitives._STALE_TEMP_MIN_AGE_SECONDS,
    )

    tmp_path = target.parent / f".{target.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
    try:
        os.close(os.open(tmp_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, _FILE_MODE))
    except OSError as exc:
        raise AtomicWriteError(
            f"Failed to create temporary file {tmp_path}: {exc}", path=str(target)
        ) from exc
    try:
        yield tmp_path
        if backup:
            create_backup(target, backup_dir=backup_dir, retention=retention, now=now)
        try:
            tmp_path.replace(target)
        except OSError as exc:
            raise AtomicWriteError(
                f"Failed to replace {target} with {tmp_path}: {exc}", path=str(target)
            ) from exc
    except BaseException:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise


def write_bytes_atomic(
    target: Path,
    data: bytes,
    *,
    backup: bool = True,
    backup_dir: Path | None = None,
    retention: int = DEFAULT_RETENTION,
) -> None:
    """Atomically write ``data`` to ``target``, via :func:`atomic_write`.

    Args:
        target: The file to write.
        data: The full desired contents of ``target``.
        backup: Whether to back up the current ``target`` before
            replacing it.
        backup_dir: Directory to store the backup under, when ``backup``
            is true.
        retention: Number of backups to retain, when ``backup`` is true.

    Raises:
        AtomicWriteError: If writing the temp file, backing up, or
            replacing ``target`` fails.
    """
    with atomic_write(target, backup=backup, backup_dir=backup_dir, retention=retention) as tmp:
        try:
            tmp.write_bytes(data)
        except OSError as exc:
            raise AtomicWriteError(
                f"Failed to write temporary file {tmp}: {exc}", path=str(target)
            ) from exc


def restore_backup(
    backup: Path,
    target: Path,
    *,
    backup_dir: Path | None = None,
    validate: Callable[[bytes], object] | None = None,
) -> None:
    """Restore ``target`` from a backup file, atomically.

    When ``validate`` is given, it runs against the backup's bytes
    *before* anything is written -- neither a pre-restore backup of
    ``target`` nor the replace itself happens until it returns. A bad
    ``backup`` file (wrong format, fails schema validation) therefore
    never touches ``target``: the caller finds out the same way it would
    have found out on the very next unrelated read of the live database,
    just before that damage would have been done instead of after.

    Absent ``validate``, or once it passes, backs up the *current*
    ``target`` first (so the restore itself is reversible), then
    atomically replaces ``target`` with the backup's contents.

    Args:
        backup: Path to the backup file to restore from.
        target: The file to restore.
        backup_dir: Directory to store the pre-restore backup of
            ``target`` under.
        validate: Called with the backup's bytes before any write. Its
            return value is discarded; it signals a bad backup by
            raising. ``None`` skips validation, restoring unconditionally.

    Raises:
        AtomicWriteError: If ``backup`` cannot be read, or the restore
            write fails.
        Exception: Whatever ``validate`` raises, when the backup's
            content fails validation. Propagates before any write.
    """
    if not backup.is_file():
        raise AtomicWriteError(f"Backup file not found: {backup}", path=str(backup))
    try:
        data = backup.read_bytes()
    except OSError as exc:
        raise AtomicWriteError(f"Failed to read backup {backup}: {exc}", path=str(backup)) from exc
    if validate is not None:
        validate(data)
    write_bytes_atomic(target, data, backup=True, backup_dir=backup_dir)
