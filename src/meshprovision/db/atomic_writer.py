"""Byte-level atomic file writes with pre-write timestamped backups.

This module has no knowledge of the ODS format at all -- it operates on
raw ``bytes``. The write pattern is: write to a temp file in the *same*
directory as the target (so the final rename is on one filesystem and
therefore atomic), copy the previous version of the target into a
timestamped backup directory (itself via its own temp-then-rename, so a
partially-copied backup can never appear under a final name), then
``os.replace()`` the temp file into place. Order matters: the backup is
taken **before** the replace, so an interrupted or failed replace never
loses the pre-write state.

Backups default to ``data/backups/`` (already covered by ``.gitignore``)
with a retention limit, since key material lives in the ODS this module
is typically used to protect. Both the target file and each backup are
created with mode ``0o600``: the target's temp file is pre-created at
that mode before it is handed to the caller, and ``os.replace`` carries
it onto the target unchanged; each backup's temp copy is chmodded to the
same mode before its own rename. There is no window in which a
fully-written database or a complete backup of one sits at the process
umask, and a brand-new database gets the same treatment as a rewrite.
"""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from meshprovision.errors import AtomicWriteError

__all__ = [
    "BACKUP_TIMESTAMP_FORMAT",
    "DEFAULT_BACKUP_DIR",
    "DEFAULT_RETENTION",
    "BackupInfo",
    "atomic_write",
    "backup_dir_for",
    "backup_name",
    "create_backup",
    "list_backups",
    "prune_backups",
    "restore_backup",
    "write_bytes_atomic",
]

_logger = logging.getLogger(__name__)

DEFAULT_BACKUP_DIR: Final[Path] = Path("data/backups")
"""Default backup directory, relative to the current working directory."""

DEFAULT_RETENTION: Final[int] = 20
"""Default number of backups to keep per target file."""

BACKUP_TIMESTAMP_FORMAT: Final[str] = "%Y%m%dT%H%M%SZ"
"""``strftime``/``strptime`` format embedded in a backup file's name."""

_BACKUP_DIR_MODE: Final[int] = 0o700

_FILE_MODE: Final[int] = 0o600


@dataclass(frozen=True, slots=True)
class BackupInfo:
    """Metadata about one backup copy of a target file.

    Attributes:
        path: Path to the backup file.
        source: Path to the target file this is a backup of.
        created_at: Tz-aware UTC timestamp the backup was taken at.
        size_bytes: Size of the backup file, in bytes.
    """

    path: Path
    source: Path
    created_at: datetime
    size_bytes: int


def _normalize_utc(when: datetime | None) -> datetime:
    """Resolve a possibly-``None``, possibly-naive datetime to tz-aware UTC.

    Args:
        when: A datetime to normalize, or ``None`` for the current time.

    Returns:
        ``when`` converted to UTC (a naive value is treated as already
        being UTC), or ``datetime.now(tz=UTC)`` when ``when`` is ``None``.
    """
    resolved = when if when is not None else datetime.now(tz=UTC)
    return resolved.replace(tzinfo=UTC) if resolved.tzinfo is None else resolved.astimezone(UTC)


def backup_dir_for(target: Path, backup_dir: Path | None = None) -> Path:  # noqa: ARG001
    """Resolve the backup directory to use for a target file.

    Args:
        target: The file backups are being resolved for. Accepted for API
            symmetry with :func:`backup_name` and :func:`create_backup`
            and to leave room for a future per-target default; the
            current default is always :data:`DEFAULT_BACKUP_DIR`,
            independent of ``target``'s own location.
        backup_dir: An explicit backup directory to use instead of the
            default.

    Returns:
        ``backup_dir`` if given, otherwise :data:`DEFAULT_BACKUP_DIR`.
    """
    return backup_dir if backup_dir is not None else DEFAULT_BACKUP_DIR


def backup_name(target: Path, when: datetime) -> str:
    """Build the backup file name for one target file and timestamp.

    Args:
        target: The file being backed up.
        when: The (ideally UTC) timestamp to embed in the name.

    Returns:
        For example ``"nodes_db-20260825T031410Z.ods"``.
    """
    return f"{target.stem}-{when.strftime(BACKUP_TIMESTAMP_FORMAT)}{target.suffix}"


def _unique_backup_path(directory: Path, name: str) -> Path:
    """Find a free path for a backup file, resolving same-second collisions.

    Args:
        directory: The backup directory.
        name: The proposed backup file name, from :func:`backup_name`.

    Returns:
        ``directory / name`` if free; otherwise ``directory / "<stem>-<n><suffix>"``
        for the smallest positive ``n`` that is free.
    """
    candidate = directory / name
    if not candidate.exists():
        return candidate
    stem, suffix = candidate.stem, candidate.suffix
    counter = 1
    while True:
        candidate = directory / f"{stem}-{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def create_backup(
    target: Path,
    *,
    backup_dir: Path | None = None,
    retention: int = DEFAULT_RETENTION,
    now: datetime | None = None,
) -> BackupInfo | None:
    """Copy the current contents of ``target`` into the backup directory.

    A no-op that returns ``None`` when ``target`` does not yet exist --
    there is nothing to back up on a first write. Prunes older backups
    down to ``retention`` after the copy succeeds.

    Args:
        target: The file to back up.
        backup_dir: Directory to store the backup under. Defaults to
            :func:`backup_dir_for`'s resolution.
        retention: Number of backups to retain for ``target`` after this
            one is created. ``<= 0`` keeps everything.
        now: Timestamp to embed in the backup's name. Defaults to the
            current time.

    Returns:
        Metadata about the created backup, or ``None`` if ``target`` does
        not exist.

    Raises:
        AtomicWriteError: If the backup directory cannot be created, or
            the copy fails.
    """
    if not target.exists():
        return None

    resolved_dir = backup_dir_for(target, backup_dir)
    try:
        resolved_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise AtomicWriteError(
            f"Failed to create backup directory {resolved_dir}: {exc}", path=str(target)
        ) from exc

    try:
        resolved_dir.chmod(_BACKUP_DIR_MODE)
    except OSError as exc:
        _logger.debug("Failed to chmod backup directory %s: %s", resolved_dir, exc)

    when = _normalize_utc(now)
    destination = _unique_backup_path(resolved_dir, backup_name(target, when))
    tmp_destination = destination.with_name(
        f".{destination.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
    )
    try:
        shutil.copy2(target, tmp_destination)
        # Mode is set on the temp file, before it becomes visible under the
        # final name: a complete copy of the key material must never exist
        # at the process umask, even briefly.
        try:
            tmp_destination.chmod(_FILE_MODE)
        except OSError as chmod_exc:
            _logger.debug("Failed to chmod backup %s: %s", tmp_destination, chmod_exc)
        tmp_destination.replace(destination)
    except OSError as exc:
        with contextlib.suppress(OSError):
            tmp_destination.unlink()
        raise AtomicWriteError(
            f"Failed to back up {target} to {destination}: {exc}", path=str(target)
        ) from exc

    # Captured before pruning: two backups can share the same embedded
    # (second-resolution) timestamp, so the one just created is not
    # guaranteed to survive a subsequent prune -- see _backup_sort_key.
    size_bytes = destination.stat().st_size
    prune_backups(target, backup_dir=resolved_dir, retention=retention)

    return BackupInfo(
        path=destination,
        source=target,
        created_at=when,
        size_bytes=size_bytes,
    )


def _parse_backup_timestamp(name: str, target: Path) -> datetime | None:
    """Extract the embedded timestamp from a backup file name, if possible.

    Tolerates a trailing collision suffix (``-N``) from
    :func:`_unique_backup_path`, which is not itself part of the
    timestamp.

    Args:
        name: The backup file's bare name (no directory component).
        target: The target file the backup belongs to, used to strip the
            shared stem/suffix.

    Returns:
        The parsed tz-aware UTC timestamp, or ``None`` if ``name`` does
        not match the expected ``"<stem>-<timestamp>[-N]<suffix>"`` shape.
    """
    prefix = f"{target.stem}-"
    if not name.startswith(prefix):
        return None
    remainder = name[len(prefix) :]
    if target.suffix and remainder.endswith(target.suffix):
        remainder = remainder[: -len(target.suffix)]
    token = remainder.split("-", 1)[0]
    try:
        return datetime.strptime(token, BACKUP_TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None


def _backup_sort_key(path: Path, target: Path) -> tuple[datetime, float]:
    """Build a newest-first sort key for one backup file.

    The embedded timestamp only has second resolution, so two backups
    created within the same second can share one; ``shutil.copy2``
    (used by :func:`create_backup`) preserves ``target``'s mtime onto
    each backup, and since ``target``'s mtime advances between writes,
    that mtime is normally a finer-grained tiebreaker for creation
    order. A backup collision suffix from :func:`_unique_backup_path`
    is deliberately *not* used for ordering: once an older backup
    sharing that base name is pruned, a later backup can be assigned
    the same freed-up suffix, which would make counter-based ordering
    wrong.

    This is a best-effort tiebreak, not a hard guarantee: on a
    filesystem/clock whose mtime resolution is coarser than the actual
    gap between two writes (possible when many backups are forced in
    rapid succession, well outside how this module is meant to be
    used -- interactively, or once per provisioning run), ties can
    still occur and are broken arbitrarily. Retention still correctly
    keeps ``retention`` backups either way; only the exact ordering
    among true sub-tick ties is not guaranteed.

    Args:
        path: The backup file.
        target: The target file the backup belongs to.

    Returns:
        A ``(timestamp, mtime)`` tuple, sortable ascending (larger means
        newer).
    """
    timestamp = _parse_backup_timestamp(path.name, target)
    mtime = path.stat().st_mtime
    if timestamp is None:
        timestamp = datetime.fromtimestamp(mtime, tz=UTC)
    return (timestamp, mtime)


def list_backups(target: Path, *, backup_dir: Path | None = None) -> tuple[BackupInfo, ...]:
    """List every backup of ``target``, newest first.

    Args:
        target: The file whose backups should be listed.
        backup_dir: Directory backups are stored under. Defaults to
            :func:`backup_dir_for`'s resolution.

    Returns:
        A tuple of :class:`BackupInfo`, newest first (see
        :func:`_backup_sort_key` for how same-second ties are broken).
        Empty when the backup directory does not exist.
    """
    resolved_dir = backup_dir_for(target, backup_dir)
    if not resolved_dir.is_dir():
        return ()

    keyed = [
        (path, _backup_sort_key(path, target))
        for path in resolved_dir.glob(f"{target.stem}-*{target.suffix}")
        if path.is_file()
    ]
    keyed.sort(key=lambda item: item[1], reverse=True)
    return tuple(
        BackupInfo(path=path, source=target, created_at=sort_key[0], size_bytes=path.stat().st_size)
        for path, sort_key in keyed
    )


def prune_backups(
    target: Path, *, backup_dir: Path | None = None, retention: int = DEFAULT_RETENTION
) -> tuple[Path, ...]:
    """Delete the oldest backups of ``target`` beyond ``retention``.

    Args:
        target: The file whose backups should be pruned.
        backup_dir: Directory backups are stored under. Defaults to
            :func:`backup_dir_for`'s resolution.
        retention: Number of newest backups to keep. ``<= 0`` keeps
            everything (no pruning).

    Returns:
        Paths of the backups that were deleted, in no particular order.

    Raises:
        AtomicWriteError: If deleting a backup fails.
    """
    if retention <= 0:
        return ()

    backups = list_backups(target, backup_dir=backup_dir)
    removed: list[Path] = []
    for info in backups[retention:]:
        try:
            info.path.unlink()
        except OSError as exc:
            raise AtomicWriteError(
                f"Failed to prune backup {info.path}: {exc}", path=str(info.path)
            ) from exc
        removed.append(info.path)
    return tuple(removed)


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
            is true. Defaults to :func:`backup_dir_for`'s resolution.
        retention: Number of backups to retain, when ``backup`` is true.
        now: Timestamp to embed in the backup's name, when ``backup`` is
            true. Defaults to the current time.

    Yields:
        A temporary file path in ``target``'s directory, already created
        with mode ``0o600``. The caller must write the full desired
        contents of ``target`` to this path; both ``open("wb")`` and
        ``write_bytes`` truncate without changing the mode.

    Raises:
        AtomicWriteError: If creating the temporary file, creating the
            backup, or replacing ``target`` fails.
    """
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise AtomicWriteError(
            f"Failed to create directory {target.parent}: {exc}", path=str(target)
        ) from exc

    tmp_path = target.parent / f".{target.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
    try:
        os.close(os.open(tmp_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, _FILE_MODE))
    except OSError as exc:
        raise AtomicWriteError(
            f"Failed to create temporary file {tmp_path}: {exc}", path=str(target)
        ) from exc
    try:
        yield tmp_path
    except BaseException:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise
    else:
        if backup:
            create_backup(target, backup_dir=backup_dir, retention=retention, now=now)
        try:
            tmp_path.replace(target)
        except OSError as exc:
            with contextlib.suppress(OSError):
                tmp_path.unlink()
            raise AtomicWriteError(
                f"Failed to replace {target} with {tmp_path}: {exc}", path=str(target)
            ) from exc


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


def restore_backup(backup: Path, target: Path, *, backup_dir: Path | None = None) -> None:
    """Restore ``target`` from a backup file, atomically.

    Backs up the *current* ``target`` first (so the restore itself is
    reversible), then atomically replaces ``target`` with the backup's
    contents.

    Args:
        backup: Path to the backup file to restore from.
        target: The file to restore.
        backup_dir: Directory to store the pre-restore backup of
            ``target`` under.

    Raises:
        AtomicWriteError: If ``backup`` cannot be read, or the restore
            write fails.
    """
    if not backup.is_file():
        raise AtomicWriteError(f"Backup file not found: {backup}", path=str(backup))
    try:
        data = backup.read_bytes()
    except OSError as exc:
        raise AtomicWriteError(f"Failed to read backup {backup}: {exc}", path=str(backup)) from exc
    write_bytes_atomic(target, data, backup=True, backup_dir=backup_dir)
