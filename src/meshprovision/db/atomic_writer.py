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

Backups default to a ``backups/`` directory next to the target file
(see ``backup_dir_for``) with a retention limit, since key material
lives in the ODS this module is typically used to protect. For the
project's own default database path, ``data/nodes_db.ods``, that is
``data/backups/`` -- already covered by ``.gitignore`` -- but a
non-default ``--db-path``/``MESHPROVISION_DB_PATH`` puts backups beside
*that* file instead, which is not necessarily covered by any
``.gitignore``. Both the target file and each backup are
created with mode ``0o600``: the target's temp file is pre-created at
that mode before it is handed to the caller, and ``os.replace`` carries
it onto the target unchanged; each backup's temp copy is chmodded to the
same mode before its own rename. There is no window in which a
fully-written database or a complete backup of one sits at the process
umask, and a brand-new database gets the same treatment as a rewrite.

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
import re
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
    "DEFAULT_RETENTION",
    "BackupInfo",
    "atomic_write",
    "backup_dir_for",
    "backup_name",
    "create_backup",
    "legacy_backup_notice",
    "link_no_clobber",
    "list_backups",
    "prune_backups",
    "restore_backup",
    "write_bytes_atomic",
]

_logger = logging.getLogger(__name__)

_BACKUP_DIR_NAME: Final[str] = "backups"
"""Name of the backup directory created next to each target file."""

_LEGACY_BACKUP_DIR: Final[Path] = Path("data/backups")
"""Old CWD-relative default backup directory, from before backup
directories followed the target file's own location.

Kept only so :func:`legacy_backup_notice` can point an operator at
files that may still be sitting there for a non-default
``--db-path``/``MESHPROVISION_DB_PATH``. Never consulted for a restore,
and never migrated automatically -- a leftover file there cannot be
safely attributed to any one database by this module alone.
"""

DEFAULT_RETENTION: Final[int] = 20
"""Default number of backups to keep per target file."""

BACKUP_TIMESTAMP_FORMAT: Final[str] = "%Y%m%dT%H%M%S.%fZ"
"""``strftime``/``strptime`` format embedded in a backup file's name."""

_LEGACY_BACKUP_TIMESTAMP_FORMAT: Final[str] = "%Y%m%dT%H%M%SZ"
"""Second-resolution format used before backup names carried microseconds.

Still parsed by :func:`_parse_backup_timestamp` so backups already on
disk keep listing with their real creation time rather than falling
back to mtime; never written.
"""

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


def backup_dir_for(target: Path, backup_dir: Path | None = None) -> Path:
    """Resolve the backup directory to use for a target file.

    Args:
        target: The file backups are being resolved for.
        backup_dir: An explicit backup directory to use instead of the
            default.

    Returns:
        ``backup_dir`` if given, otherwise a ``backups/`` directory next
        to ``target``'s real location: ``target.resolve().parent /
        "backups"``. This is CWD-independent, and it means two different
        databases that merely happen to share a file name -- for example
        two fleets each named ``nodes_db.ods`` -- never share a backup
        directory or known-good slot. Resolving ``target`` (non-strict,
        so it need not exist yet) also means a symlinked database's
        backups live beside the real file, not the link. For the
        project's own default, ``data/nodes_db.ods``, this resolves to
        ``<cwd>/data/backups`` -- the same directory used before this
        function considered ``target`` at all -- so default layouts see
        no change beyond messages now showing an absolute path.
    """
    if backup_dir is not None:
        return backup_dir
    return target.resolve().parent / _BACKUP_DIR_NAME


def backup_name(target: Path, when: datetime) -> str:
    """Build the backup file name for one target file and timestamp.

    Args:
        target: The file being backed up.
        when: The (ideally UTC) timestamp to embed in the name.

    Returns:
        For example ``"nodes_db-20260825T031410Z.ods"``.
    """
    return f"{target.stem}-{when.strftime(BACKUP_TIMESTAMP_FORMAT)}{target.suffix}"


_BACKUP_NAME_TIMESTAMP: Final[str] = r"\d{8}T\d{6}(?:\.\d{6})?Z"


def _backup_name_re(target: Path) -> re.Pattern[str]:
    """Build the strict backup-file-name pattern for one target file.

    Always matched with :meth:`re.Pattern.fullmatch`, never as a
    prefix/glob match, so a sibling database whose name merely starts
    with the same stem (``fleet-west.ods`` for target ``fleet.ods``) is
    never mistaken for one of ``target``'s own backups -- the glob used
    to prefilter candidate files is deliberately loose, this regex is
    what actually decides membership.

    Accepts the current microsecond-resolution timestamp format, the
    legacy second-resolution format still on disk from before it, and
    :func:`_claim_backup_path`'s ``-N`` collision suffix.

    Args:
        target: The file whose backup names should match.

    Returns:
        A compiled pattern over ``"<stem>-<timestamp>[-N]<suffix>"``,
        with the timestamp token captured in group 1.
    """
    return re.compile(
        rf"{re.escape(target.stem)}-({_BACKUP_NAME_TIMESTAMP})(?:-\d+)?{re.escape(target.suffix)}"
    )


def legacy_backup_notice(target: Path, *, backup_dir: Path | None = None) -> str | None:
    """Build a one-line notice about a legacy CWD-relative backup directory, if relevant.

    Before :func:`backup_dir_for` resolved backups next to the target
    file, every database defaulted to a single ``data/backups``,
    relative to the current working directory. A non-default
    ``--db-path``/``MESHPROVISION_DB_PATH`` run before this version may
    have left backups there -- possibly mixed with a different,
    same-named database's own backups, which is exactly the ambiguity
    the per-target directory now avoids. This performs no migration and
    is never consulted for a restore or offered for ``--known-good``; it
    only surfaces a pointer so ``mesh db backup --list`` can tell an
    operator to go look, and restore by explicit path after checking.

    Args:
        target: The database file to check for matching legacy backups.
        backup_dir: An explicit backup directory override that was
            passed to the caller's own operation. When given, there is
            no default-location ambiguity to report.

    Returns:
        A human-readable notice, or ``None`` when: ``backup_dir`` was
        explicitly given; the legacy directory does not exist; it is
        already ``target``'s own resolved backup directory (the default
        layout, where nothing changed); or it holds no file names that
        match ``target``.
    """
    if backup_dir is not None:
        return None
    if not _LEGACY_BACKUP_DIR.is_dir():
        return None

    resolved = backup_dir_for(target)
    try:
        if _LEGACY_BACKUP_DIR.resolve() == resolved.resolve():
            return None
    except OSError:
        pass

    pattern = _backup_name_re(target)
    count = sum(
        1
        for path in _LEGACY_BACKUP_DIR.glob(f"{target.stem}-*{target.suffix}")
        if path.is_file() and pattern.fullmatch(path.name)
    )
    if count == 0:
        return None

    plural = "" if count == 1 else "s"
    return (
        f"{count} older backup{plural} named like this database are under "
        f"{_LEGACY_BACKUP_DIR} (the location used before this version). They may "
        "belong to a different database that happens to share this file name -- "
        "restore one only by explicit path, after checking it. Never offered for "
        "--known-good."
    )


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


def _claim_backup_path(directory: Path, name: str, source: Path) -> Path:
    """Link a finished backup copy into the first free name, atomically.

    :func:`link_no_clobber` fails with :class:`FileExistsError` rather
    than clobbering, which is what makes this safe against a concurrent
    ``mesh db backup``: an ``exists()`` check followed by
    ``os.replace`` would let two processes agree on one name and
    silently lose one of the two copies. The claim is made only after
    ``source`` is a complete, correctly-moded copy, so a partial backup
    can never appear under a final name.

    A SIGKILL between :func:`link_no_clobber`'s internal claim and its
    consuming of ``source`` leaves ``source`` behind as an orphaned temp
    under both names; a later :func:`_sweep_stale_temps` run reclaims it
    once it ages past the staleness guard.

    Args:
        directory: The backup directory.
        name: The proposed backup file name, from :func:`backup_name`.
        source: The completed temp copy to link into place. Consumed on
            success, leaving exactly one name for the new inode.

    Returns:
        The path the backup now occupies -- ``directory / name`` if it
        was free, otherwise ``directory / "<stem>-<n><suffix>"`` for the
        smallest positive ``n`` that was free.

    Raises:
        OSError: If linking fails for any reason other than the
            candidate name already existing.
    """
    base = directory / name
    stem, suffix = base.stem, base.suffix
    candidate = base
    counter = 0
    while True:
        try:
            link_no_clobber(source, candidate)
        except FileExistsError:
            counter += 1
            candidate = directory / f"{stem}-{counter}{suffix}"
            continue
        return candidate


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
    down to ``retention`` after the copy succeeds; pruning is best-effort
    -- a failure there is logged at ``WARNING`` and never aborts an
    otherwise-successful backup, since the new backup is already safely
    in place by the time pruning runs.

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
            the copy fails. A failure to prune old backups afterwards is
            logged, not raised.
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

    # Before this call's own temp exists, so it can never sweep it.
    _sweep_stale_temps(
        resolved_dir,
        f".{target.stem}-*{target.suffix}.tmp-*",
        min_age_seconds=_STALE_TEMP_MIN_AGE_SECONDS,
    )

    when = _normalize_utc(now)
    name = backup_name(target, when)
    tmp_destination = resolved_dir / f".{name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
    try:
        shutil.copy2(target, tmp_destination)
        # Mode is set on the temp file, before it becomes visible under the
        # final name: a complete copy of the key material must never exist
        # at the process umask, even briefly.
        try:
            tmp_destination.chmod(_FILE_MODE)
        except OSError as chmod_exc:
            _logger.debug("Failed to chmod backup %s: %s", tmp_destination, chmod_exc)
        destination = _claim_backup_path(resolved_dir, name, tmp_destination)
    except OSError as exc:
        with contextlib.suppress(OSError):
            tmp_destination.unlink()
        raise AtomicWriteError(
            f"Failed to back up {target} into {resolved_dir} as {name}: {exc}", path=str(target)
        ) from exc

    # Captured before pruning: two backups can share the same embedded
    # timestamp when the caller passes an explicit `now=`, so the one just
    # created is not guaranteed to survive a subsequent prune -- see
    # _backup_sort_key.
    size_bytes = destination.stat().st_size
    try:
        prune_backups(target, backup_dir=resolved_dir, retention=retention)
    except AtomicWriteError as exc:
        _logger.warning("Backup created, but pruning old backups failed: %s", exc)

    return BackupInfo(
        path=destination,
        source=target,
        created_at=when,
        size_bytes=size_bytes,
    )


def _parse_backup_timestamp(name: str, target: Path) -> datetime | None:
    """Extract the embedded timestamp from a backup file name, if possible.

    Uses :func:`_backup_name_re` for both the shape check and the
    timestamp extraction, so the two can never drift apart -- a name
    this rejects is never counted as one of ``target``'s backups
    elsewhere, and a name it accepts always parses.

    Args:
        name: The backup file's bare name (no directory component).
        target: The target file the backup belongs to.

    Returns:
        The parsed tz-aware UTC timestamp, or ``None`` if ``name`` does
        not match the expected ``"<stem>-<timestamp>[-N]<suffix>"`` shape.
    """
    match = _backup_name_re(target).fullmatch(name)
    if match is None:
        return None
    token = match.group(1)
    fmt = BACKUP_TIMESTAMP_FORMAT if "." in token else _LEGACY_BACKUP_TIMESTAMP_FORMAT
    try:
        return datetime.strptime(token, fmt).replace(tzinfo=UTC)
    except ValueError:
        return None


def _backup_sort_key(path: Path, target: Path) -> tuple[datetime, float]:
    """Build a newest-first sort key for one backup file.

    The embedded timestamp now has microsecond resolution, so two
    backups share one only when the caller passes an explicit ``now=``
    or a backup carries the legacy second-resolution format;
    ``shutil.copy2`` (used by :func:`create_backup`) preserves
    ``target``'s mtime onto each backup, and since ``target``'s mtime
    advances between writes, that mtime is normally a finer-grained
    tiebreaker for creation order. A backup collision suffix from
    :func:`_claim_backup_path` is deliberately *not* used for ordering:
    once an older backup sharing that base name is pruned, a later
    backup can be assigned the same freed-up suffix, which would make
    counter-based ordering wrong.

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
        Empty when the backup directory does not exist. A backup deleted
        by a concurrent pruner between the directory scan and its own
        stat is silently omitted rather than raising. Only names that
        :func:`_backup_name_re` fully matches count -- a sibling
        database's backups (``fleet-west-<ts>.ods`` for target
        ``fleet.ods``) and a hand-named file (``nodes_db-old.ods``) are
        both excluded, even though a looser glob would catch them.
    """
    resolved_dir = backup_dir_for(target, backup_dir)
    if not resolved_dir.is_dir():
        return ()

    pattern = _backup_name_re(target)
    keyed: list[tuple[Path, tuple[datetime, float], int]] = []
    for path in resolved_dir.glob(f"{target.stem}-*{target.suffix}"):
        if not pattern.fullmatch(path.name):
            continue
        try:
            if not path.is_file():
                continue
            keyed.append((path, _backup_sort_key(path, target), path.stat().st_size))
        except FileNotFoundError:
            continue
    keyed.sort(key=lambda item: item[1], reverse=True)
    return tuple(
        BackupInfo(path=path, source=target, created_at=sort_key[0], size_bytes=size_bytes)
        for path, sort_key, size_bytes in keyed
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
        A backup already removed by a concurrent pruner is not included,
        since this call did not delete it.

    Raises:
        AtomicWriteError: If deleting a backup fails for any reason other
            than the file having already been removed -- losing that race
            to a concurrent writer is the expected outcome, not an error.
    """
    if retention <= 0:
        return ()

    backups = list_backups(target, backup_dir=backup_dir)
    removed: list[Path] = []
    for info in backups[retention:]:
        try:
            info.path.unlink()
        except FileNotFoundError:
            _logger.debug(
                "backup %s was already removed, presumably by a concurrent writer",
                info.path,
            )
            continue
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

    ``target`` is resolved (non-strict) before anything else, so a
    symlinked database path is written through to the real file rather
    than having the symlink itself replaced by a regular file -- a
    concurrent write through a different symlink to the same real file
    is then a genuine collision, not a silent split-brain. See
    :func:`lock_path_for`, which resolves for the same reason.

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
        AtomicWriteError: If ``target`` cannot be resolved (for example a
            symlink loop), or if creating the temporary file, creating
            the backup, or replacing ``target`` fails.
    """
    try:
        target = target.resolve()
    except (OSError, RuntimeError) as exc:
        raise AtomicWriteError(f"Failed to resolve {target}: {exc}", path=str(target)) from exc

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise AtomicWriteError(
            f"Failed to create directory {target.parent}: {exc}", path=str(target)
        ) from exc

    # Before this call's own temp exists, so it can never sweep it.
    _sweep_stale_temps(
        target.parent, f".{target.name}.tmp-*", min_age_seconds=_STALE_TEMP_MIN_AGE_SECONDS
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
