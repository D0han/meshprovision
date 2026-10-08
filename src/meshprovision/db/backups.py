"""Timestamped backup directory: creation, listing, pruning, and naming.

Backups default to a ``backups/`` directory next to the target file
(see ``backup_dir_for``) with a retention limit, since key material
lives in the ODS this module is typically used to protect. For the
project's own default database path, ``data/nodes_db.ods``, that is
``data/backups/`` -- already covered by ``.gitignore`` -- but a
non-default ``--db-path``/``MESHPROVISION_DB_PATH`` puts backups beside
*that* file instead, which is not necessarily covered by any
``.gitignore``. Each backup is created with mode ``0o600``: its temp
copy is chmodded to that mode before its own rename, so there is no
window in which a complete backup of a key-bearing database sits at the
process umask.

A backup's temp copy is swept opportunistically at its creation site
(see :mod:`meshprovision.db.fs_primitives`), since a SIGKILL between
creating one and renaming it leaves an orphan nothing else on disk ever
reclaims.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import shutil
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

from meshprovision.db import fs_primitives
from meshprovision.db.fs_primitives import BACKUP_DIR_MODE, FILE_MODE, link_no_clobber
from meshprovision.errors import AtomicWriteError

__all__ = [
    "BACKUP_TIMESTAMP_FORMAT",
    "DEFAULT_RETENTION",
    "BackupInfo",
    "backup_dir_for",
    "backup_name",
    "backup_name_targets",
    "create_backup",
    "legacy_backup_notice",
    "list_backups",
    "prune_backups",
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

_NAME_TIMESTAMP_STEP: Final[timedelta] = timedelta(microseconds=1)
"""How far past the newest existing backup a behind-the-clock name is placed."""

_warned_clock_behind = False
"""Whether the clock-behind warning has already been logged in this process."""


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

    Raises:
        AtomicWriteError: If ``backup_dir`` is not given and ``target``
            cannot be resolved (for example a symlink loop, see
            :func:`~meshprovision.db.fs_primitives.resolve_path`).
    """
    if backup_dir is not None:
        return backup_dir
    return fs_primitives.resolve_path(target).parent / _BACKUP_DIR_NAME


def backup_name_targets(target: Path) -> tuple[Path, ...]:
    """List the paths whose names a target file's backup-directory files are named after.

    Every file this package keeps in a backup directory for ``target`` --
    timestamped backups, the known-good copy and its sidecar, pending-key
    files -- is named after ``target``'s *real* file, the same file
    :func:`backup_dir_for` places the directory beside and
    :func:`~meshprovision.db.locking.lock_path_for` locks. So a symlinked
    database reached as ``fleet.ods`` and as the ``nodes_db.ods`` it
    points at finds the same files under either spelling.

    Files written before names followed the real file were named after
    the path as given, so a differently named spelling is returned too,
    for reads and clean-up only (never for new writes). It is left out
    when a different file of that name sits beside the real file: names
    of that spelling in the shared backup directory then belong to that
    other database.

    Args:
        target: The file, as given.

    Returns:
        ``(resolved,)``, or ``(resolved, target)`` when ``target``'s file
        name differs from the real file's and no other database owns that
        name beside it. The first entry is the one to write under.
        ``(target,)`` when ``target`` cannot be resolved (a symlink loop):
        the names as given, as before names followed the real file. Only
        an explicit backup directory gets that far -- without one,
        :func:`backup_dir_for` has already refused the path.
    """
    try:
        resolved = fs_primitives.resolve_path(target)
    except AtomicWriteError:
        return (target,)
    if target.name == resolved.name:
        return (resolved,)
    sibling = resolved.parent / target.name
    try:
        owned_elsewhere = (
            os.path.lexists(sibling) and fs_primitives.resolve_path(sibling) != resolved
        )
    except AtomicWriteError:
        owned_elsewhere = True
    return (resolved,) if owned_elsewhere else (resolved, target)


def backup_name(target: Path, when: datetime) -> str:
    """Build the backup file name for one target file and timestamp.

    Args:
        target: The file whose name the backup is named after (see
            :func:`backup_name_targets` for which one that is).
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

    # Best-effort: an unresolvable path just skips the "same directory" check.
    with contextlib.suppress(AtomicWriteError):
        resolved = backup_dir_for(target)
        if fs_primitives.resolve_path(_LEGACY_BACKUP_DIR) == fs_primitives.resolve_path(resolved):
            return None

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


def _claim_backup_path(directory: Path, name: str, source: Path) -> Path:
    """Link a finished backup copy into the first free name, atomically.

    :func:`~meshprovision.db.fs_primitives.link_no_clobber` fails with
    :class:`FileExistsError` rather than clobbering, which is what makes
    this safe against a concurrent ``mesh db backup``: an ``exists()``
    check followed by ``os.replace`` would let two processes agree on
    one name and silently lose one of the two copies. The claim is made
    only after ``source`` is a complete, correctly-moded copy, so a
    partial backup can never appear under a final name.

    A SIGKILL between :func:`~meshprovision.db.fs_primitives.link_no_clobber`'s
    internal claim and its consuming of ``source`` leaves ``source``
    behind as an orphaned temp under both names; a later sweep reclaims
    it once it ages past the staleness guard.

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


def _monotonic_backup_time(
    target: Path, directory: Path, when: datetime, *, from_clock: bool
) -> datetime:
    """Pick the timestamp for a new backup's name, never older than an existing one.

    Backups are ordered -- and pruned -- by the timestamp in their names.
    A system clock behind the newest existing name (a Raspberry Pi
    without a real-time clock after a power cut, a dead clock battery, a
    restored VM snapshot) would otherwise name each new backup as the
    *oldest*, and its own prune would delete it straight away once
    ``retention`` newer-named backups exist. Instead the new name goes
    one microsecond past the newest existing one, so name order stays
    creation order. Legacy second-resolution names count with their
    parsed timestamp, like everywhere else.

    Logs a ``WARNING`` the first time per process that the system clock
    (``from_clock``) is found behind; an explicit ``now=`` is bumped the
    same way, without the warning.

    Args:
        target: The file being backed up.
        directory: The resolved backup directory.
        when: The UTC timestamp the caller asked for.
        from_clock: Whether ``when`` came from the system clock.

    Returns:
        ``when``, unless it is not later than the newest existing
        backup's timestamp; then that timestamp plus one microsecond.
    """
    global _warned_clock_behind
    existing = list_backups(target, backup_dir=directory)
    if not existing or when > existing[0].created_at:
        return when
    newest = existing[0].created_at
    if from_clock and not _warned_clock_behind:
        _warned_clock_behind = True
        _logger.warning(
            "The system clock (%s) is behind the newest backup of %s (%s); new backup names "
            "continue after it to keep them in creation order.",
            when.isoformat(),
            target,
            newest.isoformat(),
        )
    return newest + _NAME_TIMESTAMP_STEP


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
    in place by the time pruning runs. Pruning never deletes the backup
    this call just created (see :func:`prune_backups`'s ``keep``), so the
    returned path always exists when this returns.

    The backup's name never sorts before an existing backup's, even when
    the system clock is behind (see :func:`_monotonic_backup_time`).

    Args:
        target: The file to back up.
        backup_dir: Directory to store the backup under. Defaults to
            :func:`backup_dir_for`'s resolution.
        retention: Number of backups to retain for ``target`` after this
            one is created. ``<= 0`` keeps everything.
        now: Timestamp to embed in the backup's name. Defaults to the
            current time. Moved forward past the newest existing backup's
            timestamp when it is not later than it.

    Returns:
        Metadata about the created backup -- its ``created_at`` is the
        timestamp actually embedded in its name -- or ``None`` if
        ``target`` does not exist.

    Raises:
        AtomicWriteError: If the backup directory cannot be created, or
            the copy (or flushing it to disk) fails. A failure to prune
            old backups afterwards is logged, not raised.
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
        resolved_dir.chmod(BACKUP_DIR_MODE)
    except OSError as exc:
        _logger.debug("Failed to chmod backup directory %s: %s", resolved_dir, exc)

    name_targets = backup_name_targets(target)
    # Before this call's own temp exists, so it can never sweep it.
    for name_target in name_targets:
        fs_primitives.sweep_stale_temps(
            resolved_dir,
            f".{name_target.stem}-*{name_target.suffix}.tmp-*",
            min_age_seconds=fs_primitives.STALE_TEMP_MIN_AGE_SECONDS,
        )

    when = _monotonic_backup_time(target, resolved_dir, _normalize_utc(now), from_clock=now is None)
    name = backup_name(name_targets[0], when)
    tmp_destination = resolved_dir / f".{name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
    try:
        shutil.copy2(target, tmp_destination)
        # Mode is set on the temp file, before it becomes visible under the
        # final name: a complete copy of the key material must never exist
        # at the process umask, even briefly.
        try:
            tmp_destination.chmod(FILE_MODE)
        except OSError as chmod_exc:
            _logger.debug("Failed to chmod backup %s: %s", tmp_destination, chmod_exc)
        # Flushed before it gets its final name, so that name never points
        # at a copy the disk does not hold yet.
        fs_primitives.fsync_file(tmp_destination)
        destination = _claim_backup_path(resolved_dir, name, tmp_destination)
    except OSError as exc:
        with contextlib.suppress(OSError):
            tmp_destination.unlink()
        raise AtomicWriteError(
            f"Failed to back up {target} into {resolved_dir} as {name}: {exc}", path=str(target)
        ) from exc

    fs_primitives.fsync_dir(resolved_dir)

    # Captured before pruning. keep= protects this backup from its own
    # prune, but not from a concurrent writer's prune (possible only when
    # that one's retention is 1).
    size_bytes = destination.stat().st_size
    try:
        prune_backups(target, backup_dir=resolved_dir, retention=retention, keep=destination)
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
        target: The file the backup is named after (see
            :func:`backup_name_targets`).

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

    The embedded timestamp has microsecond resolution and
    :func:`create_backup` never names a new backup at or before the
    newest existing one, so two backups share a timestamp only when two
    writers race for the same name (one then carries a ``-N`` suffix)
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
        target: The file the backup is named after (see
            :func:`backup_name_targets`).

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
        :func:`_backup_sort_key` for how same-second ties are broken),
        under every name :func:`backup_name_targets` returns -- the real
        file's, and an older spelling's still on disk -- so retention and
        ordering span both. Empty when the backup directory does not
        exist. A backup deleted
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

    keyed: list[tuple[Path, tuple[datetime, float], int]] = []
    seen: set[Path] = set()
    for name_target in backup_name_targets(target):
        pattern = _backup_name_re(name_target)
        for path in resolved_dir.glob(f"{name_target.stem}-*{name_target.suffix}"):
            if path in seen or not pattern.fullmatch(path.name):
                continue
            try:
                if not path.is_file():
                    continue
                keyed.append((path, _backup_sort_key(path, name_target), path.stat().st_size))
            except FileNotFoundError:
                continue
            seen.add(path)
    keyed.sort(key=lambda item: item[1], reverse=True)
    return tuple(
        BackupInfo(path=path, source=target, created_at=sort_key[0], size_bytes=size_bytes)
        for path, sort_key, size_bytes in keyed
    )


def prune_backups(
    target: Path,
    *,
    backup_dir: Path | None = None,
    retention: int = DEFAULT_RETENTION,
    keep: Path | None = None,
) -> tuple[Path, ...]:
    """Delete the oldest backups of ``target`` beyond ``retention``.

    Args:
        target: The file whose backups should be pruned.
        backup_dir: Directory backups are stored under. Defaults to
            :func:`backup_dir_for`'s resolution.
        retention: Number of newest backups to keep. ``<= 0`` keeps
            everything (no pruning).
        keep: A backup that must survive, whatever its position -- the
            one :func:`create_backup` just made. It counts towards
            ``retention``: ``keep`` plus the ``retention - 1`` newest
            others survive. Ignored when it is not among the listed
            backups.

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
    survivors = retention
    if keep is not None and any(info.path == keep for info in backups):
        backups = tuple(info for info in backups if info.path != keep)
        survivors -= 1
    removed: list[Path] = []
    for info in backups[survivors:]:
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
