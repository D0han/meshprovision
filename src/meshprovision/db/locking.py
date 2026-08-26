"""Cross-process advisory write locking for a single target file.

Format-agnostic, like :mod:`meshprovision.db.atomic_writer`: this module
locks a *sidecar* file next to the target and never touches the target
itself. The sidecar is deliberate -- ``flock`` locks an inode, and
:func:`~meshprovision.db.atomic_writer.atomic_write` installs a brand-new
inode at the target path on every write, so a lock taken on the target
itself would be silently dropped by the very operation it is meant to
guard.

Only writers take this lock; commands that operate on raw files (``mesh
db backup`` today) take :func:`exclusive_lock` directly instead of going
through :meth:`~meshprovision.cli.common.CliContext.open_database` --
this module makes no assumption that all callers arrive by that one path.
Readers never need it at all: every write to the target replaces it with
a single ``os.replace()``, so a reader's ``open()`` always resolves to a
complete pre- or post-write file, never a torn one.

Advisory only, and POSIX only: on a platform without ``fcntl`` the lock
degrades to a documented no-op, logged once at WARNING rather than
raised, so an un-guarded write is never silently mistaken for a guarded
one by an operator who saw no message at all.

The default timeout can be overridden two ways -- an explicit ``timeout``
argument, and the ``MESHPROVISION_LOCK_TIMEOUT`` environment variable
(read at call time, so a test's ``monkeypatch.setenv`` always takes
effect). Neither alone suffices for every caller: the environment
variable is the only lever a CLI invocation (which threads no timeout
parameter through ``open_database``) can pull, and the explicit argument
is what a direct unit test wants without depending on ambient state.
"""

from __future__ import annotations

import contextlib
import errno
import logging
import math
import os
import time
from types import ModuleType
from typing import TYPE_CHECKING, Final

from meshprovision.errors import AtomicWriteError, DatabaseLockedError

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

fcntl: ModuleType | None
try:
    import fcntl
except ImportError:  # pragma: no cover - exercised via a monkeypatched sentinel
    fcntl = None

__all__ = [
    "DEFAULT_LOCK_TIMEOUT",
    "LOCK_SUFFIX",
    "LOCK_TIMEOUT_ENV",
    "exclusive_lock",
    "lock_path_for",
]

_logger = logging.getLogger(__name__)

LOCK_SUFFIX: Final[str] = ".lock"
"""Suffix appended to a target path to derive its sidecar lock file path."""

DEFAULT_LOCK_TIMEOUT: Final[float] = 5.0
"""Default number of seconds :func:`exclusive_lock` polls before giving up."""

LOCK_TIMEOUT_ENV: Final[str] = "MESHPROVISION_LOCK_TIMEOUT"
"""Environment variable overriding the lock-acquisition timeout."""

_POLL_INTERVAL: Final[float] = 0.1
_LOCK_FILE_MODE: Final[int] = 0o600

_CONTENTION_ERRNOS: Final[frozenset[int]] = frozenset({errno.EAGAIN, errno.EWOULDBLOCK})
"""Errnos a non-blocking ``flock`` uses to mean "another holder has it".

Anything else -- ``ENOLCK`` from a filesystem out of lock records, ``EIO``,
``EBADF`` -- is a real failure that polling cannot resolve, so it is raised
immediately instead of waited out. ``EAGAIN`` and ``EWOULDBLOCK`` are the
same value on Linux; both are named because POSIX does not require that.
"""

_warned_no_fcntl = False


def lock_path_for(target: Path) -> Path:
    """Derive a target file's sidecar lock path.

    Args:
        target: The file being protected.

    Returns:
        ``target`` with :data:`LOCK_SUFFIX` appended to its name, for
        example ``data/nodes_db.ods.lock`` for ``data/nodes_db.ods``.
    """
    return target.with_name(target.name + LOCK_SUFFIX)


def _resolve_timeout(timeout: float | None) -> float:
    """Resolve the effective timeout: explicit argument, then env var, then default.

    Args:
        timeout: An explicit timeout, or ``None`` to fall back to the
            environment variable / default.

    Returns:
        The timeout, in seconds. A malformed value -- an unparseable
        string, or a non-finite one such as ``inf`` or ``nan``, which
        would make the acquisition deadline unreachable -- falls back
        to :data:`DEFAULT_LOCK_TIMEOUT` rather than raising.
    """
    if timeout is not None:
        return timeout
    raw = os.environ.get(LOCK_TIMEOUT_ENV)
    if raw is None:
        return DEFAULT_LOCK_TIMEOUT
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_LOCK_TIMEOUT
    if not math.isfinite(value):
        return DEFAULT_LOCK_TIMEOUT
    return value


def _warn_no_fcntl_once() -> None:
    """Log the non-POSIX degradation warning at most once per process."""
    global _warned_no_fcntl
    if _warned_no_fcntl:
        return
    _warned_no_fcntl = True
    _logger.warning(
        "database write locking is unavailable on this platform; concurrent "
        "`mesh` runs are not protected"
    )


def _read_holder_pid(fd: int) -> int | None:
    """Best-effort read of the pid recorded in an already-open lock file.

    Args:
        fd: The lock file's open file descriptor.

    Returns:
        The recorded pid, or ``None`` if the file is empty, unreadable,
        or does not hold a plain integer -- a holder killed between
        acquiring the lock and recording its pid leaves this ``None``,
        and that is treated as an ordinary, expected case, not an error.
    """
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        raw = os.read(fd, 32)
    except OSError:
        return None
    try:
        return int(raw.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError):
        return None


def _record_holder_pid(fd: int) -> None:
    """Best-effort write of the current process's pid into an acquired lock file.

    Args:
        fd: The lock file's open file descriptor, already ``flock``-ed.
    """
    with contextlib.suppress(OSError):
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, str(os.getpid()).encode("ascii"))


@contextlib.contextmanager
def exclusive_lock(target: Path, *, timeout: float | None = None) -> Iterator[None]:
    """Hold an exclusive cross-process write lock on ``target``'s sidecar file.

    Acquires a ``flock`` on ``<target>.lock`` (creating it at mode
    ``0o600`` if needed -- never ``target`` itself, see the module
    docstring for why) and releases it on any exit from the ``with``
    block, including an exception. The sidecar is never unlinked: doing
    so would let a third process create a fresh file at the same path
    and lock a different inode while an earlier holder still believes it
    owns the original one.

    On a platform without ``fcntl`` this is a no-op that logs a WARNING
    once per process and otherwise proceeds as if the lock were held.

    Args:
        target: The database file to protect. The lock itself is taken
            on ``target``'s sidecar, derived via :func:`lock_path_for`.
        timeout: Seconds to poll before giving up. ``None`` (the
            default) resolves :data:`LOCK_TIMEOUT_ENV`, falling back to
            :data:`DEFAULT_LOCK_TIMEOUT`.

    Yields:
        Nothing.

    Raises:
        AtomicWriteError: If the sidecar lock file cannot be created or
            opened (a read-only filesystem, a missing parent directory,
            a permissions error), or if ``flock`` fails for any reason
            other than contention (``ENOLCK`` on a filesystem out of
            lock records, for example) -- a filesystem failure unrelated
            to contention, which polling cannot resolve.
        DatabaseLockedError: If another process holds the lock and does
            not release it within the resolved timeout.
    """
    if fcntl is None:
        _warn_no_fcntl_once()
        yield
        return

    lock_path = lock_path_for(target)
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, _LOCK_FILE_MODE)
    except OSError as exc:
        raise AtomicWriteError(
            f"Failed to create the database lock file {lock_path}: {exc}",
            path=str(target),
        ) from exc

    try:
        deadline = time.monotonic() + _resolve_timeout(timeout)
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in _CONTENTION_ERRNOS:
                    raise AtomicWriteError(
                        f"Failed to acquire the database lock file {lock_path}: {exc}",
                        path=str(target),
                    ) from exc
                if time.monotonic() >= deadline:
                    holder_pid = _read_holder_pid(fd)
                    raise DatabaseLockedError(
                        f"Another mesh command is using the node database: {target}",
                        path=str(target),
                        holder_pid=holder_pid,
                        hint=(
                            "A concurrent `mesh provision` or `mesh admin` run"
                            f"{f' (pid {holder_pid})' if holder_pid else ''} holds "
                            "the write lock; it may be waiting at a confirmation "
                            "prompt. Wait for it to finish, or check for a stale "
                            "process. Read-only commands (`mesh status`, `mesh db "
                            "verify`, `mesh db backup`) are never blocked."
                        ),
                    ) from None
                time.sleep(_POLL_INTERVAL)
        _record_holder_pid(fd)
        yield
    finally:
        os.close(fd)
