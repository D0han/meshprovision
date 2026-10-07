"""Upward ``.env`` discovery and the trust checks a discovered file must pass.

:func:`find_env_file` locates the nearest ``.env`` above the working
directory (bounded at ``$HOME``), skipping one that another user could
have planted, and :func:`read_discovered_env_file` returns its text only
after checking -- on the one open descriptor that is then read -- that the
file is a regular file owned by the current user and writable by no one
else, by mode bits or by POSIX ACL. Both are used by
:func:`meshprovision.config.settings.load_settings`; an explicitly passed
``--env-file`` never goes through here.

This module imports only the standard library and :mod:`meshprovision.errors`.
"""

from __future__ import annotations

import errno
import logging
import os
import shlex
import stat
import struct
from pathlib import Path
from typing import Final, NamedTuple

from meshprovision.errors import SettingsError

__all__ = [
    "find_env_file",
    "read_discovered_env_file",
]

_logger = logging.getLogger(__name__)


def find_env_file(start: Path | None = None) -> Path | None:
    """Locate the nearest ``.env`` file, searching upward from ``start``.

    Walks ``start`` and each of its parent directories, returning the
    first ``.env`` found. Deliberately does not use ``dotenv.find_dotenv``,
    which inspects the caller's stack frame and behaves unpredictably
    when called from within pytest.

    When ``start`` is under the user's home directory, the walk stops at
    ``$HOME`` itself rather than continuing to filesystem root -- a
    project nested a few directories deep inside the home directory has
    no business picking up a ``.env`` planted by another user higher up
    the tree. ``$HOME`` is compared both as given and resolved, since
    ``start`` (the working directory) is always a resolved path.

    A ``.env`` owned by another user, in a directory that is not private
    to the current user (see :func:`_directory_is_private`), is skipped
    and the walk goes on: whoever can create files there -- every local
    user, in ``/tmp`` -- could have planted it, and refusing it would let
    them break every command run below that directory. It is logged at
    INFO. One owned by another user in a private directory is still
    returned, and :func:`read_discovered_env_file` refuses it.

    Args:
        start: Directory to begin searching from. Defaults to
            ``Path.cwd()``.

    Returns:
        The path to the nearest ``.env`` file, or ``None`` if none is
        found.
    """
    base = start if start is not None else Path.cwd()
    homes = _home_directories()
    for directory in (base, *base.parents):
        candidate = directory / ".env"
        if candidate.is_file():
            owner = _planted_by(candidate)
            if owner is None:
                return candidate
            _logger.info(
                "Ignoring %s: it is owned by %s and its directory is not private to you.",
                candidate,
                _user_label(owner),
            )
        if directory in homes:
            break
    return None


def _home_directories() -> frozenset[Path]:
    """Return ``$HOME`` as given and resolved, either of which bounds :func:`find_env_file`.

    Returns:
        ``Path.home()`` and, when it can be resolved, its resolved form.
    """
    home = Path.home()
    try:
        return frozenset({home, home.resolve()})
    except (OSError, RuntimeError):  # a symlink loop: RuntimeError before Python 3.13
        return frozenset({home})


def _planted_by(candidate: Path) -> int | None:
    """Return the owner of a discovered ``.env`` that another user could have planted.

    Args:
        candidate: An existing ``.env`` file (a symlink is judged by its
            target, like :func:`read_discovered_env_file` does).

    Returns:
        The uid owning ``candidate`` when that is not the current user and
        ``candidate``'s directory is not private to the current user;
        otherwise None -- including where ``os.getuid`` doesn't exist
        (Windows) and when ``candidate`` can't be stat-ed (the read then
        reports why).
    """
    if not hasattr(os, "getuid"):
        return None
    try:
        owner = candidate.stat().st_uid
    except OSError:
        return None
    if owner == os.getuid() or _directory_is_private(candidate.parent):
        return None
    return owner


def _directory_is_private(directory: Path) -> bool:
    """Return whether only the current user (or root) can create files in ``directory``.

    The directory must be owned by the current user and pass the same
    mode-bit checks as a discovered ``.env`` (see
    :func:`_env_trust_problems`): not world-writable, and group-writable
    only through the user's own private primary group. Its ACL is not
    read.

    Args:
        directory: The directory to check.

    Returns:
        True if it is private; False otherwise, including when it can't
        be stat-ed.
    """
    try:
        st = directory.stat()
    except OSError:
        return False
    return st.st_uid == os.getuid() and not _env_trust_problems(directory, st, None)


_POSIX_ACL_XATTR: Final[str] = "system.posix_acl_access"
"""The Linux extended attribute holding a file's POSIX access ACL, if it has one."""

_ACL_VERSION: Final[int] = 2
_ACL_HEADER: Final[struct.Struct] = struct.Struct("<I")
_ACL_ENTRY: Final[struct.Struct] = struct.Struct("<HHI")
"""The xattr is a little-endian ``u32`` version followed by ``(tag, perm, id)`` entries."""

_ACL_USER_OBJ: Final[int] = 0x01
_ACL_USER: Final[int] = 0x02
_ACL_GROUP_OBJ: Final[int] = 0x04
_ACL_GROUP: Final[int] = 0x08
_ACL_MASK: Final[int] = 0x10
_ACL_OTHER: Final[int] = 0x20
_ACL_TAGS: Final[frozenset[int]] = frozenset(
    {_ACL_USER_OBJ, _ACL_USER, _ACL_GROUP_OBJ, _ACL_GROUP, _ACL_MASK, _ACL_OTHER}
)
_ACL_WRITE: Final[int] = 0o2
_ACL_ALL_PERMS: Final[int] = 0o7


class _AclEntry(NamedTuple):
    """One entry of a POSIX access ACL, as stored in :data:`_POSIX_ACL_XATTR`."""

    tag: int
    """Which principal the entry is for (``_ACL_USER_OBJ`` ... ``_ACL_OTHER``)."""
    perm: int
    """The entry's ``rwx`` bits (read 4, write 2, execute 1)."""
    qualifier: int
    """The uid of a named USER entry or the gid of a named GROUP entry; unused otherwise."""


class _EnvTrustProblem(NamedTuple):
    """One reason a discovered ``.env`` file is refused, and the command that fixes it."""

    reason: str
    """Why the file is refused, phrased to follow "Refusing to load ...: "."""
    fix: str
    """A shell command that removes this reason, with the path already shell-quoted."""


def _env_trust_problems(
    path: Path, st: os.stat_result, acl: tuple[_AclEntry, ...] | None
) -> list[_EnvTrustProblem]:
    """List every way the ``st`` and ``acl`` of a discovered ``.env`` let others write it.

    Ownership is checked separately (see :func:`read_discovered_env_file`).

    A group-writable file is accepted when its group is the current
    user's primary group and no one else is in that group (see
    :func:`_primary_group_is_private`): most distros give each user a
    private group (umask 002), so ``rw-rw-r--`` is the everyday default
    and refusing it would block normal users, but a shared primary group
    (e.g. ``users``) would let every member rewrite the file.

    With a POSIX ACL the mode's group bits are the ACL *mask*, not the
    owning group's permissions, so the owning group's write access is
    taken from the ACL instead, and any named user or group entry that
    can write (through the mask) is refused outright. A named entry for
    the file's owner is ignored: the kernel matches the owner entry
    first, so it never applies. Read-only ACL entries are harmless.

    Args:
        path: The discovered ``.env`` path, used only to build the fix
            commands (``chmod`` follows a symlink to its target, which is
            what ``st`` describes).
        st: ``os.fstat`` of the open file descriptor that will be parsed.
        acl: That descriptor's access ACL (see :func:`_read_access_acl`),
            or None if it has none.

    Returns:
        One :class:`_EnvTrustProblem` per failed check, in a stable order
        (world-write, group-write, ACL write); empty if no one else can
        write the file.
    """
    quoted = shlex.quote(str(path))
    problems: list[_EnvTrustProblem] = []
    if st.st_mode & stat.S_IWOTH:
        problems.append(_EnvTrustProblem("it is world-writable", f"chmod o-w {quoted}"))
    group_obj_writable, named_writable = (
        (bool(st.st_mode & stat.S_IWGRP), False)
        if acl is None
        else _acl_write_access(acl, st.st_uid)
    )
    if group_obj_writable:
        if st.st_gid != os.getgid():
            problems.append(
                _EnvTrustProblem(
                    "it is group-writable by a group other than your primary group",
                    f"chmod g-w {quoted}",
                )
            )
        elif not _primary_group_is_private(st.st_gid, os.getuid()):
            problems.append(
                _EnvTrustProblem(
                    f"it is group-writable and its group {_group_label(st.st_gid)} "
                    "is shared with other users",
                    f"chmod g-w {quoted}",
                )
            )
    if named_writable:
        problems.append(
            _EnvTrustProblem(
                "an ACL grants write access to another user or group", f"chmod g-w {quoted}"
            )
        )
    return problems


def _acl_write_access(acl: tuple[_AclEntry, ...], owner_uid: int) -> tuple[bool, bool]:
    """Return who besides the owner can write a file, according to its access ACL.

    Every group-class entry's permissions are limited by the ACL's mask
    (``chmod g-w`` clears the mask's write bit, making all of them
    read-only). An ACL without named entries needs no mask.

    Args:
        acl: The file's access ACL, as returned by :func:`_parse_posix_acl`.
        owner_uid: The file's owner; a named USER entry for it never applies.

    Returns:
        ``(owning_group_can_write, a_named_user_or_group_can_write)``.
    """
    mask = next((entry.perm for entry in acl if entry.tag == _ACL_MASK), _ACL_ALL_PERMS)

    def can_write(entry: _AclEntry) -> bool:
        return bool(entry.perm & mask & _ACL_WRITE)

    group_obj = any(can_write(entry) for entry in acl if entry.tag == _ACL_GROUP_OBJ)
    named = any(
        can_write(entry)
        for entry in acl
        if entry.tag == _ACL_GROUP or (entry.tag == _ACL_USER and entry.qualifier != owner_uid)
    )
    return group_obj, named


def _parse_posix_acl(blob: bytes) -> tuple[_AclEntry, ...]:
    """Decode the value of a :data:`_POSIX_ACL_XATTR` extended attribute.

    Args:
        blob: The raw attribute value.

    Returns:
        The ACL's entries, in stored order.

    Raises:
        ValueError: If ``blob`` is not a version-2 POSIX ACL made of whole
            entries with known tags, exactly one owner, owning-group and
            other entry, and exactly one mask when there are named entries
            (at most one otherwise).
    """
    header, body = blob[: _ACL_HEADER.size], blob[_ACL_HEADER.size :]
    if len(header) != _ACL_HEADER.size or len(body) % _ACL_ENTRY.size:
        raise ValueError(f"{len(blob)} bytes is not a whole number of ACL entries")
    (version,) = _ACL_HEADER.unpack(header)
    if version != _ACL_VERSION:
        raise ValueError(f"unsupported ACL version {version}")
    entries = tuple(_AclEntry(*fields) for fields in _ACL_ENTRY.iter_unpack(body))
    tags = [entry.tag for entry in entries]
    unknown = set(tags) - _ACL_TAGS
    if unknown:
        raise ValueError(f"unknown ACL entry tag {min(unknown):#x}")
    if any(tags.count(tag) != 1 for tag in (_ACL_USER_OBJ, _ACL_GROUP_OBJ, _ACL_OTHER)):
        raise ValueError("the owner, owning-group and other entries must each appear once")
    masks = tags.count(_ACL_MASK)
    if masks > 1 or (masks == 0 and (_ACL_USER in tags or _ACL_GROUP in tags)):
        raise ValueError("an ACL with named entries needs exactly one mask entry")
    return entries


def _read_access_acl(fd: int, path: Path) -> tuple[_AclEntry, ...] | None:
    """Return the POSIX access ACL of the open file ``fd``, or None if it has none.

    Read through the descriptor, so it describes the same file that was
    ``fstat``-ed and will be parsed (a symlink's target). Only Linux
    exposes ACLs as :data:`_POSIX_ACL_XATTR`; where ``os.getxattr`` is
    missing (macOS, the BSDs) ACLs are not inspected. A file with no ACL
    (``ENODATA``) or on a filesystem without ACL support (``ENOTSUP``)
    has nothing beyond its mode bits; any other failure to read or decode
    the ACL refuses the file, since an ACL that can't be inspected could
    grant anyone write access.

    Args:
        fd: The open descriptor of the discovered ``.env``.
        path: The discovered ``.env`` path, used only in error messages.

    Returns:
        The ACL's entries, or None when the file has no ACL to check.

    Raises:
        SettingsError: If the ACL can't be read or decoded.
    """
    if not hasattr(os, "getxattr"):
        return None
    try:
        blob = os.getxattr(fd, _POSIX_ACL_XATTR)
    except OSError as exc:
        if exc.errno in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
            return None
        raise SettingsError(
            f"Could not read the ACL of discovered .env file {path}: {exc.strerror or exc}",
            hint="Pass the file explicitly with --env-file instead of relying on upward search.",
        ) from exc
    try:
        return _parse_posix_acl(blob)
    except ValueError as exc:
        raise SettingsError(
            f"Refusing to load discovered .env file {path}: its ACL could not be decoded ({exc}).",
            hint=(
                f"Remove the ACL with `setfacl -b {shlex.quote(str(path))}`, or pass the file "
                "explicitly with --env-file instead of relying on upward search."
            ),
        ) from exc


def _primary_group_is_private(gid: int, uid: int) -> bool:
    """Return whether no user other than ``uid`` belongs to group ``gid``.

    A group counts as shared if its member list (``gr_mem``) names anyone
    but ``uid``'s own login name, or if any other account has it as its
    primary group. Accounts sharing ``uid`` (aliases) are the same user.
    A group or user that can't be looked up counts as shared (fail closed).

    Known limit: on hosts whose name service doesn't enumerate (LDAP/sssd
    with enumeration off), ``pwd.getpwall`` sees only local accounts, so a
    directory user whose primary group is ``gid`` but who isn't listed in
    ``gr_mem`` goes unnoticed.

    Only called after the ``os.getuid`` guard in
    :func:`read_discovered_env_file`, so ``grp``/``pwd`` (POSIX-only) are
    imported here rather than at module level.

    Args:
        gid: The file's group, already known to be the user's primary group.
        uid: The current user's uid.

    Returns:
        True if the group is effectively the user's private group.
    """
    import grp
    import pwd

    try:
        members = set(grp.getgrgid(gid).gr_mem)
        own_name = pwd.getpwuid(uid).pw_name
    except KeyError:
        return False
    if not members <= {own_name}:
        return False
    return not any(entry.pw_gid == gid and entry.pw_uid != uid for entry in pwd.getpwall())


def _user_label(uid: int) -> str:
    """Return user ``uid``'s login name for messages, or ``uid <n>`` if it has none.

    Args:
        uid: The user id to name.

    Returns:
        The login name, or ``uid <n>`` when the lookup fails.
    """
    import pwd

    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return f"uid {uid}"


def _group_label(gid: int) -> str:
    """Return group ``gid``'s name for messages, or the number if it has none.

    Args:
        gid: The group id to name.

    Returns:
        The group name, or ``str(gid)`` when the lookup fails.
    """
    import grp

    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def read_discovered_env_file(path: Path) -> str:
    """Return the text of a discovered ``.env`` file, refusing an untrustworthy one.

    Only applies to a ``.env`` found by :func:`find_env_file` -- a file
    planted above the search start by another user on a shared machine,
    or writable by others, could inject hostile environment overrides.
    A file owned by another user is refused on that ground alone, with a
    hint that never suggests taking it over (``chown``): it may be
    someone else's.
    An explicitly-passed ``env_file`` is operator-chosen and is never
    checked here.

    The file is opened once and the ownership/permission checks run
    against ``os.fstat`` of that same descriptor, whose contents are then
    returned for parsing: nothing is re-opened by path, so the file
    cannot be swapped between the check and the read. A symlinked
    ``.env`` is followed, and its *target* is what gets checked and read.
    ``O_NONBLOCK`` keeps a FIFO from hanging the open; anything that is
    not a regular file is refused. On Linux the descriptor's POSIX access
    ACL is checked too (see :func:`_read_access_acl`). Two problems with
    the same fix command list it once in the hint.

    On platforms without ``os.getuid`` (Windows), where POSIX ownership/
    permission bits don't apply, the file is read without any checks.

    Args:
        path: The discovered ``.env`` file.

    Returns:
        The file's full text, decoded as UTF-8.

    Raises:
        SettingsError: If the file cannot be opened, is not a regular
            file, is not owned by the current user, is world-writable, is
            writable by a group other than the user's primary group or by
            a primary group shared with other users, has an ACL that grants
            write access to another user or group, or has an ACL that
            can't be read or decoded.
    """
    if not hasattr(os, "getuid"):
        return path.read_text(encoding="utf-8")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        raise SettingsError(
            f"Could not open discovered .env file {path}: {exc.strerror or exc}",
            hint="Make the file readable by you, or pass a .env file explicitly with --env-file.",
        ) from exc
    with os.fdopen(fd, encoding="utf-8") as stream:
        st = os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise SettingsError(
                f"Refusing to load discovered .env file {path}: it is not a regular file.",
                hint="Replace it with a regular file, or pass one explicitly with --env-file.",
            )
        if st.st_uid != os.getuid():
            raise SettingsError(
                f"Refusing to load discovered .env file {path}: it is owned by "
                f"{_user_label(st.st_uid)}, not you.",
                hint=(
                    "If you did not create it, do not use it: delete it (or ask its owner to), "
                    "keep your own .env in your project directory, or pass one explicitly "
                    "with --env-file."
                ),
            )
        acl = _read_access_acl(stream.fileno(), path)
        problems = _env_trust_problems(path, st, acl)
        if problems:
            reasons = "; ".join(problem.reason for problem in problems)
            fixes = " && ".join(dict.fromkeys(problem.fix for problem in problems))
            raise SettingsError(
                f"Refusing to load discovered .env file {path}: {reasons}.",
                hint=(
                    f"Fix it with `{fixes}`, or pass the file explicitly with "
                    "--env-file instead of relying on upward search."
                ),
            )
        return stream.read()
