"""Application settings, loaded from environment variables and ``.env``.

:class:`Settings` is a frozen ``pydantic`` model covering everything the
``mesh`` console script needs before it can do anything else: where the
ODS database and provisioning template live, where the HTTP response
cache is stored, how long cached entries stay fresh, the operator's
contact string (required by lorastats.pl), and the logging verbosity.

:func:`load_settings` builds a :class:`Settings` instance by layering,
from lowest to highest precedence: an optional ``.env`` file, the process
environment, and explicit programmatic overrides. ``os.environ`` itself
is never mutated -- every layer is read into a plain ``dict`` first, so
loading settings twice in the same process (as tests routinely do) never
leaks state between calls.

This module is a leaf within the ``config`` group: :mod:`meshprovision.
config.template` imports :func:`format_validation_error` from here, but
this module imports nothing from ``meshprovision.config.template``.
"""

from __future__ import annotations

import errno
import io
import logging
import os
import shlex
import stat
import struct
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Final, Literal, NamedTuple, TypeAlias

import dotenv
import platformdirs
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from meshprovision.errors import MissingContactError, SettingsError

_logger = logging.getLogger(__name__)

__all__ = [
    "APP_NAME",
    "DEFAULT_CACHE_TTL",
    "DEFAULT_DB_PATH",
    "DEFAULT_LOG_LEVEL",
    "DEFAULT_TEMPLATE_PATH",
    "ENV_FIELD_MAP",
    "ENV_PREFIX",
    "LogLevel",
    "Settings",
    "default_cache_dir",
    "find_env_file",
    "format_validation_error",
    "load_settings",
]

APP_NAME: Final[str] = "meshprovision"
"""Application name used for the platform cache directory and elsewhere."""

ENV_PREFIX: Final[str] = "MESHPROVISION_"
"""Prefix shared by every environment variable meshprovision reads."""

DEFAULT_DB_PATH: Final[Path] = Path("data/nodes_db.ods")
"""Default path to the ODS node database, relative to the CWD."""

DEFAULT_TEMPLATE_PATH: Final[Path] = Path("config/template.yaml")
"""Default path to the provisioning template, relative to the CWD."""

DEFAULT_CACHE_TTL: Final[float] = 300.0
"""Default HTTP response cache time-to-live, in seconds."""

DEFAULT_LOG_LEVEL: Final[str] = "WARNING"
"""Default logging verbosity."""

LogLevel: TypeAlias = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
"""The set of logging verbosities accepted by :attr:`Settings.log_level`."""

ENV_FIELD_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "MESHPROVISION_DB_PATH": "db_path",
        "MESHPROVISION_TEMPLATE_PATH": "template_path",
        "MESHPROVISION_CACHE_DIR": "cache_dir",
        "MESHPROVISION_CACHE_TTL": "cache_ttl",
        "MESHPROVISION_CONTACT": "contact",
        "MESHPROVISION_LOG_LEVEL": "log_level",
    }
)
"""Maps every supported ``MESHPROVISION_*`` environment variable to the
:class:`Settings` field it populates."""


def default_cache_dir() -> Path:
    """Return the platform-appropriate user cache directory.

    Uses ``platformdirs`` so the location follows OS convention (for
    example ``~/.cache/meshprovision`` on Linux) without meshprovision
    having to special-case any platform itself.

    Returns:
        The default cache directory for meshprovision.
    """
    return Path(platformdirs.user_cache_dir(APP_NAME, appauthor=False))


class Settings(BaseModel):
    """Top-level application settings.

    Immutable once constructed (``frozen=True``): callers that need a
    modified copy use :meth:`with_overrides` rather than mutating fields
    in place, matching the project's immutability convention.

    Attributes:
        db_path: Path to the ODS node database.
        template_path: Path to the provisioning template YAML file.
        cache_dir: Directory the HTTP response cache is stored under.
        cache_ttl: HTTP response cache time-to-live, in seconds.
        contact: Operator contact string sent to lorastats.pl in the
            ``User-Agent`` header. ``None`` when unset -- there is
            deliberately no default value.
        log_level: Logging verbosity for the ``mesh`` console script.
            Defaults to ``"WARNING"`` -- a plain run stays quiet on
            stderr; ``-v`` raises this project's own loggers to
            ``INFO``, ``-vv``/``-vvv`` to ``DEBUG`` (see
            :func:`~meshprovision.cli.logging_setup.resolve_log_level`).
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
        validate_default=True,
    )

    db_path: Path = DEFAULT_DB_PATH
    template_path: Path = DEFAULT_TEMPLATE_PATH
    cache_dir: Path = Field(default_factory=default_cache_dir)
    cache_ttl: float = Field(default=DEFAULT_CACHE_TTL, ge=0.0)
    contact: str | None = None
    log_level: LogLevel = "WARNING"

    @field_validator("db_path", "template_path", "cache_dir", mode="after")
    @classmethod
    def _expand(cls, value: Path) -> Path:
        """Expand a leading ``~`` in a path field.

        Relative paths are left relative to the current working
        directory (documented in the bundled ``env.example``); only
        user-home expansion happens here.

        Args:
            value: The path as parsed so far.

        Returns:
            The path with any leading ``~`` expanded.
        """
        return Path(value).expanduser()

    @field_validator("contact", mode="before")
    @classmethod
    def _blank_contact_is_unset(cls, value: object) -> object:
        """Treat a blank or whitespace-only contact string as unset.

        ``MESHPROVISION_CONTACT=`` in ``.env`` is the documented shape of
        the bundled ``env.example`` for "not configured yet"; this
        validator turns that into ``None`` so :meth:`require_contact`
        sees it as unset rather than as an empty, technically-present
        value.

        Args:
            value: The raw value supplied for ``contact``.

        Returns:
            ``None`` when ``value`` is a blank/whitespace-only string;
            otherwise ``value`` unchanged.
        """
        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def _upper(cls, value: object) -> object:
        """Normalize a log level string to stripped upper case.

        Args:
            value: The raw value supplied for ``log_level``.

        Returns:
            The stripped, upper-cased string when ``value`` is a string;
            otherwise ``value`` unchanged.
        """
        if isinstance(value, str):
            return value.strip().upper()
        return value

    def require_contact(self) -> str:
        """Return the operator contact string, raising when unset.

        Returns:
            The configured, non-blank contact string.

        Raises:
            MissingContactError: If :attr:`contact` is ``None``.
        """
        if self.contact is None:
            raise MissingContactError()
        return self.contact

    def user_agent(self, *, version: str | None = None, require_contact: bool = True) -> str:
        """Build the ``User-Agent`` string sent to lorastats.pl.

        Args:
            version: Package version to embed. Defaults to
                ``meshprovision.__version__``.
            require_contact: Whether a missing :attr:`contact` should
                raise. Set to ``False`` on paths that never query
                lorastats, where contact-bearing identification is not
                required.

        Returns:
            A string of the form ``"meshprovision/<version> (+<contact>)"``,
            or bare ``"meshprovision/<version>"`` when ``require_contact``
            is ``False`` and no contact is configured.

        Raises:
            MissingContactError: If :attr:`contact` is unset **and**
                ``require_contact`` is ``True`` -- this is the single
                startup gate lorastats.pl access requires.
        """
        if version is None:
            from meshprovision import __version__ as package_version

            version = package_version
        if not require_contact and self.contact is None:
            return f"meshprovision/{version}"
        contact = self.require_contact()
        return f"meshprovision/{version} (+{contact})"

    def with_overrides(self, **changes: object) -> Settings:
        """Return a new :class:`Settings` with the given fields replaced.

        The project's immutability convention: this never mutates
        ``self``. The copy is re-validated (not just shallow-copied) so
        an override that would violate a field constraint is caught
        immediately.

        Args:
            **changes: Field name/value pairs to replace.

        Returns:
            A new, independently validated :class:`Settings` instance.
        """
        copied = self.model_copy(update=changes, deep=False)
        return Settings.model_validate(copied.model_dump())


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
    the tree.

    Args:
        start: Directory to begin searching from. Defaults to
            ``Path.cwd()``.

    Returns:
        The path to the nearest ``.env`` file, or ``None`` if none is
        found.
    """
    base = start if start is not None else Path.cwd()
    directories: tuple[Path, ...] = (base, *base.parents)
    home = Path.home()
    if base == home or home in base.parents:
        bounded: list[Path] = []
        for directory in directories:
            bounded.append(directory)
            if directory == home:
                break
        directories = tuple(bounded)
    for directory in directories:
        candidate = directory / ".env"
        if candidate.is_file():
            return candidate
    return None


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
    """List every reason the ``st`` and ``acl`` of a discovered ``.env`` make it untrustworthy.

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
            commands (``chmod``/``chown`` follow a symlink to its target,
            which is what ``st`` describes).
        st: ``os.fstat`` of the open file descriptor that will be parsed.
        acl: That descriptor's access ACL (see :func:`_read_access_acl`),
            or None if it has none.

    Returns:
        One :class:`_EnvTrustProblem` per failed check, in a stable order
        (owner, world-write, group-write, ACL write); empty if the file is
        trusted.
    """
    quoted = shlex.quote(str(path))
    problems: list[_EnvTrustProblem] = []
    if st.st_uid != os.getuid():
        problems.append(_EnvTrustProblem("it is not owned by you", f'chown "$USER" {quoted}'))
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
    :func:`_read_discovered_env_file`, so ``grp``/``pwd`` (POSIX-only) are
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


def _read_discovered_env_file(path: Path) -> str:
    """Return the text of a discovered ``.env`` file, refusing an untrustworthy one.

    Only applies to a ``.env`` found by :func:`find_env_file` -- a file
    planted above the search start by another user on a shared machine,
    or writable by others, could inject hostile environment overrides.
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


def _unrecognized_env_keys(source: Mapping[str, object]) -> set[str]:
    """Return every key in ``source`` that looks like a mistyped ``MESHPROVISION_*`` variable.

    Args:
        source: A ``.env``/environment mapping to scan the keys of.

    Returns:
        Every key starting with :data:`ENV_PREFIX` that is not a name in
        :data:`ENV_FIELD_MAP`.
    """
    return {k for k in source if k.startswith(ENV_PREFIX) and k not in ENV_FIELD_MAP}


def load_settings(
    *,
    env_file: Path | str | None = None,
    environ: Mapping[str, str] | None = None,
    overrides: Mapping[str, object] | None = None,
    search_dotenv: bool = True,
) -> Settings:
    """Build a :class:`Settings` instance from ``.env``, the environment, and overrides.

    Layers, from lowest to highest precedence: values from a ``.env``
    file (explicit ``env_file``, or the nearest one found via
    :func:`find_env_file` when ``search_dotenv`` is true), then
    ``environ`` (defaulting to ``os.environ``), then ``overrides``.
    ``os.environ`` is never mutated.

    A ``.env`` file found via :func:`find_env_file` is only trusted if
    it is a regular file (a symlink's target counts) owned by the current
    user and not world-writable nor writable by a foreign or shared group,
    nor by another user or group through a POSIX ACL (see
    :func:`_read_discovered_env_file`); an explicit ``env_file`` is
    operator-chosen and is loaded as-is.

    A blank value for any field (including ``MESHPROVISION_CONTACT=`` in
    ``.env``) is treated as "not set" rather than as an empty string,
    letting the field's own default (or lack of one) apply.

    A ``.env``/environment key that starts with :data:`ENV_PREFIX` but
    doesn't name a field in :data:`ENV_FIELD_MAP` (a typo, most often)
    is logged as a warning rather than silently ignored -- the affected
    field still falls back to its default either way, but the operator
    at least has a trail back to the cause.

    Args:
        env_file: An explicit ``.env`` file to read. When given, it is
            used instead of searching.
        environ: The environment mapping to read ``MESHPROVISION_*``
            variables from. Defaults to ``os.environ``.
        overrides: Explicit field overrides, highest precedence. A
            ``None`` value in this mapping is ignored rather than
            treated as an explicit override.
        search_dotenv: Whether to search for the nearest ``.env`` file
            when ``env_file`` is not given.

    Returns:
        A validated :class:`Settings` instance.

    Raises:
        SettingsError: If a discovered ``.env`` file is refused (see
            :func:`_read_discovered_env_file`), or the layered values fail
            :class:`Settings` validation.
    """
    values: dict[str, str] = {}
    unrecognized: set[str] = set()
    if search_dotenv or env_file is not None:
        dotenv_values: dict[str, str | None] | None = None
        if env_file is not None:
            explicit_path = Path(env_file)
            if explicit_path.is_file():
                dotenv_values = dotenv.dotenv_values(explicit_path)
        else:
            discovered_path = find_env_file()
            if discovered_path is not None:
                text = _read_discovered_env_file(discovered_path)
                dotenv_values = dotenv.dotenv_values(stream=io.StringIO(text))
        if dotenv_values is not None:
            values.update({k: v for k, v in dotenv_values.items() if v is not None})
            unrecognized.update(_unrecognized_env_keys(dotenv_values))

    source_environ = environ if environ is not None else os.environ
    values.update({k: v for k, v in source_environ.items() if k in ENV_FIELD_MAP})
    unrecognized.update(_unrecognized_env_keys(source_environ))

    if unrecognized:
        _logger.warning(
            "Unrecognized %s variable(s), ignored: %s. Run `mesh init` or see the bundled "
            "env.example for every supported name.",
            ENV_PREFIX.rstrip("_"),
            ", ".join(sorted(unrecognized)),
        )

    data: dict[str, object] = {}
    for env_name, field in ENV_FIELD_MAP.items():
        raw = values.get(env_name)
        if raw is not None and raw.strip():
            data[field] = raw.strip()

    if overrides:
        data.update({k: v for k, v in overrides.items() if v is not None})

    try:
        return Settings.model_validate(data)
    except ValidationError as exc:
        raise SettingsError(
            format_validation_error(exc, source="environment/.env"),
            hint="Run `mesh init` or see the bundled env.example for every supported variable.",
        ) from exc


def format_validation_error(exc: ValidationError, *, source: str) -> str:
    r"""Render a pydantic :class:`ValidationError` as operator-readable text.

    Deliberately omits each error's ``input`` value: a template or
    environment value could be sensitive (a path containing a username,
    or worse), so nothing that was actually submitted is echoed back.

    Args:
        exc: The validation error to render.
        source: Human-readable description of what was being validated
            (a file path, or ``"environment/.env"``).

    Returns:
        A multi-line string: a header naming ``source`` and the problem
        count, followed by one indented ``field.path: message`` line per
        error.
    """
    lines = [f"{source} failed validation ({exc.error_count()} problem(s)):"]
    for err in exc.errors():
        loc = ".".join(str(part) for part in err["loc"]) or "<root>"
        lines.append(f"  {loc}: {err['msg']}")
    return "\n".join(lines)
