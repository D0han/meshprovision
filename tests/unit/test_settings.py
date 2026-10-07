"""Tests for meshprovision.config.settings."""

from __future__ import annotations

import errno
import grp
import logging
import os
import pwd
import shlex
import stat
import struct
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

import pytest

from meshprovision.config import env_trust
from meshprovision.config.settings import (
    APP_NAME,
    DEFAULT_CACHE_TTL,
    Settings,
    default_cache_dir,
    find_env_file,
    format_validation_error,
    load_settings,
)
from meshprovision.errors import MissingContactError, SettingsError
from tests.unit.conftest import pretend_owned_by_someone_else

pytestmark = pytest.mark.unit

_CONTENT = "MESHPROVISION_CONTACT=me@example.invalid\n"
_SELF_USER = "mesh-test-self"
_OTHER_USER = "mesh-test-other"
_GROUP_NAME = "mesh-test-group"
_FALLBACK_HINT = (
    ", or pass the file explicitly with --env-file instead of relying on upward search."
)
_ACL_XATTR = "system.posix_acl_access"
_USER_OBJ, _USER, _GROUP_OBJ, _GROUP, _MASK, _OTHER = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
_R, _RW = 0o4, 0o6
_NO_ID = 0xFFFFFFFF


def _acl_blob(*entries: tuple[int, int, int]) -> bytes:
    """Encode ``(tag, perm, id)`` entries as a ``system.posix_acl_access`` value."""
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)


def _acl(*extra: tuple[int, int, int], group_obj: int = _R) -> bytes:
    """Encode an ACL: owner rw, owning group ``group_obj``, other r, plus ``extra`` entries.

    Entries are sorted by tag then id, the order the kernel requires.
    """
    base = ((_USER_OBJ, _RW, _NO_ID), (_GROUP_OBJ, group_obj, _NO_ID), (_OTHER, _R, _NO_ID))
    return _acl_blob(*sorted((*base, *extra), key=lambda entry: (entry[0], entry[2])))


def _fake_getxattr(acl: bytes | None) -> Callable[..., bytes]:
    """Return an ``os.getxattr`` stand-in that reports ``acl`` (None: no ACL, ``ENODATA``)."""

    def getxattr(path: object, attribute: str, *, follow_symlinks: bool = True) -> bytes:
        assert attribute == _ACL_XATTR
        if acl is None:
            raise OSError(errno.ENODATA, os.strerror(errno.ENODATA))
        return acl

    return getxattr


def _patch_accounts(
    monkeypatch: pytest.MonkeyPatch,
    *,
    uid: int,
    gid: int,
    file_gid: int,
    group_members: tuple[str, ...],
    private_group: bool,
) -> None:
    """Replace the account database with the current user plus, optionally, one other."""
    me = pwd.struct_passwd((_SELF_USER, "x", uid, gid, "", "/nonexistent", "/bin/sh"))
    accounts = [me]
    if not private_group:
        accounts.append(
            pwd.struct_passwd((_OTHER_USER, "x", uid + 1, file_gid, "", "/nonexistent", "/bin/sh"))
        )

    def getgrgid(lookup_gid: int) -> grp.struct_group:
        if lookup_gid != file_gid:
            raise KeyError(lookup_gid)
        return grp.struct_group((_GROUP_NAME, "x", file_gid, list(group_members)))

    def getpwuid(lookup_uid: int) -> pwd.struct_passwd:
        if lookup_uid != uid:
            raise KeyError(lookup_uid)
        return me

    monkeypatch.setattr(grp, "getgrgid", getgrgid)
    monkeypatch.setattr(pwd, "getpwuid", getpwuid)
    monkeypatch.setattr(pwd, "getpwall", lambda: list(accounts))


def _set_real_acl(target: Path, acl: bytes | None) -> None:
    """Write ``acl`` as ``target``'s access ACL, or skip where the filesystem can't."""
    if not hasattr(os, "setxattr"):
        pytest.skip("os.setxattr is unavailable (POSIX ACLs are read on Linux only)")
    assert acl is not None
    try:
        os.setxattr(target, _ACL_XATTR, acl)
    except OSError as exc:
        if exc.errno in {errno.ENOTSUP, errno.EOPNOTSUPP}:
            pytest.skip(f"the tmp filesystem has no POSIX ACL support: {exc}")
        raise


@pytest.fixture
def discovered_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[..., Path]:
    """Write ``tmp_path/.env`` at an exact mode and pin the process identity to it.

    The mode is set with chmod (umask-independent) and ``os.getuid``/``os.getgid``
    are patched relative to the file's REAL ``st_uid``/``st_gid``, so the outcome
    is the same whatever user, primary group, umask or setgid tmp dir runs it.

    With ``symlink=True`` the content, mode and identity anchor all apply to
    ``tmp_path/real.env`` and ``.env`` is a symlink to it.

    ``grp.getgrgid``/``pwd.getpwuid``/``pwd.getpwall`` are always patched too,
    so no test depends on the host's ``/etc/group``: the file's group is
    :data:`_GROUP_NAME` with ``group_members`` as its ``gr_mem``, the current
    user is :data:`_SELF_USER`, and ``private_group=False`` adds an
    :data:`_OTHER_USER` account whose primary group is the file's group.

    ``os.getxattr`` is patched as well, to report ``acl`` as the file's POSIX
    access ACL (``None``: no ACL), so a host whose tmp dir carries a default
    ACL can't change the outcome. ``real_xattr=True`` instead writes ``acl``
    to the file with ``os.setxattr`` (skipping the test where that's
    unsupported) and leaves the real ``os.getxattr`` in place. Discovery tests
    outside this fixture (CLI/init/setup/first-run) are deliberately not
    patched: they read the real ACL, ``ENODATA`` on a normal tmp dir.
    """
    monkeypatch.chdir(tmp_path)

    def make(
        mode: int = 0o600,
        *,
        own_uid: bool = True,
        primary_gid: bool = True,
        content: str = _CONTENT,
        symlink: bool = False,
        group_members: tuple[str, ...] = (),
        private_group: bool = True,
        acl: bytes | None = None,
        real_xattr: bool = False,
    ) -> Path:
        path = tmp_path / ".env"
        target = tmp_path / "real.env" if symlink else path
        target.write_text(content)
        target.chmod(mode)
        if symlink:
            path.symlink_to(target)
        if real_xattr:
            _set_real_acl(target, acl)
        else:
            monkeypatch.setattr(os, "getxattr", _fake_getxattr(acl), raising=False)
        st = target.stat()
        uid = st.st_uid if own_uid else st.st_uid + 1
        gid = st.st_gid if primary_gid else st.st_gid + 1
        monkeypatch.setattr(os, "getuid", lambda: uid)
        monkeypatch.setattr(os, "getgid", lambda: gid)
        _patch_accounts(
            monkeypatch,
            uid=uid,
            gid=gid,
            file_gid=st.st_gid,
            group_members=group_members,
            private_group=private_group,
        )
        return path

    return make


def test_load_settings_from_env_file_alone(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MESHPROVISION_CONTACT=me@example.invalid\nMESHPROVISION_LOG_LEVEL=DEBUG\n")
    settings = load_settings(env_file=env_file, environ={}, search_dotenv=False)
    assert settings.contact == "me@example.invalid"
    assert settings.log_level == "DEBUG"


def test_load_settings_finds_dotenv_by_default(
    discovered_env: Callable[..., Path],
) -> None:
    """``search_dotenv`` defaults to True, and that default is production.

    ``cli/common.py``'s ``build_settings`` never passes ``search_dotenv``,
    so this default is the entire mechanism by which a real ``.env`` is
    discovered. Every other test here opts out of it explicitly, so it
    must be pinned once from the outside: write a ``.env``, chdir to it
    (``find_env_file`` searches upward from the CWD), and call
    ``load_settings`` with the kwarg omitted entirely.
    """
    discovered_env(0o600, content="MESHPROVISION_CONTACT=found@example.invalid\n")
    settings = load_settings(environ={})
    assert settings.contact == "found@example.invalid"


def test_environ_overrides_env_file(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MESHPROVISION_CONTACT=fromfile@example.invalid\n")
    settings = load_settings(
        env_file=env_file, environ={"MESHPROVISION_CONTACT": "fromenv@example.invalid"}
    )
    assert settings.contact == "fromenv@example.invalid"


def test_overrides_beat_both(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MESHPROVISION_CONTACT=fromfile@example.invalid\n")
    settings = load_settings(
        env_file=env_file,
        environ={"MESHPROVISION_CONTACT": "fromenv@example.invalid"},
        overrides={"contact": "fromoverride@example.invalid"},
    )
    assert settings.contact == "fromoverride@example.invalid"


def test_blank_value_treated_as_unset(tmp_path: Path) -> None:
    settings = load_settings(environ={"MESHPROVISION_CONTACT": "   "}, search_dotenv=False)
    assert settings.contact is None


def test_os_environ_never_mutated(tmp_path: Path) -> None:
    snapshot = dict(os.environ)
    env_file = tmp_path / ".env"
    env_file.write_text("MESHPROVISION_CONTACT=me@example.invalid\n")
    load_settings(env_file=env_file, environ={}, search_dotenv=False)
    assert os.environ == snapshot


def test_unrecognized_env_var_from_environ_logs_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A typo'd MESHPROVISION_* variable must not be silently ignored.

    The field still falls back to its default either way -- this only
    pins that the operator gets a trail back to the cause.
    """
    with caplog.at_level("WARNING", logger="meshprovision.config.settings"):
        load_settings(environ={"MESHPROVISION_CACHE_TLL": "600"}, search_dotenv=False)
    assert any("MESHPROVISION_CACHE_TLL" in r.getMessage() for r in caplog.records)


def test_unrecognized_env_var_from_dotenv_logs_a_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MESHPROVISION_CACHE_TLL=600\n")
    with caplog.at_level("WARNING", logger="meshprovision.config.settings"):
        load_settings(env_file=env_file, environ={}, search_dotenv=False)
    assert any("MESHPROVISION_CACHE_TLL" in r.getMessage() for r in caplog.records)


def test_recognized_env_vars_never_log_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING", logger="meshprovision.config.settings"):
        load_settings(environ={"MESHPROVISION_CONTACT": "me@example.invalid"}, search_dotenv=False)
    assert caplog.records == []


def test_invalid_cache_ttl_raises_and_does_not_echo_value() -> None:
    with pytest.raises(SettingsError) as exc_info:
        load_settings(environ={"MESHPROVISION_CACHE_TTL": "-5"}, search_dotenv=False)
    assert "-5" not in str(exc_info.value)


def test_require_contact_raises_when_unset() -> None:
    settings = Settings(contact=None)
    with pytest.raises(MissingContactError):
        settings.require_contact()


def test_require_contact_whitespace_only_is_unset() -> None:
    settings = Settings.model_validate({"contact": "   "})
    with pytest.raises(MissingContactError):
        settings.require_contact()


def test_user_agent_format() -> None:
    settings = Settings(contact="me@example.invalid")
    agent = settings.user_agent(version="9.9.9")
    assert agent == "meshprovision/9.9.9 (+me@example.invalid)"


def test_user_agent_requires_contact_by_default() -> None:
    """``require_contact`` defaults to True -- the lorastats.pl startup gate.

    Both real call sites pass the kwarg explicitly, and the one test that
    omits it already has ``contact`` set, so nothing else distinguishes
    the default from ``require_contact=False``.
    """
    settings = Settings(contact=None)
    with pytest.raises(MissingContactError):
        settings.user_agent(version="9.9.9")


def test_user_agent_omits_contact_when_not_required_and_unset() -> None:
    settings = Settings(contact=None)
    assert settings.user_agent(version="9.9.9", require_contact=False) == "meshprovision/9.9.9"


def test_user_agent_still_includes_contact_when_set_and_not_required() -> None:
    settings = Settings(contact="me@example.invalid")
    agent = settings.user_agent(version="9.9.9", require_contact=False)
    assert agent == "meshprovision/9.9.9 (+me@example.invalid)"


def test_with_overrides_returns_new_revalidated_instance() -> None:
    settings = Settings(contact="me@example.invalid")
    updated = settings.with_overrides(log_level="debug")
    assert updated is not settings
    assert updated.log_level == "DEBUG"
    assert settings.log_level == "WARNING"


def test_tilde_expansion_on_path_fields(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    settings = Settings.model_validate({"db_path": "~/mydb.ods"})
    assert str(settings.db_path) == str(tmp_path / "mydb.ods")


def test_find_env_file_walks_upward(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("X=1\n")
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)
    found = find_env_file(nested)
    assert found == tmp_path / ".env"


def test_find_env_file_returns_none_when_absent(tmp_path: Path) -> None:
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert find_env_file(nested) is None


def test_find_env_file_does_not_walk_above_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ``.env`` planted above ``$HOME`` must never be picked up.

    Patches ``Path.home`` to a directory under ``tmp_path``, places a
    ``.env`` *above* that patched home, and confirms searching upward
    from several levels below the patched home never escapes it.
    """
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    (tmp_path / ".env").write_text("X=1\n")
    nested = fake_home / "a" / "b" / "c"
    nested.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    assert find_env_file(nested) is None


def test_find_env_file_does_not_walk_above_a_symlinked_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``$HOME`` naming a symlink still bounds a walk that starts from the resolved path.

    The working directory is always resolved, so ``$HOME=/home/u`` -> ``/data/u``
    and a cwd of ``/data/u/proj`` would otherwise never meet ``$HOME``.
    """
    real_home = tmp_path / "data" / "u"
    nested = real_home / "proj" / "sub"
    nested.mkdir(parents=True)
    (tmp_path / "data" / ".env").write_text("X=1\n")
    link = tmp_path / "home-link"
    link.symlink_to(real_home, target_is_directory=True)
    monkeypatch.setattr(Path, "home", lambda: link)
    assert find_env_file(nested) is None


def _no_such_user(uid: int) -> NoReturn:
    raise KeyError(uid)


@pytest.mark.parametrize(
    ("mode", "foreign_gid"),
    [
        pytest.param(0o777, False, id="world-writable-like-tmp"),
        pytest.param(0o770, True, id="writable-by-a-foreign-group"),
    ],
)
def test_find_env_file_skips_another_users_env_in_a_shared_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    mode: int,
    foreign_gid: bool,
) -> None:
    """A ``.env`` someone else could have planted is skipped, and the walk goes on.

    The shared directory is owned by the current user here, like ``/tmp``
    is owned by root when root runs ``mesh``: being the directory's owner
    doesn't make it private while others can create files in it.
    """
    own = tmp_path / ".env"
    own.write_text("X=1\n")
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(mode)
    planted = shared / ".env"
    planted.write_text("X=2\n")
    if foreign_gid:
        real_gid = os.getgid()
        monkeypatch.setattr(os, "getgid", lambda: real_gid + 1)
    other_uid = pretend_owned_by_someone_else(monkeypatch, planted)
    monkeypatch.setattr(pwd, "getpwuid", _no_such_user)

    with caplog.at_level(logging.INFO, logger="meshprovision.config.env_trust"):
        assert find_env_file(shared) == own

    (record,) = caplog.records
    assert record.getMessage() == (
        f"Ignoring {planted}: it is owned by uid {other_uid} and its directory is not "
        "private to you."
    )


def test_find_env_file_returns_another_users_env_in_a_private_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the user (or root, e.g. via sudo) could have put it there: it is refused on read."""
    private = tmp_path / "private"
    private.mkdir()
    private.chmod(0o700)
    planted = private / ".env"
    planted.write_text("X=2\n")
    pretend_owned_by_someone_else(monkeypatch, planted)
    assert find_env_file(private) == planted


def test_find_env_file_skips_nothing_without_getuid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without ``os.getuid`` (Windows) there is no ownership to judge, so nothing is skipped."""
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    planted = shared / ".env"
    planted.write_text("X=2\n")
    pretend_owned_by_someone_else(monkeypatch, planted)
    monkeypatch.delattr(os, "getuid")
    assert find_env_file(shared) == planted


def _expected_hint(path: Path, *fixes: str) -> str:
    quoted = shlex.quote(str(path))
    return "Fix it with `" + " && ".join(f"{fix} {quoted}" for fix in fixes) + "`" + _FALLBACK_HINT


@pytest.mark.parametrize(
    ("mode", "own_uid", "primary_gid", "fixes"),
    [
        pytest.param(0o600, True, True, (), id="600-owner-primary-accepted"),
        pytest.param(0o644, True, True, (), id="644-owner-primary-accepted"),
        pytest.param(0o664, True, True, (), id="664-owner-primary-group-write-accepted"),
        pytest.param(
            0o664, True, False, ("chmod g-w",), id="664-owner-foreign-group-write-refused"
        ),
        pytest.param(0o646, True, True, ("chmod o-w",), id="646-owner-primary-world-write-refused"),
        pytest.param(
            0o646, True, False, ("chmod o-w",), id="646-owner-foreign-world-write-refused"
        ),
        pytest.param(
            0o666, True, True, ("chmod o-w",), id="666-owner-primary-world-group-write-refused"
        ),
        pytest.param(
            0o666,
            True,
            False,
            ("chmod o-w", "chmod g-w"),
            id="666-owner-foreign-world-group-write-refused",
        ),
    ],
)
def test_discovered_env_trust_matrix(
    discovered_env: Callable[..., Path],
    mode: int,
    own_uid: bool,
    primary_gid: bool,
    fixes: tuple[str, ...],
) -> None:
    path = discovered_env(mode, own_uid=own_uid, primary_gid=primary_gid)
    if not fixes:
        assert load_settings(environ={}).contact == "me@example.invalid"
    else:
        with pytest.raises(SettingsError) as exc_info:
            load_settings(environ={})
        assert str(exc_info.value).startswith(f"Refusing to load discovered .env file {path}: ")
        assert exc_info.value.hint == _expected_hint(path, *fixes)


@pytest.mark.skipif(os.name != "posix", reason="runs the hint's chmod through sh")
@pytest.mark.parametrize(
    ("mode", "primary_gid", "group_members"),
    [
        pytest.param(0o664, False, (), id="664-foreign-group"),
        pytest.param(0o646, True, (), id="646-world"),
        pytest.param(0o666, True, (), id="666-primary-world"),
        pytest.param(0o666, False, (), id="666-foreign-world-and-group"),
        pytest.param(0o664, True, (_OTHER_USER,), id="664-shared-primary-group"),
    ],
)
def test_discovered_env_refusal_hint_command_makes_it_loadable(
    discovered_env: Callable[..., Path],
    mode: int,
    primary_gid: bool,
    group_members: tuple[str, ...],
) -> None:
    discovered_env(mode, primary_gid=primary_gid, group_members=group_members)
    with pytest.raises(SettingsError) as exc_info:
        load_settings(environ={})
    command = (exc_info.value.hint or "").split("`")[1]
    subprocess.run(["/bin/sh", "-c", command], check=True)
    assert load_settings(environ={}).contact == "me@example.invalid"


_SHARED_REASON = f"it is group-writable and its group {_GROUP_NAME} is shared with other users"
_FOREIGN_REASON = "it is group-writable by a group other than your primary group"


@pytest.mark.parametrize(
    ("primary_gid", "group_members", "private_group", "reason"),
    [
        pytest.param(True, (), True, None, id="no-members-accepted"),
        pytest.param(True, (_SELF_USER,), True, None, id="only-self-member-accepted"),
        pytest.param(
            True, (_SELF_USER, _OTHER_USER), True, _SHARED_REASON, id="other-member-refused"
        ),
        pytest.param(True, (), False, _SHARED_REASON, id="other-account-primary-gid-refused"),
        pytest.param(
            False,
            (_OTHER_USER,),
            False,
            _FOREIGN_REASON,
            id="foreign-group-gets-only-foreign-reason",
        ),
    ],
)
def test_discovered_env_group_write_needs_a_private_primary_group(
    discovered_env: Callable[..., Path],
    primary_gid: bool,
    group_members: tuple[str, ...],
    private_group: bool,
    reason: str | None,
) -> None:
    path = discovered_env(
        0o664, primary_gid=primary_gid, group_members=group_members, private_group=private_group
    )
    if reason is None:
        assert load_settings(environ={}).contact == "me@example.invalid"
        return
    with pytest.raises(SettingsError) as exc_info:
        load_settings(environ={})
    assert str(exc_info.value) == f"Refusing to load discovered .env file {path}: {reason}."
    assert exc_info.value.hint == _expected_hint(path, "chmod g-w")


@pytest.mark.parametrize("failing_lookup", ["getgrgid", "getpwuid"])
def test_discovered_env_group_write_refused_when_account_lookup_fails(
    discovered_env: Callable[..., Path], monkeypatch: pytest.MonkeyPatch, failing_lookup: str
) -> None:
    """A group or user that can't be resolved counts as shared (fail closed)."""
    path = discovered_env(0o664)
    st_gid = path.stat().st_gid

    def missing(key: int) -> NoReturn:
        raise KeyError(key)

    monkeypatch.setattr(grp if failing_lookup == "getgrgid" else pwd, failing_lookup, missing)
    with pytest.raises(SettingsError) as exc_info:
        load_settings(environ={})
    group = str(st_gid) if failing_lookup == "getgrgid" else _GROUP_NAME
    assert str(exc_info.value) == (
        f"Refusing to load discovered .env file {path}: it is group-writable and its "
        f"group {group} is shared with other users."
    )
    assert exc_info.value.hint == _expected_hint(path, "chmod g-w")


def test_discovered_env_symlink_to_trusted_target_loads(
    discovered_env: Callable[..., Path],
) -> None:
    path = discovered_env(0o600, symlink=True)
    assert path.is_symlink()
    assert load_settings(environ={}).contact == "me@example.invalid"


def test_discovered_env_symlink_to_untrusted_target_is_refused(
    discovered_env: Callable[..., Path],
) -> None:
    path = discovered_env(0o646, symlink=True)
    with pytest.raises(SettingsError) as exc_info:
        load_settings(environ={})
    assert exc_info.value.hint == _expected_hint(path, "chmod o-w")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs os.mkfifo")
def test_read_discovered_env_file_refuses_a_fifo(tmp_path: Path) -> None:
    fifo = tmp_path / ".env"
    os.mkfifo(fifo)
    with pytest.raises(SettingsError, match="it is not a regular file"):
        env_trust.read_discovered_env_file(fifo)


def test_discovered_env_open_failure_is_a_settings_error(
    discovered_env: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    path = discovered_env(0o600)

    def refuse_open(*_args: object, **_kwargs: object) -> int:
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(os, "open", refuse_open)
    with pytest.raises(SettingsError) as exc_info:
        load_settings(environ={})
    assert str(exc_info.value) == f"Could not open discovered .env file {path}: Permission denied"
    assert isinstance(exc_info.value.__cause__, PermissionError)


@pytest.mark.parametrize("primary_gid", [True, False], ids=["primary-group", "foreign-group"])
def test_discovered_env_owned_by_another_user_is_refused_without_a_chown_hint(
    discovered_env: Callable[..., Path], primary_gid: bool
) -> None:
    """Taking the file over would trust whatever its owner wrote; the hint says not to use it."""
    path = discovered_env(0o600, own_uid=False, primary_gid=primary_gid)
    with pytest.raises(SettingsError) as exc_info:
        env_trust.read_discovered_env_file(path)
    owner = path.stat().st_uid
    assert str(exc_info.value) == (
        f"Refusing to load discovered .env file {path}: it is owned by uid {owner}, not you."
    )
    assert exc_info.value.hint == (
        "If you did not create it, do not use it: delete it (or ask its owner to), keep your "
        "own .env in your project directory, or pass one explicitly with --env-file."
    )


def test_discovered_env_is_parsed_from_the_checked_open_file(
    discovered_env: Callable[..., Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A ``.env`` swapped for another file mid-check must not be what gets parsed.

    The swap is triggered from inside the trust check of the open file
    (``_env_trust_problems`` called with a regular file's ``st``, not a
    directory's): a check-then-reopen-by-path implementation would parse
    the swapped-in file, while checking and reading one open descriptor
    parses the file that was actually checked.
    """
    path = discovered_env(0o600)
    real_problems = env_trust._env_trust_problems
    swapped: list[bool] = []

    def swap_then_check(
        checked: Path, st: os.stat_result, acl: tuple[object, ...] | None
    ) -> list[object]:
        if stat.S_ISREG(st.st_mode) and not swapped:
            replacement = tmp_path / "replacement.env"
            replacement.write_text("MESHPROVISION_CONTACT=swapped@example.invalid\n")
            replacement.chmod(0o600)
            replacement.replace(path)
            swapped.append(True)
        return real_problems(checked, st, acl)  # type: ignore[arg-type]

    monkeypatch.setattr(env_trust, "_env_trust_problems", swap_then_check)
    assert load_settings(environ={}).contact == "me@example.invalid"
    assert swapped == [True]


def test_discovered_env_is_not_checked_without_getuid(
    discovered_env: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """On platforms without ``os.getuid`` (Windows) the file is read unchecked."""
    discovered_env(0o666, primary_gid=False)
    monkeypatch.delattr(os, "getuid")
    assert load_settings(environ={}).contact == "me@example.invalid"


def test_parse_posix_acl_decodes_every_entry() -> None:
    blob = _acl((_USER, _RW, 1234), (_GROUP, _R, 99), (_MASK, _RW, _NO_ID))
    assert env_trust._parse_posix_acl(blob) == (
        (_USER_OBJ, _RW, _NO_ID),
        (_USER, _RW, 1234),
        (_GROUP_OBJ, _R, _NO_ID),
        (_GROUP, _R, 99),
        (_MASK, _RW, _NO_ID),
        (_OTHER, _R, _NO_ID),
    )


@pytest.mark.parametrize(
    "blob",
    [
        pytest.param(b"\x02\x00", id="truncated-header"),
        pytest.param(_acl() + b"\x01\x00", id="partial-entry"),
        pytest.param(b"\x01" + _acl()[1:], id="wrong-version"),
        pytest.param(_acl((0x40, _RW, _NO_ID)), id="unknown-tag"),
        pytest.param(
            _acl_blob((_USER_OBJ, _RW, _NO_ID), (_OTHER, _R, _NO_ID)), id="no-owning-group-entry"
        ),
        pytest.param(_acl((_USER, _R, 1234)), id="named-entry-without-mask"),
    ],
)
def test_parse_posix_acl_rejects_a_malformed_blob(blob: bytes) -> None:
    with pytest.raises(ValueError, match=r"."):
        env_trust._parse_posix_acl(blob)


_ACL_REASON = "an ACL grants write access to another user or group"
_OWNER = -1
"""Stands for the file owner's uid in an ACL entry; anything else is another user."""


@pytest.mark.parametrize(
    ("mode", "group_obj", "named", "mask", "primary_gid", "reasons"),
    [
        pytest.param(
            0o664, _R, ((_USER, _RW, 1),), _RW, True, (_ACL_REASON,), id="named-user-write-refused"
        ),
        pytest.param(
            0o644, _R, ((_USER, _RW, 1),), _R, True, (), id="named-user-write-masked-accepted"
        ),
        pytest.param(
            0o664,
            _R,
            ((_GROUP, _RW, 1),),
            _RW,
            True,
            (_ACL_REASON,),
            id="named-group-write-refused",
        ),
        pytest.param(
            0o664, _R, ((_USER, _RW, _OWNER),), _RW, True, (), id="owner-named-entry-accepted"
        ),
        pytest.param(
            0o664,
            _R,
            ((_USER, _R, 1), (_GROUP, _R, 1)),
            _RW,
            False,
            (),
            id="read-only-entries-with-writable-mask-accepted",
        ),
        pytest.param(
            0o664,
            _RW,
            ((_USER, _R, 1),),
            _RW,
            True,
            (),
            id="owning-group-write-private-primary-accepted",
        ),
        pytest.param(
            0o664,
            _RW,
            ((_USER, _R, 1),),
            _RW,
            False,
            (_FOREIGN_REASON,),
            id="owning-group-write-foreign-group-refused",
        ),
        pytest.param(
            0o644, _RW, ((_USER, _R, 1),), _R, False, (), id="owning-group-write-masked-accepted"
        ),
        pytest.param(
            0o664,
            _RW,
            ((_USER, _RW, 1),),
            _RW,
            False,
            (_FOREIGN_REASON, _ACL_REASON),
            id="foreign-group-and-acl-write-refused-with-one-fix",
        ),
    ],
)
def test_discovered_env_acl_trust_matrix(
    discovered_env: Callable[..., Path],
    tmp_path: Path,
    mode: int,
    group_obj: int,
    named: tuple[tuple[int, int, int], ...],
    mask: int,
    primary_gid: bool,
    reasons: tuple[str, ...],
) -> None:
    """Group-class write access comes from the ACL entries through the mask, not the mode."""
    owner = tmp_path.stat().st_uid
    entries = tuple(
        (tag, perm, owner if qualifier == _OWNER else owner + qualifier)
        for tag, perm, qualifier in named
    )
    path = discovered_env(
        mode,
        primary_gid=primary_gid,
        acl=_acl(*entries, (_MASK, mask, _NO_ID), group_obj=group_obj),
    )
    if not reasons:
        assert load_settings(environ={}).contact == "me@example.invalid"
        return
    with pytest.raises(SettingsError) as exc_info:
        load_settings(environ={})
    assert str(exc_info.value) == (
        f"Refusing to load discovered .env file {path}: {'; '.join(reasons)}."
    )
    assert exc_info.value.hint == _expected_hint(path, "chmod g-w")


@pytest.mark.parametrize(
    ("code", "loads"),
    [
        pytest.param(errno.ENODATA, True, id="ENODATA-no-acl-loads"),
        pytest.param(errno.ENOTSUP, True, id="ENOTSUP-no-acl-support-loads"),
        pytest.param(errno.EACCES, False, id="EACCES-refused"),
        pytest.param(errno.EIO, False, id="EIO-refused"),
    ],
)
def test_discovered_env_acl_read_failure_refuses_unless_there_is_no_acl(
    discovered_env: Callable[..., Path], monkeypatch: pytest.MonkeyPatch, code: int, loads: bool
) -> None:
    path = discovered_env(0o644)

    def failing_getxattr(*args: object, **kwargs: object) -> bytes:
        raise OSError(code, os.strerror(code))

    monkeypatch.setattr(os, "getxattr", failing_getxattr, raising=False)
    if loads:
        assert load_settings(environ={}).contact == "me@example.invalid"
        return
    with pytest.raises(SettingsError) as exc_info:
        load_settings(environ={})
    assert str(exc_info.value) == (
        f"Could not read the ACL of discovered .env file {path}: {os.strerror(code)}"
    )
    assert exc_info.value.hint == (
        "Pass the file explicitly with --env-file instead of relying on upward search."
    )


def test_discovered_env_malformed_acl_is_refused(discovered_env: Callable[..., Path]) -> None:
    path = discovered_env(0o644, acl=b"\x02\x00\x00\x00\x01")
    with pytest.raises(SettingsError) as exc_info:
        load_settings(environ={})
    assert str(exc_info.value).startswith(
        f"Refusing to load discovered .env file {path}: its ACL could not be decoded ("
    )
    assert exc_info.value.hint == (
        f"Remove the ACL with `setfacl -b {shlex.quote(str(path))}`" + _FALLBACK_HINT
    )


def test_discovered_env_acl_is_not_checked_without_getxattr(
    discovered_env: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Where ``os.getxattr`` doesn't exist (macOS, the BSDs) only the mode bits are checked."""
    discovered_env(0o644, acl=_acl((_USER, _RW, 12345), (_MASK, _RW, _NO_ID)))
    monkeypatch.delattr(os, "getxattr")
    assert load_settings(environ={}).contact == "me@example.invalid"


def test_discovered_env_acl_is_read_from_the_checked_open_file(
    discovered_env: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ACL comes from the open descriptor of the symlink's target, not a re-resolved path."""
    path = discovered_env(0o600, symlink=True)
    seen: list[object] = []

    def recording_getxattr(target: object, attribute: str, **kwargs: object) -> bytes:
        seen.append(target)
        assert isinstance(target, int)
        assert os.fstat(target).st_ino == path.resolve().stat().st_ino
        raise OSError(errno.ENODATA, os.strerror(errno.ENODATA))

    monkeypatch.setattr(os, "getxattr", recording_getxattr, raising=False)
    assert load_settings(environ={}).contact == "me@example.invalid"
    assert len(seen) == 1


@pytest.mark.skipif(os.name != "posix", reason="runs the hint's chmod through sh")
@pytest.mark.parametrize("symlink", [False, True], ids=["file", "symlink"])
def test_discovered_env_real_acl_write_entry_is_refused_until_the_hint_runs(
    discovered_env: Callable[..., Path], tmp_path: Path, symlink: bool
) -> None:
    """A real ``setfacl -m u:<other>:rw`` ACL is refused, and ``chmod g-w`` makes it loadable."""
    other = tmp_path.stat().st_uid + 1
    path = discovered_env(
        0o644,
        symlink=symlink,
        acl=_acl((_USER, _RW, other), (_MASK, _RW, _NO_ID)),
        real_xattr=True,
    )
    with pytest.raises(SettingsError) as exc_info:
        load_settings(environ={})
    assert str(exc_info.value) == f"Refusing to load discovered .env file {path}: {_ACL_REASON}."
    command = (exc_info.value.hint or "").split("`")[1]
    subprocess.run(["/bin/sh", "-c", command], check=True)
    assert load_settings(environ={}).contact == "me@example.invalid"


def test_format_validation_error_lists_field_paths_never_input() -> None:
    from pydantic import ValidationError

    try:
        Settings.model_validate({"cache_ttl": "not-a-number"})
    except ValidationError as exc:
        text = format_validation_error(exc, source="test-source")
        assert "test-source" in text
        assert "cache_ttl" in text
        assert "not-a-number" not in text
    else:
        pytest.fail("expected a ValidationError")


def test_default_cache_ttl_constant() -> None:
    assert DEFAULT_CACHE_TTL == 300.0


def test_default_cache_dir_is_app_scoped() -> None:
    cache_dir = default_cache_dir()
    assert cache_dir.name == APP_NAME
    assert cache_dir.is_absolute()
