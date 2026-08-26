"""Tests for meshprovision.db.locking."""

from __future__ import annotations

import errno
import logging
import os
from pathlib import Path

import pytest

from meshprovision.db import locking
from meshprovision.errors import AtomicWriteError, DatabaseLockedError, SettingsError

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised only on non-POSIX platforms
    fcntl = None  # type: ignore[assignment]

pytestmark = pytest.mark.unit

_POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="flock is POSIX-only")


@_POSIX_ONLY
def test_second_exclusive_lock_in_the_same_process_is_refused(tmp_path: Path) -> None:
    # Proves flock (not fcntl.lockf) was used: lockf is per-process and would
    # let two handles in one process acquire the "same" lock without
    # conflict, passing this test for the wrong reason.
    target = tmp_path / "nodes_db.ods"
    with (
        locking.exclusive_lock(target, timeout=1.0),
        pytest.raises(DatabaseLockedError),
        locking.exclusive_lock(target, timeout=0.1),
    ):
        pass


@_POSIX_ONLY
def test_lock_is_released_on_exit_and_reacquirable(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    with locking.exclusive_lock(target, timeout=1.0):
        pass
    with locking.exclusive_lock(target, timeout=0.1):
        pass  # would raise DatabaseLockedError if the first lock had leaked


@_POSIX_ONLY
def test_lock_is_released_when_the_block_raises(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    with pytest.raises(RuntimeError, match="boom"), locking.exclusive_lock(target, timeout=1.0):
        raise RuntimeError("boom")
    with locking.exclusive_lock(target, timeout=0.1):
        pass  # would raise DatabaseLockedError if the first lock had leaked


@_POSIX_ONLY
def test_lock_file_is_not_removed_on_release(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    with locking.exclusive_lock(target, timeout=1.0):
        pass
    assert locking.lock_path_for(target).is_file()


@_POSIX_ONLY
def test_lock_file_records_the_holder_pid(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    with locking.exclusive_lock(target, timeout=1.0):
        content = locking.lock_path_for(target).read_text(encoding="ascii")
    assert content.strip() == str(os.getpid())


@_POSIX_ONLY
def test_locked_error_names_the_holder_pid(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    with (
        locking.exclusive_lock(target, timeout=1.0),
        pytest.raises(DatabaseLockedError) as excinfo,
        locking.exclusive_lock(target, timeout=0.1),
    ):
        pass
    assert excinfo.value.holder_pid == os.getpid()


@_POSIX_ONLY
def test_locked_error_reports_no_pid_when_the_holder_never_recorded_one(
    tmp_path: Path,
) -> None:
    # A holder killed between acquiring flock and writing its pid must
    # degrade gracefully -- holder_pid is None, not a raised exception.
    assert fcntl is not None
    target = tmp_path / "nodes_db.ods"
    lock_path = locking.lock_path_for(target)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with (
            pytest.raises(DatabaseLockedError) as excinfo,
            locking.exclusive_lock(target, timeout=0.1),
        ):
            pass
        assert excinfo.value.holder_pid is None
    finally:
        os.close(fd)


@_POSIX_ONLY
def test_lock_file_is_owner_only(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    with locking.exclusive_lock(target, timeout=1.0):
        pass
    mode = locking.lock_path_for(target).stat().st_mode & 0o777
    assert mode == 0o600


@_POSIX_ONLY
def test_lock_file_creation_failure_raises_atomic_write_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "nodes_db.ods"
    lock_path = locking.lock_path_for(target)
    real_open = os.open

    def _fail_open(path: object, *args: object, **kwargs: object) -> int:
        if path == lock_path:
            raise OSError("Read-only file system")
        return real_open(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(locking.os, "open", _fail_open)
    with (
        pytest.raises(AtomicWriteError) as excinfo,
        locking.exclusive_lock(target, timeout=0.1),
    ):
        pass
    assert excinfo.value.path == str(target)


@_POSIX_ONLY
def test_flock_failure_unrelated_to_contention_raises_atomic_write_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "nodes_db.ods"
    attempts = 0

    def _fail_flock(fd: int, operation: int) -> None:
        nonlocal attempts
        attempts += 1
        raise OSError(errno.ENOLCK, "No locks available")

    def _never_sleep(seconds: float) -> None:
        raise AssertionError(
            f"exclusive_lock polled after a non-contention flock failure "
            f"({seconds}s); ENOLCK must fail immediately, not wait out the timeout"
        )

    monkeypatch.setattr(locking.fcntl, "flock", _fail_flock)
    monkeypatch.setattr(locking.time, "sleep", _never_sleep)

    # A deliberately long timeout: if the errno check regresses, the sleep
    # tripwire fires on the first poll instead of the suite stalling for 30s.
    with (
        pytest.raises(AtomicWriteError) as excinfo,
        locking.exclusive_lock(target, timeout=30.0),
    ):
        pass

    assert excinfo.value.path == str(target)
    assert attempts == 1
    assert "No locks available" in str(excinfo.value)


def test_lock_is_a_noop_without_fcntl(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(locking, "fcntl", None)
    monkeypatch.setattr(locking, "_warned_no_fcntl", False)
    target = tmp_path / "nodes_db.ods"
    with locking.exclusive_lock(target):
        pass
    assert not locking.lock_path_for(target).exists()


def test_no_fcntl_warning_is_emitted_once_not_per_acquisition(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(locking, "fcntl", None)
    monkeypatch.setattr(locking, "_warned_no_fcntl", False)
    target = tmp_path / "nodes_db.ods"
    with caplog.at_level(logging.WARNING, logger="meshprovision.db.locking"):
        with locking.exclusive_lock(target):
            pass
        with locking.exclusive_lock(target):
            pass
    matches = [r for r in caplog.records if "unavailable on this platform" in r.message]
    assert len(matches) == 1


def test_resolve_timeout_prefers_explicit_argument_then_env_then_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(locking.LOCK_TIMEOUT_ENV, raising=False)
    assert locking._resolve_timeout(None) == locking.DEFAULT_LOCK_TIMEOUT
    assert locking._resolve_timeout(2.5) == 2.5

    monkeypatch.setenv(locking.LOCK_TIMEOUT_ENV, "1.5")
    assert locking._resolve_timeout(None) == 1.5
    assert locking._resolve_timeout(3.0) == 3.0


@pytest.mark.parametrize(
    "raw", ["not-a-number", "inf", "-inf", "Infinity", "nan", "NaN", "-5", "10s"]
)
def test_resolve_timeout_rejects_a_malformed_env_value(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    monkeypatch.setenv(locking.LOCK_TIMEOUT_ENV, raw)
    with pytest.raises(SettingsError) as excinfo:
        locking._resolve_timeout(None)
    assert locking.LOCK_TIMEOUT_ENV in str(excinfo.value)


@pytest.mark.parametrize("raw", ["", "   "])
def test_resolve_timeout_treats_an_empty_env_value_as_unset(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    monkeypatch.setenv(locking.LOCK_TIMEOUT_ENV, raw)
    assert locking._resolve_timeout(None) == locking.DEFAULT_LOCK_TIMEOUT


@_POSIX_ONLY
def test_exclusive_lock_refuses_a_malformed_env_timeout_without_creating_the_lock_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(locking.LOCK_TIMEOUT_ENV, "inf")
    target = tmp_path / "nodes_db.ods"

    with pytest.raises(SettingsError), locking.exclusive_lock(target):
        pass

    assert not locking.lock_path_for(target).exists()


@_POSIX_ONLY
def test_read_holder_pid_returns_none_when_the_lock_file_cannot_be_read(
    tmp_path: Path,
) -> None:
    # A closed descriptor makes the lseek/read raise EBADF for real, with
    # no monkeypatching -- the same degrade-to-None contract as an empty
    # or garbage pid file, on the OS-failure path instead.
    fd = os.open(tmp_path / "nodes_db.ods.lock", os.O_CREAT | os.O_RDWR, 0o600)
    os.close(fd)
    assert locking._read_holder_pid(fd) is None
