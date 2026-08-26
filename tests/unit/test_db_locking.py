"""Tests for meshprovision.db.locking."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest

from meshprovision.db import locking
from meshprovision.errors import AtomicWriteError, DatabaseLockedError

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

    monkeypatch.setenv(locking.LOCK_TIMEOUT_ENV, "not-a-number")
    assert locking._resolve_timeout(None) == locking.DEFAULT_LOCK_TIMEOUT


@pytest.mark.parametrize("raw", ["inf", "-inf", "Infinity", "nan", "NaN"])
def test_resolve_timeout_falls_back_on_a_non_finite_env_value(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    monkeypatch.setenv(locking.LOCK_TIMEOUT_ENV, raw)
    assert locking._resolve_timeout(None) == locking.DEFAULT_LOCK_TIMEOUT
