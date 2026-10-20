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
def test_lock_file_holds_only_the_new_holder_pid_after_a_longer_stale_one(
    tmp_path: Path,
) -> None:
    """A shorter pid written over a longer one must not keep the old one's tail ("12399")."""
    target = tmp_path / "nodes_db.ods"
    lock_path = locking.lock_path_for(target)
    stale_pid = "9" * (len(str(os.getpid())) + 3)
    lock_path.write_text(stale_pid, encoding="ascii")
    lock_path.chmod(0o600)

    with locking.exclusive_lock(target, timeout=1.0):
        content = lock_path.read_text(encoding="ascii")

    assert content == str(os.getpid())


@_POSIX_ONLY
def test_locked_error_hint_mentions_the_timeout_env_var(tmp_path: Path) -> None:
    """The hint must proactively surface the tuning knob, not just say "wait"."""
    target = tmp_path / "nodes_db.ods"
    with (
        locking.exclusive_lock(target, timeout=1.0),
        pytest.raises(DatabaseLockedError) as excinfo,
        locking.exclusive_lock(target, timeout=0.1),
    ):
        pass
    assert "MESHPROVISION_LOCK_TIMEOUT" in (excinfo.value.hint or "")
    assert "0.1" in (excinfo.value.hint or "")


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


@_POSIX_ONLY
def test_contended_lock_polls_until_the_holder_releases_within_the_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Contention inside the timeout is waited out, not refused on the first EWOULDBLOCK."""
    target = tmp_path / "nodes_db.ods"
    real_flock = locking.fcntl.flock
    attempts = 0

    def _busy_twice(fd: int, operation: int) -> None:
        nonlocal attempts
        attempts += 1
        if attempts <= 2:
            raise OSError(errno.EWOULDBLOCK, "Resource temporarily unavailable")
        real_flock(fd, operation)

    sleeps: list[float] = []
    monkeypatch.setattr(locking.fcntl, "flock", _busy_twice)
    monkeypatch.setattr(locking.time, "sleep", sleeps.append)

    with locking.exclusive_lock(target, timeout=30.0):
        pass

    assert attempts == 3
    assert sleeps == [locking._POLL_INTERVAL, locking._POLL_INTERVAL]


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
    "raw", ["not-a-number", "inf", "-inf", "Infinity", "nan", "NaN", "-5", "-1", "-0.5", "10s"]
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


# --- lock_path_for resolves a symlinked target (B3) -----------------------------


def test_lock_path_for_resolves_a_symlinked_target(tmp_path: Path) -> None:
    real_dir = tmp_path / "shared"
    real_dir.mkdir()
    real_target = real_dir / "nodes_db.ods"
    real_target.write_bytes(b"x")
    link_dir = tmp_path / "ws1" / "data"
    link_dir.mkdir(parents=True)
    link = link_dir / "nodes_db.ods"
    link.symlink_to(real_target)

    assert locking.lock_path_for(link) == locking.lock_path_for(real_target)
    assert locking.lock_path_for(link) == real_target.with_name(
        real_target.name + locking.LOCK_SUFFIX
    )


@_POSIX_ONLY
def test_exclusive_lock_contends_across_a_symlink_and_the_real_path(tmp_path: Path) -> None:
    real_dir = tmp_path / "shared"
    real_dir.mkdir()
    real_target = real_dir / "nodes_db.ods"
    real_target.write_bytes(b"x")
    link_dir = tmp_path / "ws1" / "data"
    link_dir.mkdir(parents=True)
    link = link_dir / "nodes_db.ods"
    link.symlink_to(real_target)

    with (
        locking.exclusive_lock(real_target, timeout=1.0),
        pytest.raises(DatabaseLockedError),
        locking.exclusive_lock(link, timeout=0.1),
    ):
        pass
    assert not (link_dir / "nodes_db.ods.lock").exists()


@_POSIX_ONLY
def test_a_lock_path_planted_as_a_symlink_is_never_followed(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me", encoding="utf-8")
    locking.lock_path_for(target).symlink_to(victim)

    with (
        pytest.raises(AtomicWriteError, match="Failed to create the database lock file") as excinfo,
        locking.exclusive_lock(target, timeout=0),
    ):
        pass

    assert victim.read_text(encoding="utf-8") == "keep me"
    assert excinfo.value.hint is not None
    assert "must be a regular file" in excinfo.value.hint


@_POSIX_ONLY
def test_a_lock_path_that_is_not_a_regular_file_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    os.mkfifo(locking.lock_path_for(target))

    with (
        pytest.raises(AtomicWriteError, match="is not a regular file") as excinfo,
        locking.exclusive_lock(target, timeout=0),
    ):
        pass

    assert excinfo.value.hint == f"Delete {locking.lock_path_for(target)}; mesh recreates it."


@_POSIX_ONLY
def test_a_lock_path_hard_linked_to_another_file_is_locked_without_writing_into_it(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """O_NOFOLLOW does not stop a hard link: the pid overwrote the linked file."""
    target = tmp_path / "nodes_db.ods"
    victim = tmp_path / "victim.txt"
    victim.write_text("precious contents", encoding="utf-8")
    os.link(victim, locking.lock_path_for(target))

    with (
        caplog.at_level(logging.WARNING, logger="meshprovision.db.locking"),
        locking.exclusive_lock(target, timeout=0),
        pytest.raises(DatabaseLockedError) as excinfo,
        locking.exclusive_lock(target, timeout=0),
    ):
        pass

    assert victim.read_text(encoding="utf-8") == "precious contents"
    assert excinfo.value.holder_pid is None
    assert [record.getMessage() for record in caplog.records] == [
        f"{locking.lock_path_for(target)} has 2 hard links; not writing the holder pid into it"
    ]
