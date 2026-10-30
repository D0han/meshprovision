"""Tests for ``mesh status --watch``'s tolerance of transient ``DbError`` polls.

Round 37 Aspect 4, Batch E10: a single poll's database reload failing
(a concurrent ``mesh db restore``, a non-atomic external save, a brief
``EACCES`` while file ownership is being fixed) used to end the entire
monitor. These tests drive the real ``status`` click command through
:class:`~click.testing.CliRunner`, monkeypatching
:func:`meshprovision.cli.status._run_once` so no real database or
network access is needed -- only the watch loop's own error handling is
under test.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from meshprovision.cli import status as status_cli
from meshprovision.cli.main import cli
from meshprovision.db.nodes import NodeRecord
from meshprovision.errors import DbIntegrityError, ExitCode
from meshprovision.nodeid import NodeId
from meshprovision.status.merge import Availability, MergedNode, Thresholds
from meshprovision.status.report import StatusOptions, StatusReport

if TYPE_CHECKING:
    pass

pytestmark = pytest.mark.unit


def _ok_report() -> StatusReport:
    """A minimal, non-degraded :class:`StatusReport` (``exit_code() == 0``)."""
    return StatusReport(generated_at=datetime.now(UTC), nodes=(), thresholds=Thresholds())


def test_watch_tolerates_two_transient_db_errors_then_recovers(
    monkeypatch: pytest.MonkeyPatch, cli_env: dict[str, str]
) -> None:
    r"""A watch run keeps polling through 1-2 consecutive ``DbError``\ s.

    On revert (no tolerance), the very first ``DbError`` ends the run:
    ``_run_once`` would be called once, and the process would exit with
    :attr:`ExitCode.DB` instead of continuing to poll and eventually
    exiting 0 on the recovered report.
    """
    calls = {"n": 0}

    def fake_run_once(ctx: object, options: object, client: object) -> StatusReport:
        calls["n"] += 1
        if calls["n"] in (1, 2):
            raise DbIntegrityError(f"transient failure #{calls['n']}")
        return _ok_report()

    monkeypatch.setattr(status_cli, "_run_once", fake_run_once)

    sleeps = {"n": 0}

    def fake_sleep(_seconds: float) -> None:
        sleeps["n"] += 1
        if sleeps["n"] >= 3:
            raise KeyboardInterrupt

    monkeypatch.setattr(time, "sleep", fake_sleep)

    result = CliRunner().invoke(
        cli, ["status", "--watch", "--interval", "1", "--json"], env=cli_env, catch_exceptions=False
    )

    assert result.exit_code == 0
    assert calls["n"] == 3
    assert result.stderr.count("Poll failed") == 2
    assert "transient failure #1" in result.stderr
    assert "transient failure #2" in result.stderr
    assert result.stdout.count('"generated_at"') == 1
    assert result.stderr.rstrip().endswith("Stopped.")


def test_watch_gives_up_after_three_consecutive_db_errors(
    monkeypatch: pytest.MonkeyPatch, cli_env: dict[str, str]
) -> None:
    r"""Three consecutive ``DbError``\ s exhaust the tolerance and exit 4."""
    calls = {"n": 0}

    def fake_run_once(ctx: object, options: object, client: object) -> StatusReport:
        calls["n"] += 1
        raise DbIntegrityError("still broken")

    monkeypatch.setattr(status_cli, "_run_once", fake_run_once)

    result = CliRunner().invoke(
        cli, ["status", "--watch", "--interval", "1"], env=cli_env, catch_exceptions=False
    )

    assert result.exit_code == int(ExitCode.DB)
    assert calls["n"] == 3
    assert result.stderr.count("Poll failed") == 3
    assert "still broken" in result.stderr


def test_watch_success_resets_the_consecutive_db_failure_count(
    monkeypatch: pytest.MonkeyPatch, cli_env: dict[str, str]
) -> None:
    """Two failures, a success, two more failures: never three in a row, so it keeps polling."""
    outcomes = iter(["err", "err", "ok", "err", "err", "ok"])
    calls = {"n": 0}

    def fake_run_once(ctx: object, options: object, client: object) -> StatusReport:
        calls["n"] += 1
        if next(outcomes) == "err":
            raise DbIntegrityError(f"transient failure #{calls['n']}")
        return _ok_report()

    monkeypatch.setattr(status_cli, "_run_once", fake_run_once)
    sleeps = {"n": 0}

    def fake_sleep(_seconds: float) -> None:
        sleeps["n"] += 1
        if sleeps["n"] >= 6:
            raise KeyboardInterrupt

    monkeypatch.setattr(time, "sleep", fake_sleep)

    result = CliRunner().invoke(
        cli, ["status", "--watch", "--interval", "1", "--json"], env=cli_env, catch_exceptions=False
    )

    assert result.exit_code == 0
    assert calls["n"] == 6
    assert result.stderr.count("Poll failed") == 4
    assert result.stdout.count('"generated_at"') == 2


def test_watch_ctrl_c_after_a_failed_last_poll_reports_the_failure_exit_code(
    monkeypatch: pytest.MonkeyPatch, cli_env: dict[str, str]
) -> None:
    """Ctrl-C right after a (tolerated) failed poll exits with the DB code.

    A stale successful report's ``exit_code()`` (0, since no report was
    ever produced here) must not paper over the fact that the last poll
    failed.
    """

    def fake_run_once(ctx: object, options: object, client: object) -> StatusReport:
        raise DbIntegrityError("still broken")

    monkeypatch.setattr(status_cli, "_run_once", fake_run_once)

    def fake_sleep(_seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(time, "sleep", fake_sleep)

    result = CliRunner().invoke(
        cli, ["status", "--watch", "--interval", "1"], env=cli_env, catch_exceptions=False
    )

    assert result.exit_code == int(ExitCode.DB)
    assert result.stderr.rstrip().endswith("Stopped.")


def test_watch_ctrl_c_after_a_good_poll_exits_with_that_reports_code(
    monkeypatch: pytest.MonkeyPatch, cli_env: dict[str, str]
) -> None:
    """--fail-on-offline still applies when a watch is stopped after a successful poll."""
    offline = StatusReport(
        generated_at=datetime.now(UTC),
        nodes=(MergedNode(node_id=NodeId.from_hex("a0000001"), availability=Availability.OFFLINE),),
        thresholds=Thresholds(),
    )
    expected = offline.exit_code(fail_on_offline=True)
    assert expected != 0
    monkeypatch.setattr(status_cli, "_run_once", lambda *_args: offline)

    def fake_sleep(_seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(time, "sleep", fake_sleep)

    result = CliRunner().invoke(
        cli,
        ["status", "--watch", "--interval", "1", "--json", "--fail-on-offline"],
        env=cli_env,
        catch_exceptions=False,
    )

    assert result.exit_code == expected


def test_watch_ctrl_c_after_a_poll_with_an_unseen_database_node_exits_seven(
    monkeypatch: pytest.MonkeyPatch, cli_env: dict[str, str]
) -> None:
    node = MergedNode(node_id=NodeId.from_hex("a0000001"), record=NodeRecord(node_id="a0000001"))
    unseen = StatusReport(
        generated_at=datetime.now(UTC),
        nodes=(node,),
        thresholds=Thresholds(),
    )
    monkeypatch.setattr(status_cli, "_run_once", lambda *_args: unseen)

    def fake_sleep(_seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(time, "sleep", fake_sleep)

    def run(*flags: str) -> int:
        args = ["status", "--watch", "--interval", "1", "--json", *flags]
        return CliRunner().invoke(cli, args, env=cli_env, catch_exceptions=False).exit_code

    assert run() == int(ExitCode.STATUS_DEGRADED)
    assert run("--no-fail-on-offline") == 0


def test_single_shot_status_stays_strict_on_a_db_error(
    monkeypatch: pytest.MonkeyPatch, cli_env: dict[str, str]
) -> None:
    """Without ``--watch``, a ``DbError`` still propagates and exits immediately.

    Guards against loosening the non-watch path while adding the
    ``--watch`` tolerance: it must call ``_run_once`` exactly once and
    exit strictly, unaffected by the new retry/tolerance logic.
    """
    calls = {"n": 0}

    def fake_run_once(ctx: object, options: object, client: object) -> StatusReport:
        calls["n"] += 1
        raise DbIntegrityError("broken")

    monkeypatch.setattr(status_cli, "_run_once", fake_run_once)

    result = CliRunner().invoke(cli, ["status"], env=cli_env, catch_exceptions=False)

    assert result.exit_code == int(ExitCode.DB)
    assert calls["n"] == 1
    assert "broken" in result.stderr
    assert "Poll failed" not in result.stderr


def _record_force_refresh(
    monkeypatch: pytest.MonkeyPatch, *, fail_first: bool = False, polls: int = 3
) -> list[bool]:
    """Patch ``_run_once``/``time.sleep``; return each poll's ``options.force_refresh``."""
    seen: list[bool] = []

    def fake_run_once(ctx: object, options: StatusOptions, client: object) -> StatusReport:
        seen.append(options.force_refresh)
        if fail_first and len(seen) == 1:
            raise DbIntegrityError("transient failure")
        return _ok_report()

    def fake_sleep(_seconds: float) -> None:
        if len(seen) >= polls:
            raise KeyboardInterrupt

    monkeypatch.setattr(status_cli, "_run_once", fake_run_once)
    monkeypatch.setattr(time, "sleep", fake_sleep)
    return seen


def test_watch_no_cache_bypasses_the_cache_on_the_first_poll_only(
    monkeypatch: pytest.MonkeyPatch, cli_env: dict[str, str]
) -> None:
    seen = _record_force_refresh(monkeypatch)

    result = CliRunner().invoke(
        cli, ["--no-cache", "status", "--watch", "--interval", "1", "--json"], env=cli_env
    )

    assert result.exit_code == 0, result.output
    assert seen == [True, False, False]


def test_watch_no_cache_still_applies_to_the_retry_of_a_failed_first_poll(
    monkeypatch: pytest.MonkeyPatch, cli_env: dict[str, str]
) -> None:
    seen = _record_force_refresh(monkeypatch, fail_first=True)

    result = CliRunner().invoke(
        cli, ["--no-cache", "status", "--watch", "--interval", "1", "--json"], env=cli_env
    )

    assert result.exit_code == 0, result.output
    assert seen == [True, True, False]


def test_watch_without_no_cache_never_bypasses_the_cache(
    monkeypatch: pytest.MonkeyPatch, cli_env: dict[str, str]
) -> None:
    seen = _record_force_refresh(monkeypatch)

    result = CliRunner().invoke(
        cli, ["status", "--watch", "--interval", "1", "--json"], env=cli_env
    )

    assert result.exit_code == 0, result.output
    assert seen == [False, False, False]
