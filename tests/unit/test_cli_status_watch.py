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
from meshprovision.errors import DbIntegrityError, ExitCode
from meshprovision.status.merge import Thresholds
from meshprovision.status.report import StatusReport

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
