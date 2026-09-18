"""Tests for the ``-v``/``--verbose`` flag: level resolution and library staging."""

from __future__ import annotations

import io
import logging
from collections.abc import Iterator

import pytest
import structlog

from meshprovision.cli.common import configure_logging, resolve_log_level

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _restore_logging() -> Iterator[None]:
    """Undo each test's ``configure_logging`` call so it never leaks.

    Mirrors the equivalent fixture in ``test_cli_common.py`` and
    ``test_redact.py``: ``configure_logging`` strips every root handler
    by design, so a test that calls it would otherwise leave its own
    ``StringIO`` handler attached to the root logger for the rest of the
    session.
    """
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    yield
    for existing in list(root.handlers):
        root.removeHandler(existing)
    for handler in saved_handlers:
        root.addHandler(handler)
    root.setLevel(saved_level)
    structlog.reset_defaults()


class TestResolveLogLevel:
    def test_explicit_log_level_always_wins(self) -> None:
        """An explicit --log-level beats any -v count, in either direction."""
        assert resolve_log_level("warning", 0) == "warning"
        assert resolve_log_level("warning", 3) == "warning"
        assert resolve_log_level("error", 1) == "error"

    def test_no_log_level_and_no_verbose_returns_none(self) -> None:
        """Neither given: caller's env/.env/default layers must still decide."""
        assert resolve_log_level(None, 0) is None

    @pytest.mark.parametrize("verbose", [1, 2, 3])
    def test_any_verbose_count_implies_debug_absent_explicit_level(self, verbose: int) -> None:
        assert resolve_log_level(None, verbose) == "DEBUG"


class TestStageThirdPartyLoggers:
    """Regression coverage for the ``max(numeric_level, WARNING)`` bug.

    The old code could only ever make ``meshtastic``/``httpx`` *quieter*
    than WARNING (a quieter explicit ``--log-level``), never louder --
    so ``--log-level debug`` alone could never surface their own
    progress logging. ``-vv``/``-vvv`` must be able to do what
    ``--log-level`` alone never could.
    """

    def test_default_verbosity_matches_pre_verbose_behavior(self) -> None:
        """verbosity=0 must reproduce the exact levels the old code set."""
        configure_logging("DEBUG", stream=io.StringIO(), colors=False)

        assert logging.getLogger("httpcore").level == logging.WARNING
        assert logging.getLogger("bleak").level == logging.WARNING
        assert logging.getLogger("urllib3").level == logging.WARNING
        assert logging.getLogger("httpx").level == logging.WARNING
        assert logging.getLogger("meshtastic").level == logging.WARNING
        assert logging.getLogger().level == logging.DEBUG

    def test_default_verbosity_still_tracks_a_quieter_explicit_level(self) -> None:
        """A quieter --log-level still quiets meshtastic/httpx further, as before."""
        configure_logging("ERROR", stream=io.StringIO(), colors=False)

        assert logging.getLogger("httpx").level == logging.ERROR
        assert logging.getLogger("meshtastic").level == logging.ERROR
        assert logging.getLogger("httpcore").level == logging.WARNING

    def test_single_v_does_not_unmute_any_library(self) -> None:
        """-v alone (verbosity=1) only raises this project's own loggers."""
        configure_logging("DEBUG", stream=io.StringIO(), colors=False, verbosity=1)

        assert logging.getLogger("meshtastic").level == logging.WARNING
        assert logging.getLogger("bleak").level == logging.WARNING

    def test_double_v_unmutes_meshtastic_and_httpx_only(self) -> None:
        """-vv releases stage 0 to inherit the root (DEBUG) level."""
        configure_logging("DEBUG", stream=io.StringIO(), colors=False, verbosity=2)

        assert logging.getLogger("meshtastic").getEffectiveLevel() == logging.DEBUG
        assert logging.getLogger("httpx").getEffectiveLevel() == logging.DEBUG
        assert logging.getLogger("bleak").level == logging.WARNING
        assert logging.getLogger("httpcore").level == logging.WARNING
        assert logging.getLogger("urllib3").level == logging.WARNING

    def test_triple_v_unmutes_every_staged_library(self) -> None:
        """-vvv releases both stages."""
        configure_logging("DEBUG", stream=io.StringIO(), colors=False, verbosity=3)

        for name in ("meshtastic", "httpx", "bleak", "httpcore", "urllib3"):
            assert logging.getLogger(name).getEffectiveLevel() == logging.DEBUG

    def test_explicit_log_level_still_caps_released_loggers(self) -> None:
        """--log-level warning -vvv still means WARNING, not DEBUG."""
        configure_logging("WARNING", stream=io.StringIO(), colors=False, verbosity=3)

        assert logging.getLogger("bleak").getEffectiveLevel() == logging.WARNING
        assert logging.getLogger("meshtastic").getEffectiveLevel() == logging.WARNING
