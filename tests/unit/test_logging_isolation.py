"""Leak canary for :func:`tests.conftest.preserved_logging_state`."""

from __future__ import annotations

import logging

import pytest
import structlog
from click.testing import CliRunner

from meshprovision.cli.logging_setup import _LIBRARY_STAGES
from meshprovision.cli.main import cli
from tests.conftest import preserved_logging_state

pytestmark = pytest.mark.unit


def _logging_state() -> tuple[object, ...]:
    root = logging.getLogger()
    return (
        tuple(h for h in root.handlers if not type(h).__module__.startswith("_pytest.")),
        root.level,
        tuple(logging.getLogger(name).level for stage in _LIBRARY_STAGES for name in stage),
        structlog.is_configured(),
        repr(structlog.get_config()),
    )


def test_a_cli_invocation_leaves_no_logging_state_behind(cli_env: dict[str, str]) -> None:
    """If ``configure_logging`` starts touching new global state, extend the guard."""
    before = _logging_state()

    with preserved_logging_state():
        result = CliRunner().invoke(cli, ["-vv", "--log-level", "debug", "db", "list"], env=cli_env)
        during = _logging_state()

    assert result.exit_code == 4, result.output  # no database yet; logging was set up first
    assert during != before  # the CLI really did reconfigure logging
    assert _logging_state() == before
