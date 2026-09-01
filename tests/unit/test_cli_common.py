"""Tests for meshprovision.cli.common."""

from __future__ import annotations

import io
from collections.abc import Callable
from pathlib import Path

import pytest
from rich.console import Console

from meshprovision.cli.common import CliContext
from meshprovision.config.settings import Settings

pytestmark = pytest.mark.unit


def _context(template_path: Path, buf: io.StringIO) -> CliContext:
    """Build a context whose stderr console writes into ``buf``.

    Args:
        template_path: The template the context should load.
        buf: The buffer the stderr console writes to.

    Returns:
        A :class:`CliContext` with capturable consoles.
    """
    return CliContext(
        settings=Settings(template_path=template_path),
        non_interactive=True,
        force_refresh=False,
        assume_yes=False,
        out=Console(file=io.StringIO()),
        err=Console(file=buf, no_color=True, width=200),
    )


def test_load_template_warns_through_the_styled_path(
    write_template: Callable[..., Path],
) -> None:
    """A template warning reaches stderr via ``warn``, not just structlog."""
    path = write_template(enabled_options=["not_a_real_module_option"])
    buf = io.StringIO()
    ctx = _context(path, buf)

    ctx.load_template()

    assert "warning: " in buf.getvalue()
    assert "not_a_real_module_option" in buf.getvalue()


def test_load_template_is_quiet_for_a_clean_template(
    write_template: Callable[..., Path],
) -> None:
    """An unmodified example template prints nothing to stderr."""
    buf = io.StringIO()
    ctx = _context(write_template(), buf)

    ctx.load_template()

    assert buf.getvalue() == ""
