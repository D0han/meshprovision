"""Tests for meshprovision.cli.init_cmd's non-interactive orchestration.

Genuinely interactive flows (a real confirm/prompt exchange) are covered
at the e2e layer via ``click.testing.CliRunner``'s ``input=`` -- see
``tests/e2e/test_e2e_init.py`` and ``tests/e2e/test_e2e_first_run_wizard.py``.
Everything here uses ``assume_yes=True`` (bypasses every confirm) or
``non_interactive=True`` (turns a would-be prompt into an error), which
is this codebase's established way to exercise prompting code without
a real stdin.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from rich.console import Console

from meshprovision.cli.common import CliContext
from meshprovision.cli.init_cmd import run_setup
from meshprovision.cli.setup import inspect_setup
from meshprovision.config.settings import Settings
from meshprovision.errors import NonInteractiveError

pytestmark = pytest.mark.unit


def _context(tmp_path: Path, *, assume_yes: bool, non_interactive: bool) -> CliContext:
    """Build a :class:`CliContext` rooted at ``tmp_path``, capturable consoles.

    Args:
        tmp_path: The directory ``db_path``/``template_path`` resolve
            under.
        assume_yes: Whether every ``confirm`` should short-circuit True.
        non_interactive: Whether a prompt should raise instead.

    Returns:
        A new :class:`CliContext`.
    """
    settings = Settings(
        db_path=tmp_path / "data" / "nodes_db.ods",
        template_path=tmp_path / "config" / "template.yaml",
    )
    return CliContext(
        settings=settings,
        non_interactive=non_interactive,
        force_refresh=False,
        assume_yes=assume_yes,
        out=Console(file=io.StringIO()),
        err=Console(file=io.StringIO(), no_color=True, width=200),
    )


def test_creates_all_three_artifacts_with_a_supplied_contact(tmp_path: Path) -> None:
    ctx = _context(tmp_path, assume_yes=True, non_interactive=False)
    status = inspect_setup(ctx.settings, env_file=tmp_path / ".env", cwd=tmp_path)

    outcome = run_setup(ctx, status, contact="ops@example.org")

    assert outcome.changed is True
    assert len(outcome.created) == 3
    assert outcome.declined == ()
    assert outcome.contact == "ops@example.org"
    assert (tmp_path / ".env").is_file()
    assert (tmp_path / "config" / "template.yaml").is_file()
    assert (tmp_path / "data" / "nodes_db.ods").is_file()


def test_skips_artifacts_that_already_exist(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "template.yaml").write_text("version: 1\n", encoding="utf-8")
    ctx = _context(tmp_path, assume_yes=True, non_interactive=False)
    status = inspect_setup(ctx.settings, env_file=tmp_path / ".env", cwd=tmp_path)

    outcome = run_setup(ctx, status, contact="ops@example.org")

    assert tmp_path / "config" / "template.yaml" not in outcome.created
    assert tmp_path / "config" / "template.yaml" in outcome.present
    assert (tmp_path / "config" / "template.yaml").read_text(encoding="utf-8") == "version: 1\n"


def test_returns_immediately_when_nothing_is_missing(tmp_path: Path) -> None:
    ctx = _context(tmp_path, assume_yes=True, non_interactive=False)
    complete_settings = ctx.settings.with_overrides(contact="ops@example.org")
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "template.yaml").write_text("version: 1\n", encoding="utf-8")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "nodes_db.ods").write_bytes(b"x")
    status = inspect_setup(complete_settings, env_file=tmp_path / ".env", cwd=tmp_path)
    assert status.complete

    outcome = run_setup(ctx, status)

    assert outcome.changed is False
    assert outcome.created == ()
    assert len(outcome.present) == 3


def test_raises_non_interactive_when_the_contact_must_be_prompted_for(tmp_path: Path) -> None:
    ctx = _context(tmp_path, assume_yes=True, non_interactive=True)
    status = inspect_setup(ctx.settings, env_file=tmp_path / ".env", cwd=tmp_path)

    with pytest.raises(NonInteractiveError):
        run_setup(ctx, status)

    assert not (tmp_path / ".env").exists()


def test_reports_the_next_steps_on_stderr(tmp_path: Path) -> None:
    ctx = _context(tmp_path, assume_yes=True, non_interactive=False)
    status = inspect_setup(ctx.settings, env_file=tmp_path / ".env", cwd=tmp_path)

    run_setup(ctx, status, contact="ops@example.org")

    assert isinstance(ctx.err.file, io.StringIO)
    output = ctx.err.file.getvalue()
    assert "Next steps:" in output
    assert "mesh db verify" in output


def test_reports_no_next_steps_when_nothing_was_created(tmp_path: Path) -> None:
    ctx = _context(tmp_path, assume_yes=True, non_interactive=False)
    complete_settings = ctx.settings.with_overrides(contact="ops@example.org")
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "template.yaml").write_text("version: 1\n", encoding="utf-8")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "nodes_db.ods").write_bytes(b"x")
    status = inspect_setup(complete_settings, env_file=tmp_path / ".env", cwd=tmp_path)

    run_setup(ctx, status)

    assert isinstance(ctx.err.file, io.StringIO)
    assert "Next steps:" not in ctx.err.file.getvalue()
