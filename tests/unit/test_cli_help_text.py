"""Tests for the operator-facing ``--help`` rendering in ``meshprovision.cli.help_format``.

Covers :func:`clean_help_text` in isolation, :class:`MeshCommand`/
:class:`MeshGroup` wiring, and a standing regression guard that walks
every registered ``mesh`` command and asserts none of them leaks a
Google-style docstring section, raw rST markup or an internal identifier
into ``--help``.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Final

import click
import pytest

import meshprovision
from meshprovision.cli.common import CONTEXT_SETTINGS
from meshprovision.cli.help_format import (
    HELP_REQUESTED_KEY,
    MeshCommand,
    MeshGroup,
    clean_help_text,
    help_requested,
)

pytestmark = pytest.mark.unit

_INTERNAL_NAMES: Final[frozenset[str]] = frozenset(
    node.name
    for path in Path(meshprovision.__file__).parent.rglob("*.py")
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
    and "_" in node.name.strip("_")
)
"""Every function and class name in the package with an underscore (``create_backup``): code,
never ``--help`` text. Names without one (``KeyRecord``) are too often plain words to check."""


def _leaked_names(text: str) -> list[str]:
    """The tokens of ``text`` that name code: an internal name, ``meshprovision.``, a ``.py`` file.

    A token is a dotted path (``backups.create_backup``), so a name that ends a sentence
    (``create_backup.``) is found too.
    """
    return [
        token
        for token in re.findall(r"\w+(?:\.\w+)*", text)
        if token.startswith("meshprovision.")
        or token.endswith(".py")
        or _INTERNAL_NAMES.intersection(token.split("."))
    ]


class TestCleanHelpText:
    def test_returns_none_for_none(self) -> None:
        assert clean_help_text(None) is None

    def test_is_a_no_op_on_prose_with_no_sections(self) -> None:
        doc = "Do the thing.\n\nA second paragraph of prose."
        assert clean_help_text(doc) == doc

    @pytest.mark.parametrize(
        "header",
        [
            "Args:",
            "Arguments:",
            "Attributes:",
            "Example:",
            "Examples:",
            "Note:",
            "Notes:",
            "Raises:",
            "Returns:",
            "See Also:",
            "Todo:",
            "Warning:",
            "Warnings:",
            "Warns:",
            "Yields:",
        ],
    )
    def test_truncates_at_the_first_section_header(self, header: str) -> None:
        doc = f"Summary line.\n\n{header}\n    detail: something a developer needs.\n"
        assert clean_help_text(doc) == "Summary line."

    def test_keeps_a_section_like_sentence_with_text_after_the_colon(self) -> None:
        doc = "Summary line.\n\nNote: this runs fast.\n"
        assert clean_help_text(doc) == "Summary line.\n\nNote: this runs fast."

    def test_preserves_a_paragraph_break_before_the_cut(self) -> None:
        doc = "First paragraph.\n\nSecond paragraph.\n\nArgs:\n    x: unused.\n"
        assert clean_help_text(doc) == "First paragraph.\n\nSecond paragraph."

    def test_shortens_a_role_target_to_its_last_segment(self) -> None:
        doc = "See :class:`~meshprovision.cli.common.CliContext` for details."
        assert clean_help_text(doc) == "See CliContext for details."

    def test_shortens_a_role_target_wrapped_across_lines(self) -> None:
        # The exact shape click sees from a real docstring after
        # inspect.cleandoc: the role's backtick-quoted target broken
        # across two source lines by the 100-column wrap.
        doc = "ctx.obj is set to the shared :class:`~meshprovision.cli.common.\nCliContext`."
        assert clean_help_text(doc) == "ctx.obj is set to the shared CliContext."

    def test_keeps_a_module_role_fully_dotted(self) -> None:
        doc = "See :mod:`meshprovision.db.locking` for the write-lock protocol."
        assert clean_help_text(doc) == "See meshprovision.db.locking for the write-lock protocol."

    def test_unwraps_an_inline_literal(self) -> None:
        doc = "Pass ``--strict`` to fail on warnings."
        assert clean_help_text(doc) == "Pass --strict to fail on warnings."

    def test_unwraps_a_multi_line_inline_literal(self) -> None:
        doc = "Pass ``--dry-run\n--yes``."
        assert clean_help_text(doc) == "Pass --dry-run --yes."

    def test_is_idempotent(self) -> None:
        doc = "Summary.\n\nSee :class:`~a.b.C` and ``--flag``.\n\nArgs:\n    x: y.\n"
        once = clean_help_text(doc)
        assert clean_help_text(once) == once


class TestMeshCommand:
    def test_cleans_help_at_construction_time(self) -> None:
        @click.command(cls=MeshCommand)
        def cmd() -> None:
            """Summary.

            Args:
                nothing: unused.
            """

        assert cmd.help == "Summary."

    def test_leaves_a_one_line_docstring_unchanged(self) -> None:
        @click.command(cls=MeshCommand)
        def cmd() -> None:
            """Just one line."""

        assert cmd.help == "Just one line."

    def test_handles_a_command_with_no_docstring(self) -> None:
        @click.command(cls=MeshCommand)
        def cmd() -> None:
            pass

        assert cmd.help is None


class TestMeshGroup:
    def test_group_command_decorator_yields_mesh_command(self) -> None:
        @click.group(cls=MeshGroup)
        def grp() -> None:
            """Group."""

        @grp.command()
        def sub() -> None:
            """Sub."""

        assert isinstance(grp.get_command(click.Context(grp), "sub"), MeshCommand)

    def test_group_group_decorator_yields_mesh_group(self) -> None:
        @click.group(cls=MeshGroup)
        def grp() -> None:
            """Group."""

        @grp.group()
        def subgrp() -> None:
            """Subgroup."""

        assert isinstance(grp.get_command(click.Context(grp), "subgrp"), MeshGroup)

    def test_nested_subcommand_help_is_also_cleaned(self) -> None:
        @click.group(cls=MeshGroup)
        def grp() -> None:
            """Group."""

        @grp.command()
        def sub() -> None:
            """Sub summary.

            Raises:
                ValueError: never.
            """

        assert sub.help == "Sub summary."

    def test_records_help_requested_when_help_flag_is_present(self) -> None:
        @click.group(cls=MeshGroup, context_settings=CONTEXT_SETTINGS)
        def grp() -> None:
            """Group."""

        @grp.command()
        def sub() -> None:
            """Sub."""

        ctx = grp.make_context("grp", ["sub", "--help"], resilient_parsing=True)
        assert ctx.meta.get(HELP_REQUESTED_KEY) is True
        assert help_requested(ctx) is True

    def test_does_not_record_help_requested_for_an_ordinary_invocation(self) -> None:
        @click.group(cls=MeshGroup, context_settings=CONTEXT_SETTINGS)
        def grp() -> None:
            """Group."""

        @grp.command()
        def sub() -> None:
            """Sub."""

        ctx = grp.make_context("grp", ["sub"], resilient_parsing=True)
        assert HELP_REQUESTED_KEY not in ctx.meta
        assert help_requested(ctx) is False


class TestRealCommandSurface:
    """Regression guard: no registered ``mesh`` command may leak sections or rST."""

    @staticmethod
    def _iter_commands(group: click.Group, ctx: click.Context) -> list[tuple[str, click.Command]]:
        found: list[tuple[str, click.Command]] = []
        for name in group.list_commands(ctx):
            cmd = group.get_command(ctx, name)
            assert cmd is not None
            found.append((name, cmd))
            if isinstance(cmd, click.Group):
                found.extend(TestRealCommandSurface._iter_commands(cmd, ctx))
        return found

    def test_no_command_help_leaks_a_docstring_section_or_rst_markup(self) -> None:
        from meshprovision.cli.main import cli

        ctx = click.Context(cli)
        forbidden = ("Args:", "Arguments:", "Raises:", "Returns:", "Yields:", ":class:", "``")
        for name, cmd in [("mesh", cli), *self._iter_commands(cli, ctx)]:
            if cmd.help is None:
                continue
            for marker in forbidden:
                assert marker not in cmd.help, f"{name} --help still contains {marker!r}"

    def test_no_command_help_names_a_module_or_an_internal_function(self) -> None:
        """Maintainer notes (``see refresh_known_good``) belong under a ``Note:`` section."""
        from meshprovision.cli.main import cli

        ctx = click.Context(cli)
        for name, cmd in [("mesh", cli), *self._iter_commands(cli, ctx)]:
            texts = [cmd.help or "", *(getattr(param, "help", None) or "" for param in cmd.params)]
            leaked = sorted({word for text in texts for word in _leaked_names(text)})
            assert leaked == [], f"{name} --help names {leaked}"

    @pytest.mark.parametrize(
        "text",
        [
            "Uses create_backup.",
            "See create_backup.",
            "See backups.create_backup here.",
            "See meshprovision.db.backups here.",
            "See ``db/backups.py`` here.",
        ],
    )
    def test_the_identifier_guard_flags_a_name_at_the_end_of_a_sentence_or_in_a_path(
        self, text: str
    ) -> None:
        assert _leaked_names(text) != []

    def test_the_identifier_guard_leaves_plain_prose_alone(self) -> None:
        assert _leaked_names("Back up the database, e.g. data/nodes_db.ods.") == []

    def test_every_registered_command_is_a_mesh_command(self) -> None:
        from meshprovision.cli.main import cli

        ctx = click.Context(cli)
        assert isinstance(cli, MeshGroup)
        for name, cmd in self._iter_commands(cli, ctx):
            assert isinstance(cmd, MeshCommand), f"{name} was not built via MeshCommand/MeshGroup"


def test_the_wheel_smoke_step_asks_every_command_for_its_help() -> None:
    from meshprovision.cli.main import cli

    workflow = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
    if not workflow.exists():
        pytest.skip("ci.yml is not part of the sdist")
    text = workflow.read_text(encoding="utf-8")

    missing = sorted(name for name in cli.commands if f"/bin/mesh {name} --help" not in text)
    assert missing == []
