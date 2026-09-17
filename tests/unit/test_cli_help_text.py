"""Tests for the operator-facing ``--help`` rendering in ``meshprovision.cli.common``.

Covers :func:`clean_help_text` in isolation, :class:`MeshCommand`/
:class:`MeshGroup` wiring, and a standing regression guard that walks
every registered ``mesh`` command and asserts none of them leaks a
Google-style docstring section or raw rST markup into ``--help``.
"""

from __future__ import annotations

import click
import pytest

from meshprovision.cli.common import (
    CONTEXT_SETTINGS,
    HELP_REQUESTED_KEY,
    MeshCommand,
    MeshGroup,
    clean_help_text,
    help_requested,
)

pytestmark = pytest.mark.unit


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

    def test_every_registered_command_is_a_mesh_command(self) -> None:
        from meshprovision.cli.main import cli

        ctx = click.Context(cli)
        assert isinstance(cli, MeshGroup)
        for name, cmd in self._iter_commands(cli, ctx):
            assert isinstance(cmd, MeshCommand), f"{name} was not built via MeshCommand/MeshGroup"
