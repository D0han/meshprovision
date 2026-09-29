"""``--help`` text customization for every ``mesh`` subcommand.

Click renders a command's raw docstring verbatim as ``--help`` text, which
turns every ``Args:``/``Raises:`` developer section -- plus any Sphinx
cross-reference roles and inline literals inside it -- into confusing
run-on prose. :func:`clean_help_text` trims that down to operator-facing
prose, wired in automatically via :class:`MeshCommand`/:class:`MeshGroup`.

This module also tracks whether a ``-h``/``--help`` flag appeared anywhere
in an invocation (:data:`HELP_REQUESTED_KEY`, :func:`help_requested`) --
``cli.main`` uses this to skip the first-run setup offer on a help-only
run, even one several subcommand levels deep.

This module imports nothing from :mod:`meshprovision.cli.common`,
:mod:`meshprovision.cli.main`, or any command module -- only downward,
from click and the standard library.
"""

from __future__ import annotations

import inspect
import re
from typing import TYPE_CHECKING, Any, Final

import click

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "HELP_REQUESTED_KEY",
    "MeshCommand",
    "MeshGroup",
    "clean_help_text",
    "help_requested",
]

HELP_REQUESTED_KEY: Final[str] = "meshprovision.cli.help_requested"
"""``click.Context.meta`` key set by :class:`MeshGroup` when any ``-h``/
``--help`` flag appears anywhere in the invocation -- checked by
``cli.main`` to skip the first-run setup offer on a help-only run, even
one several subcommand levels deep (``mesh db verify --help`` runs the
``mesh`` and ``db`` group callbacks before ``verify``'s own ``--help``
handling ever gets a chance to exit)."""

_GOOGLE_SECTIONS: Final[tuple[str, ...]] = (
    "Args",
    "Arguments",
    "Attributes",
    "Example",
    "Examples",
    "Note",
    "Notes",
    "Raises",
    "Returns",
    "See Also",
    "Todo",
    "Warning",
    "Warnings",
    "Warns",
    "Yields",
)
"""Google-style docstring section headers :func:`clean_help_text` truncates at."""

_SECTION_RE: Final[re.Pattern[str]] = re.compile(
    rf"^(?:{'|'.join(_GOOGLE_SECTIONS)}):[ \t]*$", re.MULTILINE
)
"""Matches a *whole line* that is exactly one Google section header.

Anchored so a sentence like ``"Note: this is slow."`` -- prose, not a
section -- is never mistaken for a truncation point.
"""

_ROLE_RE: Final[re.Pattern[str]] = re.compile(
    r":(?:py:)?(?P<role>[a-zA-Z]+):`(?P<target>[^`]+)`", re.DOTALL
)
"""Matches a Sphinx cross-reference role, e.g. ``:class:`~a.b.C``` --
including one whose target wraps across multiple docstring lines."""

_LITERAL_RE: Final[re.Pattern[str]] = re.compile(r"``(?P<body>[^`]+)``", re.DOTALL)
"""Matches an rST inline literal, e.g. ``` ``--strict`` ```."""

_FULL_PATH_ROLES: Final[frozenset[str]] = frozenset({"mod"})
"""Roles whose target stays fully dotted (a module path is only useful whole)."""


def _shorten_role(match: re.Match[str]) -> str:
    """Reduce a Sphinx role match to its bare, readable target.

    Args:
        match: A match of :data:`_ROLE_RE`.

    Returns:
        The role's target with a leading ``~`` and internal line-wrap
        whitespace stripped, collapsed to its last dotted segment --
        unless the role is in :data:`_FULL_PATH_ROLES`, which keeps the
        full dotted path.
    """
    role = match.group("role")
    target = "".join(match.group("target").split()).lstrip("~")
    if role in _FULL_PATH_ROLES:
        return target
    return target.rsplit(".", maxsplit=1)[-1]


def _flatten_literal(match: re.Match[str]) -> str:
    """Collapse a (possibly line-wrapped) inline literal's body to one line.

    Args:
        match: A match of :data:`_LITERAL_RE`.

    Returns:
        The literal's body with internal whitespace collapsed.
    """
    return " ".join(match.group("body").split())


def clean_help_text(docstring: str | None) -> str | None:
    """Trim a Google-style docstring down to its operator-facing prose.

    Click renders a command's raw docstring verbatim as ``--help`` text,
    which turns every ``Args:``/``Raises:`` developer section -- plus
    any Sphinx cross-reference roles and inline literals inside it --
    into confusing run-on prose. This cuts the docstring at the first
    such section header and de-rSTs what remains, leaving paragraph
    breaks intact.

    Args:
        docstring: The raw docstring, or ``None``.

    Returns:
        ``None`` if ``docstring`` is ``None``; otherwise the cleaned,
        operator-facing text.
    """
    if docstring is None:
        return None
    text = inspect.cleandoc(docstring)
    section = _SECTION_RE.search(text)
    if section is not None:
        text = text[: section.start()].rstrip()
    text = _ROLE_RE.sub(_shorten_role, text)
    text = _LITERAL_RE.sub(_flatten_literal, text)
    return text.replace("`", "").strip()


def _mentions_help(args: Sequence[str], help_option_names: Sequence[str]) -> bool:
    """Return whether any token in ``args`` is exactly a help flag.

    A quoted option *value* that happens to equal ``--help`` is
    misdetected as a help request too -- harmless here, since the only
    effect is suppressing the first-run setup offer for that one run.

    Args:
        args: The raw, unparsed argument tokens.
        help_option_names: The configured help flag spellings, e.g.
            ``["-h", "--help"]``.

    Returns:
        ``True`` if any token in ``args`` exactly matches a help flag.
    """
    return any(arg in help_option_names for arg in args)


def help_requested(ctx: click.Context) -> bool:
    """Report whether this invocation asked for help anywhere in its args.

    Args:
        ctx: Any click context belonging to the current invocation --
            :attr:`click.Context.meta` is shared by the whole context
            chain, so a child context sees what :class:`MeshGroup` set
            on the root.

    Returns:
        ``True`` if :class:`MeshGroup` recorded a help flag while
        parsing this invocation's arguments.
    """
    return bool(ctx.meta.get(HELP_REQUESTED_KEY, False))


class MeshCommand(click.Command):
    """A :class:`click.Command` whose ``--help`` text is operator-facing.

    Runs the raw docstring through :func:`clean_help_text` once, at
    construction time -- covering both ``format_help_text`` and
    ``get_short_help_str``, which both read ``self.help`` directly, with
    a single change. ``Command.__doc__`` (used by Sphinx/pydoc, and set
    separately by click's ``@command`` decorator) is left untouched, so
    the full developer docstring is still available to tooling that
    reads it directly.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Construct the command, then clean :attr:`help` in place.

        Args:
            *args: Forwarded to :class:`click.Command`.
            **kwargs: Forwarded to :class:`click.Command`.
        """
        super().__init__(*args, **kwargs)
        if self.help is not None:
            self.help = clean_help_text(self.help)


class MeshGroup(MeshCommand, click.Group):
    """A :class:`click.Group` that mints :class:`MeshCommand`/:class:`MeshGroup`.

    Setting ``command_class``/``group_class`` here means every
    ``@group.command()``/``@group.group()`` registered under a
    ``MeshGroup`` gets the cleaned-help behavior automatically, with no
    ``cls=`` at the subcommand site -- only the handful of top-level
    ``@click.group``/``@click.command`` decorators need it explicitly.
    """

    command_class = MeshCommand
    group_class = type  # click's sentinel: "reuse this group's own class"

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        """Record a help-only invocation in ``ctx.meta`` before parsing.

        A root ``MeshGroup`` sees the *full* remaining argument list
        here, before any subcommand's own eager ``--help`` handling has
        had a chance to run -- ``Group.invoke`` runs every ancestor
        group's callback before recursing into the next level (verified
        against installed click 8.4.2), so by the time ``mesh db
        verify --help`` would reach ``verify``'s own help handling, both
        the ``mesh`` and ``db`` callbacks have already executed. Setting
        :data:`HELP_REQUESTED_KEY` here, first, is what lets
        ``cli.main`` skip the first-run setup offer for that run.

        Args:
            ctx: This group's freshly built context.
            args: The raw arguments remaining for this group to parse.

        Returns:
            Whatever :meth:`click.Group.parse_args` returns.
        """
        if _mentions_help(args, ctx.help_option_names):
            ctx.meta[HELP_REQUESTED_KEY] = True
        return super().parse_args(ctx, args)
