"""``mesh`` commands named in hints, with the global options of this invocation.

A hint such as "Run `mesh db restore --known-good`" is meant to be copied
and run. When the failing invocation picked its files with ``--db-path``,
``--template-path`` or ``--env-file``, the bare command would act on the
default files instead (restoring the wrong database), so every command a
hint names gets the same options, as given on the command line. Values
from the environment or ``.env`` carry over by themselves and are not
repeated.

This module imports only click and the standard library.
"""

from __future__ import annotations

import re
import shlex
from typing import Final

import click
from click.core import ParameterSource

__all__ = [
    "invocation_globals",
    "mesh_command",
    "with_invocation_globals",
]

_FILE_OPTIONS: Final[tuple[tuple[str, str], ...]] = (
    ("env_file", "--env-file"),
    ("db_path", "--db-path"),
    ("template_path", "--template-path"),
)
"""The root ``mesh`` options that choose a file, by parameter name, in usage order."""

_NAMED_COMMAND_RE: Final[re.Pattern[str]] = re.compile(r"(?:(?<=`)|(?<=Run: ))mesh (?=[a-z])")
"""Where a hint names a ``mesh`` subcommand: in backticks, or after "Run: "."""


def invocation_globals() -> str:
    """Return the file-choosing global options given on this command line.

    Returns:
        For example ``"--db-path ex.ods"``, shell-quoted, in usage order;
        ``""`` outside a ``mesh`` invocation or when none was given.
    """
    current = click.get_current_context(silent=True)
    if current is None:
        return ""
    root = current.find_root()
    parts = []
    for name, flag in _FILE_OPTIONS:
        value = root.params.get(name)
        if value is not None and root.get_parameter_source(name) is ParameterSource.COMMANDLINE:
            parts.append(f"{flag} {shlex.quote(str(value))}")
    return " ".join(parts)


def mesh_command(arguments: str) -> str:
    """Spell a ``mesh`` command line with this invocation's file options.

    Args:
        arguments: The subcommand and its own arguments, for example
            ``"db verify"``.

    Returns:
        For example ``"mesh --db-path ex.ods db verify"``.
    """
    options = invocation_globals()
    return f"mesh {options} {arguments}" if options else f"mesh {arguments}"


def with_invocation_globals(text: str) -> str:
    """Add this invocation's file options to every ``mesh`` command ``text`` names.

    Args:
        text: A message or hint.

    Returns:
        ``text`` with ``mesh <subcommand>`` turned into ``mesh <options>
        <subcommand>`` wherever it is quoted in backticks or follows
        "Run: ", or unchanged when no file option was given.
    """
    options = invocation_globals()
    if not options:
        return text
    return _NAMED_COMMAND_RE.sub(f"mesh {options} ", text)
