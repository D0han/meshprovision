"""Every backticked ``mesh ...`` command in ``src/`` names a real command and real flags.

Hints and messages tell the operator what to run next, so a stale one
(an option that was renamed, or never existed) turns the recovery step
itself into a usage error. This walks every string literal in ``src/``
-- f-strings included, with each ``{...}`` hole read as a placeholder --
and checks each single-backticked ``mesh ...`` span against the live
click command tree. Double-backticked rST spans in docstrings are left
alone.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path

import click
import pytest

from meshprovision.cli.main import cli

pytestmark = pytest.mark.unit

SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "meshprovision"

_SPAN_RE = re.compile(r"(?<!`)`(mesh(?: [^`]*)?)`(?!`)")


def _string_literals(tree: ast.AST) -> Iterator[tuple[int, str]]:
    """Yield ``(lineno, text)`` for every str constant and f-string in ``tree``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.lineno, node.value
        elif isinstance(node, ast.JoinedStr):
            yield (
                node.lineno,
                "".join(
                    part.value if isinstance(part, ast.Constant) else "X" for part in node.values
                ),
            )


def _value_count(param: click.Parameter) -> int:
    """How many following tokens ``param`` consumes as its value (0 for a flag)."""
    if not isinstance(param, click.Option) or param.is_flag or param.count:
        return 0
    return param.nargs


def _problems(span: str) -> list[str]:
    """Check one ``mesh ...`` span against the click tree.

    Args:
        span: The span's text, starting with ``mesh``.

    Returns:
        One description per unknown subcommand or option; empty if the
        span is valid. Tokens after the last subcommand that are not
        options are arguments and are not checked.
    """
    command: click.Command = cli
    options: dict[str, click.Parameter] = {}
    tokens = span.split()[1:]
    index = 0
    while index < len(tokens):
        token = tokens[index]
        index += 1
        options.update({o: p for p in command.params for o in p.opts + p.secondary_opts})
        if token.startswith("-"):
            name, has_value, _ = token.partition("=")
            param = options.get(name)
            if param is None and name != "--help":
                return [f"{name} is not an option of `{command.name}`"]
            if param is not None and not has_value:
                index += _value_count(param)
        elif isinstance(command, click.Group):
            sub = command.commands.get(token)
            if sub is None:
                return [f"{token!r} is not a subcommand of `{command.name}`"]
            command = sub
    return []


def test_every_backticked_mesh_command_in_src_exists() -> None:
    problems = [
        f"{path.relative_to(SRC_ROOT)}:{lineno}: `{match.group(1)}`: {problem}"
        for path in sorted(SRC_ROOT.rglob("*.py"))
        for lineno, text in _string_literals(ast.parse(path.read_text(encoding="utf-8")))
        for match in _SPAN_RE.finditer(text)
        for problem in _problems(match.group(1))
    ]
    assert problems == []


def test_command_checker_handles_option_values_and_rejects_unknowns() -> None:
    # A value-taking option's value is not mistaken for a subcommand.
    assert _problems("mesh --db-path X db restore --known-good") == []
    assert _problems("mesh --env-file <FILE> status") == []
    assert _problems("mesh --db-path=X db verify") == []
    # A count option (-v) and a flag take no value: the next token is a subcommand.
    assert _problems("mesh -v status --json") == []
    assert _problems("mesh --non-interactive adopt --show-admin-keys") == []
    # Arguments after the last subcommand are not checked.
    assert _problems("mesh admin import <NAME>=<BASE64>") == []
    assert _problems("mesh db restore --help") == []
    # Unknown options and subcommands are caught.
    assert _problems("mesh admin import --ref <NAME>") == ["--ref is not an option of `import`"]
    assert _problems("mesh db restor") == ["'restor' is not a subcommand of `db`"]
    assert _problems("mesh -v X status") == ["'X' is not a subcommand of `mesh`"]
