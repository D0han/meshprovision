"""The read-only guard: ``mesh remote`` names no device, transport or write API.

Walks ``cli/remote.py`` with ``ast`` (identifiers, not text), as the certification of
``meshprovision.remote`` does, so a docstring that names a banned word is not a finding and
an aliased or attribute use is.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

import pytest

from tests.unit.test_remote_write_free import (
    _ALLOWED_DUNDER_ATTRIBUTES,
    _FORBIDDEN_ATTRIBUTES,
    _FORBIDDEN_CALLS,
    _FORBIDDEN_IDENTIFIERS,
    _identifiers,
    _imported,
    _matches,
    _tree,
)

pytestmark = pytest.mark.unit

CLI_REMOTE: Final[Path] = (
    Path(__file__).resolve().parents[2] / "src" / "meshprovision" / "cli" / "remote.py"
)

_CLI_FORBIDDEN: Final[frozenset[str]] = _FORBIDDEN_IDENTIFIERS | {
    "transport_options",
    "connected_with_progress",
    "resolve_backend",
    "select_backend",
    "close_interface",
    "http_client",
    "for_write",
    "must_exist",
    "save",
    "upsert",
    "delete",
    "replace",
    "update",
    "lock",
    "write_json",
    "atomic_writer",
    "getattr",
}
"""Everything the remote modules may not name, plus the ways to reach a device, an HTTP
client or a database write from a command."""


_ALLOWED_IMPORTS: Final[tuple[str, ...]] = (
    "__future__",
    "collections.abc",
    "time",
    "typing",
    "click",
    "meshprovision.cli.common",
    "meshprovision.cli.help_format",
    "meshprovision.db.schema",
    "meshprovision.errors",
    "meshprovision.health.store",
    "meshprovision.remote.plan",
    "meshprovision.remote.plan_types",
    "meshprovision.remote.render",
    # TYPE_CHECKING only
    "meshprovision.config.template",
    "meshprovision.db.nodes",
    "meshprovision.health.history",
    "meshprovision.nodeid",
)
"""Exactly what ``cli/remote.py`` imports: an allow-list, so ``os``, ``sys``, ``importlib``,
``builtins``, ``socket`` and every other module fail by being absent, not by being named."""


def _calls(name: str) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(_tree(CLI_REMOTE))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == name
    ]


def test_the_cli_names_no_device_transport_or_write_api() -> None:
    assert _identifiers(_tree(CLI_REMOTE)) & _CLI_FORBIDDEN == set()


def test_open_database_is_called_read_only() -> None:
    calls = _calls("open_database")

    assert len(calls) == 1
    assert calls[0].args == []
    assert calls[0].keywords == []


def test_the_history_is_only_loaded() -> None:
    attributes = [
        node.attr
        for node in ast.walk(_tree(CLI_REMOTE))
        if isinstance(node, ast.Attribute) and node.attr == "load"
    ]

    assert attributes == ["load"]


def test_dry_run_is_checked_before_anything_is_read() -> None:
    function = next(
        node
        for node in ast.walk(_tree(CLI_REMOTE))
        if isinstance(node, ast.FunctionDef) and node.name == "diff"
    )

    first = function.body[1]  # body[0] is the docstring

    assert isinstance(first, ast.If)
    assert isinstance(first.test, ast.UnaryOp)
    assert isinstance(first.test.op, ast.Not)
    assert isinstance(first.test.operand, ast.Name)
    assert first.test.operand.id == "dry_run"
    assert len(first.body) == 1
    assert isinstance(first.body[0], ast.Raise)


def _keyword_names(tree: ast.AST) -> set[str]:
    return {
        keyword.arg
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        for keyword in node.keywords
        if keyword.arg is not None
    }


def test_the_cli_names_no_keyword_that_selects_a_write_or_a_lock() -> None:
    """``f(for_write=True)`` through an alias shows only the keyword, not the callee."""
    assert _keyword_names(_tree(CLI_REMOTE)) & _CLI_FORBIDDEN == set()


def test_the_cli_unpacks_no_arguments() -> None:
    """``f(**{"for_" + "write": True})`` reaches a keyword by a computed name."""
    unpacked = [
        node
        for node in ast.walk(_tree(CLI_REMOTE))
        if isinstance(node, ast.Call)
        and (
            any(keyword.arg is None for keyword in node.keywords)
            or any(isinstance(arg, ast.Starred) for arg in node.args)
        )
    ]
    assert unpacked == []


def test_the_cli_imports_only_what_it_uses_today() -> None:
    offending = [
        name
        for name in _imported(_tree(CLI_REMOTE))
        if not any(_matches(name, allowed) for allowed in _ALLOWED_IMPORTS)
    ]
    assert offending == []


def test_the_cli_does_io_or_reaches_names_dynamically_nowhere() -> None:
    """The builtins that open, import or look names up, and the dunders that reach them."""
    names: list[str] = []
    for node in ast.walk(_tree(CLI_REMOTE)):
        if isinstance(node, ast.Name) and node.id in _FORBIDDEN_CALLS | {"__builtins__"}:
            names.append(node.id)
        if isinstance(node, ast.Attribute) and (
            node.attr in _FORBIDDEN_ATTRIBUTES
            or (
                node.attr.startswith("__")
                and node.attr.endswith("__")
                and node.attr not in _ALLOWED_DUNDER_ATTRIBUTES
            )
        ):
            names.append(node.attr)
    assert names == []


def test_open_database_is_referenced_once() -> None:
    """An alias (``_o = ctx.open_database``) is a reference, not a call, so count references."""
    references = [
        node
        for node in ast.walk(_tree(CLI_REMOTE))
        if (isinstance(node, ast.Attribute) and node.attr == "open_database")
        or (isinstance(node, ast.Name) and node.id == "open_database")
    ]
    assert len(references) == 1
