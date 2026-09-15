"""The read-only guard: `mesh template validate` structurally cannot touch a database or device."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SRC = Path(__file__).resolve().parents[2] / "src" / "meshprovision"

# cli/template_cmd.py bans the *names* outright (its module docstring
# already explains why: template validation must work with no database
# or device involved at all, unlike mesh db verify's degraded-not-absent
# template cross-check).
_CLI_TEMPLATE_FORBIDDEN = frozenset(
    {
        "OdsDatabase",
        "NodeRepository",
        "KeyRepository",
        "atomic_writer",
        "open_database",
        "apply_plan",
        "ReconnectingSession",
        "InPlaceSession",
        "device_session",
        "writeConfig",
    }
)


def _source_without_docstring(path: Path) -> str:
    """Return a module's code with its own docstring and comments stripped.

    The guarded module *names* every forbidden token inside its own
    module docstring, so a naive text search matches the very rule it is
    checking. Round-tripping through :mod:`ast` removes the docstring and
    all comments, leaving only executable code.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    if (
        tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
    ):
        del tree.body[0]
    return ast.unparse(tree)


def test_cli_template_never_names_a_db_or_device_write_symbol() -> None:
    code = _source_without_docstring(SRC / "cli" / "template_cmd.py")
    found = sorted(name for name in _CLI_TEMPLATE_FORBIDDEN if name in code)
    assert found == [], f"cli/template_cmd.py must not reference: {found}"
