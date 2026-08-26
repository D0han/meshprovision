"""The read-only guard: `mesh status` structurally cannot write the database."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SRC = Path(__file__).resolve().parents[2] / "src" / "meshprovision"

# cli/status.py bans the *names* outright (its module docstring, lines 3-11).
_CLI_STATUS_FORBIDDEN = frozenset(
    {
        "OdsDatabase",
        "NodeRepository",
        "KeyRepository",
        "atomic_writer",
        "open_database",
        "meshprovision.provisioning.apply",
        "meshprovision.provisioning.repair",
    }
)

# status/report.py may hold those types; it bans the write *operations*
# (its module docstring, lines 10-20).
_REPORT_FORBIDDEN_ATTRS = frozenset({"save", "replace", "upsert", "delete"})
_REPORT_FORBIDDEN_MODULES = (
    "meshprovision.db.atomic_writer",
    "meshprovision.provisioning.apply",
    "meshprovision.provisioning.repair",
)


def _source_without_docstring(path: Path) -> str:
    """Return a module's code with its own docstring and comments stripped.

    Both guarded modules *name* every forbidden token inside their own
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


def test_cli_status_never_names_a_write_capable_symbol() -> None:
    code = _source_without_docstring(SRC / "cli" / "status.py")
    found = sorted(name for name in _CLI_STATUS_FORBIDDEN if name in code)
    assert found == [], f"cli/status.py must not reference: {found}"


def test_status_report_never_calls_a_write_operation() -> None:
    tree = ast.parse((SRC / "status" / "report.py").read_text(encoding="utf-8"))
    offenders = sorted(
        {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and node.attr in _REPORT_FORBIDDEN_ATTRS
        }
    )
    assert offenders == [], f"status/report.py must not call: {offenders}"


def test_status_report_never_imports_a_write_capable_module() -> None:
    tree = ast.parse((SRC / "status" / "report.py").read_text(encoding="utf-8"))
    offenders = sorted(
        {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module is not None
            and node.module.startswith(_REPORT_FORBIDDEN_MODULES)
        }
    )
    assert offenders == [], f"status/report.py must not import: {offenders}"
