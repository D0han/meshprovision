"""The read-only guard: `mesh status` structurally cannot write the database."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.unit.conftest import source_without_docstring

pytestmark = pytest.mark.unit

SRC = Path(__file__).resolve().parents[2] / "src" / "meshprovision"

# cli/status.py bans the *names* outright (its module docstring, lines 3-11).
# Its module imports (``meshprovision.provisioning.apply`` and the rest,
# however spelled) are banned by its row in test_import_contracts.py.
_CLI_STATUS_FORBIDDEN = frozenset(
    {
        "OdsDatabase",
        "NodeRepository",
        "KeyRepository",
        "atomic_writer",
        "backups",
        "fs_primitives",
        "known_good",
        "pending_keys",
        "open_database",
        "ods_write",
        "write_database",
    }
)

# status/report.py may hold those types; it bans the write *operations*
# (its module docstring, lines 10-20).
_REPORT_FORBIDDEN_ATTRS = frozenset({"save", "replace", "upsert", "delete"})
_REPORT_FORBIDDEN_MODULES = (
    "meshprovision.db.atomic_writer",
    "meshprovision.db.backups",
    "meshprovision.db.fs_primitives",
    "meshprovision.db.known_good",
    "meshprovision.db.ods_write",
    "meshprovision.db.pending_keys",
    "meshprovision.provisioning.apply",
    "meshprovision.provisioning.persist",
    "meshprovision.provisioning.repair",
)


def test_cli_status_never_names_a_write_capable_symbol() -> None:
    code = source_without_docstring(SRC / "cli" / "status.py")
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
    """Also catches ``from meshprovision.db import ods_write`` (module import).

    ``node.module`` alone is ``"meshprovision.db"`` for that form -- it
    never mentions ``ods_write`` -- so a plain ``.startswith`` check on
    ``node.module`` would silently pass it. Each imported name is
    resolved to its own dotted path (``node.module`` + ``.`` + the
    name) and checked too, matching the module-qualified-import style
    this project actually uses for cross-module access.
    """
    tree = ast.parse((SRC / "status" / "report.py").read_text(encoding="utf-8"))
    offenders: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.module is None:
            continue
        if node.module.startswith(_REPORT_FORBIDDEN_MODULES):
            offenders.add(node.module)
        for alias in node.names:
            full_name = f"{node.module}.{alias.name}"
            if full_name.startswith(_REPORT_FORBIDDEN_MODULES):
                offenders.add(full_name)
    assert sorted(offenders) == [], f"status/report.py must not import: {sorted(offenders)}"
