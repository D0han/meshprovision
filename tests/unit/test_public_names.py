"""A name another module imports from a ``meshprovision`` module is in that module's ``__all__``."""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "meshprovision"


def _imported_names() -> dict[str, set[str]]:
    """Map each ``meshprovision`` module to the public names other src modules import from it."""
    found: dict[str, set[str]] = {}
    for path in sorted(SRC_ROOT.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
                "meshprovision."
            ):
                names = {alias.name for alias in node.names if not alias.name.startswith("_")}
                found.setdefault(str(node.module), set()).update(names)
    return found


def test_every_name_imported_across_modules_is_exported() -> None:
    missing = []
    for module_name, names in sorted(_imported_names().items()):
        module = importlib.import_module(module_name)
        exported = getattr(module, "__all__", None)
        if exported is None:
            continue
        missing.extend(
            f"{module_name}.{name}"
            for name in sorted(names - set(exported))
            # ``from meshprovision.network import render`` names a submodule.
            if not isinstance(getattr(module, name, None), type(importlib))
        )
    assert missing == []
