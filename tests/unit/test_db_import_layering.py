"""The import-layering guard: ``db/`` does not depend on ``provisioning`` or ``config``.

Added alongside G1 (the ``provisioning.observed_keys`` -> ``db.observed_keys`` move and
the ``config.template`` admin-ref helper deletion): with those changes, no module in
``db/`` imports from ``provisioning`` at all, and only ``db/nodes.py`` still imports from
``config.template`` (its own name-pattern validation, left for a later batch to resolve).
Only a top-level ``from`` import counts -- one nested under ``if TYPE_CHECKING:`` never
executes and creates no runtime coupling, which is why ``db/verify.py`` may still name
``TemplateConfig`` there for a type hint without tripping this guard.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

DB_DIR = Path(__file__).resolve().parents[2] / "src" / "meshprovision" / "db"

_CONFIG_TEMPLATE_EXEMPT = frozenset({"nodes.py"})


def _forbidden_imports(path: Path) -> list[str]:
    """Return every forbidden upward import this ``db/`` module makes at runtime.

    Args:
        path: A module under ``src/meshprovision/db/``.

    Returns:
        One message per top-level ``from`` import of ``meshprovision.provisioning``
        (any submodule) or exactly ``meshprovision.config.template`` -- empty for a
        compliant module, and for ``db/nodes.py``'s one intentional
        ``config.template`` exception. A top-level statement excludes anything
        nested under ``if TYPE_CHECKING:``, which never executes.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    problems: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom) or node.module is None:
            continue
        is_config_template = node.module == "meshprovision.config.template"
        exempt = is_config_template and path.name in _CONFIG_TEMPLATE_EXEMPT
        is_provisioning = node.module.startswith("meshprovision.provisioning")
        if not exempt and (is_provisioning or is_config_template):
            problems.append(f"{path.name}:{node.lineno}: imports {node.module!r}")
    return problems


def test_db_modules_do_not_import_provisioning_or_config_template() -> None:
    problems: list[str] = []
    for path in sorted(DB_DIR.glob("*.py")):
        problems.extend(_forbidden_imports(path))
    assert problems == [], "Upward import(s) found in db/:\n" + "\n".join(problems)
