"""The documented import contracts: each "imports nothing from X" module docstring, enforced.

Several modules promise in their docstring what they never import -- ``errors.py``
is a leaf, the ``plan`` modules never import :mod:`meshprovision.crypto`, the CLI's
shared layers never import a command module, and so on. Nothing checked those
promises; this module does, by parsing each module's source.

Contracts are about a module's *own* import statements, not what it reaches
transitively: ``provisioning/plan.py`` imports ``detect.py``, which loads
``crypto.redact``, and that is fine -- what ``plan.py`` promises is that it never
imports :mod:`meshprovision.crypto` itself. Unless a row says otherwise, every
import statement counts wherever it appears -- module level, inside a function,
or under ``if TYPE_CHECKING:`` -- since the docstrings make no exception for any
of them. ``db/`` has its own layering guard in ``test_db_import_layering.py``.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Final

import pytest

import meshprovision

pytestmark = pytest.mark.unit

PACKAGE: Final[Path] = Path(meshprovision.__file__).resolve().parent
"""The installed ``meshprovision`` package directory (independent of the cwd)."""

_PURE_PLAN_FORBIDDEN: Final[tuple[str, ...]] = (
    "meshtastic",
    "httpx",
    "pathlib",
    "odf",
    "meshprovision.crypto",
)
"""``provisioning/plan.py``'s purity contract, shared by the modules split out of it."""

CLI_COMMAND_MODULES: Final[frozenset[str]] = frozenset(
    {"admin", "adopt", "db_cmd", "init_cmd", "main", "provision", "status", "template_cmd"}
)
"""``cli/`` modules that define (or, for ``main``, assemble) ``mesh`` commands."""

CLI_HELPER_MODULES: Final[frozenset[str]] = frozenset(
    {
        "__init__",
        "adopt_backup",
        "common",
        "help_format",
        "logging_setup",
        "progress",
        "provision_keys",
        "setup",
        "transport",
    }
)
"""``cli/`` modules shared by, or split out of, the command modules; never a command."""

_CLI_COMMANDS: Final[tuple[str, ...]] = tuple(
    sorted(f"meshprovision.cli.{name}" for name in CLI_COMMAND_MODULES)
)

FORBIDDEN_IMPORTS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("errors.py", ("meshprovision",)),
    ("provisioning/plan.py", _PURE_PLAN_FORBIDDEN),
    ("provisioning/plan_types.py", _PURE_PLAN_FORBIDDEN),
    ("provisioning/plan_admin_keys.py", _PURE_PLAN_FORBIDDEN),
    ("provisioning/discovery.py", ("meshtastic", "meshprovision.provisioning.connection")),
    ("config/settings.py", ("meshprovision.config.template",)),
    ("cli/help_format.py", ("meshprovision",)),
    ("cli/logging_setup.py", ("meshprovision.cli",)),
    ("cli/adopt_backup.py", _CLI_COMMANDS),
    ("cli/common.py", _CLI_COMMANDS),
    ("cli/provision_keys.py", _CLI_COMMANDS),
    (
        "status/merge.py",
        (
            "meshtastic",
            "httpx",
            "pathlib",
            "meshprovision.db.nodes",
            "meshprovision.db.ods",
            "meshprovision.cache",
        ),
    ),
    ("db/verify.py", ("meshprovision.cli",)),
    (
        "provisioning/persist.py",
        (
            "meshtastic",
            "meshprovision.provisioning.connection",
            "meshprovision.provisioning.detect",
            "meshprovision.cli",
        ),
    ),
)
"""``(module path under the package, forbidden import prefixes)``, from each docstring."""

STDLIB_ONLY: Final[tuple[str, ...]] = (
    "firmware.py",
    "provisioning/plan_warnings.py",
    "termsafe.py",
    "status/timefmt.py",
)
"""Modules documented as importing nothing but the standard library."""

STDLIB_PLUS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("name_pattern.py", ("meshprovision.errors",)),
    ("crypto/redact.py", ("meshprovision.termsafe",)),
)
"""``(module, allowed meshprovision prefixes)`` for leaves documented as importing
only the standard library plus those modules."""

NO_IMPORT_TIME_IMPORTS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("enums.py", ("meshtastic",)),
)
"""``(module, prefixes)`` that may be imported lazily, inside a function, but never
while the module itself is being imported."""


def _imported_names(node: ast.Import | ast.ImportFrom, path: Path) -> list[str]:
    """Return every dotted name one import statement imports.

    ``from a.b import c`` yields both ``a.b`` and ``a.b.c``, so a forbidden prefix
    matches ``from meshprovision import crypto`` as well as ``import
    meshprovision.crypto``.

    Args:
        node: The import statement.
        path: The module it appears in, for the failure message.

    Returns:
        The imported module (and, for ``from`` imports, ``module.name``) names.
    """
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    assert node.level == 0, f"{path}:{node.lineno}: relative import"
    module = node.module or ""
    return [module, *(f"{module}.{alias.name}" for alias in node.names)]


def _imports(path: Path, *, import_time_only: bool = False) -> list[tuple[int, str]]:
    """Collect ``(line, dotted name)`` for every import statement in a module.

    Args:
        path: The module to parse.
        import_time_only: Skip anything inside a function or lambda body, which
            only runs when called, not while the module is being imported.

    Returns:
        Every imported name, with the line of its statement.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[tuple[int, str]] = []
    pending: list[ast.AST] = [tree]
    while pending:
        node = pending.pop()
        if import_time_only and isinstance(
            node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda
        ):
            continue
        if isinstance(node, ast.Import | ast.ImportFrom):
            found.extend((node.lineno, name) for name in _imported_names(node, path))
        pending.extend(ast.iter_child_nodes(node))
    return sorted(found)


def _matches(name: str, prefixes: tuple[str, ...]) -> bool:
    return any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes)


@pytest.mark.parametrize(
    ("relpath", "forbidden"), FORBIDDEN_IMPORTS, ids=[row[0] for row in FORBIDDEN_IMPORTS]
)
def test_module_never_imports_what_its_docstring_rules_out(
    relpath: str, forbidden: tuple[str, ...]
) -> None:
    offending = [
        f"{relpath}:{line}: {name}"
        for line, name in _imports(PACKAGE / relpath)
        if _matches(name, forbidden)
    ]
    assert offending == []


@pytest.mark.parametrize("relpath", STDLIB_ONLY)
def test_module_imports_only_the_standard_library(relpath: str) -> None:
    offending = [
        f"{relpath}:{line}: {name}"
        for line, name in _imports(PACKAGE / relpath)
        if name.split(".", 1)[0] not in sys.stdlib_module_names
    ]
    assert offending == []


@pytest.mark.parametrize(("relpath", "allowed"), STDLIB_PLUS, ids=[row[0] for row in STDLIB_PLUS])
def test_module_imports_only_the_standard_library_plus_its_documented_leaves(
    relpath: str, allowed: tuple[str, ...]
) -> None:
    offending = [
        f"{relpath}:{line}: {name}"
        for line, name in _imports(PACKAGE / relpath)
        if name.split(".", 1)[0] not in sys.stdlib_module_names and not _matches(name, allowed)
    ]
    assert offending == []


@pytest.mark.parametrize(
    ("relpath", "forbidden"),
    NO_IMPORT_TIME_IMPORTS,
    ids=[row[0] for row in NO_IMPORT_TIME_IMPORTS],
)
def test_module_defers_these_imports_until_first_use(
    relpath: str, forbidden: tuple[str, ...]
) -> None:
    offending = [
        f"{relpath}:{line}: {name}"
        for line, name in _imports(PACKAGE / relpath, import_time_only=True)
        if _matches(name, forbidden)
    ]
    assert offending == []


def test_every_cli_module_is_classified_as_a_command_or_a_helper() -> None:
    """A new ``cli/`` module must be placed deliberately, so ``cli/common.py``'s row stays right."""
    found = {path.stem for path in (PACKAGE / "cli").glob("*.py")}
    assert CLI_COMMAND_MODULES.isdisjoint(CLI_HELPER_MODULES)
    assert found == CLI_COMMAND_MODULES | CLI_HELPER_MODULES
