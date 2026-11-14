"""The write-free certification of ``meshprovision.remote``.

No module in it can talk to a device, send a packet, plan or apply a change, read a file
or the clock, or reach names dynamically; and no other module uses it yet. Like
``test_import_contracts.py``, it checks each module's *own* import statements and names,
walked with ``ast.walk`` over the whole tree (function bodies and ``TYPE_CHECKING`` blocks
included), not what they import transitively: ``provisioning/plan_types.py`` imports
``detect``, and that is allowed. The positive allow-list is each module's
``STDLIB_ONLY``/``STDLIB_PLUS`` row in ``test_import_contracts.py``; this file adds a
block-list of what must never appear even among the standard library, and refuses a module
that has no contract row.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path
from types import ModuleType
from typing import Final

import pytest

from tests.unit.test_import_contracts import PACKAGE, STDLIB_ONLY, STDLIB_PLUS

pytestmark = pytest.mark.unit

REMOTE: Final[Path] = PACKAGE / "remote"

_REMOTE_MODULES: Final[frozenset[str]] = frozenset(
    {
        "__init__.py",
        "budget.py",
        "diff.py",
        "firmware.py",
        "ledger.py",
        "plan.py",
        "plan_types.py",
        "refused.py",
        "render.py",
    }
)
"""Every module ``remote/`` may hold; a new one must be certified here first."""

_FORBIDDEN_IDENTIFIERS: Final[frozenset[str]] = frozenset(
    {
        # device and library write/send paths
        "writeConfig",
        "writeChannel",
        "setOwner",
        "setFixedPosition",
        "removeFixedPosition",
        "setURL",
        "beginSettingsTransaction",
        "commitSettingsTransaction",
        "sendData",
        "sendText",
        "sendPacket",
        "_sendPacket",
        "_sendAdmin",
        "sendAdmin",
        "requestConfig",
        "waitForAckNak",
        "getNode",
        "localNode",
        "reboot",
        "shutdown",
        "factoryReset",
        "resetNodeDb",
        "removeNode",
        "setFavorite",
        "MeshInterface",
        "SerialInterface",
        "TCPInterface",
        "BLEInterface",
        # AdminMessage set/transaction variants as identifiers (strings in refused.py are data)
        "set_config",
        "set_module_config",
        "set_owner",
        "set_channel",
        "set_fixed_position",
        "begin_edit_settings",
        "commit_edit_settings",
        # project paths that read the wrong node or plan/apply a change
        "read_live_config",
        "build_plan",
        "apply_plan",
        "write_section",
        "verify_plan",
    }
)

_FORBIDDEN_CALLS: Final[frozenset[str]] = frozenset(
    {
        "open",
        "print",
        "input",
        "eval",
        "exec",
        "__import__",
        "compile",
        "breakpoint",
        "getattr",
        "setattr",
        "delattr",
        "globals",
        "locals",
        "vars",
    }
)
"""Builtins a remote module never calls: I/O, and every way to reach a name dynamically."""

_FORBIDDEN_ATTRIBUTES: Final[frozenset[str]] = frozenset(
    {"__dict__", "__builtins__", "__import__", "modules"}
)

_FORBIDDEN_IMPORTS: Final[tuple[str, ...]] = (
    "meshprovision",
    "meshtastic",
    "serial",
    "bleak",
    "pubsub",
    "httpx",
    "socket",
    "subprocess",
    "pathlib",
    "os",
    "io",
    "time",
    "datetime",
    "threading",
    "asyncio",
    "urllib",
    "http",
    "sys",
    "builtins",
    "importlib",
    "ctypes",
    "operator",
    "logging",
    "random",
)
"""Matched exactly or as a dotted parent (``os`` bans ``os`` and ``os.path``, not
``ossaudiodev``), *unless* the name is allowed by the module's ``STDLIB_PLUS`` row: that row
is the one exception mechanism, so ``meshprovision.provisioning.plan_types`` is importable
by ``remote/diff.py`` only, and every other ``meshprovision`` module by none."""

_ALLOWED_STDLIB: Final[tuple[str, ...]] = (
    "__future__",
    "collections.abc",
    "dataclasses",
    "enum",
    "fractions",
    "math",
    "types",
    "typing",
)
"""The only standard-library modules a remote module may import."""

_ALLOWED_DUNDER_ATTRIBUTES: Final[frozenset[str]] = frozenset({"__getitem__"})

_MODULES = sorted(_REMOTE_MODULES)


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imported(tree: ast.AST) -> list[str]:
    """Every dotted name the imports bring in; ``from m import n`` gives ``m`` and ``m.n``."""
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, f"relative import at line {node.lineno}"
            module = node.module or ""
            names.extend([module, *(f"{module}.{alias.name}" for alias in node.names)])
    return names


def _matches(name: str, prefix: str) -> bool:
    return name == prefix or name.startswith(prefix + ".")


def _allowed_prefixes(module: str) -> tuple[str, ...]:
    for relpath, allowed in STDLIB_PLUS:
        if relpath == f"remote/{module}":
            return allowed
    return ()


def _identifiers(tree: ast.AST) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            found.add(node.id)
        elif isinstance(node, ast.Attribute):
            found.add(node.attr)
        elif isinstance(node, ast.alias):
            found.update({node.name, node.name.rsplit(".", 1)[-1]})
            if node.asname:
                found.add(node.asname)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            found.add(node.name)
        elif isinstance(node, ast.arg):
            found.add(node.arg)
    return found


def test_the_remote_package_has_exactly_these_modules() -> None:
    assert {path.name for path in REMOTE.glob("*.py")} == _REMOTE_MODULES
    assert [p for p in REMOTE.rglob("*.py") if p.parent != REMOTE] == []


def test_every_remote_module_has_an_import_contract_row() -> None:
    plus = {relpath for relpath, _ in STDLIB_PLUS}
    for module in _MODULES:
        row = f"remote/{module}"
        assert row in STDLIB_ONLY or row in plus, row


@pytest.mark.parametrize("module", _MODULES)
def test_no_remote_module_names_a_device_write_send_or_plan_api(module: str) -> None:
    assert _identifiers(_tree(REMOTE / module)) & _FORBIDDEN_IDENTIFIERS == set()


@pytest.mark.parametrize("module", _MODULES)
def test_no_remote_module_imports_io_a_device_or_a_write_path(module: str) -> None:
    allowed = _allowed_prefixes(module)
    offending = [
        name
        for name in _imported(_tree(REMOTE / module))
        if not any(_matches(name, prefix) for prefix in allowed)
        and (
            any(_matches(name, banned) for banned in _FORBIDDEN_IMPORTS)
            or not any(_matches(name, ok) for ok in _ALLOWED_STDLIB)
        )
    ]
    assert offending == []


@pytest.mark.parametrize("module", _MODULES)
def test_no_remote_module_does_io_or_reaches_names_dynamically(module: str) -> None:
    calls: list[str] = []
    attributes: list[str] = []
    for node in ast.walk(_tree(REMOTE / module)):
        if isinstance(node, ast.Name) and node.id in _FORBIDDEN_CALLS | {"__builtins__"}:
            calls.append(node.id)
        if isinstance(node, ast.Attribute) and (
            node.attr in _FORBIDDEN_ATTRIBUTES
            or (
                node.attr.startswith("__")
                and node.attr.endswith("__")
                and node.attr not in _ALLOWED_DUNDER_ATTRIBUTES
            )
        ):
            attributes.append(node.attr)
    assert (calls, attributes) == ([], [])


def test_nothing_outside_remote_imports_it() -> None:
    """``mesh`` has no remote command, and ``build_plan`` can never be handed remote data.

    This must be relaxed deliberately when a ``cli/remote.py`` is added. It checks import
    statements only, so a dynamic import elsewhere in ``src`` is not caught; inside
    ``remote/`` the standard-library allow-list above rules that out.
    """
    offending = [
        f"{path.relative_to(PACKAGE).as_posix()}: {name}"
        for path in PACKAGE.rglob("*.py")
        if REMOTE not in path.parents
        for name in _imported(_tree(path))
        if _matches(name, "meshprovision.remote")
    ]
    assert offending == []


@pytest.mark.parametrize("module", _MODULES)
def test_no_remote_module_reaches_a_module_through_an_allowed_leaf(module: str) -> None:
    """``from <allowed leaf> import x`` must bring in a name, never a module it re-exports."""
    reached = [
        f"{node.module}.{alias.name}"
        for node in ast.walk(_tree(REMOTE / module))
        if isinstance(node, ast.ImportFrom) and _matches(node.module or "", "meshprovision")
        for alias in node.names
        if isinstance(getattr(importlib.import_module(node.module or ""), alias.name), ModuleType)
    ]
    assert reached == []
