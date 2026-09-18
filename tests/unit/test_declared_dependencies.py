"""The required CI guard: every import in ``src/`` is a declared dependency.

``pyproject.toml`` is the single source of truth for what this package needs
installed. A ``src/`` import that only works because some *other* declared
dependency happens to pull it in transitively (as ``meshtastic`` does for
``PyYAML``, ``protobuf``, and ``pyserial``) is a packaging hole: if the
transitive dependency is ever dropped or re-scoped, the import breaks and
``mypy --strict`` starts failing with ``import-untyped``/``import-not-found``
again, exactly as it did before ``PyYAML``/``protobuf`` were declared
directly. This test fails locally the moment a new such hole opens, instead
of surfacing only in CI.

An import wrapped in ``try: ... except ImportError`` anywhere in ``src/`` is
treated as optional and excluded from the requirement -- this is how
``bleak`` (``provisioning/discovery.py``) is handled: BLE support is meant to
degrade gracefully, per the ``ble`` extra's own comment in
``pyproject.toml``, even though ``meshtastic`` currently installs it
unconditionally.
"""

from __future__ import annotations

import ast
import re
import sys
import tomllib
from importlib.metadata import packages_distributions
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"

_STDLIB = sys.stdlib_module_names | frozenset(sys.builtin_module_names)
_INTERNAL_PACKAGE = "meshprovision"

# Runtime dependency -> its mypy-only stub package. Each pair must have its
# runtime half in [project.dependencies] and its stub half in the `dev`
# extra: PyYAML and protobuf ship no `py.typed` marker, so `mypy --strict`
# needs a stub for each (config/template.py, provisioning/backup.py,
# provisioning/apply.py, provisioning/detect.py). pyserial needs no stub
# here because [[tool.mypy.overrides]] already sets ignore_missing_imports
# for `serial.*`.
_STUB_PAIRS = {
    "pyyaml": "types-pyyaml",
    "protobuf": "types-protobuf",
}

_SPEC_SPLIT_RE = re.compile(r"[\[<>=!~; ]")


def _normalize(name: str) -> str:
    """Normalize a distribution name PEP 503 style for comparison.

    Args:
        name: A distribution or requirement name.

    Returns:
        The lowercased name with runs of ``-_.`` collapsed to a single ``-``.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def _bare_name(requirement: str) -> str:
    """Return the normalized bare distribution name from a PEP 508 requirement.

    Args:
        requirement: A raw entry from ``pyproject.toml``, e.g. ``"PyYAML>=6.0.1,<7"``.

    Returns:
        The requirement's name with no version specifier, extras, or marker.
    """
    match = _SPEC_SPLIT_RE.search(requirement)
    name = requirement[: match.start()] if match else requirement
    return _normalize(name)


def _load_pyproject() -> dict[str, object]:
    """Return the parsed contents of the repository's ``pyproject.toml``."""
    with (REPO_ROOT / "pyproject.toml").open("rb") as fh:
        return tomllib.load(fh)


def declared_dependency_names() -> frozenset[str]:
    """Return the normalized names declared in ``[project.dependencies]``."""
    project = _load_pyproject()["project"]
    return frozenset(_bare_name(r) for r in project["dependencies"])  # type: ignore[index]


def declared_dev_names() -> frozenset[str]:
    """Return the normalized names declared in the ``dev`` optional extra."""
    project = _load_pyproject()["project"]
    dev = project["optional-dependencies"]["dev"]  # type: ignore[index]
    return frozenset(_bare_name(r) for r in dev)


def _handles_import_error(handler: ast.ExceptHandler) -> bool:
    """Return whether an ``except`` clause catches ``ImportError``.

    Args:
        handler: One ``except`` clause of a ``try`` statement.

    Returns:
        True if ``handler`` names ``ImportError``, bare or in a tuple.
    """
    node = handler.type
    if node is None:
        return False
    candidates = node.elts if isinstance(node, ast.Tuple) else [node]
    return any(isinstance(n, ast.Name) and n.id == "ImportError" for n in candidates)


def _guarded_import_ids(tree: ast.Module) -> set[int]:
    """Return the ``id()`` of every import statement guarded by ``except ImportError``.

    Args:
        tree: A parsed module.

    Returns:
        Identity-set of ``Import``/``ImportFrom`` nodes inside the body of a
        ``try`` block whose handlers catch ``ImportError``.
    """
    guarded: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and any(_handles_import_error(h) for h in node.handlers):
            for stmt in node.body:
                for inner in ast.walk(stmt):
                    if isinstance(inner, ast.Import | ast.ImportFrom):
                        guarded.add(id(inner))
    return guarded


def _module_roots(tree: ast.Module) -> list[tuple[str, ast.AST]]:
    """Return every top-level import root in a module, paired with its AST node.

    Args:
        tree: A parsed module.

    Returns:
        ``(root_name, node)`` pairs; relative imports (``level > 0``) are
        skipped since they can only refer to this package.
    """
    roots: list[tuple[str, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.extend((alias.name.split(".")[0], node) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.append((node.module.split(".")[0], node))
    return roots


def collect_required_roots() -> tuple[frozenset[str], dict[str, str]]:
    """Return the import roots that must be declared, and where each first appears.

    A root is exempt from the requirement if *any* of its occurrences in
    ``src/`` is guarded by ``try: ... except ImportError``.

    Returns:
        A ``(required_roots, first_seen_by_root)`` pair.
    """
    first_seen: dict[str, str] = {}
    optional_roots: set[str] = set()
    for path in sorted(SRC_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        guarded_ids = _guarded_import_ids(tree)
        for root, node in _module_roots(tree):
            if root in _STDLIB or root == _INTERNAL_PACKAGE:
                continue
            first_seen.setdefault(root, str(path.relative_to(REPO_ROOT)))
            if id(node) in guarded_ids:
                optional_roots.add(root)
    required = frozenset(first_seen) - optional_roots
    return required, first_seen


def test_every_required_import_root_is_a_declared_dependency() -> None:
    required_roots, first_seen = collect_required_roots()
    distributions = packages_distributions()
    declared = declared_dependency_names()

    problems = []
    for root in sorted(required_roots):
        dist_names = distributions.get(root)
        if not dist_names:
            problems.append(
                f"{root!r} (first imported in {first_seen[root]}): "
                "no installed distribution provides this module"
            )
            continue
        normalized = {_normalize(d) for d in dist_names}
        if not normalized & declared:
            problems.append(
                f"{root!r} (first imported in {first_seen[root]}): "
                f"distribution {dist_names[0]!r} is not in [project.dependencies]"
            )
    assert problems == [], "Undeclared third-party imports in src/:\n" + "\n".join(problems)


def test_stub_packages_stay_paired_with_their_runtime_dependency() -> None:
    declared = declared_dependency_names()
    dev = declared_dev_names()

    problems = []
    for runtime, stub in _STUB_PAIRS.items():
        if runtime not in declared:
            problems.append(
                f"{stub!r} is a mypy stub for {runtime!r}, but {runtime!r} is missing "
                "from [project.dependencies]"
            )
        if stub not in dev:
            problems.append(
                f"{stub!r} is expected in the dev extra for runtime dependency {runtime!r}"
            )
    assert problems == [], "\n".join(problems)
