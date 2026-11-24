"""``pyproject.toml``'s claims about the package hold."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

import meshprovision

pytestmark = pytest.mark.unit

_PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"


def test_the_typed_classifier_has_its_marker() -> None:
    """PEP 561: without ``py.typed`` a type checker ignores the types the classifier claims."""
    classifiers = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]["classifiers"]

    assert "Typing :: Typed" in classifiers
    assert (Path(meshprovision.__file__).parent / "py.typed").is_file()


def test_the_os_classifier_names_linux_only() -> None:
    """locking.py uses fcntl and O_NOFOLLOW unguarded; Linux is what is tested."""
    classifiers = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]["classifiers"]

    assert [c for c in classifiers if c.startswith("Operating System ::")] == [
        "Operating System :: POSIX :: Linux"
    ]


def test_the_sdist_holds_every_document_the_readme_links() -> None:
    sdist = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["tool"]["hatch"]["build"][
        "targets"
    ]["sdist"]["include"]
    readme = (_PYPROJECT.parent / "README.md").read_text(encoding="utf-8")

    for document in ("CONTRIBUTING.md", "CHANGELOG.md", "LICENSE", "docs"):
        assert f"]({document}" in readme or document == "LICENSE"
        assert document in sdist


_REPO_PATH_RE = re.compile(
    r"(?:\bparents\[2\]|\b_?(?:REPO_)?ROOT\b|\brepo_root\b)\)?((?:\s*/\s*\"[^\"]+\")+)"
)
"""A repository path a test builds from the repository root, one literal per part."""

_ALWAYS_IN_THE_SDIST = frozenset({"pyproject.toml"})
"""What hatchling adds to every sdist whatever ``include`` says."""


def _repo_paths_the_tests_read() -> set[str]:
    tests_dir = _PYPROJECT.parent / "tests"
    found: set[str] = set()
    for source in tests_dir.rglob("*.py"):
        for match in _REPO_PATH_RE.finditer(source.read_text(encoding="utf-8")):
            found.add("/".join(re.findall(r'"([^"]+)"', match.group(1))))
    return found


def test_the_sdist_holds_every_repository_file_the_tests_read() -> None:
    """The sdist ships tests/, so it must ship what they open (rs67 E4)."""
    include = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["tool"]["hatch"]["build"][
        "targets"
    ]["sdist"]["include"]
    paths = _repo_paths_the_tests_read()

    missing = {
        path
        for path in paths - _ALWAYS_IN_THE_SDIST
        if not any(path == entry or path.startswith(f"{entry}/") for entry in include)
    }

    assert {"data/nodes_db.example.ods", ".github/workflows"} <= paths
    assert missing == set()
    assert ".pre-commit-config.yaml" in include
