"""``pyproject.toml``'s claims about the package hold."""

from __future__ import annotations

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
