"""Every repository file a ``hint=`` in ``src/`` names exists.

A hint that says "copy this file" is the recovery step; a path that was
moved or never existed makes the operator search for it. This walks the
string literals of every ``hint=`` argument in ``src/`` (implicitly
concatenated literals are one constant) and checks each relative path
with a file extension against the repository, except the files the
operator or ``mesh init`` creates.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Final

import pytest

pytestmark = pytest.mark.unit

SRC_ROOT: Final = Path(__file__).resolve().parents[2] / "src" / "meshprovision"
REPO_ROOT: Final = SRC_ROOT.parents[1]

_PATH_RE: Final = re.compile(r"(?<![\w/.~-])((?:[\w.-]+/)+[\w.-]*\.[a-z]+)\b")

_CREATED_FILES: Final = frozenset({"config/template.yaml", "data/nodes_db.ods"})
"""Files a hint names before they exist: ``mesh init`` or the operator creates them."""


def _hint_texts(tree: ast.AST) -> Iterator[tuple[int, str]]:
    """Yield ``(lineno, text)`` for every str constant inside a ``hint=`` argument."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg != "hint":
                continue
            for part in ast.walk(keyword.value):
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    yield part.lineno, part.value


def _missing(text: str) -> list[str]:
    return [
        path
        for path in _PATH_RE.findall(text)
        if path not in _CREATED_FILES and not (REPO_ROOT / path).exists()
    ]


def test_every_repository_file_a_hint_names_exists() -> None:
    problems = [
        f"{path.relative_to(SRC_ROOT)}:{lineno}: {missing}"
        for path in sorted(SRC_ROOT.rglob("*.py"))
        for lineno, text in _hint_texts(ast.parse(path.read_text(encoding="utf-8")))
        for missing in _missing(text)
    ]
    assert problems == []


def test_the_path_checker_finds_relative_file_paths_only() -> None:
    assert _missing("copy config/template.example.yaml to config/template.yaml") == [
        "config/template.example.yaml"
    ]
    assert _missing("copy data/nodes_db.example.ods to data/nodes_db.ods") == []
    assert _missing("Close/save the file, pass --setlat/--setlon/--setalt") == []
    assert _missing("see ~/.config/x/missing.yaml or /etc/missing.conf") == []
