"""Every template section field is listed in docs/configuration.md."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from pydantic import BaseModel

from meshprovision.config.template import TemplateConfig

pytestmark = pytest.mark.unit

_DOCS = (Path(__file__).resolve().parents[2] / "docs" / "configuration.md").read_text(
    encoding="utf-8"
)
_REFERENCE = _DOCS[_DOCS.index("### Every section field") :]

_SECTIONS: dict[str, type[BaseModel]] = {
    name: field.annotation
    for name, field in TemplateConfig.model_fields.items()
    if isinstance(field.annotation, type) and issubclass(field.annotation, BaseModel)
}


def _table(section: str) -> str:
    """Return the reference table under ``#### `section```."""
    body = _REFERENCE.index("\n", _REFERENCE.index(f"#### `{section}`"))
    following = re.search(r"^#{1,4} ", _REFERENCE[body:], flags=re.MULTILINE)
    return _REFERENCE[body : None if following is None else body + following.start()]


def test_every_section_has_a_table() -> None:
    assert set(_SECTIONS) == set(re.findall(r"^#### `(\w+)`$", _REFERENCE, flags=re.MULTILINE))


@pytest.mark.parametrize("section", sorted(_SECTIONS))
def test_every_field_of_the_section_is_in_its_table(section: str) -> None:
    rows = set(re.findall(r"^\| `(\w+)` \|", _table(section), flags=re.MULTILINE))

    assert rows == set(_SECTIONS[section].model_fields)
