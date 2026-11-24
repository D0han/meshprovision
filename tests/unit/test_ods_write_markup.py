"""What a written database tells a spreadsheet editor: dropdowns and column notes.

The reader ignores these, so a round trip cannot see them; they are read
from the written ``content.xml`` instead.
"""

from __future__ import annotations

import zipfile
from typing import TYPE_CHECKING

import pytest
from defusedxml import ElementTree

from meshprovision.db import ods_write, schema
from meshprovision.db.nodes import NodeRecord

if TYPE_CHECKING:
    from pathlib import Path
    from xml.etree.ElementTree import Element

pytestmark = pytest.mark.unit

_TABLE = "urn:oasis:names:tc:opendocument:xmlns:table:1.0"
_OFFICE = "urn:oasis:names:tc:opendocument:xmlns:office:1.0"
_TEXT = "urn:oasis:names:tc:opendocument:xmlns:text:1.0"
_STYLE = "urn:oasis:names:tc:opendocument:xmlns:style:1.0"
_FO = "urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"


def _t(name: str) -> str:
    return f"{{{_TABLE}}}{name}"


@pytest.fixture
def content(tmp_path: Path) -> Element:
    path = tmp_path / "db.ods"
    row = NodeRecord(node_id="deadbe01", short_name="MT01", region="EU_868").to_row()
    ods_write.write_database(path, nodes=[row], keys=[], backup=False)
    with zipfile.ZipFile(path) as archive:
        root: Element = ElementTree.fromstring(archive.read("content.xml"))
    return root


def _validated_columns() -> list[tuple[schema.SheetSpec, schema.ColumnSpec]]:
    return [
        (sheet, column)
        for sheet in schema.SHEET_SPECS.values()
        for column in sheet.columns
        if column.validation_name is not None
    ]


def test_every_dropdown_allows_an_empty_cell_and_lists_unsorted_from_row_two(
    content: Element,
) -> None:
    validations = {
        element.get(_t("name")): element for element in content.iter(_t("content-validation"))
    }

    assert _validated_columns()
    for sheet, column in _validated_columns():
        validation = validations[column.validation_name]
        assert validation.get(_t("allow-empty-cell")) == "true"
        assert validation.get(_t("display-list")) == "unsorted"
        assert (
            validation.get(_t("base-cell-address")) == f"{sheet.name}.{sheet.letter(column.name)}2"
        )


def test_every_data_cell_of_a_dropdown_column_names_its_validation(content: Element) -> None:
    nodes = next(table for table in content.iter(_t("table")) if table.get(_t("name")) == "Nodes")
    _, data = list(nodes.iter(_t("table-row")))[:2]
    names = [cell.get(_t("content-validation-name")) for cell in data.iter(_t("table-cell"))]
    spec = schema.SHEET_SPECS["Nodes"]

    for index, column in enumerate(spec.columns):
        assert names[index] == column.validation_name, column.name


def test_every_header_cell_carries_its_column_description(content: Element) -> None:
    for sheet in schema.SHEET_SPECS.values():
        table = next(
            table for table in content.iter(_t("table")) if table.get(_t("name")) == sheet.name
        )
        header = next(table.iter(_t("table-row")))
        notes = [
            "".join("".join(p.itertext()) for p in annotation.iter(f"{{{_TEXT}}}p"))
            for annotation in header.iter(f"{{{_OFFICE}}}annotation")
        ]
        assert notes == [column.description for column in sheet.columns]


def test_every_header_cell_has_the_bold_header_style(tmp_path: Path) -> None:
    """rs67 T13: a header cell naming another style would lose its bold look."""
    path = tmp_path / "db.ods"
    ods_write.write_database(path, nodes=[], keys=[], backup=False)
    with zipfile.ZipFile(path) as archive:
        content: Element = ElementTree.fromstring(archive.read("content.xml"))
        styles: Element = ElementTree.fromstring(archive.read("styles.xml"))
    bold = {
        style.get(f"{{{_STYLE}}}name")
        for style in styles.iter(f"{{{_STYLE}}}style")
        if any(
            props.get(f"{{{_FO}}}font-weight") == "bold"
            for props in style.iter(f"{{{_STYLE}}}text-properties")
        )
    }

    for table in content.iter(_t("table")):
        header = next(table.iter(_t("table-row")))
        names = {cell.get(_t("style-name")) for cell in header.iter(_t("table-cell"))}
        assert names == {ods_write.HEADER_CELL_STYLE_NAME}, table.get(_t("name"))
    assert ods_write.HEADER_CELL_STYLE_NAME in bold
