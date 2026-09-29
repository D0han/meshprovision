"""Low-level odfpy writer for the ``Nodes``/``Keys`` ODS database.

This is the only place in the project that builds and serializes an ODS
document via ``odfpy`` -- formulas, content-validation dropdowns, a frozen
header row via ``settings.xml`` view settings, a bold header style, column
widths, and a forced-text number style so LibreOffice never silently
re-types a hex node id as a float. Schema knowledge (column order,
validation rules, formula templates) lives in
:mod:`meshprovision.db.schema`; this module only knows ODF mechanics.
Reading a document back is :mod:`meshprovision.db.ods_read`'s job.

Everything here was verified empirically against the installed ``odfpy``
1.4.1: a prototype document with formulas, ``table:content-validation``,
a forced-``Text`` number style and a freeze-pane was built, saved,
unzipped, and read back successfully before this module was written. Every
attribute name used below (``contentvalidationname``, ``allowemptycell``,
``basecelladdress``, ``displaylist``, ``columnwidth``,
``defaultcellstylename``, ``stylename``, ``datastylename``,
``fontweight``, ``backgroundcolor``) was confirmed against odfpy's own
attribute-name conversion for the corresponding ``table:*``/``style:*``
grammar, not guessed. The list-validity condition grammar
(``of:cell-content-is-in-list(...)``) is documented and verified in
:mod:`meshprovision.db.schema`.

Two independent load-order requirements of the ODF format matter here:

- ``<table:content-validations>`` must be the first child of
  ``<office:spreadsheet>`` -- it is added to ``doc.spreadsheet`` before
  any ``<table:table>``.
- ``odfpy``'s ``OpenDocumentSpreadsheet.save()`` appends ``.ods`` to a
  bare name without a suffix, so writing is done via
  ``doc.write(fileobj)`` inside :func:`meshprovision.db.atomic_writer.atomic_write`,
  never via ``.save()``.

Rows are written sorted, via :func:`meshprovision.db.sorting.sorted_rows`
(:func:`build_document`) -- see :mod:`meshprovision.db.ods` for the other
two points at which row order is enforced (on load, and after every
in-memory mutation).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from odf import config as odf_config
from odf import number as odf_number
from odf import office as odf_office
from odf import style as odf_style
from odf import table as odf_table
from odf import text as odf_text
from odf.opendocument import OpenDocumentSpreadsheet

from meshprovision.db import schema, sorting
from meshprovision.db.atomic_writer import DEFAULT_RETENTION, atomic_write

__all__ = [
    "HEADER_CELL_STYLE_NAME",
    "TEXT_CELL_STYLE_NAME",
    "TEXT_DATA_STYLE_NAME",
    "build_document",
    "create_empty",
    "write_database",
]

TEXT_DATA_STYLE_NAME: Final[str] = "MPTextFormat"
"""Name of the ``number:text-style`` that forces a cell to display as text."""

TEXT_CELL_STYLE_NAME: Final[str] = "MPText"
"""Name of the ``style:style`` (family ``table-cell``) applied to every data cell."""

HEADER_CELL_STYLE_NAME: Final[str] = "MPHeader"
"""Name of the ``style:style`` applied to header-row cells: bold, shaded."""

_HEADER_BG_COLOR: Final[str] = "#e6e6e6"

_FREEZE_HEADER_ITEMS: Final[tuple[tuple[str, str, str], ...]] = (
    ("CursorPositionX", "int", "0"),
    ("CursorPositionY", "int", "1"),
    ("HorizontalSplitMode", "short", "0"),
    ("VerticalSplitMode", "short", "2"),
    ("HorizontalSplitPosition", "int", "0"),
    ("VerticalSplitPosition", "int", "1"),
    ("ActiveSplitRange", "short", "2"),
    ("PositionLeft", "int", "0"),
    ("PositionRight", "int", "0"),
    ("PositionTop", "int", "0"),
    ("PositionBottom", "int", "1"),
)
"""``config:config-item`` name/type/text triples that freeze row 1 in Calc.

``VerticalSplitMode=2`` is FREEZE (``1`` would be a plain movable split);
``VerticalSplitPosition=1`` freezes exactly the header row.
"""


def _add_common_styles(doc: OpenDocumentSpreadsheet) -> None:
    """Add the shared text-forcing number style and cell styles to ``doc.styles``.

    Args:
        doc: The document being built.
    """
    data_style = odf_number.TextStyle(name=TEXT_DATA_STYLE_NAME)
    data_style.addElement(odf_number.TextContent())
    doc.styles.addElement(data_style)

    doc.styles.addElement(
        odf_style.Style(
            name=TEXT_CELL_STYLE_NAME, family="table-cell", datastylename=TEXT_DATA_STYLE_NAME
        )
    )

    header_style = odf_style.Style(
        name=HEADER_CELL_STYLE_NAME, family="table-cell", datastylename=TEXT_DATA_STYLE_NAME
    )
    header_style.addElement(odf_style.TextProperties(fontweight="bold"))
    header_style.addElement(odf_style.TableCellProperties(backgroundcolor=_HEADER_BG_COLOR))
    doc.styles.addElement(header_style)


def _add_column_width_styles(doc: OpenDocumentSpreadsheet) -> dict[str, str]:
    """Add one automatic ``table-column`` style per distinct column width.

    Args:
        doc: The document being built.

    Returns:
        A map from ODF width string (e.g. ``"1.0in"``) to the automatic
        style name created for it.
    """
    style_names: dict[str, str] = {}
    for sheet_spec in schema.SHEET_SPECS.values():
        for col in sheet_spec.columns:
            if col.width in style_names:
                continue
            style_name = f"mpco{len(style_names)}"
            style_names[col.width] = style_name
            col_style = odf_style.Style(name=style_name, family="table-column")
            col_style.addElement(odf_style.TableColumnProperties(columnwidth=col.width))
            doc.automaticstyles.addElement(col_style)
    return style_names


def _add_content_validations(doc: OpenDocumentSpreadsheet) -> None:
    """Add one ``table:content-validation`` per dropdown column.

    Must run before any ``table:table`` is added to ``doc.spreadsheet``:
    ODF requires ``table:content-validations`` to be the first child of
    ``office:spreadsheet``.

    Args:
        doc: The document being built.
    """
    validations = odf_table.ContentValidations()
    for sheet_spec in schema.SHEET_SPECS.values():
        for col in sheet_spec.columns:
            if col.validation_name is None:
                continue
            values = schema.allowed_values(col) or ()
            letter = sheet_spec.letter(col.name)
            validations.addElement(
                odf_table.ContentValidation(
                    name=col.validation_name,
                    condition=schema.validation_condition(values),
                    allowemptycell="true",
                    basecelladdress=f"{sheet_spec.name}.{letter}2",
                    displaylist="unsorted",
                )
            )
    doc.spreadsheet.addElement(validations)


def _build_header_row(sheet_spec: schema.SheetSpec) -> Any:
    """Build the header ``table:table-row`` for one sheet.

    Each header cell carries its column name as text plus its
    description as an ``office:annotation``, so the header stays both
    readable and unambiguous.

    Args:
        sheet_spec: The sheet's column layout.

    Returns:
        The built ``TableRow`` element.
    """
    row_elem = odf_table.TableRow()
    for col in sheet_spec.columns:
        cell = odf_table.TableCell(
            valuetype="string", stringvalue=col.name, stylename=HEADER_CELL_STYLE_NAME
        )
        cell.addElement(odf_text.P(text=col.name))
        annotation = odf_office.Annotation()
        annotation.addElement(odf_text.P(text=col.description))
        cell.addElement(annotation)
        row_elem.addElement(cell)
    return row_elem


def _build_data_cell(
    sheet_spec: schema.SheetSpec, col: schema.ColumnSpec, value: str, ods_row: int
) -> Any:
    """Build one data ``table:table-cell``.

    Args:
        sheet_spec: The sheet the cell belongs to.
        col: The cell's column.
        value: The cell's value (already validated/normalized).
        ods_row: The cell's 1-based ODS row number.

    Returns:
        The built ``TableCell`` element, carrying a formula and/or a
        content-validation reference when the column has one.
    """
    if value:
        cell = odf_table.TableCell(valuetype="string", stringvalue=value)
        cell.addElement(odf_text.P(text=value))
    else:
        cell = odf_table.TableCell()
    formula = schema.formula_for(sheet_spec, col.name, ods_row)
    if formula is not None:
        cell.setAttribute("formula", formula)
    if col.validation_name is not None:
        cell.setAttribute("contentvalidationname", col.validation_name)
    return cell


def _build_data_row(sheet_spec: schema.SheetSpec, row: Mapping[str, str], ods_row: int) -> Any:
    """Build one data ``table:table-row``.

    Args:
        sheet_spec: The sheet the row belongs to.
        row: The row's ``{column_name: value}`` map.
        ods_row: The row's 1-based ODS row number.

    Returns:
        The built ``TableRow`` element.
    """
    row_elem = odf_table.TableRow()
    for col in sheet_spec.columns:
        row_elem.addElement(_build_data_cell(sheet_spec, col, row.get(col.name, ""), ods_row))
    return row_elem


def _build_table(
    sheet_spec: schema.SheetSpec,
    rows: Sequence[Mapping[str, str]],
    width_styles: Mapping[str, str],
) -> Any:
    """Build one full ``table:table`` element.

    Args:
        sheet_spec: The sheet's column layout.
        rows: The sheet's data rows, in write order.
        width_styles: Map from ODF width string to automatic style name,
            from :func:`_add_column_width_styles`.

    Returns:
        The built ``Table`` element.
    """
    table_elem = odf_table.Table(name=sheet_spec.name)
    for col in sheet_spec.columns:
        table_elem.addElement(
            odf_table.TableColumn(
                stylename=width_styles[col.width], defaultcellstylename=TEXT_CELL_STYLE_NAME
            )
        )
    table_elem.addElement(_build_header_row(sheet_spec))
    for index, row in enumerate(rows):
        table_elem.addElement(_build_data_row(sheet_spec, row, ods_row=index + 2))
    return table_elem


def _add_view_settings(doc: OpenDocumentSpreadsheet) -> None:
    """Add ``settings.xml`` view settings that freeze row 1 on every sheet.

    Args:
        doc: The document being built.
    """
    view_id = odf_config.ConfigItem(name="ViewId", type="string")
    view_id.addText("view1")

    entry = odf_config.ConfigItemMapEntry()
    entry.addElement(view_id)

    tables_map = odf_config.ConfigItemMapNamed(name="Tables")
    for sheet_name in schema.SHEET_NAMES:
        table_entry = odf_config.ConfigItemMapEntry(name=sheet_name)
        for item_name, item_type, item_text in _FREEZE_HEADER_ITEMS:
            item = odf_config.ConfigItem(name=item_name, type=item_type)
            item.addText(item_text)
            table_entry.addElement(item)
        tables_map.addElement(table_entry)
    entry.addElement(tables_map)

    active_table = odf_config.ConfigItem(name="ActiveTable", type="string")
    active_table.addText(schema.NODES_SHEET)
    entry.addElement(active_table)

    views = odf_config.ConfigItemMapIndexed(name="Views")
    views.addElement(entry)

    view_settings = odf_config.ConfigItemSet(name="ooo:view-settings")
    view_settings.addElement(views)
    doc.settings.addElement(view_settings)


def build_document(
    *, nodes: Sequence[Mapping[str, str]], keys: Sequence[Mapping[str, str]]
) -> OpenDocumentSpreadsheet:
    """Build a complete, in-memory ODS document from row data.

    Args:
        nodes: The ``Nodes`` sheet's rows -- written out sorted into
            their canonical order (see :mod:`meshprovision.db.sorting`)
            regardless of the order passed in.
        keys: The ``Keys`` sheet's rows -- likewise sorted.

    Returns:
        The built document, ready to be serialized via ``doc.write(fileobj)``.
    """
    doc = OpenDocumentSpreadsheet()
    _add_common_styles(doc)
    width_styles = _add_column_width_styles(doc)
    _add_content_validations(doc)  # Must precede every <table:table> below.

    row_data: Mapping[str, Sequence[Mapping[str, str]]] = {
        schema.NODES_SHEET: sorting.sorted_rows(schema.NODES_SHEET, nodes),
        schema.KEYS_SHEET: sorting.sorted_rows(schema.KEYS_SHEET, keys),
    }
    for sheet_name in schema.SHEET_NAMES:
        sheet_spec = schema.SHEET_SPECS[sheet_name]
        doc.spreadsheet.addElement(_build_table(sheet_spec, row_data[sheet_name], width_styles))

    _add_view_settings(doc)
    return doc


def write_database(
    path: Path,
    *,
    nodes: Sequence[Mapping[str, str]],
    keys: Sequence[Mapping[str, str]],
    backup: bool = True,
    backup_dir: Path | None = None,
    retention: int = DEFAULT_RETENTION,
) -> None:
    """Build and atomically write a complete ODS database.

    Args:
        path: Path to write the ``.ods`` file to.
        nodes: The ``Nodes`` sheet's rows -- written sorted into their
            canonical order (see :mod:`meshprovision.db.sorting`)
            regardless of the order passed in.
        keys: The ``Keys`` sheet's rows -- likewise sorted.
        backup: Whether to back up the current file at ``path`` before
            replacing it.
        backup_dir: Directory to store the backup under, when ``backup``
            is true.
        retention: Number of backups to retain, when ``backup`` is true.

    Raises:
        AtomicWriteError: If the write or backup fails.
    """
    doc = build_document(nodes=nodes, keys=keys)
    with (
        atomic_write(path, backup=backup, backup_dir=backup_dir, retention=retention) as tmp,
        tmp.open("wb") as fh,
    ):
        doc.write(fh)


def create_empty(path: Path, *, backup: bool = False) -> None:
    """Write a brand-new, empty (header-only) ODS database.

    Args:
        path: Path to write the ``.ods`` file to.
        backup: Whether to back up any existing file at ``path`` first.

    Raises:
        AtomicWriteError: If the write or backup fails.
    """
    write_database(path, nodes=(), keys=(), backup=backup)
