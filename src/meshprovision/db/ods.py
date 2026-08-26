"""Low-level odfpy read/write layer for the ``Nodes``/``Keys`` ODS database.

This module is the only place in the project that touches ``odfpy``
directly. It builds the real spreadsheet -- formulas, content-validation
dropdowns, a frozen header row via ``settings.xml`` view settings, a bold
header style, column widths, and a forced-text number style so LibreOffice
never silently re-types a hex node id as a float -- and reads it back
defensively, treating every cell as an explicit string. Schema knowledge
(column order, validation rules, formula templates) lives in
:mod:`meshprovision.db.schema`; this module only knows ODF mechanics.

Everything here was verified empirically against the installed ``odfpy``
1.4.1: a prototype document with formulas, ``table:content-validation``,
a forced-``Text`` number style and a freeze-pane was built, saved,
unzipped, and read back successfully before this module was written. Every
attribute name used below (``valuetype``, ``stringvalue``, ``formula``,
``contentvalidationname``, ``allowemptycell``, ``basecelladdress``,
``displaylist``, ``columnwidth``, ``defaultcellstylename``, ``stylename``,
``datastylename``, ``fontweight``, ``backgroundcolor``) was confirmed
against odfpy's own attribute-name conversion for the corresponding
``table:*``/``style:*`` grammar, not guessed. The list-validity condition
grammar (``of:cell-content-is-in-list(...)``) is documented and verified
in :mod:`meshprovision.db.schema`.

Two independent load-order requirements of the ODF format matter here:

- ``<table:content-validations>`` must be the first child of
  ``<office:spreadsheet>`` -- it is added to ``doc.spreadsheet`` before
  any ``<table:table>``.
- ``odfpy``'s ``OpenDocumentSpreadsheet.save()`` appends ``.ods`` to a
  bare name without a suffix, so writing is done via
  ``doc.write(fileobj)`` inside :func:`meshprovision.db.atomic_writer.atomic_write`,
  never via ``.save()``.
"""

from __future__ import annotations

import contextlib
import logging
import xml.parsers.expat
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from odf import config as odf_config
from odf import number as odf_number
from odf import office as odf_office
from odf import opendocument, teletype
from odf import style as odf_style
from odf import table as odf_table
from odf import text as odf_text
from odf.element import Node
from odf.opendocument import OpenDocumentSpreadsheet

from meshprovision.db import locking, schema
from meshprovision.db.atomic_writer import DEFAULT_RETENTION, atomic_write
from meshprovision.errors import DbIntegrityError, DuplicateNodeError, SchemaError

__all__ = [
    "HEADER_CELL_STYLE_NAME",
    "MAX_BLANK_ROWS",
    "MAX_COLUMNS",
    "MAX_ROW_REPEAT",
    "TEXT_CELL_STYLE_NAME",
    "TEXT_DATA_STYLE_NAME",
    "CellValue",
    "DatabaseData",
    "IntegrityWarning",
    "LoadedDatabase",
    "OdsDatabase",
    "SheetData",
    "build_document",
    "create_empty",
    "load_database",
    "read_raw",
    "verify",
    "write_database",
]

_logger = logging.getLogger(__name__)

TEXT_DATA_STYLE_NAME: Final[str] = "MPTextFormat"
"""Name of the ``number:text-style`` that forces a cell to display as text."""

TEXT_CELL_STYLE_NAME: Final[str] = "MPText"
"""Name of the ``style:style`` (family ``table-cell``) applied to every data cell."""

HEADER_CELL_STYLE_NAME: Final[str] = "MPHeader"
"""Name of the ``style:style`` applied to header-row cells: bold, shaded."""

MAX_COLUMNS: Final[int] = 256
"""Upper bound on columns read per row, guarding against a runaway repeat count."""

MAX_BLANK_ROWS: Final[int] = 64
"""Maximum consecutive blank data rows read before stopping."""

MAX_ROW_REPEAT: Final[int] = 1024
"""Above this ``table:number-rows-repeated`` count, a blank row is treated as
LibreOffice's giant trailing filler row and read stops immediately."""

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

_TABLE_CELL_QNAME: Final[tuple[str, str]] = (odf_table.TABLENS, "table-cell")
_COVERED_CELL_QNAME: Final[tuple[str, str]] = (odf_table.TABLENS, "covered-table-cell")

_TEXT_LIKE_KINDS: Final[frozenset[schema.ColumnKind]] = frozenset(
    {
        schema.ColumnKind.TEXT,
        schema.ColumnKind.NODE_ID,
        schema.ColumnKind.KEY_REF,
        schema.ColumnKind.KEY_REF_LIST,
        schema.ColumnKind.PIN,
        schema.ColumnKind.BASE64_KEY,
    }
)
_COERCED_VALUE_TYPES: Final[frozenset[str]] = frozenset(
    {"float", "percentage", "currency", "date", "time"}
)


@dataclass(frozen=True, slots=True)
class CellValue:
    """One cell's raw, defensively-extracted content.

    Attributes:
        text: The cell's display text -- from ``office:string-value`` when
            the cell is explicitly typed as a string, otherwise from the
            extracted paragraph text.
        formula: The cell's ``table:formula`` attribute, when present.
        value_type: The cell's ``table:value-type`` attribute, when
            present (for example ``"string"``, ``"float"``, ``"date"``).
    """

    text: str
    formula: str | None = None
    value_type: str | None = None


@dataclass(frozen=True, slots=True)
class SheetData:
    """One sheet's raw header and data rows.

    Attributes:
        name: The sheet name.
        header: The header row's cell texts, in column order.
        rows: The data rows (header excluded), each a tuple of
            :class:`CellValue` in column order.
        first_data_row: The 1-based ODS row number of ``rows[0]``.
    """

    name: str
    header: tuple[str, ...]
    rows: tuple[tuple[CellValue, ...], ...]
    first_data_row: int = 2


@dataclass(frozen=True, slots=True)
class DatabaseData:
    """The raw contents of every sheet in one ODS file.

    Attributes:
        path: Path to the ODS file that was read.
        sheets: Every sheet found, keyed by sheet name.
    """

    path: Path
    sheets: Mapping[str, SheetData]


@dataclass(frozen=True, slots=True)
class IntegrityWarning:
    """One non-fatal integrity problem found while loading a database.

    Attributes:
        sheet: Name of the sheet containing the cell.
        cell: The cell reference, for example ``"Nodes.O3"``.
        column: Name of the affected column.
        cached: The value that was cached in the cell.
        recomputed: The value recomputed from the row's source columns
            (and the value actually used).
        kind: ``"recompute"`` (a derived cell's cached value disagreed
            with its recomputed value) or ``"coerced_cell"`` (a
            text-kind cell was not stored as text, so LibreOffice may
            have coerced its content).
    """

    sheet: str
    cell: str
    column: str
    cached: str = ""
    recomputed: str = ""
    kind: str = "recompute"

    def message(self) -> str:
        """Render a human-readable summary of this warning.

        Returns:
            For example ``"Nodes.O3: cached private_key_ref value ... disagrees ..."``.
        """
        if self.kind == "coerced_cell":
            return (
                f"{self.cell}: {self.column} is not formatted as text "
                f"(value type {self.cached!r}); LibreOffice may have coerced its content"
            )
        return (
            f"{self.cell}: cached {self.column} value {self.cached!r} disagrees with "
            f"recomputed value {self.recomputed!r}; using the recomputed value"
        )


@dataclass(frozen=True, slots=True)
class LoadedDatabase:
    """The fully validated, recomputed contents of one ODS database.

    Attributes:
        path: Path to the ODS file that was loaded.
        nodes: Every ``Nodes`` sheet row, validated and with derived
            columns already recomputed.
        keys: Every ``Keys`` sheet row, validated and with derived
            columns already recomputed.
        warnings: Every integrity problem found while loading, across
            both sheets.
    """

    path: Path
    nodes: tuple[Mapping[str, str], ...]
    keys: tuple[Mapping[str, str], ...]
    warnings: tuple[IntegrityWarning, ...]


# ---------------------------------------------------------------------------
# Reading.
# ---------------------------------------------------------------------------


def _int_attr(elem: Any, name: str, *, default: int) -> int:
    """Read an integer-valued ODF attribute, tolerating absence/garbage.

    Args:
        elem: The odfpy element to read from.
        name: The attribute's Python-side (no-hyphen) name.
        default: Value to use when the attribute is absent or unparsable.

    Returns:
        The parsed integer, or ``default``.
    """
    raw = elem.getAttribute(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _extract_cell(cell_elem: Any) -> CellValue:
    """Defensively extract one ``table:table-cell``'s content.

    Prefers the cached ``office:string-value`` when the cell is
    explicitly typed as a string; otherwise falls back to the extracted
    paragraph text, which is what a numeric/date-typed cell (one
    LibreOffice may have coerced) still yields.

    Args:
        cell_elem: The odfpy ``TableCell`` element.

    Returns:
        The extracted :class:`CellValue`.
    """
    value_type: str | None = cell_elem.getAttribute("valuetype")
    formula: str | None = cell_elem.getAttribute("formula")
    string_value: str | None = cell_elem.getAttribute("stringvalue")
    text: str
    if value_type == "string" and string_value is not None:
        text = string_value
    else:
        text = teletype.extractText(cell_elem)
    return CellValue(text=text, formula=formula, value_type=value_type)


def _read_row_cells(row_elem: Any) -> tuple[CellValue, ...]:
    """Read one row's cells, in document order, expanding column repeats.

    Iterates the row's direct children so ``table:table-cell`` and
    ``table:covered-table-cell`` elements are read in the interleaved
    order they actually appear, capped at :data:`MAX_COLUMNS` total.

    Args:
        row_elem: The odfpy ``TableRow`` element.

    Returns:
        The row's cells, in column order.
    """
    cells: list[CellValue] = []
    for child in row_elem.childNodes:
        if len(cells) >= MAX_COLUMNS:
            break
        if getattr(child, "nodeType", None) != Node.ELEMENT_NODE:
            continue
        qname = child.qname
        if qname == _COVERED_CELL_QNAME:
            repeat = _int_attr(child, "numbercolumnsrepeated", default=1)
            cells.extend(CellValue(text="") for _ in range(min(repeat, MAX_COLUMNS - len(cells))))
        elif qname == _TABLE_CELL_QNAME:
            cell_value = _extract_cell(child)
            repeat = _int_attr(child, "numbercolumnsrepeated", default=1)
            cells.extend(cell_value for _ in range(min(repeat, MAX_COLUMNS - len(cells))))
    return tuple(cells)


def _read_sheet(name: str, table_elem: Any) -> SheetData:
    """Read one ``table:table`` element into a :class:`SheetData`.

    Args:
        name: The sheet's name.
        table_elem: The odfpy ``Table`` element.

    Returns:
        The sheet's header and data rows.
    """
    row_elems = table_elem.getElementsByType(odf_table.TableRow)
    if not row_elems:
        return SheetData(name=name, header=(), rows=())

    header = tuple(cell.text for cell in _read_row_cells(row_elems[0]))

    data_rows: list[tuple[CellValue, ...]] = []
    consecutive_blank = 0
    for row_elem in row_elems[1:]:
        cells = _read_row_cells(row_elem)
        is_blank = all(not cell.text.strip() for cell in cells)
        repeat = _int_attr(row_elem, "numberrowsrepeated", default=1)

        if is_blank and repeat > MAX_ROW_REPEAT:
            # LibreOffice's giant trailing filler row: treat as end-of-data.
            break

        count = min(repeat, MAX_ROW_REPEAT) if is_blank else 1
        exhausted = False
        for _ in range(count):
            if is_blank:
                consecutive_blank += 1
                if consecutive_blank > MAX_BLANK_ROWS:
                    exhausted = True
                    break
            else:
                consecutive_blank = 0
            data_rows.append(cells)
        if exhausted:
            break

    return SheetData(name=name, header=header, rows=tuple(data_rows))


def read_raw(path: Path) -> DatabaseData:
    """Read an ODS file's raw sheet contents, with no schema validation.

    Args:
        path: Path to the ``.ods`` file.

    Returns:
        The raw contents of every sheet found.

    Raises:
        SchemaError: If ``path`` cannot be opened and parsed as an ODF
            spreadsheet.
    """
    try:
        doc = opendocument.load(str(path))
    except (
        OSError,
        zipfile.BadZipFile,
        xml.parsers.expat.ExpatError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
    ) as exc:
        raise SchemaError(f"{path} is not a readable ODF spreadsheet: {exc}") from exc

    sheets: dict[str, SheetData] = {}
    for table_elem in doc.spreadsheet.getElementsByType(odf_table.Table):
        sheet_name: str | None = table_elem.getAttribute("name")
        if sheet_name is None:
            continue
        sheets[sheet_name] = _read_sheet(sheet_name, table_elem)
    return DatabaseData(path=path, sheets=sheets)


def _check_header(sheet_data: SheetData, sheet_spec: schema.SheetSpec) -> None:
    """Confirm a sheet's header row matches its expected column order.

    Trailing extra blank columns are tolerated -- order is otherwise
    strict, since the ODF formulas reference fixed column letters.

    Args:
        sheet_data: The sheet's raw data.
        sheet_spec: The expected column layout.

    Raises:
        SchemaError: If the header does not match, naming what was
            expected and what was found.
    """
    expected = sheet_spec.column_names()
    trimmed = list(sheet_data.header)
    while trimmed and not trimmed[-1].strip():
        trimmed.pop()
    if tuple(trimmed) != expected:
        raise SchemaError(
            f"{sheet_spec.name} sheet header does not match the expected schema: "
            f"expected {expected!r}, found {tuple(trimmed)!r}",
            sheet=sheet_spec.name,
        )


def _row_values(
    sheet_spec: schema.SheetSpec, cells: tuple[CellValue, ...], ods_row: int
) -> tuple[dict[str, str], list[IntegrityWarning]]:
    """Build a ``{column_name: text}`` map for one row, flagging likely coercion.

    Args:
        sheet_spec: The sheet's column layout.
        cells: The row's raw cells, in column order.
        ods_row: The row's 1-based ODS row number, used only in the
            coercion warning's cell reference.

    Returns:
        A new ``dict`` of raw cell text, one entry per column in
        ``sheet_spec``, and the list of coercion warnings found in this
        row (not yet logged -- the caller decides whether the row is
        blank before doing that).
    """
    values: dict[str, str] = {}
    coercions: list[IntegrityWarning] = []
    for index, col in enumerate(sheet_spec.columns):
        cell = cells[index] if index < len(cells) else CellValue(text="")
        if col.kind in _TEXT_LIKE_KINDS and cell.value_type in _COERCED_VALUE_TYPES:
            coercions.append(
                IntegrityWarning(
                    sheet=sheet_spec.name,
                    cell=f"{sheet_spec.name}.{sheet_spec.letter(col.name)}{ods_row}",
                    column=col.name,
                    cached=cell.value_type or "",
                    kind="coerced_cell",
                )
            )
        values[col.name] = cell.text
    return values, coercions


def _apply_recompute(
    sheet_spec: schema.SheetSpec,
    validated: Mapping[str, str],
    ods_row: int,
    warnings: list[IntegrityWarning],
) -> dict[str, str]:
    """Recompute every derived column and reconcile it against its cached value.

    A cached value that is empty is silently replaced. A cached value
    that disagrees with the recomputed value produces an
    :class:`IntegrityWarning` (appended to ``warnings`` and logged) --
    either way, the recomputed value is what is used.

    Args:
        sheet_spec: The row's column layout.
        validated: The row's already-validated values.
        ods_row: The row's 1-based ODS row number, used in the warning's
            cell reference.
        warnings: Mutable list warnings are appended to.

    Returns:
        A new ``dict`` combining ``validated`` with every derived
        column's recomputed value.
    """
    merged = dict(validated)
    recomputed = schema.recompute_derived(sheet_spec, validated)
    for column, new_value in recomputed.items():
        cached = validated.get(column, "")
        if cached and cached != new_value:
            warning = IntegrityWarning(
                sheet=sheet_spec.name,
                cell=f"{sheet_spec.name}.{sheet_spec.letter(column)}{ods_row}",
                column=column,
                cached=cached,
                recomputed=new_value,
            )
            warnings.append(warning)
            _logger.warning("%s", warning.message())
        merged[column] = new_value
    return merged


def _load_sheet_rows(
    sheet_data: SheetData,
    sheet_spec: schema.SheetSpec,
    warnings: list[IntegrityWarning],
) -> tuple[Mapping[str, str], ...]:
    """Validate and recompute every row of one sheet.

    Args:
        sheet_data: The sheet's raw data.
        sheet_spec: The sheet's expected column layout.
        warnings: Mutable list warnings are appended to.

    Returns:
        Every non-blank row, validated and with derived columns
        recomputed.

    Raises:
        SchemaError: If the sheet's header does not match its schema.
        DbValidationError: If any cell fails validation.
    """
    _check_header(sheet_data, sheet_spec)
    records: list[Mapping[str, str]] = []
    ods_row = sheet_data.first_data_row
    for cells in sheet_data.rows:
        raw_values, coercions = _row_values(sheet_spec, cells, ods_row)
        if all(not value.strip() for value in raw_values.values()):
            ods_row += 1
            continue
        for coercion in coercions:
            warnings.append(coercion)
            _logger.warning("%s", coercion.message())
        validated = schema.validate_row(sheet_spec, ods_row, raw_values)
        records.append(_apply_recompute(sheet_spec, validated, ods_row, warnings))
        ods_row += 1
    return tuple(records)


def _check_unique_node_ids(nodes: Sequence[Mapping[str, str]]) -> None:
    """Confirm no ``node_id`` value repeats across the ``Nodes`` sheet.

    Args:
        nodes: The sheet's validated rows.

    Raises:
        DuplicateNodeError: If a ``node_id`` value appears more than once.
    """
    seen: set[str] = set()
    for row in nodes:
        node_id = row.get("node_id", "")
        if not node_id:
            continue
        if node_id in seen:
            raise DuplicateNodeError(
                f"Duplicate node_id in {schema.NODES_SHEET} sheet: {node_id!r}",
                node_id=node_id,
                sheet=schema.NODES_SHEET,
            )
        seen.add(node_id)


def _check_unique_key_refs(keys: Sequence[Mapping[str, str]]) -> None:
    """Confirm no ``key_ref`` value repeats across the ``Keys`` sheet.

    Args:
        keys: The sheet's validated rows.

    Raises:
        DbIntegrityError: If a ``key_ref`` value appears more than once.
    """
    seen: set[str] = set()
    for row in keys:
        key_ref = row.get("key_ref", "")
        if not key_ref:
            continue
        if key_ref in seen:
            raise DbIntegrityError(
                f"Duplicate key_ref in {schema.KEYS_SHEET} sheet: {key_ref!r}",
                sheet=schema.KEYS_SHEET,
                cell=key_ref,
            )
        seen.add(key_ref)


def load_database(path: Path) -> LoadedDatabase:
    """Read, validate, and recompute an ODS database's full contents.

    Args:
        path: Path to the ``.ods`` file.

    Returns:
        The fully validated database.

    Raises:
        SchemaError: If the file cannot be read, is missing the
            ``Nodes`` or ``Keys`` sheet, or either sheet's header does
            not match its schema.
        DbValidationError: If any cell fails validation.
        DuplicateNodeError: If ``Nodes.node_id`` has a duplicate.
        DbIntegrityError: If ``Keys.key_ref`` has a duplicate.
    """
    raw = read_raw(path)
    for sheet_name in schema.SHEET_NAMES:
        if sheet_name not in raw.sheets:
            raise SchemaError(
                f"{path} is missing the required {sheet_name!r} sheet", sheet=sheet_name
            )

    warnings: list[IntegrityWarning] = []
    nodes = _load_sheet_rows(raw.sheets[schema.NODES_SHEET], schema.NODES_SHEET_SPEC, warnings)
    keys = _load_sheet_rows(raw.sheets[schema.KEYS_SHEET], schema.KEYS_SHEET_SPEC, warnings)

    _check_unique_node_ids(nodes)
    _check_unique_key_refs(keys)

    return LoadedDatabase(path=path, nodes=nodes, keys=keys, warnings=tuple(warnings))


def verify(path: Path) -> tuple[IntegrityWarning, ...]:
    """Load a database purely to collect its integrity warnings.

    Args:
        path: Path to the ``.ods`` file.

    Returns:
        Every cached-vs-recomputed disagreement found while loading.

    Raises:
        SchemaError: If the file cannot be read or does not match its schema.
        DbValidationError: If any cell fails validation.
        DuplicateNodeError: If ``Nodes.node_id`` has a duplicate.
        DbIntegrityError: If ``Keys.key_ref`` has a duplicate.
    """
    return load_database(path).warnings


# ---------------------------------------------------------------------------
# Writing.
# ---------------------------------------------------------------------------


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
        nodes: The ``Nodes`` sheet's rows, in write order.
        keys: The ``Keys`` sheet's rows, in write order.

    Returns:
        The built document, ready to be serialized via ``doc.write(fileobj)``.
    """
    doc = OpenDocumentSpreadsheet()
    _add_common_styles(doc)
    width_styles = _add_column_width_styles(doc)
    _add_content_validations(doc)  # Must precede every <table:table> below.

    row_data: Mapping[str, Sequence[Mapping[str, str]]] = {
        schema.NODES_SHEET: nodes,
        schema.KEYS_SHEET: keys,
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
        nodes: The ``Nodes`` sheet's rows, in write order.
        keys: The ``Keys`` sheet's rows, in write order.
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


class OdsDatabase:
    """A read/modify/write session over one ODS file.

    Untyped at this layer: every row is a plain ``dict[str, str]`` keyed
    by column name. db-facade wraps this class with typed repositories.
    ``nodes.py`` and ``keys.py`` both wrap the *same* :class:`OdsDatabase`
    instance so that a single :meth:`save` call writes both sheets
    atomically, in one file, in one backup.

    Concurrency safety is opt-in via :meth:`lock`. A read-only session
    never needs it: every write replaces ``path`` with a single
    ``os.replace()`` (see :mod:`meshprovision.db.atomic_writer`), so a
    reader's :meth:`load` always sees a complete pre- or post-write file,
    never a torn one. A session that may run concurrently with another
    ``mesh`` process holding a write intent must call :meth:`lock`
    *before* :meth:`load` and hold it through :meth:`save` -- see
    :meth:`lock` and :meth:`save` for why the span matters.
    """

    def __init__(
        self, path: Path, *, backup_dir: Path | None = None, retention: int = DEFAULT_RETENTION
    ) -> None:
        """Initialize a session over ``path``, without reading it yet.

        Args:
            path: Path to the ``.ods`` file.
            backup_dir: Directory to store backups under on :meth:`save`.
            retention: Number of backups to retain on :meth:`save`.
        """
        self._path = path
        self._backup_dir = backup_dir
        self._retention = retention
        self._loaded = False
        self._is_dirty = False
        self._warnings: tuple[IntegrityWarning, ...] = ()
        self._rows: dict[str, tuple[Mapping[str, str], ...]] = {}
        self._lock_cm: contextlib.AbstractContextManager[None] | None = None

    @property
    def path(self) -> Path:
        """Path to the ``.ods`` file this session manages.

        Returns:
            The path passed to the constructor.
        """
        return self._path

    @property
    def loaded(self) -> bool:
        """Whether :meth:`load` has populated this session's rows.

        Returns:
            ``True`` once at least one successful load has completed.
        """
        return self._loaded

    @property
    def warnings(self) -> tuple[IntegrityWarning, ...]:
        """Integrity warnings collected by the most recent load.

        Returns:
            The warnings from the last :meth:`load`/:meth:`reload` call.
        """
        return self._warnings

    @property
    def locked(self) -> bool:
        """Whether this session currently holds the cross-process write lock.

        Returns:
            ``True`` between a successful :meth:`lock` call and the
            matching :meth:`unlock`.
        """
        return self._lock_cm is not None

    def lock(self, *, timeout: float | None = None) -> None:
        """Acquire the cross-process write lock for this database.

        Must be called before :meth:`load` -- locking after the read
        would leave a window in which another process's write lands
        between the two, reintroducing the stale-snapshot race this
        exists to close. A no-op if already held by this session.

        Args:
            timeout: Seconds to poll before giving up. ``None`` (the
                default) defers to :func:`meshprovision.db.locking.
                exclusive_lock`'s own resolution (an explicit argument,
                then the ``MESHPROVISION_LOCK_TIMEOUT`` environment
                variable, then a five-second default).

        Raises:
            DatabaseLockedError: If another process holds the lock and
                does not release it within the resolved timeout.
            AtomicWriteError: If the sidecar lock file itself cannot be
                created.
        """
        if self._lock_cm is not None:
            return
        cm = locking.exclusive_lock(self._path, timeout=timeout)
        cm.__enter__()
        self._lock_cm = cm

    def unlock(self) -> None:
        """Release the cross-process write lock. Idempotent.

        A no-op when the lock is not currently held by this session.
        """
        if self._lock_cm is None:
            return
        cm = self._lock_cm
        self._lock_cm = None
        cm.__exit__(None, None, None)

    def __enter__(self) -> OdsDatabase:
        """Enter as a context manager, unlocking on exit.

        Returns:
            This instance.
        """
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Release the write lock, if held. Delegates to :meth:`unlock`.

        Args:
            *exc_info: The exception triple, unused -- the lock is
                released the same way whether the block raised or not.
        """
        self.unlock()

    def load(self, *, force: bool = False) -> None:
        """Load the database from disk, unless already loaded.

        Args:
            force: When true, reload even if already loaded, discarding
                any unsaved in-memory changes.

        Raises:
            SchemaError: If the file cannot be read or does not match
                its schema.
            DbValidationError: If any cell fails validation.
            DuplicateNodeError: If ``Nodes.node_id`` has a duplicate.
            DbIntegrityError: If ``Keys.key_ref`` has a duplicate.
        """
        if self._loaded and not force:
            return
        loaded = load_database(self._path)
        self._rows = {schema.NODES_SHEET: loaded.nodes, schema.KEYS_SHEET: loaded.keys}
        self._warnings = loaded.warnings
        self._loaded = True
        self._is_dirty = False

    def reload(self) -> None:
        """Reload the database from disk, discarding unsaved changes.

        Raises:
            SchemaError: If the file cannot be read or does not match
                its schema.
            DbValidationError: If any cell fails validation.
            DuplicateNodeError: If ``Nodes.node_id`` has a duplicate.
            DbIntegrityError: If ``Keys.key_ref`` has a duplicate.
        """
        self.load(force=True)

    def rows(self, sheet: str) -> tuple[Mapping[str, str], ...]:
        """Return one sheet's current in-memory rows, loading first if needed.

        Args:
            sheet: The sheet name (``"Nodes"`` or ``"Keys"``).

        Returns:
            The sheet's rows.

        Raises:
            SchemaError: If ``sheet`` is not a known sheet name.
        """
        self.load()
        if sheet not in self._rows:
            raise SchemaError(f"Unknown sheet: {sheet!r}", sheet=sheet)
        return self._rows[sheet]

    def replace(self, sheet: str, rows: Sequence[Mapping[str, str]]) -> None:
        """Replace one sheet's in-memory rows. Does not touch disk.

        Args:
            sheet: The sheet name (``"Nodes"`` or ``"Keys"``).
            rows: The new full set of rows for ``sheet``.

        Raises:
            SchemaError: If ``sheet`` is not a known sheet name.
        """
        self.load()
        if sheet not in schema.SHEET_SPECS:
            raise SchemaError(f"Unknown sheet: {sheet!r}", sheet=sheet)
        self._rows[sheet] = tuple(dict(row) for row in rows)
        self._is_dirty = True

    def dirty(self) -> bool:
        """Whether there are in-memory changes not yet written to disk.

        Returns:
            ``True`` if :meth:`replace` has been called since the last
            load or save.
        """
        return self._is_dirty

    def save(self, *, backup: bool = True) -> None:
        """Write both sheets to disk atomically. A no-op when not dirty.

        Does **not** acquire the write lock itself -- a caller that may
        run concurrently with another ``mesh`` process must hold it
        across the whole load-modify-save cycle via :meth:`lock`, not
        just around this call: re-acquiring only here would leave this
        session's in-memory state stale relative to a write that landed
        after :meth:`load` but before :meth:`lock`, and locking again
        while already held would need re-entrancy bookkeeping this class
        does not have. :meth:`~meshprovision.cli.common.CliContext.
        open_database` does this for you.

        Args:
            backup: Whether to back up the current file before replacing
                it.

        Raises:
            AtomicWriteError: If the write or backup fails.
        """
        if not self._is_dirty:
            return
        write_database(
            self._path,
            nodes=self._rows.get(schema.NODES_SHEET, ()),
            keys=self._rows.get(schema.KEYS_SHEET, ()),
            backup=backup,
            backup_dir=self._backup_dir,
            retention=self._retention,
        )
        self._is_dirty = False

    @classmethod
    def create(
        cls, path: Path, *, overwrite: bool = False, backup_dir: Path | None = None
    ) -> OdsDatabase:
        """Create a brand-new, empty ODS database and open a session over it.

        Args:
            path: Path to create the ``.ods`` file at.
            overwrite: Whether to replace an existing file at ``path``.
            backup_dir: Directory to store future backups under.

        Returns:
            A loaded :class:`OdsDatabase` session over the new, empty
            database.

        Raises:
            SchemaError: If ``path`` already exists and ``overwrite`` is
                false.
            AtomicWriteError: If the write fails.
        """
        if path.exists() and not overwrite:
            raise SchemaError(f"{path} already exists; pass overwrite=True to replace it")
        create_empty(path, backup=False)
        instance = cls(path, backup_dir=backup_dir)
        instance.load(force=True)
        return instance
