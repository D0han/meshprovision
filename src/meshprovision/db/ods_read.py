"""Low-level odfpy reader for the ``Nodes``/``Keys`` ODS database.

This is the only place in the project that reads an ODS file's raw sheet
contents via ``odfpy``, treating every cell defensively as an explicit
string -- see :func:`_extract_cell`. It has no knowledge of
:mod:`meshprovision.db.schema`: validating and coercing this module's raw
:class:`DatabaseData` into a fully-typed database is
:mod:`meshprovision.db.ods`'s job, and building/writing an ODS document is
:mod:`meshprovision.db.ods_write`'s.

The ``valuetype``/``stringvalue``/``formula`` attribute names used below
were confirmed against odfpy's own attribute-name conversion for the
corresponding ``table:*`` grammar, not guessed -- see
:mod:`meshprovision.db.ods_write`'s docstring for how the file each of
these later reads back was itself built and verified.
"""

from __future__ import annotations

import io
import os
import xml.parsers.expat
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from odf import opendocument, teletype
from odf import table as odf_table
from odf import text as odf_text
from odf.element import Node

from meshprovision.errors import DbIntegrityError, DbReadError, SchemaError

__all__ = [
    "MAX_BLANK_ROWS",
    "MAX_COLUMNS",
    "MAX_ROW_REPEAT",
    "CellValue",
    "DatabaseData",
    "SheetData",
    "read_raw",
]

MAX_COLUMNS: Final[int] = 256
"""Upper bound on columns read per row, guarding against a runaway repeat count."""

MAX_BLANK_ROWS: Final[int] = 64
"""Maximum consecutive blank data rows read before stopping."""

MAX_ROW_REPEAT: Final[int] = 1024
"""Above this ``table:number-rows-repeated`` count, a blank row is treated as
LibreOffice's giant trailing filler row and read stops immediately."""

_TABLE_CELL_QNAME: Final[tuple[str, str]] = (odf_table.TABLENS, "table-cell")
_COVERED_CELL_QNAME: Final[tuple[str, str]] = (odf_table.TABLENS, "covered-table-cell")


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
        paragraph_text: The cell's own extracted paragraph text (see
            :func:`_cell_own_text`), always populated regardless of
            :attr:`value_type` -- unlike :attr:`text`, this is exactly
            what a human sees on screen for the cell, and is what a
            text-kind column's caller prefers instead of the
            ``office:string-value``-cached :attr:`text`: XML attribute-value
            normalization silently turns a literal tab in
            ``office:string-value`` into a space on the next parse, a
            corruption the paragraph's own ``text:tab`` run does not
            suffer. Not preferred generically for every column, because a
            formula-bearing column (for example ``key_ref``) must keep
            reading its cached *result* text, never a stale on-screen
            paragraph.
    """

    text: str
    formula: str | None = None
    value_type: str | None = None
    paragraph_text: str = ""


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


_PARAGRAPH_QNAMES: Final[frozenset[tuple[str, str]]] = frozenset(
    {(odf_text.TEXTNS, "p"), (odf_text.TEXTNS, "h")}
)
"""``text:p``/``text:h`` -- the only children of a cell that hold its own text.

A cell can also carry an ``office:annotation`` (a Calc comment) and, once
LibreOffice has touched the file, ``draw:*`` shapes anchoring that
comment's on-screen box. Neither is part of the cell's value, so
:func:`_cell_own_text` walks only these direct children instead of
recursing into the whole cell.
"""


def _cell_own_text(cell_elem: Any) -> str:
    r"""Extract a cell's own text, ignoring any attached comment.

    ``teletype.extractText`` recurses into *every* descendant, comment
    included -- harmless for a file this project wrote (whose header
    cells carry their column description as an ``office:annotation``,
    see :func:`meshprovision.db.ods_write._build_header_row`) only because
    ``_extract_cell`` prefers the cached ``office:string-value`` and never
    reaches this function for that cell. LibreOffice, on saving the file
    back, drops that cached ``office:string-value`` (it uses
    ``calcext:value-type`` instead) and reorders the annotation ahead of
    the text paragraph, so a plain "open, resize a column, save"
    round-trip through Calc used to make every touched cell's fallback
    path read as ``annotation-text + own-text`` -- for a header cell, the
    column's entire description prepended to its name. Reading only the
    cell's direct ``text:p``/``text:h`` children (still run through
    ``teletype.extractText`` each, since that is what correctly unwraps
    ``text:s``/``text:tab``/``text:line-break`` runs *within* one
    paragraph) fixes both the header and a hand-added comment on a data
    cell silently corrupting that cell's value.

    Args:
        cell_elem: The odfpy ``TableCell`` element.

    Returns:
        The cell's own paragraphs, joined with ``"\\n"`` (a cell written
        as several ``text:p`` children is a multi-line value).
    """
    paragraphs = [
        teletype.extractText(child)
        for child in cell_elem.childNodes
        if getattr(child, "nodeType", None) == Node.ELEMENT_NODE
        and child.qname in _PARAGRAPH_QNAMES
    ]
    return "\n".join(paragraphs)


def _extract_cell(cell_elem: Any) -> CellValue:
    """Defensively extract one ``table:table-cell``'s content.

    Prefers the cached ``office:string-value`` when the cell is
    explicitly typed as a string; otherwise falls back to the cell's own
    extracted paragraph text (see :func:`_cell_own_text`), which is what
    a numeric/date-typed cell (one LibreOffice may have coerced) still
    yields.

    Args:
        cell_elem: The odfpy ``TableCell`` element.

    Returns:
        The extracted :class:`CellValue`.
    """
    value_type: str | None = cell_elem.getAttribute("valuetype")
    formula: str | None = cell_elem.getAttribute("formula")
    string_value: str | None = cell_elem.getAttribute("stringvalue")
    own_text = _cell_own_text(cell_elem)
    text = string_value if value_type == "string" and string_value is not None else own_text
    return CellValue(text=text, formula=formula, value_type=value_type, paragraph_text=own_text)


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


def _has_data_below(row_elems: Sequence[Any], index: int) -> bool:
    """Whether any row after ``row_elems[index]`` holds a non-blank cell.

    Args:
        row_elems: The sheet's raw ``table:table-row`` elements.
        index: Index, within ``row_elems``, of the row just processed --
            the rows checked start at ``index + 1``.

    Returns:
        ``True`` if any remaining row has at least one non-blank cell.
    """
    return any(
        not all(not cell.text.strip() for cell in _read_row_cells(remaining))
        for remaining in row_elems[index + 1 :]
    )


def _gap_error(name: str, ods_row: int) -> DbIntegrityError:
    """Build the "blank-row gap with real data still below it" error.

    Args:
        name: The sheet's name.
        ods_row: The 1-based ODS row number where the blank-row gap
            starts.

    Returns:
        The constructed :class:`DbIntegrityError`, not yet raised.
    """
    return DbIntegrityError(
        f"{name} sheet has a run of more than {MAX_BLANK_ROWS} consecutive "
        f"blank rows starting at row {ods_row}, with real data still below "
        "it; stopped reading there rather than risk silently dropping it.",
        sheet=name,
        cell=f"{name}.A{ods_row}",
        hint=(
            "Open the file in LibreOffice Calc and delete the blank row "
            "block (Select rows -> Delete Rows, not just Delete Contents), "
            "then re-run mesh db verify."
        ),
    )


def _read_sheet(name: str, table_elem: Any) -> SheetData:
    """Read one ``table:table`` element into a :class:`SheetData`.

    Args:
        name: The sheet's name.
        table_elem: The odfpy ``Table`` element.

    Returns:
        The sheet's header and data rows.

    Raises:
        DbIntegrityError: If a run of more than :data:`MAX_BLANK_ROWS`
            consecutive blank rows is hit with non-blank rows still
            following it below -- whether that run is encoded as many
            separate blank row elements or as one element with a large
            ``table:number-rows-repeated`` count (including one above
            :data:`MAX_ROW_REPEAT`) -- see :data:`MAX_BLANK_ROWS`'s own
            docstring for why this can never be silently truncated.
    """
    row_elems = table_elem.getElementsByType(odf_table.TableRow)
    if not row_elems:
        return SheetData(name=name, header=(), rows=())

    header = tuple(cell.text for cell in _read_row_cells(row_elems[0]))

    data_rows: list[tuple[CellValue, ...]] = []
    consecutive_blank = 0
    for index, row_elem in enumerate(row_elems[1:], start=1):
        cells = _read_row_cells(row_elem)
        is_blank = all(not cell.text.strip() for cell in cells)
        repeat = _int_attr(row_elem, "numberrowsrepeated", default=1)

        if is_blank and repeat > MAX_ROW_REPEAT:
            if _has_data_below(row_elems, index):
                raise _gap_error(name, len(data_rows) + 2)
            # LibreOffice's giant trailing filler row: treat as end-of-data.
            break

        count = min(repeat, MAX_ROW_REPEAT)
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
            # A blank-row gap this long is exactly what an ordinary Calc
            # edit (delete a block of rows' contents, or insert rows to
            # make room) produces -- LibreOffice writes it as a single
            # <table:table-row table:number-rows-repeated="N"> element,
            # and real data can genuinely still follow it below. A gap
            # with nothing real below it (a trailing block of deleted
            # rows, which this project's own sorted writes always push to
            # the front, but a hand-edit could still leave trailing) is
            # harmless to stop at, same as before -- so only refuse when
            # something non-blank is actually waiting past the gap.
            if _has_data_below(row_elems, index):
                raise _gap_error(name, len(data_rows) + 2)  # +1 header, +1 for 1-indexing
            break

    return SheetData(name=name, header=header, rows=tuple(data_rows))


def _read_db_file(path: Path) -> tuple[bytes, os.stat_result]:
    """Read a database file's bytes and stat in one shot, off the same fd.

    Using ``fstat`` on the fd the bytes were read from means the stat
    describes exactly the inode whose content was read -- not whatever
    happens to be at ``path`` a moment later, which is what closes the
    validate-then-known-good-refresh race this exists for (see
    :func:`meshprovision.db.ods.load_database`).

    Args:
        path: Path to the ``.ods`` file.

    Returns:
        The file's raw bytes and its ``fstat`` result at read time.

    Raises:
        DbReadError: If ``path`` cannot be opened or read (permissions,
            I/O) -- distinct from a file that reads fine but is not
            valid ODF content, which :func:`read_raw` reports instead.
    """
    try:
        with path.open("rb") as fh:
            stat_result = os.fstat(fh.fileno())
            data = fh.read()
    except OSError as exc:
        raise DbReadError(
            f"Could not read {path}: {exc.strerror or exc}",
            hint=(
                "Check the file's owner and permissions (a `sudo mesh …` run leaves it "
                "root-owned: `sudo chown $USER <path>`). The file's content was not examined."
            ),
        ) from exc
    return data, stat_result


def read_raw(path: Path, *, data: bytes | None = None) -> DatabaseData:
    """Read an ODS file's raw sheet contents, with no schema validation.

    Args:
        path: Path to the ``.ods`` file. Used to name it in any error,
            and to load from disk when ``data`` is not given.
        data: The file's bytes, already read -- when given, parsed
            directly instead of re-opening ``path``. Used by
            :func:`meshprovision.db.ods.parse_database` so the bytes that
            are validated are exactly the bytes read once via
            :func:`_read_db_file`.

    Returns:
        The raw contents of every sheet found.

    Raises:
        SchemaError: If ``path``/``data`` cannot be parsed as an ODF
            spreadsheet.
    """
    try:
        doc = opendocument.load(io.BytesIO(data) if data is not None else str(path))
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
