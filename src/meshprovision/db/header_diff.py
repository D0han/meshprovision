"""Human-readable diagnosis for a mismatched ODS header row.

Split out of :mod:`meshprovision.db.ods` (already 1200+ lines) since this
is pure text formatting with no ODF/odfpy dependency: given the header
row actually found in a sheet and the column names
:mod:`meshprovision.db.schema` expects there, render an aligned
``cell``/``expected``/``found`` table plus a best-guess diagnosis of what
happened to the file -- a column deleted, inserted, renamed, or the
whole row reordered -- instead of a bare "expected (...), found (...)"
line dumping two raw Python tuples (which, for a 23-column sheet, can run
past a terminal's scrollback in one unreadable paragraph).
"""

from __future__ import annotations

import difflib
import itertools
from collections.abc import Sequence
from typing import Final

from meshprovision.db.schema import column_letter

__all__ = ["describe_header_mismatch"]

_MAX_CELL_DISPLAY: Final[int] = 60
"""Cap on how much of one cell's text is echoed into the diagnosis table.

A stray hand-edit can put arbitrarily long text in a header cell (see
the LibreOffice-comment-leak bug this module's caller was written to
diagnose); without a cap, one such cell reproduces the exact
wall-of-text problem this module exists to avoid.
"""

_ROLLBACK_HINT: Final[str] = (
    "Roll back if this wasn't intentional: `mesh db backup --list`, then "
    "`mesh db restore <backup>`."
)


def _truncate(value: str) -> str:
    """Shorten ``value`` to :data:`_MAX_CELL_DISPLAY` characters, marked with an ellipsis."""
    if len(value) <= _MAX_CELL_DISPLAY:
        return value
    return value[: _MAX_CELL_DISPLAY - 1] + "…"


def _cell_ref(index: int) -> str:
    """Render a 0-based column index as a header-row cell reference (``"E1"``)."""
    return f"{column_letter(index)}1"


def _render_table(found: Sequence[str], expected: Sequence[str]) -> list[str]:
    """Render the aligned ``cell``/``expected``/``found`` diagnosis table.

    Built from :class:`difflib.SequenceMatcher` opcodes over
    ``(found, expected)``: a run of matching columns collapses to one
    ``"A1-D1  (4 columns match)"`` line, and every other opcode
    (``replace``/``delete``/``insert``) expands to one table row per
    column touched, padding the shorter side with a placeholder so an
    inserted or deleted column still lines up against a real cell
    reference.

    Args:
        found: The header row actually read from the file.
        expected: The column names the schema expects, in order.

    Returns:
        The table's lines, including its own header row.
    """
    lines = ["  cell    expected             found in file"]
    matcher = difflib.SequenceMatcher(None, found, expected, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            count = i2 - i1
            ref = _cell_ref(i1) if count == 1 else f"{_cell_ref(i1)}-{_cell_ref(i2 - 1)}"
            noun, verb = ("column", "matches") if count == 1 else ("columns", "match")
            lines.append(f"  {ref:<7} ({count} {noun} {verb})")
            continue
        for offset, (found_name, expected_name) in enumerate(
            itertools.zip_longest(found[i1:i2], expected[j1:j2])
        ):
            found_display = _truncate(found_name) if found_name is not None else "(no cell)"
            expected_display = (
                _truncate(expected_name) if expected_name is not None else "(no column)"
            )
            lines.append(f"  {_cell_ref(i1 + offset):<7} {expected_display:<20} {found_display}")
    return lines


def _diagnose(found: Sequence[str], expected: Sequence[str]) -> str:
    """Guess what edit produced this mismatch, from the shape of the difference.

    Checked in order: a prefix match (columns added to the schema since
    this file was written -- the common "regenerate and re-apply"
    upgrade case), the same names present but reordered, then a single
    isolated deleted/inserted/renamed column. Anything else -- multiple
    simultaneous changes, or a header that shares no structure with the
    schema at all -- gets a generic fallback rather than a guess likely
    to be wrong.

    Args:
        found: The header row actually read from the file.
        expected: The column names the schema expects, in order.

    Returns:
        A one-or-two-sentence diagnosis, always ending with the
        rollback instructions.
    """
    if len(found) < len(expected) and tuple(expected[: len(found)]) == tuple(found):
        missing = expected[len(found) :]
        diagnosis = (
            f"Missing trailing column(s): {tuple(missing)!r}. If this file predates a "
            f"schema update, regenerate the example and re-apply your data, or add the "
            f"missing header cell(s) by hand: `python scripts/generate_example_db.py` "
            f"shows the current column layout."
        )
        return f"{diagnosis} {_ROLLBACK_HINT}"

    if sorted(found) == sorted(expected) and tuple(found) != tuple(expected):
        return f"The columns are all present but in the wrong order. {_ROLLBACK_HINT}"

    matcher = difflib.SequenceMatcher(None, found, expected, autojunk=False)
    changes = [op for op in matcher.get_opcodes() if op[0] != "equal"]
    if len(changes) == 1:
        tag, i1, i2, j1, j2 = changes[0]
        if tag == "insert" and j2 - j1 == 1:
            diagnosis = (
                f"Column {expected[j1]!r} looks deleted -- every later column shifted "
                f"left by one. Re-insert it at {_cell_ref(i1)}."
            )
            return f"{diagnosis} {_ROLLBACK_HINT}"
        if tag == "delete" and i2 - i1 == 1:
            diagnosis = (
                f"An extra column ({found[i1]!r}) looks inserted at {_cell_ref(i1)} -- "
                f"every later column shifted right by one. Remove it, or add it to the "
                f"schema first if it's intentional."
            )
            return f"{diagnosis} {_ROLLBACK_HINT}"
        if tag == "replace" and i2 - i1 == 1 and j2 - j1 == 1:
            diagnosis = (
                f"Column {_cell_ref(i1)} looks renamed: expected {expected[j1]!r}, "
                f"found {found[i1]!r}."
            )
            return f"{diagnosis} {_ROLLBACK_HINT}"

    return (
        f"The header doesn't match any of the usual edit patterns (a single deleted, "
        f"inserted, or renamed column, or the columns reordered). {_ROLLBACK_HINT}"
    )


def describe_header_mismatch(
    *, sheet: str, found: Sequence[str], expected: Sequence[str]
) -> tuple[str, str]:
    """Render a human-readable diagnosis of one sheet's mismatched header row.

    Args:
        sheet: The sheet's name, for the message's opening line.
        found: The header row actually read from the file. The caller is
            responsible for trimming trailing blank cells first --
            distinguishing "no cell" from "cell holds an empty string"
            is the caller's job, not this formatter's.
        expected: The column names :mod:`meshprovision.db.schema`
            expects, in order.

    Returns:
        A ``(message, hint)`` pair: ``message`` is the full aligned-table
        description, suitable as a
        :class:`~meshprovision.errors.SchemaError`'s main text; ``hint``
        is the best-guess diagnosis plus rollback instructions.
    """
    lines = [
        f"{sheet} sheet: the header row (row 1) does not match the expected layout.",
        "",
        *_render_table(found, expected),
        "",
        f"  {len(expected)} column(s) expected, {len(found)} found.",
    ]
    return "\n".join(lines), _diagnose(found, expected)
