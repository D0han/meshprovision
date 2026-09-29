"""Per-cell validation engine for the ODS database schema.

Validates and normalizes one cell's raw text against its
:class:`meshprovision.db.schema.ColumnSpec`, and validates a whole row at
once. This is the layer :mod:`meshprovision.db.ods` distrusts every cell's
raw text through on load.

**Never pandas, never implicit typing.** Every cell is read and written as
an explicit string. A hex node id like ``"1234567e8"`` must survive a
round trip byte-for-byte; nothing in this module ever coerces a cell value
through ``int()``/``float()`` except inside the ``INT``/``FLOAT`` column
kinds' own validators, and even then the canonical form re-emitted is a
string.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from typing import Final

from meshprovision import enums
from meshprovision.crypto.keys import decode_key, encode_key
from meshprovision.db import schema
from meshprovision.errors import (
    DbValidationError,
    EnumMappingError,
    KeyMaterialError,
    NodeIdError,
    SchemaError,
)
from meshprovision.nodeid import NodeId

__all__ = [
    "validate_cell",
    "validate_row",
]

_INT_PATTERN: Final[re.Pattern[str]] = re.compile(r"^-?[0-9]+$")


def _validate_node_id(sheet: str, row: int, spec: schema.ColumnSpec, stripped: str) -> str:
    """Validate a ``NODE_ID`` cell.

    Args:
        sheet: Name of the sheet containing the cell.
        row: 1-indexed row number of the cell.
        spec: The column's spec.
        stripped: The already-stripped, non-empty cell text.

    Returns:
        The canonical 8-digit lowercase hex form.

    Raises:
        DbValidationError: If ``stripped`` is not a valid node id.
    """
    try:
        return NodeId.from_hex(stripped).hex
    except NodeIdError as exc:
        raise DbValidationError(
            f"{spec.name!r} is not a valid node id: {exc.message}",
            sheet=sheet,
            row=row,
            column=spec.name,
            value=stripped,
            hint=(
                "Format this column as Text in LibreOffice (Format > Cells > Text) "
                "and re-enter the value."
            ),
        ) from exc


def _validate_enum(sheet: str, row: int, spec: schema.ColumnSpec, stripped: str) -> str:
    """Validate an ``ENUM`` cell, against either an enum table or a literal set.

    Args:
        sheet: Name of the sheet containing the cell.
        row: 1-indexed row number of the cell.
        spec: The column's spec.
        stripped: The already-stripped, non-empty cell text.

    Returns:
        The canonical name.

    Raises:
        DbValidationError: If ``stripped`` cannot be resolved.
    """
    if spec.enum_table is not None:
        table = enums.enum_tables()[spec.enum_table]
        try:
            return table.to_name(stripped)
        except EnumMappingError as exc:
            raise DbValidationError(
                f"{spec.name!r} has an unrecognized value: {stripped!r}",
                sheet=sheet,
                row=row,
                column=spec.name,
                value=stripped,
                hint=f"Known values: {', '.join(exc.known)}" if exc.known else None,
            ) from exc
    allowed = spec.allowed or ()
    if stripped not in allowed:
        raise DbValidationError(
            f"{spec.name!r} must be one of {', '.join(allowed)}, got {stripped!r}",
            sheet=sheet,
            row=row,
            column=spec.name,
            value=stripped,
        )
    return stripped


def _validate_int(sheet: str, row: int, spec: schema.ColumnSpec, stripped: str) -> str:
    """Validate an ``INT`` cell.

    Args:
        sheet: Name of the sheet containing the cell.
        row: 1-indexed row number of the cell.
        spec: The column's spec.
        stripped: The already-stripped, non-empty cell text.

    Returns:
        The canonical decimal integer text.

    Raises:
        DbValidationError: If ``stripped`` is not an integer, or is out of
            ``[spec.min_value, spec.max_value]``.
    """
    if not _INT_PATTERN.match(stripped):
        raise DbValidationError(
            f"{spec.name!r} must be an integer, got {stripped!r}",
            sheet=sheet,
            row=row,
            column=spec.name,
            value=stripped,
        )
    parsed = int(stripped)
    _check_range(sheet=sheet, row=row, spec=spec, parsed=float(parsed))
    return str(parsed)


def _validate_float(sheet: str, row: int, spec: schema.ColumnSpec, stripped: str) -> str:
    """Validate a ``FLOAT`` cell.

    Args:
        sheet: Name of the sheet containing the cell.
        row: 1-indexed row number of the cell.
        spec: The column's spec.
        stripped: The already-stripped, non-empty cell text.

    Returns:
        The canonical text: fixed to 7 decimal places, then trailing zeros
        and a trailing decimal point trimmed.

    Raises:
        DbValidationError: If ``stripped`` is not a finite number, or is
            out of ``[spec.min_value, spec.max_value]``.
    """
    try:
        parsed = float(stripped)
    except ValueError as exc:
        raise DbValidationError(
            f"{spec.name!r} must be a number, got {stripped!r}",
            sheet=sheet,
            row=row,
            column=spec.name,
            value=stripped,
        ) from exc
    if not math.isfinite(parsed):
        raise DbValidationError(
            f"{spec.name!r} must be a finite number, got {stripped!r}",
            sheet=sheet,
            row=row,
            column=spec.name,
            value=stripped,
        )
    _check_range(sheet=sheet, row=row, spec=spec, parsed=parsed)
    return f"{parsed:.7f}".rstrip("0").rstrip(".")


def _check_range(*, sheet: str, row: int, spec: schema.ColumnSpec, parsed: float) -> None:
    """Enforce ``spec.min_value``/``spec.max_value`` on a numeric value.

    Args:
        sheet: Name of the sheet containing the cell.
        row: 1-indexed row number of the cell.
        spec: The column's spec.
        parsed: The already-parsed numeric value.

    Raises:
        DbValidationError: If ``parsed`` is outside the configured bounds.
    """
    if spec.min_value is not None and parsed < spec.min_value:
        raise DbValidationError(
            f"{spec.name!r} must be >= {spec.min_value}, got {parsed}",
            sheet=sheet,
            row=row,
            column=spec.name,
            value=str(parsed),
        )
    if spec.max_value is not None and parsed > spec.max_value:
        raise DbValidationError(
            f"{spec.name!r} must be <= {spec.max_value}, got {parsed}",
            sheet=sheet,
            row=row,
            column=spec.name,
            value=str(parsed),
        )


def _validate_timestamp(sheet: str, row: int, spec: schema.ColumnSpec, stripped: str) -> str:
    """Validate a ``TIMESTAMP`` cell.

    Args:
        sheet: Name of the sheet containing the cell.
        row: 1-indexed row number of the cell.
        spec: The column's spec.
        stripped: The already-stripped, non-empty cell text.

    Returns:
        The canonical ``...Z`` UTC text, via :func:`meshprovision.db.schema.utc_timestamp`.

    Raises:
        DbValidationError: If ``stripped`` cannot be parsed as a timestamp.
    """
    try:
        parsed = schema.parse_timestamp(stripped)
    except ValueError as exc:
        raise DbValidationError(
            f"{spec.name!r} is not a valid timestamp: {stripped!r}",
            sheet=sheet,
            row=row,
            column=spec.name,
            value=stripped,
            hint="Use ISO-8601, e.g. 2026-08-25T03:14:10Z.",
        ) from exc
    return schema.utc_timestamp(parsed)


def _validate_base64_key(sheet: str, row: int, spec: schema.ColumnSpec, stripped: str) -> str:
    """Validate a ``BASE64_KEY`` cell.

    Args:
        sheet: Name of the sheet containing the cell.
        row: 1-indexed row number of the cell.
        spec: The column's spec.
        stripped: The already-stripped, non-empty cell text.

    Returns:
        The canonical base64 re-encoding of the decoded key bytes.

    Raises:
        DbValidationError: If ``stripped`` is not valid key material.
            ``value`` is always ``None`` on this error -- the offending
            text is key material and must never reach a message or log.
    """
    try:
        raw = decode_key(stripped, field=spec.name)
    except KeyMaterialError as exc:
        raise DbValidationError(
            f"{spec.name!r} is not valid key material: {exc.reason}",
            sheet=sheet,
            row=row,
            column=spec.name,
            value=None,
            hint=exc.hint,
        ) from exc
    return encode_key(raw)


def _validate_base64_key_list(sheet: str, row: int, spec: schema.ColumnSpec, stripped: str) -> str:
    """Validate a ``BASE64_KEY_LIST`` cell.

    Args:
        sheet: Name of the sheet containing the cell.
        row: 1-indexed row number of the cell.
        spec: The column's spec.
        stripped: The already-stripped, non-empty cell text.

    Returns:
        Each element's canonical base64 re-encoding, de-duplicated
        (preserving first-seen order) and re-joined with
        :data:`meshprovision.db.schema.LIST_SEPARATOR`. De-duplication
        happens *after* canonicalization, so two spellings of one key --
        bare base64 and the :data:`~meshprovision.crypto.keys.B64_KEY_PREFIX`
        form ``decode_key`` also accepts -- collapse to a single element
        rather than surviving as two.

    Raises:
        DbValidationError: If any element is not valid key material.
            ``value`` is always ``None`` on this error -- an element is
            key material and must never reach a message or log.
    """
    seen: set[str] = set()
    canonical: list[str] = []
    for element in schema.normalize_ref_list(stripped):
        try:
            raw = decode_key(element, field=spec.name)
        except KeyMaterialError as exc:
            raise DbValidationError(
                f"{spec.name!r} contains invalid key material: {exc.reason}",
                sheet=sheet,
                row=row,
                column=spec.name,
                value=None,
                hint=exc.hint,
            ) from exc
        encoded = encode_key(raw)
        if encoded in seen:
            continue
        seen.add(encoded)
        canonical.append(encoded)
    return schema.format_ref_list(canonical)


def _validate_key_ref(sheet: str, row: int, spec: schema.ColumnSpec, stripped: str) -> str:
    """Validate a ``KEY_REF`` cell.

    Args:
        sheet: Name of the sheet containing the cell.
        row: 1-indexed row number of the cell.
        spec: The column's spec.
        stripped: The already-stripped, non-empty cell text.

    Returns:
        ``stripped`` unchanged.

    Raises:
        DbValidationError: If ``stripped`` does not match
            :data:`meshprovision.db.schema.REF_PATTERN`.
    """
    if not schema.REF_PATTERN.match(stripped):
        raise DbValidationError(
            f"{spec.name!r} does not look like a key reference: {stripped!r}",
            sheet=sheet,
            row=row,
            column=spec.name,
            value=stripped,
        )
    return stripped


def _validate_key_ref_list(sheet: str, row: int, spec: schema.ColumnSpec, stripped: str) -> str:
    """Validate a ``KEY_REF_LIST`` cell.

    Args:
        sheet: Name of the sheet containing the cell.
        row: 1-indexed row number of the cell.
        spec: The column's spec.
        stripped: The already-stripped, non-empty cell text.

    Returns:
        The normalized, de-duplicated list, re-joined with
        :data:`meshprovision.db.schema.LIST_SEPARATOR`.

    Raises:
        DbValidationError: If any element does not match
            :data:`meshprovision.db.schema.REF_PATTERN`.
    """
    refs = schema.normalize_ref_list(stripped)
    for ref in refs:
        if not schema.REF_PATTERN.match(ref):
            raise DbValidationError(
                f"{spec.name!r} contains an invalid reference: {ref!r}",
                sheet=sheet,
                row=row,
                column=spec.name,
                value=stripped,
            )
    return schema.format_ref_list(refs)


def _validate_pin(sheet: str, row: int, spec: schema.ColumnSpec, stripped: str) -> str:
    """Validate a ``PIN`` cell.

    Args:
        sheet: Name of the sheet containing the cell.
        row: 1-indexed row number of the cell.
        spec: The column's spec.
        stripped: The already-stripped, non-empty cell text.

    Returns:
        ``stripped`` unchanged (leading zeros are significant).

    Raises:
        DbValidationError: If ``stripped`` is not exactly
            :data:`meshprovision.db.schema.BLE_PIN_LENGTH` ASCII digits.
            ``value`` is always ``None`` on this error -- a PIN is secret
            material.
    """
    if not (stripped.isascii() and stripped.isdigit() and len(stripped) == schema.BLE_PIN_LENGTH):
        raise DbValidationError(
            f"{spec.name!r} must be exactly {schema.BLE_PIN_LENGTH} ASCII digits",
            sheet=sheet,
            row=row,
            column=spec.name,
            value=None,
        )
    return stripped


def validate_cell(*, sheet: str, row: int, spec: schema.ColumnSpec, value: str) -> str:
    """Validate and normalize one cell's raw text against its column spec.

    Every kind first strips the input. An empty, required cell is a
    validation error; an empty, non-required cell short-circuits to
    ``""`` with no further checks.

    Args:
        sheet: Name of the sheet containing the cell.
        row: 1-indexed row number of the cell.
        spec: The column's spec.
        value: The cell's raw text.

    Returns:
        The normalized, canonical cell text.

    Raises:
        DbValidationError: If ``value`` fails validation for ``spec.kind``.
        SchemaError: If ``spec.kind`` is not a recognized
            :class:`meshprovision.db.schema.ColumnKind` (unreachable for
            any :class:`~meshprovision.db.schema.ColumnKind` member; guards
            against a future member left unhandled here).
    """
    stripped = value.strip()
    if not stripped:
        if spec.required:
            raise DbValidationError(
                f"{spec.name!r} is required but is empty",
                sheet=sheet,
                row=row,
                column=spec.name,
                value=None if spec.secret else "",
            )
        return ""
    if spec.kind is schema.ColumnKind.TEXT:
        return stripped
    if spec.kind is schema.ColumnKind.NODE_ID:
        return _validate_node_id(sheet, row, spec, stripped)
    if spec.kind is schema.ColumnKind.ENUM:
        return _validate_enum(sheet, row, spec, stripped)
    if spec.kind is schema.ColumnKind.INT:
        return _validate_int(sheet, row, spec, stripped)
    if spec.kind is schema.ColumnKind.FLOAT:
        return _validate_float(sheet, row, spec, stripped)
    if spec.kind is schema.ColumnKind.TIMESTAMP:
        return _validate_timestamp(sheet, row, spec, stripped)
    if spec.kind is schema.ColumnKind.BASE64_KEY:
        return _validate_base64_key(sheet, row, spec, stripped)
    if spec.kind is schema.ColumnKind.BASE64_KEY_LIST:
        return _validate_base64_key_list(sheet, row, spec, stripped)
    if spec.kind is schema.ColumnKind.KEY_REF:
        return _validate_key_ref(sheet, row, spec, stripped)
    if spec.kind is schema.ColumnKind.KEY_REF_LIST:
        return _validate_key_ref_list(sheet, row, spec, stripped)
    if spec.kind is schema.ColumnKind.PIN:
        return _validate_pin(sheet, row, spec, stripped)
    raise SchemaError(  # pragma: no cover - exhaustive over ColumnKind members
        f"Unhandled column kind: {spec.kind!r}", sheet=sheet, column=spec.name
    )


def validate_row(
    sheet_spec: schema.SheetSpec, row: int, values: Mapping[str, str]
) -> dict[str, str]:
    """Validate every column of one row.

    Args:
        sheet_spec: The sheet the row belongs to.
        row: 1-indexed row number, used in any raised error.
        values: The row's raw ``{column_name: text}`` values. A missing
            column name is treated as an empty cell.

    Returns:
        A new ``dict`` of ``{column_name: normalized_value}``, covering
        every column in ``sheet_spec.columns``.

    Raises:
        DbValidationError: If any cell fails validation.
    """
    return {
        col.name: validate_cell(
            sheet=sheet_spec.name, row=row, spec=col, value=values.get(col.name, "")
        )
        for col in sheet_spec.columns
    }
