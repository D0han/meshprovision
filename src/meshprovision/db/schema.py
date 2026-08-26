"""Single source of truth for the ODS database shape.

This module owns everything about the two-sheet ``Nodes``/``Keys`` layout
that is *not* byte-level ODF mechanics (that lives in
:mod:`meshprovision.db.ods`): the column specs, the enums used across the
schema, per-cell validation rules, the dropdown value sets used by the
generated ``table:content-validation`` elements, the OpenFormula templates
for derived columns, and the pure recompute functions
:mod:`meshprovision.db.ods` uses to distrust a formula's cached result on
every load.

**Never pandas, never implicit typing.** Every cell is read and written as
an explicit string. A hex node id like ``"1234567e8"`` must survive a
round trip byte-for-byte; nothing in this module ever coerces a cell value
through ``int()``/``float()`` except inside the ``INT``/``FLOAT`` column
kinds' own validators, and even then the canonical form re-emitted is a
string.

**Formula columns are derived, never authoritative.** A column with a
:class:`FormulaSpec` records both an OpenFormula template (for
:mod:`meshprovision.db.ods` to write into the cell alongside a cached
display value) and a pure ``recompute`` function. On every load, the
recomputed value wins over whatever was cached in the cell -- this is what
makes a stale LibreOffice cache or a hand-edit that broke a formula a
*warning*, not silent data corruption. ``Nodes.authorized_admin_keys`` is
the one deliberate exception: it has no :class:`FormulaSpec` at all,
because it records what was actually written to the device's
``security.adminKey``, which is not a function of any other cell on the
row. Its integrity is enforced instead by ``KEY_REF_LIST`` validation
here, plus db-facade's cross-check that every listed reference resolves
to a real row in the ``Keys`` sheet.

**OpenFormula list-validity condition, verified.** The exact grammar for
``table:content-validation``'s ``table:condition`` attribute in list mode
is confirmed directly from the OASIS OpenDocument v1.3 Part 3 schema
specification (the ``<table:content-validation>`` "defined conditions"
list): *"cell-content-is-in-list(list), where list is one or more string
entries, separated by ';' (U+003B, SEMICOLON), or an expression."* This
was cross-checked against LibreOffice's own importer
(``sc/source/filter/xml/XMLConverter.cxx``, the
``XML_COND_ISINLIST`` -> ``"cell-content-is-in-list"`` condition table
entry parsed by ``ScXMLConditionHelper::parseCondition``), which agrees.
:func:`validation_condition` implements exactly this: semicolon-separated,
double-quoted string values with inner ``"`` doubled. This is advisory
only -- :func:`validate_cell` re-validates every value independently
regardless of what LibreOffice's dropdown ever offered.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from meshprovision import chipsets, enums
from meshprovision.crypto.keys import decode_key, encode_key
from meshprovision.errors import (
    DbValidationError,
    EnumMappingError,
    KeyMaterialError,
    NodeIdError,
    SchemaError,
)
from meshprovision.nodeid import NodeId

__all__ = [
    "BLE_PIN_LENGTH",
    "KEYS_SHEET",
    "KEYS_SHEET_SPEC",
    "KEY_REF_SUFFIXES",
    "LIST_SEPARATOR",
    "NODES_SHEET",
    "NODES_SHEET_SPEC",
    "REF_PATTERN",
    "SCHEMA_VERSION",
    "SHEET_NAMES",
    "SHEET_SPECS",
    "ColumnKind",
    "ColumnSpec",
    "FirmwareType",
    "FormulaSpec",
    "KeyType",
    "SheetSpec",
    "allowed_values",
    "column_letter",
    "format_ref_list",
    "formula_for",
    "normalize_ref_list",
    "parse_timestamp",
    "recompute_derived",
    "ref_for",
    "utc_timestamp",
    "validate_cell",
    "validate_row",
    "validation_condition",
]

SCHEMA_VERSION: Final[int] = 1
"""Version of the ODS schema this module implements."""

NODES_SHEET: Final[str] = "Nodes"
"""Name of the sheet holding one row per mesh node."""

KEYS_SHEET: Final[str] = "Keys"
"""Name of the sheet holding one row per key (admin public/private, PSK)."""

SHEET_NAMES: Final[tuple[str, str]] = (NODES_SHEET, KEYS_SHEET)
"""Both sheet names, in the order they must appear in the workbook."""

LIST_SEPARATOR: Final[str] = ";"
"""Separator used inside a ``KEY_REF_LIST`` cell (``Nodes.authorized_admin_keys``)."""

BLE_PIN_LENGTH: Final[int] = 6
"""Exact digit count of a BLE pairing PIN (``bluetooth.fixed_pin``)."""

REF_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
"""Shape shared with ``config/template.py``'s admin-node reference pattern.

Matches both a bare ``node_id`` hex value and a template ``admin_nodes``
reference name -- both are valid ``owner_node_id``/``key_ref`` values.
"""

_INT_PATTERN: Final[re.Pattern[str]] = re.compile(r"^-?[0-9]+$")


class FirmwareType(StrEnum):
    """Firmware flavor running on a node, as recorded by the operator."""

    VANILLA = "vanilla"
    LORANET = "loranet"
    OTHER = "other"


class KeyType(StrEnum):
    """Kind of key material a ``Keys`` sheet row holds."""

    ADMIN_PUBLIC = "admin_public"
    ADMIN_PRIVATE = "admin_private"
    CHANNEL_PSK = "channel_psk"


class ColumnKind(StrEnum):
    """Content-validation kind of one column, driving :func:`validate_cell`."""

    TEXT = "text"
    NODE_ID = "node_id"
    ENUM = "enum"
    INT = "int"
    FLOAT = "float"
    TIMESTAMP = "timestamp"
    BASE64_KEY = "base64_key"
    KEY_REF = "key_ref"
    KEY_REF_LIST = "key_ref_list"
    PIN = "pin"


KEY_REF_SUFFIXES: Final[Mapping[KeyType, str]] = MappingProxyType(
    {
        KeyType.ADMIN_PUBLIC: "_pub",
        KeyType.ADMIN_PRIVATE: "_priv",
        KeyType.CHANNEL_PSK: "_psk",
    }
)
"""Suffix appended to an owner reference to form a ``key_ref`` for each :class:`KeyType`."""


@dataclass(frozen=True, slots=True)
class FormulaSpec:
    """An OpenFormula template plus the pure function that recomputes it.

    Attributes:
        template: An OpenFormula expression containing a literal ``{row}``
            placeholder for the 1-based ODS row number, or ``None`` when
            the derived value cannot be expressed as an ODF formula (for
            example ``main_chipset``, which needs a Python lookup table).
        sources: Names of the source columns this value is derived from,
            used only in warning text when a cached value disagrees.
        recompute: A pure function from the row's already-validated
            values to the recomputed value for this column. Never raises;
            returns ``""`` when its source columns are not (yet) present.
    """

    template: str | None
    sources: tuple[str, ...]
    recompute: Callable[[Mapping[str, str]], str]


@dataclass(frozen=True, slots=True)
class ColumnSpec:
    """The full content-validation contract for one column.

    Attributes:
        name: The machine-readable column name, written as the header
            cell's text.
        description: A longer human-readable description, written as an
            ``office:annotation`` on the header cell.
        kind: Which validation/normalization rules apply to this column.
        required: Whether an empty cell is a validation error.
        allowed: A literal, fixed set of accepted values (mutually
            exclusive with ``enum_table``).
        enum_table: Name of a table from :func:`meshprovision.enums.enum_tables`
            (``"role"``, ``"hw_model"``, or ``"region"``) this column's
            allowed values are resolved from.
        validation_name: Name of the ``table:content-validation`` element
            to attach to this column's cells, or ``None`` for no dropdown.
        formula: The derived-value contract for this column, or ``None``
            when the column holds an authoritative (non-derived) value.
        width: ODF column width, e.g. ``"1.0in"``.
        min_value: Inclusive lower bound for ``INT``/``FLOAT`` columns.
        max_value: Inclusive upper bound for ``INT``/``FLOAT`` columns.
        secret: Whether this column holds material that must never be
            echoed back in an error message or log line.
    """

    name: str
    description: str
    kind: ColumnKind
    required: bool = False
    allowed: tuple[str, ...] | None = None
    enum_table: str | None = None
    validation_name: str | None = None
    formula: FormulaSpec | None = None
    width: str = "1.0in"
    min_value: float | None = None
    max_value: float | None = None
    secret: bool = False


@dataclass(frozen=True, slots=True)
class SheetSpec:
    """The full column layout of one sheet.

    Attributes:
        name: The sheet name.
        columns: The sheet's columns, in left-to-right order.
        key_column: Name of the column that is this sheet's primary key.
    """

    name: str
    columns: tuple[ColumnSpec, ...]
    key_column: str

    def column_names(self) -> tuple[str, ...]:
        """Return every column name, in left-to-right order.

        Returns:
            A tuple of column names.
        """
        return tuple(col.name for col in self.columns)

    def column(self, name: str) -> ColumnSpec:
        """Look up one column by name.

        Args:
            name: The column name to look up.

        Returns:
            The matching :class:`ColumnSpec`.

        Raises:
            SchemaError: If no column named ``name`` exists on this sheet.
        """
        for col in self.columns:
            if col.name == name:
                return col
        raise SchemaError(
            f"Sheet {self.name!r} has no column named {name!r}",
            sheet=self.name,
            column=name,
        )

    def column_index(self, name: str) -> int:
        """Look up one column's 0-based position.

        Args:
            name: The column name to look up.

        Returns:
            The column's 0-based index.

        Raises:
            SchemaError: If no column named ``name`` exists on this sheet.
        """
        for index, col in enumerate(self.columns):
            if col.name == name:
                return index
        raise SchemaError(
            f"Sheet {self.name!r} has no column named {name!r}",
            sheet=self.name,
            column=name,
        )

    def letter(self, name: str) -> str:
        """Look up one column's spreadsheet letter (``"A"``, ``"B"``, ...).

        Args:
            name: The column name to look up.

        Returns:
            The column's letter, via :func:`column_letter`.

        Raises:
            SchemaError: If no column named ``name`` exists on this sheet.
        """
        return column_letter(self.column_index(name))

    def derived_columns(self) -> tuple[ColumnSpec, ...]:
        """Return every column that has a :class:`FormulaSpec`.

        Returns:
            The subset of :attr:`columns` whose ``formula`` is not
            ``None``, in left-to-right order.
        """
        return tuple(col for col in self.columns if col.formula is not None)


# ---------------------------------------------------------------------------
# Derived-column recompute functions.
#
# Defined before the sheet specs below since a FormulaSpec captures the
# function object directly (not a lazy lookup) at module import time.
# ---------------------------------------------------------------------------


def _suffix_recompute(suffix: str) -> Callable[[Mapping[str, str]], str]:
    """Build a recompute function for a ``"{node_id}{suffix}"`` derived column.

    Args:
        suffix: The literal suffix to append (for example ``"_priv"``).

    Returns:
        A pure function from a ``Nodes`` row to the derived value.
    """

    def _recompute(row: Mapping[str, str]) -> str:
        node_id = row.get("node_id", "")
        return f"{node_id}{suffix}" if node_id else ""

    return _recompute


def _recompute_key_ref(row: Mapping[str, str]) -> str:
    """Recompute a ``Keys.key_ref`` value from its owner and key type.

    Args:
        row: The ``Keys`` sheet row's already-validated values.

    Returns:
        ``ref_for(owner_node_id, key_type)``, or ``""`` when either source
        column is absent or ``key_type`` is not a known :class:`KeyType`.
    """
    owner = row.get("owner_node_id", "")
    key_type_raw = row.get("key_type", "")
    if not owner or not key_type_raw:
        return ""
    try:
        return ref_for(owner, KeyType(key_type_raw))
    except ValueError:
        return ""


def _recompute_main_chipset(row: Mapping[str, str]) -> str:
    """Recompute ``Nodes.main_chipset`` from ``hw_model``.

    Deliberately code-only (``FormulaSpec.template=None``): a hw_model ->
    chipset lookup is not expressible in OpenFormula without shipping a
    lookup sheet. It still goes through the same recompute/compare/warn
    path as every other derived column.

    Args:
        row: The ``Nodes`` sheet row's already-validated values.

    Returns:
        ``meshprovision.chipsets.main_chipset(hw_model)``, or ``""`` when
        ``hw_model`` is absent.
    """
    hw_model = row.get("hw_model", "")
    if not hw_model:
        return ""
    return chipsets.main_chipset(hw_model)


# ---------------------------------------------------------------------------
# Sheet specs.
# ---------------------------------------------------------------------------

NODES_SHEET_SPEC: Final[SheetSpec] = SheetSpec(
    name=NODES_SHEET,
    key_column="node_id",
    columns=(
        ColumnSpec(
            name="node_id",
            description=(
                "Primary key. 8 lowercase hex digits, no leading '!' -- the same "
                "form lorastats.pl's NodeId field uses."
            ),
            kind=ColumnKind.NODE_ID,
            required=True,
            width="1.0in",
        ),
        ColumnSpec(
            name="short_name",
            description="Device short name (<=4 bytes UTF-8), as sent to the node.",
            kind=ColumnKind.TEXT,
            width="0.8in",
        ),
        ColumnSpec(
            name="long_name",
            description="Device long name (<=39 bytes UTF-8), as sent to the node.",
            kind=ColumnKind.TEXT,
            width="2.2in",
        ),
        ColumnSpec(
            name="hw_model",
            description="Hardware model, from the installed HardwareModel protobuf enum.",
            kind=ColumnKind.ENUM,
            enum_table="hw_model",
            validation_name="mp_hw_model",
            width="1.6in",
        ),
        ColumnSpec(
            name="main_chipset",
            description=(
                "Main MCU/SoC for hw_model, derived by code "
                "(meshprovision.chipsets.main_chipset). Not expressible as an ODF "
                "formula, so this column has no OpenFormula template -- see the "
                "module docstring."
            ),
            kind=ColumnKind.TEXT,
            width="1.0in",
            formula=FormulaSpec(
                template=None,
                sources=("hw_model",),
                recompute=_recompute_main_chipset,
            ),
        ),
        ColumnSpec(
            name="firmware_type",
            description="Firmware flavor running on this node: vanilla, loranet, or other.",
            kind=ColumnKind.ENUM,
            allowed=tuple(FirmwareType),
            validation_name="mp_firmware_type",
            width="1.1in",
        ),
        ColumnSpec(
            name="firmware_version",
            description="Firmware version string as reported by the device.",
            kind=ColumnKind.TEXT,
            width="1.3in",
        ),
        ColumnSpec(
            name="gps_lat",
            description="Latitude in decimal degrees, [-90, 90].",
            kind=ColumnKind.FLOAT,
            min_value=-90.0,
            max_value=90.0,
            width="1.0in",
        ),
        ColumnSpec(
            name="gps_lon",
            description="Longitude in decimal degrees, [-180, 180].",
            kind=ColumnKind.FLOAT,
            min_value=-180.0,
            max_value=180.0,
            width="1.0in",
        ),
        ColumnSpec(
            name="gps_alt",
            description="Altitude in meters.",
            kind=ColumnKind.INT,
            width="0.8in",
        ),
        ColumnSpec(
            name="first_added_ts",
            description="UTC timestamp this node was first added to the database.",
            kind=ColumnKind.TIMESTAMP,
            width="1.5in",
        ),
        ColumnSpec(
            name="last_updated_ts",
            description="UTC timestamp this node's record was last updated.",
            kind=ColumnKind.TIMESTAMP,
            width="1.5in",
        ),
        ColumnSpec(
            name="authorized_admin_keys",
            description=(
                "Semicolon-separated key_ref list of admin public keys authorized "
                "on this node's security.adminKey. NOT a formula: this records what "
                "was actually written to the device, which is not a function of any "
                "other cell on this row. Integrity is enforced by KEY_REF_LIST "
                "validation plus db-facade's cross-check that every listed ref "
                "resolves in the Keys sheet."
            ),
            kind=ColumnKind.KEY_REF_LIST,
            width="2.2in",
        ),
        ColumnSpec(
            name="notes",
            description="Free-form operator notes.",
            kind=ColumnKind.TEXT,
            width="3.0in",
        ),
        ColumnSpec(
            name="private_key_ref",
            description=(
                "Reference to this node's private key row in the Keys sheet (node_id + '_priv')."
            ),
            kind=ColumnKind.KEY_REF,
            width="1.4in",
            formula=FormulaSpec(
                template='of:=[.A{row}]&"_priv"',
                sources=("node_id",),
                recompute=_suffix_recompute("_priv"),
            ),
        ),
        ColumnSpec(
            name="public_key_ref",
            description=(
                "Reference to this node's public key row in the Keys sheet (node_id + '_pub')."
            ),
            kind=ColumnKind.KEY_REF,
            width="1.4in",
            formula=FormulaSpec(
                template='of:=[.A{row}]&"_pub"',
                sources=("node_id",),
                recompute=_suffix_recompute("_pub"),
            ),
        ),
        ColumnSpec(
            name="role",
            description="Device role, from the installed Config.DeviceConfig.Role protobuf enum.",
            kind=ColumnKind.ENUM,
            enum_table="role",
            validation_name="mp_role",
            width="1.3in",
        ),
        ColumnSpec(
            name="region",
            description=(
                "LoRa region, from the installed Config.LoRaConfig.RegionCode protobuf enum."
            ),
            kind=ColumnKind.ENUM,
            enum_table="region",
            validation_name="mp_region",
            width="1.0in",
        ),
        ColumnSpec(
            name="channel_psk_ref",
            description=(
                "Reference to this node's channel PSK row in the Keys sheet (node_id + '_psk')."
            ),
            kind=ColumnKind.KEY_REF,
            width="1.4in",
            formula=FormulaSpec(
                template='of:=[.A{row}]&"_psk"',
                sources=("node_id",),
                recompute=_suffix_recompute("_psk"),
            ),
        ),
        ColumnSpec(
            name="ble_pin",
            description=(
                "6-digit BLE pairing PIN (bluetooth.fixed_pin). Stored as text so "
                "leading zeros survive; never logged or displayed."
            ),
            kind=ColumnKind.PIN,
            width="0.8in",
            secret=True,
        ),
    ),
)

KEYS_SHEET_SPEC: Final[SheetSpec] = SheetSpec(
    name=KEYS_SHEET,
    key_column="key_ref",
    columns=(
        ColumnSpec(
            name="key_ref",
            description=(
                "Primary key. Derived as owner_node_id plus a suffix determined by "
                "key_type (_pub/_priv/_psk)."
            ),
            kind=ColumnKind.KEY_REF,
            required=True,
            width="1.6in",
            formula=FormulaSpec(
                template=(
                    'of:=[.B{row}]&IF([.C{row}]="admin_public";"_pub";'
                    'IF([.C{row}]="admin_private";"_priv";"_psk"))'
                ),
                sources=("owner_node_id", "key_type"),
                recompute=_recompute_key_ref,
            ),
        ),
        ColumnSpec(
            name="owner_node_id",
            description=(
                "The node this key belongs to: either a node_id hex value, or a "
                "template admin_nodes reference."
            ),
            kind=ColumnKind.KEY_REF,
            required=True,
            width="1.6in",
        ),
        ColumnSpec(
            name="key_type",
            description="Kind of key this row holds: admin_public, admin_private, or channel_psk.",
            kind=ColumnKind.ENUM,
            allowed=tuple(KeyType),
            validation_name="mp_key_type",
            required=True,
            width="1.3in",
        ),
        ColumnSpec(
            name="key_value",
            description=(
                "Base64-encoded raw key material (32 bytes, X25519). Never logged or displayed."
            ),
            kind=ColumnKind.BASE64_KEY,
            required=True,
            secret=True,
            width="3.4in",
        ),
        ColumnSpec(
            name="created_ts",
            description="UTC timestamp this key was recorded.",
            kind=ColumnKind.TIMESTAMP,
            width="1.5in",
        ),
    ),
)

SHEET_SPECS: Final[Mapping[str, SheetSpec]] = MappingProxyType(
    {NODES_SHEET: NODES_SHEET_SPEC, KEYS_SHEET: KEYS_SHEET_SPEC}
)
"""Both sheet specs, keyed by sheet name."""


# ---------------------------------------------------------------------------
# Column letters and dropdown value sets.
# ---------------------------------------------------------------------------


def column_letter(index: int) -> str:
    """Convert a 0-based column index to a spreadsheet column letter.

    Args:
        index: A 0-based column index (``0`` -> ``"A"``).

    Returns:
        The column letter, extending past ``"Z"`` into ``"AA"``, ``"AB"``,
        and so on for ``index >= 26``.

    Raises:
        SchemaError: If ``index`` is negative.
    """
    if index < 0:
        raise SchemaError(f"Column index must be non-negative, got {index}")
    position = index + 1
    letters = ""
    while position > 0:
        position, remainder = divmod(position - 1, 26)
        letters = chr(ord("A") + remainder) + letters
    return letters


def allowed_values(spec: ColumnSpec) -> tuple[str, ...] | None:
    """Resolve a column's fixed value set, from either source.

    Args:
        spec: The column to resolve values for.

    Returns:
        ``spec.allowed`` when set; otherwise the names from
        ``enums.enum_tables()[spec.enum_table]`` when ``spec.enum_table``
        is set; otherwise ``None`` (no fixed value set, no dropdown).
    """
    if spec.allowed is not None:
        return spec.allowed
    if spec.enum_table is not None:
        return enums.enum_tables()[spec.enum_table].names()
    return None


def validation_condition(values: Sequence[str]) -> str:
    """Build an ODF ``table:condition`` string for a list-validity dropdown.

    See the module docstring for how this grammar was verified.

    Args:
        values: The allowed values, in the order they should be offered.

    Returns:
        For example ``'of:cell-content-is-in-list("A";"B")'``, with any
        literal ``"`` inside a value doubled per the OpenFormula string
        literal escaping rule.
    """
    quoted = (f'"{value.replace(chr(34), chr(34) * 2)}"' for value in values)
    return "of:cell-content-is-in-list(" + ";".join(quoted) + ")"


# ---------------------------------------------------------------------------
# Cell validation.
# ---------------------------------------------------------------------------


def _validate_node_id(sheet: str, row: int, spec: ColumnSpec, stripped: str) -> str:
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


def _validate_enum(sheet: str, row: int, spec: ColumnSpec, stripped: str) -> str:
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


def _validate_int(sheet: str, row: int, spec: ColumnSpec, stripped: str) -> str:
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


def _validate_float(sheet: str, row: int, spec: ColumnSpec, stripped: str) -> str:
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


def _check_range(*, sheet: str, row: int, spec: ColumnSpec, parsed: float) -> None:
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


def _validate_timestamp(sheet: str, row: int, spec: ColumnSpec, stripped: str) -> str:
    """Validate a ``TIMESTAMP`` cell.

    Args:
        sheet: Name of the sheet containing the cell.
        row: 1-indexed row number of the cell.
        spec: The column's spec.
        stripped: The already-stripped, non-empty cell text.

    Returns:
        The canonical ``...Z`` UTC text, via :func:`utc_timestamp`.

    Raises:
        DbValidationError: If ``stripped`` cannot be parsed as a timestamp.
    """
    try:
        parsed = parse_timestamp(stripped)
    except ValueError as exc:
        raise DbValidationError(
            f"{spec.name!r} is not a valid timestamp: {stripped!r}",
            sheet=sheet,
            row=row,
            column=spec.name,
            value=stripped,
            hint="Use ISO-8601, e.g. 2026-08-25T03:14:10Z.",
        ) from exc
    return utc_timestamp(parsed)


def _validate_base64_key(sheet: str, row: int, spec: ColumnSpec, stripped: str) -> str:
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


def _validate_key_ref(sheet: str, row: int, spec: ColumnSpec, stripped: str) -> str:
    """Validate a ``KEY_REF`` cell.

    Args:
        sheet: Name of the sheet containing the cell.
        row: 1-indexed row number of the cell.
        spec: The column's spec.
        stripped: The already-stripped, non-empty cell text.

    Returns:
        ``stripped`` unchanged.

    Raises:
        DbValidationError: If ``stripped`` does not match :data:`REF_PATTERN`.
    """
    if not REF_PATTERN.match(stripped):
        raise DbValidationError(
            f"{spec.name!r} does not look like a key reference: {stripped!r}",
            sheet=sheet,
            row=row,
            column=spec.name,
            value=stripped,
        )
    return stripped


def _validate_key_ref_list(sheet: str, row: int, spec: ColumnSpec, stripped: str) -> str:
    """Validate a ``KEY_REF_LIST`` cell.

    Args:
        sheet: Name of the sheet containing the cell.
        row: 1-indexed row number of the cell.
        spec: The column's spec.
        stripped: The already-stripped, non-empty cell text.

    Returns:
        The normalized, de-duplicated list, re-joined with
        :data:`LIST_SEPARATOR`.

    Raises:
        DbValidationError: If any element does not match :data:`REF_PATTERN`.
    """
    refs = normalize_ref_list(stripped)
    for ref in refs:
        if not REF_PATTERN.match(ref):
            raise DbValidationError(
                f"{spec.name!r} contains an invalid reference: {ref!r}",
                sheet=sheet,
                row=row,
                column=spec.name,
                value=stripped,
            )
    return format_ref_list(refs)


def _validate_pin(sheet: str, row: int, spec: ColumnSpec, stripped: str) -> str:
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
            :data:`BLE_PIN_LENGTH` ASCII digits. ``value`` is always
            ``None`` on this error -- a PIN is secret material.
    """
    if not (stripped.isascii() and stripped.isdigit() and len(stripped) == BLE_PIN_LENGTH):
        raise DbValidationError(
            f"{spec.name!r} must be exactly {BLE_PIN_LENGTH} ASCII digits",
            sheet=sheet,
            row=row,
            column=spec.name,
            value=None,
        )
    return stripped


def validate_cell(*, sheet: str, row: int, spec: ColumnSpec, value: str) -> str:
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
        SchemaError: If ``spec.kind`` is not a recognized :class:`ColumnKind`
            (unreachable for any :class:`ColumnKind` member; guards
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
    if spec.kind is ColumnKind.TEXT:
        return stripped
    if spec.kind is ColumnKind.NODE_ID:
        return _validate_node_id(sheet, row, spec, stripped)
    if spec.kind is ColumnKind.ENUM:
        return _validate_enum(sheet, row, spec, stripped)
    if spec.kind is ColumnKind.INT:
        return _validate_int(sheet, row, spec, stripped)
    if spec.kind is ColumnKind.FLOAT:
        return _validate_float(sheet, row, spec, stripped)
    if spec.kind is ColumnKind.TIMESTAMP:
        return _validate_timestamp(sheet, row, spec, stripped)
    if spec.kind is ColumnKind.BASE64_KEY:
        return _validate_base64_key(sheet, row, spec, stripped)
    if spec.kind is ColumnKind.KEY_REF:
        return _validate_key_ref(sheet, row, spec, stripped)
    if spec.kind is ColumnKind.KEY_REF_LIST:
        return _validate_key_ref_list(sheet, row, spec, stripped)
    if spec.kind is ColumnKind.PIN:
        return _validate_pin(sheet, row, spec, stripped)
    raise SchemaError(  # pragma: no cover - exhaustive over ColumnKind members
        f"Unhandled column kind: {spec.kind!r}", sheet=sheet, column=spec.name
    )


def validate_row(sheet_spec: SheetSpec, row: int, values: Mapping[str, str]) -> dict[str, str]:
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


def recompute_derived(sheet_spec: SheetSpec, values: Mapping[str, str]) -> dict[str, str]:
    """Recompute every derived column's value from its sources.

    Args:
        sheet_spec: The sheet the row belongs to.
        values: The row's already-validated ``{column_name: value}`` map.

    Returns:
        A new ``dict`` of ``{column_name: recomputed_value}``, one entry
        per column in ``sheet_spec.derived_columns()``.
    """
    result: dict[str, str] = {}
    for col in sheet_spec.derived_columns():
        formula = col.formula
        if formula is None:  # pragma: no cover - derived_columns() guarantees this
            continue
        result[col.name] = formula.recompute(values)
    return result


def formula_for(sheet_spec: SheetSpec, column: str, row: int) -> str | None:
    """Render one derived column's OpenFormula template for one row.

    Args:
        sheet_spec: The sheet the column belongs to.
        column: Name of the column.
        row: The 1-based ODS row number (header row is 1).

    Returns:
        The template with ``{row}`` substituted, or ``None`` when the
        column has no formula, or has a code-only :class:`FormulaSpec`
        (``template=None``, e.g. ``main_chipset``).

    Raises:
        SchemaError: If ``column`` does not exist on ``sheet_spec``.
    """
    spec = sheet_spec.column(column)
    if spec.formula is None or spec.formula.template is None:
        return None
    return spec.formula.template.format(row=row)


def ref_for(owner: str, key_type: KeyType) -> str:
    """Build the canonical ``key_ref`` for an owner and key type.

    Args:
        owner: The owning node id or admin-node template reference.
        key_type: The kind of key.

    Returns:
        ``f"{owner}{suffix}"``, using :data:`KEY_REF_SUFFIXES`.
    """
    return f"{owner}{KEY_REF_SUFFIXES[key_type]}"


def normalize_ref_list(raw: str) -> tuple[str, ...]:
    """Parse a ``KEY_REF_LIST`` cell's raw text into a clean tuple of refs.

    Splits on :data:`LIST_SEPARATOR`, strips each element, drops empty
    elements, and de-duplicates while preserving first-seen order.

    Args:
        raw: The raw cell text.

    Returns:
        A tuple of non-empty, de-duplicated, stripped references.
    """
    seen: set[str] = set()
    result: list[str] = []
    for part in raw.split(LIST_SEPARATOR):
        stripped = part.strip()
        if not stripped or stripped in seen:
            continue
        seen.add(stripped)
        result.append(stripped)
    return tuple(result)


def format_ref_list(refs: Sequence[str]) -> str:
    """Join a sequence of references back into ``KEY_REF_LIST`` cell text.

    Args:
        refs: The references to join.

    Returns:
        ``refs`` joined by :data:`LIST_SEPARATOR`.
    """
    return LIST_SEPARATOR.join(refs)


def utc_timestamp(when: datetime | None = None) -> str:
    """Format a datetime as the canonical ``...Z`` UTC timestamp text.

    Args:
        when: The datetime to format. Naive datetimes are treated as
            already being UTC. Defaults to the current time when
            ``None``.

    Returns:
        For example ``"2026-08-25T03:14:10Z"``.
    """
    dt = when if when is not None else datetime.now(tz=UTC)
    dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp(raw: str) -> datetime:
    """Parse an ISO-8601 timestamp, normalizing to a tz-aware UTC datetime.

    Args:
        raw: An ISO-8601 timestamp string, with or without a UTC/offset
            suffix. A naive value is interpreted as already being UTC.

    Returns:
        A tz-aware :class:`datetime.datetime` in UTC.

    Raises:
        ValueError: If ``raw`` cannot be parsed as an ISO-8601 timestamp.
    """
    token = raw.strip()
    if not token:
        raise ValueError("Cannot parse an empty timestamp")
    dt = datetime.fromisoformat(token)
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
