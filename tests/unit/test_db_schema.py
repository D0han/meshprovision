"""Tests for meshprovision.db.schema (and the cell_validation helpers built on it)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from meshprovision.crypto.keys import encode_key
from meshprovision.db import cell_validation, schema
from meshprovision.db.schema import KeyType
from meshprovision.errors import (
    DbValidationError,
    SchemaError,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# schema.py units.
# ---------------------------------------------------------------------------


def test_column_letter() -> None:
    assert schema.column_letter(0) == "A"
    assert schema.column_letter(25) == "Z"
    assert schema.column_letter(26) == "AA"
    assert schema.column_letter(27) == "AB"
    with pytest.raises(SchemaError):
        schema.column_letter(-1)


def test_validation_condition_doubles_inner_quote() -> None:
    condition = schema.validation_condition(['a"b', "c"])
    assert 'a""b' in condition
    assert condition.startswith("of:cell-content-is-in-list(")


def test_allowed_values_literal_and_enum_table() -> None:
    firmware_col = schema.NODES_SHEET_SPEC.column("firmware_type")
    assert schema.allowed_values(firmware_col) == tuple(schema.FirmwareType)

    role_col = schema.NODES_SHEET_SPEC.column("role")
    values = schema.allowed_values(role_col)
    assert values is not None
    assert "CLIENT" in values


def test_normalize_ref_list_and_format_ref_list() -> None:
    refs = schema.normalize_ref_list(" a ; b ; a ; ;c")
    assert refs == ("a", "b", "c")
    assert schema.format_ref_list(refs) == "a;b;c"


def test_ref_for_and_key_ref_suffixes() -> None:
    assert schema.ref_for("deadbe01", KeyType.ADMIN_PUBLIC) == "deadbe01_pub"
    assert schema.ref_for("deadbe01", KeyType.ADMIN_PRIVATE) == "deadbe01_priv"
    assert schema.ref_for("deadbe01", KeyType.CHANNEL_PSK) == "deadbe01_psk"


def test_utc_timestamp_round_trip() -> None:
    text = "2026-08-25T03:14:10Z"
    dt = schema.parse_timestamp(text)
    assert schema.utc_timestamp(dt) == text

    naive_treated_as_utc = schema.parse_timestamp("2026-08-25T03:14:10")
    assert naive_treated_as_utc.tzinfo is UTC


def test_parse_timestamp_converts_a_non_utc_offset_to_utc() -> None:
    """An offset-aware value must be shifted to UTC, not relabelled as UTC.

    A ``...Z`` input cannot tell the naive branch (``replace(tzinfo=UTC)``)
    apart from the aware branch (``astimezone(UTC)``) -- both leave it
    unchanged. A genuine ``+05:00`` offset separates them: shifting gives
    05:00Z, relabelling would give 10:00Z.
    """
    parsed = schema.parse_timestamp("2026-01-01T10:00:00+05:00")
    assert schema.utc_timestamp(parsed) == "2026-01-01T05:00:00Z"
    assert parsed == datetime(2026, 1, 1, 5, 0, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "text",
    ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-05:00"],
    ids=["before-year-1-in-utc", "after-year-9999-in-utc"],
)
def test_parse_timestamp_out_of_range_in_utc_is_a_value_error(text: str) -> None:
    """Shifting to UTC can leave datetime's range; that is a bad value, not a crash."""
    with pytest.raises(ValueError, match="out of range in UTC"):
        schema.parse_timestamp(text)


def test_utc_timestamp_shifts_an_offset_aware_datetime() -> None:
    aware = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone(timedelta(hours=5)))
    assert schema.utc_timestamp(aware) == "2026-01-01T05:00:00Z"


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("gps_lat", "-90"),
        ("gps_lat", "90"),
        ("gps_lon", "-180"),
        ("gps_lon", "180"),
    ],
)
def test_float_bounds_are_inclusive_at_the_exact_boundary(column: str, value: str) -> None:
    """``min_value``/``max_value`` are documented as inclusive bounds.

    Every other range test uses a value well outside the range, which a
    ``>``-to-``>=`` flip in ``cell_validation._check_range`` would still
    reject correctly.
    """
    spec = schema.NODES_SHEET_SPEC.column(column)
    assert cell_validation.validate_cell(sheet="Nodes", row=2, spec=spec, value=value) == value


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("gps_lat", "-90.0000001"),
        ("gps_lat", "90.0000001"),
        ("gps_lon", "-180.0000001"),
        ("gps_lon", "180.0000001"),
    ],
)
def test_float_bounds_reject_just_past_the_boundary(column: str, value: str) -> None:
    spec = schema.NODES_SHEET_SPEC.column(column)
    with pytest.raises(DbValidationError) as exc_info:
        cell_validation.validate_cell(sheet="Nodes", row=2, spec=spec, value=value)
    assert exc_info.value.column == column


def test_base64_key_list_dedupes_after_canonicalization(keypair) -> None:
    """One key spelled two ways collapses to one element.

    ``decode_key`` accepts both the bare base64 and the ``base64:``
    form, so de-duplicating on the raw cell text (as ``normalize_ref_list``
    does) is not enough to honour this column's documented dedup contract.
    """
    encoded = encode_key(keypair.public)
    spec = schema.NODES_SHEET_SPEC.column("unregistered_admin_keys")
    result = cell_validation.validate_cell(
        sheet="Nodes", row=2, spec=spec, value=f"{encoded};base64:{encoded};{encoded}"
    )
    assert result == encoded


def test_validate_row_fills_every_column() -> None:
    result = cell_validation.validate_row(schema.NODES_SHEET_SPEC, 2, {"node_id": "deadbe01"})
    assert set(result) == set(schema.NODES_SHEET_SPEC.column_names())
