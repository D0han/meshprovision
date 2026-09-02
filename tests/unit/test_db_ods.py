"""Tests for meshprovision.db.ods."""

from __future__ import annotations

import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from meshprovision.db import ods, schema
from meshprovision.db.keys import KeyRecord
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import KeyType, ManagementMode
from meshprovision.errors import (
    DbIntegrityError,
    DbValidationError,
    DuplicateNodeError,
    SchemaError,
)

pytestmark = pytest.mark.unit


def _sample_records(keypair) -> tuple[NodeRecord, KeyRecord, KeyRecord]:
    node = NodeRecord(
        node_id="deadbe01",
        short_name="MT00",
        long_name="Meshtastic MT00",
        hw_model="RAK4631",
        main_chipset="nRF52840",
        firmware_type="vanilla",
        firmware_version="2.7.11",
        gps_lat=52.2297,
        gps_lon=21.0122,
        gps_alt=100,
        first_added_ts=datetime(2026, 1, 1, tzinfo=UTC),
        last_updated_ts=datetime(2026, 2, 1, tzinfo=UTC),
        authorized_admin_keys=(),
        notes="a note",
        role="CLIENT",
        region="EU_868",
        ble_pin="012345",
    )
    pub, priv = KeyRecord.for_keypair(
        "deadbe01", keypair, created_ts=datetime(2026, 1, 1, tzinfo=UTC)
    )
    return node, pub, priv


# ---------------------------------------------------------------------------
# Round-trip.
# ---------------------------------------------------------------------------


def test_round_trip_write_then_read(tmp_path: Path, keypair) -> None:
    node, pub, priv = _sample_records(keypair)
    path = tmp_path / "db.ods"
    ods.write_database(
        path, nodes=[node.to_row()], keys=[pub.to_row(), priv.to_row()], backup=False
    )

    loaded = ods.load_database(path)
    assert loaded.warnings == ()
    assert len(loaded.nodes) == 1
    round_tripped_node = NodeRecord.from_row(loaded.nodes[0])
    assert round_tripped_node == node

    assert len(loaded.keys) == 2
    round_tripped_keys = {r["key_ref"]: KeyRecord.from_row(r) for r in loaded.keys}
    assert round_tripped_keys[pub.key_ref] == pub
    assert round_tripped_keys[priv.key_ref] == priv


@pytest.mark.parametrize("mode", [ManagementMode.TEMPLATE, ManagementMode.OBSERVED])
def test_round_trip_management_mode(tmp_path: Path, keypair, mode: ManagementMode) -> None:
    node, pub, priv = _sample_records(keypair)
    node = node.with_updates(management=mode)
    path = tmp_path / "db.ods"
    ods.write_database(
        path, nodes=[node.to_row()], keys=[pub.to_row(), priv.to_row()], backup=False
    )

    loaded = ods.load_database(path)
    assert loaded.warnings == ()
    round_tripped_node = NodeRecord.from_row(loaded.nodes[0])
    assert round_tripped_node == node
    assert round_tripped_node.management is mode


def test_structural_assertions_formulas_validations_freeze(tmp_path: Path, keypair) -> None:
    node, pub, priv = _sample_records(keypair)
    path = tmp_path / "db.ods"
    ods.write_database(
        path, nodes=[node.to_row()], keys=[pub.to_row(), priv.to_row()], backup=False
    )

    raw = ods.read_raw(path)
    assert raw.sheets["Nodes"].header == schema.NODES_SHEET_SPEC.column_names()
    assert raw.sheets["Keys"].header == schema.KEYS_SHEET_SPEC.column_names()

    nodes_row = raw.sheets["Nodes"].rows[0]
    for col in ("private_key_ref", "public_key_ref", "channel_psk_ref"):
        idx = schema.NODES_SHEET_SPEC.column_index(col)
        cell = nodes_row[idx]
        expected_formula = schema.formula_for(schema.NODES_SHEET_SPEC, col, 2)
        assert cell.formula == expected_formula
        source_values = {
            c.name: nodes_row[i].text for i, c in enumerate(schema.NODES_SHEET_SPEC.columns)
        }
        recomputed = schema.recompute_derived(schema.NODES_SHEET_SPEC, source_values)
        assert cell.text == recomputed[col]

    keys_row_idx = 0
    keys_row = raw.sheets["Keys"].rows[keys_row_idx]
    key_ref_idx = schema.KEYS_SHEET_SPEC.column_index("key_ref")
    assert "IF(" in (keys_row[key_ref_idx].formula or "")

    with zipfile.ZipFile(path) as zf:
        content = zf.read("content.xml").decode("utf-8")
        settings = zf.read("settings.xml").decode("utf-8")
        styles = zf.read("styles.xml").decode("utf-8")

    assert "table:content-validation" in content
    for name in ("mp_role", "mp_region", "mp_hw_model", "mp_firmware_type", "mp_key_type"):
        assert name in content
    assert "cell-content-is-in-list(" in content
    assert '"CLIENT"' in content

    assert "ooo:view-settings" in settings
    assert 'name="Nodes"' in settings
    assert 'name="Keys"' in settings
    assert "VerticalSplitMode" in settings and ">2<" in settings
    assert "VerticalSplitPosition" in settings and ">1<" in settings

    assert "MPTextFormat" in styles
    assert "MPText" in styles or "MPText" in content
    assert "MPHeader" in styles or "MPHeader" in content
    assert "default-cell-style-name" in content
    assert "MPText" in content


# ---------------------------------------------------------------------------
# Operator hand-edit.
# ---------------------------------------------------------------------------


def test_operator_hand_edit_is_read_back_exactly(tmp_path: Path, keypair, request) -> None:
    from tests.unit.conftest import edit_ods_cell

    node, pub, priv = _sample_records(keypair)
    path = tmp_path / "db.ods"
    ods.write_database(
        path, nodes=[node.to_row()], keys=[pub.to_row(), priv.to_row()], backup=False
    )

    edit_ods_cell(path, "Nodes", "notes", 2, "operator edited note")
    edit_ods_cell(path, "Nodes", "short_name", 2, "NEW1")

    loaded = ods.load_database(path)
    assert loaded.warnings == ()
    row = loaded.nodes[0]
    assert row["notes"] == "operator edited note"
    assert row["short_name"] == "NEW1"
    assert row["main_chipset"] == "nRF52840"


# ---------------------------------------------------------------------------
# Stale-cached-formula tests.
# ---------------------------------------------------------------------------


def test_stale_cached_formula_private_key_ref(tmp_path: Path, keypair) -> None:
    from tests.unit.conftest import edit_ods_cell

    node, pub, priv = _sample_records(keypair)
    path = tmp_path / "db.ods"
    ods.write_database(
        path, nodes=[node.to_row()], keys=[pub.to_row(), priv.to_row()], backup=False
    )

    edit_ods_cell(path, "Nodes", "private_key_ref", 2, "WRONG_ref")

    loaded = ods.load_database(path)
    assert len(loaded.warnings) == 1
    warning = loaded.warnings[0]
    assert warning.sheet == "Nodes"
    assert warning.cell == "Nodes.O2"
    assert warning.column == "private_key_ref"
    assert warning.cached == "WRONG_ref"
    assert warning.recomputed == "deadbe01_priv"
    msg = warning.message()
    assert "WRONG_ref" in msg
    assert "deadbe01_priv" in msg

    assert loaded.nodes[0]["private_key_ref"] == "deadbe01_priv"


def test_stale_cached_formula_keys_key_ref(tmp_path: Path, keypair) -> None:
    from tests.unit.conftest import edit_ods_cell

    node, pub, priv = _sample_records(keypair)
    path = tmp_path / "db.ods"
    ods.write_database(
        path, nodes=[node.to_row()], keys=[pub.to_row(), priv.to_row()], backup=False
    )

    edit_ods_cell(path, "Keys", "key_ref", 2, "totally_wrong_ref")

    loaded = ods.load_database(path)
    assert len(loaded.warnings) == 1
    assert loaded.warnings[0].sheet == "Keys"
    assert loaded.warnings[0].column == "key_ref"
    assert loaded.keys[0]["key_ref"] == pub.key_ref


def test_stale_cached_formula_main_chipset(tmp_path: Path, keypair) -> None:
    from tests.unit.conftest import edit_ods_cell

    node, pub, priv = _sample_records(keypair)
    path = tmp_path / "db.ods"
    ods.write_database(
        path, nodes=[node.to_row()], keys=[pub.to_row(), priv.to_row()], backup=False
    )

    edit_ods_cell(path, "Nodes", "main_chipset", 2, "bogus")

    loaded = ods.load_database(path)
    assert len(loaded.warnings) == 1
    assert loaded.warnings[0].column == "main_chipset"
    assert loaded.nodes[0]["main_chipset"] == "nRF52840"


# ---------------------------------------------------------------------------
# Type-coercion guard.
# ---------------------------------------------------------------------------


def test_hex_node_id_looking_like_scientific_notation_survives(tmp_path: Path, keypair) -> None:
    node = NodeRecord(node_id="12345e78")
    pub, priv = KeyRecord.for_keypair("12345e78", keypair)
    path = tmp_path / "db.ods"
    ods.write_database(
        path, nodes=[node.to_row()], keys=[pub.to_row(), priv.to_row()], backup=False
    )

    loaded = ods.load_database(path)
    assert loaded.nodes[0]["node_id"] == "12345e78"


def test_coerced_text_cell_warns_instead_of_raising(tmp_path: Path, keypair) -> None:
    from tests.unit.conftest import edit_ods_cell

    node, pub, priv = _sample_records(keypair)
    path = tmp_path / "db.ods"
    ods.write_database(
        path, nodes=[node.to_row()], keys=[pub.to_row(), priv.to_row()], backup=False
    )

    edit_ods_cell(path, "Nodes", "notes", 2, "1234", value_type="float")

    loaded = ods.load_database(path)
    assert len(loaded.warnings) == 1
    warning = loaded.warnings[0]
    assert warning.kind == "coerced_cell"
    assert warning.sheet == "Nodes"
    assert warning.column == "notes"
    assert "notes" in warning.message()
    assert loaded.nodes[0]["notes"] == "1234"


def test_coerced_identity_column_still_raises_db_validation_error(tmp_path: Path, keypair) -> None:
    from tests.unit.conftest import edit_ods_cell

    path = _write_raw_row(tmp_path, keypair, {})
    edit_ods_cell(path, "Nodes", "node_id", 2, "not-hex-zzz", value_type="float")

    with pytest.raises(DbValidationError) as exc_info:
        ods.load_database(path)
    assert exc_info.value.sheet == "Nodes"
    assert exc_info.value.column == "node_id"


def test_blank_trailing_row_with_coerced_cell_produces_no_warnings(tmp_path: Path, keypair) -> None:
    from tests.unit.conftest import edit_ods_cell

    node, pub, priv = _sample_records(keypair)
    blank_row = {col.name: "" for col in schema.SHEET_SPECS["Nodes"].columns}
    path = tmp_path / "db.ods"
    ods.write_database(
        path,
        nodes=[node.to_row(), blank_row],
        keys=[pub.to_row(), priv.to_row()],
        backup=False,
    )

    edit_ods_cell(path, "Nodes", "notes", 3, "", value_type="float")

    loaded = ods.load_database(path)
    assert loaded.warnings == ()
    assert len(loaded.nodes) == 1


# ---------------------------------------------------------------------------
# Validation errors on load.
# ---------------------------------------------------------------------------


def _write_raw_row(
    tmp_path: Path, keypair, node_overrides: dict, key_overrides: dict | None = None
) -> Path:
    node = NodeRecord(node_id="deadbe01")
    row = node.to_row()
    row.update(node_overrides)
    pub, priv = KeyRecord.for_keypair("deadbe01", keypair)
    key_rows = [pub.to_row(), priv.to_row()]
    if key_overrides:
        key_rows[0].update(key_overrides)
    path = tmp_path / "db.ods"
    ods.write_database(path, nodes=[row], keys=key_rows, backup=False)
    return path


def test_invalid_role_raises_db_validation_error(tmp_path: Path, keypair) -> None:
    from tests.unit.conftest import edit_ods_cell

    path = _write_raw_row(tmp_path, keypair, {})
    edit_ods_cell(path, "Nodes", "role", 2, "NOT_A_ROLE")
    with pytest.raises(DbValidationError) as exc_info:
        ods.load_database(path)
    assert exc_info.value.sheet == "Nodes"
    assert exc_info.value.column == "role"


@pytest.mark.parametrize(
    ("column", "bad_value"),
    [("management", "BOGUS"), ("firmware_type", "BOGUS"), ("key_type", "BOGUS")],
)
def test_invalid_literal_allowed_enum_raises_db_validation_error(
    tmp_path: Path, keypair, column: str, bad_value: str
) -> None:
    """Reject an unrecognized value in a literal-``allowed``-set ENUM column.

    `_validate_enum`'s ``spec.allowed`` (non-``enum_table``) branch, used by
    ``management``/``firmware_type``/``key_type``, must reject an
    unrecognized value exactly like the ``enum_table`` branch already
    tested by ``test_invalid_role_raises_db_validation_error`` does.
    """
    from tests.unit.conftest import edit_ods_cell

    path = _write_raw_row(tmp_path, keypair, {})
    sheet = "Keys" if column == "key_type" else "Nodes"
    edit_ods_cell(path, sheet, column, 2, bad_value)
    with pytest.raises(DbValidationError) as exc_info:
        ods.load_database(path)
    assert exc_info.value.sheet == sheet
    assert exc_info.value.column == column


def test_gps_lat_below_min_range_raises(tmp_path: Path, keypair) -> None:
    from tests.unit.conftest import edit_ods_cell

    path = _write_raw_row(tmp_path, keypair, {})
    edit_ods_cell(path, "Nodes", "gps_lat", 2, "-95")
    with pytest.raises(DbValidationError) as exc_info:
        ods.load_database(path)
    assert exc_info.value.column == "gps_lat"


def test_non_numeric_int_column_raises(tmp_path: Path, keypair) -> None:
    from tests.unit.conftest import edit_ods_cell

    path = _write_raw_row(tmp_path, keypair, {})
    edit_ods_cell(path, "Nodes", "gps_alt", 2, "not-a-number")
    with pytest.raises(DbValidationError) as exc_info:
        ods.load_database(path)
    assert exc_info.value.column == "gps_alt"


def test_non_numeric_float_column_raises(tmp_path: Path, keypair) -> None:
    from tests.unit.conftest import edit_ods_cell

    path = _write_raw_row(tmp_path, keypair, {})
    edit_ods_cell(path, "Nodes", "gps_lat", 2, "not-a-number")
    with pytest.raises(DbValidationError) as exc_info:
        ods.load_database(path)
    assert exc_info.value.column == "gps_lat"


def test_non_finite_float_column_raises(tmp_path: Path, keypair) -> None:
    from tests.unit.conftest import edit_ods_cell

    path = _write_raw_row(tmp_path, keypair, {})
    edit_ods_cell(path, "Nodes", "gps_lat", 2, "nan")
    with pytest.raises(DbValidationError) as exc_info:
        ods.load_database(path)
    assert exc_info.value.column == "gps_lat"


def test_malformed_timestamp_raises(tmp_path: Path, keypair) -> None:
    from tests.unit.conftest import edit_ods_cell

    path = _write_raw_row(tmp_path, keypair, {})
    edit_ods_cell(path, "Nodes", "first_added_ts", 2, "not-a-date")
    with pytest.raises(DbValidationError) as exc_info:
        ods.load_database(path)
    assert exc_info.value.column == "first_added_ts"


def test_invalid_ref_inside_key_ref_list_raises(tmp_path: Path, keypair) -> None:
    from tests.unit.conftest import edit_ods_cell

    path = _write_raw_row(tmp_path, keypair, {})
    edit_ods_cell(path, "Nodes", "authorized_admin_keys", 2, "ADMIN1_pub;not a valid ref!")
    with pytest.raises(DbValidationError) as exc_info:
        ods.load_database(path)
    assert exc_info.value.column == "authorized_admin_keys"


def test_invalid_base64_key_value_raises_without_leaking(tmp_path: Path, keypair) -> None:
    from tests.unit.conftest import edit_ods_cell

    path = _write_raw_row(tmp_path, keypair, {})
    edit_ods_cell(path, "Keys", "key_value", 2, "not-valid-base64!!!")
    with pytest.raises(DbValidationError) as exc_info:
        ods.load_database(path)
    assert exc_info.value.value is None
    assert "not-valid-base64" not in str(exc_info.value)


def test_five_digit_ble_pin_raises_without_value(tmp_path: Path, keypair) -> None:
    from tests.unit.conftest import edit_ods_cell

    path = _write_raw_row(tmp_path, keypair, {})
    edit_ods_cell(path, "Nodes", "ble_pin", 2, "12345")
    with pytest.raises(DbValidationError) as exc_info:
        ods.load_database(path)
    assert exc_info.value.value is None


@pytest.mark.parametrize("column", ["key_ref", "owner_node_id", "key_type", "key_value"])
def test_missing_required_key_column_raises(tmp_path: Path, keypair, column: str) -> None:
    pub, priv = KeyRecord.for_keypair("deadbe01", keypair)
    row = pub.to_row()
    row[column] = ""
    node = NodeRecord(node_id="deadbe01")
    path = tmp_path / "db.ods"
    ods.write_database(path, nodes=[node.to_row()], keys=[row, priv.to_row()], backup=False)
    with pytest.raises(DbValidationError):
        ods.load_database(path)


def test_out_of_range_gps_lat_raises(tmp_path: Path, keypair) -> None:
    from tests.unit.conftest import edit_ods_cell

    path = _write_raw_row(tmp_path, keypair, {})
    edit_ods_cell(path, "Nodes", "gps_lat", 2, "95")
    with pytest.raises(DbValidationError):
        ods.load_database(path)


# ---------------------------------------------------------------------------
# Structure errors.
# ---------------------------------------------------------------------------


def test_duplicate_node_id_raises(tmp_path: Path, keypair) -> None:
    node1 = NodeRecord(node_id="deadbe01", short_name="AAAA")
    node2 = NodeRecord(node_id="deadbe01", short_name="BBBB")
    path = tmp_path / "db.ods"
    ods.write_database(path, nodes=[node1.to_row(), node2.to_row()], keys=[], backup=False)
    with pytest.raises(DuplicateNodeError):
        ods.load_database(path)


def test_duplicate_key_ref_raises(tmp_path: Path, keypair) -> None:
    pub, _priv = KeyRecord.for_keypair("deadbe01", keypair)
    path = tmp_path / "db.ods"
    ods.write_database(
        path,
        nodes=[NodeRecord(node_id="deadbe01").to_row()],
        keys=[pub.to_row(), pub.to_row()],
        backup=False,
    )
    with pytest.raises(DbIntegrityError):
        ods.load_database(path)


def test_check_header_hint_names_missing_trailing_column(tmp_path: Path, keypair) -> None:
    from tests.unit.conftest import edit_ods_cell

    node, pub, priv = _sample_records(keypair)
    path = tmp_path / "db.ods"
    ods.write_database(
        path, nodes=[node.to_row()], keys=[pub.to_row(), priv.to_row()], backup=False
    )
    edit_ods_cell(path, "Nodes", "management", 1, "")

    with pytest.raises(SchemaError) as exc_info:
        ods.load_database(path)
    assert exc_info.value.hint is not None
    assert "management" in exc_info.value.hint


def test_check_header_no_hint_for_non_prefix_mismatch(tmp_path: Path, keypair) -> None:
    from tests.unit.conftest import edit_ods_cell

    node, pub, priv = _sample_records(keypair)
    path = tmp_path / "db.ods"
    ods.write_database(
        path, nodes=[node.to_row()], keys=[pub.to_row(), priv.to_row()], backup=False
    )
    edit_ods_cell(path, "Nodes", "role", 1, "not_a_real_column")

    with pytest.raises(SchemaError) as exc_info:
        ods.load_database(path)
    assert exc_info.value.hint is None


def test_file_missing_keys_sheet_raises_schema_error(tmp_path: Path) -> None:
    from odf import opendocument as odf_opendocument
    from odf import table as odf_table

    doc = odf_opendocument.OpenDocumentSpreadsheet()
    doc.spreadsheet.addElement(odf_table.Table(name="Nodes"))
    path = tmp_path / "broken.ods"
    with path.open("wb") as fh:
        doc.write(fh)

    with pytest.raises(SchemaError):
        ods.load_database(path)


def test_read_raw_on_text_file_raises_schema_error(tmp_path: Path) -> None:
    path = tmp_path / "notods.txt"
    path.write_text("hello world")
    with pytest.raises(SchemaError):
        ods.read_raw(path)


# ---------------------------------------------------------------------------
# OdsDatabase session.
# ---------------------------------------------------------------------------


def test_ods_database_load_loaded_rows(tmp_path: Path, keypair) -> None:
    node, pub, priv = _sample_records(keypair)
    path = tmp_path / "db.ods"
    ods.write_database(
        path, nodes=[node.to_row()], keys=[pub.to_row(), priv.to_row()], backup=False
    )

    db = ods.OdsDatabase(path)
    assert db.loaded is False
    db.load()
    assert db.loaded is True
    assert len(db.rows("Nodes")) == 1


def test_ods_database_rows_bogus_sheet_raises(tmp_path: Path) -> None:
    ods.create_empty(tmp_path / "db.ods", backup=False)
    db = ods.OdsDatabase(tmp_path / "db.ods")
    with pytest.raises(SchemaError):
        db.rows("Bogus")


def test_ods_database_create_existing_without_overwrite_raises(tmp_path: Path) -> None:
    path = tmp_path / "db.ods"
    ods.OdsDatabase.create(path)
    with pytest.raises(SchemaError):
        ods.OdsDatabase.create(path)


def test_ods_database_save_no_op_when_not_dirty(tmp_path: Path) -> None:
    path = tmp_path / "db.ods"
    db = ods.OdsDatabase.create(path)
    mtime_before = path.stat().st_mtime_ns
    db.save()
    assert path.stat().st_mtime_ns == mtime_before


def test_ods_database_save_backup_true_creates_one_file_under_data_backups(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    path = Path("nodes_db.ods")
    db = ods.OdsDatabase.create(path)
    db.replace("Nodes", [NodeRecord(node_id="deadbe01").to_row()])
    assert db.dirty() is True
    db.save(backup=True)
    assert db.dirty() is False

    backups_dir = Path("data/backups")
    assert backups_dir.is_dir()
    backup_files = list(backups_dir.glob("*.ods"))
    assert len(backup_files) == 1


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


def test_validate_row_fills_every_column() -> None:
    result = schema.validate_row(schema.NODES_SHEET_SPEC, 2, {"node_id": "deadbe01"})
    assert set(result) == set(schema.NODES_SHEET_SPEC.column_names())
