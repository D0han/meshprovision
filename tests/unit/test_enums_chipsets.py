"""Tests for meshprovision.enums and meshprovision.chipsets."""

from __future__ import annotations

import pytest

from meshprovision import chipsets, enums
from meshprovision.enums import EnumSource, normalize_enum_name
from meshprovision.errors import EnumMappingError

pytestmark = pytest.mark.unit


def test_role_table_source_is_protobuf_in_this_environment() -> None:
    assert enums.role_table().source is EnumSource.PROTOBUF
    assert enums.hw_model_table().source is EnumSource.PROTOBUF
    assert enums.region_table().source is EnumSource.PROTOBUF


def test_load_protobuf_items_returns_none_when_every_candidate_path_fails() -> None:
    bogus_paths = (
        ("meshprovision._no_such_module_at_all", ("Nope",)),
        ("meshprovision.enums", ("_no_such_attribute_at_all",)),
    )
    assert enums._load_protobuf_items(bogus_paths) is None


def test_build_table_falls_back_when_every_protobuf_path_fails() -> None:
    bogus_paths = (("meshprovision._no_such_module_at_all", ("Nope",)),)
    table = enums._build_table("test_enum", bogus_paths, {"ALPHA": 1, "BETA": 2})

    assert table.source is EnumSource.FALLBACK
    assert table.to_name(1) == "ALPHA"
    assert table.to_value("BETA") == 2


def test_build_table_alias_collision_keeps_the_first_seen_name() -> None:
    bogus_paths = (("meshprovision._no_such_module_at_all", ("Nope",)),)
    table = enums._build_table("test_enum", bogus_paths, {"FIRST": 5, "SECOND": 5})

    assert table.to_name(5) == "FIRST"
    assert table.to_value("FIRST") == 5
    assert table.to_value("SECOND") == 5


def test_to_value_digit_string_resolves_like_int() -> None:
    table = enums.role_table()
    value = table.to_value("CLIENT")
    assert table.to_value(str(value)) == value


def test_enum_table_values_and_contains_value() -> None:
    table = enums.role_table()
    assert table.values() == tuple(sorted(table.value_to_name))
    known_value = table.values()[0]
    assert table.contains_value(known_value) is True
    assert table.contains_value(999999) is False


@pytest.mark.parametrize("table_fn", [enums.role_table, enums.hw_model_table, enums.region_table])
def test_to_name_to_value_round_trip(table_fn) -> None:
    table = table_fn()
    for name, value in table.items():
        assert table.to_name(value) == name
        assert table.to_value(name) == value
        assert table.to_name(str(value)) == name
        assert table.to_value(value) == value


@pytest.mark.parametrize("bad", [None, 3.5, [], object()])
def test_to_name_to_value_wrong_type_raises(bad) -> None:
    table = enums.role_table()
    with pytest.raises(EnumMappingError):
        table.to_name(bad)
    with pytest.raises(EnumMappingError):
        table.to_value(bad)


def test_digit_string_resolves_like_int() -> None:
    table = enums.role_table()
    value = table.to_value("CLIENT")
    assert table.to_name(str(value)) == "CLIENT"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Router Client", "ROUTER_CLIENT"),
        ("t-beam", "T_BEAM"),
        (" client ", "CLIENT"),
    ],
)
def test_normalize_enum_name(raw: str, expected: str) -> None:
    assert normalize_enum_name(raw) == expected


def test_to_name_to_value_on_garbage_raises() -> None:
    table = enums.role_table()
    with pytest.raises(EnumMappingError) as exc_info:
        table.to_name("NOT_A_REAL_ROLE")
    assert exc_info.value.enum_name == "role"
    assert exc_info.value.known

    with pytest.raises(EnumMappingError):
        table.to_value("NOT_A_REAL_ROLE")

    with pytest.raises(EnumMappingError):
        table.to_name(999999)

    with pytest.raises(EnumMappingError):
        table.to_value(999999)


def test_try_name_try_value_return_none() -> None:
    table = enums.role_table()
    assert table.try_name("NOT_A_REAL_ROLE") is None
    assert table.try_value("NOT_A_REAL_ROLE") is None
    assert table.try_name(999999) is None


@pytest.mark.parametrize(
    ("fallback", "table_fn"),
    [
        (enums._FALLBACK_ROLE, enums.role_table),
        (enums._FALLBACK_REGION, enums.region_table),
        (enums._FALLBACK_HW_MODEL, enums.hw_model_table),
    ],
)
def test_fallback_tables_agree_with_real_protobufs_where_present(fallback, table_fn) -> None:
    table = table_fn()
    for name, value in fallback.items():
        assert table.contains_name(name), f"{name} missing from real {table.name} table"
        assert table.to_value(name) == value, f"{name} value mismatch in real {table.name} table"


def test_chipset_for_hw_model_by_name_and_numeric() -> None:
    assert chipsets.chipset_for_hw_model("RAK4631") is chipsets.Chipset.NRF52840
    numeric = enums.hw_model_table().to_value("RAK4631")
    assert chipsets.chipset_for_hw_model(numeric) is chipsets.Chipset.NRF52840
    assert chipsets.chipset_for_hw_model(str(numeric)) is chipsets.Chipset.NRF52840


def test_chipset_for_unknown_model_degrades_to_unknown() -> None:
    assert chipsets.chipset_for_hw_model("TOTALLY_MADE_UP_BOARD") is chipsets.Chipset.UNKNOWN
    assert chipsets.chipset_for_hw_model(123456789) is chipsets.Chipset.UNKNOWN


def test_main_chipset_returns_display_string() -> None:
    assert chipsets.main_chipset("RAK4631") == "nRF52840"
    assert chipsets.main_chipset("UNKNOWN_THING") == "unknown"


def test_family_for_hw_model_and_chipset() -> None:
    assert chipsets.family_for_hw_model("RAK4631") is chipsets.ChipFamily.NRF52
    assert chipsets.family_for_chipset(chipsets.Chipset.ESP32_S3) is chipsets.ChipFamily.ESP32
    assert chipsets.family_for_chipset(chipsets.Chipset.UNKNOWN) is chipsets.ChipFamily.UNKNOWN


def test_is_mapped_hw_model() -> None:
    assert chipsets.is_mapped_hw_model("RAK4631") is True
    assert chipsets.is_mapped_hw_model("NOT_A_MODEL") is False


def test_mapped_hw_models_is_sorted() -> None:
    mapped = chipsets.mapped_hw_models()
    assert list(mapped) == sorted(mapped)
    assert "RAK4631" in mapped


def test_unmapped_hw_models_is_informational_only() -> None:
    # Must not raise, and must not assert emptiness -- purely informational.
    result = chipsets.unmapped_hw_models()
    assert isinstance(result, tuple)
