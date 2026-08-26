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


@pytest.mark.parametrize("table_fn", [enums.role_table, enums.hw_model_table, enums.region_table])
def test_to_name_to_value_round_trip(table_fn) -> None:
    table = table_fn()
    for name, value in table.items():
        assert table.to_name(value) == name
        assert table.to_value(name) == value
        assert table.to_name(str(value)) == name


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
