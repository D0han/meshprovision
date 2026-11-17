"""Firmware traits for remote work: version gates, retry counts and CAD length."""

from __future__ import annotations

import pytest

from meshprovision.remote.firmware import FirmwareTraits, RadioChip, cad_symbols, firmware_traits

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param("", FirmwareTraits(None, False, False, False, False, 5, True), id="empty"),
        pytest.param(
            "garbage", FirmwareTraits(None, False, False, False, False, 5, True), id="garbage"
        ),
        pytest.param("2.x", FirmwareTraits(None, False, False, False, False, 5, True), id="2.x"),
        pytest.param(
            "2.6.13", FirmwareTraits((2, 6, 13), False, False, False, False, 3, False), id="2.6.13"
        ),
        pytest.param(
            "2.7.0", FirmwareTraits((2, 7, 0), True, False, False, False, 3, False), id="2.7.0"
        ),
        pytest.param(
            "2.7.26.9861e82",
            FirmwareTraits((2, 7, 26), True, False, False, False, 3, False),
            id="2.7.26-build",
        ),
        pytest.param(
            "2.8.0", FirmwareTraits((2, 8, 0), True, True, True, True, 5, True), id="2.8.0"
        ),
        pytest.param(
            "v2.8.3", FirmwareTraits((2, 8, 3), True, True, True, True, 5, True), id="v2.8.3"
        ),
    ],
)
def test_traits_by_version(raw: str, expected: FirmwareTraits) -> None:
    assert firmware_traits(raw) == expected


@pytest.mark.parametrize(
    ("raw", "chip", "symbols"),
    [
        pytest.param("2.8.3", RadioChip.SX126X, 4, id="2.8-sx126x"),
        pytest.param("2.8.3", RadioChip.UNKNOWN, 4, id="2.8-unknown"),
        pytest.param("2.8.3", RadioChip.RF95, 2, id="2.8-rf95"),
        pytest.param("2.7.26", RadioChip.SX126X, 2, id="2.7-sx126x"),
        pytest.param("2.7.26", RadioChip.UNKNOWN, 2, id="2.7-unknown"),
        pytest.param("2.7.26", RadioChip.RF95, 2, id="2.7-rf95"),
    ],
)
def test_cad_symbols(raw: str, chip: RadioChip, symbols: int) -> None:
    assert cad_symbols(firmware_traits(raw), chip) == symbols


def test_an_unparseable_version_with_an_unknown_chip_scans_the_long_cad() -> None:
    assert cad_symbols(firmware_traits("garbage"), RadioChip.UNKNOWN) == 4
