"""Hardware-model to main-chipset lookup table.

Maps a Meshtastic ``hw_model`` (e.g. ``"RAK4631"``, ``"TBEAM"``) to the
board's main MCU/SoC, and to the coarser chipset family. This drives
operator-facing expectations (chipset appears in ``mesh status`` output
and in the ODS ``Nodes`` sheet) about BLE/serial behaviour, so a wrong
mapping is worse than an absent one: every board listed in
:data:`CHIPSET_BY_HW_MODEL` below has its MCU confirmed against the
Meshtastic supported-hardware documentation, and boards that could not be
confirmed are left out rather than guessed.

None of the public functions in this module ever raise. Chipset data is
informational only, so an unrecognised board degrades to
:attr:`Chipset.UNKNOWN` / :attr:`ChipFamily.UNKNOWN` rather than aborting
a run.
"""

from __future__ import annotations

import types
from collections.abc import Mapping
from enum import StrEnum
from typing import Final

from meshprovision import enums

__all__ = [
    "CHIPSET_BY_HW_MODEL",
    "FAMILY_BY_CHIPSET",
    "ChipFamily",
    "Chipset",
    "chipset_for_hw_model",
    "family_for_chipset",
    "family_for_hw_model",
    "is_mapped_hw_model",
    "main_chipset",
    "mapped_hw_models",
    "unmapped_hw_models",
]


class Chipset(StrEnum):
    """Main MCU/SoC of a Meshtastic hardware model. Values are display strings."""

    NRF52840 = "nRF52840"
    ESP32 = "ESP32"
    ESP32_S3 = "ESP32-S3"
    ESP32_C3 = "ESP32-C3"
    ESP32_C6 = "ESP32-C6"
    RP2040 = "RP2040"
    RP2350 = "RP2350"
    STM32WL = "STM32WL"
    NATIVE = "native"
    UNKNOWN = "unknown"


class ChipFamily(StrEnum):
    """Coarse chipset family, useful for capability decisions."""

    NRF52 = "nrf52"
    ESP32 = "esp32"
    RP2 = "rp2"
    STM32 = "stm32"
    NATIVE = "native"
    UNKNOWN = "unknown"


_CHIPSET_BY_HW_MODEL: Final[dict[str, Chipset]] = {
    # --- Chipset.NRF52840 ---
    "RAK4631": Chipset.NRF52840,
    "RAK4630": Chipset.NRF52840,
    "T_ECHO": Chipset.NRF52840,
    "TRACKER_T1000_E": Chipset.NRF52840,
    "HELTEC_MESH_NODE_T114": Chipset.NRF52840,
    "NANO_G2_ULTRA": Chipset.NRF52840,
    "NRF52840DK": Chipset.NRF52840,
    "NRF52840_PCA10059": Chipset.NRF52840,
    "NRF52_PROMICRO_DIY": Chipset.NRF52840,
    "CANARYONE": Chipset.NRF52840,
    "WIO_WM1110": Chipset.NRF52840,
    "XIAO_NRF52_KIT": Chipset.NRF52840,
    # --- Chipset.ESP32 (classic) ---
    "TBEAM": Chipset.ESP32,
    "TBEAM_V0P7": Chipset.ESP32,
    "LORA_RELAY_V1": Chipset.ESP32,
    "TLORA_V1": Chipset.ESP32,
    "TLORA_V1_1P3": Chipset.ESP32,
    "TLORA_V2": Chipset.ESP32,
    "TLORA_V2_1_1P6": Chipset.ESP32,
    "TLORA_V2_1_1P8": Chipset.ESP32,
    "HELTEC_V1": Chipset.ESP32,
    "HELTEC_V2_0": Chipset.ESP32,
    "HELTEC_V2_1": Chipset.ESP32,
    "RAK11200": Chipset.ESP32,
    "STATION_G1": Chipset.ESP32,
    "NANO_G1": Chipset.ESP32,
    "NANO_G1_EXPLORER": Chipset.ESP32,
    "M5STACK": Chipset.ESP32,
    "DIY_V1": Chipset.ESP32,
    # --- Chipset.ESP32_S3 ---
    "HELTEC_V3": Chipset.ESP32_S3,
    "HELTEC_WSL_V3": Chipset.ESP32_S3,
    "HELTEC_WIRELESS_TRACKER": Chipset.ESP32_S3,
    "HELTEC_WIRELESS_PAPER": Chipset.ESP32_S3,
    "HELTEC_VISION_MASTER_T190": Chipset.ESP32_S3,
    "HELTEC_VISION_MASTER_E213": Chipset.ESP32_S3,
    "HELTEC_VISION_MASTER_E290": Chipset.ESP32_S3,
    "LILYGO_TBEAM_S3_CORE": Chipset.ESP32_S3,
    "TLORA_T3_S3": Chipset.ESP32_S3,
    "T_DECK": Chipset.ESP32_S3,
    "T_WATCH_S3": Chipset.ESP32_S3,
    "STATION_G2": Chipset.ESP32_S3,
    "SENSECAP_INDICATOR": Chipset.ESP32_S3,
    "UNPHONE": Chipset.ESP32_S3,
    "PICOMPUTER_S3": Chipset.ESP32_S3,
    "EBYTE_ESP32_S3": Chipset.ESP32_S3,
    "ESP32_S3_PICO": Chipset.ESP32_S3,
    "CDEBYTE_EORA_S3": Chipset.ESP32_S3,
    "SEEED_XIAO_S3": Chipset.ESP32_S3,
    "SENSELORA_S3": Chipset.ESP32_S3,
    "M5STACK_CORES3": Chipset.ESP32_S3,
    # --- Chipset.ESP32_C3 ---
    "HELTEC_HT62": Chipset.ESP32_C3,
    # --- Chipset.ESP32_C6 ---
    "TLORA_C6": Chipset.ESP32_C6,
    # --- Chipset.RP2040 ---
    "RPI_PICO": Chipset.RP2040,
    "RP2040_LORA": Chipset.RP2040,
    "RAK11310": Chipset.RP2040,
    "SENSELORA_RP2040": Chipset.RP2040,
    "RP2040_FEATHER_RFM95": Chipset.RP2040,
    # --- Chipset.RP2350 ---
    "RPI_PICO2": Chipset.RP2350,
    # --- Chipset.STM32WL ---
    "RAK3172": Chipset.STM32WL,
    "WIO_E5": Chipset.STM32WL,
    # --- Chipset.NATIVE ---
    "PORTDUINO": Chipset.NATIVE,
}

CHIPSET_BY_HW_MODEL: Final[Mapping[str, Chipset]] = types.MappingProxyType(_CHIPSET_BY_HW_MODEL)
"""Read-only map from canonical ``hw_model`` name to its main :class:`Chipset`.

Deliberately NOT mapped (left absent so lookup resolves to
:attr:`Chipset.UNKNOWN` rather than a guess): ``UNSET``, ``PRIVATE_HW``,
``ANDROID_SIM``, ``NRF52_UNKNOWN``, ``LORA_TYPE``, and any board whose MCU
could not be confirmed.
"""

_FAMILY_BY_CHIPSET: Final[dict[Chipset, ChipFamily]] = {
    Chipset.NRF52840: ChipFamily.NRF52,
    Chipset.ESP32: ChipFamily.ESP32,
    Chipset.ESP32_S3: ChipFamily.ESP32,
    Chipset.ESP32_C3: ChipFamily.ESP32,
    Chipset.ESP32_C6: ChipFamily.ESP32,
    Chipset.RP2040: ChipFamily.RP2,
    Chipset.RP2350: ChipFamily.RP2,
    Chipset.STM32WL: ChipFamily.STM32,
    Chipset.NATIVE: ChipFamily.NATIVE,
    Chipset.UNKNOWN: ChipFamily.UNKNOWN,
}

FAMILY_BY_CHIPSET: Final[Mapping[Chipset, ChipFamily]] = types.MappingProxyType(_FAMILY_BY_CHIPSET)
"""Read-only map from :class:`Chipset` to its coarser :class:`ChipFamily`."""


def _canonical(hw_model: str | int) -> str | None:
    """Canonicalize a ``hw_model`` value for table lookup.

    An ``int`` is resolved through the installed/fallback HardwareModel
    enum table (miss -> ``None``). A ``str`` of all ASCII digits is
    reinterpreted as an ``int`` and resolved the same way. Any other
    ``str`` is normalized via :func:`meshprovision.enums.normalize_enum_name`
    and returned *even if it is not a known enum member* -- the chipset
    table lookup that follows decides whether it matches, which keeps
    chipset lookup working for a board name the installed protobuf does
    not know but :data:`CHIPSET_BY_HW_MODEL` does, and vice versa.

    Args:
        hw_model: A ``hw_model`` value, numeric or string.

    Returns:
        A canonical ``UPPER_SNAKE`` name, or ``None`` if ``hw_model`` is
        neither a usable ``int`` nor a usable ``str``.
    """
    if isinstance(hw_model, bool) or not isinstance(hw_model, (int, str)):
        return None
    if isinstance(hw_model, int):
        return enums.hw_model_table().try_name(hw_model)
    token = hw_model.strip()
    if token.isascii() and token.isdigit():
        return _canonical(int(token))
    return enums.normalize_enum_name(hw_model)


def chipset_for_hw_model(hw_model: str | int) -> Chipset:
    """Look up the main chipset for a ``hw_model``.

    Args:
        hw_model: A ``hw_model`` value, numeric or string.

    Returns:
        The matching :class:`Chipset`, or :attr:`Chipset.UNKNOWN` if
        ``hw_model`` cannot be resolved or is not in the lookup table.
        Never raises.
    """
    canonical = _canonical(hw_model)
    if canonical is None:
        return Chipset.UNKNOWN
    return CHIPSET_BY_HW_MODEL.get(canonical, Chipset.UNKNOWN)


def main_chipset(hw_model: str | int) -> str:
    """Look up the main chipset for a ``hw_model``, as a display string.

    Args:
        hw_model: A ``hw_model`` value, numeric or string.

    Returns:
        The matching :class:`Chipset` value string, or ``"unknown"`` when
        unmapped. Never raises.
    """
    return chipset_for_hw_model(hw_model).value


def family_for_hw_model(hw_model: str | int) -> ChipFamily:
    """Look up the coarse chip family for a ``hw_model``.

    Args:
        hw_model: A ``hw_model`` value, numeric or string.

    Returns:
        The matching :class:`ChipFamily`, or :attr:`ChipFamily.UNKNOWN` if
        unresolved. Never raises.
    """
    return family_for_chipset(chipset_for_hw_model(hw_model))


def family_for_chipset(chipset: Chipset) -> ChipFamily:
    """Look up the coarse chip family for a :class:`Chipset`.

    Args:
        chipset: A chipset value.

    Returns:
        The matching :class:`ChipFamily`, or :attr:`ChipFamily.UNKNOWN` if
        unmapped. Never raises.
    """
    return FAMILY_BY_CHIPSET.get(chipset, ChipFamily.UNKNOWN)


def is_mapped_hw_model(hw_model: str | int) -> bool:
    """Check whether ``hw_model`` has a known chipset mapping.

    Args:
        hw_model: A ``hw_model`` value, numeric or string.

    Returns:
        ``True`` if ``hw_model`` resolves to an entry in
        :data:`CHIPSET_BY_HW_MODEL`. Never raises.
    """
    canonical = _canonical(hw_model)
    return canonical is not None and canonical in CHIPSET_BY_HW_MODEL


def mapped_hw_models() -> tuple[str, ...]:
    """Return every ``hw_model`` name with a known chipset mapping.

    Returns:
        A tuple of canonical names, sorted alphabetically.
    """
    return tuple(sorted(CHIPSET_BY_HW_MODEL))


def unmapped_hw_models() -> tuple[str, ...]:
    """Return every known ``hw_model`` name absent from the chipset table.

    Informational only -- a later test layer reports coverage from this,
    but it must not assert emptiness, since new hardware models routinely
    arrive ahead of a chipset mapping for them.

    Returns:
        A tuple of canonical names present in
        :func:`meshprovision.enums.hw_model_table` but absent from
        :data:`CHIPSET_BY_HW_MODEL`, sorted alphabetically.
    """
    known = set(enums.hw_model_table().names())
    return tuple(sorted(known - set(CHIPSET_BY_HW_MODEL)))
