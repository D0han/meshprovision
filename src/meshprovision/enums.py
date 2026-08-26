"""Protobuf-first enum tables for Role, HardwareModel, and LoRa RegionCode.

loranet.pl reports ``role`` and ``hw_model`` as human-ish strings (for
example ``"Client"``, ``"T-Beam"``) while lorastats.pl reports the same
fields as protobuf integers. This module is what reconciles the two: it
loads the canonical name/number tables from the installed ``meshtastic``
protobufs when available, and normalizes any input -- name, alias, or
number -- against them.

**No meshtastic import happens at module import time.** ``meshtastic`` is
an optional runtime dependency; this module must import cleanly even when
it is absent. All protobuf access happens lazily, inside the
:func:`functools.cache`-decorated table builders, guarded by
``try/except (ImportError, AttributeError, TypeError)``. When the
protobufs are unavailable (or the expected attribute path has moved), a
curated fallback table is used instead and a warning is logged via the
stdlib ``logging`` module (this module stays dependency-free; the
application's structlog configuration routes stdlib log records
alongside its own).

The fallback tables (``_FALLBACK_ROLE``, ``_FALLBACK_HW_MODEL``,
``_FALLBACK_REGION``) are module-level, ``Final`` dicts kept importable
under those private-but-stable names specifically so a later test layer
can assert they agree with the real protobufs whenever those are
installed.
"""

from __future__ import annotations

import importlib
import logging
import re
import types
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from typing import Final

from meshprovision.errors import EnumMappingError

__all__ = [
    "EnumSource",
    "EnumTable",
    "enum_tables",
    "hw_model_name",
    "hw_model_table",
    "hw_model_value",
    "normalize_enum_name",
    "region_name",
    "region_table",
    "region_value",
    "role_name",
    "role_table",
    "role_value",
]

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Candidate protobuf module/attribute paths, newest layout first.
# ---------------------------------------------------------------------------

_ROLE_PATHS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("meshtastic.protobuf.config_pb2", ("Config", "DeviceConfig", "Role")),
    ("meshtastic.config_pb2", ("Config", "DeviceConfig", "Role")),
)
_HW_MODEL_PATHS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("meshtastic.protobuf.mesh_pb2", ("HardwareModel",)),
    ("meshtastic.mesh_pb2", ("HardwareModel",)),
)
_REGION_PATHS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("meshtastic.protobuf.config_pb2", ("Config", "LoRaConfig", "RegionCode")),
    ("meshtastic.config_pb2", ("Config", "LoRaConfig", "RegionCode")),
)

# ---------------------------------------------------------------------------
# Curated fallback tables, used only when the protobufs cannot be loaded.
# Verified 2026-08-24 against installed meshtastic==2.7.11 protobufs
# (meshtastic.protobuf.config_pb2 / mesh_pb2). Members that could not be
# confirmed against a real protobuf enum were omitted rather than guessed.
# ---------------------------------------------------------------------------

_FALLBACK_ROLE: Final[dict[str, int]] = {
    "CLIENT": 0,
    "CLIENT_MUTE": 1,
    "ROUTER": 2,
    "ROUTER_CLIENT": 3,
    "REPEATER": 4,
    "TRACKER": 5,
    "SENSOR": 6,
    "TAK": 7,
    "CLIENT_HIDDEN": 8,
    "LOST_AND_FOUND": 9,
    "TAK_TRACKER": 10,
    "ROUTER_LATE": 11,
    "CLIENT_BASE": 12,
}

_FALLBACK_REGION: Final[dict[str, int]] = {
    "UNSET": 0,
    "US": 1,
    "EU_433": 2,
    "EU_868": 3,
    "CN": 4,
    "JP": 5,
    "ANZ": 6,
    "KR": 7,
    "TW": 8,
    "RU": 9,
    "IN": 10,
    "NZ_865": 11,
    "TH": 12,
    "LORA_24": 13,
    "UA_433": 14,
    "UA_868": 15,
    "MY_433": 16,
    "MY_919": 17,
    "SG_923": 18,
    "PH_433": 19,
    "PH_868": 20,
    "PH_915": 21,
    "ANZ_433": 22,
    "KZ_433": 23,
    "KZ_863": 24,
    "NP_865": 25,
    "BR_902": 26,
    "ITU1_2M": 27,
    "ITU2_2M": 28,
    "EU_866": 29,
    "EU_874": 30,
    "EU_917": 31,
    "EU_N_868": 32,
    "ITU3_2M": 33,
}

# Every key of chipsets.CHIPSET_BY_HW_MODEL that could be confirmed against
# a real HardwareModel protobuf enum is present here. "RAK4630" and
# "NRF52840DK" appear in CHIPSET_BY_HW_MODEL (their MCU is well known) but
# have no corresponding entry in the installed protobuf's HardwareModel
# enum, so -- per the "drop rather than guess" rule -- they are omitted
# from this fallback table; they degrade gracefully to Chipset.UNKNOWN
# whenever the real protobuf table (which also lacks them) is in effect.
_FALLBACK_HW_MODEL: Final[dict[str, int]] = {
    "UNSET": 0,
    "TLORA_V2": 1,
    "TLORA_V1": 2,
    "TLORA_V2_1_1P6": 3,
    "TBEAM": 4,
    "HELTEC_V2_0": 5,
    "TBEAM_V0P7": 6,
    "T_ECHO": 7,
    "TLORA_V1_1P3": 8,
    "RAK4631": 9,
    "HELTEC_V2_1": 10,
    "HELTEC_V1": 11,
    "LILYGO_TBEAM_S3_CORE": 12,
    "RAK11200": 13,
    "NANO_G1": 14,
    "TLORA_V2_1_1P8": 15,
    "TLORA_T3_S3": 16,
    "NANO_G1_EXPLORER": 17,
    "NANO_G2_ULTRA": 18,
    "WIO_WM1110": 21,
    "STATION_G1": 25,
    "RAK11310": 26,
    "SENSELORA_RP2040": 27,
    "SENSELORA_S3": 28,
    "CANARYONE": 29,
    "RP2040_LORA": 30,
    "STATION_G2": 31,
    "LORA_RELAY_V1": 32,
    "PORTDUINO": 37,
    "DIY_V1": 39,
    "NRF52840_PCA10059": 40,
    "M5STACK": 42,
    "HELTEC_V3": 43,
    "HELTEC_WSL_V3": 44,
    "RPI_PICO": 47,
    "HELTEC_WIRELESS_TRACKER": 48,
    "HELTEC_WIRELESS_PAPER": 49,
    "T_DECK": 50,
    "T_WATCH_S3": 51,
    "PICOMPUTER_S3": 52,
    "HELTEC_HT62": 53,
    "EBYTE_ESP32_S3": 54,
    "ESP32_S3_PICO": 55,
    "UNPHONE": 59,
    "CDEBYTE_EORA_S3": 61,
    "NRF52_PROMICRO_DIY": 63,
    "HELTEC_VISION_MASTER_T190": 66,
    "HELTEC_VISION_MASTER_E213": 67,
    "HELTEC_VISION_MASTER_E290": 68,
    "HELTEC_MESH_NODE_T114": 69,
    "SENSECAP_INDICATOR": 70,
    "TRACKER_T1000_E": 71,
    "RAK3172": 72,
    "WIO_E5": 73,
    "RP2040_FEATHER_RFM95": 76,
    "RPI_PICO2": 79,
    "M5STACK_CORES3": 80,
    "SEEED_XIAO_S3": 81,
    "TLORA_C6": 83,
    "XIAO_NRF52_KIT": 88,
    "PRIVATE_HW": 255,
}


class EnumSource(StrEnum):
    """Where an :class:`EnumTable`'s contents came from."""

    PROTOBUF = "protobuf"
    FALLBACK = "fallback"


@dataclass(frozen=True, slots=True)
class EnumTable:
    """A bidirectional, alias-tolerant name/number table for one protobuf enum.

    Attributes:
        name: Short identifier for this table (``"role"``, ``"hw_model"``,
            or ``"region"``).
        source: Whether this table's data came from the installed
            protobufs or the bundled fallback.
        name_to_value: Read-only mapping from canonical ``UPPER_SNAKE``
            name to numeric value.
        value_to_name: Read-only mapping from numeric value to its
            canonical name (the first name encountered, when the
            protobuf enum has aliases sharing one number).
    """

    name: str
    source: EnumSource
    name_to_value: Mapping[str, int]
    value_to_name: Mapping[int, str]

    def names(self) -> tuple[str, ...]:
        """Return every canonical name, ordered by ascending numeric value.

        Returns:
            A tuple of canonical names.
        """
        return tuple(name for _, name in sorted(self.value_to_name.items()))

    def values(self) -> tuple[int, ...]:
        """Return every numeric value, ascending.

        Returns:
            A tuple of numeric values.
        """
        return tuple(sorted(self.value_to_name.keys()))

    def items(self) -> tuple[tuple[str, int], ...]:
        """Return ``(name, value)`` pairs, ordered by ascending numeric value.

        Returns:
            A tuple of ``(name, value)`` pairs.
        """
        return tuple((name, value) for value, name in sorted(self.value_to_name.items()))

    def contains_name(self, name: str) -> bool:
        """Check whether ``name`` (after normalization) is known.

        Args:
            name: A candidate name, in any case/spacing convention.

        Returns:
            ``True`` if the normalized name is in this table.
        """
        return self.normalize(name) in self.name_to_value

    def contains_value(self, value: int) -> bool:
        """Check whether ``value`` is a known numeric value.

        Args:
            value: A candidate numeric value.

        Returns:
            ``True`` if ``value`` is in this table.
        """
        return value in self.value_to_name

    def normalize(self, name: str) -> str:
        """Canonicalize a name string. Pure string operation; never raises.

        Args:
            name: A candidate name, in any case/spacing convention.

        Returns:
            The canonicalized form, via :func:`normalize_enum_name`.
        """
        return normalize_enum_name(name)

    def to_name(self, value: int | str) -> str:
        """Resolve ``value`` to its canonical name.

        An ``int`` is looked up directly. A ``str`` of all ASCII digits is
        reinterpreted as an ``int`` and looked up the same way (loranet
        and lorastats sometimes stringify numeric enum values). Any other
        ``str`` is normalized and confirmed present, returning the
        normalized name itself.

        Args:
            value: A numeric value, a digit string, or a name string.

        Returns:
            The canonical name.

        Raises:
            EnumMappingError: If ``value`` cannot be resolved to a known
                name.
        """
        if isinstance(value, int) and not isinstance(value, bool):
            name = self.value_to_name.get(value)
            if name is not None:
                return name
            raise EnumMappingError(
                f"Unknown {self.name} value: {value!r}",
                enum_name=self.name,
                value=value,
                known=self.names(),
            )
        if isinstance(value, str):
            token = value.strip()
            if token.isascii() and token.isdigit():
                return self.to_name(int(token))
            normalized = self.normalize(value)
            if normalized in self.name_to_value:
                return normalized
            raise EnumMappingError(
                f"Unknown {self.name} value: {value!r}",
                enum_name=self.name,
                value=value,
                known=self.names(),
            )
        raise EnumMappingError(
            f"Unknown {self.name} value: {value!r}",
            enum_name=self.name,
            value=str(value),
            known=self.names(),
        )

    def to_value(self, name: str | int) -> int:
        """Resolve ``name`` to its numeric value. The mirror of :meth:`to_name`.

        A ``str`` is normalized and looked up directly. An ``int`` is
        confirmed to already be a known value and returned unchanged.

        Args:
            name: A name string, or a numeric value already.

        Returns:
            The numeric value.

        Raises:
            EnumMappingError: If ``name`` cannot be resolved to a known
                value.
        """
        if isinstance(name, str):
            token = name.strip()
            if token.isascii() and token.isdigit():
                return self.to_value(int(token))
            normalized = self.normalize(name)
            value = self.name_to_value.get(normalized)
            if value is not None:
                return value
            raise EnumMappingError(
                f"Unknown {self.name} name: {name!r}",
                enum_name=self.name,
                value=name,
                known=self.names(),
            )
        if isinstance(name, int) and not isinstance(name, bool):
            if name in self.value_to_name:
                return name
            raise EnumMappingError(
                f"Unknown {self.name} name: {name!r}",
                enum_name=self.name,
                value=name,
                known=self.names(),
            )
        raise EnumMappingError(
            f"Unknown {self.name} name: {name!r}",
            enum_name=self.name,
            value=str(name),
            known=self.names(),
        )

    def try_name(self, value: int | str) -> str | None:
        """Like :meth:`to_name`, returning ``None`` instead of raising.

        Args:
            value: A numeric value, a digit string, or a name string.

        Returns:
            The canonical name, or ``None`` if unresolved.
        """
        try:
            return self.to_name(value)
        except EnumMappingError:
            return None

    def try_value(self, name: str | int) -> int | None:
        """Like :meth:`to_value`, returning ``None`` instead of raising.

        Args:
            name: A name string, or a numeric value already.

        Returns:
            The numeric value, or ``None`` if unresolved.
        """
        try:
            return self.to_value(name)
        except EnumMappingError:
            return None


def normalize_enum_name(name: str) -> str:
    """Canonicalize an enum name string for lookup purposes.

    Strips surrounding whitespace, upper-cases, replaces ``-`` and spaces
    with ``_``, collapses runs of ``_`` to one, and strips leading/
    trailing ``_``. This is what reconciles loranet's human-ish strings
    (``"Client"``, ``"Router Client"``, ``"T-Beam"``) against protobuf
    names (``"CLIENT"``, ``"ROUTER_CLIENT"``, ``"TBEAM"`` would still
    differ, but ``"T_BEAM"``-style variants converge).

    This function does no table lookup and never raises.

    Args:
        name: A candidate name, in any case/spacing convention.

    Returns:
        The canonicalized ``UPPER_SNAKE`` form.
    """
    token = name.strip().upper()
    token = token.replace("-", "_").replace(" ", "_")
    token = re.sub(r"_+", "_", token)
    return token.strip("_")


def _load_protobuf_items(
    paths: tuple[tuple[str, tuple[str, ...]], ...],
) -> list[tuple[str, int]] | None:
    """Try each candidate protobuf module/attribute path in order.

    Args:
        paths: Candidate ``(module_path, attribute_chain)`` pairs, newest
            layout first.

    Returns:
        The first non-empty list of ``(name, number)`` pairs found, or
        ``None`` if every candidate failed.
    """
    for module_path, attr_chain in paths:
        try:
            obj: object = importlib.import_module(module_path)
            for attr in attr_chain:
                obj = getattr(obj, attr)
            descriptor = getattr(obj, "DESCRIPTOR", None)
            if descriptor is not None:
                items = [(v.name, v.number) for v in descriptor.values]
            else:
                items = list(obj.items())  # type: ignore[attr-defined]
            if items:
                return items
        except (ImportError, AttributeError, TypeError):
            continue
    return None


def _build_table(
    name: str, paths: tuple[tuple[str, tuple[str, ...]], ...], fallback: Mapping[str, int]
) -> EnumTable:
    """Build an :class:`EnumTable`, preferring the installed protobufs.

    Args:
        name: Short identifier for the resulting table.
        paths: Candidate protobuf module/attribute paths to try.
        fallback: The curated fallback name-to-value mapping to use if
            every protobuf path fails.

    Returns:
        The constructed, immutable :class:`EnumTable`.
    """
    items = _load_protobuf_items(paths)
    if items is None:
        _logger.warning(
            "meshtastic protobufs unavailable; using the bundled fallback table for %s", name
        )
        items = list(fallback.items())
        source = EnumSource.FALLBACK
    else:
        source = EnumSource.PROTOBUF

    name_to_value: dict[str, int] = {}
    value_to_name: dict[int, str] = {}
    for raw_name, value in items:
        canonical = normalize_enum_name(raw_name)
        name_to_value[canonical] = value
        if value not in value_to_name:
            value_to_name[value] = canonical

    return EnumTable(
        name=name,
        source=source,
        name_to_value=types.MappingProxyType(name_to_value),
        value_to_name=types.MappingProxyType(value_to_name),
    )


@cache
def role_table() -> EnumTable:
    """Return the Role enum table, cached after first build.

    Returns:
        The :class:`EnumTable` for ``config.device.role``.
    """
    return _build_table("role", _ROLE_PATHS, _FALLBACK_ROLE)


@cache
def hw_model_table() -> EnumTable:
    """Return the HardwareModel enum table, cached after first build.

    Returns:
        The :class:`EnumTable` for the device's ``hw_model``.
    """
    return _build_table("hw_model", _HW_MODEL_PATHS, _FALLBACK_HW_MODEL)


@cache
def region_table() -> EnumTable:
    """Return the LoRa RegionCode enum table, cached after first build.

    Returns:
        The :class:`EnumTable` for ``config.lora.region``.
    """
    return _build_table("region", _REGION_PATHS, _FALLBACK_REGION)


def enum_tables() -> Mapping[str, EnumTable]:
    """Return all three enum tables, keyed by short name.

    This is what ``db/schema.py`` iterates to build the ODS
    ``table:content-validation`` dropdown lists for the ``role``,
    ``hw_model`` and ``region`` columns.

    Returns:
        A read-only mapping ``{"role": ..., "hw_model": ..., "region": ...}``.
    """
    return types.MappingProxyType(
        {
            "role": role_table(),
            "hw_model": hw_model_table(),
            "region": region_table(),
        }
    )


def role_name(value: int | str) -> str:
    """Resolve a Role value or string to its canonical name.

    Args:
        value: A numeric role value, digit string, or name string.

    Returns:
        The canonical role name.

    Raises:
        EnumMappingError: If ``value`` cannot be resolved.
    """
    return role_table().to_name(value)


def role_value(name: str | int) -> int:
    """Resolve a Role name or value to its numeric value.

    Args:
        name: A role name string, or a numeric value already.

    Returns:
        The numeric role value.

    Raises:
        EnumMappingError: If ``name`` cannot be resolved.
    """
    return role_table().to_value(name)


def hw_model_name(value: int | str) -> str:
    """Resolve a HardwareModel value or string to its canonical name.

    Args:
        value: A numeric hw_model value, digit string, or name string.

    Returns:
        The canonical hardware model name.

    Raises:
        EnumMappingError: If ``value`` cannot be resolved.
    """
    return hw_model_table().to_name(value)


def hw_model_value(name: str | int) -> int:
    """Resolve a HardwareModel name or value to its numeric value.

    Args:
        name: A hardware model name string, or a numeric value already.

    Returns:
        The numeric hw_model value.

    Raises:
        EnumMappingError: If ``name`` cannot be resolved.
    """
    return hw_model_table().to_value(name)


def region_name(value: int | str) -> str:
    """Resolve a RegionCode value or string to its canonical name.

    Args:
        value: A numeric region value, digit string, or name string.

    Returns:
        The canonical region name.

    Raises:
        EnumMappingError: If ``value`` cannot be resolved.
    """
    return region_table().to_name(value)


def region_value(name: str | int) -> int:
    """Resolve a RegionCode name or value to its numeric value.

    Args:
        name: A region name string, or a numeric value already.

    Returns:
        The numeric region value.

    Raises:
        EnumMappingError: If ``name`` cannot be resolved.
    """
    return region_table().to_value(name)
