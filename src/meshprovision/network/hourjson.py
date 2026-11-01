"""One hour of a region's traffic as JSON, and back: the day files' format. Pure.

An hour is ``{"h": <hour start>, "pk", "rl", "dr", "ob", "so", "og",
"ed", "nr"}``, one key per :class:`~meshprovision.network.buckets.Traffic`
field, each left out when empty:

- ``pk`` ``{origin: packets}``; ``so`` ``{origin: {byte: packets}}``;
  ``og`` ``{origin: {gateway: packets}}``;
- ``rl`` ``{byte: {gateway: [n, measured, snr_sum, rssi_sum]}}`` and ``dr``
  ``{origin: {gateway: [...]}}`` (:class:`~meshprovision.network.buckets.Radio`);
- ``ob`` ``{origin: {byte: [n, first_hop]}}``
  (:class:`~meshprovision.network.buckets.LastHop`);
- ``ed`` ``[[a, b, source, n], ...]`` with ``a < b``; ``nr`` a count.

Node ids are canonical hex, relay bytes decimal strings ``"1"``..``"255"``.
Reading is strict per hour: any malformed field makes the whole hour
unusable (``None``), never an exception.

This module imports nothing that reads files or the network (no
``httpx``, ``pathlib``, :mod:`meshprovision.cache` or
:mod:`meshprovision.db`); ``tests/unit/test_import_contracts.py`` holds it
to that.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Any, Final

from meshprovision.health.history import HOUR_SECONDS
from meshprovision.network.buckets import (
    EDGE_NEIGHBOR,
    EDGE_TRACEROUTE,
    LastHop,
    Radio,
    RegionHour,
    Traffic,
)

__all__ = ["hour_from_json", "hour_to_json", "read_count", "read_number"]

_HEX_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{8}\Z")
_BYTE_RE: Final[re.Pattern[str]] = re.compile(r"^[1-9][0-9]{0,2}\Z")
_MAX_COUNT: Final[int] = 10**9
_MAX_HOUR: Final[int] = 2**40
_MAX_SNR_DB: Final[float] = 50.0
_MIN_RSSI_DBM: Final[int] = -200
_MAX_BYTE: Final[int] = 255
_SOURCES: Final[frozenset[str]] = frozenset({EDGE_TRACEROUTE, EDGE_NEIGHBOR})


def hour_to_json(bucket: RegionHour) -> dict[str, object]:
    """Render one hour as JSON, leaving out empty fields.

    Args:
        bucket: The hour.

    Returns:
        ``{"h": <hour>, "pk", "rl", "dr", "ob", "so", "og", "ed", "nr"}``;
        relay bytes are decimal string keys, SNR sums are rounded to 0.01 dB.
    """
    t = bucket.traffic
    fields: dict[str, object] = {
        "pk": dict(t.packets),
        "rl": {str(b): _cells(gws) for b, gws in t.relayed.items()},
        "dr": {o: _cells(gws) for o, gws in t.direct.items()},
        "ob": {
            o: {str(b): [h.receptions, h.first_hop] for b, h in v.items()}
            for o, v in t.last_hops.items()
        },
        "so": {o: {str(b): n for b, n in v.items()} for o, v in t.sole_relay.items()},
        "og": {o: dict(v) for o, v in t.only_gateway.items()},
        "ed": [[a, b, source, n] for (a, b, source), n in t.edges.items()],
        "nr": t.unrelayed,
    }
    return {"h": bucket.hour, **{key: value for key, value in fields.items() if value}}


def _cells(cells: Mapping[str, Radio]) -> dict[str, list[Any]]:
    """Render ``{gateway: Radio}`` as ``{gateway: [n, measured, snr_sum, rssi_sum]}``."""
    return {
        key: [radio.receptions, radio.measured, round(radio.snr_sum, 2), radio.rssi_sum]
        for key, radio in cells.items()
    }


def hour_from_json(value: object) -> RegionHour | None:
    """Read one hour; ``None`` when any field is malformed.

    Args:
        value: One item of a day file's ``hours``.

    Returns:
        The hour, or ``None``.
    """
    fields = value if isinstance(value, dict) else {}
    hour = read_count(fields.get("h"), _MAX_HOUR)
    if hour is None or hour % HOUR_SECONDS:
        return None
    maps = (
        _map(fields.get("pk", {}), _hex, read_count),
        _nested(fields.get("rl", {}), _byte, _hex, _radio),
        _nested(fields.get("dr", {}), _hex, _hex, _radio),
        _nested(fields.get("ob", {}), _hex, _byte, _last_hop),
        _nested(fields.get("so", {}), _hex, _byte, read_count),
        _nested(fields.get("og", {}), _hex, _hex, read_count),
    )
    edges, unrelayed = _edges(fields.get("ed", [])), read_count(fields.get("nr", 0))
    if edges is None or unrelayed is None or any(part is None for part in maps):
        return None
    return RegionHour(hour, Traffic(*maps, edges=edges, unrelayed=unrelayed))


def read_number(value: object, low: float, high: float) -> float | None:
    """Read a finite number (not a bool) within ``low..high``."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) and low <= number <= high else None


def read_count(value: object, high: int = _MAX_COUNT) -> int | None:
    """Read an int (not a bool) within ``0..high``."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= high else None


def _hex(key: object) -> str | None:
    """Read a canonical (lowercase, 8-digit) hex node id key."""
    return key if isinstance(key, str) and _HEX_RE.match(key) else None


def _byte(key: object) -> int | None:
    """Read a relay byte key: a canonical decimal ``1..255``."""
    if not isinstance(key, str) or not _BYTE_RE.match(key):
        return None
    return int(key) if int(key) <= _MAX_BYTE else None


def _radio(value: object) -> Radio | None:
    """Read ``[receptions, measured, snr_sum, rssi_sum]``."""
    if not isinstance(value, list) or len(value) != 4:
        return None
    receptions, measured = read_count(value[0]), read_count(value[1])
    if receptions is None or measured is None or measured > receptions:
        return None
    snr = read_number(value[2], -_MAX_SNR_DB * measured, _MAX_SNR_DB * measured)
    rssi = value[3]
    if snr is None or isinstance(rssi, bool) or not isinstance(rssi, int):
        return None
    return Radio(receptions, measured, snr, rssi) if _MIN_RSSI_DBM * measured <= rssi <= 0 else None


def _last_hop(value: object) -> LastHop | None:
    """Read ``[receptions, first_hop]``."""
    if not isinstance(value, list) or len(value) != 2:
        return None
    receptions, first_hop = read_count(value[0]), read_count(value[1])
    if receptions is None or first_hop is None or first_hop > receptions:
        return None
    return LastHop(receptions, first_hop)


def _map(value: object, key: Callable[[object], Any], read: Callable[[object], Any]) -> Any:
    """Read a ``{key: value}`` object, sorted by key; ``None`` when anything is malformed."""
    if not isinstance(value, dict):
        return None
    result = {}
    for raw_key, raw_value in value.items():
        parsed_key, parsed = key(raw_key), read(raw_value)
        if parsed_key is None or parsed is None:
            return None
        result[parsed_key] = parsed
    return MappingProxyType(dict(sorted(result.items())))


def _nested(
    value: object,
    key: Callable[[object], Any],
    inner: Callable[[object], Any],
    read: Callable[[object], Any],
) -> Any:
    """Read a ``{key: {inner key: value}}`` object; ``None`` when anything is malformed."""
    return _map(value, key, lambda cells: _map(cells, inner, read))


def _edges(value: object) -> Mapping[tuple[str, str, str], int] | None:
    """Read ``[[a, b, source, count], ...]`` with ``a < b``; ``None`` when any is malformed."""
    if not isinstance(value, list):
        return None
    edges: dict[tuple[str, str, str], int] = {}
    for item in value:
        if not isinstance(item, list) or len(item) != 4:
            return None
        a, b, source, count = _hex(item[0]), _hex(item[1]), item[2], read_count(item[3])
        if a is None or b is None or a >= b or source not in _SOURCES or not count:
            return None
        edges[(a, b, source)] = count
    return MappingProxyType(dict(sorted(edges.items())))
