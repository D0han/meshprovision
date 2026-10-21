"""``HistoryStore``: each node's health history as one JSON file in the cache directory.

One file per node, ``<cache dir>/health/<hex id>.json``, so a refresh
rewrites only the node it refreshed and two ``mesh`` processes only meet
on the same node. Each file is written like the lorastats region memo
(:mod:`meshprovision.datasources.json_store`): created owner-only in an
owner-only directory, replaced atomically, read tolerantly. A missing,
corrupt, oversized or wrong-version file reads as an empty history, an
entry of an unexpected shape is dropped, and a failed write is skipped;
both are logged at DEBUG, never raised. An update re-reads the file and
merges its own refresh into what it finds (see
:func:`~meshprovision.health.history.merge`), so two processes refreshing
the same node at once both leave a complete history; at worst one
refresh's data is fetched again. On Windows a file that another process
is reading cannot be replaced: that write is skipped and the refresh
repeated by a later run.

**Bounds.** Everything older than 30 days is dropped on every write, as is
every file not written for 30 days. A file is at most
:data:`HISTORY_MAX_FILE_BYTES` (the oldest days are dropped until it fits,
and a larger file is not read) and at most :data:`HISTORY_MAX_NODES` files
are kept (the least recently written go first), so the directory never
holds more than ``HISTORY_MAX_NODES * HISTORY_MAX_FILE_BYTES`` (256 MiB).
A month of a node heard by 10-30 gateways an hour takes 0.5-1 MB; even
64 gateways and 64 relays every hour with every series full stays just
under 2 MiB.
"""

from __future__ import annotations

import contextlib
import json
import logging
import math
import re
import time
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

from meshprovision.datasources.json_store import read_json, write_json
from meshprovision.health.history import (
    HISTORY_RETENTION_SECONDS,
    HOUR_SECONDS,
    MAX_GATEWAYS_PER_HOUR,
    MAX_RELAYS_PER_HOUR,
    SNR_BIN_MAX,
    SNR_BIN_MIN,
    GatewayCheck,
    HourBucket,
    LocalStatsPoint,
    NodeHistory,
    NodeInfoSeen,
    PositionPoint,
    TelemetryPoint,
    prune,
)
from meshprovision.nodeid import NodeId
from meshprovision.termsafe import terminal_safe

if TYPE_CHECKING:
    from pathlib import Path

__all__ = [
    "HISTORY_DIRNAME",
    "HISTORY_MAX_FILE_BYTES",
    "HISTORY_MAX_NODES",
    "HISTORY_VERSION",
    "HistoryStore",
    "history_from_json",
    "history_to_json",
]

_logger = logging.getLogger(__name__)

HISTORY_DIRNAME: Final[str] = "health"
"""The history directory's name, directly in the HTTP cache directory."""

HISTORY_VERSION: Final[int] = 1
"""On-disk schema version. A file with any other version reads as empty."""

HISTORY_MAX_FILE_BYTES: Final[int] = 2 * 1024 * 1024
"""The largest history file written or read."""

HISTORY_MAX_NODES: Final[int] = 128
"""The most history files kept."""

_INT_KEY_RE: Final[re.Pattern[str]] = re.compile(r"^(?:-?[1-9][0-9]{0,9}|0)\Z")
_HEX_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{8}\Z")
_FILE_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{8}\.json\Z")
_WHAT: Final[str] = "health history"
_MAX_COUNT: Final[int] = 10**9
_MAX_TEXT: Final[int] = 256
_MAX_HOUR: Final[int] = 2**40
_MAX_HOPS: Final[int] = 7
_MAX_BYTE: Final[int] = 255
_MAX_PORT: Final[int] = 1023
_DAY_HOURS: Final[int] = 24


class HistoryStore:
    """The per-node history files under one directory."""

    def __init__(self, directory: Path, *, clock: Callable[[], float] = time.time) -> None:
        """Initialize the store. Nothing is read or written until it is used.

        Args:
            directory: The history directory, normally
                ``cache_dir / HISTORY_DIRNAME``.
            clock: Callable returning the current unix epoch seconds.
        """
        self._directory = directory
        self._clock = clock

    @property
    def directory(self) -> Path:
        """The history directory.

        Returns:
            The constructor's ``directory``.
        """
        return self._directory

    def path_for(self, node: NodeId) -> Path:
        """Return the file of ``node``'s history.

        Args:
            node: The node.

        Returns:
            ``directory / "<hex id>.json"``.
        """
        return self._directory / f"{node.hex}.json"

    def load(self, node: NodeId) -> NodeHistory:
        """Read ``node``'s history.

        Args:
            node: The node.

        Returns:
            Its history, pruned to the retention; an empty one when there
            is no usable file.
        """
        document = read_json(self.path_for(node), max_bytes=HISTORY_MAX_FILE_BYTES, what=_WHAT)
        history = history_from_json(document, node)
        if history is None:
            if document is not None:
                _logger.debug("ignoring the %s of %s: unexpected shape", _WHAT, node.hex)
            return NodeHistory(node=node)
        return prune(history, now=self._clock())

    def update(self, node: NodeId, change: Callable[[NodeHistory], NodeHistory]) -> NodeHistory:
        """Re-read ``node``'s history, apply ``change``, bound it and write it back.

        Args:
            node: The node.
            change: Builds the new history from the stored one.

        Returns:
            The history as written (also when the write failed).
        """
        now = self._clock()
        history = prune(change(self.load(node)), now=now)
        document = history_to_json(history)
        while len(_encoded(document)) > HISTORY_MAX_FILE_BYTES and history.hours:
            history = _drop_oldest_day(history)
            document = history_to_json(history)
        write_json(self.path_for(node), document, what=_WHAT)
        self._sweep(keep=self.path_for(node), now=now)
        return history

    def _sweep(self, *, keep: Path, now: float) -> None:
        """Delete files not written for the retention, then the oldest beyond the cap.

        Args:
            keep: The file just written, never deleted.
            now: The current time, epoch seconds.
        """
        try:
            files = [
                (entry.stat().st_mtime, entry)
                for entry in self._directory.iterdir()
                if _FILE_RE.match(entry.name) and entry != keep
            ]
        except OSError as exc:
            _logger.debug("could not list the %s directory %s: %s", _WHAT, self._directory, exc)
            return
        files.sort(reverse=True)
        oldest = now - HISTORY_RETENTION_SECONDS
        for index, (mtime, entry) in enumerate(files):
            if mtime < oldest or index >= HISTORY_MAX_NODES - 1:
                with contextlib.suppress(OSError):
                    entry.unlink()


def _encoded(document: object) -> bytes:
    """Encode a document exactly as :func:`write_json` does."""
    return json.dumps(document).encode("utf-8")


def _drop_oldest_day(history: NodeHistory) -> NodeHistory:
    """Drop the oldest 24 hour buckets and every point before the next remaining hour."""
    hours = history.hours[_DAY_HOURS:]
    start = hours[0].hour if hours else math.inf

    def kept(time_: float) -> bool:
        return time_ >= start

    return NodeHistory(
        node=history.node,
        fetched_at=history.fetched_at,
        last_heard=history.last_heard,
        hours=hours,
        telemetry=tuple(p for p in history.telemetry if kept(p.time)),
        local_stats=tuple(p for p in history.local_stats if kept(p.time)),
        positions=tuple(p for p in history.positions if kept(p.time)),
        nodeinfo=history.nodeinfo,
        neighbors=history.neighbors,
        boots=tuple(b for b in history.boots if kept(b)),
        gateway_checks=tuple(c for c in history.gateway_checks if kept(c.time)),
    )


def history_to_json(history: NodeHistory) -> dict[str, object]:
    """Render a history as its on-disk JSON document.

    Args:
        history: The history.

    Returns:
        A JSON-serializable mapping (bucket fields that are zero or empty
        are left out).
    """
    info = history.nodeinfo
    return {
        "version": HISTORY_VERSION,
        "node": history.node.hex,
        "fetched_at": history.fetched_at,
        "last_heard": history.last_heard,
        "hours": [_bucket_to_json(bucket) for bucket in history.hours],
        "telemetry": [
            [p.time, p.battery, p.voltage, p.channel_utilization, p.air_util_tx]
            for p in history.telemetry
        ],
        "local_stats": [[p.time, p.rx, p.tx, p.relayed] for p in history.local_stats],
        "positions": [[p.time, p.latitude, p.longitude] for p in history.positions],
        "nodeinfo": None
        if info is None
        else [info.time, info.short_name, info.long_name, info.role],
        "neighbors": dict(history.neighbors),
        "boots": list(history.boots),
        "gateway_checks": [
            [c.time, c.window_seconds, c.receptions, c.nodes] for c in history.gateway_checks
        ],
    }


def _bucket_to_json(bucket: HourBucket) -> dict[str, object]:
    """Render one hour bucket, leaving out zero and empty fields."""
    fields: dict[str, object] = {
        "rx": bucket.receptions,
        "pk": bucket.packets,
        "dr": bucket.direct,
        "gw": dict(bucket.gateways),
        "rl": {str(key): value for key, value in bucket.relays.items()},
        "hp": {str(key): value for key, value in bucket.hops.items()},
        "sn": {str(key): value for key, value in bucket.snr.items()},
        "rs": None if bucket.rssi is None else list(bucket.rssi),
        "pt": {str(key): value for key, value in bucket.ports.items()},
        "hs": {str(key): value for key, value in bucket.hop_starts.items()},
    }
    return {"h": bucket.hour, **{key: value for key, value in fields.items() if value}}


def history_from_json(document: object, node: NodeId) -> NodeHistory | None:
    """Read a history from its on-disk JSON document.

    Args:
        document: The decoded file, or ``None``.
        node: The node the file must belong to.

    Returns:
        The history without any entry of an unexpected shape (for a
        repeated hour or time, the last entry), or ``None`` unless
        ``document`` is a version :data:`HISTORY_VERSION` history of
        ``node``.
    """
    if not isinstance(document, dict) or document.get("version") != HISTORY_VERSION:
        return None
    if document.get("node") != node.hex:
        return None
    hours = {
        bucket.hour: bucket
        for bucket in map(_bucket_from_json, _list(document.get("hours")))
        if bucket is not None
    }
    info = _row(document.get("nodeinfo"), (_time, _text, _text, _optional(_text)))
    return NodeHistory(
        node=node,
        fetched_at=_time(document.get("fetched_at")),
        last_heard=_time(document.get("last_heard")),
        hours=tuple(hours[hour] for hour in sorted(hours)),
        telemetry=_points(document.get("telemetry"), TelemetryPoint, _TELEMETRY),
        local_stats=_points(document.get("local_stats"), LocalStatsPoint, _LOCAL_STATS),
        positions=_points(document.get("positions"), PositionPoint, _POSITION),
        nodeinfo=None if info is None else NodeInfoSeen(*info),
        neighbors=MappingProxyType(
            {
                key: seen
                for key, raw in sorted(_dict(document.get("neighbors")).items())
                if _hex_key(key) is not None and (seen := _time(raw)) is not None
            }
        ),
        boots=tuple(sorted({t for t in map(_time, _list(document.get("boots"))) if t is not None})),
        gateway_checks=_points(document.get("gateway_checks"), GatewayCheck, _GATEWAY_CHECK),
    )


_Reader = Callable[[object], Any]
"""Reads one JSON value: the value to keep, or ``None`` when it is malformed."""

_ABSENT: Final[object] = object()
"""What an :func:`_optional` reader returns for ``null``."""


def _list(value: object) -> list[Any]:
    """Return ``value`` when it is a list, else an empty one."""
    return value if isinstance(value, list) else []


def _dict(value: object) -> dict[Any, Any]:
    """Return ``value`` when it is an object, else an empty one."""
    return value if isinstance(value, dict) else {}


def _finite(value: object, low: float, high: float) -> float | None:
    """Read a finite number (not a bool) within ``low..high``."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        number = float(value)
    except OverflowError:  # an int too large for a float
        return None
    return number if math.isfinite(number) and low <= number <= high else None


def _time(value: object) -> float | None:
    """Read a finite, non-negative epoch time."""
    return _finite(value, 0, math.inf)


def _number(low: float, high: float) -> _Reader:
    """Build a reader of a finite number (not a bool) within ``low..high``."""
    return lambda value: _finite(value, low, high)


def _integer(low: int, high: int) -> _Reader:
    """Build a reader of an int (not a bool) within ``low..high``."""

    def read(value: object) -> int | None:
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value if low <= value <= high else None

    return read


_count: Final[_Reader] = _integer(0, _MAX_COUNT)


def _text(value: object) -> str | None:
    """Read a non-blank string of at most 256 characters, made terminal-safe."""
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT:
        return None
    return terminal_safe(value)


def _optional(read: _Reader) -> _Reader:
    """Build a reader that also accepts ``null`` (as :data:`_ABSENT`)."""

    def read_optional(value: object) -> Any:
        return _ABSENT if value is None else read(value)

    return read_optional


def _row(value: object, readers: tuple[_Reader, ...]) -> list[Any] | None:
    """Read a fixed-length JSON array, one reader per item; ``None`` when any is malformed."""
    if not isinstance(value, list) or len(value) != len(readers):
        return None
    items = [read(raw) for read, raw in zip(readers, value, strict=True)]
    if any(item is None for item in items):
        return None
    return [None if item is _ABSENT else item for item in items]


_TELEMETRY: Final[tuple[_Reader, ...]] = (
    _time,
    _optional(_integer(0, 101)),
    _optional(_number(0, 10)),
    _optional(_number(0, 100)),
    _optional(_number(0, 100)),
)
_LOCAL_STATS: Final[tuple[_Reader, ...]] = (
    _time,
    _optional(_count),
    _optional(_count),
    _optional(_count),
)
_POSITION: Final[tuple[_Reader, ...]] = (_time, _number(-90, 90), _number(-180, 180))
_GATEWAY_CHECK: Final[tuple[_Reader, ...]] = (_time, _time, _count, _count)


def _points(
    value: object, build: Callable[..., Any], readers: tuple[_Reader, ...]
) -> tuple[Any, ...]:
    """Read a list of points, dropping malformed ones and keeping the last of a repeated time."""
    points = {}
    for item in _list(value):
        fields = _row(item, readers)
        if fields is not None:
            point = build(*fields)
            points[point.time] = point
    return tuple(points[key] for key in sorted(points))


def _counts(value: object, key: _Reader, limit: int) -> Mapping[Any, int] | None:
    """Read a ``{key: count}`` object of at most ``limit`` entries; ``None`` when malformed."""
    if not isinstance(value, dict) or len(value) > limit:
        return None
    result = {}
    for raw_key, raw_count in value.items():
        parsed_key = key(raw_key)
        count = _count(raw_count)
        if parsed_key is None or count is None:
            return None
        result[parsed_key] = count
    return MappingProxyType(dict(sorted(result.items())))


def _int_key(low: int, high: int) -> _Reader:
    """Build a reader of a canonical decimal integer key within ``low..high``."""

    def read(raw: object) -> int | None:
        if not isinstance(raw, str) or not _INT_KEY_RE.match(raw):
            return None
        return int(raw) if low <= int(raw) <= high else None

    return read


def _hex_key(raw: object) -> str | None:
    """Read a canonical (lowercase, 8-digit) hex node id key."""
    return raw if isinstance(raw, str) and _HEX_ID_RE.match(raw) else None


def _bucket_from_json(value: object) -> HourBucket | None:
    """Read one hour bucket; ``None`` when any field is malformed."""
    fields = _dict(value)
    hour = _integer(0, _MAX_HOUR)(fields.get("h"))
    if hour is None or hour % HOUR_SECONDS:
        return None
    counts: dict[str, Any] = {name: _count(fields.get(name, 0)) for name in ("rx", "pk", "dr")}
    maps: dict[str, Any] = {
        name: _counts(fields.get(name, {}), key, limit)
        for name, key, limit in (
            ("gw", _hex_key, MAX_GATEWAYS_PER_HOUR),
            ("rl", _int_key(0, _MAX_BYTE), MAX_RELAYS_PER_HOUR),
            ("hp", _int_key(0, _MAX_HOPS), _MAX_HOPS + 1),
            ("sn", _int_key(SNR_BIN_MIN, SNR_BIN_MAX), SNR_BIN_MAX - SNR_BIN_MIN + 1),
            ("pt", _int_key(0, _MAX_PORT), _MAX_PORT + 1),
            ("hs", _int_key(0, _MAX_HOPS), _MAX_HOPS + 1),
        )
    }
    rssi = _optional(_row_reader((_count, _count, _count, _count)))(fields.get("rs"))
    if any(v is None for v in (*counts.values(), *maps.values(), rssi)):
        return None
    return HourBucket(
        hour=hour,
        receptions=counts["rx"],
        packets=counts["pk"],
        direct=counts["dr"],
        gateways=maps["gw"],
        relays=maps["rl"],
        hops=maps["hp"],
        snr=maps["sn"],
        rssi=None if rssi is _ABSENT else tuple(rssi),
        ports=maps["pt"],
        hop_starts=maps["hs"],
    )


def _row_reader(readers: tuple[_Reader, ...]) -> _Reader:
    """Build a reader of a fixed-length array (see :func:`_row`)."""
    return lambda value: _row(value, readers)
