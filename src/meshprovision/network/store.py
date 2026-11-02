"""``RegionStore``: a region's hourly traffic as one JSON file per UTC day in the cache directory.

One directory per region, ``<cache dir>/network/r-<digest>/`` where the
digest is the first 16 hex digits of the SHA-256 of the region's NFC
name: region names are Unicode, and ``Zachód`` and ``zachód`` are two
regions even on a case-insensitive file system. In it, one file per UTC
day, ``YYYY-MM-DD.json``, holding that day's hours (see
:mod:`meshprovision.network.buckets`), and ``state.json``, when the region
was last fetched, and ``relays.json``, the node each relay byte was last
resolved ``high`` to (see :mod:`meshprovision.network.resolve`), kept for
:data:`LEARNED_RELAY_MAX_AGE_SECONDS`. Every file also names its region;
one that names another reads as empty.

Each file is written like a node's health history
(:mod:`meshprovision.health.store`): created owner-only in an owner-only
directory, replaced atomically, read tolerantly. A missing, corrupt,
oversized or wrong-version file reads as empty, an hour of an unexpected
shape is dropped, and a failed write is skipped; both are logged at DEBUG,
never raised. An update re-reads each day file it changes and replaces
only the hours of its own refresh (see
:func:`~meshprovision.network.buckets.merge`), so two processes refreshing
the same region at once both leave a complete store.

**Bounds.** Hours older than :data:`~meshprovision.network.buckets.NETWORK_RETENTION_DAYS`
days are dropped on every write, and a day file older than that is
deleted. A day file is at most :data:`DAY_MAX_BYTES` (its oldest hours
are dropped until it fits; a larger file is not read). A region's day
files take at most :data:`REGION_MAX_BYTES` (its oldest days go first),
all regions' at most :data:`STORE_MAX_TOTAL_BYTES` (the oldest days of
the least recently refreshed region go first), and a region not refreshed
for the retention, once it has no day file left, is removed.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import math
import re
import time
import unicodedata
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from meshprovision.datasources.json_store import read_json, write_json
from meshprovision.health.history import (
    DAY_SECONDS,
    FUTURE_SKEW_SECONDS,
    floor_hour,
)
from meshprovision.network.buckets import NETWORK_RETENTION_SECONDS, RegionHour, merge, prune
from meshprovision.network.hourjson import (
    hour_from_json,
    hour_to_json,
    read_hex_id,
    read_number,
    read_relay_byte,
)
from meshprovision.network.resolve import Confidence, LearnedRelay, Resolution
from meshprovision.nodeid import relay_byte

if TYPE_CHECKING:
    from pathlib import Path

__all__ = [
    "DAY_MAX_BYTES",
    "LEARNED_RELAY_MAX_AGE_SECONDS",
    "NETWORK_DIRNAME",
    "REGION_MAX_BYTES",
    "STORE_MAX_TOTAL_BYTES",
    "STORE_VERSION",
    "RegionState",
    "RegionStore",
    "region_dirname",
]

_logger = logging.getLogger(__name__)

NETWORK_DIRNAME: Final[str] = "network"
"""The store's directory name, directly in the HTTP cache directory."""

STORE_VERSION: Final[int] = 1
"""On-disk schema version of every store file. A file with any other version reads as empty."""

DAY_MAX_BYTES: Final[int] = 8 * 1024 * 1024
"""The largest day file written or read (a busy region's day is about 0.85 MB)."""

REGION_MAX_BYTES: Final[int] = 64 * 1024 * 1024
"""The most bytes one region's day files take."""

STORE_MAX_TOTAL_BYTES: Final[int] = 256 * 1024 * 1024
"""The most bytes all regions' day files take."""

LEARNED_RELAY_MAX_AGE_SECONDS: Final[float] = 7 * 24 * 3600.0
"""How long a relay byte's learned node is used (a week)."""

_STATE_FILENAME: Final[str] = "state.json"
_RELAYS_FILENAME: Final[str] = "relays.json"
_RELAYS_MAX_BYTES: Final[int] = 256 * 1024
_STATE_MAX_BYTES: Final[int] = 64 * 1024
_DAY_FILE_RE: Final[re.Pattern[str]] = re.compile(r"^(\d{4}-\d{2}-\d{2})\.json\Z")
_REGION_DIR_RE: Final[re.Pattern[str]] = re.compile(r"^r-[0-9a-f]{16}\Z")
_WHAT: Final[str] = "network store"


@dataclass(frozen=True, slots=True)
class RegionState:
    """When a region was last fetched.

    Attributes:
        fetched_at: When lorastats was last asked about it, epoch seconds,
            or ``None`` when never (or the state is unreadable).
    """

    fetched_at: float | None = None


@dataclass(slots=True)
class _DayFile:
    """One day file found by a sweep."""

    start: float
    size: int
    path: Path


@dataclass(slots=True)
class _RegionFiles:
    """One region directory found by a sweep, its day files oldest first."""

    directory: Path
    refreshed: float
    days: list[_DayFile]


def region_dirname(region: str) -> str:
    """Return the directory name of a region's store.

    Args:
        region: The region.

    Returns:
        ``r-`` and the first 16 hex digits of the SHA-256 of its NFC name.
    """
    name = unicodedata.normalize("NFC", region).encode("utf-8")
    return f"r-{hashlib.sha256(name).hexdigest()[:16]}"


class RegionStore:
    """The per-region traffic files under one directory."""

    def __init__(self, directory: Path, *, clock: Callable[[], float] = time.time) -> None:
        """Initialize the store. Nothing is read or written until it is used.

        Args:
            directory: The store directory, normally ``cache_dir / NETWORK_DIRNAME``.
            clock: Callable returning the current unix epoch seconds.
        """
        self._directory = directory
        self._clock = clock

    def path_for(self, region: str) -> Path:
        """Return the directory of ``region``'s store.

        Args:
            region: The region.

        Returns:
            ``directory /`` :func:`region_dirname` ``(region)``.
        """
        return self._directory / region_dirname(region)

    def regions(self) -> tuple[str, ...]:
        """Name the regions with a store, from their state files.

        Returns:
            Every region whose directory holds a readable state file that
            names a region stored under that directory, sorted.
        """
        try:
            directories = [e for e in self._directory.iterdir() if _REGION_DIR_RE.match(e.name)]
        except OSError:
            return ()
        found = []
        for directory in directories:
            document = read_json(
                directory / _STATE_FILENAME, max_bytes=_STATE_MAX_BYTES, what=_WHAT
            )
            region = document.get("region") if isinstance(document, dict) else None
            if isinstance(region, str) and region_dirname(region) == directory.name:
                found.append(region)
        return tuple(sorted(found))

    def state(self, region: str) -> RegionState:
        """Read when ``region`` was last fetched.

        Args:
            region: The region.

        Returns:
            Its state; an empty one when there is no usable file.
        """
        path = self.path_for(region) / _STATE_FILENAME
        document = read_json(path, max_bytes=_STATE_MAX_BYTES, what=_WHAT)
        if not _is_document(document, region):
            return RegionState()
        return RegionState(fetched_at=read_number(document.get("fetched_at"), 0, math.inf))

    def load(self, region: str, *, start: float) -> tuple[RegionHour, ...]:
        """Read ``region``'s hours from the hour of ``start`` on.

        Args:
            region: The region.
            start: The earliest time wanted, epoch seconds.

        Returns:
            The stored hours within the retention, oldest first.
        """
        first = floor_hour(start)
        days = [day for day, _ in self._day_files(region) if _day_start(day) + DAY_SECONDS > first]
        hours = (bucket for day in days for bucket in self._read_day(region, day))
        return prune((b for b in hours if b.hour >= first), now=self._clock())

    def update(
        self,
        region: str,
        hours: Iterable[RegionHour],
        *,
        fetched_at: float,
    ) -> None:
        """Merge a refresh's hours into ``region``'s day files, record it, and sweep.

        Args:
            region: The region.
            hours: The refresh's hours (from
                :func:`~meshprovision.network.buckets.summarize`).
            fetched_at: When lorastats was asked, epoch seconds. The newer
                of it and the recorded fetch is recorded, unless the recorded
                one lies more than :data:`FUTURE_SKEW_SECONDS` ahead of the
                clock (written while the clock was set ahead): that one is
                replaced, so it cannot void the request budget.
        """
        now = self._clock()
        by_day: defaultdict[str, list[RegionHour]] = defaultdict(list)
        for bucket in prune(hours, now=now):
            by_day[_day_of(bucket.hour)].append(bucket)
        for day, new in sorted(by_day.items()):
            merged = prune(merge(self._read_day(region, day), new), now=now)
            self._write_day(region, day, merged)
        previous = self.state(region).fetched_at
        if previous is not None and previous <= now + FUTURE_SKEW_SECONDS:
            fetched_at = max(previous, fetched_at)
        state = {
            "version": STORE_VERSION,
            "region": region,
            "fetched_at": fetched_at,
        }
        write_json(self.path_for(region) / _STATE_FILENAME, state, what=_WHAT)
        self._sweep(now)

    def learned_relays(self, region: str) -> Mapping[int, LearnedRelay]:
        """Read the nodes ``region``'s relay bytes were last resolved ``high`` to.

        Args:
            region: The region.

        Returns:
            Byte -> its learned node, for the entries at most
            :data:`LEARNED_RELAY_MAX_AGE_SECONDS` old (none when there is
            no usable file).
        """
        path = self.path_for(region) / _RELAYS_FILENAME
        document = read_json(path, max_bytes=_RELAYS_MAX_BYTES, what=_WHAT)
        relays = document.get("relays") if _is_document(document, region) else None
        now = self._clock()
        learned = {}
        oldest, newest = now - LEARNED_RELAY_MAX_AGE_SECONDS, now + FUTURE_SKEW_SECONDS
        for key, value in (relays if isinstance(relays, dict) else {}).items():
            entry = _learned(key, value)
            if entry is not None and oldest <= entry[1].time <= newest:
                learned[entry[0]] = entry[1]
        return MappingProxyType(dict(sorted(learned.items())))

    def remember_relays(
        self, region: str, resolutions: Mapping[int, Resolution], *, seen_at: float
    ) -> None:
        """Record every relay byte resolved ``high``, keeping the other current entries.

        Each entry is stamped with when its evidence is from, never with the
        time of this call, so looking at old data again (``--no-fetch``, a
        long window) never renews an entry: a byte keeps its newer entry.

        Args:
            region: The region.
            resolutions: The window's resolutions (see
                :func:`~meshprovision.network.resolve.resolve_relays`).
            seen_at: When the window's data was fetched, epoch seconds.
        """
        current = self.learned_relays(region)
        learned = dict(current)
        for byte, resolution in resolutions.items():
            if resolution.confidence is not Confidence.HIGH or resolution.node is None:
                continue
            if byte not in current or current[byte].time < seen_at:
                learned[byte] = LearnedRelay(resolution.node, seen_at)
        if learned == current:
            return
        document = {
            "version": STORE_VERSION,
            "region": region,
            "relays": {str(b): [e.node, e.time] for b, e in sorted(learned.items())},
        }
        write_json(self.path_for(region) / _RELAYS_FILENAME, document, what=_WHAT)

    def _day_files(self, region: str) -> list[tuple[str, Path]]:
        """List ``region``'s day files, oldest first (``[]`` when there is no directory)."""
        try:
            entries = list(self.path_for(region).iterdir())
        except OSError:
            return []
        found = [(m.group(1), e) for e in entries if (m := _DAY_FILE_RE.match(e.name))]
        return sorted(found)

    def _read_day(self, region: str, day: str) -> tuple[RegionHour, ...]:
        """Read one day file's hours (none when it is missing or unusable)."""
        path = self.path_for(region) / f"{day}.json"
        document = read_json(path, max_bytes=DAY_MAX_BYTES, what=_WHAT)
        if not _is_document(document, region) or document.get("day") != day:
            if document is not None:
                _logger.debug("ignoring the %s file %s: unexpected shape", _WHAT, path)
            return ()
        raw = document.get("hours")
        parsed = (hour_from_json(item) for item in (raw if isinstance(raw, list) else []))
        start = _day_start(day)
        hours = {
            b.hour: b for b in parsed if b is not None and start <= b.hour < start + DAY_SECONDS
        }
        return tuple(hours[hour] for hour in sorted(hours))

    def _write_day(self, region: str, day: str, hours: tuple[RegionHour, ...]) -> None:
        """Write one day file, dropping its oldest hours until it fits :data:`DAY_MAX_BYTES`."""
        document = _day_document(region, day, hours)
        while len(json.dumps(document).encode("utf-8")) > DAY_MAX_BYTES and hours:
            hours = hours[1:]
            document = _day_document(region, day, hours)
        write_json(self.path_for(region) / f"{day}.json", document, what=_WHAT)

    def _sweep(self, now: float) -> None:
        """Delete expired day files, then the oldest beyond the bounds, then dead regions."""
        regions = self._region_files()
        cutoff = now - NETWORK_RETENTION_SECONDS
        for region in regions:
            _delete_days(region, [day for day in region.days if day.start + DAY_SECONDS <= cutoff])
            while region.days and sum(day.size for day in region.days) > REGION_MAX_BYTES:
                _delete_days(region, region.days[:1])
        total = sum(day.size for region in regions for day in region.days)
        for region in sorted(regions, key=lambda r: r.refreshed):
            while total > STORE_MAX_TOTAL_BYTES and region.days:
                total -= region.days[0].size
                _delete_days(region, region.days[:1])
        for region in regions:
            if not region.days and region.refreshed <= cutoff:
                _remove_region(region.directory)

    def _region_files(self) -> list[_RegionFiles]:
        """List every region directory with its day files (none when unreadable)."""
        try:
            directories = [e for e in self._directory.iterdir() if _REGION_DIR_RE.match(e.name)]
        except OSError as exc:
            _logger.debug("could not list the %s %s: %s", _WHAT, self._directory, exc)
            return []
        regions = []
        for directory in directories:
            with contextlib.suppress(OSError):
                days = sorted(
                    (
                        _DayFile(_day_start(m.group(1)), entry.stat().st_size, entry)
                        for entry in directory.iterdir()
                        if (m := _DAY_FILE_RE.match(entry.name)) and _valid_day(m.group(1))
                    ),
                    key=lambda day: day.start,
                )
                regions.append(_RegionFiles(directory, _mtime(directory / _STATE_FILENAME), days))
        return regions


def _learned(key: object, value: object) -> tuple[int, LearnedRelay] | None:
    """Read one ``relays.json`` entry: ``"<byte>": [<hex id>, <time>]``."""
    byte = read_relay_byte(key)
    if byte is None or not isinstance(value, list) or len(value) != 2:
        return None
    node, seen = read_hex_id(value[0]), read_number(value[1], 0, math.inf)
    if node is None or seen is None or relay_byte(node) != byte:
        return None
    return byte, LearnedRelay(node, seen)


def _delete_days(region: _RegionFiles, doomed: list[_DayFile]) -> None:
    """Delete some of a region's day files, and forget them."""
    for day in doomed:
        with contextlib.suppress(OSError):
            day.path.unlink()
        region.days.remove(day)


def _remove_region(directory: Path) -> None:
    """Remove a region directory that holds no day file any more."""
    with contextlib.suppress(OSError):
        for entry in directory.iterdir():
            entry.unlink()
        directory.rmdir()


def _mtime(path: Path) -> float:
    """Return a file's modification time, 0 when it cannot be read."""
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _day_of(hour: int) -> str:
    """Return the UTC day an hour falls in, as ``YYYY-MM-DD``."""
    return datetime.fromtimestamp(hour, tz=UTC).strftime("%Y-%m-%d")


def _valid_day(day: str) -> bool:
    """Tell whether ``YYYY-MM-DD`` is a real date."""
    try:
        datetime.strptime(day, "%Y-%m-%d")  # noqa: DTZ007 -- only validated, never used
    except ValueError:
        return False
    return True


def _day_start(day: str) -> float:
    """Return the start of a UTC day (``-inf`` for a string that is not a date)."""
    if not _valid_day(day):
        return -math.inf
    return datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=UTC).timestamp()


def _is_document(document: object, region: str) -> bool:
    """Tell whether a decoded file is a current-version store file of ``region``."""
    return (
        isinstance(document, dict)
        and document.get("version") == STORE_VERSION
        and document.get("region") == region
    )


def _day_document(region: str, day: str, hours: Iterable[RegionHour]) -> dict[str, object]:
    """Build a day file's document."""
    return {
        "version": STORE_VERSION,
        "region": region,
        "day": day,
        "hours": [hour_to_json(bucket) for bucket in hours],
    }
