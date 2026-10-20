"""``RegionMemo``: which lorastats region each node was last found in.

lorastats.pl answers ``Nodes/JSON?node=<hex>`` only in the region the node
lives in (any other region returns ``[]`` with HTTP 200), and which one
that is cannot be asked, so
:class:`~meshprovision.datasources.lorastats.LorastatsSource` asks the
regions in turn. This memo remembers where each node was found,
so a later run asks that region first: one request per node instead of up
to one per configured region.

It is a hint, never a source of truth: a region that no longer answers for
the node is forgotten and the other regions are asked again. The store is
kept as simple as that allows: one small JSON document
(:data:`REGION_MEMO_FILENAME`, in the HTTP cache directory), replaced
atomically and created owner-only, bounded to
:data:`REGION_MEMO_MAX_ENTRIES` entries (the oldest are dropped), each
entry expiring :data:`REGION_MEMO_MAX_AGE_SECONDS` after it was stored.
Anything unreadable -- a missing, corrupt or oversized file, an entry of an
unexpected shape -- reads as no memo, and a failed write only costs
requests on a later run; both are logged at DEBUG, never raised. Two
``mesh`` processes may write at once: each re-reads the file and applies
only its own change before replacing it, so at worst one of two
simultaneous changes is lost and learned again.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Final

from meshprovision.datasources.json_store import read_json, write_json
from meshprovision.errors import NodeIdError
from meshprovision.nodeid import NodeId

if TYPE_CHECKING:
    from pathlib import Path

__all__ = [
    "REGION_MEMO_FILENAME",
    "REGION_MEMO_MAX_AGE_SECONDS",
    "REGION_MEMO_MAX_ENTRIES",
    "REGION_MEMO_VERSION",
    "RegionMemo",
]

_logger = logging.getLogger(__name__)

REGION_MEMO_FILENAME: Final[str] = "lorastats_regions.json"
"""The memo's file name, directly in the HTTP cache directory."""

REGION_MEMO_VERSION: Final[int] = 1
"""On-disk schema version. A file with any other version reads as empty."""

REGION_MEMO_MAX_ENTRIES: Final[int] = 2048
"""Most entries kept; a write drops the oldest beyond this."""

REGION_MEMO_MAX_AGE_SECONDS: Final[float] = 30 * 24 * 60 * 60
"""How long an entry is used after it was stored (30 days).

An entry is not refreshed while its region keeps answering (that would
cost a write per node per run), so a node is looked up in every region
again about once a month; an entry for a node that left the fleet goes
away the same way."""

_MAX_FILE_BYTES: Final[int] = 1024 * 1024
"""A larger file is not read: a full memo is about 150 KB."""

_FUTURE_SKEW_SECONDS: Final[float] = 300.0
"""How far ahead of the clock a ``stored_at`` may be (a small clock step back)."""

_WHAT: Final[str] = "lorastats region memo"

_Entries = Mapping[str, tuple[str, float]]
"""Node hex id -> (region, stored_at epoch seconds)."""


class RegionMemo:
    """Which configured lorastats region each node was last found in, persisted as JSON."""

    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time) -> None:
        """Initialize the memo. Nothing is read or written until it is used.

        Args:
            path: The memo file, normally ``cache_dir / REGION_MEMO_FILENAME``.
            clock: Callable returning the current unix epoch seconds.
                Overridable for deterministic tests.
        """
        self._path = path
        self._clock = clock
        self._entries: _Entries | None = None

    @property
    def path(self) -> Path:
        """The memo file.

        Returns:
            The constructor's ``path``.
        """
        return self._path

    def region_for(self, node_id: NodeId) -> str | None:
        """Return the region ``node_id`` was last found in, if the memo is current.

        The file is read once, on first use; this instance's own changes
        are seen at once, another process's on its next run.

        Args:
            node_id: The node to look up.

        Returns:
            The remembered region, or ``None`` when there is no current
            entry for the node.
        """
        if self._entries is None:
            self._entries = self._read()
        entry = self._entries.get(node_id.hex)
        if entry is None or not self._is_current(entry[1]):
            return None
        return entry[0]

    def remember(self, node_id: NodeId, region: str) -> None:
        """Record that ``node_id`` was found in ``region``, now.

        Args:
            node_id: The node that was found.
            region: The region it was found in. The caller passes only an
                already validated region.
        """
        entries = _newest({**self._read(), node_id.hex: (region, self._clock())})
        self._entries = entries
        self._write(entries)

    def forget(self, node_id: NodeId) -> None:
        """Drop ``node_id``'s entry; the file is only rewritten when it had one.

        Args:
            node_id: The node whose remembered region no longer answers.
        """
        current = self._read()
        entries = {key: value for key, value in current.items() if key != node_id.hex}
        self._entries = entries
        if len(entries) != len(current):
            self._write(entries)

    def _is_current(self, stored_at: float) -> bool:
        """Return whether an entry stored at ``stored_at`` is still used.

        Args:
            stored_at: The entry's ``stored_at``, epoch seconds.

        Returns:
            ``True`` when it is at most :data:`REGION_MEMO_MAX_AGE_SECONDS`
            old and not more than a small skew in the future.
        """
        now = self._clock()
        return now - REGION_MEMO_MAX_AGE_SECONDS <= stored_at <= now + _FUTURE_SKEW_SECONDS

    def _read(self) -> dict[str, tuple[str, float]]:
        """Read every current, well-formed entry from the file.

        Returns:
            The entries, or an empty mapping when the file is missing,
            unreadable, oversized, not JSON or not a version
            :data:`REGION_MEMO_VERSION` memo (logged at DEBUG).
        """
        document = read_json(self._path, max_bytes=_MAX_FILE_BYTES, what=_WHAT)
        nodes = document.get("nodes") if isinstance(document, dict) else None
        if not isinstance(nodes, dict) or document.get("version") != REGION_MEMO_VERSION:
            if document is not None:
                _logger.debug("ignoring the %s %s: unexpected shape", _WHAT, self._path)
            return {}
        entries: dict[str, tuple[str, float]] = {}
        for key, value in nodes.items():
            entry = _parse_entry(key, value)
            if entry is not None and self._is_current(entry[1]):
                entries[key] = entry
        return entries

    def _write(self, entries: _Entries) -> None:
        """Replace the file with ``entries``, atomically; never raises (see ``write_json``).

        Args:
            entries: Every entry to keep.
        """
        document = {
            "version": REGION_MEMO_VERSION,
            "nodes": {
                key: {"region": region, "stored_at": stored_at}
                for key, (region, stored_at) in sorted(entries.items())
            },
        }
        write_json(self._path, document, what=_WHAT)


def _parse_entry(key: str, value: object) -> tuple[str, float] | None:
    """Validate one ``nodes`` entry of the file.

    Args:
        key: The entry's key: a canonical (lowercase, 8-digit) hex node id.
        value: ``{"region": <non-empty str>, "stored_at": <number>}``.

    Returns:
        ``(region, stored_at)``, or ``None`` for anything else. A
        non-finite ``stored_at`` passes here and is never current.
    """
    if not isinstance(value, dict):
        return None
    try:
        if NodeId.from_hex(key).hex != key:
            return None
    except NodeIdError:
        return None
    region = value.get("region")
    stored_at = value.get("stored_at")
    if not isinstance(region, str) or not region:
        return None
    if isinstance(stored_at, bool) or not isinstance(stored_at, int | float):
        return None
    return region, float(stored_at)


def _newest(entries: _Entries) -> dict[str, tuple[str, float]]:
    """Keep the :data:`REGION_MEMO_MAX_ENTRIES` most recently stored entries.

    Args:
        entries: The entries to bound.

    Returns:
        At most :data:`REGION_MEMO_MAX_ENTRIES` entries, the newest ones.
    """
    newest_first = sorted(entries.items(), key=lambda item: item[1][1], reverse=True)
    return dict(newest_first[:REGION_MEMO_MAX_ENTRIES])
