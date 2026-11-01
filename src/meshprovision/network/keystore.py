"""``KeyStore``: the keys each region's nodes advertised, as ``keys.json`` in its store directory.

One file per region, next to its traffic (see
:mod:`meshprovision.network.store`): ``{"version", "region", "keys":
[[node, digest, first, last, [hours], short, hw, role, derived, audit],
...]}``, ``audit`` being ``null`` or ``[severity, [checks]]``. Key
digests only (64 bits of the key's SHA-256), never a key: equality and
the audit's verdict are all a later scan needs, and public keys are
handled like every other key material (``public_key`` is a sensitive
name in :mod:`meshprovision.crypto.redact`).

Written and read like the traffic files: owner-only, atomic, tolerant (an
unusable file reads as empty, an entry of an unexpected shape is
dropped). An update re-reads the file and merges its own sightings
(:func:`~meshprovision.network.keys.merge_seen`), so it is idempotent
and two processes both leave their sightings. Sightings last heard more
than :data:`~meshprovision.network.buckets.NETWORK_RETENTION_DAYS` days
ago are dropped, and the file is kept under :data:`KEYS_MAX_BYTES` by
dropping the sightings heard longest ago.
"""

from __future__ import annotations

import json
import math
import re
import time
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any, Final

from meshprovision.datasources.json_store import read_json, write_json
from meshprovision.health.history import HOUR_SECONDS
from meshprovision.network.buckets import NETWORK_RETENTION_SECONDS
from meshprovision.network.hourjson import read_count, read_hex_id, read_number
from meshprovision.network.keys import (
    KEY_DIGEST_CHARS,
    MAX_KEY_HOURS,
    KeyAudit,
    KeySeen,
    Severity,
    merge_seen,
)
from meshprovision.network.store import STORE_VERSION, region_dirname
from meshprovision.termsafe import terminal_safe

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["KEYS_FILENAME", "KEYS_MAX_BYTES", "KeyStore"]

KEYS_FILENAME: Final[str] = "keys.json"
"""The key sightings' file name, in a region's store directory."""

KEYS_MAX_BYTES: Final[int] = 2 * 1024 * 1024
"""The largest key file written or read."""

_DIGEST_RE: Final[re.Pattern[str]] = re.compile(rf"^sha256:[0-9a-f]{{{KEY_DIGEST_CHARS}}}\Z")
_MAX_TEXT: Final[int] = 64
_ENTRY_FIELDS: Final[int] = 10
_AUDIT_SEVERITIES: Final[frozenset[str]] = frozenset({Severity.CRITICAL, Severity.WARNING})
_WHAT: Final[str] = "network key store"


class KeyStore:
    """The per-region key files under the network store directory."""

    def __init__(self, directory: Path, *, clock: Callable[[], float] = time.time) -> None:
        """Initialize the store. Nothing is read or written until it is used.

        Args:
            directory: The network store directory (the one
                :class:`~meshprovision.network.store.RegionStore` uses).
            clock: Callable returning the current unix epoch seconds.
        """
        self._directory = directory
        self._clock = clock

    def load(self, region: str) -> tuple[KeySeen, ...]:
        """Read ``region``'s key sightings.

        Args:
            region: The region.

        Returns:
            The sightings within the retention, by node and digest (none
            when there is no usable file).
        """
        path = self._directory / region_dirname(region) / KEYS_FILENAME
        document = read_json(path, max_bytes=KEYS_MAX_BYTES, what=_WHAT)
        if not isinstance(document, dict) or document.get("version") != STORE_VERSION:
            return ()
        raw = document.get("keys")
        if document.get("region") != region or not isinstance(raw, list):
            return ()
        oldest = self._clock() - NETWORK_RETENTION_SECONDS
        entries = {}
        for item in raw:
            entry = _entry(item)
            if entry is not None and entry.last >= oldest:
                entries[(entry.node, entry.digest)] = entry
        return tuple(entries[key] for key in sorted(entries))

    def update(self, region: str, seen: Iterable[KeySeen]) -> None:
        """Merge a refresh's key sightings into ``region``'s file.

        Args:
            region: The region.
            seen: The refresh's sightings (see
                :func:`~meshprovision.network.keys.observe`).
        """
        new = tuple(seen)
        if not new:
            return
        entries = {(entry.node, entry.digest): entry for entry in self.load(region)}
        for entry in new:
            stored = entries.get((entry.node, entry.digest))
            entries[(entry.node, entry.digest)] = (
                entry if stored is None else merge_seen(stored, entry)
            )
        kept = sorted(entries.values(), key=lambda entry: entry.last, reverse=True)
        document = _document(region, kept)
        while kept and len(json.dumps(document).encode("utf-8")) > KEYS_MAX_BYTES:
            kept = kept[: len(kept) * 9 // 10]
            document = _document(region, kept)
        write_json(self._directory / region_dirname(region) / KEYS_FILENAME, document, what=_WHAT)


def _document(region: str, entries: Iterable[KeySeen]) -> dict[str, object]:
    """Build the file's document, by node and digest."""
    rows = [
        [
            e.node,
            e.digest,
            e.first,
            e.last,
            list(e.hours),
            e.short_name,
            e.hw_model,
            e.role,
            e.derived,
            None if e.audit is None else [e.audit.severity.value, list(e.audit.checks)],
        ]
        for e in sorted(entries, key=lambda entry: (entry.node, entry.digest))
    ]
    return {"version": STORE_VERSION, "region": region, "keys": rows}


def _entry(item: object) -> KeySeen | None:
    """Read one stored sighting; ``None`` when any field is malformed."""
    if not isinstance(item, list) or len(item) != _ENTRY_FIELDS:
        return None
    node, digest = read_hex_id(item[0]), item[1]
    first, last = read_number(item[2], 0, math.inf), read_number(item[3], 0, math.inf)
    hours = _hours(item[4])
    texts = [_text(value) for value in item[5:8]]
    audit = _audit(item[9])
    if node is None or not isinstance(digest, str) or not _DIGEST_RE.match(digest):
        return None
    if first is None or last is None or first > last or hours is None:
        return None
    if not isinstance(item[8], bool) or any(text is False for text in texts) or audit is False:
        return None
    return KeySeen(
        node=node,
        digest=digest,
        first=first,
        last=last,
        hours=hours,
        short_name=_optional(texts[0]),
        hw_model=_optional(texts[1]),
        role=_optional(texts[2]),
        derived=item[8],
        audit=audit if isinstance(audit, KeyAudit) else None,
    )


def _hours(value: object) -> tuple[int, ...] | None:
    """Read a list of at most :data:`MAX_KEY_HOURS` whole hours."""
    if not isinstance(value, list) or len(value) > MAX_KEY_HOURS:
        return None
    hours = [read_count(hour, 2**40) for hour in value]
    if any(hour is None or hour % HOUR_SECONDS for hour in hours):
        return None
    return tuple(sorted({hour for hour in hours if hour is not None}))


def _text(value: object) -> str | bool | None:
    """Read an optional short text, made terminal-safe and cut to 64 characters.

    A long or escape-laden name is cut, never a reason to drop its
    sighting (a node must not hide from the scan behind its name).

    Returns:
        The text, ``None`` for ``null``, or ``False`` when it is not a
        non-blank string.
    """
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        return False
    return terminal_safe(value)[:_MAX_TEXT]


def _optional(value: str | bool | None) -> str | None:
    """Narrow a checked :func:`_text` result."""
    return value if isinstance(value, str) else None


def _audit(value: object) -> Any:
    """Read ``null`` or ``[severity, [checks]]``; ``False`` when malformed."""
    if value is None:
        return None
    if not isinstance(value, list) or len(value) != 2 or value[0] not in _AUDIT_SEVERITIES:
        return False
    checks = value[1]
    if not isinstance(checks, list) or not all(_text(check) for check in checks):
        return False
    return KeyAudit(Severity(value[0]), tuple(terminal_safe(check) for check in checks))
