"""The network-wide key scan: who advertises which public key, and what is wrong with it. Pure.

Node-info packets that travel unencrypted (the default channel) carry the
sender's public key. Each refresh turns the keys it saw into
:class:`KeySeen` records (:func:`observe`): a 64-bit digest of the key,
never the key itself, with the hours it was heard, the node's short name,
hardware and role, whether the node's id is derived from the key
(firmware 2.8 sets ``node id == crc32(public key)``) and the weak-key
audit's verdict, all worked out while the key was in memory. Those
records are kept for 30 days (:mod:`meshprovision.network.keystore`) and
:func:`scan_keys` judges them:

- *our key on another id* (critical) -- a node of ours' database public
  key advertised by another id; unless that id is the key's derived id
  and our node was last heard before it first was: then our node moved
  to its key-derived id (a migration, info, so the database can follow);
- *our id, other key* -- a node of ours advertising a key that is not
  its database key: critical when the database key is derived from the
  id (a firmware 2.8 node cannot change its key and keep its id), else a
  warning (database out of date, a re-flash, or a spoof); a key last heard
  before the node was first heard with its database key is its old key
  (a re-key), not reported;
- *weak key* -- the weak-key audit's own findings and severity;
- *shared key* among two or more ids: a **clone** (critical) when two of
  them were heard at the same time (in a common hour, with overlapping
  first-to-last sightings), or the sightings switch between them more
  often than a hand-over can (A, B, A); a **migration** (info) when
  exactly one of them has the key-derived id and every other was last
  heard before it first was; else a **hand-over** (warning: a backup
  restored onto new hardware, a node re-flashed with its old key);
- *key changed* under one id (warning; critical when the old key was
  derived from the id and the new one is not). Not reported for a node
  of ours with a database key: the *our id, other key* check covers it.

Only a critical finding that involves one of our nodes is a failure
(:attr:`KeyScan.fleet_critical`); other people's devices are reported in
full but cannot be fixed by us.

This module imports nothing that reads files or the network (no
``httpx``, ``pathlib``, :mod:`meshprovision.cache` or
:mod:`meshprovision.db`); ``tests/unit/test_import_contracts.py`` holds it
to that.
"""

from __future__ import annotations

import zlib
from collections import defaultdict
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from itertools import combinations, pairwise
from typing import Final

from meshprovision.crypto.redact import REDACTION_DIGEST_CHARS, fingerprint
from meshprovision.crypto.weakkeys import audit_public_key
from meshprovision.health.history import floor_hour
from meshprovision.network.rawpackets import AdvertisedKey

__all__ = [
    "KEY_DIGEST_CHARS",
    "MAX_KEY_HOURS",
    "FindingKind",
    "FleetKey",
    "KeyAudit",
    "KeyFinding",
    "KeyScan",
    "KeySeen",
    "Severity",
    "fleet_key",
    "merge_seen",
    "observe",
    "scan_keys",
    "short_digest",
]

KEY_DIGEST_CHARS: Final[int] = 16
"""Hex digits of a stored key digest (64 bits of its SHA-256)."""

MAX_KEY_HOURS: Final[int] = 168
"""The most hours a key's sighting keeps (the newest)."""

_PREFIX_CHARS: Final[int] = len("sha256:")


class Severity(StrEnum):
    """How serious a key finding is."""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class FindingKind(StrEnum):
    """What a key finding is about (see the module docs)."""

    OUR_KEY_ELSEWHERE = "our-key-elsewhere"
    OUR_ID_OTHER_KEY = "our-id-other-key"
    WEAK_KEY = "weak-key"
    CLONE = "clone"
    HANDOVER = "handover"
    MIGRATION = "migration"
    KEY_CHANGED = "key-changed"


_SEVERITY_ORDER: Final[dict[Severity, int]] = {
    Severity.CRITICAL: 0,
    Severity.WARNING: 1,
    Severity.INFO: 2,
}


@dataclass(frozen=True, slots=True)
class KeyAudit:
    """The weak-key audit's verdict on a key, from when it was seen.

    Attributes:
        severity: ``critical`` or ``warning``.
        checks: The checks that flagged it.
    """

    severity: Severity
    checks: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class KeySeen:
    """A key one node advertised, over the hours it was heard with it.

    Attributes:
        node: The node's hex id.
        digest: ``sha256:`` and the first 16 hex digits of the key's SHA-256.
        first: When it was first heard with the key, epoch seconds.
        last: When it was last heard with it, epoch seconds.
        hours: The UTC hours it was heard with it, oldest first (the
            newest :data:`MAX_KEY_HOURS`).
        short_name: Its short name, terminal-safe, when given.
        hw_model: Its hardware model name, when known.
        role: Its role name, when known.
        derived: Whether its id is the CRC-32 of the key.
        audit: The weak-key audit's verdict, ``None`` when it found nothing.
    """

    node: str
    digest: str
    first: float
    last: float
    hours: tuple[int, ...]
    short_name: str | None = None
    hw_model: str | None = None
    role: str | None = None
    derived: bool = False
    audit: KeyAudit | None = None


@dataclass(frozen=True, slots=True)
class FleetKey:
    """One of our nodes, with its database public key's digest.

    Attributes:
        node: The node's hex id.
        digest: Its database public key's digest, or ``None`` when the
            database has none.
        derived: Whether its id is the CRC-32 of that key.
    """

    node: str
    digest: str | None = None
    derived: bool = False


@dataclass(frozen=True, slots=True)
class KeyFinding:
    """One thing wrong with the keys advertised.

    Attributes:
        kind: What it is about.
        severity: How serious it is.
        digest: The key's digest.
        nodes: The node ids involved, in the order the text names them
            (for a migration or hand-over the oldest first).
        fleet: Whether one of our nodes is among them.
        checks: For a weak key, the audit's checks.
        last_heard: For a hand-over, when the old id(s) were last heard.
    """

    kind: FindingKind
    severity: Severity
    digest: str
    nodes: tuple[str, ...]
    fleet: bool
    checks: tuple[str, ...] = ()
    last_heard: float | None = None


@dataclass(frozen=True, slots=True)
class KeyScan:
    """The key scan of one region's window.

    Attributes:
        seen: Every key sighting in the window, by node then first sighting.
        findings: Every finding, the most serious first.
        fleet_seen: Our nodes that advertised a key in the window.
        derived: Nodes whose id is derived from their key.
    """

    seen: tuple[KeySeen, ...]
    findings: tuple[KeyFinding, ...]
    fleet_seen: tuple[str, ...]
    derived: tuple[str, ...]

    @property
    def nodes(self) -> int:
        """How many nodes advertised a key in the window."""
        return len({entry.node for entry in self.seen})

    @property
    def fleet_critical(self) -> bool:
        """Whether a critical finding involves one of our nodes (exit code 6)."""
        return any(f.severity is Severity.CRITICAL and f.fleet for f in self.findings)


def short_digest(digest: str) -> str:
    """Return the usual 8-digit form of a stored key digest.

    Args:
        digest: A digest such as ``sha256:ecbba2d8a1b2c3d4``.

    Returns:
        ``sha256:ecbba2d8``, the same as the key's ``fingerprint``.
    """
    return digest[: _PREFIX_CHARS + REDACTION_DIGEST_CHARS]


def _derived(node: str, public_key: bytes) -> bool:
    """Tell whether a node's id is the CRC-32 of its public key (firmware 2.8)."""
    return zlib.crc32(public_key) == int(node, 16)


def fleet_key(node: str, public_key: bytes | None) -> FleetKey:
    """Describe one of our nodes' database public key without keeping it.

    Args:
        node: The node's hex id.
        public_key: Its database public key, or ``None``.

    Returns:
        Its digest and whether the id derives from it.
    """
    if public_key is None:
        return FleetKey(node)
    digest = fingerprint(public_key, chars=KEY_DIGEST_CHARS)
    return FleetKey(node, digest, _derived(node, public_key))


def observe(keys: Iterable[AdvertisedKey], known_bad: Collection[bytes]) -> tuple[KeySeen, ...]:
    """Turn one refresh's advertised keys into sightings, auditing each key once.

    Args:
        keys: The keys the refresh saw.
        known_bad: The known-bad key blocklist.

    Returns:
        One sighting per node and key, by node then digest. The raw keys
        are not kept.
    """
    grouped: defaultdict[tuple[str, bytes], list[AdvertisedKey]] = defaultdict(list)
    for key in keys:
        grouped[(key.node.hex, key.public_key)].append(key)
    seen = []
    for (node, public_key), adverts in grouped.items():
        latest = max(adverts, key=lambda advert: advert.time)
        result = audit_public_key(public_key, node_id=f"!{node}", known_bad=known_bad)
        severity = result.severity
        seen.append(
            KeySeen(
                node=node,
                digest=fingerprint(public_key, chars=KEY_DIGEST_CHARS),
                first=min(advert.time for advert in adverts),
                last=latest.time,
                hours=tuple(sorted({floor_hour(advert.time) for advert in adverts})),
                short_name=latest.short_name,
                hw_model=latest.hw_model,
                role=latest.role,
                derived=_derived(node, public_key),
                audit=None
                if severity is None
                else KeyAudit(
                    Severity(severity.value), tuple(f.check.value for f in result.findings)
                ),
            )
        )
    return tuple(sorted(seen, key=lambda entry: (entry.node, entry.digest)))


def merge_seen(old: KeySeen, new: KeySeen) -> KeySeen:
    """Merge two sightings of one node's key.

    Args:
        old: The stored sighting.
        new: A newer refresh's sighting of the same node and key.

    Returns:
        The combined sighting: the earliest first, the latest last, every
        hour (the newest :data:`MAX_KEY_HOURS`), the names and audit of
        whichever was heard last.
    """
    latest = new if new.last >= old.last else old
    return KeySeen(
        node=old.node,
        digest=old.digest,
        first=min(old.first, new.first),
        last=max(old.last, new.last),
        hours=tuple(sorted({*old.hours, *new.hours}))[-MAX_KEY_HOURS:],
        short_name=latest.short_name,
        hw_model=latest.hw_model,
        role=latest.role,
        derived=old.derived,
        audit=latest.audit,
    )


def scan_keys(seen: Iterable[KeySeen], fleet: Iterable[FleetKey], *, start: float) -> KeyScan:
    """Judge the keys advertised in a window.

    Args:
        seen: The stored sightings.
        fleet: Our nodes, with their database keys.
        start: The window's start, epoch seconds: older sightings and
            hours are left out.

    Returns:
        The scan.
    """
    window = tuple(
        sorted(
            (_within(entry, start) for entry in seen if entry.last >= start),
            key=lambda entry: (entry.node, entry.first, entry.digest),
        )
    )
    ours = {key.node: key for key in fleet}
    findings = [
        *_our_keys(window, ours),
        *_weak_keys(window, ours),
        *_shared_keys(window, ours),
        *_changed_keys(window, ours),
    ]
    findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.kind.value, f.nodes, f.digest))
    return KeyScan(
        seen=window,
        findings=tuple(findings),
        fleet_seen=tuple(sorted({entry.node for entry in window if entry.node in ours})),
        derived=tuple(sorted({entry.node for entry in window if entry.derived})),
    )


def _within(entry: KeySeen, start: float) -> KeySeen:
    """Keep only a sighting's hours from the window's start hour on."""
    first_hour = floor_hour(start)
    hours = tuple(hour for hour in entry.hours if hour >= first_hour)
    return KeySeen(
        node=entry.node,
        digest=entry.digest,
        first=max(entry.first, start),
        last=entry.last,
        hours=hours,
        short_name=entry.short_name,
        hw_model=entry.hw_model,
        role=entry.role,
        derived=entry.derived,
        audit=entry.audit,
    )


def _our_keys(window: tuple[KeySeen, ...], ours: Mapping[str, FleetKey]) -> list[KeyFinding]:
    """Find our keys on other ids and our ids with other keys."""
    findings = []
    for mine in ours.values():
        if mine.digest is None:
            continue
        own = [entry for entry in window if entry.node == mine.node]
        for entry in window:
            if entry.digest == mine.digest and entry.node != mine.node:
                kind, severity = (
                    (FindingKind.MIGRATION, Severity.INFO)
                    if _migrated_to(entry, own)
                    else (FindingKind.OUR_KEY_ELSEWHERE, Severity.CRITICAL)
                )
                findings.append(
                    KeyFinding(kind, severity, entry.digest, (mine.node, entry.node), fleet=True)
                )
        rekeyed = min((e.first for e in own if e.digest == mine.digest), default=None)
        for entry in own:
            if entry.digest != mine.digest and (rekeyed is None or entry.last >= rekeyed):
                severity = Severity.CRITICAL if mine.derived else Severity.WARNING
                findings.append(
                    KeyFinding(
                        FindingKind.OUR_ID_OTHER_KEY, severity, entry.digest, (mine.node,), True
                    )
                )
    return findings


def _migrated_to(entry: KeySeen, own: Collection[KeySeen]) -> bool:
    """Tell whether ``entry`` is our node's key-derived new id, heard only after the old one."""
    return entry.derived and all(old.last < entry.first for old in own)


def _weak_keys(window: tuple[KeySeen, ...], ours: Mapping[str, FleetKey]) -> list[KeyFinding]:
    """Report every key the weak-key audit flagged."""
    return [
        KeyFinding(
            FindingKind.WEAK_KEY,
            entry.audit.severity,
            entry.digest,
            (entry.node,),
            entry.node in ours,
            checks=entry.audit.checks,
        )
        for entry in window
        if entry.audit is not None
    ]


def _shared_keys(window: tuple[KeySeen, ...], ours: Mapping[str, FleetKey]) -> list[KeyFinding]:
    """Classify every key advertised by two or more ids (not one of our database keys)."""
    ours_digests = {key.digest for key in ours.values() if key.digest is not None}
    groups: defaultdict[str, list[KeySeen]] = defaultdict(list)
    for entry in window:
        groups[entry.digest].append(entry)
    findings = []
    for digest, members in sorted(groups.items()):
        nodes = {entry.node for entry in members}
        if len(nodes) < 2 or digest in ours_digests:
            continue
        findings.append(_classify(digest, members, fleet=bool(nodes & ours.keys())))
    return findings


def _classify(digest: str, members: list[KeySeen], *, fleet: bool) -> KeyFinding:
    """Tell a clone from a migration from a hand-over (see the module docs)."""
    by_first = sorted(members, key=lambda entry: (entry.first, entry.node))
    nodes = tuple(dict.fromkeys(entry.node for entry in by_first))
    if _concurrent(members):
        return KeyFinding(FindingKind.CLONE, Severity.CRITICAL, digest, nodes, fleet)
    newest = by_first[-1]
    earlier = [entry for entry in members if entry.node != newest.node]
    derived = [entry for entry in members if entry.derived]
    if len(derived) == 1 and derived[0] is newest and all(e.last < newest.first for e in earlier):
        return KeyFinding(FindingKind.MIGRATION, Severity.INFO, digest, nodes, fleet)
    return KeyFinding(
        FindingKind.HANDOVER,
        Severity.WARNING,
        digest,
        nodes,
        fleet,
        last_heard=max(entry.last for entry in earlier),
    )


def _concurrent(members: list[KeySeen]) -> bool:
    """Tell whether two ids were heard with a key at the same time, or alternated.

    At the same time: in a common hour, with overlapping first-to-last
    sightings (one id last heard at 10:05 and the other first at 10:40 share
    the hour but not the time: a hand-over). Alternated: the hourly
    sightings, in time order, switch ids more often than a chain of
    hand-overs can.
    """
    for a, b in combinations(members, 2):
        overlap = a.first <= b.last and b.first <= a.last
        if a.node != b.node and overlap and set(a.hours) & set(b.hours):
            return True
    events = sorted((hour, entry.first, entry.node) for entry in members for hour in entry.hours)
    sequence = [node for _, _, node in events]
    switches = sum(1 for a, b in pairwise(sequence) if a != b)
    return switches > len({entry.node for entry in members}) - 1


def _changed_keys(window: tuple[KeySeen, ...], ours: Mapping[str, FleetKey]) -> list[KeyFinding]:
    """Report each id heard with more than one key (not ours with a database key)."""
    by_node: defaultdict[str, list[KeySeen]] = defaultdict(list)
    for entry in window:
        by_node[entry.node].append(entry)
    findings = []
    for node, entries in sorted(by_node.items()):
        mine = ours.get(node)
        if len(entries) < 2 or (mine is not None and mine.digest is not None):
            continue
        newest = max(entries, key=lambda entry: entry.last)
        lost = any(entry.derived for entry in entries if entry is not newest)
        severity = Severity.CRITICAL if lost and not newest.derived else Severity.WARNING
        findings.append(
            KeyFinding(FindingKind.KEY_CHANGED, severity, newest.digest, (node,), mine is not None)
        )
    return findings
