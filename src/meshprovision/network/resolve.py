"""Resolve relay bytes to nodes, with a confidence label. Pure.

A reception names the node that transmitted it last only by the last byte
of its id (``relay_node``), shared by about 1 in 256 nodes. The
candidates of a byte are the nodes heard in the window whose id ends in
it (:func:`relay_candidates`), and a relay's rebroadcast comes from the
same transmitter as its own packets, so at each gateway the relayed
receptions' SNR and RSSI match the candidate's own *direct* ones (a radio
fingerprint). For each candidate ``c`` of byte ``b``:

- *coverage* -- the share of ``b``'s relayed receptions heard at gateways
  that hear ``c`` directly (or are ``c``);
- *distance* -- over those gateways (but ``c`` itself) with at least
  :data:`RESOLVE_MIN_GATEWAY_RECEPTIONS` measured relayed receptions, the
  mean of ``|SNR difference| + |RSSI difference| / 2`` (dB), each gateway
  weighted by its measured relayed receptions, at most
  :data:`RESOLVE_MAX_GATEWAY_WEIGHT`; ``None`` without such a gateway.

The best candidate is the first by: coverage at least
:data:`RESOLVE_MIN_COVERAGE`, then the smallest distance, then the largest
coverage. Its label (:class:`Confidence`):

- ``high`` -- coverage at least :data:`RESOLVE_MIN_COVERAGE`, distance at
  most :data:`RESOLVE_MAX_DISTANCE_DB`, and every other candidate either
  covers less than a :data:`RESOLVE_COVERAGE_MARGIN`-th of it or is at
  least :data:`RESOLVE_DISTANCE_MARGIN_DB` farther;
- ``medium`` -- the only candidate, unless its distance contradicts it
  (above :data:`RESOLVE_MAX_DISTANCE_DB`); or coverage at least
  :data:`RESOLVE_MIN_COVERAGE` with every other candidate below a
  :data:`RESOLVE_COVERAGE_MARGIN`-th of it but no distance to compare; or
  a byte that would be ambiguous whose node was learned ``high`` before
  (:class:`LearnedRelay`, kept for a week) and is still a candidate;
- ``ambiguous`` -- otherwise: no node is named, the candidates are;
- ``unknown`` -- no candidate at all (a node that never uplinks, or no
  node heard in the window).

The thresholds were tuned on one region's day (they label 71 % of its
relayed receptions ``high``, 19 % ``medium``, 10 % ``ambiguous``) and err
towards ``ambiguous``; a wrong ``high`` would attribute traffic to the
wrong node. Explicit links (traceroutes, neighbour reports) are not used:
in that sample they did not separate the right candidate from a wrong one.

This module imports nothing that reads files or the network (no
``httpx``, ``pathlib``, :mod:`meshprovision.cache` or
:mod:`meshprovision.db`); ``tests/unit/test_import_contracts.py`` holds it
to that.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from meshprovision.nodeid import relay_byte

if TYPE_CHECKING:
    from meshprovision.datasources.models import NodeObservation
    from meshprovision.network.buckets import Radio, Traffic
    from meshprovision.network.keys import KeySeen

__all__ = [
    "RESOLVE_COVERAGE_MARGIN",
    "RESOLVE_DISTANCE_MARGIN_DB",
    "RESOLVE_MAX_DISTANCE_DB",
    "RESOLVE_MAX_GATEWAY_WEIGHT",
    "RESOLVE_MIN_COVERAGE",
    "RESOLVE_MIN_GATEWAY_RECEPTIONS",
    "CandidateScore",
    "Confidence",
    "LearnedRelay",
    "Resolution",
    "relay_candidates",
    "resolve_relays",
    "resolve_window",
]

RESOLVE_MIN_COVERAGE: Final[float] = 0.5
"""The least coverage of a ``high`` (or a coverage-only ``medium``) candidate."""

RESOLVE_MAX_DISTANCE_DB: Final[float] = 4.0
"""The largest radio distance of a ``high`` candidate, dB."""

RESOLVE_COVERAGE_MARGIN: Final[float] = 3.0
"""Another candidate covering at least best coverage / this keeps the best from ``high``..."""

RESOLVE_DISTANCE_MARGIN_DB: Final[float] = 4.0
"""... unless it is at least this much (dB) farther than the best."""

RESOLVE_MAX_GATEWAY_WEIGHT: Final[int] = 50
"""The most weight one gateway has in the distance (in measured relayed receptions)."""

RESOLVE_MIN_GATEWAY_RECEPTIONS: Final[int] = 2
"""The fewest measured relayed receptions at a gateway for it to count in the distance."""

_MUTE_ROLE: Final[str] = "CLIENT_MUTE"


class Confidence(StrEnum):
    """How sure a relay byte's resolution is (see the module docs)."""

    HIGH = "high"
    MEDIUM = "medium"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CandidateScore:
    """How well one candidate matches a relay byte.

    Attributes:
        node: The candidate's hex id.
        coverage: Its coverage, ``0..1``.
        distance: Its radio distance in dB, or ``None`` when there is none
            to compare.
    """

    node: str
    coverage: float
    distance: float | None


@dataclass(frozen=True, slots=True)
class LearnedRelay:
    """The node a relay byte was resolved ``high`` to by an earlier run.

    Attributes:
        node: The node's hex id.
        time: When, epoch seconds.
    """

    node: str
    time: float


@dataclass(frozen=True, slots=True)
class Resolution:
    """What a relay byte resolves to.

    Attributes:
        byte: The relay byte.
        confidence: The label.
        node: The node's hex id for ``high`` and ``medium``, else ``None``.
        candidates: Every candidate, best first.
        learned_at: For a ``medium`` taken from an earlier ``high``, when
            that was; else ``None``.
    """

    byte: int
    confidence: Confidence
    node: str | None
    candidates: tuple[CandidateScore, ...] = ()
    learned_at: float | None = None


def relay_candidates(
    traffic: Traffic,
    nodes: Iterable[NodeObservation] = (),
    *,
    start: float,
    mute: Collection[str] = (),
) -> Mapping[int, tuple[str, ...]]:
    """List the nodes heard in the window by the last byte of their id.

    Args:
        traffic: The window's traffic: its origins and gateways were heard.
        nodes: The region's node list: a node last seen at or after
            ``start`` was heard too, and a ``CLIENT_MUTE`` node (which
            never rebroadcasts) is never a candidate.
        start: The start of the window, epoch seconds.
        mute: More ``CLIENT_MUTE`` nodes, by hex id (the role their own
            node info advertised).

    Returns:
        Byte -> candidates' hex ids, sorted.
    """
    listed = list(nodes)
    heard = {
        *traffic.packets,
        *(gateway for cells in traffic.relayed.values() for gateway in cells),
        *(gateway for cells in traffic.direct.values() for gateway in cells),
        *(gateway for cells in traffic.only_gateway.values() for gateway in cells),
        *(
            node.node_id.hex
            for node in listed
            if node.last_seen is not None and node.last_seen.timestamp() >= start
        ),
    }
    silent = {*mute, *(node.node_id.hex for node in listed if node.role == _MUTE_ROLE)}
    by_byte: defaultdict[int, list[str]] = defaultdict(list)
    for node in sorted(heard - silent):
        by_byte[relay_byte(node)].append(node)
    return MappingProxyType({byte: tuple(by_byte[byte]) for byte in sorted(by_byte)})


def resolve_window(
    traffic: Traffic,
    seen: Iterable[KeySeen],
    *,
    start: float,
    learned: Mapping[int, LearnedRelay],
    nodes: Iterable[NodeObservation] = (),
) -> Mapping[int, Resolution]:
    """Resolve a window's relay bytes, never to a node that advertised ``CLIENT_MUTE``.

    Args:
        traffic: The window's traffic.
        seen: The key sightings whose advertised roles count (see
            :class:`~meshprovision.network.keys.KeySeen`).
        start: The start of the window, epoch seconds.
        learned: Byte -> the node an earlier run resolved it ``high`` to.
        nodes: The region's node list, when it could be had.

    Returns:
        Byte -> its resolution (see :func:`resolve_relays`).
    """
    mute = {entry.node for entry in seen if entry.role == _MUTE_ROLE}
    candidates = relay_candidates(traffic, nodes, start=start, mute=mute)
    return resolve_relays(traffic, candidates, learned=learned)


def resolve_relays(
    traffic: Traffic,
    candidates: Mapping[int, Collection[str]],
    *,
    learned: Mapping[int, LearnedRelay] | None = None,
) -> Mapping[int, Resolution]:
    """Resolve every relay byte of the window.

    Args:
        traffic: The window's traffic.
        candidates: Byte -> candidates (see :func:`relay_candidates`).
        learned: Byte -> the node an earlier run resolved it ``high`` to.

    Returns:
        Byte -> its resolution, for every byte with relayed receptions.
    """
    return MappingProxyType(
        {
            byte: _resolve(byte, traffic, candidates.get(byte, ()), (learned or {}).get(byte))
            for byte in sorted(traffic.relayed)
        }
    )


def _resolve(
    byte: int, traffic: Traffic, candidates: Collection[str], learned: LearnedRelay | None
) -> Resolution:
    """Score and label one relay byte."""
    if not candidates:
        return Resolution(byte, Confidence.UNKNOWN, None)
    relayed = traffic.relayed[byte]
    scores = tuple(
        sorted(
            (_score(node, relayed, traffic.direct.get(node, {})) for node in candidates),
            key=_rank,
        )
    )
    confidence = _label(scores)
    if confidence is not Confidence.AMBIGUOUS:
        return Resolution(byte, confidence, scores[0].node, scores)
    if learned is not None and learned.node in candidates:
        return Resolution(byte, Confidence.MEDIUM, learned.node, scores, learned.time)
    return Resolution(byte, Confidence.AMBIGUOUS, None, scores)


def _rank(score: CandidateScore) -> tuple[bool, float, float, str]:
    """Sort key: enough coverage first, then the smallest distance, the largest coverage."""
    distance = math.inf if score.distance is None else score.distance
    return (score.coverage < RESOLVE_MIN_COVERAGE, distance, -score.coverage, score.node)


def _label(scores: tuple[CandidateScore, ...]) -> Confidence:
    """Label the best of the ranked candidates (``ambiguous`` before any learned prior)."""
    best, others = scores[0], scores[1:]
    covered = best.coverage >= RESOLVE_MIN_COVERAGE
    alone = all(other.coverage < best.coverage / RESOLVE_COVERAGE_MARGIN for other in others)
    close = best.distance is not None and best.distance <= RESOLVE_MAX_DISTANCE_DB
    if covered and close and all(_outclassed(other, best) for other in others):
        return Confidence.HIGH
    if not others and (best.distance is None or close):
        return Confidence.MEDIUM
    if covered and alone and best.distance is None:
        return Confidence.MEDIUM
    return Confidence.AMBIGUOUS


def _outclassed(other: CandidateScore, best: CandidateScore) -> bool:
    """Tell whether ``other`` covers too little, or is too far, to compete with ``best``."""
    if other.coverage < best.coverage / RESOLVE_COVERAGE_MARGIN:
        return True
    if other.distance is None or best.distance is None:
        return False
    return other.distance >= best.distance + RESOLVE_DISTANCE_MARGIN_DB


def _score(node: str, relayed: Mapping[str, Radio], direct: Mapping[str, Radio]) -> CandidateScore:
    """Score one candidate against a byte's relayed receptions per gateway."""
    total = sum(radio.receptions for radio in relayed.values())
    common = [gateway for gateway in relayed if gateway in direct or gateway == node]
    covered = sum(relayed[gateway].receptions for gateway in common)
    weighted = weights = 0.0
    for gateway in common:
        heard, own = relayed[gateway], direct.get(gateway)
        if gateway == node or own is None or heard.measured < RESOLVE_MIN_GATEWAY_RECEPTIONS:
            continue
        gap = _gap(heard, own)
        if gap is not None:
            weight = min(heard.measured, RESOLVE_MAX_GATEWAY_WEIGHT)
            weighted += weight * gap
            weights += weight
    return CandidateScore(
        node=node,
        coverage=covered / total if total else 0.0,
        distance=weighted / weights if weights else None,
    )


def _gap(heard: Radio, own: Radio) -> float | None:
    """Return ``|SNR difference| + |RSSI difference| / 2`` of two means, ``None`` without both."""
    heard_snr, own_snr = heard.mean_snr, own.mean_snr
    heard_rssi, own_rssi = heard.mean_rssi, own.mean_rssi
    if heard_snr is None or own_snr is None or heard_rssi is None or own_rssi is None:
        return None
    return abs(heard_snr - own_snr) + abs(heard_rssi - own_rssi) / 2
