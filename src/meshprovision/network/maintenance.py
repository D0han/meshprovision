"""The maintenance warning of ``mesh provision``: does anything depend on the node about to restart?

Applying a plan writes the device's configuration and reboots it (a key
regeneration also changes a firmware 2.8 node's id). When other nodes
rely on it, the operator should know before confirming.
:func:`maintenance_note` answers from the ``mesh network`` store alone:

- **offline** -- it reads only what ``mesh network`` stored in the cache
  directory: no request, no contact needed;
- **recent data only** -- per region, the 24 hours up to its last fetch,
  only when that fetch was at most :data:`MAINTENANCE_MAX_AGE_SECONDS` ago;
  relay bytes are resolved from the stored traffic alone (the region's
  node list is not stored), so ``mesh network impact``, which has it and
  its own ``--days``, can judge a byte differently;
- **only when it matters** -- the node's impact level (see
  :mod:`meshprovision.network.impact`) must be at least ``medium``; every
  other node counts as a dependant, ours included (rebooting the relay
  one of our own nodes relies on matters too);
- **never in the way** -- any failure is logged at DEBUG and gives no
  note; the caller prints the note as a warning and changes nothing else.

:func:`stored_impacts` is the reusable half: every given node's impact in
the region where it matters most, each region loaded and resolved once for
all of them. ``mesh health`` uses it for its importance level.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from meshprovision.network.buckets import combine
from meshprovision.network.impact import Level, NodeImpact, node_impact
from meshprovision.network.keystore import KeyStore
from meshprovision.network.resolve import resolve_window
from meshprovision.network.store import RegionStore

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from pathlib import Path

    from meshprovision.nodeid import NodeId

__all__ = [
    "MAINTENANCE_MAX_AGE_SECONDS",
    "MAINTENANCE_WINDOW_SECONDS",
    "StoredImpact",
    "maintenance_note",
    "stored_impacts",
]

_logger = logging.getLogger(__name__)

MAINTENANCE_MAX_AGE_SECONDS: Final[float] = 48 * 3600.0
"""A region's data older than this (since its last fetch) is not used."""

MAINTENANCE_WINDOW_SECONDS: Final[float] = 24 * 3600.0
"""The window judged: this long up to the region's last fetch."""

_LEVEL_ORDER: Final[dict[Level, int]] = {Level.LOW: 0, Level.MEDIUM: 1, Level.HIGH: 2}


@dataclass(frozen=True, slots=True)
class StoredImpact:
    """A node's impact in one stored region.

    Attributes:
        impact: What depends on it there.
        region: The region's name (remote text: render it safely).
        fetched_at: When that region was last fetched, epoch seconds; the
            window judged is the 24 hours before it.
    """

    impact: NodeImpact
    region: str
    fetched_at: float


def stored_impacts(
    nodes: Iterable[NodeId], directory: Path, *, now: float
) -> dict[NodeId, StoredImpact]:
    """Find each node's impact in the stored region where it matters most.

    Read-only and offline, with the freshness rules of
    :func:`maintenance_note`; every other node counts as a dependant. Each
    region is loaded and resolved once, whatever the number of nodes.

    Args:
        nodes: The nodes to judge.
        directory: The network store directory.
        now: The current time, epoch seconds.

    Returns:
        Each node's impact in its best region (the highest level, then the
        largest share carried; on a tie the first region), for every node
        any fresh region was judged for; empty when no region has recent
        data or anything failed (logged at DEBUG).
    """
    wanted = tuple(nodes)
    try:
        return _stored(wanted, directory, now)
    except Exception as exc:  # a hint must never break the command using it
        _logger.debug("no stored impacts: %s", exc, exc_info=True)
        return {}


def _stored(nodes: tuple[NodeId, ...], directory: Path, now: float) -> dict[NodeId, StoredImpact]:
    """Judge every node in every fresh region, keeping each node's best (see above)."""
    store = RegionStore(directory)
    keys = KeyStore(directory)
    best: dict[NodeId, StoredImpact] = {}
    for region in store.regions():
        fetched_at = store.state(region).fetched_at
        if fetched_at is None or not 0 <= now - fetched_at <= MAINTENANCE_MAX_AGE_SECONDS:
            continue
        start = fetched_at - MAINTENANCE_WINDOW_SECONDS
        traffic = combine(store.load(region, start=start))
        resolutions = resolve_window(
            traffic, keys.load(region), start=start, learned=store.learned_relays(region)
        )
        for node in nodes:
            impact = node_impact(traffic, resolutions, node.hex)
            kept = best.get(node)
            if kept is None or _rank(impact) > _rank(kept.impact):
                best[node] = StoredImpact(impact, region, fetched_at)
    return best


def maintenance_note(
    node: NodeId,
    directory: Path,
    *,
    renumbers: bool = False,
    clock: Callable[[], float] = time.time,
) -> str | None:
    """Say what depends on ``node``, from the ``mesh network`` store, if it matters.

    Args:
        node: The node about to be provisioned.
        directory: The network store directory
            (``cache_dir /`` :data:`~meshprovision.network.store.NETWORK_DIRNAME`).
        renumbers: Whether applying the plan also changes the node's id
            (a key write on firmware >= 2.8), said in the sentence.
        clock: Callable returning the current unix epoch seconds.

    Returns:
        One sentence for the region where the node matters most, or
        ``None`` when its level is ``low`` everywhere, no region has
        recent data, or anything failed.
    """
    try:
        return _note(node, directory, clock(), renumbers=renumbers)
    except Exception as exc:  # a hint must never break provisioning
        _logger.debug("no maintenance note for %s: %s", node.hex, exc, exc_info=True)
        return None


def _note(node: NodeId, directory: Path, now: float, *, renumbers: bool) -> str | None:
    """Find the region where ``node`` matters most and describe it, unless it is ``low``."""
    stored = _stored((node,), directory, now).get(node)
    if stored is None or stored.impact.level is Level.LOW:
        return None
    return _sentence(node, stored.impact, stored.region, stored.fetched_at, renumbers=renumbers)


def _rank(impact: NodeImpact) -> tuple[int, float]:
    """Order impacts: by level, then by the share carried."""
    return _LEVEL_ORDER[impact.level], impact.carried_share


def _sentence(
    node: NodeId, impact: NodeImpact, region: str, fetched_at: float, *, renumbers: bool
) -> str:
    """Describe the impact in one sentence, ending with where to look."""
    as_of = time.strftime("%Y-%m-%d %H:%M", time.localtime(fetched_at))
    parts = [
        f"{node.display} carried {100 * impact.carried_share:.1f}% of {region}'s stored "
        f"relayed traffic in the 24 h before {as_of}"
    ]
    if impact.sole_first_hop_for:
        parts.append(f"{len(impact.sole_first_hop_for)} node(s) used it as their only first hop")
    if impact.origins or impact.gateways:
        parts.append(
            f"{len(impact.origins)} node(s) and {len(impact.gateways)} gateway(s) got at least "
            "half of their relayed receptions through it"
        )
    if impact.only_gateway_for:
        parts.append(f"it was the only MQTT uplink of {len(impact.only_gateway_for)} node(s)")
    applying = (
        "reboots it and changes its node id (firmware >= 2.8 derives it from the new key)"
        if renumbers
        else "reboots it"
    )
    return (
        "; ".join(parts) + f". Applying this plan {applying}. See: mesh network impact {node.hex}"
    )
