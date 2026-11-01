"""The maintenance warning of ``mesh provision``: does anything depend on the node about to restart?

Applying a plan writes the device's configuration and reboots it (a key
regeneration also changes a firmware 2.8 node's id). When other nodes
rely on it, the operator should know before confirming.
:func:`maintenance_note` answers from the ``mesh network`` store alone:

- **offline** -- it reads only what ``mesh network`` stored in the cache
  directory: no request, no contact needed;
- **recent data only** -- per region, the 24 hours up to its last fetch,
  only when that fetch was at most :data:`MAINTENANCE_MAX_AGE_SECONDS` ago;
- **only when it matters** -- the node's impact level (see
  :mod:`meshprovision.network.impact`) must be at least ``medium``; every
  other node counts as a dependant, ours included (rebooting the relay
  one of our own nodes relies on matters too);
- **never in the way** -- any failure is logged at DEBUG and gives no
  note; the caller prints the note as a warning and changes nothing else.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Final

from meshprovision.network.buckets import combine
from meshprovision.network.impact import Level, NodeImpact, node_impact
from meshprovision.network.keystore import KeyStore
from meshprovision.network.resolve import relay_candidates, resolve_relays
from meshprovision.network.store import RegionStore

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from meshprovision.nodeid import NodeId

__all__ = ["MAINTENANCE_MAX_AGE_SECONDS", "MAINTENANCE_WINDOW_SECONDS", "maintenance_note"]

_logger = logging.getLogger(__name__)

MAINTENANCE_MAX_AGE_SECONDS: Final[float] = 48 * 3600.0
"""A region's data older than this (since its last fetch) is not used."""

MAINTENANCE_WINDOW_SECONDS: Final[float] = 24 * 3600.0
"""The window judged: this long up to the region's last fetch."""

_MUTE_ROLE: Final[str] = "CLIENT_MUTE"


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
    """Find the region where ``node`` matters most and describe it."""
    store = RegionStore(directory)
    keys = KeyStore(directory)
    worst: tuple[NodeImpact, str, float] | None = None
    for region in store.regions():
        fetched_at = store.state(region).fetched_at
        if fetched_at is None or not 0 <= now - fetched_at <= MAINTENANCE_MAX_AGE_SECONDS:
            continue
        start = fetched_at - MAINTENANCE_WINDOW_SECONDS
        traffic = combine(store.load(region, start=start))
        mute = {entry.node for entry in keys.load(region) if entry.role == _MUTE_ROLE}
        candidates = relay_candidates(traffic, start=start, mute=mute)
        resolutions = resolve_relays(traffic, candidates, learned=store.learned_relays(region))
        impact = node_impact(traffic, resolutions, node.hex)
        if impact.level is not Level.LOW and (worst is None or _rank(impact) > _rank(worst[0])):
            worst = (impact, region, fetched_at)
    return None if worst is None else _sentence(node, *worst, renumbers=renumbers)


def _rank(impact: NodeImpact) -> tuple[bool, float]:
    """Order impacts: ``high`` first, then by the share carried."""
    return impact.level is Level.HIGH, impact.carried_share


def _sentence(
    node: NodeId, impact: NodeImpact, region: str, fetched_at: float, *, renumbers: bool
) -> str:
    """Describe the impact in one sentence, ending with where to look."""
    as_of = time.strftime("%Y-%m-%d %H:%M", time.localtime(fetched_at))
    parts = [
        f"{node.display} carried {100 * impact.carried_share:.1f}% of {region}'s relayed "
        f"traffic in the 24 h before {as_of}"
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
