"""What depends on a node, or on our nodes together: the other side of the relay table. Pure.

For a node ``N`` over a region's window (its *dependants* are every other
node; for one of ours, every node that is not ours):

- *carried* -- the region's relayed receptions whose relay byte resolves
  (``high``/``medium``) to ``N``; a node whose byte resolves to another
  node, or is ambiguous, carried nothing it can be credited with (the
  byte's resolution is reported instead, never a guess);
- *origins* and *gateways relying* -- dependants with at least
  :data:`~meshprovision.network.relays.MIN_RELAYED` relayed receptions that
  got at least :data:`~meshprovision.network.relays.RELYING_SHARE` of them
  through ``N``;
- *sole first hop for* -- dependants with at least
  :data:`~meshprovision.network.relays.SOLE_FIRST_HOP_MIN_EVENTS` first-hop
  events whose only first hop was ``N`` (see
  :class:`~meshprovision.network.relays.FirstHops`);
- *sole-path packets* -- dependants' packets whose every reception ``N``
  relayed last;
- *only gateway for* -- dependants with at least
  :data:`ONLY_GATEWAY_MIN_PACKETS` packets of which at least
  :data:`ONLY_GATEWAY_SHARE` were uplinked by ``N`` alone: without it they
  would no longer be seen by MQTT and lorastats (not: cut off from the mesh).

Its :class:`Level` is ``high`` when any origin or gateway relies on it for
:data:`HIGH_SHARE` or more, it is anyone's sole first hop or only gateway,
or it carried :data:`HIGH_CARRIED` of the region's relayed receptions;
``medium`` when it carried :data:`MEDIUM_CARRIED`, or anyone relies on it
for :data:`~meshprovision.network.relays.RELYING_SHARE`; else ``low``.

As for the relay table, these are shares of receptions at gateways by
last hop: they show who carries traffic now, not what breaks without it.

This module imports nothing that reads files or the network (no
``httpx``, ``pathlib``, :mod:`meshprovision.cache` or
:mod:`meshprovision.db`); ``tests/unit/test_import_contracts.py`` holds it
to that.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from meshprovision.network.relays import (
    MIN_RELAYED,
    RELYING_SHARE,
    SOLE_FIRST_HOP_MIN_EVENTS,
    first_hops,
    gateway_relayed,
)
from meshprovision.network.resolve import Confidence

if TYPE_CHECKING:
    from meshprovision.network.buckets import Traffic
    from meshprovision.network.resolve import Resolution

__all__ = [
    "HIGH_CARRIED",
    "HIGH_SHARE",
    "MEDIUM_CARRIED",
    "ONLY_GATEWAY_MIN_PACKETS",
    "ONLY_GATEWAY_SHARE",
    "Dependant",
    "FleetImpact",
    "Level",
    "NodeImpact",
    "fleet_impact",
    "node_impact",
]

HIGH_SHARE: Final[float] = 0.8
"""A dependant relying on a node for this share of its relayed receptions makes it ``high``."""

HIGH_CARRIED: Final[float] = 0.10
"""Carrying this share of the region's relayed receptions makes a node ``high``."""

MEDIUM_CARRIED: Final[float] = 0.03
"""Carrying this share of the region's relayed receptions makes a node ``medium``."""

ONLY_GATEWAY_SHARE: Final[float] = 0.5
"""A dependant with this share of its packets uplinked only by a node depends on it as a gateway."""

ONLY_GATEWAY_MIN_PACKETS: Final[int] = 5
"""The fewest packets of a dependant for its only-gateway share to be judged."""

_MASK: Final[int] = 0xFF


class Level(StrEnum):
    """How much depends on a node (see the module docs)."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class Dependant:
    """A node that relies on another, and how much.

    Attributes:
        node: Its hex id.
        share: The share it relies for, ``0..1``.
    """

    node: str
    share: float


@dataclass(frozen=True, slots=True)
class NodeImpact:
    """What depends on one node.

    Attributes:
        node: Its hex id.
        resolution: Its relay byte's resolution, or ``None`` when that byte
            relayed nothing in the window.
        carried: Relayed receptions credited to it.
        carried_share: Their share of the region's relayed receptions.
        origins: Dependant origins relying on it, the most first.
        gateways: Dependant gateways relying on it, the most first.
        sole_first_hop_for: Dependants whose only first hop it was.
        sole_path_packets: Dependants' packets whose every reception it relayed last.
        only_gateway_for: Dependants it was the only uplink for, the most first.
        level: Its level.
    """

    node: str
    resolution: Resolution | None
    carried: int
    carried_share: float
    origins: tuple[Dependant, ...]
    gateways: tuple[Dependant, ...]
    sole_first_hop_for: tuple[str, ...]
    sole_path_packets: int
    only_gateway_for: tuple[Dependant, ...]
    level: Level

    @property
    def credited(self) -> bool:
        """Whether its relay byte resolves to it (else it is credited with no relaying)."""
        return self.resolution is not None and self.resolution.node == self.node


@dataclass(frozen=True, slots=True)
class FleetImpact:
    """What depends on our nodes together, and on each.

    Attributes:
        relayed: The region's relayed receptions.
        carried: Those whose relay byte resolves to one of ours.
        possibly_carried: Those of ambiguous bytes with one of ours among
            the candidates (shown, never added).
        origins_judged: Outsider origins with enough relayed receptions.
        origins_half: Of them, those relying on us for at least half.
        origins_most: Of them, those relying on us for :data:`HIGH_SHARE`.
        gateways_judged: Outsider gateways with enough relayed receptions.
        gateways_half: Of them, those relying on us for at least half.
        gateways_most: Of them, those relying on us for :data:`HIGH_SHARE`.
        outsider_packets: Packets outsiders sent.
        sole_path_packets: Of them, those whose every reception one of ours relayed last.
        only_gateway_origins: Outsiders our gateways were the only uplink for.
        nodes: Each of our nodes' impact, in database order.
    """

    relayed: int
    carried: int
    possibly_carried: int
    origins_judged: int
    origins_half: int
    origins_most: int
    gateways_judged: int
    gateways_half: int
    gateways_most: int
    outsider_packets: int
    sole_path_packets: int
    only_gateway_origins: int
    nodes: tuple[NodeImpact, ...]


def _relayed_by_origin(traffic: Traffic, origin: str, via: Collection[int]) -> tuple[int, int]:
    """Return an origin's relayed receptions, and those relayed last by one of ``via``."""
    hops = traffic.last_hops.get(origin, {})
    total = sum(hop.receptions for hop in hops.values())
    return total, sum(hop.receptions for byte, hop in hops.items() if byte in via)


def _reliance(
    traffic: Traffic, via: Collection[int], others: Collection[str]
) -> tuple[list[Dependant], list[Dependant]]:
    """Find the judged origins and gateways among ``others`` and their share through ``via``."""
    origins = []
    for origin in traffic.last_hops:
        if origin in others:
            total, through = _relayed_by_origin(traffic, origin, via)
            if total >= MIN_RELAYED:
                origins.append(Dependant(origin, through / total))
    gateways = []
    for gateway, total in gateway_relayed(traffic).items():
        if gateway in others and total >= MIN_RELAYED:
            through = sum(
                traffic.relayed[byte][gateway].receptions
                for byte in via
                if gateway in traffic.relayed.get(byte, {})
            )
            gateways.append(Dependant(gateway, through / total))
    return origins, gateways


def _only_gateway(
    traffic: Traffic, gateways: Collection[str], others: Collection[str]
) -> list[Dependant]:
    """Find the dependants whose packets were mostly uplinked only by ``gateways``."""
    found = []
    for origin, packets in traffic.packets.items():
        if origin not in others or packets < ONLY_GATEWAY_MIN_PACKETS:
            continue
        alone = sum(n for g, n in traffic.only_gateway.get(origin, {}).items() if g in gateways)
        if alone >= ONLY_GATEWAY_SHARE * packets:
            found.append(Dependant(origin, alone / packets))
    return found


def _relying(dependants: list[Dependant]) -> tuple[Dependant, ...]:
    """Keep the dependants relying for at least half, the most first."""
    kept = (d for d in dependants if d.share >= RELYING_SHARE)
    return tuple(sorted(kept, key=lambda d: (-d.share, d.node)))


def _total(traffic: Traffic) -> int:
    """Count the region's relayed receptions."""
    return sum(radio.receptions for cells in traffic.relayed.values() for radio in cells.values())


def node_impact(
    traffic: Traffic,
    resolutions: Mapping[int, Resolution],
    node: str,
    *,
    ours: Collection[str] = (),
) -> NodeImpact:
    """Work out what depends on one node.

    Args:
        traffic: The window's traffic.
        resolutions: Each relay byte's resolution.
        node: The node's hex id.
        ours: Our nodes: for one of them, they are not its dependants.

    Returns:
        Its impact.
    """
    byte = int(node, 16) & _MASK
    resolution = resolutions.get(byte)
    via = [byte] if resolution is not None and resolution.node == node else []
    others = {n for n in _everyone(traffic) if n != node and (node not in ours or n not in ours)}
    origins, gateways = _reliance(traffic, via, others)
    carried = sum(radio.receptions for b in via for radio in traffic.relayed[b].values())
    total = _total(traffic)
    sole = tuple(
        sorted(
            origin
            for origin in traffic.last_hops
            if origin in others
            and first_hops(traffic, resolutions, origin).sole(SOLE_FIRST_HOP_MIN_EVENTS) == node
        )
    )
    relying_origins, relying_gateways = _relying(origins), _relying(gateways)
    only = tuple(sorted(_only_gateway(traffic, {node}, others), key=lambda d: (-d.share, d.node)))
    share = carried / total if total else 0.0
    return NodeImpact(
        node=node,
        resolution=resolution,
        carried=carried,
        carried_share=share,
        origins=relying_origins,
        gateways=relying_gateways,
        sole_first_hop_for=sole,
        sole_path_packets=sum(traffic.sole_relay.get(o, {}).get(b, 0) for o in others for b in via),
        only_gateway_for=only,
        level=_level((*relying_origins, *relying_gateways), bool(sole or only), share),
    )


def _level(relying: tuple[Dependant, ...], sole_or_only: bool, carried_share: float) -> Level:
    """Rate a node (see the module docs)."""
    if any(d.share >= HIGH_SHARE for d in relying) or sole_or_only or carried_share >= HIGH_CARRIED:
        return Level.HIGH
    if carried_share >= MEDIUM_CARRIED or relying:
        return Level.MEDIUM
    return Level.LOW


def _everyone(traffic: Traffic) -> set[str]:
    """Every node the window heard, as an origin or a gateway."""
    return {
        *traffic.packets,
        *traffic.last_hops,
        *(gateway for gateway in gateway_relayed(traffic)),
        *(gateway for cells in traffic.only_gateway.values() for gateway in cells),
    }


def fleet_impact(
    traffic: Traffic, resolutions: Mapping[int, Resolution], ours: Collection[str]
) -> FleetImpact:
    """Work out what depends on our nodes together, and on each.

    Args:
        traffic: The window's traffic.
        resolutions: Each relay byte's resolution.
        ours: Our nodes' hex ids, in output order.

    Returns:
        The summary.
    """
    mine = set(ours)
    via = [byte for byte, r in resolutions.items() if r.node in mine and byte in traffic.relayed]
    possibly = [
        byte
        for byte, r in resolutions.items()
        if r.confidence is Confidence.AMBIGUOUS and any(c.node in mine for c in r.candidates)
    ]
    others = _everyone(traffic) - mine
    origins, gateways = _reliance(traffic, via, others)

    def count(dependants: list[Dependant], share: float) -> int:
        return sum(1 for d in dependants if d.share >= share)

    return FleetImpact(
        relayed=_total(traffic),
        carried=sum(r.receptions for b in via for r in traffic.relayed[b].values()),
        possibly_carried=sum(r.receptions for b in possibly for r in traffic.relayed[b].values()),
        origins_judged=len(origins),
        origins_half=count(origins, RELYING_SHARE),
        origins_most=count(origins, HIGH_SHARE),
        gateways_judged=len(gateways),
        gateways_half=count(gateways, RELYING_SHARE),
        gateways_most=count(gateways, HIGH_SHARE),
        outsider_packets=sum(n for origin, n in traffic.packets.items() if origin in others),
        sole_path_packets=sum(traffic.sole_relay.get(o, {}).get(b, 0) for o in others for b in via),
        only_gateway_origins=len(_only_gateway(traffic, mine, others)),
        nodes=tuple(node_impact(traffic, resolutions, node, ours=mine) for node in ours),
    )
