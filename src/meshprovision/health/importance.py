"""How much the rest of our fleet, and its region, rely on a node. Pure.

The importance half of :mod:`meshprovision.health.rules`, which
re-exports every public name here: a score that counts what the rest of
our fleet would lose without the node (see :func:`rank_importance`),
raised to how much its region relied on it when ``mesh network`` data
says so.

This module imports nothing that reads files or the network (no
``httpx``, ``pathlib``, :mod:`meshprovision.cache` or
:mod:`meshprovision.db`); ``tests/unit/test_import_contracts.py`` holds it
to that.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from meshprovision.health.metrics import NodeMetrics
from meshprovision.nodeid import NodeId

__all__ = [
    "IMPORTANCE_HIGH_SCORE",
    "IMPORTANCE_MEDIUM_SCORE",
    "MIN_RECEPTIONS",
    "RELAY_DEPENDENCY_SHARE",
    "ROUTER_ROLES",
    "Importance",
    "RegionImportance",
    "rank_importance",
]

MIN_RECEPTIONS: Final[int] = 20
"""Fewest receptions (or relayed receptions) a gateway or relay rule judges."""

RELAY_DEPENDENCY_SHARE: Final[float] = 0.5
"""A node of ours depends on a relay that carried at least this share of its relayed receptions."""

ROUTER_ROLES: Final[frozenset[str]] = frozenset(
    {"ROUTER", "ROUTER_LATE", "ROUTER_CLIENT", "REPEATER"}
)
"""Roles that rebroadcast for everyone."""

IMPORTANCE_HIGH_SCORE: Final[int] = 5
"""An importance score of this or more is ``high``."""

IMPORTANCE_MEDIUM_SCORE: Final[int] = 2
"""An importance score of this or more is ``medium``; below it ``low``."""

_IMPORTANCE_LEVELS: Final[tuple[str, ...]] = ("low", "medium", "high")
_GATEWAY_POINTS: Final[int] = 3
_SOLE_GATEWAY_POINTS: Final[int] = 3
_DEPENDENT_POINTS: Final[int] = 2
_ROUTER_POINTS: Final[int] = 1


@dataclass(frozen=True, slots=True)
class RegionImportance:
    """How much a whole region relied on a node, from the ``mesh network`` store.

    Attributes:
        region: The region's name (remote text: render it safely).
        as_of: When the region's data was fetched, epoch seconds; it
            covers the 24 hours before.
        level: The node's impact level there: ``"high"``, ``"medium"`` or
            ``"low"``.
        carried_share: Its share of the region's relayed receptions.
        sole_first_hop_for: How many nodes it was the only first hop of.
        origins_relying: How many origins got at least half of their
            relayed receptions through it.
        gateways_relying: How many gateways did.
        only_gateway_for: How many nodes it was mostly the only MQTT
            uplink for.
    """

    region: str
    as_of: float
    level: str
    carried_share: float
    sole_first_hop_for: int = 0
    origins_relying: int = 0
    gateways_relying: int = 0
    only_gateway_for: int = 0


@dataclass(frozen=True, slots=True)
class Importance:
    """How much the rest of our fleet, and its region, rely on a node.

    Attributes:
        level: ``"high"``, ``"medium"`` or ``"low"``: the higher of
            :attr:`fleet_level` and :attr:`network`'s level.
        score: The fleet points behind :attr:`fleet_level`.
        reasons: Why, for a person (the fleet's reasons).
        uplinked: Our nodes it uplinked as an MQTT gateway.
        sole_gateway_for: Our nodes no other gateway uplinked.
        dependents: Our nodes whose busiest relay is (likely) it.
        network: How much its region relied on it, when that is at least
            ``medium``; else ``None``.
    """

    level: str
    score: int
    reasons: tuple[str, ...] = ()
    uplinked: tuple[NodeId, ...] = ()
    sole_gateway_for: tuple[NodeId, ...] = ()
    dependents: tuple[NodeId, ...] = ()
    network: RegionImportance | None = None

    @property
    def fleet_level(self) -> str:
        """The level the fleet points alone give."""
        return _score_level(self.score)


def _gateway_ids(metrics: NodeMetrics) -> frozenset[str]:
    """Return every gateway that uplinked the node."""
    return frozenset(gateway for gateway, _ in metrics.gateways)


def _depends_on(metrics: NodeMetrics, relay: NodeId) -> bool:
    """Tell whether ``relay`` (likely) carried most of a node's relayed receptions."""
    top = metrics.top_relay
    return (
        top is not None
        and metrics.relayed >= MIN_RECEPTIONS
        and top.share >= RELAY_DEPENDENCY_SHARE
        and top.candidates == (relay,)
    )


def _score_level(score: int) -> str:
    """The importance level a fleet score gives."""
    if score >= IMPORTANCE_HIGH_SCORE:
        return "high"
    return "medium" if score >= IMPORTANCE_MEDIUM_SCORE else "low"


def _combined(fleet_level: str, network: RegionImportance | None) -> str:
    """The higher of the fleet level and the region's (max-combine; nothing counted twice)."""
    if network is None:
        return fleet_level
    return max(fleet_level, network.level, key=_IMPORTANCE_LEVELS.index)


def rank_importance(
    metrics_by_node: Mapping[NodeId, NodeMetrics],
    roles: Mapping[NodeId, str | None],
    *,
    region: Mapping[NodeId, RegionImportance] = MappingProxyType({}),
) -> dict[NodeId, Importance]:
    """Score how much the rest of our fleet relies on each node.

    Points: an MQTT gateway (it uplinks itself or one of our nodes, or a
    gateway check saw it uplink anything) 3; per node of ours it is the
    only gateway for (with at least :data:`MIN_RECEPTIONS` receptions) 3;
    per node of ours whose busiest relay byte is unambiguously its own
    and carried at least :data:`RELAY_DEPENDENCY_SHARE` of its relayed
    receptions 2; a router role 1. ``high`` from
    :data:`IMPORTANCE_HIGH_SCORE`, ``medium`` from
    :data:`IMPORTANCE_MEDIUM_SCORE`.

    A node whose region (``mesh network`` data) relied on it at least
    ``medium`` gets the higher of the two levels; its score stays the fleet
    points. A region rated ``low`` changes nothing.

    Args:
        metrics_by_node: Our nodes' metrics (the fleet).
        roles: Our nodes' roles, when known.
        region: How much each node's region relied on it, when known.

    Returns:
        Each node's importance.
    """
    result: dict[NodeId, Importance] = {}
    for node, metrics in metrics_by_node.items():
        others = [(other, m) for other, m in metrics_by_node.items() if other != node]
        uplinked = tuple(other for other, m in others if node.hex in _gateway_ids(m))
        sole = tuple(
            other
            for other, m in others
            if m.receptions >= MIN_RECEPTIONS and _gateway_ids(m) == {node.hex}
        )
        dependents = tuple(other for other, m in others if _depends_on(m, node))
        check = metrics.gateway_check
        gateway = (
            metrics.uplinks_itself or bool(uplinked) or (check is not None and check.nodes > 0)
        )
        router = roles.get(node) in ROUTER_ROLES
        score = (
            _GATEWAY_POINTS * gateway
            + _SOLE_GATEWAY_POINTS * len(sole)
            + _DEPENDENT_POINTS * len(dependents)
            + _ROUTER_POINTS * router
        )
        reasons = [
            text
            for text, applies in (
                ("MQTT gateway", gateway),
                (f"uplinks {len(uplinked)} of our nodes", bool(uplinked)),
                (f"only gateway for {len(sole)} of our nodes", bool(sole)),
                (f"busiest relay of {len(dependents)} of our nodes", bool(dependents)),
                (f"role {roles.get(node)}", router),
            )
            if applies
        ]
        network = region.get(node)
        if network is not None and network.level == "low":
            network = None
        level = _combined(_score_level(score), network)
        result[node] = Importance(level, score, tuple(reasons), uplinked, sole, dependents, network)
    return result
