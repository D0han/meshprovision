"""The relays a region's traffic goes through, and how much of ours each carries. Pure.

Every reception names the node that transmitted the packet last by its
relay byte; :mod:`meshprovision.network.resolve` attributes each byte to a
node (``high``/``medium``) or names its candidates (``ambiguous``). Per
relay byte, over the window:

- *region share* -- its relayed receptions / all relayed receptions;
- *our receptions* -- receptions of our nodes' packets it relayed last, and
  their share of all our relayed receptions; *our origins* -- which of ours;
- *sole first hop* -- our nodes that depend on it most strongly: every
  first-hop event of the node (a direct reception, whose first hop is the
  gateway, or a relayed reception after exactly one hop, whose first hop is
  the relay) went through it in at least :data:`SOLE_FIRST_HOP_SHARE` of
  :data:`SOLE_FIRST_HOP_MIN_EVENTS_OURS` or more events, and no gateway
  heard the node directly (:class:`FirstHops`);
- *sole-path packets* -- our packets whose every reception it relayed last;
- *gateways relying* -- gateways (with at least :data:`MIN_RELAYED`
  relayed receptions) that got at least :data:`RELYING_SHARE` of theirs
  through it.

All shares are of **receptions at gateways, by last hop**: they show who
carries traffic now, not what breaks without it (Meshtastic floods, and
another node usually rebroadcasts when one is gone).

This module imports nothing that reads files or the network (no
``httpx``, ``pathlib``, :mod:`meshprovision.cache` or
:mod:`meshprovision.db`); ``tests/unit/test_import_contracts.py`` holds it
to that.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from datetime import datetime

    from meshprovision.datasources.models import NodeObservation
    from meshprovision.network.buckets import Traffic
    from meshprovision.network.keys import KeySeen
    from meshprovision.network.resolve import Resolution

__all__ = [
    "MIN_RELAYED",
    "RELYING_SHARE",
    "SOLE_FIRST_HOP_MIN_EVENTS",
    "SOLE_FIRST_HOP_MIN_EVENTS_OURS",
    "SOLE_FIRST_HOP_SHARE",
    "FirstHops",
    "RelayRow",
    "RelayTable",
    "byte_label",
    "first_hops",
    "gateway_relayed",
    "relay_table",
]

SOLE_FIRST_HOP_SHARE: Final[float] = 0.9
"""The least share of an origin's first-hop events one relay must have to be its sole first hop."""

SOLE_FIRST_HOP_MIN_EVENTS: Final[int] = 20
"""The fewest first-hop events of an outsider for a sole first hop to be judged."""

SOLE_FIRST_HOP_MIN_EVENTS_OURS: Final[int] = 5
"""The fewest first-hop events of one of our nodes (they send little) for a sole first hop."""

MIN_RELAYED: Final[int] = 20
"""The fewest relayed receptions of an origin or gateway for its shares to be judged."""

RELYING_SHARE: Final[float] = 0.5
"""A gateway relies on a relay that carried at least this share of its relayed receptions."""


@dataclass(frozen=True, slots=True)
class FirstHops:
    """An origin's first-hop events.

    Attributes:
        direct: Strict direct receptions (their first hop is the gateway).
        relays: First hop (an attributed node, or a byte label such as
            ``0xe4``) -> relayed receptions after exactly one hop.
    """

    direct: int = 0
    relays: Mapping[str, int] = field(default_factory=lambda: MappingProxyType({}))

    @property
    def events(self) -> int:
        """All first-hop events."""
        return self.direct + sum(self.relays.values())

    def sole(self, min_events: int) -> str | None:
        """Return the origin's sole first hop, if it has one.

        Args:
            min_events: The fewest events to judge.

        Returns:
            The relay that took at least :data:`SOLE_FIRST_HOP_SHARE` of at
            least ``min_events`` events of an origin no gateway heard
            directly, else ``None``.
        """
        if self.direct or self.events < min_events or not self.relays:
            return None
        top, count = max(self.relays.items(), key=lambda item: (item[1], item[0]))
        return top if count >= SOLE_FIRST_HOP_SHARE * self.events else None


@dataclass(frozen=True, slots=True)
class RelayRow:
    """One relay byte's part in the region's traffic.

    Attributes:
        resolution: What the byte resolves to (``node`` is ``None`` unless
            ``high`` or ``medium``).
        relayed: Its relayed receptions.
        region_share: Its share of the region's relayed receptions.
        origins: How many origins it relayed last.
        our_receptions: Receptions of our packets it relayed last.
        our_share: Their share of our relayed receptions (``None`` without any).
        our_origins: Our nodes it relayed last.
        our_sole_first_hop: Our nodes whose sole first hop it is.
        our_sole_path_packets: Our packets whose every reception it relayed last.
        gateways_relying: Gateways with at least :data:`RELYING_SHARE` of
            their relayed receptions through it.
        max_gateway_share: The largest such share of any judged gateway.
        heard_directly_by: Gateways that heard its node directly.
        role: Its node's role, from lorastats' node list or its node info.
        last_seen: When lorastats last heard its node, epoch seconds.
        last_boot: When its node last booted, epoch seconds.
        gaps: What is not known about its node's identity.
    """

    resolution: Resolution
    relayed: int
    region_share: float
    origins: int
    our_receptions: int = 0
    our_share: float | None = None
    our_origins: tuple[str, ...] = ()
    our_sole_first_hop: tuple[str, ...] = ()
    our_sole_path_packets: int = 0
    gateways_relying: int = 0
    max_gateway_share: float = 0.0
    heard_directly_by: int = 0
    role: str | None = None
    last_seen: float | None = None
    last_boot: float | None = None
    gaps: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RelayTable:
    """A region's relays over the window.

    Attributes:
        rows: The relays shown, in order.
        relayed: All relayed receptions of the region.
        our_packets: Packets our nodes sent.
        our_relayed: Relayed receptions of our packets.
    """

    rows: tuple[RelayRow, ...]
    relayed: int
    our_packets: int
    our_relayed: int


def byte_label(byte: int) -> str:
    """Render a relay byte, for example ``0xe4``.

    Args:
        byte: The byte.

    Returns:
        Its label.
    """
    return f"0x{byte:02x}"


def first_hops(traffic: Traffic, resolutions: Mapping[int, Resolution], origin: str) -> FirstHops:
    """Collect an origin's first-hop events.

    Args:
        traffic: The window's traffic.
        resolutions: Each relay byte's resolution.
        origin: The origin's hex id.

    Returns:
        Its direct receptions and its relayed receptions after one hop,
        by attributed relay (or byte label).
    """
    direct = sum(radio.receptions for radio in traffic.direct.get(origin, {}).values())
    relays: Counter[str] = Counter()
    for byte, hop in traffic.last_hops.get(origin, {}).items():
        if hop.first_hop:
            resolution = resolutions.get(byte)
            node = None if resolution is None else resolution.node
            relays[node or byte_label(byte)] += hop.first_hop
    return FirstHops(direct, MappingProxyType(dict(sorted(relays.items()))))


def gateway_relayed(traffic: Traffic) -> Mapping[str, int]:
    """Count each gateway's relayed receptions.

    Args:
        traffic: The window's traffic.

    Returns:
        Gateway -> its relayed receptions.
    """
    totals: Counter[str] = Counter()
    for cells in traffic.relayed.values():
        for gateway, radio in cells.items():
            totals[gateway] += radio.receptions
    return MappingProxyType(dict(totals))


def relay_table(
    traffic: Traffic,
    resolutions: Mapping[int, Resolution],
    ours: Collection[str],
    *,
    nodes: Iterable[NodeObservation] = (),
    keys: Iterable[KeySeen] = (),
    everything: bool = False,
) -> RelayTable:
    """Build the relay table of a region's window.

    Args:
        traffic: The window's traffic.
        resolutions: Each relay byte's resolution.
        ours: Our nodes' hex ids.
        nodes: The region's node list (for roles, last seen and boot).
        keys: The window's key sightings (for node info and derived ids).
        everything: Every relay not ours, by region share (else only those
            that carried our packets, by our dependence on them).

    Returns:
        The table. A byte attributed to one of our nodes is never a row.
    """
    total = sum(radio.receptions for cells in traffic.relayed.values() for radio in cells.values())
    mine = list(ours)
    our_relayed = sum(
        hop.receptions for node in mine for hop in traffic.last_hops.get(node, {}).values()
    )
    sole = {
        node: first_hops(traffic, resolutions, node).sole(SOLE_FIRST_HOP_MIN_EVENTS_OURS)
        for node in mine
    }
    context = _Context(traffic, total, our_relayed, mine, sole, nodes, keys)
    rows = [
        _row(byte, resolution, context)
        for byte, resolution in resolutions.items()
        if resolution.node not in ours
    ]
    if everything:
        rows.sort(key=lambda row: (-row.region_share, row.resolution.byte))
    else:
        rows = [row for row in rows if row.our_receptions]
        rows.sort(
            key=lambda row: (
                -len(row.our_sole_first_hop),
                -row.our_receptions,
                -row.region_share,
                row.resolution.byte,
            )
        )
    return RelayTable(
        rows=tuple(rows),
        relayed=total,
        our_packets=sum(traffic.packets.get(node, 0) for node in mine),
        our_relayed=our_relayed,
    )


class _Context:
    """What every row of one table is computed from."""

    def __init__(
        self,
        traffic: Traffic,
        total: int,
        our_relayed: int,
        mine: list[str],
        sole: Mapping[str, str | None],
        nodes: Iterable[NodeObservation],
        keys: Iterable[KeySeen],
    ) -> None:
        self.traffic = traffic
        self.total = total
        self.our_relayed = our_relayed
        self.mine = mine
        self.sole = sole
        self.gateways = {g: n for g, n in gateway_relayed(traffic).items() if n >= MIN_RELAYED}
        self.listed = {node.node_id.hex: node for node in nodes}
        seen: dict[str, KeySeen] = {}
        for entry in keys:
            if entry.node not in seen or entry.last > seen[entry.node].last:
                seen[entry.node] = entry
        self.keys = seen


def _row(byte: int, resolution: Resolution, context: _Context) -> RelayRow:
    """Compute one relay byte's row."""
    traffic = context.traffic
    cells = traffic.relayed[byte]
    relayed = sum(radio.receptions for radio in cells.values())
    node = resolution.node
    ours = {
        origin: traffic.last_hops[origin][byte].receptions
        for origin in context.mine
        if byte in traffic.last_hops.get(origin, {})
    }
    shares = [cells[g].receptions / n for g, n in context.gateways.items() if g in cells]
    received = sum(ours.values())
    heard_directly_by, role, last_seen, last_boot, gaps = _identity(node, context)
    return RelayRow(
        resolution=resolution,
        relayed=relayed,
        region_share=relayed / context.total if context.total else 0.0,
        origins=sum(1 for hops in traffic.last_hops.values() if byte in hops),
        our_receptions=received,
        our_share=received / context.our_relayed if context.our_relayed else None,
        our_origins=tuple(sorted(ours)),
        our_sole_first_hop=tuple(
            sorted(
                o
                for o, hop in context.sole.items()
                if hop is not None and hop in (node, byte_label(byte))
            )
        ),
        our_sole_path_packets=sum(
            traffic.sole_relay.get(origin, {}).get(byte, 0) for origin in context.mine
        ),
        gateways_relying=sum(1 for share in shares if share >= RELYING_SHARE),
        max_gateway_share=max(shares, default=0.0),
        heard_directly_by=heard_directly_by,
        role=role,
        last_seen=last_seen,
        last_boot=last_boot,
        gaps=gaps,
    )


def _identity(
    node: str | None, context: _Context
) -> tuple[int, str | None, float | None, float | None, tuple[str, ...]]:
    """Describe an attributed relay node: gateways hearing it, role, last seen/boot, gaps."""
    if node is None:
        return 0, None, None, None, ()
    listed = context.listed.get(node)
    seen = context.keys.get(node)
    gaps = []
    if listed is None:
        gaps.append("not in lorastats' node list")
    if seen is None:
        gaps.append("no node info")
    elif not seen.derived:
        gaps.append("id not key-derived")
    role = listed.role if listed is not None and listed.role else None
    return (
        len(context.traffic.direct.get(node, {})),
        role or (None if seen is None else seen.role),
        _epoch(None if listed is None else listed.last_seen),
        _epoch(None if listed is None else listed.last_boot),
        tuple(gaps),
    )


def _epoch(value: datetime | None) -> float | None:
    """Return a datetime's epoch seconds, ``None`` for none."""
    return None if value is None else value.timestamp()
