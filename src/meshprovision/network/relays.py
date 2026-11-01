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

An attributed relay's *device health* (battery, voltage, uptime, channel
utilization) comes from loranet's node dump when the caller passes it
(:func:`device_health`); nothing is invented: a battery level of 101 means
external power, and a value no device reports (a battery level of 0 or
above 101, a voltage at or below zero or above :data:`MAX_PLAUSIBLE_VOLTAGE`,
a percentage outside 0-100, a negative uptime or one past a 32-bit counter)
is left out.

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

from meshprovision.health.rules import BATTERY_WARN_PERCENT

if TYPE_CHECKING:
    from datetime import datetime

    from meshprovision.datasources.models import NodeObservation
    from meshprovision.network.buckets import Traffic
    from meshprovision.network.keys import KeySeen
    from meshprovision.network.resolve import Resolution

__all__ = [
    "DEVICE_METRICS_FRESH_SECONDS",
    "EXTERNAL_POWER_LEVEL",
    "MAX_PLAUSIBLE_VOLTAGE",
    "MAX_UPTIME_SECONDS",
    "MIN_RELAYED",
    "NOT_IN_LORANET",
    "RECENT_REBOOT_SECONDS",
    "RELYING_SHARE",
    "SOLE_FIRST_HOP_MIN_EVENTS",
    "SOLE_FIRST_HOP_MIN_EVENTS_OURS",
    "SOLE_FIRST_HOP_SHARE",
    "DeviceHealth",
    "FirstHops",
    "RelayRow",
    "RelayTable",
    "byte_label",
    "device_health",
    "device_notes",
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

EXTERNAL_POWER_LEVEL: Final[int] = 101
"""The battery level Meshtastic reports on external power."""

DEVICE_METRICS_FRESH_SECONDS: Final[float] = 24 * 3600.0
"""Device metrics older than this are shown with their age."""

RECENT_REBOOT_SECONDS: Final[float] = 3600.0
"""A node that booted less than this long ago is noted (``mesh status``'s uptime rule)."""

MAX_PLAUSIBLE_VOLTAGE: Final[float] = 100.0
"""A reported voltage above this is not a device's (left out)."""

MAX_UPTIME_SECONDS: Final[int] = 0xFFFFFFFF
"""Uptime is a 32-bit count of seconds; anything larger is left out."""

NOT_IN_LORANET: Final[str] = "not in loranet"
"""The identity gap of a relay node loranet's node dump does not hold."""


@dataclass(frozen=True, slots=True)
class DeviceHealth:
    """A relay node's device health, as loranet last had it.

    Attributes:
        battery_level: Its battery level, percent (``None``: unknown, or
            external power).
        external_power: Whether it reported external power (level 101).
        voltage: Its voltage (``None``: unknown, or at or below zero).
        uptime_seconds: Its uptime when the metrics were taken.
        channel_utilization: Its channel utilization, percent.
        air_util_tx: Its transmit air utilization, percent.
        metrics_at: When it sent those device metrics, epoch seconds.
    """

    battery_level: int | None = None
    external_power: bool = False
    voltage: float | None = None
    uptime_seconds: int | None = None
    channel_utilization: float | None = None
    air_util_tx: float | None = None
    metrics_at: float | None = None

    @property
    def known(self) -> bool:
        """Whether anything at all is known."""
        return (
            any(
                value is not None
                for value in (
                    self.battery_level,
                    self.voltage,
                    self.uptime_seconds,
                    self.channel_utilization,
                    self.air_util_tx,
                )
            )
            or self.external_power
        )


def device_health(observation: NodeObservation) -> DeviceHealth:
    """Map a loranet observation to a relay's device health, inventing nothing.

    Args:
        observation: The node's loranet observation.

    Returns:
        Its device health: level 101 is external power (no level); a level
        of 0 or above 101, a voltage outside (0, :data:`MAX_PLAUSIBLE_VOLTAGE`],
        a percentage outside 0-100 and an uptime outside
        0-:data:`MAX_UPTIME_SECONDS` are left out.
    """
    level = observation.battery_level
    voltage = observation.voltage
    uptime = observation.uptime_seconds
    return DeviceHealth(
        battery_level=level if level is not None and 0 < level < EXTERNAL_POWER_LEVEL else None,
        external_power=level == EXTERNAL_POWER_LEVEL,
        voltage=voltage if voltage is not None and 0 < voltage <= MAX_PLAUSIBLE_VOLTAGE else None,
        uptime_seconds=uptime if uptime is not None and 0 <= uptime <= MAX_UPTIME_SECONDS else None,
        channel_utilization=_percent(observation.channel_utilization),
        air_util_tx=_percent(observation.air_util_tx),
        metrics_at=_epoch(observation.last_device_metrics),
    )


def _percent(value: float | None) -> float | None:
    """Keep a percentage only when it is one (0 to 100)."""
    return value if value is not None and 0 <= value <= 100 else None


def device_notes(device: DeviceHealth, *, now: float) -> tuple[str, ...]:
    """Note what is worth a look in a relay's device health.

    Args:
        device: The device health.
        now: The current time, epoch seconds.

    Returns:
        ``rebooted <1h ago`` when it booted less than
        :data:`RECENT_REBOOT_SECONDS` before ``now`` (its uptime counted
        from when its metrics were taken, when known), ``battery low`` at
        or below the health rules' warning level.
    """
    notes = []
    if device.uptime_seconds is not None:
        taken = device.metrics_at if device.metrics_at is not None else now
        if now - (taken - device.uptime_seconds) < RECENT_REBOOT_SECONDS:
            notes.append("rebooted <1h ago")
    if device.battery_level is not None and device.battery_level <= BATTERY_WARN_PERCENT:
        notes.append("battery low")
    return tuple(notes)


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
        device: Its node's device health from loranet (``None``: no node,
            loranet not asked or failed, or not in loranet).
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
    device: DeviceHealth | None = None


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
    loranet: Mapping[str, NodeObservation] | None = None,
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
        loranet: loranet's observations by hex id, for device health;
            ``None`` when loranet was not asked or failed (no gap is then
            reported for it).

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
    context = _Context(traffic, total, our_relayed, mine, sole, nodes, keys, loranet)
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
        loranet: Mapping[str, NodeObservation] | None,
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
        self.loranet = loranet


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
        device=_device(node, context),
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
    if context.loranet is not None and node not in context.loranet:
        gaps.append(NOT_IN_LORANET)
    role = listed.role if listed is not None and listed.role else None
    return (
        len(context.traffic.direct.get(node, {})),
        role or (None if seen is None else seen.role),
        _epoch(None if listed is None else listed.last_seen),
        _epoch(None if listed is None else listed.last_boot),
        tuple(gaps),
    )


def _device(node: str | None, context: _Context) -> DeviceHealth | None:
    """Look up an attributed relay node's device health in loranet's observations."""
    if node is None or context.loranet is None or node not in context.loranet:
        return None
    return device_health(context.loranet[node])


def _epoch(value: datetime | None) -> float | None:
    """Return a datetime's epoch seconds, ``None`` for none."""
    return None if value is None else value.timestamp()
