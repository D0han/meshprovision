"""Pure per-node observation merging and online/stale/offline classification.

This module is strictly pure: no filesystem, no network, no device I/O,
no ``datetime.now()``, no logging side effects, no protobuf imports. The
caller always supplies ``now`` explicitly. This is what makes it
trivially unit-testable with hand-built
:class:`~meshprovision.datasources.models.NodeObservation` instances and
a fixed clock, and what makes :mod:`meshprovision.status.report`'s
``--dry-run``-adjacent reporting exact rather than approximate.

:func:`merge_observations` combines every source's observation of one
node into a single :class:`MergedNode`, applying the field-precedence
rules documented on that function. :func:`merge_all` does the same for
every node in a caller-supplied, never-re-sorted id order.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final, TypeVar

from meshprovision.datasources.base import SOURCE_LORANET, SOURCE_LORASTATS
from meshprovision.datasources.models import NodeObservation
from meshprovision.db.nodes import NodeRecord
from meshprovision.nodeid import NodeId

__all__ = [
    "DEFAULT_OFFLINE_AFTER",
    "DEFAULT_STALE_AFTER",
    "SOURCE_PRIORITY",
    "Availability",
    "MergedNode",
    "Thresholds",
    "classify_age",
    "humanize_age",
    "merge_all",
    "merge_observations",
]

_T = TypeVar("_T")

DEFAULT_STALE_AFTER: Final[timedelta] = timedelta(hours=2)
"""A node last seen more recently than this is :attr:`Availability.ONLINE`."""

DEFAULT_OFFLINE_AFTER: Final[timedelta] = timedelta(hours=24)
"""A node last seen longer ago than this is :attr:`Availability.OFFLINE`."""

SOURCE_PRIORITY: Final[tuple[str, ...]] = (SOURCE_LORANET, SOURCE_LORASTATS)
"""Source precedence order for telemetry/identity field resolution: loranet
first (it reports ``chUtil``/``airUtilTx``/``seenBy``), lorastats second as
fallback and as last-seen corroboration."""

_SECONDS_PER_MINUTE: Final[int] = 60
_SECONDS_PER_HOUR: Final[int] = 3600
_SECONDS_PER_DAY: Final[int] = 86400


class Availability(StrEnum):
    """A node's coarse online/stale/offline classification.

    Attributes:
        ONLINE: Seen more recently than the configured ``stale_after``.
        STALE: Seen longer ago than ``stale_after`` but within
            ``offline_after``.
        OFFLINE: Not seen within ``offline_after``.
        UNKNOWN: Never seen by any configured data source.
    """

    ONLINE = "online"
    STALE = "stale"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Thresholds:
    """The age boundaries used to classify a node's availability.

    Attributes:
        stale_after: A node last seen within this age is
            :attr:`Availability.ONLINE`. Defaults to
            :data:`DEFAULT_STALE_AFTER`.
        offline_after: A node last seen within this age (but past
            ``stale_after``) is :attr:`Availability.STALE`; older is
            :attr:`Availability.OFFLINE`. Defaults to
            :data:`DEFAULT_OFFLINE_AFTER`.
    """

    stale_after: timedelta = DEFAULT_STALE_AFTER
    offline_after: timedelta = DEFAULT_OFFLINE_AFTER

    def __post_init__(self) -> None:
        """Validate that both thresholds are positive and correctly ordered.

        Raises:
            ValueError: If either threshold is not a positive duration,
                or if ``stale_after`` is not strictly less than
                ``offline_after``.
        """
        if self.stale_after <= timedelta(0):
            raise ValueError(f"stale_after must be positive, got {self.stale_after}")
        if self.offline_after <= timedelta(0):
            raise ValueError(f"offline_after must be positive, got {self.offline_after}")
        if self.stale_after >= self.offline_after:
            raise ValueError(
                f"stale_after ({self.stale_after}) must be strictly less than "
                f"offline_after ({self.offline_after})"
            )

    @classmethod
    def from_hours(cls, stale_hours: float, offline_hours: float) -> Thresholds:
        """Build a :class:`Thresholds` from hour counts.

        Args:
            stale_hours: Hours before a node stops being
                :attr:`Availability.ONLINE`.
            offline_hours: Hours before a node becomes
                :attr:`Availability.OFFLINE`.

        Returns:
            The constructed, validated :class:`Thresholds`.

        Raises:
            ValueError: If the resulting thresholds fail
                :meth:`__post_init__`'s validation.
        """
        return cls(
            stale_after=timedelta(hours=stale_hours), offline_after=timedelta(hours=offline_hours)
        )


_DEFAULT_THRESHOLDS: Final[Thresholds] = Thresholds()
"""Module-level singleton default for the ``thresholds`` parameter below --
avoids constructing a fresh :class:`Thresholds` on every call/def evaluation
(``Thresholds`` is immutable, so sharing one instance is always safe)."""


@dataclass(frozen=True, slots=True)
class MergedNode:
    """One node's combined view across every data source and the database.

    Attributes:
        node_id: The node's canonical id.
        sources: The data sources that observed this node, in
            :data:`SOURCE_PRIORITY` order.
        record: This node's row in the ``Nodes`` sheet, or ``None`` when
            the node is not in the database.
        short_name: Best-known short display name (see
            :func:`merge_observations` for the precedence rule).
        long_name: Best-known long display name.
        hw_model: Best-known hardware model.
        role: Best-known device role.
        region: Best-known LoRa region.
        firmware_version: Best-known firmware version string.
        latitude: Best-known latitude, decimal degrees.
        longitude: Best-known longitude, decimal degrees.
        altitude: Best-known altitude, meters.
        battery_level: Best-known battery level percentage.
        voltage: Best-known battery voltage.
        channel_utilization: Best-known channel utilization percentage.
        air_util_tx: Best-known transmit air utilization percentage.
        neighbor_count: Best-known neighbor/gateway count.
        uptime_seconds: Best-known device uptime, seconds.
        last_seen: The most recent ``last_seen`` timestamp across every
            observation, or ``None`` if no observation reported one.
        last_seen_source: The source that supplied :attr:`last_seen`.
        age: ``now - last_seen``, or ``None`` when :attr:`last_seen` is
            ``None``.
        age_text: Human-readable rendering of :attr:`age`, from
            :func:`humanize_age`.
        availability: The classification from :func:`classify_age`.
    """

    node_id: NodeId
    sources: tuple[str, ...] = ()
    record: NodeRecord | None = None
    short_name: str | None = None
    long_name: str | None = None
    hw_model: str | None = None
    role: str | None = None
    region: str | None = None
    firmware_version: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    altitude: int | None = None
    battery_level: int | None = None
    voltage: float | None = None
    channel_utilization: float | None = None
    air_util_tx: float | None = None
    neighbor_count: int | None = None
    uptime_seconds: int | None = None
    last_seen: datetime | None = None
    last_seen_source: str | None = None
    age: timedelta | None = None
    age_text: str = "never"
    availability: Availability = Availability.UNKNOWN

    @property
    def in_database(self) -> bool:
        """Whether this node has a row in the ``Nodes`` sheet.

        Returns:
            ``True`` if :attr:`record` is not ``None``.
        """
        return self.record is not None

    @property
    def observed(self) -> bool:
        """Whether any data source observed this node.

        Returns:
            ``True`` if :attr:`sources` is non-empty.
        """
        return bool(self.sources)

    @property
    def management(self) -> str | None:
        """This node's database management mode.

        Returns:
            ``"template"`` or ``"observed"`` from :attr:`record`, or
            ``None`` when the node has no row in the ``Nodes`` sheet.
        """
        return None if self.record is None else self.record.management.value

    def to_json_dict(self) -> dict[str, object]:
        """Render this node as a stable, secret-free JSON-able mapping.

        Never emits ``ble_pin``, any key material, or a ``key_ref`` --
        :attr:`record` is never serialized wholesale; only its
        ``short_name``/``long_name``/``role``/``region``/``management``
        are picked into a nested ``"database"`` object.

        Returns:
            A mapping with insertion-ordered keys, safe to pass to
            ``json.dumps``.
        """
        database: dict[str, object] | None = None
        if self.record is not None:
            database = {
                "short_name": self.record.short_name,
                "long_name": self.record.long_name,
                "role": self.record.role,
                "region": self.record.region,
                "management": self.record.management.value,
            }
        return {
            "node_id": self.node_id.hex,
            "display": self.node_id.display,
            "sources": list(self.sources),
            "short_name": self.short_name,
            "long_name": self.long_name,
            "hw_model": self.hw_model,
            "role": self.role,
            "region": self.region,
            "firmware_version": self.firmware_version,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "altitude": self.altitude,
            "battery_level": self.battery_level,
            "voltage": self.voltage,
            "channel_utilization": self.channel_utilization,
            "air_util_tx": self.air_util_tx,
            "neighbor_count": self.neighbor_count,
            "uptime_seconds": self.uptime_seconds,
            "last_seen": _isoformat_z(self.last_seen),
            "last_seen_source": self.last_seen_source,
            "age_seconds": int(self.age.total_seconds()) if self.age is not None else None,
            "age_text": self.age_text,
            "availability": self.availability.value,
            "in_database": self.in_database,
            "database": database,
        }


def _isoformat_z(value: datetime | None) -> str | None:
    """Render a timezone-aware datetime as ISO-8601 with a ``Z`` suffix.

    Args:
        value: The datetime to render, or ``None``.

    Returns:
        For example ``"2026-08-25T03:14:10Z"``, or ``None`` when ``value``
        is ``None``.
    """
    if value is None:
        return None
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def humanize_age(age: timedelta | None) -> str:
    """Render an age as a short, human-readable string.

    Boundaries (with ``secs = int(age.total_seconds())``):

    - ``age is None`` -> ``"never"``.
    - ``secs`` negative (a future timestamp / clock skew) -> ``"in the
      future"``.
    - ``secs < 60`` -> ``"just now"``.
    - ``secs < 3600`` -> ``"N minute(s) ago"``.
    - ``secs < 86400`` -> ``"N hour(s) ago"``.
    - else -> ``"N day(s) ago"``.

    Args:
        age: The age to render, or ``None`` when unknown.

    Returns:
        The rendered string.
    """
    if age is None:
        return "never"
    total_seconds = age.total_seconds()
    if total_seconds < 0:
        return "in the future"
    secs = int(total_seconds)
    if secs < _SECONDS_PER_MINUTE:
        return "just now"
    if secs < _SECONDS_PER_HOUR:
        minutes = secs // _SECONDS_PER_MINUTE
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    if secs < _SECONDS_PER_DAY:
        hours = secs // _SECONDS_PER_HOUR
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    days = secs // _SECONDS_PER_DAY
    return f"{days} day{'s' if days != 1 else ''} ago"


def classify_age(
    age: timedelta | None, thresholds: Thresholds = _DEFAULT_THRESHOLDS
) -> Availability:
    """Classify an age against a set of thresholds.

    A negative age (a future timestamp / clock skew) is treated as
    :attr:`Availability.ONLINE`, since it is smaller than any positive
    ``stale_after``.

    Args:
        age: The age to classify, or ``None`` when unknown.
        thresholds: The boundaries to classify against. Defaults to
            :data:`DEFAULT_STALE_AFTER` / :data:`DEFAULT_OFFLINE_AFTER`.

    Returns:
        :attr:`Availability.UNKNOWN` when ``age`` is ``None``;
        :attr:`Availability.ONLINE` when ``age <= thresholds.stale_after``;
        :attr:`Availability.STALE` when ``age <= thresholds.offline_after``;
        :attr:`Availability.OFFLINE` otherwise.
    """
    if age is None:
        return Availability.UNKNOWN
    if age <= thresholds.stale_after:
        return Availability.ONLINE
    if age <= thresholds.offline_after:
        return Availability.STALE
    return Availability.OFFLINE


def _priority_index(source: str) -> int:
    """Return a source's sort key under :data:`SOURCE_PRIORITY`.

    Args:
        source: The observation's source name.

    Returns:
        Its index in :data:`SOURCE_PRIORITY`, or ``len(SOURCE_PRIORITY)``
        for an unrecognized source -- which places every unknown source
        after every known one, and (because Python's sort is stable)
        preserves their relative input order among themselves.
    """
    try:
        return SOURCE_PRIORITY.index(source)
    except ValueError:
        return len(SOURCE_PRIORITY)


def _order_by_priority(observations: Sequence[NodeObservation]) -> tuple[NodeObservation, ...]:
    """Order observations by :data:`SOURCE_PRIORITY`, stably.

    Args:
        observations: The observations to order.

    Returns:
        ``observations`` sorted by :func:`_priority_index`; ties (equal
        priority, i.e. unrecognized sources) keep their original relative
        order.
    """
    return tuple(sorted(observations, key=lambda obs: _priority_index(obs.source)))


def _order_by_recency(by_priority: Sequence[NodeObservation]) -> tuple[NodeObservation, ...]:
    """Order (already priority-ordered) observations by recency, ``None`` last.

    Args:
        by_priority: Observations already ordered by
            :func:`_order_by_priority`.

    Returns:
        Observations ordered by their own ``last_seen`` descending
        (``None`` sorted last); ties -- including two ``None`` values --
        keep their relative priority order, since Python's sort is
        stable and the input is already priority-ordered.
    """

    def _key(obs: NodeObservation) -> tuple[int, float]:
        if obs.last_seen is None:
            return (1, 0.0)
        return (0, -obs.last_seen.timestamp())

    return tuple(sorted(by_priority, key=_key))


def _first_non_none(
    ordered: Sequence[NodeObservation], extractor: Callable[[NodeObservation], _T | None]
) -> _T | None:
    """Return the first non-``None`` value ``extractor`` finds, in order.

    Args:
        ordered: The observations to scan, in the desired precedence
            order.
        extractor: Callable pulling one field off an observation.

    Returns:
        The first non-``None`` extracted value, or ``None`` if every
        observation's extracted value was ``None``.
    """
    for obs in ordered:
        value = extractor(obs)
        if value is not None:
            return value
    return None


def _pick_last_seen(by_priority: Sequence[NodeObservation]) -> tuple[datetime | None, str | None]:
    """Pick the maximum ``last_seen`` across observations, with tie-break.

    On an exact tie, the higher-priority source wins -- achieved by only
    replacing the running best on a *strictly* greater timestamp while
    scanning ``by_priority`` in its already-priority-sorted order.

    Args:
        by_priority: Observations ordered by :func:`_order_by_priority`.

    Returns:
        A ``(last_seen, source)`` pair, or ``(None, None)`` if no
        observation reported a ``last_seen``.
    """
    best: NodeObservation | None = None
    for obs in by_priority:
        if obs.last_seen is None:
            continue
        if best is None or best.last_seen is None or obs.last_seen > best.last_seen:
            best = obs
    if best is None:
        return None, None
    return best.last_seen, best.source


def merge_observations(
    node_id: NodeId,
    observations: Sequence[NodeObservation],
    *,
    record: NodeRecord | None = None,
    now: datetime,
    thresholds: Thresholds = _DEFAULT_THRESHOLDS,
) -> MergedNode:
    """Combine every source's observation of one node into a single view.

    Field-precedence rules (stated verbatim, since they encode a
    deliberate design decision):

    1. Order the observations by :data:`SOURCE_PRIORITY` (loranet first,
       lorastats second, unknown sources appended in stable input order).
       Call this ``by_priority``.
    2. ``last_seen``: the maximum non-``None`` ``last_seen`` across all
       observations -- most-recent-wins on conflicting timestamps.
       ``last_seen_source`` is the source that supplied that maximum; on
       an exact tie, the higher-priority source (loranet) wins. This is
       the "lorastats corroborates last-seen" requirement.
    3. Telemetry fields (``battery_level``, ``voltage``,
       ``channel_utilization``, ``air_util_tx``, ``neighbor_count``,
       ``uptime_seconds``): the first non-``None`` value in
       ``by_priority`` order, i.e. loranet preferred, lorastats only as
       fallback (loranet is the source that reports
       ``chUtil``/``airUtilTx``/``seenBy``, but omits them frequently).
    4. Identity/descriptive fields (``short_name``, ``long_name``,
       ``hw_model``, ``role``, ``region``, ``firmware_version``,
       ``latitude``, ``longitude``, ``altitude``): the first non-``None``
       value in *recency* order -- observations sorted by their own
       ``last_seen`` descending (``None`` last), ties broken by
       :data:`SOURCE_PRIORITY`. A node that was renamed shows its newest
       name.
    5. ``sources`` = the ``source`` of every observation, in
       :data:`SOURCE_PRIORITY` order.
    6. ``age = now - last_seen`` when ``last_seen`` is set; ``age_text =
       humanize_age(age)``; ``availability = classify_age(age,
       thresholds)``.
    7. ``now`` must be timezone-aware.

    An empty ``observations`` sequence is valid: it returns a
    :class:`MergedNode` with ``sources=()``,
    ``availability=Availability.UNKNOWN``, ``age_text="never"``, and
    ``record`` attached -- this is how "in the database but nobody has
    seen it" is represented.

    Args:
        node_id: The node id being merged.
        observations: Every source's observation of this node (any
            order; each is expected to already carry this ``node_id`` --
            :class:`~meshprovision.datasources.base.DataSource` documents
            the invariant that producers must uphold; not re-checked
            here).
        record: This node's ``Nodes`` sheet row, when it exists in the
            database.
        now: The current time. Must be timezone-aware.
        thresholds: The age boundaries to classify availability against.

    Returns:
        The combined :class:`MergedNode`.

    Raises:
        ValueError: If ``now`` is not timezone-aware.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")

    if not observations:
        return MergedNode(
            node_id=node_id,
            sources=(),
            record=record,
            age_text="never",
            availability=Availability.UNKNOWN,
        )

    by_priority = _order_by_priority(observations)
    by_recency = _order_by_recency(by_priority)

    last_seen, last_seen_source = _pick_last_seen(by_priority)

    battery_level = _first_non_none(by_priority, lambda obs: obs.battery_level)
    voltage = _first_non_none(by_priority, lambda obs: obs.voltage)
    channel_utilization = _first_non_none(by_priority, lambda obs: obs.channel_utilization)
    air_util_tx = _first_non_none(by_priority, lambda obs: obs.air_util_tx)
    neighbor_count = _first_non_none(by_priority, lambda obs: obs.neighbor_count)
    uptime_seconds = _first_non_none(by_priority, lambda obs: obs.uptime_seconds)

    short_name = _first_non_none(by_recency, lambda obs: obs.short_name)
    long_name = _first_non_none(by_recency, lambda obs: obs.long_name)
    hw_model = _first_non_none(by_recency, lambda obs: obs.hw_model)
    role = _first_non_none(by_recency, lambda obs: obs.role)
    region = _first_non_none(by_recency, lambda obs: obs.region)
    firmware_version = _first_non_none(by_recency, lambda obs: obs.firmware_version)
    latitude = _first_non_none(by_recency, lambda obs: obs.latitude)
    longitude = _first_non_none(by_recency, lambda obs: obs.longitude)
    altitude = _first_non_none(by_recency, lambda obs: obs.altitude)

    sources = tuple(obs.source for obs in by_priority)

    age = now - last_seen if last_seen is not None else None
    age_text = humanize_age(age)
    availability = classify_age(age, thresholds)

    return MergedNode(
        node_id=node_id,
        sources=sources,
        record=record,
        short_name=short_name,
        long_name=long_name,
        hw_model=hw_model,
        role=role,
        region=region,
        firmware_version=firmware_version,
        latitude=latitude,
        longitude=longitude,
        altitude=altitude,
        battery_level=battery_level,
        voltage=voltage,
        channel_utilization=channel_utilization,
        air_util_tx=air_util_tx,
        neighbor_count=neighbor_count,
        uptime_seconds=uptime_seconds,
        last_seen=last_seen,
        last_seen_source=last_seen_source,
        age=age,
        age_text=age_text,
        availability=availability,
    )


def _gather_observations(
    observations_by_source: Mapping[str, Mapping[NodeId, NodeObservation]], node_id: NodeId
) -> tuple[NodeObservation, ...]:
    """Collect one node's observations across every source, deterministically.

    Iterates :data:`SOURCE_PRIORITY` first, then any additional source
    names present in ``observations_by_source`` in sorted order -- never
    relying on the caller-supplied mapping's own iteration order, per the
    project's determinism rule.

    Args:
        observations_by_source: Per-source observation maps.
        node_id: The node id to collect observations for.

    Returns:
        Every observation of ``node_id`` found across sources, in
        deterministic source order.
    """
    known = set(SOURCE_PRIORITY)
    extra_sources = sorted(set(observations_by_source) - known)
    ordered_sources = (*SOURCE_PRIORITY, *extra_sources)

    result: list[NodeObservation] = []
    for source in ordered_sources:
        source_map = observations_by_source.get(source)
        if source_map is None:
            continue
        obs = source_map.get(node_id)
        if obs is not None:
            result.append(obs)
    return tuple(result)


def merge_all(
    observations_by_source: Mapping[str, Mapping[NodeId, NodeObservation]],
    *,
    node_ids: Sequence[NodeId],
    records: Mapping[NodeId, NodeRecord] | None = None,
    now: datetime,
    thresholds: Thresholds = _DEFAULT_THRESHOLDS,
) -> tuple[MergedNode, ...]:
    """Merge every node's observations across every source.

    Iterates ``node_ids`` in the caller's own order and never re-sorts
    it -- :mod:`meshprovision.status.report` supplies the database's own
    row order, so an operator's hand-ordering of the spreadsheet survives
    into the rendered report.

    Args:
        observations_by_source: Per-source observation maps, keyed by
            source name (for example ``"loranet"``, ``"lorastats"``).
        node_ids: Every node id to produce a :class:`MergedNode` for, in
            the desired output order.
        records: Each node's ``Nodes`` sheet row, when known.
        now: The current time. Must be timezone-aware.
        thresholds: The age boundaries to classify availability against.

    Returns:
        One :class:`MergedNode` per entry in ``node_ids``, in that same
        order.

    Raises:
        ValueError: If ``now`` is not timezone-aware.
    """
    records_map = records if records is not None else {}
    merged: list[MergedNode] = []
    for node_id in node_ids:
        observations = _gather_observations(observations_by_source, node_id)
        merged.append(
            merge_observations(
                node_id,
                observations,
                record=records_map.get(node_id),
                now=now,
                thresholds=thresholds,
            )
        )
    return tuple(merged)
