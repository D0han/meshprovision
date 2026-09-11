"""The normalized ``NodeObservation`` model and its coercion helpers.

``loranet.py`` and ``lorastats.py`` each map their own source-specific
JSON shape into a single :class:`NodeObservation`, so the merge layer
(``status/merge.py``, a later layer) never has to know which source a
field came from. Every field besides ``node_id``, ``source`` and
``observed_at`` is optional: a source that does not report something
leaves it ``None`` rather than inventing a default.

The module-level coercion helpers (``coerce_*``, ``e7_to_degrees``,
``parse_epoch``, ``parse_iso8601``) exist because both upstream APIs are
loosely typed JSON with observed inconsistencies -- loranet.pl reports
``voltage``/``chUtil``/``temperature`` as *either* ``int`` or ``float``,
and lorastats.pl's ``LastSeen``/``LastBoot`` fields alternate between
offset-aware and naive ISO 8601 strings from the same endpoint within
minutes of each other. Every helper accepts ``object`` and returns
``None`` on anything it cannot confidently coerce, rather than raising --
a malformed field in one node's payload must never fail the whole batch.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Final, TypeVar
from zoneinfo import ZoneInfo

from pydantic import BaseModel, ConfigDict, field_validator

from meshprovision.nodeid import NodeId

__all__ = [
    "E7_SCALE",
    "LORASTATS_NAIVE_TZ",
    "MAX_SEEN_BY_TOPICS",
    "CoercionTracker",
    "NodeObservation",
    "coerce_bool",
    "coerce_float",
    "coerce_int",
    "coerce_str",
    "e7_to_degrees",
    "parse_epoch",
    "parse_iso8601",
]

_T = TypeVar("_T")


class CoercionTracker:
    """Counts ``coerce_*`` calls that received a present-but-unparsable value.

    Distinct from :attr:`~meshprovision.datasources.base.DataSource
    .last_fetch_skipped`, which counts a whole *entry* that failed to
    parse at all: this counts one *field* within an otherwise-parsed
    entry whose raw value was present (not ``None``/absent from the
    payload) but a ``coerce_*`` helper still could not confidently
    coerce it -- an upstream schema rename or a shape change would
    otherwise silently zero out that field fleet-wide with no signal
    anywhere. A source's ``fetch_nodes`` resets and aggregates one
    instance per call, the same "how many did the *last* fetch see,
    not a lifetime total" convention ``last_fetch_skipped`` already
    uses.
    """

    def __init__(self) -> None:
        """Initialize with :attr:`failures` at 0."""
        self.failures = 0

    def coerce(self, raw: object, coerce_fn: Callable[[object], _T | None]) -> _T | None:
        """Coerce ``raw`` via ``coerce_fn``, counting a present-but-failed result.

        Args:
            raw: The raw value read from the payload, before coercion.
            coerce_fn: The ``coerce_*`` helper to apply.

        Returns:
            ``coerce_fn(raw)``.
        """
        result = coerce_fn(raw)
        if raw is not None and result is None:
            self.failures += 1
        return result


E7_SCALE: Final[float] = 1e7
"""Divisor converting a Meshtastic E7 fixed-point coordinate to degrees."""

LORASTATS_NAIVE_TZ: Final[ZoneInfo] = ZoneInfo("Europe/Warsaw")
"""Timezone assumed for a naive (offset-less) lorastats.pl timestamp.

lorastats.pl's own server is in Poland; :func:`parse_iso8601` attaches
this zone to any timestamp that arrives without a UTC offset, then
normalizes the result to UTC. This is a documented assumption, not a
guarantee -- see :func:`parse_iso8601` for the verified evidence that
the same endpoint returns both naive and offset-aware forms.
"""

MAX_SEEN_BY_TOPICS: Final[int] = 32
"""Cap on the number of loranet MQTT gateway topics kept in ``seen_by``."""


class NodeObservation(BaseModel):
    """One normalized observation of a mesh node from a single data source.

    This is the single shape both ``loranet.py`` and ``lorastats.py`` map
    into, and the only shape ``status/merge.py`` (a later layer) ever
    sees. It is immutable and rejects unknown fields, matching the
    project's immutability convention.

    Attributes:
        node_id: The observed node's canonical id.
        source: Which data source produced this observation -- one of
            :data:`meshprovision.datasources.base.SOURCE_LORANET` or
            :data:`meshprovision.datasources.base.SOURCE_LORASTATS`.
        observed_at: Timezone-aware UTC timestamp of when this
            observation was produced (not necessarily when the node
            itself last reported -- see ``last_seen`` for that).
        region_queried: For lorastats only, which region path segment
            produced this observation. ``None`` for loranet, whose dump
            is not region-scoped.
        short_name: The node's short display name.
        long_name: The node's long display name.
        hw_model: Canonical ``HardwareModel`` enum name when resolvable
            against the installed protobufs, otherwise the raw source
            string (a numeric value newer than the installed protobufs
            degrades to its raw string form rather than being dropped).
        hw_model_value: Numeric ``HardwareModel`` value, when resolvable.
        role: Canonical ``Role`` enum name when resolvable, else the raw
            source string.
        role_value: Numeric ``Role`` value, when resolvable.
        region: Canonical LoRa ``RegionCode`` enum name when resolvable,
            else the raw source string.
        modem_preset: The node's configured modem preset name.
        firmware_version: The node's reported firmware version string.
        latitude: Decimal degrees, or ``None`` when the node has not
            reported (or reported exactly ``0, 0``) a position.
        longitude: Decimal degrees, or ``None``.
        altitude: Altitude in meters, when reported.
        position_precision: Position precision bits, when reported.
        battery_level: Battery level percentage, when reported.
        voltage: Battery voltage, when reported.
        channel_utilization: Channel utilization percentage (loranet
            ``chUtil``), when reported.
        air_util_tx: Air utilization for transmit, percentage (loranet
            ``airUtilTx``), when reported.
        temperature: Reported temperature, when available.
        uptime_seconds: Device uptime in seconds, when reported.
        online_local_nodes: Count of other nodes seen locally online, when
            reported.
        has_default_channel: Whether the node still uses the default
            channel, when reported.
        neighbor_count: Number of distinct MQTT gateway topics that have
            relayed this node (loranet ``len(seenBy)``), when known.
        seen_by: The (sorted, capped at :data:`MAX_SEEN_BY_TOPICS`) MQTT
            gateway topics that have relayed this node.
        last_seen: Timezone-aware UTC timestamp of the node's most recent
            activity, when known.
        last_boot: Timezone-aware UTC timestamp of the node's most recent
            boot, when known.
        last_device_metrics: Timezone-aware UTC timestamp of the node's
            most recent device-metrics report, when known.
        last_map_report: Timezone-aware UTC timestamp of the node's most
            recent map report, when known.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    node_id: NodeId
    source: str
    observed_at: datetime
    region_queried: str | None = None

    short_name: str | None = None
    long_name: str | None = None
    hw_model: str | None = None
    hw_model_value: int | None = None
    role: str | None = None
    role_value: int | None = None
    region: str | None = None
    modem_preset: str | None = None
    firmware_version: str | None = None

    latitude: float | None = None
    longitude: float | None = None
    altitude: int | None = None
    position_precision: int | None = None

    battery_level: int | None = None
    voltage: float | None = None
    channel_utilization: float | None = None
    air_util_tx: float | None = None
    temperature: float | None = None
    uptime_seconds: int | None = None
    online_local_nodes: int | None = None
    has_default_channel: bool | None = None

    neighbor_count: int | None = None
    seen_by: tuple[str, ...] = ()
    last_seen: datetime | None = None
    last_boot: datetime | None = None
    last_device_metrics: datetime | None = None
    last_map_report: datetime | None = None

    @field_validator("node_id", mode="before")
    @classmethod
    def _coerce_node_id(cls, value: object) -> NodeId:
        """Coerce ``node_id`` via :meth:`NodeId.parse`.

        Args:
            value: A :class:`NodeId` already, or any value
                :meth:`NodeId.parse` accepts.

        Returns:
            The corresponding :class:`NodeId`.

        Raises:
            meshprovision.errors.NodeIdError: If ``value`` cannot be
                parsed. Propagates directly rather than being wrapped in
                a pydantic ``ValidationError``, since it is already a
                :class:`~meshprovision.errors.MeshprovisionError`
                subclass callers can catch specifically.
        """
        return NodeId.parse(value)  # type: ignore[arg-type]

    @field_validator(
        "observed_at",
        "last_seen",
        "last_boot",
        "last_device_metrics",
        "last_map_report",
        mode="after",
    )
    @classmethod
    def _require_timezone_aware(cls, value: datetime | None) -> datetime | None:
        """Reject a naive datetime on any timestamp field.

        Args:
            value: The already-type-validated datetime, or ``None``.

        Returns:
            ``value`` unchanged.

        Raises:
            ValueError: If ``value`` is a datetime with no ``tzinfo``.
        """
        if value is not None and value.tzinfo is None:
            raise ValueError("datetime fields must be timezone-aware")
        return value

    def age(self, *, now: datetime | None = None) -> timedelta | None:
        """Return how long ago this node was last seen.

        Args:
            now: The current time. Defaults to ``datetime.now(tz=UTC)``.

        Returns:
            ``now - last_seen``, or ``None`` when ``last_seen`` is unknown.
        """
        if self.last_seen is None:
            return None
        current = now if now is not None else datetime.now(tz=UTC)
        return current - self.last_seen


def e7_to_degrees(value: object, *, limit: float) -> float | None:
    """Convert a Meshtastic E7 fixed-point coordinate to decimal degrees.

    Args:
        value: The raw E7 integer/float value (for example loranet's
            ``latitude``/``longitude`` fields). ``bool`` is rejected even
            though it is technically an ``int`` subtype.
        limit: The maximum valid magnitude of the *converted* degree
            value (``90.0`` for latitude, ``180.0`` for longitude).

    Returns:
        ``value / 1e7``, or ``None`` when ``value`` is not a plain
        ``int``/``float``, or the converted result is outside
        ``[-limit, limit]`` or not finite.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    degrees = value / E7_SCALE
    if not math.isfinite(degrees):
        return None
    if not (-limit <= degrees <= limit):
        return None
    return degrees


def parse_epoch(value: object) -> datetime | None:
    """Convert a unix epoch seconds value to a timezone-aware UTC datetime.

    Args:
        value: The raw epoch value. ``bool`` is rejected even though it
            is technically an ``int`` subtype; non-positive values are
            rejected (Meshtastic/loranet epoch fields are never
            meaningfully zero or negative).

    Returns:
        The corresponding UTC datetime, or ``None`` when ``value`` is not
        a plain ``int``/``float``, is not positive, or is out of range
        for :meth:`datetime.fromtimestamp`.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def parse_iso8601(value: object, *, assume_tz: tzinfo = LORASTATS_NAIVE_TZ) -> datetime | None:
    """Parse an ISO 8601 string, assuming a timezone when none is given.

    lorastats.pl's ``LastSeen``/``LastBoot`` fields have been verified to
    alternate between naive and offset-aware forms from the same
    endpoint within minutes of each other -- for example
    ``"2026-08-25T03:14:10"`` (naive) and
    ``"2026-08-25T03:23:11+02:00"`` (offset-aware). **A naive value is
    interpreted as ``assume_tz`` (Europe/Warsaw, lorastats.pl's own local
    timezone by default), then normalized to UTC.** This is a documented
    assumption about lorastats.pl's local clock, not a protocol
    guarantee.

    Args:
        value: The raw timestamp string.
        assume_tz: Timezone to attach to a naive parse result before
            converting to UTC. Defaults to :data:`LORASTATS_NAIVE_TZ`.

    Returns:
        A timezone-aware UTC datetime, or ``None`` when ``value`` is not
        a ``str`` or does not parse as ISO 8601.
    """
    if not isinstance(value, str):
        return None
    token = value.strip()
    if not token:
        return None
    if token.endswith("Z"):
        token = f"{token[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(token)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=assume_tz)
    return parsed.astimezone(UTC)


def coerce_float(value: object) -> float | None:
    """Coerce a loosely-typed JSON value to a finite ``float``.

    Accepts a plain ``int``/``float`` (rejecting ``bool``) or a numeric
    ``str``. Exists because loranet.pl reports ``voltage``, ``chUtil``,
    and ``temperature`` as *either* ``int`` or ``float``.

    Args:
        value: The raw value.

    Returns:
        The coerced ``float``, or ``None`` when ``value`` cannot be
        confidently coerced or the result is not finite.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        result = float(value)
        return result if math.isfinite(result) else None
    if isinstance(value, str):
        token = value.strip()
        if not token:
            return None
        try:
            result = float(token)
        except ValueError:
            return None
        return result if math.isfinite(result) else None
    return None


def coerce_int(value: object) -> int | None:
    """Coerce a loosely-typed JSON value to an ``int``.

    Accepts a plain ``int`` (rejecting ``bool``) or an all-ASCII-digit
    ``str``.

    Args:
        value: The raw value.

    Returns:
        The coerced ``int``, or ``None`` when ``value`` cannot be
        confidently coerced.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        token = value.strip()
        if token.isascii() and token.isdigit():
            return int(token)
        return None
    return None


def coerce_bool(value: object) -> bool | None:
    """Coerce a loosely-typed JSON value to a ``bool``.

    Accepts a plain ``bool`` unchanged, ``0``/``1`` (rejecting other
    ints), and the case-insensitive strings ``"true"``/``"false"``.

    Args:
        value: The raw value.

    Returns:
        The coerced ``bool``, or ``None`` when ``value`` cannot be
        confidently coerced.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if value == 1:
            return True
        if value == 0:
            return False
        return None
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
        return None
    return None


def coerce_str(value: object) -> str | None:
    """Coerce a loosely-typed JSON value to a non-blank ``str``.

    Args:
        value: The raw value.

    Returns:
        ``value`` stripped, or ``None`` when ``value`` is not a ``str``
        or is blank after stripping.
    """
    if isinstance(value, str):
        token = value.strip()
        return token or None
    return None
