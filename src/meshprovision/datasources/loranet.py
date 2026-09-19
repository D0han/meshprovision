"""``LoranetSource``: the loranet.pl ``nodes.json`` dump as a ``DataSource``.

https://loranet.pl/nodes.json is a single JSON **object** keyed by decimal
node id (verified: 13,134 entries, 12.7 MB at design time -- not a list),
holding a snapshot of every node loranet.pl has heard. This module fetches
it once per process (memoized on the instance, and cached on disk by the
injected :class:`~meshprovision.cache.http.CachedHTTPClient` -- the cache
layer is load-bearing here, not a nicety), indexes it by decimal id, and
maps each entry into a normalized
:class:`~meshprovision.datasources.models.NodeObservation`.
"""

from __future__ import annotations

import logging
from collections.abc import Collection, Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

from pydantic import ValidationError

from meshprovision.datasources.base import SOURCE_LORANET, BaseHTTPDataSource, require_json_object
from meshprovision.datasources.models import (
    MAX_SEEN_BY_TOPICS,
    CoercionTracker,
    NodeObservation,
    coerce_bool,
    coerce_float,
    coerce_int,
    coerce_str,
    e7_to_degrees,
    parse_epoch,
)
from meshprovision.enums import EnumTable, hw_model_table, region_table, role_table
from meshprovision.errors import EnumMappingError, NodeIdError
from meshprovision.nodeid import NodeId

if TYPE_CHECKING:
    from meshprovision.cache.http import CachedHTTPClient

__all__ = ["LORANET_NODES_URL", "LoranetSource", "parse_node"]

_logger = logging.getLogger(__name__)

LORANET_NODES_URL: Final[str] = "https://loranet.pl/nodes.json"
"""The loranet.pl node dump endpoint."""

_LATITUDE_LIMIT: Final[float] = 90.0
_LONGITUDE_LIMIT: Final[float] = 180.0

_PARSE_NODE_EXCEPTIONS: Final[tuple[type[Exception], ...]] = (
    ValueError,
    TypeError,
    KeyError,
    NodeIdError,
    EnumMappingError,
    ValidationError,
)
"""Exception types :meth:`LoranetSource.fetch_all`/``fetch_nodes`` tolerate
per malformed entry, logging and skipping rather than failing the whole
13k-entry batch for one bad node."""


class LoranetSource(BaseHTTPDataSource):
    """Data source backed by loranet.pl's bulk ``nodes.json`` dump.

    Unlike lorastats, loranet has no per-node query endpoint: every fetch
    (of even a single node) requires the full ~12.7 MB dump, so this
    class fetches it once and memoizes the decoded index on the instance.
    :meth:`invalidate` drops that in-memory memo (not the on-disk HTTP
    cache); pass ``force_refresh=True`` to bypass both.
    """

    def __init__(self, client: CachedHTTPClient, *, url: str = LORANET_NODES_URL) -> None:
        """Initialize the source.

        Args:
            client: The cache-backed HTTP client to fetch through.
            url: The node dump URL. Overridable for tests.
        """
        super().__init__(client, source_name=SOURCE_LORANET)
        self._url = url
        self._index: Mapping[str, Any] | None = None
        self._index_fetched_at: float | None = None

    @property
    def url(self) -> str:
        """The node dump URL this source fetches from.

        Returns:
            The configured URL.
        """
        return self._url

    def raw_index(self, *, force_refresh: bool | None = None) -> Mapping[str, Any]:
        """Return the decoded dump, fetching (and memoizing) it if needed.

        Args:
            force_refresh: When true, bypasses both the in-memory memo
                and the on-disk HTTP cache read (the fetched response is
                still written back to the on-disk cache either way).

        Returns:
            The decoded dump: an object keyed by decimal node id string.

        Raises:
            meshprovision.errors.InvalidResponseError: If the response
                does not parse as JSON, or parses as something other
                than a JSON object.
            meshprovision.errors.HttpError: If the request itself fails.
        """
        if self._index is not None and not force_refresh:
            # The in-memory memo means get_json() -- and so
            # last_fetch_data_as_of -- is never touched on this path;
            # re-apply the fetch time captured when the memo was built so
            # a caller (via fetch_all/fetch_nodes) still learns when this
            # data actually came off the wire, not "no HTTP request was
            # made" (None).
            self._last_fetch_data_as_of = self._index_fetched_at
            return self._index
        payload = self.get_json(self._url, force_refresh=force_refresh)
        index = require_json_object(payload, url=self._url, source=self.name)
        self._index = index
        self._index_fetched_at = self._last_fetch_data_as_of
        return index

    def invalidate(self) -> None:
        """Drop the in-memory memoized index (not the on-disk HTTP cache).

        The next call to :meth:`raw_index`, :meth:`fetch_all`, or
        :meth:`fetch_nodes` will re-decode from a fresh (or still-cached,
        depending on TTL) HTTP response.
        """
        self._index = None
        self._index_fetched_at = None

    def fetch_all(self, *, force_refresh: bool | None = None) -> dict[NodeId, NodeObservation]:
        """Parse every entry in the dump into a normalized observation.

        A single malformed key or entry is logged and skipped rather than
        failing the whole 13k-entry batch; :attr:`last_fetch_skipped` is
        set to how many were skipped by this call.
        :attr:`last_fetch_data_as_of` is set to when the dump itself was
        fetched (see :meth:`raw_index`), whether that was a fresh
        request or the in-process memo.

        Args:
            force_refresh: Forwarded to :meth:`raw_index`.

        Returns:
            A mapping from every successfully parsed node id to its
            observation.
        """
        self._begin_fetch()
        index = self.raw_index(force_refresh=force_refresh)
        observed_at = datetime.now(tz=UTC)
        result: dict[NodeId, NodeObservation] = {}
        skipped = 0
        tracker = CoercionTracker()
        for key, payload in index.items():
            node_id = self._parse_key(key)
            if node_id is None:
                skipped += 1
                continue
            observation = self._parse_entry(
                node_id, key, payload, observed_at=observed_at, coercion_tracker=tracker
            )
            if observation is None:
                skipped += 1
                continue
            result[node_id] = observation
        self._last_fetch_skipped = skipped
        self._last_fetch_field_coercions = tracker.failures
        return result

    def fetch_nodes(
        self, ids: Collection[NodeId], *, force_refresh: bool | None = None
    ) -> dict[NodeId, NodeObservation]:
        """Fetch normalized observations for the given node ids.

        Fetches the dump once (memoized) regardless of how many ids are
        requested, then looks each one up by its decimal form. An id
        absent from the dump -- its key is not in the index at all -- is
        simply omitted from the result -- never an error, and never
        counted in :attr:`last_fetch_skipped`. A key that *is* present
        but maps to a JSON ``null`` is a different case: the entry was
        there and failed to parse, so it is counted the same as any
        other malformed entry (see :meth:`_parse_entry`, which rejects
        anything that isn't a JSON object -- ``None`` included).
        :attr:`last_fetch_skipped` is set to the number of *requested*
        ids whose entry was present but failed to parse.
        :attr:`last_fetch_data_as_of` is set to when the dump itself was
        fetched (see :meth:`raw_index`), whether that was a fresh
        request or the in-process memo.

        Args:
            ids: The node ids to look up.
            force_refresh: Forwarded to :meth:`raw_index`.

        Returns:
            A mapping from every requested id that was found (and parsed
            successfully) to its observation.
        """
        self._begin_fetch()
        index = self.raw_index(force_refresh=force_refresh)
        observed_at = datetime.now(tz=UTC)
        result: dict[NodeId, NodeObservation] = {}
        skipped = 0
        tracker = CoercionTracker()
        for node_id in ids:
            key = node_id.decimal
            if key not in index:
                continue
            observation = self._parse_entry(
                node_id, key, index[key], observed_at=observed_at, coercion_tracker=tracker
            )
            if observation is None:
                skipped += 1
                continue
            result[node_id] = observation
        self._last_fetch_skipped = skipped
        self._last_fetch_field_coercions = tracker.failures
        return result

    @staticmethod
    def _parse_key(key: str) -> NodeId | None:
        """Parse a dump's decimal-string key into a :class:`NodeId`.

        Uses the explicit :meth:`NodeId.from_decimal` constructor, never
        the ``parse`` heuristic -- an 8-digit decimal key would otherwise
        be misread as hex.

        Args:
            key: The raw JSON object key.

        Returns:
            The parsed :class:`NodeId`, or ``None`` (logged at DEBUG) if
            ``key`` is not a valid decimal node id.
        """
        try:
            return NodeId.from_decimal(key)
        except NodeIdError:
            _logger.debug("skipping loranet entry with unparsable decimal key %r", key)
            return None

    @staticmethod
    def _parse_entry(
        node_id: NodeId,
        key: str,
        payload: object,
        *,
        observed_at: datetime,
        coercion_tracker: CoercionTracker,
    ) -> NodeObservation | None:
        """Parse one dump entry, tolerating a malformed payload.

        Args:
            node_id: The already-parsed id for this entry.
            key: The raw dump key, for logging.
            payload: The raw per-node payload; expected to be a JSON
                object.
            observed_at: Timestamp to stamp the observation with.
            coercion_tracker: Forwarded to :func:`parse_node`, shared
                across every entry in one fetch.

        Returns:
            The parsed observation, or ``None`` (logged at WARNING) when
            ``payload`` is not an object or fails to parse.
        """
        if not isinstance(payload, dict):
            _logger.warning("skipping loranet node %s: payload is not a JSON object", key)
            return None
        try:
            return parse_node(
                node_id, payload, observed_at=observed_at, coercion_tracker=coercion_tracker
            )
        except _PARSE_NODE_EXCEPTIONS as exc:
            _logger.warning("skipping loranet node %s: %s", key, exc)
            return None


def _typed_enum_raw(raw: object) -> str | int | None:
    """Return ``raw`` unchanged when it's a valid enum-lookup shape, else ``None``.

    A thin coercion-shaped wrapper around the type guard
    :func:`_resolve_enum_name`/:func:`_resolve_enum_value` already apply,
    so a single :class:`~meshprovision.datasources.models.CoercionTracker`
    call can cover both derived outputs (name and numeric value) for one
    raw payload field without double-counting.

    Args:
        raw: The raw payload value; expected ``str``/``int``, possibly
            absent.

    Returns:
        ``raw`` unchanged when it is a non-bool ``str``/``int``;
        ``None`` otherwise.
    """
    if raw is None or isinstance(raw, bool) or not isinstance(raw, str | int):
        return None
    return raw


def _resolve_enum_name(table: EnumTable, raw: object) -> str | None:
    """Resolve a loranet enum-like field to a canonical name, or the raw string.

    loranet.pl reports ``role``/``hwModel``/``region`` as protobuf names
    most of the time, but sometimes as stringified integers when loranet
    itself could not map them. ``try_name`` (never ``to_name``) is used
    so a value newer than the installed protobufs degrades to the raw
    string instead of raising.

    Args:
        table: The enum table to resolve against.
        raw: The raw payload value; expected ``str``/``int``, possibly
            absent.

    Returns:
        The canonical name when resolvable; ``str(raw)`` when ``raw`` is
        present but unresolvable; ``None`` when ``raw`` is absent or of
        an unsupported type.
    """
    if raw is None or isinstance(raw, bool) or not isinstance(raw, str | int):
        return None
    name = table.try_name(raw)
    return name if name is not None else str(raw)


def _resolve_enum_value(table: EnumTable, raw: object) -> int | None:
    """Resolve a loranet enum-like field to its numeric value, when known.

    Args:
        table: The enum table to resolve against.
        raw: The raw payload value; expected ``str``/``int``, possibly
            absent.

    Returns:
        The numeric value when resolvable; ``None`` otherwise (including
        when ``raw`` names a value newer than the installed protobufs).
    """
    if raw is None or isinstance(raw, bool) or not isinstance(raw, str | int):
        return None
    return table.try_value(raw)


def _parse_seen_by(raw: object) -> tuple[int | None, tuple[str, ...], datetime | None]:
    """Derive ``neighbor_count``, ``seen_by``, and ``last_seen`` from ``seenBy``.

    Args:
        raw: The raw ``seenBy`` field; expected to be a JSON object
            mapping MQTT gateway topic to unix epoch seconds.

    Returns:
        A ``(neighbor_count, seen_by, last_seen)`` tuple. All three stay
        ``(None, (), None)`` when ``raw`` is not a ``dict``.
    """
    if not isinstance(raw, dict):
        return None, (), None
    neighbor_count = len(raw)
    seen_by = tuple(sorted(str(topic) for topic in raw))[:MAX_SEEN_BY_TOPICS]
    epochs = [v for v in raw.values() if isinstance(v, int) and not isinstance(v, bool)]
    last_seen = parse_epoch(max(epochs)) if epochs else None
    return neighbor_count, seen_by, last_seen


def parse_node(
    node_id: NodeId,
    payload: Mapping[str, Any],
    *,
    observed_at: datetime,
    coercion_tracker: CoercionTracker | None = None,
) -> NodeObservation:
    """Map one loranet.pl ``nodes.json`` entry to a :class:`NodeObservation`.

    Args:
        node_id: The already-parsed id for this entry (from the dump's
            decimal key).
        payload: The per-node JSON object.
        observed_at: Timestamp to stamp the observation with.
        coercion_tracker: Accumulates a count of fields present in
            ``payload`` but not confidently coercible (see
            :class:`~meshprovision.datasources.models.CoercionTracker`).
            Defaults to a throwaway tracker when not given -- callers
            that want the count share one instance across every entry
            in a fetch.

    Returns:
        The normalized observation.

    Raises:
        ValueError: If a field's value is malformed in a way its
            coercion helper does not tolerate.
        TypeError: Likewise.
        pydantic.ValidationError: If the assembled fields fail
            :class:`NodeObservation`'s own validation.
    """
    tracker = coercion_tracker if coercion_tracker is not None else CoercionTracker()
    latitude = tracker.coerce(
        payload.get("latitude"), lambda raw: e7_to_degrees(raw, limit=_LATITUDE_LIMIT)
    )
    longitude = tracker.coerce(
        payload.get("longitude"), lambda raw: e7_to_degrees(raw, limit=_LONGITUDE_LIMIT)
    )
    if latitude == 0.0 and longitude == 0.0:
        # An unpositioned node reports (0, 0), not the Gulf of Guinea.
        latitude = None
        longitude = None

    neighbor_count, seen_by, seen_by_last_seen = _parse_seen_by(payload.get("seenBy"))
    last_device_metrics = tracker.coerce(payload.get("lastDeviceMetrics"), parse_epoch)
    last_map_report = tracker.coerce(payload.get("lastMapReport"), parse_epoch)
    # last_seen is documented as "the node's most recent activity," not
    # "the most recent seenBy relay" -- a device-metrics or map report is
    # just as much activity as being relayed by an MQTT gateway topic, and
    # ignoring them can report a node STALE/OFFLINE minutes after it was
    # genuinely active. last_boot is deliberately excluded: it's a
    # different signal (when the node last rebooted, not when it was last
    # seen) and lorastats' own last_boot is never folded into its last_seen
    # either.
    last_seen = max(
        (ts for ts in (seen_by_last_seen, last_device_metrics, last_map_report) if ts is not None),
        default=None,
    )

    raw_hw_model = tracker.coerce(payload.get("hwModel"), _typed_enum_raw)
    raw_role = tracker.coerce(payload.get("role"), _typed_enum_raw)
    raw_region = tracker.coerce(payload.get("region"), _typed_enum_raw)

    return NodeObservation(
        node_id=node_id,
        source=SOURCE_LORANET,
        observed_at=observed_at,
        short_name=tracker.coerce(payload.get("shortName"), coerce_str),
        long_name=tracker.coerce(payload.get("longName"), coerce_str),
        hw_model=_resolve_enum_name(hw_model_table(), raw_hw_model),
        hw_model_value=_resolve_enum_value(hw_model_table(), raw_hw_model),
        role=_resolve_enum_name(role_table(), raw_role),
        role_value=_resolve_enum_value(role_table(), raw_role),
        region=_resolve_enum_name(region_table(), raw_region),
        modem_preset=tracker.coerce(payload.get("modemPreset"), coerce_str),
        firmware_version=tracker.coerce(payload.get("fwVersion"), coerce_str),
        latitude=latitude,
        longitude=longitude,
        altitude=tracker.coerce(payload.get("altitude"), coerce_int),
        position_precision=tracker.coerce(payload.get("precision"), coerce_int),
        battery_level=tracker.coerce(payload.get("batteryLevel"), coerce_int),
        voltage=tracker.coerce(payload.get("voltage"), coerce_float),
        channel_utilization=tracker.coerce(payload.get("chUtil"), coerce_float),
        air_util_tx=tracker.coerce(payload.get("airUtilTx"), coerce_float),
        temperature=tracker.coerce(payload.get("temperature"), coerce_float),
        uptime_seconds=tracker.coerce(payload.get("uptime"), coerce_int),
        online_local_nodes=tracker.coerce(payload.get("onlineLocalNodes"), coerce_int),
        has_default_channel=tracker.coerce(payload.get("hasDefaultCh"), coerce_bool),
        neighbor_count=neighbor_count,
        seen_by=seen_by,
        last_seen=last_seen,
        last_device_metrics=last_device_metrics,
        last_map_report=last_map_report,
    )
