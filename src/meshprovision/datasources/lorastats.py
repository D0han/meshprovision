"""``LorastatsSource``: per-node ``?node=<hex>`` queries against lorastats.pl.

Unlike loranet.pl's single bulk dump, lorastats.pl's ``/API/{region}/Nodes/
JSON`` endpoint supports server-side filtering via a ``?node=<hex>`` query
parameter -- verified to shrink a ~1.84 MB bulk region dump down to a
~150-byte filtered response. This module therefore queries per node
rather than pulling region dumps, and deliberately exposes no bulk-dump
method at all: lorastats.pl's terms treat bulk scraping as grounds for an
IP ban, so the absence is the safeguard.

Two behaviors verified live and worth restating here because they drive
this module's design:

- ``?node=`` requires **bare lowercase hex**; uppercase or a ``!``-prefix
  both silently return ``[]``. Always pass ``node_id.hex``.
- An unknown node returns ``[]`` with **HTTP 200** -- not an error.

The region path segment is documented by lorastats.pl itself, but is
**not validated server-side**: an invalid region still returns HTTP 200
with real data for a valid node (a silent soft-fallback). This module can
therefore only validate a region's *local* shape (see
:func:`validate_regions`); it cannot detect a mistyped region, and there
is deliberately no discovery endpoint to fall back on -- lorastats.pl
bans IPs for scraping its HTML site, and no JSON region-list endpoint
exists.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Collection, Mapping, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

from meshprovision.datasources.base import SOURCE_LORASTATS, BaseHTTPDataSource, require_json_list
from meshprovision.datasources.models import (
    CoercionTracker,
    NodeObservation,
    coerce_int,
    coerce_str,
    parse_iso8601,
)
from meshprovision.enums import hw_model_table, role_table
from meshprovision.errors import HttpError, MissingContactError, NodeIdError, SettingsError
from meshprovision.nodeid import NodeId, NodeIdLike

if TYPE_CHECKING:
    from meshprovision.cache.http import CachedHTTPClient

__all__ = [
    "DEFAULT_REGIONS",
    "LORASTATS_BASE_URL",
    "LORASTATS_NODES_PATH",
    "LORASTATS_STATUS_PATH",
    "REGION_PATTERN",
    "LorastatsSource",
    "parse_node",
    "validate_regions",
]

_logger = logging.getLogger(__name__)

LORASTATS_BASE_URL: Final[str] = "https://lorastats.pl"
"""Base URL of the lorastats.pl API."""

LORASTATS_NODES_PATH: Final[str] = "/API/{region}/Nodes/JSON"
"""Region-scoped nodes endpoint, filterable by the ``node`` query param."""

LORASTATS_STATUS_PATH: Final[str] = "/Node/{node}/Status"
"""The node health-check endpoint. Verified NOT under ``/API`` and NOT
region-scoped: ``/API/PL/Node/<id>/Status`` is a 404; the bare
``/Node/<id>/Status`` form returns HTTP 200 ``text/plain`` for a healthy
node and HTTP 404 for an unknown one."""

DEFAULT_REGIONS: Final[tuple[str, ...]] = ("PL",)
"""Default, config-overridable region list (finding #3: no JSON region-list
endpoint exists, and scraping the HTML site is an IP-bannable offense)."""

REGION_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
"""Shape a region path segment must match. This is a *local* sanity check
only -- lorastats.pl does not validate the region segment server-side, so
this pattern can catch a malformed value but can never catch a
mistyped-but-well-formed one."""

_HTTP_NOT_FOUND: Final[int] = 404
_HTTP_SERVER_ERROR: Final[int] = 500


class LorastatsSource(BaseHTTPDataSource):
    """Data source backed by lorastats.pl's per-node ``Nodes/JSON`` endpoint."""

    def __init__(
        self,
        client: CachedHTTPClient,
        *,
        contact: str,
        regions: Sequence[str] = DEFAULT_REGIONS,
        base_url: str = LORASTATS_BASE_URL,
    ) -> None:
        """Initialize the source.

        This constructor is the explicit startup gate the project
        requires: no lorastats.pl request can ever be issued without an
        identifying contact string, even though the injected ``client``
        is also expected to already carry ``contact`` in its own
        ``User-Agent`` (built by
        :meth:`meshprovision.config.settings.Settings.user_agent`, which
        raises the same error when unset). There is deliberately no
        default value for ``contact``.

        Args:
            client: The cache-backed HTTP client to fetch through.
            contact: The operator's contact string. Only checked for
                non-blankness here; the actual ``User-Agent`` sent on
                every request is owned by ``client``.
            regions: The static, config-overridable region list to query
                when a call does not specify one explicitly. Validated
                via :func:`validate_regions`.
            base_url: The lorastats.pl base URL. Overridable for tests.

        Raises:
            meshprovision.errors.MissingContactError: If ``contact`` is
                empty or whitespace-only.
            meshprovision.errors.SettingsError: If ``regions`` is empty,
                contains only blank entries, or contains an entry that
                does not match :data:`REGION_PATTERN`.
        """
        if not contact.strip():
            raise MissingContactError()
        super().__init__(client, source_name=SOURCE_LORASTATS)
        self._base_url = base_url.rstrip("/")
        self._regions = validate_regions(regions)

    @property
    def regions(self) -> tuple[str, ...]:
        """The validated, de-duplicated region list this source queries by default.

        Returns:
            The configured regions, in the order they were given.
        """
        return self._regions

    @property
    def base_url(self) -> str:
        """The lorastats.pl base URL this source queries.

        Returns:
            The configured base URL, with any trailing slash stripped.
        """
        return self._base_url

    def fetch_nodes(
        self, ids: Collection[NodeId], *, force_refresh: bool | None = None
    ) -> dict[NodeId, NodeObservation]:
        """Fetch normalized observations for the given node ids.

        Issues one per-node request per id (the whole point of the
        server-side ``?node=`` filter -- see the module docstring), never
        a region bulk dump. Resets :attr:`last_fetch_skipped`,
        :attr:`last_fetch_field_coercions`, and :attr:`last_fetch_data_as_of`,
        and folds each :meth:`fetch_node` call's contribution into them
        (the oldest fetch time across every id, for the latter).

        Args:
            ids: The node ids to look up.
            force_refresh: Forwarded to each :meth:`fetch_node` call.

        Returns:
            A mapping from every requested id that was found in at least
            one configured region to its observation.
        """
        result: dict[NodeId, NodeObservation] = {}
        skipped = 0
        field_coercions = 0
        data_as_of: datetime | None = None
        for node_id in ids:
            observation = self.fetch_node(node_id, force_refresh=force_refresh)
            skipped += self._last_fetch_skipped
            field_coercions += self._last_fetch_field_coercions
            # fetch_node() calls _begin_fetch() itself, so
            # self.last_fetch_data_as_of here reflects only *this* id's
            # request(s) -- aggregate the oldest across the loop the same
            # way skipped/field_coercions are already summed above.
            node_data_as_of = self.last_fetch_data_as_of
            if node_data_as_of is not None and (data_as_of is None or node_data_as_of < data_as_of):
                data_as_of = node_data_as_of
            if observation is not None:
                result[node_id] = observation
        self._last_fetch_skipped = skipped
        self._last_fetch_field_coercions = field_coercions
        self._last_fetch_data_as_of = data_as_of.timestamp() if data_as_of is not None else None
        return result

    def fetch_node(
        self,
        node_id: NodeIdLike,
        *,
        region: str | None = None,
        force_refresh: bool | None = None,
    ) -> NodeObservation | None:
        """Fetch one node's observation, trying each configured region in turn.

        Args:
            node_id: The node id to look up, in any form
                :meth:`NodeId.parse` accepts.
            region: A single region to query instead of
                :attr:`regions`. Does not need to already be validated
                (this call validates it before use).
            force_refresh: Whether to bypass the HTTP cache read for
                this call.

        Returns:
            The observation, or ``None`` when the node was not found in
            any candidate region (a legitimate, non-error outcome:
            lorastats.pl returns ``[]`` with HTTP 200 for an unknown
            node). Also sets :attr:`last_fetch_skipped` to the number of
            candidate records across every queried region that could not
            even be inspected for a match (see :func:`_match_record`) --
            never counting a record that simply belonged to a different
            node, only one this call could not parse at all. Resets and
            sets :attr:`last_fetch_data_as_of` to the oldest fetch time
            across every request this call made (via :meth:`_begin_fetch`
            and :meth:`~meshprovision.datasources.base.BaseHTTPDataSource
            .get_json`).

        Raises:
            meshprovision.errors.NodeIdError: If ``node_id`` cannot be
                parsed.
            meshprovision.errors.SettingsError: If ``region`` is given
                and does not match :data:`REGION_PATTERN`.
            meshprovision.errors.InvalidResponseError: If a response
                body does not parse as a JSON array.
            meshprovision.errors.HttpError: If a request itself fails.
        """
        self._begin_fetch()
        nid = NodeId.parse(node_id)
        candidates = validate_regions((region,)) if region is not None else self._regions
        skipped = 0
        tracker = CoercionTracker()

        for candidate in candidates:
            url = f"{self._base_url}{LORASTATS_NODES_PATH.format(region=candidate)}"
            payload = self.get_json(url, params={"node": nid.hex}, force_refresh=force_refresh)
            records = require_json_list(payload, url=url, source=self.name)
            if not records:
                continue
            record, record_skipped = _match_record(records, nid)
            skipped += record_skipped
            if record is None:
                continue
            observation = parse_node(
                record, region=candidate, observed_at=datetime.now(tz=UTC), coercion_tracker=tracker
            )
            if observation is None:
                continue
            if observation.node_id != nid:
                _logger.warning(
                    "lorastats returned a record for %s in response to a query for %s; ignoring",
                    observation.node_id.hex,
                    nid.hex,
                )
                continue
            self._last_fetch_skipped = skipped
            self._last_fetch_field_coercions = tracker.failures
            return observation
        self._last_fetch_skipped = skipped
        self._last_fetch_field_coercions = tracker.failures
        return None

    def node_status(self, node_id: NodeIdLike, *, force_refresh: bool | None = None) -> bool | None:
        """Check a node's health via the ``/Node/{id}/Status`` endpoint.

        Opt-in and off by default: this endpoint returns ``text/plain``,
        not JSON, so it bypasses :meth:`get_json` entirely and inspects
        only whether the request raised. Because
        :class:`~meshprovision.cache.http.CachedHTTPClient` retries a
        5xx response
        :data:`~meshprovision.cache.http.DEFAULT_MAX_RETRIES` times
        before raising, checking an unhealthy node costs several
        requests -- callers on a budget should call this sparingly.

        Args:
            node_id: The node id to check, in any form
                :meth:`NodeId.parse` accepts.
            force_refresh: Whether to bypass the HTTP cache read.

        Returns:
            ``True`` when the endpoint returns HTTP 200 (healthy),
            ``False`` when it returns HTTP 500 (unhealthy, per
            lorastats.pl's own documented contract), or ``None`` when it
            returns HTTP 404 (unknown node).

        Raises:
            meshprovision.errors.NodeIdError: If ``node_id`` cannot be
                parsed.
            meshprovision.errors.HttpError: If the request fails with
                any other status code, or for a non-HTTP reason.
        """
        nid = NodeId.parse(node_id)
        url = f"{self._base_url}{LORASTATS_STATUS_PATH.format(node=nid.hex)}"
        try:
            self._client.get(url, source=self.name, force_refresh=force_refresh)
        except HttpError as exc:
            if exc.status_code == _HTTP_NOT_FOUND:
                return None
            if exc.status_code == _HTTP_SERVER_ERROR:
                return False
            raise
        return True


def _match_record(records: list[Any], nid: NodeId) -> tuple[Mapping[str, Any] | None, int]:
    """Pick the record whose ``NodeId`` matches ``nid``.

    Args:
        records: The decoded JSON array from a ``Nodes/JSON`` response.
        nid: The id being looked up.

    Returns:
        A ``(record, skipped)`` pair. ``record`` is the exactly-matching
        record, or ``None`` when no record's ``NodeId`` parses to ``nid``
        (logged at DEBUG). A record for a *different* node is never
        returned: filing another node's telemetry under the requested id
        is worse than reporting the node as not found. ``skipped`` counts
        candidate records that could not even be inspected for a match
        (not a dict, missing/unparsable ``NodeId``) -- distinct from a
        record that was inspected and simply belonged to a different
        node, which is the expected, non-error case for every response
        with more than one node in it.
    """
    skipped = 0
    for record in records:
        if not isinstance(record, dict):
            skipped += 1
            continue
        raw = record.get("NodeId")
        if not isinstance(raw, str):
            skipped += 1
            continue
        try:
            if NodeId.from_hex(raw) == nid:
                return record, skipped
        except NodeIdError:
            skipped += 1
            continue
    _logger.debug("lorastats returned no record matching NodeId %s", nid.hex)
    return None, skipped


def parse_node(
    payload: Mapping[str, Any],
    *,
    region: str,
    observed_at: datetime,
    coercion_tracker: CoercionTracker | None = None,
) -> NodeObservation | None:
    """Map one lorastats.pl ``Nodes/JSON`` record to a :class:`NodeObservation`.

    ``LastSeen`` and ``LastBoot`` are ISO 8601 and may be either
    offset-aware or naive; a naive value is interpreted as Europe/Warsaw,
    lorastats.pl's local timezone, then normalized to UTC (see
    :func:`meshprovision.datasources.models.parse_iso8601`).

    Args:
        payload: One element of the decoded JSON array.
        region: The region path segment this record was fetched from.
        observed_at: Timestamp to stamp the observation with.
        coercion_tracker: Accumulates a count of fields present in
            ``payload`` but not confidently coercible (see
            :class:`~meshprovision.datasources.models.CoercionTracker`).
            Defaults to a throwaway tracker when not given.

    Returns:
        The normalized observation, or ``None`` (logged at WARNING) when
        ``payload["NodeId"]`` is missing or unparsable.
    """
    tracker = coercion_tracker if coercion_tracker is not None else CoercionTracker()
    raw_node_id = payload.get("NodeId")
    if not isinstance(raw_node_id, str):
        _logger.warning("lorastats record is missing a NodeId field: %r", raw_node_id)
        return None
    try:
        node_id = NodeId.from_hex(raw_node_id)
    except NodeIdError:
        _logger.warning("lorastats record has an unparsable NodeId: %r", raw_node_id)
        return None

    role_value = tracker.coerce(payload.get("Role"), coerce_int)
    hw_model_value = tracker.coerce(payload.get("HwModel"), coerce_int)

    return NodeObservation(
        node_id=node_id,
        source=SOURCE_LORASTATS,
        observed_at=observed_at,
        region_queried=region,
        short_name=tracker.coerce(payload.get("ShortName"), coerce_str),
        long_name=tracker.coerce(payload.get("LongName"), coerce_str),
        role=role_table().try_name(role_value) if role_value is not None else None,
        role_value=role_value,
        hw_model=hw_model_table().try_name(hw_model_value) if hw_model_value is not None else None,
        hw_model_value=hw_model_value,
        last_seen=tracker.coerce(payload.get("LastSeen"), parse_iso8601),
        last_boot=tracker.coerce(payload.get("LastBoot"), parse_iso8601),
    )


def validate_regions(regions: Sequence[str]) -> tuple[str, ...]:
    """Validate and normalize a candidate region list.

    Strips each entry, drops blanks, de-duplicates while preserving
    order, and requires every surviving entry to match
    :data:`REGION_PATTERN`. This is a *local* shape check only:
    lorastats.pl does not validate the region path segment server-side
    (an invalid-but-well-formed region silently returns real data for a
    valid node), so this function cannot detect a mistyped-but-well-
    formed region -- only a malformed one.

    Args:
        regions: The candidate region list.

    Returns:
        The validated, de-duplicated regions, in their original order.

    Raises:
        meshprovision.errors.SettingsError: If no non-blank entry
            remains, or an entry does not match :data:`REGION_PATTERN`.
    """
    deduplicated: list[str] = []
    for raw in regions:
        token = raw.strip()
        if token and token not in deduplicated:
            deduplicated.append(token)

    if not deduplicated:
        raise SettingsError("At least one lorastats region must be configured.")

    for token in deduplicated:
        if not REGION_PATTERN.match(token):
            raise SettingsError(
                f"Invalid lorastats region {token!r}: must match {REGION_PATTERN.pattern}"
            )

    return tuple(deduplicated)
