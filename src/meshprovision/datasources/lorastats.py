"""``LorastatsSource``: per-node ``?node=<hex>`` queries against lorastats.pl.

Unlike loranet.pl's single bulk dump, lorastats.pl's ``/API/{region}/Nodes/
JSON`` endpoint supports server-side filtering via a ``?node=<hex>`` query
parameter -- verified to shrink a ~1.84 MB bulk region dump down to a
~150-byte filtered response. This module therefore queries per node
rather than pulling region dumps, and deliberately exposes no bulk-dump
method at all: lorastats.pl's terms treat bulk scraping as grounds for an
IP ban, so the absence is the safeguard.

Behaviors verified live and worth restating here because they drive
this module's design:

- ``?node=`` requires **bare lowercase hex**; uppercase or a ``!``-prefix
  both silently return ``[]``. Always pass ``node_id.hex``.
- An unknown node returns ``[]`` with **HTTP 200** -- not an error.
- So does a node asked about in a region other than the one it lives in
  (by its last reported position, so a node can move), and any unknown or
  mistyped region: ``[]`` with HTTP 200, indistinguishable from "no data".

The regions to ask are configured, or -- when none is -- read from
lorastats.pl's own site navigation and cached for a week by
:class:`~meshprovision.datasources.lorastats_regions.RegionList` (no API
lists them). Each is checked only for its *local* shape (see
:func:`validate_regions`) and asked in turn. Two things keep that cheap
when more than one region is asked:

- a :class:`~meshprovision.datasources.region_memo.RegionMemo` remembers
  the region each node was last found in, which is asked first and alone
  while it keeps answering;
- before asking the regions for a node without such an answer, the
  region-free ``/Node/{hex}/Status`` endpoint is asked whether lorastats
  knows the node at all. Only its HTTP status is read (the body is Polish
  free text): 404 means unknown, so no region is asked; 200 (fine) and
  500 (known, but no packet received) mean known. The answer is reused
  for at least :data:`LORASTATS_STATUS_TTL_SECONDS`.

Per node and cache window that is one request when the memo's region
answers, one for a node lorastats does not know, and at most
``1 + len(regions)`` otherwise (the status probe plus every region, the
memo's included), with at most :data:`LORASTATS_MAX_REGIONS` regions. A
single region is asked directly, exactly one request per node, without
probe or memo.
"""

from __future__ import annotations

import functools
import logging
import re
import unicodedata
from collections.abc import Collection, Mapping, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import quote

from meshprovision.datasources.base import SOURCE_LORASTATS, BaseHTTPDataSource, require_json_list
from meshprovision.datasources.models import (
    CoercionTracker,
    NodeObservation,
    coerce_int,
    coerce_str,
    parse_iso8601,
)
from meshprovision.enums import hw_model_table, role_table
from meshprovision.errors import MissingContactError, NodeIdError, SettingsError
from meshprovision.nodeid import NodeId, NodeIdLike

if TYPE_CHECKING:
    from meshprovision.cache.http import CachedHTTPClient
    from meshprovision.datasources.lorastats_regions import RegionList
    from meshprovision.datasources.region_memo import RegionMemo

__all__ = [
    "LORASTATS_BASE_URL",
    "LORASTATS_MAX_REGIONS",
    "LORASTATS_MIN_TTL_SECONDS",
    "LORASTATS_NODES_PATH",
    "LORASTATS_STATUS_PATH",
    "LORASTATS_STATUS_TTL_SECONDS",
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

LORASTATS_MIN_TTL_SECONDS: Final[float] = 60.0
"""Shortest time a lorastats.pl response is reused, whatever the client's TTL.

One request per node per poll is the request storm lorastats.pl bans IPs
for; with this floor, ``--cache-ttl 0`` and a short ``--watch --interval``
still ask for each node at most once a minute (``--no-cache`` still forces
a fresh fetch)."""

LORASTATS_STATUS_PATH: Final[str] = "/Node/{node}/Status"
"""Region-free per-node status endpoint; only its HTTP status is read."""

LORASTATS_STATUS_TTL_SECONDS: Final[float] = 3600.0
"""Shortest time a status-endpoint answer is reused, whatever the client's TTL.

Above all for a node lorastats does not know (HTTP 404): it is not asked
about again, in any region, for an hour (``--no-cache`` still asks)."""

_STATUS_UNKNOWN_NODE: Final[int] = 404
"""The status endpoint's answer for a node lorastats does not know."""

_STATUS_ANSWERS: Final[frozenset[int]] = frozenset({_STATUS_UNKNOWN_NODE, 500})
"""Status-endpoint statuses that are answers, not failures: 500 is its normal
"known, but no packet received" answer, so it must not be retried."""

LORASTATS_MAX_REGIONS: Final[int] = 16
"""Most regions in a list, configured or read from lorastats.pl: each may be
asked for a node, so this bounds the requests one node can cost."""

REGION_PATTERN: Final[re.Pattern[str]] = re.compile(r"^(?!\.{1,2}$)[^\x00-\x1f\x7f/\\?#%]{1,64}\Z")
"""Shape a region path segment must match: 1-64 characters of any script
(lorastats names regions such as ``Zachód``, and region names have changed
over time, so no list of names is assumed), spaces included, but never a
path separator (``/``, ``\\``), a query or fragment mark (``?``, ``#``), a
percent sign, a control character, or the bare ``.``/``..`` segments.
This is a *local* sanity check only -- lorastats.pl does not validate the
region segment server-side (an unknown region just returns an empty list),
so this pattern can catch a value that would alter the URL path but never
a mistyped-but-well-formed name. The region is percent-encoded when it is
put into the URL."""


class LorastatsSource(BaseHTTPDataSource):
    """Data source backed by lorastats.pl's per-node ``Nodes/JSON`` endpoint."""

    def __init__(
        self,
        client: CachedHTTPClient,
        *,
        contact: str,
        regions: Sequence[str] = (),
        base_url: str = LORASTATS_BASE_URL,
        region_list: RegionList | None = None,
        region_memo: RegionMemo | None = None,
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
            regions: The configured region list to query when a call does
                not specify one explicitly. Validated via
                :func:`validate_regions`. Empty means ``region_list``.
            base_url: The lorastats.pl base URL. Overridable for tests.
            region_list: Where to get the regions when none are
                configured, on first use.
            region_memo: Where to remember the region each node was found
                in, when more than one region is asked. ``None``
                remembers nothing (the status probe still applies).

        Raises:
            meshprovision.errors.MissingContactError: If ``contact`` is
                empty or whitespace-only.
            meshprovision.errors.SettingsError: If ``regions`` contains
                only blank entries, an entry that does not match
                :data:`REGION_PATTERN`, or more than
                :data:`LORASTATS_MAX_REGIONS` entries, or is empty without
                a ``region_list``.
        """
        if not contact.strip():
            raise MissingContactError()
        super().__init__(client, source_name=SOURCE_LORASTATS)
        self._base_url = base_url.rstrip("/")
        if not regions and region_list is None:
            raise SettingsError("No lorastats regions to ask were given.")
        self._regions = validate_regions(regions) if regions else None
        self._region_list = region_list
        self._memo = region_memo

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
        """Fetch one node's observation from the region it lives in.

        With more than one configured region (and no explicit
        ``region``), the memo's region is asked first; when it does not
        answer, or there is none, the status endpoint is asked whether
        lorastats knows the node (no region is asked when it does not),
        then every other configured region in order. The memo is updated
        to the region that answered, or the entry is dropped when its
        region no longer does. See the module docstring for the request
        budget.

        Args:
            node_id: The node id to look up, in any form
                :meth:`NodeId.parse` accepts.
            region: A single region to query instead of the
                configured regions, without memo or status probe. Does
                not need to already be validated (this call validates it
                before use).
            force_refresh: Whether to bypass the HTTP cache read for
                this call. Otherwise a cached response is reused for the
                client's TTL, but never less than
                :data:`LORASTATS_MIN_TTL_SECONDS` (a status-endpoint
                answer: :data:`LORASTATS_STATUS_TTL_SECONDS`).

        Returns:
            The observation, or ``None`` when the node was not found in
            any candidate region (a legitimate, non-error outcome:
            lorastats.pl returns ``[]`` with HTTP 200 for an unknown
            node) or lorastats does not know it. Also sets
            :attr:`last_fetch_skipped` to the number of
            candidate records across every queried region that could not
            even be inspected for a match (see :func:`_match_record`) --
            never counting a record that simply belonged to a different
            node, only one this call could not parse at all. Resets and
            sets :attr:`last_fetch_data_as_of` to the oldest fetch time
            across every region request this call made (via
            :meth:`_begin_fetch` and :meth:`~meshprovision.datasources.base
            .BaseHTTPDataSource.get_json`); the status probe does not
            count, as it carries no node data.

        Raises:
            meshprovision.errors.NodeIdError: If ``node_id`` cannot be
                parsed.
            meshprovision.errors.SettingsError: If ``region`` is given
                and does not match :data:`REGION_PATTERN`.
            meshprovision.errors.InvalidResponseError: If a response
                body does not parse as a JSON array.
            meshprovision.errors.HttpError: If a request itself fails,
                the status probe's included (any status but 2xx, 404
                and 500).
            meshprovision.errors.DataSourceError: If no regions are
                configured and the region list cannot be had.
        """
        self._begin_fetch()
        nid = NodeId.parse(node_id)
        tracker = CoercionTracker()
        self._last_fetch_skipped = 0
        try:
            if region is not None:
                found = self._search(nid, validate_regions((region,)), tracker, force_refresh)
            else:
                regions = self._configured()
                if len(regions) == 1:
                    found = self._search(nid, regions, tracker, force_refresh)
                else:
                    found = self._search_learning(nid, regions, tracker, force_refresh)
        finally:
            self._last_fetch_field_coercions = tracker.failures
        return found[0] if found is not None else None

    def _search_learning(
        self,
        nid: NodeId,
        regions: tuple[str, ...],
        tracker: CoercionTracker,
        force_refresh: bool | None,
    ) -> tuple[NodeObservation, str] | None:
        """Look ``nid`` up in ``regions``, memo first, and update the memo.

        Args:
            nid: The node to look up.
            regions: The regions to ask, in order (more than one).
            tracker: Collects field-coercion failures.
            force_refresh: Forwarded to every request.

        Returns:
            The observation and the region that answered, or ``None``.
        """
        remembered = self._remembered_region(nid, regions)
        if remembered is not None:
            found = self._search(nid, (remembered,), tracker, force_refresh)
            if found is not None:
                return found
        if self._unknown_to_lorastats(nid, force_refresh):
            found = None
        else:
            others = tuple(candidate for candidate in regions if candidate != remembered)
            found = self._search(nid, others, tracker, force_refresh)
        if self._memo is not None:
            if found is not None:
                self._memo.remember(nid, found[1])
            elif remembered is not None:
                self._memo.forget(nid)
        return found

    def _remembered_region(self, nid: NodeId, regions: tuple[str, ...]) -> str | None:
        """Return the memo's region for ``nid`` when it is one of ``regions``.

        A remembered region that is not in the list (any more) is ignored,
        never asked: the list is the operator's (or lorastats.pl's) choice.

        Args:
            nid: The node to look up.
            regions: The regions being asked.

        Returns:
            The configured region the node was last found in, or ``None``.
        """
        if self._memo is None:
            return None
        remembered = self._memo.region_for(nid)
        return remembered if remembered in regions else None

    def _unknown_to_lorastats(self, nid: NodeId, force_refresh: bool | None) -> bool:
        """Ask the region-free status endpoint whether lorastats knows ``nid``.

        Args:
            nid: The node to ask about.
            force_refresh: Forwarded to the request.

        Returns:
            ``True`` only for HTTP 404. Every other answer -- 200, 500,
            or a 2xx soft-404 page -- means "ask the regions".

        Raises:
            meshprovision.errors.HttpError: For any other status, or a
                failed request (as for a region request).
        """
        response = self._client.get(
            f"{self._base_url}{LORASTATS_STATUS_PATH.format(node=nid.hex)}",
            ttl=max(self._client.ttl, LORASTATS_STATUS_TTL_SECONDS),
            force_refresh=force_refresh,
            source=self.name,
            accept_statuses=_STATUS_ANSWERS,
        )
        if response.status_code != _STATUS_UNKNOWN_NODE:
            return False
        _logger.info("lorastats does not know node %s; not asking any region about it", nid.hex)
        return True

    def _search(
        self,
        nid: NodeId,
        regions: Sequence[str],
        tracker: CoercionTracker,
        force_refresh: bool | None,
    ) -> tuple[NodeObservation, str] | None:
        """Ask each of ``regions`` in turn for ``nid``, stopping at the first match.

        Adds every record that could not be inspected to
        :attr:`last_fetch_skipped`.

        Args:
            nid: The node to look up.
            regions: The validated regions to ask, in order.
            tracker: Collects field-coercion failures.
            force_refresh: Forwarded to every request.

        Returns:
            The observation and the region that answered, or ``None``.
        """
        for candidate in regions:
            region_segment = quote(candidate, safe="")
            url = f"{self._base_url}{LORASTATS_NODES_PATH.format(region=region_segment)}"
            payload = self.get_json(
                url,
                params={"node": nid.hex},
                ttl=max(self._client.ttl, LORASTATS_MIN_TTL_SECONDS),
                force_refresh=force_refresh,
                validate=functools.partial(require_json_list, url=url, source=self.name),
            )
            records = require_json_list(payload, url=url, source=self.name)
            if not records:
                continue
            record, record_skipped = _match_record(records, nid)
            self._last_fetch_skipped += record_skipped
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
            return observation, candidate
        return None

    def _configured(self) -> tuple[str, ...]:
        """Return the configured regions, else the region list's (loaded once by it).

        Returns:
            The validated regions to ask, in order.

        Raises:
            meshprovision.errors.DataSourceError: If the region list cannot
                be had.
        """
        if self._regions is not None:
            return self._regions
        listed = self._region_list.regions(self._client) if self._region_list else ()
        return validate_regions(listed)


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

    Strips each entry and normalizes it to Unicode NFC (so ``Zachód``
    typed with a combining accent, as macOS input produces, is the same
    region as the precomposed spelling), drops blanks, de-duplicates while
    preserving order, and requires every surviving entry to match
    :data:`REGION_PATTERN`. Nothing else is folded: ``PL`` and ``pl`` stay
    two regions, since lorastats.pl's own matching cannot be verified
    offline. At most :data:`LORASTATS_MAX_REGIONS` may remain. This is a
    *local* shape check only: lorastats.pl does not validate the region
    path segment server-side (an invalid-but-well-formed region silently
    returns an empty list, as for a node that is not there), so this
    function cannot detect a mistyped-but-well-formed region -- only a
    malformed one.

    Args:
        regions: The candidate region list.

    Returns:
        The validated, NFC-normalized, de-duplicated regions, in their
        original order.

    Raises:
        meshprovision.errors.SettingsError: If no non-blank entry
            remains, more than :data:`LORASTATS_MAX_REGIONS` do, or an
            entry does not match :data:`REGION_PATTERN`.
    """
    deduplicated: list[str] = []
    for raw in regions:
        token = unicodedata.normalize("NFC", raw.strip())
        if token and token not in deduplicated:
            deduplicated.append(token)

    if not deduplicated:
        raise SettingsError("At least one lorastats region must be configured.")
    if len(deduplicated) > LORASTATS_MAX_REGIONS:
        raise SettingsError(
            f"At most {LORASTATS_MAX_REGIONS} lorastats regions can be configured, "
            f"got {len(deduplicated)}."
        )

    for token in deduplicated:
        if not REGION_PATTERN.match(token):
            raise SettingsError(
                f"Invalid lorastats region {token!r}: must match {REGION_PATTERN.pattern}"
            )

    return tuple(deduplicated)
