"""``LorastatsRegionFeed``: a whole region's raw packets and node list from lorastats.pl.

The one exception to :mod:`~meshprovision.datasources.lorastats`' rule of
asking per node, used by ``mesh network`` only: its views are region-wide
by definition. Two requests, each for a whole region:

- ``/API/{region}/PacketsRaw/JSON`` -- every gateway's uplink of every
  packet (about 25 MB for a busy region's day), always with ``since``
  once a region has been fetched, so a refresh only asks for what is new
  (about 0.6 MB per hour). Fetched fresh, capped at
  :data:`REGION_RAW_MAX_BYTES` and never written to the HTTP cache
  (``store=False``), like
  :class:`~meshprovision.datasources.lorastats_packets.LorastatsPackets`:
  what is kept is the compact store built from it (see
  :mod:`meshprovision.network.store`).
- ``/API/{region}/Nodes/JSON`` without ``node=`` -- the region's node
  list (about 0.1 MB), cached for at least
  :data:`REGION_NODES_TTL_SECONDS` and capped at
  :data:`REGION_NODES_MAX_BYTES`.

How often each is asked is the refresher's budget (see
:mod:`meshprovision.network.refresh`). Every request goes through the
shared client, with its contact ``User-Agent``, retries, redirect rules
and per-host 429 cool-down.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import quote

from meshprovision.datasources.base import SOURCE_LORASTATS, require_json_list
from meshprovision.datasources.lorastats import (
    LORASTATS_BASE_URL,
    LORASTATS_NODES_PATH,
    parse_node,
    validate_regions,
)
from meshprovision.datasources.lorastats_packets import since_param
from meshprovision.errors import InvalidResponseError

if TYPE_CHECKING:
    from meshprovision.cache.http import CachedHTTPClient
    from meshprovision.datasources.models import NodeObservation

__all__ = [
    "LORASTATS_PACKETS_RAW_PATH",
    "REGION_NODES_MAX_BYTES",
    "REGION_NODES_TTL_SECONDS",
    "REGION_RAW_MAX_BYTES",
    "LorastatsRegionFeed",
]

LORASTATS_PACKETS_RAW_PATH: Final[str] = "/API/{region}/PacketsRaw/JSON"
"""Region-scoped raw packets (base64 ``MeshPacket`` per gateway uplink), filterable by ``since``."""

REGION_RAW_MAX_BYTES: Final[int] = 48 * 1024 * 1024
"""The largest raw-packets answer accepted: about twice a busy region's day."""

REGION_NODES_MAX_BYTES: Final[int] = 4 * 1024 * 1024
"""The largest node-list answer accepted (0.1-1.8 MB seen)."""

REGION_NODES_TTL_SECONDS: Final[float] = 3600.0
"""A region's node list is reused for at least this long."""


class LorastatsRegionFeed:
    """Fetches a whole region's raw packets (uncached) and node list (cached) from lorastats.pl."""

    def __init__(self, client: CachedHTTPClient, *, base_url: str = LORASTATS_BASE_URL) -> None:
        """Initialize the feed.

        Args:
            client: The shared HTTP client (it carries the contact ``User-Agent``).
            base_url: The lorastats.pl base URL. Overridable for tests.
        """
        self._client = client
        self._base_url = base_url.rstrip("/")

    def raw(self, region: str, *, since: float | None) -> list[Any]:
        """Fetch the region's raw packet rows, fresh, keeping nothing in the HTTP cache.

        Args:
            region: The region.
            since: Only rows from then on, epoch seconds; ``None`` for all
                lorastats still keeps.

        Returns:
            The decoded JSON array.

        Raises:
            meshprovision.errors.SettingsError: If ``region`` is malformed.
            meshprovision.errors.InvalidResponseError: If the answer is not
                a JSON array.
            meshprovision.errors.HttpError: If the request fails or the
                answer is larger than :data:`REGION_RAW_MAX_BYTES`.
            meshprovision.errors.RateLimitError: If lorastats.pl rate-limits it.
        """
        url = self._url(LORASTATS_PACKETS_RAW_PATH, region)
        params = {} if since is None else {"since": since_param(since)}
        response = self._client.get(
            url,
            params=params,
            force_refresh=True,
            source=SOURCE_LORASTATS,
            max_bytes=REGION_RAW_MAX_BYTES,
            store=False,
        )
        try:
            return require_json_list(response.json(), url=url, source=SOURCE_LORASTATS)
        finally:
            self._client.evict(response.cache_key)

    def nodes(self, region: str) -> tuple[NodeObservation, ...]:
        """Fetch the region's node list, from the HTTP cache while it is fresh.

        Args:
            region: The region.

        Returns:
            One observation per usable record (a record without a usable
            ``NodeId`` is left out), stamped with the fetch time.

        Raises:
            meshprovision.errors.DataSourceError: As for :meth:`raw` (except
                the size cap, :data:`REGION_NODES_MAX_BYTES`); an answer
                that is not a JSON array is also dropped from the cache.
        """
        url = self._url(LORASTATS_NODES_PATH, region)
        response = self._client.get(
            url,
            ttl=max(self._client.ttl, REGION_NODES_TTL_SECONDS),
            source=SOURCE_LORASTATS,
            max_bytes=REGION_NODES_MAX_BYTES,
        )
        try:
            rows = require_json_list(response.json(), url=url, source=SOURCE_LORASTATS)
        except InvalidResponseError:
            self._client.evict(response.cache_key)
            raise
        observed_at = datetime.fromtimestamp(response.fetched_at, tz=UTC)
        (valid,) = validate_regions((region,))
        parsed = (
            parse_node(row, region=valid, observed_at=observed_at)
            for row in rows
            if isinstance(row, dict)
        )
        return tuple(observation for observation in parsed if observation is not None)

    def _url(self, path: str, region: str) -> str:
        """Build an endpoint's URL for a validated, percent-encoded region.

        Raises:
            meshprovision.errors.SettingsError: If ``region`` is malformed.
        """
        (valid,) = validate_regions((region,))
        return f"{self._base_url}{path.format(region=quote(valid, safe=''))}"
