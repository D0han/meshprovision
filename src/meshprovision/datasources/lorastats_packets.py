"""``LorastatsPackets``: a node's packet reports and decoded packets from lorastats.pl.

Three requests, each for one node in the region lorastats knows it in
(the one :class:`~meshprovision.datasources.lorastats.LorastatsSource`
found it in; this module never looks for a region):

- ``/API/{region}/PacketReports/JSON?fromNode=<hex>`` -- every reception
  of the node's packets (one row per packet per gateway);
- ``/API/{region}/PacketsParsed/JSON?fromNode=<hex>`` -- the packets
  lorastats decoded;
- ``/API/{region}/PacketReports/JSON?gateway=<hex>`` -- what the node
  uplinked as an MQTT gateway (``[]`` for a node that is not one).

All take ``since``, a *naive Europe/Warsaw* time (``2026-10-20T08:48:30``;
lorastats ignores an offset and returns everything for an epoch number),
so a refresh only asks for what is new. Every answer is fetched fresh,
capped at :data:`PACKETS_MAX_BYTES`, and never written to the HTTP cache
(``store=False``): each ``since`` is a new URL, so keeping them would only
fill the cache; what is kept is the history built from them (see
:mod:`meshprovision.health.history`). Every request still goes through
the shared client, with its contact ``User-Agent``, retries, redirect
rules and per-host 429 cool-down.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import quote

from meshprovision.datasources.base import SOURCE_LORASTATS, require_json_list
from meshprovision.datasources.lorastats import LORASTATS_BASE_URL, validate_regions
from meshprovision.datasources.models import LORASTATS_NAIVE_TZ

if TYPE_CHECKING:
    from meshprovision.cache.http import CachedHTTPClient
    from meshprovision.nodeid import NodeId

__all__ = [
    "LORASTATS_PACKETS_PARSED_PATH",
    "LORASTATS_PACKET_REPORTS_PATH",
    "PACKETS_MAX_BYTES",
    "LorastatsPackets",
    "since_param",
]

LORASTATS_PACKET_REPORTS_PATH: Final[str] = "/API/{region}/PacketReports/JSON"
"""Region-scoped packet reports, filterable by ``fromNode``, ``gateway`` and ``since``."""

LORASTATS_PACKETS_PARSED_PATH: Final[str] = "/API/{region}/PacketsParsed/JSON"
"""Region-scoped decoded packets, filterable by ``fromNode`` and ``since``."""

PACKETS_MAX_BYTES: Final[int] = 8 * 1024 * 1024
"""The largest answer accepted: a busy node's day of reports is about 270 KB."""


def since_param(epoch: float) -> str:
    """Render a time as lorastats' ``since`` parameter: naive Europe/Warsaw, to the second.

    Args:
        epoch: Unix epoch seconds.

    Returns:
        For example ``"2026-10-20T08:48:30"``.
    """
    local = datetime.fromtimestamp(int(epoch), tz=LORASTATS_NAIVE_TZ)
    return local.strftime("%Y-%m-%dT%H:%M:%S")


class LorastatsPackets:
    """Fetches a node's packet rows from lorastats.pl, uncached."""

    def __init__(self, client: CachedHTTPClient, *, base_url: str = LORASTATS_BASE_URL) -> None:
        """Initialize the fetcher.

        Args:
            client: The shared HTTP client (it carries the contact ``User-Agent``).
            base_url: The lorastats.pl base URL. Overridable for tests.
        """
        self._client = client
        self._base_url = base_url.rstrip("/")

    def reports(self, node: NodeId, region: str, *, since: float | None) -> list[Any]:
        """Fetch the receptions of ``node``'s packets.

        Args:
            node: The node.
            region: The region lorastats knows it in.
            since: Only rows from then on, epoch seconds; ``None`` for all
                lorastats still keeps.

        Returns:
            The decoded JSON array.

        Raises:
            meshprovision.errors.SettingsError: If ``region`` is malformed.
            meshprovision.errors.InvalidResponseError: If the answer is not
                a JSON array.
            meshprovision.errors.HttpError: If the request fails.
            meshprovision.errors.RateLimitError: If lorastats.pl rate-limits it.
        """
        return self._rows(LORASTATS_PACKET_REPORTS_PATH, region, {"fromNode": node.hex}, since)

    def decoded(self, node: NodeId, region: str, *, since: float | None) -> list[Any]:
        """Fetch the packets of ``node`` lorastats decoded.

        Args:
            node: The node.
            region: The region lorastats knows it in.
            since: As for :meth:`reports`.

        Returns:
            The decoded JSON array.

        Raises:
            meshprovision.errors.DataSourceError: As for :meth:`reports`.
        """
        return self._rows(LORASTATS_PACKETS_PARSED_PATH, region, {"fromNode": node.hex}, since)

    def uplinked(self, gateway: NodeId, region: str, *, since: float) -> list[Any]:
        """Fetch the reports ``gateway`` uplinked as an MQTT gateway.

        Args:
            gateway: The node, as a gateway.
            region: The region lorastats knows it in.
            since: Only rows from then on, epoch seconds.

        Returns:
            The decoded JSON array (``[]`` for a node that is no gateway).

        Raises:
            meshprovision.errors.DataSourceError: As for :meth:`reports`.
        """
        return self._rows(LORASTATS_PACKET_REPORTS_PATH, region, {"gateway": gateway.hex}, since)

    def _rows(
        self, path: str, region: str, params: dict[str, str], since: float | None
    ) -> list[Any]:
        """Request one endpoint fresh, uncached, and read it as a JSON array.

        The answer is never stored; the eviction afterwards is a no-op
        kept so that no entry for it can outlive this call.
        """
        (valid,) = validate_regions((region,))
        url = f"{self._base_url}{path.format(region=quote(valid, safe=''))}"
        query = dict(params) if since is None else {**params, "since": since_param(since)}
        response = self._client.get(
            url,
            params=query,
            force_refresh=True,
            source=SOURCE_LORASTATS,
            max_bytes=PACKETS_MAX_BYTES,
            store=False,
        )
        try:
            return require_json_list(response.json(), url=url, source=SOURCE_LORASTATS)
        finally:
            self._client.evict(response.cache_key)
