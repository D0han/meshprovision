"""The :class:`DataSource` protocol and shared HTTP plumbing.

Every concrete data source (``loranet.py``, ``lorastats.py``) implements
:class:`DataSource` and is built on top of :class:`BaseHTTPDataSource`,
which owns the injected :class:`~meshprovision.cache.http.CachedHTTPClient`
and provides :meth:`BaseHTTPDataSource.get_json` -- the single most
important rule in this group: **never trust the HTTP status code**.
lorastats.pl returns HTTP 200 with an HTML body for invalid request paths
(a "soft 404"), so every call must decode the body as JSON and let
:meth:`~meshprovision.cache.http.CachedResponse.json` raise
:class:`~meshprovision.errors.InvalidResponseError` when it isn't.
:func:`require_json_list` and :func:`require_json_object` layer a shape
assertion on top of that for the two payload shapes this project's
sources actually return (loranet's node-id-keyed object, lorastats'
per-node array).
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import TYPE_CHECKING, Any, Final, Protocol

from meshprovision.errors import InvalidResponseError

if TYPE_CHECKING:
    from meshprovision.cache.http import CachedHTTPClient
    from meshprovision.datasources.models import NodeObservation
    from meshprovision.nodeid import NodeId

__all__ = [
    "SOURCE_LORANET",
    "SOURCE_LORASTATS",
    "BaseHTTPDataSource",
    "DataSource",
    "require_json_list",
    "require_json_object",
]

SOURCE_LORANET: Final[str] = "loranet"
"""Short source name used in :class:`NodeObservation.source` and error messages."""

SOURCE_LORASTATS: Final[str] = "lorastats"
"""Short source name used in :class:`NodeObservation.source` and error messages."""


class DataSource(Protocol):
    """Protocol every concrete node data source implements.

    ``status/merge.py`` (a later layer) consumes only this protocol, so it
    never sees a source-specific shape -- adding a third source (for
    example MQTT) later requires no change to the merge layer.

    An implementation must never return an observation whose ``node_id``
    differs from the id it was asked about. Callers file observations
    under the requested id and do not re-check.
    """

    @property
    def name(self) -> str:
        """Return this source's short name (for example ``"loranet"``)."""
        ...

    def fetch_nodes(self, ids: Collection[NodeId]) -> dict[NodeId, NodeObservation]:
        """Fetch normalized observations for the given node ids.

        Args:
            ids: The node ids to fetch. A source is free to fetch more
                efficiently than one request per id where its API allows
                it (loranet fetches one bulk dump); a source that must
                query per node (lorastats) issues one request per id.

        Returns:
            A mapping from each requested id that was found to its
            :class:`~meshprovision.datasources.models.NodeObservation`.
            An id absent from the source's data is simply omitted --
            never an error; the caller (the merge layer) decides what a
            missing node means.
        """
        ...


class BaseHTTPDataSource:
    """Shared plumbing for HTTP-backed data sources.

    Holds the injected
    :class:`~meshprovision.cache.http.CachedHTTPClient` and provides
    :meth:`get_json`, the one path every concrete source uses to turn a
    cached HTTP response into a decoded JSON value without ever trusting
    the response's status code.
    """

    def __init__(self, client: CachedHTTPClient, *, source_name: str) -> None:
        """Initialize the shared HTTP plumbing.

        Args:
            client: The cache-backed HTTP client to issue requests
                through. This is the only outbound-HTTP path a data
                source is permitted to use.
            source_name: This source's short name (for example
                ``"loranet"``), passed as ``source=`` on every request so
                errors identify the calling data source.
        """
        self._client = client
        self._source_name = source_name

    @property
    def name(self) -> str:
        """This source's short name.

        Returns:
            The ``source_name`` passed to the constructor.
        """
        return self._source_name

    @property
    def client(self) -> CachedHTTPClient:
        """The cache-backed HTTP client this source issues requests through.

        Returns:
            The injected :class:`~meshprovision.cache.http.CachedHTTPClient`.
        """
        return self._client

    def get_json(
        self,
        url: str,
        *,
        params: Mapping[str, object] | None = None,
        ttl: float | None = None,
        force_refresh: bool | None = None,
    ) -> Any:
        """Perform a cached ``GET`` and decode the response body as JSON.

        Deliberately never inspects the response's status code: a 2xx
        status from :class:`~meshprovision.cache.http.CachedHTTPClient`
        does not imply the body is JSON (lorastats.pl's soft-404 case),
        so the JSON parse itself -- via
        :meth:`~meshprovision.cache.http.CachedResponse.json` -- is the
        only thing this method trusts.

        Args:
            url: The request URL.
            params: Query parameters.
            ttl: Freshness window override for this call, in seconds.
            force_refresh: Whether to bypass the cache read for this
                call. The fetched response is still written to the cache
                either way.

        Returns:
            The decoded JSON value (of any shape); callers narrow it with
            :func:`require_json_list` or :func:`require_json_object`.

        Raises:
            meshprovision.errors.InvalidResponseError: If the response
                body does not parse as JSON.
            meshprovision.errors.HttpError: If the request itself fails.
        """
        response = self._client.get(
            url,
            params=params,
            ttl=ttl,
            force_refresh=force_refresh,
            source=self._source_name,
        )
        return response.json()


def require_json_list(payload: object, *, url: str, source: str) -> list[Any]:
    """Assert that a decoded JSON payload is a list, naming the type when it isn't.

    Args:
        payload: The value returned by :meth:`BaseHTTPDataSource.get_json`.
        url: The request URL, for the error message.
        source: The short source name, for the error message.

    Returns:
        ``payload`` unchanged, narrowed to ``list[Any]``.

    Raises:
        meshprovision.errors.InvalidResponseError: If ``payload`` is not
            a ``list``.
    """
    if not isinstance(payload, list):
        raise InvalidResponseError(
            f"Expected a JSON array from {url}, got {type(payload).__name__}",
            url=url,
            source=source,
        )
    return payload


def require_json_object(payload: object, *, url: str, source: str) -> dict[str, Any]:
    """Assert that a decoded JSON payload is an object, naming the type when it isn't.

    Args:
        payload: The value returned by :meth:`BaseHTTPDataSource.get_json`.
        url: The request URL, for the error message.
        source: The short source name, for the error message.

    Returns:
        ``payload`` unchanged, narrowed to ``dict[str, Any]``.

    Raises:
        meshprovision.errors.InvalidResponseError: If ``payload`` is not
            a ``dict``.
    """
    if not isinstance(payload, dict):
        raise InvalidResponseError(
            f"Expected a JSON object from {url}, got {type(payload).__name__}",
            url=url,
            source=source,
        )
    return payload
