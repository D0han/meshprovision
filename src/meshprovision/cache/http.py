"""Disk-backed TTL cache wrapping ``httpx`` -- the sole outbound-HTTP path.

:class:`CachedHTTPClient` is the *only* place in meshprovision that is
allowed to open a socket to loranet.pl or lorastats.pl. Every datasource
call flows through :meth:`CachedHTTPClient.get` or
:meth:`CachedHTTPClient.request`, which enforces TLS verification,
explicit timeouts, exponential backoff on 5xx/network failures only, and
a disk-backed response cache keyed by method + URL + sorted params.

TLS verification is an invariant of this class, not an option: there is
deliberately no ``verify`` constructor parameter. The internal
``httpx.Client`` is always built with ``verify=True``, and it refuses to
follow a redirect from an ``https`` URL to a non-``https`` one (which
would send the operator-contact ``User-Agent`` in cleartext and cache an
unauthenticated body for the full TTL).

**TTL and refresh.** This module does not know about
:class:`meshprovision.config.settings.Settings` -- the ``cache`` group is
independent of ``config`` by design (see the layer's cross-cutting
notes). The caller passes the already-resolved TTL (the CLI uses
``Settings.cache_ttl``, which applies the ``--cache-ttl`` >
``MESHPROVISION_CACHE_TTL`` > config > default precedence) and
``force_refresh``. ``--no-cache`` / ``--force-refresh`` both map to
``force_refresh=True`` (bypassing cache *reads* only -- a forced fetch is
still written to disk, refreshing the entry for the next run).

**On-disk format.** Each cache entry is one JSON file, holding the
response's status code, a small allow-listed subset of headers, the body
base64-encoded (so binary content or a mis-declared encoding can never
corrupt the file), and metadata (``version``, ``key``, ``fetched_at``).
Only 2xx responses, and a status the caller explicitly accepts (see
:meth:`CachedHTTPClient.request`'s ``accept_statuses``), are ever written,
and an entry is only served to a call that accepts its status. A 12.7 MB body (the loranet.pl node
dump) base64s to roughly 17 MB on disk and is held fully in memory during
read/write; this is a deliberate simplicity trade-off for a low-volume,
single-operator tool and should not be "optimised" into a streaming
format without a concrete reason. What is bounded is the body itself: it
is read under :data:`MAX_RESPONSE_BYTES` (counted after decompression), so
a hostile server cannot turn that trade-off into gigabytes.

**Contract for the datasources layer** (``datasources/loranet.py``,
``datasources/lorastats.py``, written in a later layer): call
``client.get(url, params=..., source=...)`` once per logical request and
always call :meth:`CachedResponse.json` rather than trusting the HTTP
status code -- lorastats.pl returns HTTP 200 with an HTML body for
invalid paths (a "soft 404"), and only :meth:`CachedResponse.json`
surfaces that as an error. Because only the status decides what is
written, such a rejected 2xx body is already on disk by then; a caller
that rejects a response drops it with
:meth:`CachedHTTPClient.evict` (``evict(response.cache_key)``), and
:meth:`~meshprovision.datasources.base.BaseHTTPDataSource.get_json` does
so for every :class:`~meshprovision.errors.InvalidResponseError`, so a
soft 404 or maintenance page is fetched again on the next call instead
of being replayed for the whole TTL. Cache keys include sorted params, so
per-node lorastats queries (``?node=<hex>``) never collide with each
other or with the bulk loranet dump. :attr:`CacheStats.network_requests`
increments once per actual ``httpx`` call, including retries, so tests
can assert that a second call inside the TTL performs zero network
calls.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import email.utils
import hashlib
import json
import logging
import os
import time
import uuid
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast
from urllib.parse import urlencode

import httpx

from meshprovision.datasources.json_store import read_json, write_json
from meshprovision.errors import (
    CacheError,
    HttpError,
    InvalidResponseError,
    MissingContactError,
    RateLimitCoolingDownError,
    RateLimitError,
    SettingsError,
)

if TYPE_CHECKING:
    from types import TracebackType

__all__ = [
    "CACHE_ENTRY_VERSION",
    "DEFAULT_BACKOFF_BASE",
    "DEFAULT_BACKOFF_MAX",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_TTL_SECONDS",
    "MAX_RESPONSE_BYTES",
    "PERSISTED_HEADERS",
    "RATE_LIMIT_FILENAME",
    "RATE_LIMIT_VERSION",
    "RETRY_STATUS_MIN",
    "CacheStats",
    "CachedHTTPClient",
    "CachedResponse",
    "cache_key",
]

_logger = logging.getLogger(__name__)

CACHE_ENTRY_VERSION: Final[int] = 1
"""On-disk cache entry schema version. A mismatch is treated as a miss."""

DEFAULT_TTL_SECONDS: Final[float] = 300.0
"""Default freshness window for a cache entry, in seconds."""

MAX_RESPONSE_BYTES: Final[int] = 64 * 1024 * 1024
"""Upper bound on a response body, counted after ``Content-Encoding`` decoding.

The largest real body (the loranet.pl node dump) is about 13 MB; the cap
keeps a hostile or broken server from filling memory and the cache with a
small compressed response that decodes to gigabytes."""

DEFAULT_TIMEOUT_SECONDS: Final[float] = 15.0
"""Default per-request ``httpx`` timeout, in seconds."""

DEFAULT_MAX_RETRIES: Final[int] = 3
"""Default number of retries after the first attempt (total attempts = this + 1)."""

DEFAULT_BACKOFF_BASE: Final[float] = 0.5
"""Base delay, in seconds, for exponential backoff between retries."""

DEFAULT_BACKOFF_MAX: Final[float] = 8.0
"""Maximum delay, in seconds, between retries."""

RETRY_STATUS_MIN: Final[int] = 500
"""Status codes at or above this value are retried; below it, never."""

PERSISTED_HEADERS: Final[frozenset[str]] = frozenset(
    {"content-type", "etag", "last-modified", "date", "content-encoding"}
)
"""Lowercase response header names persisted in a cache entry."""

_CACHE_SHARD_WIDTH: Final[int] = 2
"""Number of leading hex characters of a cache key used as a shard directory."""

_CACHE_ROOT_MODE: Final[int] = 0o700
"""Permission bits applied to the cache root on first write (contains node data)."""

_FETCHED_AT_FUTURE_SKEW_SECONDS: Final[float] = 300.0
"""How far ahead of the clock a cached ``fetched_at`` may be and still count as fresh.

Absorbs a small backwards clock correction (an NTP step) and minor skew
between hosts sharing one cache directory. An entry further ahead was
written under a wrong clock, or edited, and would otherwise stay fresh
until the clock caught up with it.
"""

_STALE_ENTRY_TEMP_AGE_SECONDS: Final[float] = 60 * 60
"""How old an entry's leftover temp file must be before a later write of that entry removes it.

Writing even the largest entry (the ~17 MB loranet.pl dump) takes
seconds, so an hour-old temp belongs to a writer that was killed, not to
one still running.
"""

_MAX_REDIRECTS: Final[int] = 20
"""Redirect hops followed for one request before it fails as a loop (``httpx``'s default)."""

_RATE_LIMIT_DEFAULT_COOLDOWN_SECONDS: Final[float] = 600.0
"""How long a host that answered HTTP 429 without a usable ``Retry-After`` is not asked again."""

_RATE_LIMIT_MAX_COOLDOWN_SECONDS: Final[float] = 86_400.0
"""Upper bound on a 429 cool-down, whatever ``Retry-After`` asks for (one day)."""

RATE_LIMIT_FILENAME: Final[str] = "rate_limits.json"
"""The file, directly in the cache directory, that keeps every process's 429 cool-downs.

``{"version": 1, "hosts": {"<host>": <until, epoch seconds>}}``. Deleting
it lets mesh ask a rate-limited host again at once."""

RATE_LIMIT_VERSION: Final[int] = 1
"""On-disk schema version of :data:`RATE_LIMIT_FILENAME`. Any other version reads as empty."""

_RATE_LIMIT_MAX_FILE_BYTES: Final[int] = 8 * 1024
"""The largest cool-down file read; :data:`_RATE_LIMIT_MAX_HOSTS` long host names fit."""

_RATE_LIMIT_MAX_HOSTS: Final[int] = 16
"""Cool-downs kept in the file; the ones ending last win."""

_RATE_LIMIT_MAX_HOST_CHARS: Final[int] = 253
"""The longest host name (DNS) a cool-down is read for."""

_RATE_LIMIT_FUTURE_SKEW_SECONDS: Final[float] = 300.0
"""Clock skew allowed past the longest cool-down before a stored one is ignored."""

_RATE_LIMIT_WHAT: Final[str] = "HTTP 429 cool-downs"

_RATE_LIMIT_HINT: Final[str] = (
    "lorastats.pl bans IP addresses for misuse; wait before retrying "
    "and check MESHPROVISION_CONTACT."
)

_HTTP_RATE_LIMITED: Final[int] = 429
_HTTP_CLIENT_ERROR_MIN: Final[int] = 400
_HTTP_CLIENT_ERROR_MAX: Final[int] = 500
_HTTP_SUCCESS_MIN: Final[int] = 200
_HTTP_SUCCESS_MAX: Final[int] = 300


class _InsecureRedirectError(httpx.RequestError):
    """A redirect from an ``https`` URL to a non-``https`` one was refused.

    A :class:`httpx.RequestError` (not a ``TransportError``) so that
    :meth:`CachedHTTPClient._fetch_with_retry` treats it like a redirect
    loop: deterministic, never retried, wrapped as :class:`HttpError`.
    """

    def __init__(self, target: str, *, request: httpx.Request) -> None:
        """Initialize the error.

        Args:
            target: The refused redirect target, without its query string.
            request: The ``https`` request whose response redirected.
        """
        super().__init__(
            f"refused to follow a redirect from HTTPS to non-HTTPS URL {target}",
            request=request,
        )
        self.target = target


class _InvalidRedirectError(httpx.RequestError):
    """A redirect's ``Location`` header is not a valid URL.

    A :class:`httpx.RequestError` (not a ``TransportError``), like
    :class:`_InsecureRedirectError`: deterministic, never retried, wrapped
    as :class:`HttpError`. Left to ``httpx``, it would surface as a
    ``RemoteProtocolError``, which is a ``TransportError`` and so retried.
    """

    def __init__(self, reason: str, *, request: httpx.Request) -> None:
        """Initialize the error.

        Args:
            reason: Why ``httpx`` could not parse the target.
            request: The request whose response redirected.
        """
        super().__init__(f"the redirect target is not a valid URL: {reason}", request=request)


class _ResponseTooLargeError(httpx.RequestError):
    """A response body exceeded its cap (:data:`MAX_RESPONSE_BYTES` or a call's lower one).

    A :class:`httpx.RequestError` (not a ``TransportError``), like
    :class:`_InsecureRedirectError`: deterministic, never retried, wrapped
    as :class:`HttpError`, and never cached.
    """

    def __init__(self, limit: int, *, request: httpx.Request) -> None:
        """Initialize the error.

        Args:
            limit: The cap the body exceeded, in bytes.
            request: The request whose response was too large.
        """
        super().__init__(f"the response body is larger than {limit} bytes", request=request)


def _read_capped(response: httpx.Response, limit: int) -> bytes:
    """Read a streamed response's decoded body, stopping past ``limit`` bytes.

    Args:
        response: A response opened with ``stream=True``.
        limit: The largest body accepted, in bytes.

    Returns:
        The decoded body.

    Raises:
        _ResponseTooLargeError: If the body exceeds the cap.
    """
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_bytes():
        size += len(chunk)
        if size > limit:
            raise _ResponseTooLargeError(limit, request=response.request)
        chunks.append(chunk)
    return b"".join(chunks)


def _refuse_insecure_redirect(response: httpx.Response) -> None:
    """``httpx`` response hook: refuse any ``https`` -> non-``https`` redirect.

    Runs on every response, before ``httpx`` builds the next request of a
    redirect chain, so the downgraded request is never sent. A redirect
    between two ``https`` URLs (same host or not) is followed as usual.

    Args:
        response: The response just received.

    Raises:
        _InsecureRedirectError: If ``response`` redirects from an ``https``
            URL to a non-``https`` one.
        _InvalidRedirectError: If its ``Location`` is not a valid URL.
    """
    if not response.has_redirect_location:
        return
    source = response.request.url
    try:
        target = source.join(response.headers["location"])
    except httpx.InvalidURL as exc:
        raise _InvalidRedirectError(str(exc), request=response.request) from exc
    if source.scheme == "https" and target.scheme != "https":
        raise _InsecureRedirectError(str(target.copy_with(query=None)), request=response.request)


def _param_pairs(
    params: Mapping[str, object] | Sequence[tuple[str, object]] | None,
) -> list[tuple[str, str]]:
    """Coerce loose query params into ``(key, value)`` string pairs, in input order.

    Shared by :func:`cache_key` (which sorts the result before hashing)
    and :func:`_display_url` (which keeps input order, so a logged URL
    reads like the request that actually went out).

    Args:
        params: Query parameters, as a mapping or a sequence of
            ``(key, value)`` pairs. List/tuple values expand into one
            pair per item; ``None`` becomes an empty string; ``bool``
            becomes ``"true"``/``"false"``; everything else is
            stringified.

    Returns:
        The coerced ``(key, value)`` pairs, in input order.
    """
    pairs: list[tuple[str, str]] = []
    if not params:
        return pairs
    items = params.items() if isinstance(params, Mapping) else params
    for raw_key, raw_value in items:
        if isinstance(raw_value, (list, tuple)):
            pairs.extend((str(raw_key), str(item)) for item in raw_value)
        elif raw_value is None:
            pairs.append((str(raw_key), ""))
        elif isinstance(raw_value, bool):
            pairs.append((str(raw_key), "true" if raw_value else "false"))
        else:
            pairs.append((str(raw_key), str(raw_value)))
    return pairs


def _display_url(
    url: str, params: Mapping[str, object] | Sequence[tuple[str, object]] | None
) -> str:
    """Render ``url`` with ``params`` appended as a query string, for logging only.

    Never used for the actual request (httpx handles that encoding) or
    for the cache key (:func:`cache_key` sorts pairs; this preserves
    input order instead, so distinct per-node requests -- e.g.
    lorastats.pl's ``?node=<hex>`` -- read as distinct log lines).

    Args:
        url: The request URL, exactly as passed to the client.
        params: Query parameters, in the same shape :func:`cache_key`
            accepts.

    Returns:
        ``url`` unchanged if ``params`` is empty; otherwise ``url``
        with a ``?``-prefixed, urlencoded query string appended.
    """
    pairs = _param_pairs(params)
    if not pairs:
        return url
    return f"{url}?{urlencode(pairs)}"


def cache_key(
    method: str,
    url: str,
    params: Mapping[str, object] | Sequence[tuple[str, object]] | None = None,
) -> str:
    """Return the sha256 hex digest identifying one cacheable request.

    The digest is stable across processes and Python runs (built from
    ``hashlib.sha256``, never the builtin ``hash()``). Headers -- notably
    the User-Agent, which is constant for the lifetime of one process --
    are deliberately excluded, so they cannot fragment the cache.

    Args:
        method: The HTTP method, case-insensitively (``"GET"``, ``"get"``).
        url: The request URL, exactly as passed to the client.
        params: Query parameters, as a mapping or a sequence of
            ``(key, value)`` pairs. List/tuple values expand into one
            pair per item; ``None`` becomes an empty string; ``bool``
            becomes ``"true"``/``"false"``; everything else is
            stringified.

    Returns:
        A 64-character lowercase hex sha256 digest.
    """
    parts = [method.strip().upper(), url.strip()]
    parts.extend(f"{k}={v}" for k, v in sorted(_param_pairs(params)))
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class CacheStats:
    """Cumulative counters for one :class:`CachedHTTPClient` instance.

    Attributes:
        hits: Number of :meth:`CachedHTTPClient.request` calls served
            from a fresh cache entry.
        misses: Number of :meth:`CachedHTTPClient.request` calls that
            required a network fetch (absent, stale, or force-refreshed).
        writes: Number of cache entries written to disk.
        network_requests: Number of actual ``httpx`` calls made,
            including retries.
        retries: Number of retry attempts performed after a 5xx or
            network-error response.
    """

    hits: int = 0
    misses: int = 0
    writes: int = 0
    network_requests: int = 0
    retries: int = 0


@dataclass(frozen=True, slots=True)
class CachedResponse:
    """One HTTP response, either freshly fetched or read from the cache.

    Attributes:
        status_code: The HTTP status code.
        headers: Lowercase-keyed headers, restricted to the
            :data:`PERSISTED_HEADERS` subset.
        content: The raw response body bytes.
        url: The final URL after redirects.
        method: The HTTP method used for the request.
        fetched_at: Unix epoch seconds when this response was fetched
            from the network (not when it was read from the cache).
        cache_key: The cache key identifying this request.
        from_cache: Whether this response was served from the on-disk
            cache rather than freshly fetched.
    """

    status_code: int
    headers: Mapping[str, str]
    content: bytes
    url: str
    method: str
    fetched_at: float
    cache_key: str
    from_cache: bool

    def age(self, *, now: float | None = None) -> float:
        """Return how long ago this response was fetched from the network.

        Args:
            now: The current time in unix epoch seconds. Defaults to
                ``time.time()``.

        Returns:
            ``now - fetched_at``, in seconds.
        """
        current = time.time() if now is None else now
        return current - self.fetched_at

    def is_fresh(self, ttl: float, *, now: float | None = None) -> bool:
        """Return whether this response is still within its TTL window.

        Args:
            ttl: The freshness window, in seconds.
            now: The current time in unix epoch seconds. Defaults to
                ``time.time()``.

        Returns:
            ``True`` if :meth:`age` is less than or equal to ``ttl`` and
            :attr:`fetched_at` is a plausible fetch time: not before the
            epoch and at most :data:`_FETCHED_AT_FUTURE_SKEW_SECONDS` ahead
            of ``now``. A non-finite, pre-epoch or far-future value (a
            corrupted or hand-edited entry, or one written while the clock
            was wrong) is never fresh, so it is refetched rather than
            served for years or handed to a datetime conversion that
            cannot represent it.
        """
        current = time.time() if now is None else now
        if not 0.0 <= self.fetched_at <= current + _FETCHED_AT_FUTURE_SKEW_SECONDS:
            return False
        return self.age(now=current) <= ttl

    def json(self) -> Any:
        """Parse the response body as JSON.

        This is the load-bearing call for every datasource: lorastats.pl
        returns HTTP 200 with an HTML body for invalid request paths (a
        "soft 404"), so datasources must call this method and trust its
        error rather than trusting :attr:`status_code`.

        Returns:
            The decoded JSON value.

        Raises:
            InvalidResponseError: If the body is not valid JSON, nests too
                deeply to decode, or holds an integer with more digits
                than Python converts.
        """
        try:
            return json.loads(self.content)
        except (ValueError, RecursionError) as exc:
            # ValueError covers JSONDecodeError, UnicodeDecodeError and an
            # integer literal past Python's int max-str-digits limit.
            raise InvalidResponseError(
                f"{self.url} did not return JSON "
                f"(content-type {self.content_type!r}, {len(self.content)} bytes)",
                url=self.url,
                status_code=self.status_code,
                content_type=self.content_type,
            ) from exc

    @property
    def content_type(self) -> str | None:
        """The response's ``Content-Type`` header, if present.

        Returns:
            The lowercase-keyed header's value, or ``None``.
        """
        return self.headers.get("content-type")


def _entry_to_response(
    entry: Mapping[str, Any], *, cache_key_value: str, from_cache: bool
) -> CachedResponse:
    """Build a :class:`CachedResponse` from a decoded on-disk entry.

    Args:
        entry: The decoded JSON entry.
        cache_key_value: The cache key this entry was read from.
        from_cache: Value to set on the resulting :attr:`CachedResponse.from_cache`.

    Returns:
        The reconstructed response.

    Raises:
        KeyError: If a required field is missing.
        TypeError: If a field has the wrong shape.
        ValueError: If a numeric field cannot be converted.
        binascii.Error: If the body is not valid base64.
    """
    body = _base64_decode(entry["body"])
    headers = entry["headers"]
    if not isinstance(headers, dict):
        raise TypeError("cache entry 'headers' must be an object")
    return CachedResponse(
        status_code=int(entry["status_code"]),
        headers={str(k): str(v) for k, v in headers.items()},
        content=body,
        url=str(entry["url"]),
        method=str(entry["method"]),
        fetched_at=float(entry["fetched_at"]),
        cache_key=cache_key_value,
        from_cache=from_cache,
    )


def _sweep_stale_entry_temps(path: Path) -> None:
    """Best-effort removal of temp files a killed writer left for one cache entry.

    Only this entry's own temps (``<key>.json.tmp-*`` beside ``path``)
    older than :data:`_STALE_ENTRY_TEMP_AGE_SECONDS`, judged by wall-clock
    time like the file times themselves. Never raises: a missing shard
    directory (the entry's first write), a temp that vanished meanwhile, or
    one that cannot be removed is simply skipped.

    Args:
        path: The cache entry's path.
    """
    cutoff = time.time() - _STALE_ENTRY_TEMP_AGE_SECONDS
    with contextlib.suppress(OSError):
        for stale in path.parent.glob(f"{path.name}.tmp-*"):
            with contextlib.suppress(OSError):
                if stale.stat().st_mtime < cutoff:
                    stale.unlink()


def _base64_decode(value: object) -> bytes:
    """Decode a cache entry's base64 body field.

    Args:
        value: The raw ``body`` field from a decoded JSON entry.

    Returns:
        The decoded bytes.

    Raises:
        TypeError: If ``value`` is not a string.
        binascii.Error: If ``value`` is not valid base64.
    """
    if not isinstance(value, str):
        raise TypeError("cache entry 'body' must be a string")
    return base64.b64decode(value, validate=True)


def _parse_retry_after(value: str | None, *, clock: Callable[[], float]) -> float | None:
    """Parse a ``Retry-After`` header value into a delay in seconds.

    Args:
        value: The raw header value, or ``None`` if absent.
        clock: Callable returning the current unix epoch seconds, used to
            compute a delay from an HTTP-date value.

    Returns:
        The delay in seconds (never negative), or ``None`` if ``value``
        is absent or could not be parsed. Only ASCII digits count as a
        delay: ``str.isdigit`` also accepts ``"²"`` (byte ``0xB2`` decoded
        as Latin-1), which ``float`` then rejects.
    """
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    if stripped.isascii() and stripped.isdigit():
        return float(stripped)
    try:
        parsed = email.utils.parsedate_to_datetime(stripped)
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        return None
    return max(0.0, parsed.timestamp() - clock())


def _answers(status: int, accept_statuses: Collection[int]) -> bool:
    """Return whether a cached response's status answers a call.

    Args:
        status: The cached response's HTTP status.
        accept_statuses: The call's accepted non-2xx statuses.

    Returns:
        ``True`` for a 2xx status or one in ``accept_statuses``.
    """
    return _HTTP_SUCCESS_MIN <= status < _HTTP_SUCCESS_MAX or status in accept_statuses


def _rate_limit_key(url: str) -> str:
    """Return what a 429 cool-down is kept under: ``url``'s host.

    Args:
        url: The request URL.

    Returns:
        The host, or ``url`` itself when it does not parse (its request
        then fails as invalid before anything is sent).
    """
    try:
        return httpx.URL(url).host
    except httpx.InvalidURL:
        return url


def _valid_cooldowns(document: object, now: float) -> dict[str, float]:
    """Validate the content of :data:`RATE_LIMIT_FILENAME`.

    Anything unexpected is ignored rather than trusted, so a corrupt or
    planted file can never stop requests for longer than a real 429 would.

    Args:
        document: The decoded file, or ``None``.
        now: The current time, epoch seconds.

    Returns:
        Host to until (epoch seconds) for every entry of a version
        :data:`RATE_LIMIT_VERSION` document whose host is a string of 1 to
        :data:`_RATE_LIMIT_MAX_HOST_CHARS` characters and whose until is a
        number after ``now`` and at most the longest cool-down (plus
        :data:`_RATE_LIMIT_FUTURE_SKEW_SECONDS`) ahead. A JSON boolean
        reads as 0 or 1, long past, so it is ignored like any old entry.
    """
    if not isinstance(document, dict) or document.get("version") != RATE_LIMIT_VERSION:
        return {}
    hosts = document.get("hosts")
    if not isinstance(hosts, dict):
        return {}
    latest = now + _RATE_LIMIT_MAX_COOLDOWN_SECONDS + _RATE_LIMIT_FUTURE_SKEW_SECONDS
    return {
        host: float(until)
        for host, until in hosts.items()
        if isinstance(host, str)
        and 1 <= len(host) <= _RATE_LIMIT_MAX_HOST_CHARS
        and isinstance(until, int | float)
        and now < until <= latest
    }


def _request_error_hint(exc: httpx.RequestError) -> str | None:
    """Explain a non-retried request failure, when there is more to say.

    Args:
        exc: The ``httpx.RequestError`` (not a ``TransportError``) that
            ended the fetch.

    Returns:
        A hint for a ``TooManyRedirects`` redirect loop, a refused
        HTTPS -> non-HTTPS redirect or a redirect to an invalid URL, else
        ``None``.
    """
    if isinstance(exc, httpx.TooManyRedirects):
        last_url = None
        with contextlib.suppress(RuntimeError):
            # Drop the query string: it is the last hop of a
            # redirect loop and may not be this request's own
            # `params`, so it is not ours to display in full.
            last_url = _display_url(str(exc.request.url.copy_with(query=None)), None)
        return "the server (or a proxy/captive portal) is redirecting in a loop" + (
            f" (last URL: {last_url})" if last_url else ""
        )
    if isinstance(exc, _InsecureRedirectError):
        return (
            f"the server (or a proxy/captive portal) redirected to {exc.target}, "
            "which would drop HTTPS; check the URL and your network"
        )
    if isinstance(exc, _InvalidRedirectError):
        return "the server (or a proxy/captive portal) sent a redirect to an invalid URL"
    return None


def _status_error(
    response: httpx.Response,
    *,
    url: str,
    source: str | None,
    clock: Callable[[], float],
) -> HttpError | None:
    """Build the error for a response status that is neither success nor retried.

    Called only for a status below :data:`RETRY_STATUS_MIN` (a 5xx is
    retried by the caller first).

    Args:
        response: The server's response.
        url: The request URL, for the message.
        source: A short label identifying the calling datasource.
        clock: Callable returning the current unix epoch seconds, for
            an HTTP-date ``Retry-After``.

    Returns:
        A :class:`RateLimitError` for HTTP 429, an :class:`HttpError` for
        any other 4xx or a non-2xx status, or ``None`` for a 2xx.
    """
    status = response.status_code

    if status == _HTTP_RATE_LIMITED:
        return RateLimitError(
            f"{url} returned HTTP 429 (rate limited)",
            url=str(response.url),
            status_code=status,
            source=source,
            retry_after=_parse_retry_after(response.headers.get("retry-after"), clock=clock),
            hint=_RATE_LIMIT_HINT,
        )

    if _HTTP_CLIENT_ERROR_MIN <= status < _HTTP_CLIENT_ERROR_MAX:
        return HttpError(
            f"{url} returned HTTP {status}",
            url=str(response.url),
            status_code=status,
            source=source,
        )

    if not (_HTTP_SUCCESS_MIN <= status < _HTTP_SUCCESS_MAX):
        return HttpError(
            f"{url} returned unexpected HTTP {status}",
            url=str(response.url),
            status_code=status,
            source=source,
        )
    return None


class CachedHTTPClient:
    """Disk-backed TTL cache wrapping ``httpx.Client``.

    This is the only outbound-HTTP path in meshprovision. It enforces:

    - **TLS verification always on.** There is no ``verify`` parameter --
      the internal ``httpx.Client`` is always constructed with
      ``verify=True`` and an explicit ``httpx.Timeout``. This is an
      invariant of the class, not an option.
    - **Redirect bodies are never read.** The internal ``httpx.Client``
      is built with ``follow_redirects=False`` and this class follows up
      to :data:`_MAX_REDIRECTS` hops itself, closing each 3xx response
      unread: ``httpx`` would read every hop's body in full, past
      :data:`MAX_RESPONSE_BYTES`, and keep it in ``response.history``.
    - **No HTTPS downgrade on redirect.** A response hook refuses a
      redirect from an ``https`` URL to a non-``https`` URL before it is
      sent; the call fails with :class:`HttpError` (not retried, nothing
      cached). An externally supplied ``client`` gets no such hook -- its
      redirect policy is the caller's responsibility.
    - **A required, non-empty User-Agent.** ``user_agent`` embeds the
      operator's contact string that lorastats.pl requires; a blank
      value raises :class:`MissingContactError` before any request can
      be sent, and a caller-supplied ``User-Agent`` in a per-call
      ``headers`` mapping is ignored (with a debug log) rather than
      silently overriding it.
    - **A disk-backed TTL cache**, keyed by :func:`cache_key`. A fresh
      hit costs zero network calls; a stale or absent entry triggers a
      network fetch that is written back (2xx responses only).
    - **Exponential backoff** on 5xx responses and network-transport
      errors only -- never on 4xx, which is never retried, nor on a status
      the call accepts (``accept_statuses``), which is returned like a 2xx.
    - **A per-host cool-down after HTTP 429.** A host that answered 429 is
      not asked again for its ``Retry-After`` delay
      (:data:`_RATE_LIMIT_DEFAULT_COOLDOWN_SECONDS` without a usable one,
      at most :data:`_RATE_LIMIT_MAX_COOLDOWN_SECONDS`) by this instance
      nor by any other using the same cache directory: the cool-down is
      kept in :data:`RATE_LIMIT_FILENAME`, read before every request. A
      request to it meanwhile raises :class:`RateLimitCoolingDownError`
      without being sent, so neither a ``--watch`` loop nor a cron'd run
      can keep asking. ``force_refresh`` and a zero TTL do not bypass it;
      fresh cache entries are still served.

    Attributes are exposed as read-only properties; the client itself is
    otherwise stateful (it owns cache-hit/miss counters, the 429
    cool-downs and, unless an
    external ``httpx.Client`` was supplied, an ``httpx.Client``
    connection pool that must be closed via :meth:`close` or the context
    manager protocol).
    """

    def __init__(
        self,
        *,
        cache_dir: Path,
        user_agent: str,
        ttl: float = DEFAULT_TTL_SECONDS,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_base: float = DEFAULT_BACKOFF_BASE,
        backoff_max: float = DEFAULT_BACKOFF_MAX,
        force_refresh: bool = False,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Initialize the client.

        Args:
            cache_dir: Directory the on-disk cache is stored under. Its
                immediate children are two-hex-character shard
                directories; it is created (with parents) on first use
                and chmod'd to ``0o700`` on the first write, since
                responses carry node data.
            user_agent: The ``User-Agent`` header sent on every request.
                Must be non-empty after stripping whitespace.
            ttl: Default freshness window, in seconds, used when a call
                does not pass an explicit ``ttl``.
            timeout: Per-request ``httpx`` timeout, in seconds.
            max_retries: Number of retries after the first attempt
                (total attempts = ``max_retries + 1``).
            backoff_base: Base delay, in seconds, for exponential
                backoff between retries.
            backoff_max: Maximum delay, in seconds, between retries.
            force_refresh: Default value for a call's ``force_refresh``
                when not passed explicitly. Bypasses cache reads but
                still writes the refreshed entry.
            client: An existing ``httpx.Client`` to use instead of
                constructing one. When supplied, this instance does not
                own it and :meth:`close` will not close it. Intended for
                tests (``respx``-mocked clients). It is used as-is: the
                HTTPS-downgrade redirect refusal is not added to it, and
                if it follows redirects itself their bodies are read.
            sleep: Callable used to wait between retries. Overridable for
                deterministic tests.
            clock: Callable returning the current unix epoch seconds.
                Overridable for deterministic tests.

        Raises:
            MissingContactError: If ``user_agent`` is empty or
                whitespace-only after stripping.
        """
        stripped_user_agent = user_agent.strip()
        if not stripped_user_agent:
            raise MissingContactError()

        self._user_agent = stripped_user_agent
        self._cache_dir = cache_dir
        self._ttl = ttl
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._backoff_max = backoff_max
        self._force_refresh = force_refresh
        self._sleep = sleep
        self._clock = clock
        self._stats = CacheStats()
        self._chmod_done = False
        self._cooldown_until: Mapping[str, float] = {}

        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            verify=True,
            headers={"User-Agent": user_agent, "Accept": "application/json"},
            event_hooks={"response": [_refuse_insecure_redirect]},
        )

    @property
    def cache_dir(self) -> Path:
        """The directory the on-disk cache is stored under.

        Returns:
            The configured cache directory.
        """
        return self._cache_dir

    @property
    def ttl(self) -> float:
        """The default freshness window, used when a call passes no ``ttl``.

        Returns:
            The constructor's ``ttl``, in seconds.
        """
        return self._ttl

    @property
    def stats(self) -> CacheStats:
        """A snapshot of this client's cumulative cache/network counters.

        Returns:
            The current :class:`CacheStats`.
        """
        return self._stats

    def path_for_key(self, key: str) -> Path:
        """Return the on-disk path for a cache key.

        Args:
            key: A cache key produced by :func:`cache_key`.

        Returns:
            ``cache_dir / key[:2] / f"{key}.json"``. A 2-hex-character
            shard keeps individual directories small.
        """
        return self._cache_dir / key[:_CACHE_SHARD_WIDTH] / f"{key}.json"

    def evict(self, key: str) -> None:
        """Drop one cache entry, best-effort; never raises.

        For a 2xx response the caller rejected (see the module docstring's
        datasource contract): left in place it would be served again until
        the TTL expires.

        Args:
            key: The entry's cache key, for example
                :attr:`CachedResponse.cache_key`.
        """
        path = self.path_for_key(key)
        try:
            path.unlink()
        except FileNotFoundError:
            return
        except OSError as exc:
            _logger.warning("could not drop rejected cache entry %s: %s", path, exc)
            return
        _logger.debug("dropped rejected cache entry %s", path)

    def get(
        self,
        url: str,
        *,
        params: Mapping[str, object] | None = None,
        headers: Mapping[str, str] | None = None,
        ttl: float | None = None,
        force_refresh: bool | None = None,
        source: str | None = None,
        accept_statuses: Collection[int] = (),
        max_bytes: int = MAX_RESPONSE_BYTES,
        max_retries: int | None = None,
        store: bool = True,
    ) -> CachedResponse:
        """Perform a cached ``GET`` request.

        Args:
            url: The request URL.
            params: Query parameters.
            headers: Extra request headers, merged over the client's
                defaults (call-site wins), except ``User-Agent`` which is
                always the client's own.
            ttl: Freshness window override for this call, in seconds.
                Defaults to the client's constructor ``ttl``.
            force_refresh: Whether to bypass the cache read for this
                call. Defaults to the client's configured default. The
                fetched response is still written to the cache either
                way (unless ``store`` is ``False``).
            source: A short label (``"loranet"``, ``"lorastats"``) used
                in error messages to identify the calling datasource.
            accept_statuses: Non-2xx statuses that are an answer for this
                call rather than a failure; see :meth:`request`.
            max_bytes: The largest response body accepted for this call;
                see :meth:`request`.
            max_retries: Retries for this call; see :meth:`request`.
            store: Whether to write the fetched response to the disk
                cache; see :meth:`request`.

        Returns:
            The cached or freshly fetched response. If the fetched
            response cannot be written to the cache, a WARNING is
            logged and the response is still returned uncached.

        Raises:
            SettingsError: If the resolved ``ttl`` is negative.
            ValueError: If ``accept_statuses`` contains 429.
            HttpError: If the request fails and cannot be served from a
                fresh cache entry.
            RateLimitError: If the server responds with HTTP 429, or the
                host is still cooling down from one, also received by
                another process (a :class:`RateLimitCoolingDownError`;
                nothing is sent).
        """
        return self.request(
            "GET",
            url,
            params=params,
            headers=headers,
            ttl=ttl,
            force_refresh=force_refresh,
            source=source,
            accept_statuses=accept_statuses,
            max_bytes=max_bytes,
            max_retries=max_retries,
            store=store,
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, object] | None = None,
        headers: Mapping[str, str] | None = None,
        ttl: float | None = None,
        force_refresh: bool | None = None,
        source: str | None = None,
        accept_statuses: Collection[int] = (),
        max_bytes: int = MAX_RESPONSE_BYTES,
        max_retries: int | None = None,
        store: bool = True,
    ) -> CachedResponse:
        """Perform a cached HTTP request of any method.

        Args:
            method: The HTTP method (``"GET"``, ``"POST"``, etc.).
            url: The request URL.
            params: Query parameters.
            headers: Extra request headers, merged over the client's
                defaults (call-site wins), except ``User-Agent`` which is
                always the client's own -- a caller-supplied value is
                ignored, with a debug log, so no code path can send a
                different contact string than the one this client was
                constructed with.
            ttl: Freshness window override for this call, in seconds.
                Defaults to the client's constructor ``ttl``.
            force_refresh: Whether to bypass the cache read for this
                call. Defaults to the client's configured default. The
                fetched response is still written to the cache either
                way (unless ``store`` is ``False``), refreshing the entry
                for the next call.
            source: A short label (``"loranet"``, ``"lorastats"``) used
                in error messages to identify the calling datasource.
            accept_statuses: Non-2xx statuses that are an answer for this
                call rather than a failure (lorastats.pl's per-node status
                endpoint answers 404 for a node it does not know): such a
                response is neither retried nor raised, and is cached and
                returned like a 2xx. A cached entry with a status outside
                2xx and this set is a miss. Never 429, whose cool-down
                must hold.
            max_bytes: The largest response body accepted for this call,
                counted after decoding; a larger one fails like one past
                :data:`MAX_RESPONSE_BYTES`, which a call can only lower.
            max_retries: Retries of a 5xx or transport failure for this
                call; defaults to the client's constructor ``max_retries``.
            store: Write the fetched response to the disk cache (the
                default). ``False`` for an answer the caller uses once and
                drops: it is never written, so nothing is left behind if
                the process dies, and it costs no disk write.

        Returns:
            The cached or freshly fetched response. If the fetched
            response cannot be written to the cache, a WARNING is
            logged and the response is still returned uncached.

        Raises:
            SettingsError: If the resolved ``ttl`` is negative.
            ValueError: If ``accept_statuses`` contains 429.
            HttpError: If the request fails and cannot be served from a
                fresh cache entry.
            RateLimitError: If the server responds with HTTP 429, or the
                host is still cooling down from one, also received by
                another process (a :class:`RateLimitCoolingDownError`;
                nothing is sent).
        """
        effective_ttl = self._ttl if ttl is None else ttl
        if effective_ttl < 0:
            raise SettingsError("Cache TTL must not be negative.")
        if _HTTP_RATE_LIMITED in accept_statuses:
            raise ValueError("HTTP 429 cannot be an accepted status")
        refresh = self._force_refresh if force_refresh is None else force_refresh

        key = cache_key(method, url, params)
        path = self.path_for_key(key)

        if not refresh:
            entry = self._read_entry(path, cache_key_value=key)
            if (
                entry is not None
                and _answers(entry.status_code, accept_statuses)
                and entry.is_fresh(effective_ttl, now=self._clock())
            ):
                self._stats = replace(self._stats, hits=self._stats.hits + 1)
                _logger.debug("cache hit for %s %s (key=%s)", method, url, key)
                return replace(entry, from_cache=True)

        self._stats = replace(self._stats, misses=self._stats.misses + 1)
        _logger.debug("cache miss for %s %s (key=%s)", method, url, key)

        merged_headers = self._merge_headers(headers)
        response = self._fetch_with_retry(
            method,
            url,
            params=params,
            headers=merged_headers,
            source=source,
            cache_key_value=key,
            accept_statuses=accept_statuses,
            max_bytes=min(max_bytes, MAX_RESPONSE_BYTES),
            max_retries=self._max_retries if max_retries is None else max_retries,
        )
        if not store:
            # The root's 0o700 holds whatever the first call of a process was.
            self._chmod_cache_root()
            return replace(response, from_cache=False)
        try:
            self._write_entry(path, response)
        except CacheError as exc:
            _logger.warning("%s; returning the fetched response uncached", exc.user_message)
        else:
            self._stats = replace(self._stats, writes=self._stats.writes + 1)
        return replace(response, from_cache=False)

    def close(self) -> None:
        """Close the underlying ``httpx.Client``.

        A no-op when this instance was constructed with an externally
        supplied ``client`` (which it does not own).
        """
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> CachedHTTPClient:
        """Enter the context manager.

        Returns:
            This instance.
        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Exit the context manager, closing the client via :meth:`close`.

        Args:
            exc_type: The exception type, if the block raised.
            exc: The exception instance, if the block raised.
            tb: The traceback, if the block raised.
        """
        self.close()

    def _merge_headers(self, headers: Mapping[str, str] | None) -> dict[str, str]:
        """Merge per-call headers over the client defaults.

        A caller-supplied ``User-Agent`` (any casing) is dropped, with a
        debug log, so the operator's contact string can never be
        overridden per call. The contact ``User-Agent`` this instance was
        constructed with is then set explicitly on the returned mapping,
        which is passed as *request-level* headers to ``httpx`` -- this
        holds even when an externally supplied ``httpx.Client`` (for
        example a test double) has no ``User-Agent`` of its own set as a
        client-level default.

        Args:
            headers: Extra request headers for this call, or ``None``.

        Returns:
            The merged headers to send, with ``User-Agent`` always set to
            this instance's contact string.
        """
        merged: dict[str, str] = {}
        for name, value in (headers or {}).items():
            if name.strip().lower() == "user-agent":
                _logger.debug("ignoring caller-supplied User-Agent %r", value)
                continue
            merged[name] = value
        merged["User-Agent"] = self._user_agent
        return merged

    def _read_entry(self, path: Path, *, cache_key_value: str) -> CachedResponse | None:
        """Read and decode one on-disk cache entry.

        Args:
            path: Path to the cache entry file.
            cache_key_value: The cache key this path corresponds to.

        Returns:
            The decoded :class:`CachedResponse`, or ``None`` on a miss
            (missing file, corrupt entry, or version mismatch -- all of
            which are treated as a miss, never a crash).
        """
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            _logger.warning("could not read cache entry %s: %s", path, exc)
            return None

        try:
            entry = json.loads(raw)
            if not isinstance(entry, dict):
                raise TypeError("cache entry root must be an object")
            if entry.get("version") != CACHE_ENTRY_VERSION:
                raise ValueError(f"unsupported cache entry version: {entry.get('version')!r}")
            return _entry_to_response(entry, cache_key_value=cache_key_value, from_cache=True)
        except (
            json.JSONDecodeError,
            UnicodeDecodeError,
            KeyError,
            TypeError,
            ValueError,
            binascii.Error,
        ) as exc:
            _logger.debug("corrupt cache entry %s, treating as miss: %s", path, exc)
            with contextlib.suppress(OSError):
                path.unlink()
            return None

    def _write_entry(self, path: Path, response: CachedResponse) -> None:
        """Atomically write one cache entry to disk.

        Args:
            path: Path to write the cache entry to.
            response: The response to persist. Only a 2xx response, or one
                whose status the call accepted, should ever be passed here.

        Raises:
            CacheError: If the write fails. Write failures are raised,
                not swallowed, since a silently dead cache means every
                run re-downloads the full dataset.
        """
        self._chmod_cache_root()

        entry = {
            "version": CACHE_ENTRY_VERSION,
            "key": response.cache_key,
            "method": response.method,
            "url": response.url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "fetched_at": response.fetched_at,
            "encoding": "base64",
            "body": base64.b64encode(response.content).decode("ascii"),
        }
        _sweep_stale_entry_temps(path)
        tmp = path.with_name(f"{path.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_bytes(json.dumps(entry).encode("utf-8"))
            tmp.replace(path)
        except OSError as exc:
            raise CacheError(
                f"Could not write the HTTP cache entry: {exc}",
                path=str(path),
                hint="Set MESHPROVISION_CACHE_DIR to a writable directory.",
            ) from exc
        finally:
            # Also on Ctrl-C, which the handler above does not catch; after a
            # successful replace there is nothing left to remove.
            with contextlib.suppress(OSError):
                tmp.unlink(missing_ok=True)

    def _chmod_cache_root(self) -> None:
        """Restrict the cache root to owner-only access, once per instance.

        Ignores a ``PermissionError`` on platforms that do not support
        this (logged at debug); the cache still functions, just with
        looser filesystem permissions.

        Callers must invoke this *before* creating any subdirectory
        under the root: the root would otherwise be created at the
        process umask by a ``mkdir(parents=True)`` and only tightened
        afterwards.
        """
        if self._chmod_done:
            return
        self._chmod_done = True
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            self._cache_dir.chmod(_CACHE_ROOT_MODE)
        except OSError as exc:
            _logger.debug("could not chmod cache root %s: %s", self._cache_dir, exc)

    def _fetch_with_retry(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, object] | None,
        headers: Mapping[str, str],
        source: str | None,
        cache_key_value: str,
        accept_statuses: Collection[int],
        max_bytes: int,
        max_retries: int,
    ) -> CachedResponse:
        """Perform the network fetch, retrying on 5xx and transport errors.

        Args:
            method: The HTTP method.
            url: The request URL.
            params: Query parameters.
            headers: Headers to send, already merged and User-Agent-safe.
            source: A short label identifying the calling datasource, for
                error messages.
            cache_key_value: The cache key this fetch is for.
            accept_statuses: Statuses returned as they are, never retried
                or raised (see :meth:`request`).
            max_bytes: The largest response body accepted.
            max_retries: Retries after the first attempt.

        Returns:
            The freshly fetched response, with ``from_cache=False``.

        Raises:
            HttpError: On a non-retryable failure (including a
                ``TooManyRedirects`` redirect loop, a refused HTTPS ->
                non-HTTPS redirect, a redirect to an invalid URL, an
                undecodable response body, or one
                larger than ``max_bytes``), or
                after exhausting retries on a retryable transport error.
            RateLimitError: If the server responds with HTTP 429 (never
                retried automatically; starts the host's cool-down), or
                ``url``'s host is still cooling down from one (a
                :class:`RateLimitCoolingDownError`; nothing is sent).
        """
        self._refuse_while_rate_limited(url, source=source)
        last_exc: Exception | None = None
        display_url = _display_url(url, params)
        for attempt in range(max_retries + 1):
            self._stats = replace(self._stats, network_requests=self._stats.network_requests + 1)
            _logger.info("fetching %s %s (attempt %d)", method, display_url, attempt + 1)
            try:
                # `params` is typed `Mapping[str, object]` at this class's public
                # boundary (any stringifiable value is accepted, matching
                # `cache_key`'s normalization); httpx's own parameter type is
                # narrower, so the value is passed through as `Any` here.
                httpx_params = cast("Any", params)
                request = self._client.build_request(
                    method, url, params=httpx_params, headers=headers
                )
                # Streamed, so the body is read (and decoded) under the cap
                # instead of whole; a transport error mid-body is still
                # retried below, as with a buffered request.
                response = self._send_following_redirects(request)
                try:
                    content = _read_capped(response, max_bytes)
                finally:
                    response.close()
            except (httpx.InvalidURL, httpx.UnsupportedProtocol) as exc:
                raise HttpError(
                    f"Request to {url} is invalid: {exc}", url=url, source=source
                ) from exc
            except httpx.TransportError as exc:
                last_exc = exc
                if attempt == max_retries:
                    raise HttpError(
                        f"Request to {url} failed after {attempt + 1} attempt(s): {exc}",
                        url=url,
                        source=source,
                    ) from exc
                self._stats = replace(self._stats, retries=self._stats.retries + 1)
                self._backoff(attempt, url=url)
                continue
            except httpx.RequestError as exc:
                # Deterministic for a given server state (a redirect loop, a
                # refused HTTPS downgrade, an invalid redirect target, an
                # undecodable body), unlike `TransportError` above -- so this
                # is not retried. Must stay after the `TransportError` arm,
                # since `TransportError` is itself a `RequestError` subclass.
                raise HttpError(
                    f"Request to {url} failed: {exc}",
                    url=url,
                    source=source,
                    hint=_request_error_hint(exc),
                ) from exc

            status = response.status_code
            accepted = status in accept_statuses

            if status >= RETRY_STATUS_MIN and not accepted:
                if attempt == max_retries:
                    raise HttpError(
                        f"{url} returned HTTP {status} after {attempt + 1} attempt(s)",
                        url=str(response.url),
                        status_code=status,
                        source=source,
                    )
                self._stats = replace(self._stats, retries=self._stats.retries + 1)
                self._backoff(attempt, url=url)
                continue

            status_error = (
                None
                if accepted
                else _status_error(response, url=url, source=source, clock=self._clock)
            )
            if isinstance(status_error, RateLimitError):
                self._start_rate_limit_cooldown(url, status_error.retry_after)
            if status_error is not None:
                raise status_error

            return CachedResponse(
                status_code=status,
                headers={
                    name: value
                    for name, value in response.headers.items()
                    if name.lower() in PERSISTED_HEADERS
                },
                content=content,
                url=str(response.url),
                method=method.strip().upper(),
                fetched_at=self._clock(),
                cache_key=cache_key_value,
                from_cache=False,
            )

        # Unreachable: the loop above always returns or raises before
        # exhausting its range (the final iteration's branches all
        # terminate). This satisfies mypy's warn_unreachable by naming
        # the last transport error seen, if any.
        raise HttpError(
            f"Request to {url} failed after retries: {last_exc}", url=url, source=source
        )

    def _refuse_while_rate_limited(self, url: str, *, source: str | None) -> None:
        """Refuse a request to a host still cooling down after an HTTP 429.

        The cool-down file is read on every call (it is tiny), so a long
        running ``--watch`` also honours a 429 another process received.

        Args:
            url: The request URL.
            source: A short label identifying the calling datasource.

        Raises:
            RateLimitCoolingDownError: If ``url``'s host answered 429 to
                this instance or to another process using the same cache
                directory, and its cool-down has not ended. Nothing is sent.
        """
        host = _rate_limit_key(url)
        untils = [
            until
            for until in (self._cooldown_until.get(host), self._persisted_cooldowns().get(host))
            if until is not None
        ]
        if not untils:
            return
        remaining = max(untils) - self._clock()
        if remaining <= 0:
            return
        raise RateLimitCoolingDownError(
            f"{url} not requested: {host} rate-limited this client; "
            f"retrying after {remaining:.0f}s",
            url=url,
            source=source,
            retry_after=remaining,
            hint=_RATE_LIMIT_HINT,
        )

    def _start_rate_limit_cooldown(self, url: str, retry_after: float | None) -> None:
        """Stop asking ``url``'s host for as long as its HTTP 429 asked.

        Args:
            url: The request URL that was answered with 429.
            retry_after: The parsed ``Retry-After`` delay (never negative), or
                ``None``.
        """
        delay = _RATE_LIMIT_DEFAULT_COOLDOWN_SECONDS if retry_after is None else retry_after
        host = _rate_limit_key(url)
        now = self._clock()
        until = now + min(delay, _RATE_LIMIT_MAX_COOLDOWN_SECONDS)
        self._cooldown_until = {**self._cooldown_until, host: until}
        self._persist_cooldown(host, until, now)

    def _persisted_cooldowns(self, now: float | None = None) -> dict[str, float]:
        """Read the cool-downs of every process from :data:`RATE_LIMIT_FILENAME`.

        Args:
            now: The current time, epoch seconds; read from the clock only
                when the file exists, when not given.

        Returns:
            The running cool-downs, host to until (see
            :func:`_valid_cooldowns`); empty when the file is missing,
            unreadable or not a cool-down file.
        """
        document = read_json(
            self._cache_dir / RATE_LIMIT_FILENAME,
            max_bytes=_RATE_LIMIT_MAX_FILE_BYTES,
            what=_RATE_LIMIT_WHAT,
        )
        if document is None:
            return {}
        return _valid_cooldowns(document, self._clock() if now is None else now)

    def _persist_cooldown(self, host: str, until: float, now: float) -> None:
        """Add ``host``'s cool-down to :data:`RATE_LIMIT_FILENAME` for every process.

        The file is re-read first, so another process's cool-downs are
        kept; ended ones are dropped and only the
        :data:`_RATE_LIMIT_MAX_HOSTS` ending last stay. A failed write is
        only logged at DEBUG: this instance's own cool-down still applies.

        Args:
            host: The host that answered 429.
            until: When its cool-down ends, epoch seconds.
            now: The current time, epoch seconds.
        """
        hosts = self._persisted_cooldowns(now)
        hosts[host] = max(until, hosts.get(host, until))
        latest = sorted(hosts.items(), key=lambda item: item[1], reverse=True)
        self._chmod_cache_root()
        write_json(
            self._cache_dir / RATE_LIMIT_FILENAME,
            {"version": RATE_LIMIT_VERSION, "hosts": dict(latest[:_RATE_LIMIT_MAX_HOSTS])},
            what=_RATE_LIMIT_WHAT,
        )

    def _send_following_redirects(self, request: httpx.Request) -> httpx.Response:
        """Send ``request`` streamed, following redirects without reading their bodies.

        Each hop is the ``next_request`` ``httpx`` builds for a 3xx (so its
        method, header and cross-origin rules stay ``httpx``'s), sent after
        the 3xx response is closed unread. The client's response hooks run
        on every hop, so a refused HTTPS downgrade is never sent.

        Args:
            request: The first request of the chain.

        Returns:
            The final, still unread response. The caller closes it.

        Raises:
            httpx.TooManyRedirects: If the chain is longer than
                :data:`_MAX_REDIRECTS` hops.
        """
        response = self._client.send(request, stream=True)
        hops = 0
        while response.next_request is not None:
            next_request = response.next_request
            response.close()
            hops += 1
            if hops > _MAX_REDIRECTS:
                raise httpx.TooManyRedirects(
                    "Exceeded maximum allowed redirects.", request=next_request
                )
            response = self._client.send(next_request, stream=True)
        return response

    def _backoff(self, attempt: int, *, url: str) -> None:
        """Sleep for an exponential backoff delay before the next retry.

        Args:
            attempt: The zero-based attempt index that just failed.
            url: The request URL, for the warning log.
        """
        delay = min(self._backoff_max, self._backoff_base * (2**attempt))
        _logger.warning(
            "retrying %s after attempt %d failed; waiting %.2fs", url, attempt + 1, delay
        )
        self._sleep(delay)
