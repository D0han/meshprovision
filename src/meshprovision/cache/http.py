"""Disk-backed TTL cache wrapping ``httpx`` -- the sole outbound-HTTP path.

:class:`CachedHTTPClient` is the *only* place in meshprovision that is
allowed to open a socket to loranet.pl or lorastats.pl. Every datasource
call flows through :meth:`CachedHTTPClient.get` or
:meth:`CachedHTTPClient.request`, which enforces TLS verification,
explicit timeouts, exponential backoff on 5xx/network failures only, and
a disk-backed response cache keyed by method + URL + sorted params.

TLS verification is an invariant of this class, not an option: there is
deliberately no ``verify`` constructor parameter. The internal
``httpx.Client`` is always built with ``verify=True``.

**TTL precedence.** This module does not know about
:class:`meshprovision.config.settings.Settings` -- the ``cache`` group is
independent of ``config`` by design (see the layer's cross-cutting
notes). :func:`resolve_ttl` instead accepts loose values and resolves the
precedence chain ``explicit > env (MESHPROVISION_CACHE_TTL) > config >
DEFAULT_TTL_SECONDS``. The CLI layer is expected to wire it as::

    ttl = resolve_ttl(config_ttl=settings.cache_ttl, explicit=cli_ttl)
    client = CachedHTTPClient(
        cache_dir=..., user_agent=..., ttl=ttl, force_refresh=no_cache or force_refresh
    )

where ``--cache-ttl`` supplies ``explicit``, and ``--no-cache`` /
``--force-refresh`` both map to ``force_refresh=True`` (bypassing cache
*reads* only -- a forced fetch is still written to disk, refreshing the
entry for the next run).

**On-disk format.** Each cache entry is one JSON file, holding the
response's status code, a small allow-listed subset of headers, the body
base64-encoded (so binary content or a mis-declared encoding can never
corrupt the file), and metadata (``version``, ``key``, ``fetched_at``).
Only 2xx responses are ever written. A 12.7 MB body (the loranet.pl node
dump) base64s to roughly 17 MB on disk and is held fully in memory during
read/write; this is a deliberate simplicity trade-off for a low-volume,
single-operator tool and should not be "optimised" into a streaming
format without a concrete reason.

**Contract for the datasources layer** (``datasources/loranet.py``,
``datasources/lorastats.py``, written in a later layer): call
``client.get(url, params=..., source=...)`` once per logical request and
always call :meth:`CachedResponse.json` rather than trusting the HTTP
status code -- lorastats.pl returns HTTP 200 with an HTML body for
invalid paths (a "soft 404"), and only :meth:`CachedResponse.json`
surfaces that as an error. Cache keys include sorted params, so
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
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

import httpx

from meshprovision.errors import (
    CacheError,
    HttpError,
    InvalidResponseError,
    MissingContactError,
    RateLimitError,
    SettingsError,
)

if TYPE_CHECKING:
    from types import TracebackType

__all__ = [
    "CACHE_ENTRY_VERSION",
    "CACHE_TTL_ENV",
    "DEFAULT_BACKOFF_BASE",
    "DEFAULT_BACKOFF_MAX",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_TTL_SECONDS",
    "PERSISTED_HEADERS",
    "RETRY_STATUS_MIN",
    "CacheStats",
    "CachedHTTPClient",
    "CachedResponse",
    "cache_key",
    "resolve_ttl",
]

_logger = logging.getLogger(__name__)

CACHE_TTL_ENV: Final[str] = "MESHPROVISION_CACHE_TTL"
"""Environment variable that overrides the configured cache TTL."""

CACHE_ENTRY_VERSION: Final[int] = 1
"""On-disk cache entry schema version. A mismatch is treated as a miss."""

DEFAULT_TTL_SECONDS: Final[float] = 300.0
"""Default freshness window for a cache entry, in seconds."""

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

_HTTP_RATE_LIMITED: Final[int] = 429
_HTTP_CLIENT_ERROR_MIN: Final[int] = 400
_HTTP_CLIENT_ERROR_MAX: Final[int] = 500
_HTTP_SUCCESS_MIN: Final[int] = 200
_HTTP_SUCCESS_MAX: Final[int] = 300


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
    pairs: list[tuple[str, str]] = []
    if params:
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
    parts.extend(f"{k}={v}" for k, v in sorted(pairs))
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def resolve_ttl(
    *,
    config_ttl: float | None = None,
    explicit: float | None = None,
    environ: Mapping[str, str] | None = None,
) -> float:
    """Resolve the effective cache TTL from the precedence chain.

    Precedence, highest first: ``explicit`` > the ``MESHPROVISION_CACHE_TTL``
    environment variable > ``config_ttl`` > :data:`DEFAULT_TTL_SECONDS`.

    Args:
        config_ttl: TTL from a loaded ``Settings`` object, when available.
        explicit: TTL requested explicitly at the call site (for example
            the CLI's ``--cache-ttl`` flag).
        environ: Environment mapping to read ``MESHPROVISION_CACHE_TTL``
            from. Defaults to ``os.environ``.

    Returns:
        The resolved TTL in seconds. ``0.0`` is a legal result and means
        "always refetch, still write".

    Raises:
        SettingsError: If the environment variable is set but is not a
            valid number, or if the resolved value is negative.
    """
    env = environ if environ is not None else os.environ
    raw = env.get(CACHE_TTL_ENV)

    value: float
    if explicit is not None:
        value = explicit
    elif raw is not None and raw.strip():
        try:
            value = float(raw)
        except ValueError as exc:
            raise SettingsError(
                f"{CACHE_TTL_ENV} must be a number of seconds, got {raw!r}"
            ) from exc
    elif config_ttl is not None:
        value = config_ttl
    else:
        value = DEFAULT_TTL_SECONDS

    if value < 0:
        raise SettingsError("Cache TTL must not be negative.")
    return float(value)


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
            ``True`` if :meth:`age` is less than or equal to ``ttl``.
        """
        return self.age(now=now) <= ttl

    def text(self, *, encoding: str = "utf-8") -> str:
        """Decode the response body as text.

        Args:
            encoding: The text encoding to decode with.

        Returns:
            The decoded body.
        """
        return self.content.decode(encoding)

    def json(self) -> Any:
        """Parse the response body as JSON.

        This is the load-bearing call for every datasource: lorastats.pl
        returns HTTP 200 with an HTML body for invalid request paths (a
        "soft 404"), so datasources must call this method and trust its
        error rather than trusting :attr:`status_code`.

        Returns:
            The decoded JSON value.

        Raises:
            InvalidResponseError: If the body is not valid JSON.
        """
        try:
            return json.loads(self.content)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
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
        is absent or could not be parsed.
    """
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    if stripped.isdigit():
        return float(stripped)
    try:
        parsed = email.utils.parsedate_to_datetime(stripped)
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        return None
    return max(0.0, parsed.timestamp() - clock())


class CachedHTTPClient:
    """Disk-backed TTL cache wrapping ``httpx.Client``.

    This is the only outbound-HTTP path in meshprovision. It enforces:

    - **TLS verification always on.** There is no ``verify`` parameter --
      the internal ``httpx.Client`` is always constructed with
      ``verify=True``, ``follow_redirects=True``, and an explicit
      ``httpx.Timeout``. This is an invariant of the class, not an
      option.
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
      errors only -- never on 4xx, which is never retried.

    Attributes are exposed as read-only properties; the client itself is
    otherwise stateful (it owns cache-hit/miss counters and, unless an
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
                tests (``respx``-mocked clients).
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
        self._timeout = timeout
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._backoff_max = backoff_max
        self._force_refresh = force_refresh
        self._sleep = sleep
        self._clock = clock
        self._stats = CacheStats()
        self._chmod_done = False

        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            verify=True,
            headers={"User-Agent": user_agent, "Accept": "application/json"},
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
        """The default TTL used when a call does not pass an explicit one.

        Returns:
            The default TTL, in seconds.
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

    def get(
        self,
        url: str,
        *,
        params: Mapping[str, object] | None = None,
        headers: Mapping[str, str] | None = None,
        ttl: float | None = None,
        force_refresh: bool | None = None,
        source: str | None = None,
    ) -> CachedResponse:
        """Perform a cached ``GET`` request.

        Args:
            url: The request URL.
            params: Query parameters.
            headers: Extra request headers, merged over the client's
                defaults (call-site wins), except ``User-Agent`` which is
                always the client's own.
            ttl: Freshness window override for this call, in seconds.
                Defaults to :attr:`ttl`.
            force_refresh: Whether to bypass the cache read for this
                call. Defaults to the client's configured default. The
                fetched response is still written to the cache either
                way.
            source: A short label (``"loranet"``, ``"lorastats"``) used
                in error messages to identify the calling datasource.

        Returns:
            The cached or freshly fetched response.

        Raises:
            SettingsError: If the resolved ``ttl`` is negative.
            HttpError: If the request fails and cannot be served from a
                fresh cache entry.
            RateLimitError: If the server responds with HTTP 429.
            CacheError: If the fetched response cannot be written to disk.
        """
        return self.request(
            "GET",
            url,
            params=params,
            headers=headers,
            ttl=ttl,
            force_refresh=force_refresh,
            source=source,
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
                Defaults to :attr:`ttl`.
            force_refresh: Whether to bypass the cache read for this
                call. Defaults to the client's configured default. The
                fetched response is still written to the cache either
                way, refreshing the entry for the next call.
            source: A short label (``"loranet"``, ``"lorastats"``) used
                in error messages to identify the calling datasource.

        Returns:
            The cached or freshly fetched response.

        Raises:
            SettingsError: If the resolved ``ttl`` is negative.
            HttpError: If the request fails and cannot be served from a
                fresh cache entry.
            RateLimitError: If the server responds with HTTP 429.
            CacheError: If the fetched response cannot be written to disk.
        """
        effective_ttl = self._ttl if ttl is None else ttl
        if effective_ttl < 0:
            raise SettingsError("Cache TTL must not be negative.")
        refresh = self._force_refresh if force_refresh is None else force_refresh

        key = cache_key(method, url, params)
        path = self.path_for_key(key)

        if not refresh:
            entry = self._read_entry(path, cache_key_value=key)
            if entry is not None and entry.is_fresh(effective_ttl, now=self._clock()):
                self._stats = replace(self._stats, hits=self._stats.hits + 1)
                _logger.debug("cache hit for %s %s (key=%s)", method, url, key)
                return replace(entry, from_cache=True)

        self._stats = replace(self._stats, misses=self._stats.misses + 1)
        _logger.debug("cache miss for %s %s (key=%s)", method, url, key)

        merged_headers = self._merge_headers(headers)
        response = self._fetch_with_retry(
            method, url, params=params, headers=merged_headers, source=source, cache_key_value=key
        )
        self._write_entry(path, response)
        self._stats = replace(self._stats, writes=self._stats.writes + 1)
        return replace(response, from_cache=False)

    def purge(self, *, older_than: float | None = None) -> int:
        """Delete cache entries older than a threshold, or all corrupt entries.

        Also sweeps orphaned ``*.json.tmp-*`` temp files left behind by a
        :meth:`_write_entry` that was interrupted mid-write. This can
        delete a *live* concurrent writer's temp file, since two
        processes may legitimately share a cache directory and this
        method takes no lock. The consequence is not benign: the
        victim's ``replace`` raises ``OSError``, which
        :meth:`_write_entry` deliberately turns into a
        :class:`CacheError` rather than swallowing it, and since
        :meth:`request` writes the entry *before* returning, that error
        surfaces out of the victim's own in-flight :meth:`request` call
        -- discarding a fetch that had already succeeded.

        No shipped CLI command reaches this method today. Whenever one
        is wired up, this sweep should first grow an age guard of the
        kind :mod:`meshprovision.db.atomic_writer` already applies to
        its own orphaned temps: skip any temp file younger than some
        threshold, so an in-flight write is never a sweep target. The
        injectable ``self._clock()`` this class already carries makes
        such a guard straightforward to test.

        Args:
            older_than: Age threshold in seconds. Defaults to :attr:`ttl`.
                An entry is deleted when it is corrupt, or when its age
                exceeds this threshold.

        Returns:
            The number of entries deleted.
        """
        threshold = self._ttl if older_than is None else older_than
        deleted = 0
        for entry_path in self._cache_dir.rglob("*.json"):
            try:
                entry = self._read_entry(entry_path, cache_key_value=entry_path.stem)
            except OSError:
                continue
            if entry is None and not entry_path.exists():
                # _read_entry() already unlinked a corrupt entry itself;
                # counting it here without a second (always-failing)
                # unlink attempt avoids undercounting deleted and logging
                # a misleading "could not purge" line for an entry that
                # was in fact already removed.
                deleted += 1
                continue
            is_corrupt = entry is None
            is_expired = entry is not None and entry.age(now=self._clock()) > threshold
            if is_corrupt or is_expired:
                try:
                    entry_path.unlink()
                    deleted += 1
                except OSError as exc:
                    _logger.debug("could not purge cache entry %s: %s", entry_path, exc)
        for stray in self._cache_dir.rglob("*.json.tmp-*"):
            try:
                stray.unlink()
                deleted += 1
            except OSError as exc:
                _logger.debug("could not remove stray cache temp %s: %s", stray, exc)
        return deleted

    def clear(self) -> int:
        """Delete every cache entry under :attr:`cache_dir`.

        Also sweeps orphaned ``*.json.tmp-*`` temp files left behind by
        an interrupted :meth:`_write_entry`. This shares the
        concurrent-writer race described on :meth:`purge`: sweeping a
        live writer's temp file makes that writer's own in-flight
        :meth:`request` call raise :class:`CacheError` out of
        :meth:`_write_entry`, throwing away an already-successful fetch.
        Like :meth:`purge`, this method is not reachable from any
        shipped CLI command, and should gain the same age guard --
        leaving temp files younger than some threshold alone, timed off
        the injectable ``self._clock()`` -- before one exposes it.

        Returns:
            The number of entries deleted.
        """
        deleted = 0
        for entry_path in self._cache_dir.rglob("*.json"):
            try:
                entry_path.unlink()
                deleted += 1
            except OSError as exc:
                _logger.debug("could not clear cache entry %s: %s", entry_path, exc)
        for stray in self._cache_dir.rglob("*.json.tmp-*"):
            try:
                stray.unlink()
                deleted += 1
            except OSError as exc:
                _logger.debug("could not remove stray cache temp %s: %s", stray, exc)
        return deleted

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
            response: The response to persist. Only 2xx responses should
                ever be passed here.

        Raises:
            CacheError: If the write fails. Write failures are raised,
                not swallowed, since a silently dead cache means every
                run re-downloads the full dataset.
        """
        self._chmod_cache_root()
        path.parent.mkdir(parents=True, exist_ok=True)

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
        tmp = path.with_name(f"{path.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}")
        try:
            tmp.write_bytes(json.dumps(entry).encode("utf-8"))
            tmp.replace(path)
        except OSError as exc:
            with contextlib.suppress(OSError):
                tmp.unlink()
            raise CacheError(
                f"Could not write the HTTP cache entry: {exc}",
                path=str(path),
                hint="Set MESHPROVISION_CACHE_DIR to a writable directory.",
            ) from exc

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

        Returns:
            The freshly fetched response, with ``from_cache=False``.

        Raises:
            HttpError: On a non-retryable failure, or after exhausting
                retries on a retryable one.
            RateLimitError: If the server responds with HTTP 429 (never
                retried automatically).
        """
        last_exc: Exception | None = None
        for attempt in range(self._max_retries + 1):
            self._stats = replace(self._stats, network_requests=self._stats.network_requests + 1)
            _logger.info("fetching %s %s (attempt %d)", method, url, attempt + 1)
            try:
                # `params` is typed `Mapping[str, object]` at this class's public
                # boundary (any stringifiable value is accepted, matching
                # `cache_key`'s normalization); httpx's own parameter type is
                # narrower, so the value is passed through as `Any` here.
                httpx_params = cast("Any", params)
                response = self._client.request(method, url, params=httpx_params, headers=headers)
            except (httpx.InvalidURL, httpx.UnsupportedProtocol) as exc:
                raise HttpError(
                    f"Request to {url} is invalid: {exc}", url=url, source=source
                ) from exc
            except httpx.TransportError as exc:
                last_exc = exc
                if attempt == self._max_retries:
                    raise HttpError(
                        f"Request to {url} failed after {attempt + 1} attempt(s): {exc}",
                        url=url,
                        source=source,
                    ) from exc
                self._stats = replace(self._stats, retries=self._stats.retries + 1)
                self._backoff(attempt, url=url)
                continue

            status = response.status_code

            if status == _HTTP_RATE_LIMITED:
                raise RateLimitError(
                    f"{url} returned HTTP 429 (rate limited)",
                    url=str(response.url),
                    status_code=status,
                    source=source,
                    retry_after=_parse_retry_after(
                        response.headers.get("retry-after"), clock=self._clock
                    ),
                    hint=(
                        "lorastats.pl bans IP addresses for misuse; wait before retrying "
                        "and check MESHPROVISION_CONTACT."
                    ),
                )

            if _HTTP_CLIENT_ERROR_MIN <= status < _HTTP_CLIENT_ERROR_MAX:
                raise HttpError(
                    f"{url} returned HTTP {status}",
                    url=str(response.url),
                    status_code=status,
                    source=source,
                )

            if status >= RETRY_STATUS_MIN:
                if attempt == self._max_retries:
                    raise HttpError(
                        f"{url} returned HTTP {status} after {attempt + 1} attempt(s)",
                        url=str(response.url),
                        status_code=status,
                        source=source,
                    )
                self._stats = replace(self._stats, retries=self._stats.retries + 1)
                self._backoff(attempt, url=url)
                continue

            if not (_HTTP_SUCCESS_MIN <= status < _HTTP_SUCCESS_MAX):
                raise HttpError(
                    f"{url} returned unexpected HTTP {status}",
                    url=str(response.url),
                    status_code=status,
                    source=source,
                )

            return CachedResponse(
                status_code=status,
                headers={
                    name: value
                    for name, value in response.headers.items()
                    if name.lower() in PERSISTED_HEADERS
                },
                content=response.content,
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
