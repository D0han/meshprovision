"""The lorastats region list, read from lorastats.pl's own site navigation and cached.

lorastats.pl answers ``Nodes/JSON`` only in the region a node lives in,
and offers no API listing its regions; the names exist only as the links
of the regional navigation on the server-rendered page
``https://lorastats.pl/Nodes`` (``/Nodes/<Region>``, plus role pages
``/Nodes/<Region>/<Role>``, which also name the region the bare ``/Nodes``
link stands for). lorastats.pl asks API clients not to scrape its HTML
pages and bans IP addresses that do, so this module is the one place that
reads that page, and it does so as little as possible:

- only when no region is configured (``--region`` and
  ``MESHPROVISION_LORASTATS_REGIONS`` both win, and then the page is never
  requested);
- at most once per :data:`REGION_LIST_TTL_SECONDS` (a week): the list is
  kept in :data:`REGION_LIST_FILENAME` in the cache directory, and neither
  ``--no-cache`` nor a ``--watch`` poll refreshes it -- only
  ``mesh status --refresh-regions`` does before the week is up;
- after a failed request, not again for :data:`REGION_LIST_RETRY_SECONDS`
  (a day) by any process: the attempt is recorded in the same file
  (``tried_at``), the stale list, if any, kept and used meanwhile
  (``--refresh-regions`` still asks);
- at most once per :class:`RegionList`, which ``mesh status`` creates once
  per process, ``--watch`` included;
- through the shared :class:`~meshprovision.cache.http.CachedHTTPClient`
  (contact ``User-Agent``, 429 cool-down, redirect rules) with a body cap
  of :data:`REGION_LIST_MAX_PAGE_BYTES`, and without the client's retries.

The page is untrusted input: it is only tokenized by the standard
library's :class:`html.parser.HTMLParser` for the ``href`` of ``<a>`` tags
(no script runs, no link is followed, nothing of it is logged), and a
name is kept only when it passes
:func:`~meshprovision.datasources.lorastats.validate_regions`. There is
no built-in fallback list: when the page cannot be read and no list was
ever cached, lorastats fails as a source and the operator is told to set
``MESHPROVISION_LORASTATS_REGIONS``.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from html.parser import HTMLParser
from typing import TYPE_CHECKING, Final
from urllib.parse import unquote, urlsplit

from meshprovision.datasources.base import SOURCE_LORASTATS
from meshprovision.datasources.json_store import read_json, write_json
from meshprovision.datasources.lorastats import (
    LORASTATS_BASE_URL,
    LORASTATS_MAX_REGIONS,
    validate_regions,
)
from meshprovision.errors import DataSourceError, RateLimitCoolingDownError, SettingsError

if TYPE_CHECKING:
    from pathlib import Path

    from meshprovision.cache.http import CachedHTTPClient

__all__ = [
    "REGION_LIST_FILENAME",
    "REGION_LIST_MAX_PAGE_BYTES",
    "REGION_LIST_PAGE_PATH",
    "REGION_LIST_RETRY_SECONDS",
    "REGION_LIST_TTL_SECONDS",
    "REGION_LIST_VERSION",
    "ROLE_PAGE_NAMES",
    "RegionList",
    "parse_region_list",
]

_logger = logging.getLogger(__name__)

REGION_LIST_PAGE_PATH: Final[str] = "/Nodes"
"""The server-rendered page whose navigation names the regions."""

REGION_LIST_FILENAME: Final[str] = "lorastats_region_list.json"
"""The cached list's file name, directly in the HTTP cache directory."""

REGION_LIST_VERSION: Final[int] = 1
"""On-disk schema version. A file with any other version reads as no list."""

REGION_LIST_TTL_SECONDS: Final[float] = 7 * 24 * 60 * 60
"""How long a fetched list is used before the page is requested again (a week)."""

REGION_LIST_RETRY_SECONDS: Final[float] = 24 * 60 * 60
"""How long after a failed request the page is not requested again (a day)."""

REGION_LIST_MAX_PAGE_BYTES: Final[int] = 2 * 1024 * 1024
"""The largest page accepted; the real one is far smaller."""

ROLE_PAGE_NAMES: Final[frozenset[str]] = frozenset(
    {"Client", "ClientBase", "ClientMute", "Router", "RouterLate", "Tracker"}
)
"""The role pages of a region (``/Nodes/<Region>/<Role>``); never a region themselves."""

_MAX_FILE_BYTES: Final[int] = 64 * 1024
_FUTURE_SKEW_SECONDS: Final[float] = 300.0
_WHAT: Final[str] = "lorastats region list"
_HINT: Final[str] = (
    "Set MESHPROVISION_LORASTATS_REGIONS (or pass --region) to the lorastats "
    "regions to ask, for example MESHPROVISION_LORASTATS_REGIONS=Zachód,Warszawa."
)


class _AnchorHrefs(HTMLParser):
    """Collects the ``href`` of every ``<a>`` start tag, nothing else."""

    def __init__(self) -> None:
        """Initialize the parser with no hrefs collected."""
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Record the tag's ``href`` when it is an anchor.

        Args:
            tag: The lowercased tag name.
            attrs: The tag's attributes, lowercased names, unescaped values.
        """
        if tag != "a":
            return
        for name, value in attrs:
            if name == "href" and value is not None:
                self.hrefs.append(value)
                return


def _region_from_href(href: str) -> str | None:
    """Return the region a navigation link names, or ``None`` for any other link.

    Only a same-site path ``/Nodes/<Region>`` or ``/Nodes/<Region>/<Role>``
    (``<Role>`` one of :data:`ROLE_PAGE_NAMES`) names a region; a query
    (``/Nodes?poi=...`` localities), a fragment, another host or scheme,
    and every other path are ignored. The segment is percent-decoded
    (strictly, as UTF-8) and must pass
    :func:`~meshprovision.datasources.lorastats.validate_regions`, so a
    decoded ``/``, ``..`` or an over-long name is dropped.

    Args:
        href: The link target, as written in the page.

    Returns:
        The validated, NFC-normalized region name, or ``None``.
    """
    try:
        parts = urlsplit(href.strip())
    except ValueError:
        return None
    if parts.scheme not in ("", "https") or parts.netloc not in ("", "lorastats.pl"):
        return None
    if parts.query or parts.fragment or not parts.path.startswith(REGION_LIST_PAGE_PATH + "/"):
        return None
    segments = parts.path[len(REGION_LIST_PAGE_PATH) + 1 :].split("/")
    if len(segments) == 2 and segments[1] in ROLE_PAGE_NAMES:
        segments = segments[:1]
    if len(segments) != 1 or segments[0] in ROLE_PAGE_NAMES:
        return None
    try:
        name = unquote(segments[0], errors="strict")
        (region,) = validate_regions((name,))
    except (UnicodeDecodeError, SettingsError):
        return None
    return region


def parse_region_list(html: str) -> tuple[str, ...]:
    """Extract the region names from the navigation of lorastats.pl's ``/Nodes`` page.

    Args:
        html: The page, decoded.

    Returns:
        Every region named by a link (see :func:`_region_from_href`), once,
        in first-seen order, at most :data:`~meshprovision.datasources
        .lorastats.LORASTATS_MAX_REGIONS` of them: the links are read only
        up to the first region past the limit, which is logged as a
        WARNING. Empty when the page names none.
    """
    parser = _AnchorHrefs()
    parser.feed(html)
    parser.close()
    regions: dict[str, None] = {}  # insertion-ordered, O(1) membership
    for href in parser.hrefs:
        region = _region_from_href(href)
        if region is None:
            continue
        regions.setdefault(region, None)
        if len(regions) > LORASTATS_MAX_REGIONS:
            _logger.warning(
                "lorastats.pl names more than %d regions; asking only the first %d",
                LORASTATS_MAX_REGIONS,
                LORASTATS_MAX_REGIONS,
            )
            break
    return tuple(regions)[:LORASTATS_MAX_REGIONS]


class RegionList:
    """The lorastats region list, loaded once: from the cache file, else from lorastats.pl."""

    def __init__(
        self,
        *,
        refresh: bool = False,
        base_url: str = LORASTATS_BASE_URL,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Initialize the list. Nothing is read or fetched until :meth:`regions`.

        Args:
            refresh: Request the page even when the cached list is still
                fresh (``mesh status --refresh-regions``).
            base_url: The lorastats.pl base URL. Overridable for tests.
            clock: Callable returning the current unix epoch seconds.
        """
        self._refresh = refresh
        self._url = base_url.rstrip("/") + REGION_LIST_PAGE_PATH
        self._clock = clock
        self._regions: tuple[str, ...] | None = None
        self._error: DataSourceError | None = None

    def regions(self, client: CachedHTTPClient) -> tuple[str, ...]:
        """Return the region list, loading it on the first call only.

        A later call returns the same list, or raises the same error,
        without reading or requesting anything again.

        Args:
            client: The client to fetch through; its cache directory holds
                the cached list.

        Returns:
            The validated region names, in the page's order.

        Raises:
            meshprovision.errors.DataSourceError: If no list is cached and
                the page cannot be fetched or names no region.
        """
        if self._error is not None:
            raise self._error
        if self._regions is None:
            try:
                self._regions = self._load(client)
            except DataSourceError as exc:
                self._error = exc
                raise
        return self._regions

    def _load(self, client: CachedHTTPClient) -> tuple[str, ...]:
        """Use the cached list while fresh, else fetch the page; fall back to a stale list.

        The page is not fetched (unless refreshing) while a failed fetch is
        less than :data:`REGION_LIST_RETRY_SECONDS` old; a failed fetch is
        recorded for that (not one the client refused unsent during a 429
        cool-down).

        Args:
            client: The client to fetch through.

        Returns:
            The region names.

        Raises:
            meshprovision.errors.DataSourceError: If no list is cached and
                the fetch fails or failed recently.
        """
        path = client.cache_dir / REGION_LIST_FILENAME
        document = read_json(path, max_bytes=_MAX_FILE_BYTES, what=_WHAT)
        cached = _read_cached(document)
        now = self._clock()
        if not self._refresh:
            if cached is not None and _recent(cached[1], REGION_LIST_TTL_SECONDS, now):
                return cached[0]
            tried_at = _read_tried_at(document)
            if tried_at is not None and _recent(tried_at, REGION_LIST_RETRY_SECONDS, now):
                return _after_recent_failure(cached, self._url)
        try:
            regions = self._fetch(client)
        except DataSourceError as exc:
            # A request refused for another process's 429 never reached
            # lorastats: it must not lock the page out for a day.
            if not isinstance(exc, RateLimitCoolingDownError):
                _record_failure(path, cached, now)
            if cached is None:
                raise DataSourceError(
                    f"No lorastats region list: {exc.message}", hint=_HINT
                ) from exc
            _logger.warning(
                "Could not refresh the lorastats region list (%s); using the cached one.",
                exc.message,
            )
            return cached[0]
        write_json(
            path,
            {"version": REGION_LIST_VERSION, "regions": list(regions), "fetched_at": now},
            what=_WHAT,
        )
        return regions

    def _fetch(self, client: CachedHTTPClient) -> tuple[str, ...]:
        """Request the page once, without retries, and parse it.

        The response is never written to the HTTP cache: only the parsed
        list is kept. The eviction still removes a page an earlier version
        of mesh cached.

        Args:
            client: The client to fetch through.

        Returns:
            The region names, never empty.

        Raises:
            meshprovision.errors.DataSourceError: If the request fails or
                the page names no region.
        """
        response = client.get(
            self._url,
            headers={"Accept": "text/html"},
            force_refresh=True,
            source=SOURCE_LORASTATS,
            max_bytes=REGION_LIST_MAX_PAGE_BYTES,
            max_retries=0,
            store=False,
        )
        client.evict(response.cache_key)
        regions = parse_region_list(response.content.decode("utf-8", errors="replace"))
        if not regions:
            raise DataSourceError(f"{self._url} named no lorastats region")
        _logger.info("read %d lorastats region(s) from %s", len(regions), self._url)
        return regions


def _read_cached(document: object) -> tuple[tuple[str, ...], float] | None:
    """Validate the cached list file's content.

    Args:
        document: The decoded file, or ``None``.

    Returns:
        ``(regions, fetched_at)``, or ``None`` unless ``document`` is a
        version :data:`REGION_LIST_VERSION` list of 1 to
        :data:`~meshprovision.datasources.lorastats.LORASTATS_MAX_REGIONS`
        valid, canonical region names with a numeric ``fetched_at`` (a
        non-finite one is never fresh).
    """
    if not isinstance(document, dict) or document.get("version") != REGION_LIST_VERSION:
        return None
    regions = document.get("regions")
    fetched_at = document.get("fetched_at")
    if not isinstance(regions, list) or not all(isinstance(r, str) for r in regions):
        return None
    if isinstance(fetched_at, bool) or not isinstance(fetched_at, int | float):
        return None
    try:
        valid = validate_regions(regions)
    except SettingsError:
        return None
    if list(valid) != regions:
        return None
    return valid, float(fetched_at)


def _read_tried_at(document: object) -> float | None:
    """Return when a request for the page last failed, from the cached list file's content.

    Args:
        document: The decoded file, or ``None``.

    Returns:
        A version :data:`REGION_LIST_VERSION` document's numeric
        ``tried_at`` (a boolean reads as the epoch's first second, never
        recent), else ``None``.
    """
    if not isinstance(document, dict) or document.get("version") != REGION_LIST_VERSION:
        return None
    tried_at = document.get("tried_at")
    if not isinstance(tried_at, int | float):
        return None
    return float(tried_at)


def _recent(at: float, window: float, now: float) -> bool:
    """Tell whether ``at`` lies within ``window`` seconds before ``now``.

    Args:
        at: The time, epoch seconds.
        window: The window, seconds.
        now: The current time, epoch seconds.

    Returns:
        ``True`` when ``at`` is at most ``window`` old and at most a small
        clock skew in the future (a non-finite ``at`` never is).
    """
    return now - window <= at <= now + _FUTURE_SKEW_SECONDS


def _after_recent_failure(
    cached: tuple[tuple[str, ...], float] | None, url: str
) -> tuple[str, ...]:
    """Answer without a request while the last one failed recently.

    Args:
        cached: The stale cached list and when it was fetched, if any.
        url: The page's URL, for the error.

    Returns:
        The stale cached list.

    Raises:
        meshprovision.errors.DataSourceError: If no list is cached.
    """
    if cached is None:
        raise DataSourceError(
            f"No lorastats region list: reading {url} failed in the last day "
            "(mesh status --refresh-regions asks again now)",
            hint=_HINT,
        )
    _logger.info("Reading the lorastats region list failed in the last day; using the cached one.")
    return cached[0]


def _record_failure(path: Path, cached: tuple[tuple[str, ...], float] | None, now: float) -> None:
    """Record a failed request for the page, keeping the cached list.

    Args:
        path: The cached list file.
        cached: The cached list and when it was fetched, if any.
        now: When the request failed, epoch seconds.
    """
    document: dict[str, object] = {"version": REGION_LIST_VERSION, "tried_at": now}
    if cached is not None:
        document["regions"] = list(cached[0])
        document["fetched_at"] = cached[1]
    write_json(path, document, what=_WHAT)
