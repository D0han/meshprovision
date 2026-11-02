"""``RegionRefresher``: bring the regions' traffic stores up to date, within a request budget.

**Which regions.** :func:`select_regions`: the ones asked for, else the
lorastats regions our nodes were last found in (the region memo that
``mesh status`` and ``mesh health`` fill), busiest first, at most
:data:`NETWORK_DEFAULT_MAX_REGIONS`. Never every region: a region's day
of raw packets is about 25 MB.

**Request budget, per region.** At most one ``PacketsRaw`` request per
:data:`NETWORK_REFRESH_INTERVAL_SECONDS` (per
:data:`NETWORK_FORCED_REFRESH_INTERVAL_SECONDS`, the lorastats TTL floor,
when forced), counted from the fetch stored in the region's state, and
always from ``since`` once the region has been fetched, so a refresh
costs about 0.6 MB per hour since the previous one; and one ``Nodes``
request, served from the HTTP cache for at least an hour (see
:class:`~meshprovision.datasources.lorastats_region.LorastatsRegionFeed`).
A 429 answer makes the client refuse every further request to
lorastats.pl for its cool-down.

**One failure stops a refresh.** Once a request fails because
lorastats.pl is down or refusing (see
:func:`~meshprovision.datasources.lorastats_failures.is_outage`), no other
request is made in that call: each remaining request is reported as a
failure without being sent. A failure of one answer (a 404, an unusable
or over-large body) does not stop the others.

**Incremental, idempotent.** As for a node's health history
(:mod:`meshprovision.health.refresh`): each refresh asks from one hour
before the start of the hour of the previous one (the extra hour absorbs
a misread Warsaw time around a DST change) and replaces that hour onwards
(see :func:`~meshprovision.network.buckets.merge`). The public keys a
fetch saw are audited and recorded as digests
(:mod:`meshprovision.network.keystore`) before the rows are dropped. The raw rows are
dropped as soon as they are summarized; regions are refreshed one at a
time, so at most one region's answer is in memory.
"""

from __future__ import annotations

import logging
import time
from collections import Counter
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from meshprovision.datasources.lorastats import LORASTATS_MIN_TTL_SECONDS, validate_regions
from meshprovision.datasources.lorastats_failures import outage_error
from meshprovision.errors import DataSourceError, SettingsError
from meshprovision.health.history import floor_hour
from meshprovision.health.packets import FUTURE_SKEW_SECONDS
from meshprovision.health.refresh import SINCE_MARGIN_SECONDS
from meshprovision.network.buckets import summarize
from meshprovision.network.keys import observe
from meshprovision.network.rawpackets import parse_raw

if TYPE_CHECKING:
    from meshprovision.datasources.lorastats_region import LorastatsRegionFeed
    from meshprovision.datasources.models import NodeObservation
    from meshprovision.network.keystore import KeyStore
    from meshprovision.network.store import RegionState, RegionStore

__all__ = [
    "NETWORK_DEFAULT_MAX_REGIONS",
    "NETWORK_FORCED_REFRESH_INTERVAL_SECONDS",
    "NETWORK_REFRESH_INTERVAL_SECONDS",
    "NetworkRefresh",
    "RegionFailure",
    "RegionRefresher",
    "select_regions",
]

_logger = logging.getLogger(__name__)

NETWORK_REFRESH_INTERVAL_SECONDS: Final[float] = 900.0
"""A region's raw packets are fetched at most once per this (15 minutes)."""

NETWORK_FORCED_REFRESH_INTERVAL_SECONDS: Final[float] = LORASTATS_MIN_TTL_SECONDS
"""When forced, at most once per this (lorastats' 60 s TTL floor)."""

NETWORK_DEFAULT_MAX_REGIONS: Final[int] = 4
"""The most regions looked at when none is asked for."""


@dataclass(frozen=True, slots=True)
class RegionFailure:
    """A region whose refresh failed.

    Attributes:
        region: The region.
        message: The error's message.
        hint: The error's hint, when it has one.
    """

    region: str
    message: str
    hint: str | None = None


@dataclass(frozen=True, slots=True)
class NetworkRefresh:
    """What one :meth:`RegionRefresher.refresh` call did.

    Attributes:
        refreshed: The regions whose raw packets were fetched.
        failures: Every failed (or, after an outage, unsent) request.
        nodes: Each region's node list, for the regions it could be had for.
        skipped_rows: Raw rows that could not be used.
    """

    refreshed: tuple[str, ...] = ()
    failures: tuple[RegionFailure, ...] = ()
    nodes: Mapping[str, tuple[NodeObservation, ...]] = field(
        default_factory=lambda: MappingProxyType({})
    )
    skipped_rows: int = 0


def select_regions(asked: Sequence[str], fleet: Iterable[str | None]) -> tuple[str, ...]:
    """Choose the regions to look at.

    Args:
        asked: The regions asked for (``--region``), possibly none.
        fleet: The lorastats region each of our nodes was last found in,
            ``None`` where none is known.

    Returns:
        The validated regions asked for, else our nodes' valid regions,
        the region of most nodes first (ties: the first seen), at most
        :data:`NETWORK_DEFAULT_MAX_REGIONS`.

    Raises:
        meshprovision.errors.SettingsError: If a region asked for is
            malformed or there are too many, or none is asked for and none
            is known for any of our nodes.
    """
    if asked:
        return validate_regions(asked)
    counts = Counter(region for region in fleet if region is not None and _valid(region))
    if not counts:
        raise SettingsError(
            "No lorastats region is known for any of our nodes.",
            hint="Run `mesh status` once to find their regions, or pass --region.",
        )
    return tuple(region for region, _ in counts.most_common(NETWORK_DEFAULT_MAX_REGIONS))


def _valid(region: str) -> bool:
    """Tell whether a remembered region is well-formed (and already normalized)."""
    try:
        return validate_regions((region,)) == (region,)
    except SettingsError:
        return False


class RegionRefresher:
    """Refreshes region stores through one :class:`~meshprovision.network.store.RegionStore`."""

    def __init__(
        self,
        store: RegionStore,
        feed: LorastatsRegionFeed,
        *,
        keys: KeyStore,
        known_bad: Collection[bytes],
        force: bool = False,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Initialize the refresher.

        Args:
            store: Where the regions' traffic is kept.
            feed: What fetches the rows and node lists.
            keys: Where the keys each fetch saw advertised are kept.
            known_bad: The known-bad key blocklist, for the audit of
                every key seen (while it is still in memory).
            force: Fetch once per :data:`NETWORK_FORCED_REFRESH_INTERVAL_SECONDS`
                instead of :data:`NETWORK_REFRESH_INTERVAL_SECONDS`.
            clock: Callable returning the current unix epoch seconds.
        """
        self._store = store
        self._feed = feed
        self._keys = keys
        self._known_bad = known_bad
        self._force = force
        self._clock = clock

    def refresh(self, regions: Sequence[str]) -> NetworkRefresh:
        """Refresh every due region and get each region's node list.

        Args:
            regions: The validated regions, in the order to ask them.

        Returns:
            What was done.
        """
        refreshed: list[str] = []
        failures: list[RegionFailure] = []
        nodes: dict[str, tuple[NodeObservation, ...]] = {}
        down: DataSourceError | None = None
        skipped = 0
        for region in regions:
            for step in ("raw", "nodes"):
                if step == "raw" and not self._due(self._store.state(region)):
                    continue
                if down is not None:
                    failures.append(RegionFailure(region, down.message))
                    continue
                try:
                    if step == "raw":
                        skipped += self._fetch(region)
                        refreshed.append(region)
                    else:
                        nodes[region] = self._feed.nodes(region)
                except DataSourceError as exc:
                    failures.append(RegionFailure(region, exc.message, exc.hint))
                    down = _tripped(exc, region)
        return NetworkRefresh(
            refreshed=tuple(refreshed),
            failures=tuple(failures),
            nodes=MappingProxyType(nodes),
            skipped_rows=skipped,
        )

    def _due(self, state: RegionState) -> bool:
        """Tell whether a region with this state may be fetched now."""
        now = self._clock()
        interval = (
            NETWORK_FORCED_REFRESH_INTERVAL_SECONDS
            if self._force
            else NETWORK_REFRESH_INTERVAL_SECONDS
        )
        last = state.fetched_at
        return last is None or last > now + FUTURE_SKEW_SECONDS or now - last >= interval

    def _fetch(self, region: str) -> int:
        """Fetch a region's raw packets since its previous fetch and store them.

        Returns:
            How many rows could not be used.

        Raises:
            meshprovision.errors.DataSourceError: If the request fails.
        """
        now = self._clock()
        previous = self._store.state(region).fetched_at
        since = None if previous is None else floor_hour(min(previous, now))
        asked = None if since is None else since - SINCE_MARGIN_SECONDS
        parsed = parse_raw(self._feed.raw(region, since=asked), now=now)
        hours = summarize(parsed, since=since, fetched_at=now)
        self._store.update(region, hours, fetched_at=now)
        self._keys.update(region, observe(parsed.keys, self._known_bad))
        _logger.info(
            "lorastats: %d reception(s) in %s, %d row(s) skipped",
            len(parsed.receptions),
            region,
            parsed.skipped,
        )
        return parsed.skipped


def _tripped(exc: DataSourceError, region: str) -> DataSourceError | None:
    """Return the error to report instead of every later request, when lorastats is failing."""
    return outage_error(exc, region, asked="lorastats region data", others="region", logger=_logger)
