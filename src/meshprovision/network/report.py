"""Read-only ``mesh network`` orchestration: our nodes, the regions, a refresh, each region's view.

Like :mod:`meshprovision.health.report` this is **strictly read-only**
toward the database and every device: it loads the database and never
saves, replaces, upserts or deletes anything in it
(``tests/unit/test_readonly_status_boundary.py`` walks it for those
operations). The only files it writes are the HTTP cache and the region
stores in the cache directory (:mod:`meshprovision.network.store`,
:mod:`meshprovision.network.keystore`).

The ``relays`` and ``graph`` views also read loranet's node dump (one
download per run, through the HTTP cache ``mesh status`` shares): the
resolved relay nodes' observations and the neighbour lists of the nodes
the window heard (:class:`LoranetView`); ``--no-fetch`` asks nothing.

"Us" is every active (not archived) node of the database, observed ones
included. The regions are the ones asked for, else those our nodes were
last found in (:func:`~meshprovision.network.refresh.select_regions`).
"""

from __future__ import annotations

import time
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from meshprovision.datasources.loranet import LoranetSource
from meshprovision.datasources.lorastats_region import LorastatsRegionFeed
from meshprovision.datasources.region_memo import REGION_MEMO_FILENAME, RegionMemo
from meshprovision.db.keys import KeyRepository
from meshprovision.db.nodes import NodeRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.db.schema import KeyType, ref_for
from meshprovision.errors import DataSourceError, DbIntegrityError, ExitCode
from meshprovision.network.buckets import Traffic, combine
from meshprovision.network.keys import FleetKey, KeyScan, fleet_key, scan_keys
from meshprovision.network.keystore import KeyStore
from meshprovision.network.refresh import NetworkRefresh, RegionRefresher, select_regions
from meshprovision.network.relays import gateway_relayed
from meshprovision.network.resolve import Resolution, relay_candidates, resolve_relays
from meshprovision.network.store import NETWORK_DIRNAME, RegionStore
from meshprovision.nodeid import NodeId
from meshprovision.termsafe import terminal_safe

if TYPE_CHECKING:
    from pathlib import Path

    from meshprovision.cache.http import CachedHTTPClient
    from meshprovision.config.settings import Settings
    from meshprovision.datasources.loranet import ReportedNeighbor
    from meshprovision.datasources.models import NodeObservation

__all__ = [
    "DEFAULT_KEYS_DAYS",
    "DEFAULT_TRAFFIC_DAYS",
    "MAX_DAYS",
    "FleetNode",
    "LoranetView",
    "NetworkOptions",
    "NetworkReport",
    "RegionReport",
    "heard_ids",
    "load_fleet",
    "loranet_ids",
    "run_network",
]

DEFAULT_KEYS_DAYS: Final[int] = 30
"""The default window of ``mesh network keys``, in days."""

DEFAULT_TRAFFIC_DAYS: Final[int] = 1
"""The default window of the traffic views, in days (lorastats' own span)."""

MAX_DAYS: Final[int] = 30
"""The longest window: the stores keep 30 days."""

_DAY_SECONDS: Final[int] = 24 * 3600
_MUTE_ROLE: Final[str] = "CLIENT_MUTE"


@dataclass(frozen=True, slots=True)
class NetworkOptions:
    """Everything that shapes one ``mesh network`` run.

    Attributes:
        days: The window, in days (1 to :data:`MAX_DAYS`).
        regions: The regions asked for (``--region``); empty means ours.
        fetch: Whether to ask lorastats at all.
        refresh: Fetch even within the 15-minute interval (at most once a
            minute per region).
        traffic: Whether to load the traffic and resolve relay bytes (the
            key scan does not need them).
        loranet: Whether to read loranet's node dump for the resolved
            relay nodes (``relays`` and ``graph``); never without ``fetch``.
        neighbors: Whether to also read the neighbour lists from it (only
            ``graph`` uses them).
    """

    days: int
    regions: tuple[str, ...] = ()
    fetch: bool = True
    refresh: bool = False
    traffic: bool = True
    loranet: bool = False
    neighbors: bool = False


@dataclass(frozen=True, slots=True)
class LoranetView:
    """What loranet's node dump said about the nodes a view names.

    Attributes:
        asked: Whether loranet was asked at all (``False`` with ``--no-fetch``).
        nodes: Its observation of each resolved relay node it holds, by hex id.
        neighbors: The neighbour lists the nodes the window heard
            reported, by hex id.
        data_as_of: When the dump was fetched (the HTTP cache keeps it),
            epoch seconds.
        error: Why it could not be had, terminal-safe; ``None`` when it was.
    """

    asked: bool
    nodes: Mapping[str, NodeObservation] = field(default_factory=lambda: MappingProxyType({}))
    neighbors: Mapping[str, tuple[ReportedNeighbor, ...]] = field(
        default_factory=lambda: MappingProxyType({})
    )
    data_as_of: float | None = None
    error: str | None = None

    @property
    def usable(self) -> Mapping[str, NodeObservation] | None:
        """The observations, or ``None`` when loranet was not asked or failed."""
        return self.nodes if self.asked and self.error is None else None

    @property
    def reported(self) -> Mapping[str, tuple[tuple[str, float], ...]] | None:
        """The neighbour lists as ``(neighbour hex id, report time)``, or ``None`` (see usable)."""
        if not self.asked or self.error is not None:
            return None
        return {
            node: tuple((entry.node.hex, entry.updated) for entry in entries)
            for node, entries in self.neighbors.items()
        }


@dataclass(frozen=True, slots=True)
class FleetNode:
    """One of our nodes.

    Attributes:
        node: Its hex id.
        short_name: Its database short name, terminal-safe.
        key: Its database public key's digest.
    """

    node: str
    short_name: str
    key: FleetKey


@dataclass(frozen=True, slots=True)
class RegionReport:
    """One region's view over the window.

    Attributes:
        region: The region.
        fetched_at: When its data was last fetched (``None``: never).
        first_hour: The oldest stored hour in the window, if any.
        keys: The key scan of the window.
        traffic: The window's traffic (empty when not loaded).
        nodes: The region's node list, when it could be had.
        resolutions: Each relay byte's resolution (empty when the
            traffic was not loaded).
    """

    region: str
    fetched_at: float | None
    first_hour: int | None
    keys: KeyScan
    traffic: Traffic = field(default_factory=Traffic)
    nodes: tuple[NodeObservation, ...] = ()
    resolutions: Mapping[int, Resolution] = field(default_factory=lambda: MappingProxyType({}))


@dataclass(frozen=True, slots=True)
class NetworkReport:
    """The result of one ``mesh network`` run.

    Attributes:
        generated_at: When it was assembled, epoch seconds.
        days: The window, in days.
        fleet: Our nodes, in database order.
        regions: Each region's view, in the order they were chosen.
        refresh: What the refresh did (``None`` without fetching).
        loranet: What loranet said about the resolved relay nodes
            (``None`` for the views that do not ask it).
    """

    generated_at: float
    days: int
    fleet: tuple[FleetNode, ...]
    regions: tuple[RegionReport, ...]
    refresh: NetworkRefresh | None = None
    loranet: LoranetView | None = None

    @property
    def start(self) -> float:
        """The window's start, epoch seconds."""
        return self.generated_at - self.days * _DAY_SECONDS

    @property
    def keys_critical(self) -> bool:
        """Whether a region's key scan found a critical problem with one of our nodes."""
        return any(region.keys.fleet_critical for region in self.regions)

    def exit_code(self, *, crypto: bool = False) -> int:
        """The exit code of a view.

        Args:
            crypto: Whether the view found a critical problem with one of
                our nodes' keys.

        Returns:
            3 (:attr:`ExitCode.DATASOURCE`) when no region has any data;
            else 6 (:attr:`ExitCode.CRYPTO`) for ``crypto``; else 7
            (:attr:`ExitCode.STATUS_DEGRADED`) when a request failed (the
            stored data was used, or loranet could not be had); else 0.
        """
        if all(region.fetched_at is None for region in self.regions):
            return int(ExitCode.DATASOURCE)
        if crypto:
            return int(ExitCode.CRYPTO)
        if self.refresh is not None and self.refresh.failures:
            return int(ExitCode.STATUS_DEGRADED)
        if self.loranet is not None and self.loranet.error is not None:
            return int(ExitCode.STATUS_DEGRADED)
        return int(ExitCode.OK)


def load_fleet(db_path: Path) -> tuple[FleetNode, ...]:
    """Load our active nodes and their database public keys, strictly read-only.

    Args:
        db_path: The ``.ods`` database.

    Returns:
        Every active node, in the database's order.

    Raises:
        meshprovision.errors.DbError: If the database cannot be read (see
            :func:`~meshprovision.status.report.load_records`).
    """
    db = OdsDatabase(db_path)
    db.load()
    records = NodeRepository(db).all()
    public = KeyRepository(db).public_key_map()
    if db.dirty():
        raise DbIntegrityError(
            "Loading the database marked it dirty; refusing to continue in read-only mode",
            sheet=None,
            cell=None,
        )
    return tuple(
        FleetNode(
            node=record.node_id,
            short_name=terminal_safe(record.short_name),
            key=fleet_key(
                record.node_id, public.get(ref_for(record.node_id, KeyType.ADMIN_PUBLIC))
            ),
        )
        for record in records
        if not record.is_archived
    )


def run_network(
    settings: Settings,
    options: NetworkOptions,
    *,
    client: CachedHTTPClient,
    known_bad: Collection[bytes],
) -> NetworkReport:
    """Run ``mesh network``'s data side: choose regions, refresh them, build each view.

    Args:
        settings: The run's settings (database, cache directory).
        options: What to do.
        client: The shared HTTP client (not used without fetching).
        known_bad: The known-bad key blocklist, for the audit of new keys.

    Returns:
        The report.

    Raises:
        meshprovision.errors.SettingsError: If no region is asked for and
            none is known for any of our nodes, or a region is malformed.
        meshprovision.errors.DbError: If the database cannot be read.
    """
    now = time.time()
    fleet = load_fleet(settings.db_path)
    memo = RegionMemo(settings.cache_dir / REGION_MEMO_FILENAME)
    regions = select_regions(
        options.regions, (memo.region_for(NodeId.from_hex(member.node)) for member in fleet)
    )
    store = RegionStore(settings.cache_dir / NETWORK_DIRNAME)
    keystore = KeyStore(settings.cache_dir / NETWORK_DIRNAME)
    refresh = None
    if options.fetch:
        feed = LorastatsRegionFeed(client)
        refresher = RegionRefresher(
            store, feed, keys=keystore, known_bad=known_bad, force=options.refresh
        )
        refresh = refresher.refresh(regions)
    start = now - options.days * _DAY_SECONDS
    views = tuple(
        _region(region, store, keystore, fleet, refresh, start=start, traffic=options.traffic)
        for region in regions
    )
    loranet = None
    if options.loranet:
        loranet = (
            _loranet(client, views, neighbors=options.neighbors)
            if options.fetch
            else LoranetView(asked=False)
        )
    return NetworkReport(
        generated_at=now,
        days=options.days,
        fleet=fleet,
        regions=views,
        refresh=refresh,
        loranet=loranet,
    )


def loranet_ids(views: tuple[RegionReport, ...]) -> frozenset[NodeId]:
    """The nodes a view asks loranet about: every resolved relay node of every region.

    Args:
        views: The regions' views.

    Returns:
        Their ids.
    """
    return frozenset(
        NodeId.from_hex(resolution.node)
        for view in views
        for resolution in view.resolutions.values()
        if resolution.node is not None
    )


def heard_ids(views: tuple[RegionReport, ...]) -> frozenset[NodeId]:
    """The nodes whose neighbour lists a graph can use: every node the windows heard.

    Args:
        views: The regions' views.

    Returns:
        Every origin and gateway of the windows' traffic and every resolved
        relay node.
    """
    heard: set[str] = set()
    for view in views:
        traffic = view.traffic
        heard.update(traffic.direct, traffic.last_hops, gateway_relayed(traffic))
        heard.update(gateway for cells in traffic.direct.values() for gateway in cells)
    return frozenset({*(NodeId.from_hex(node) for node in heard), *loranet_ids(views)})


def _loranet(
    client: CachedHTTPClient, views: tuple[RegionReport, ...], *, neighbors: bool
) -> LoranetView:
    """Read loranet's node dump once for the views' nodes; a failure is reported, not raised."""
    source = LoranetSource(client)
    try:
        found = source.fetch_nodes(loranet_ids(views))
        lists = source.reported_neighbors(heard_ids(views)) if neighbors else {}
    except DataSourceError as exc:
        return LoranetView(asked=True, error=terminal_safe(str(exc)))
    as_of = source.last_fetch_data_as_of
    return LoranetView(
        asked=True,
        nodes=MappingProxyType({node.hex: observation for node, observation in found.items()}),
        neighbors=MappingProxyType({node.hex: entries for node, entries in lists.items()}),
        data_as_of=None if as_of is None else as_of.timestamp(),
    )


def _region(
    region: str,
    store: RegionStore,
    keystore: KeyStore,
    fleet: tuple[FleetNode, ...],
    refresh: NetworkRefresh | None,
    *,
    start: float,
    traffic: bool,
) -> RegionReport:
    """Build one region's view over the window."""
    seen = keystore.load(region)
    scan = scan_keys(seen, (member.key for member in fleet), start=start)
    fetched_at = store.state(region).fetched_at
    nodes = () if refresh is None else refresh.nodes.get(region, ())
    if not traffic:
        return RegionReport(region, fetched_at, None, scan, nodes=nodes)
    hours = store.load(region, start=start)
    combined = combine(hours)
    mute = {entry.node for entry in scan.seen if entry.role == _MUTE_ROLE}
    candidates = relay_candidates(combined, nodes, start=start, mute=mute)
    resolutions = resolve_relays(combined, candidates, learned=store.learned_relays(region))
    if fetched_at is not None:
        store.remember_relays(region, resolutions, seen_at=fetched_at)
    return RegionReport(
        region=region,
        fetched_at=fetched_at,
        first_hour=hours[0].hour if hours else None,
        keys=scan,
        traffic=combined,
        nodes=nodes,
        resolutions=resolutions,
    )
